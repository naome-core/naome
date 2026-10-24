"""Offline d1-3B categorical adapter; native custody and caller policy stay outside."""
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import queue
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

MAX_FRAME = 256 * 1024


def read_frame():
    line = sys.stdin.buffer.readline(MAX_FRAME + 1)
    if not line:
        return None
    if len(line) > MAX_FRAME or not line.endswith(b"\n"):
        raise ValueError("input_frame_limit")
    return json.loads(line)


def emit(value):
    print(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")), flush=True)


def verify(directory, assets, runtime=False):
    if runtime:
        actual = {p.name for p in directory.iterdir()
                  if p.name in ("llama-server", "LICENSE") or p.name.startswith("lib")}
        if actual != {a["file"] for a in assets}:
            raise ValueError("runtime_file_set_differs")
    for asset in assets:
        path = directory / asset["file"]
        if "link" in asset:
            if not path.is_symlink() or os.readlink(path) != asset["link"]:
                raise ValueError("asset_link_mismatch")
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size != asset["bytes"]:
            raise ValueError("asset_size_mismatch")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != asset["sha256"]:
            raise ValueError("asset_digest_mismatch")


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host)


def call(endpoint, key, path, value=None):
    connection = UnixHTTP(endpoint, timeout=120)
    try:
        connection.request("GET" if value is None else "POST", path,
            body=None if value is None else json.dumps(value, ensure_ascii=False).encode("utf-8"),
            headers={"Host": "localhost", "Authorization": "Bearer " + key,
                     "Content-Type": "application/json"})
        response = connection.getresponse()
        body = response.read(MAX_FRAME + 1)
        if len(body) > MAX_FRAME:
            raise ValueError("response_frame_limit")
        if response.status != 200:
            # Server diagnostics may contain inputs; never copy them to a receipt.
            raise ValueError("model_http_" + str(response.status))
        return json.loads(body)
    finally:
        connection.close()


def main():
    start = read_frame()
    config, manifest = start["configuration"], start["assets"]
    model_directory = Path(config["model_directory"])
    runtime_directory = Path(config["runtime_directory"])
    slot = int(os.environ["NAOME_DECISION_SLOT_FD"])
    os.fstat(slot)
    # A bounded stdin lifeline stops the server during loading or blocked HTTP.
    # The native worker independently kills this entire process group.
    stopped, inbox = threading.Event(), queue.Queue(maxsize=1)
    custody, child = threading.RLock(), None

    def stop(*unused):
        stopped.set()
        with custody:
            if child is not None:
                child.terminate()
                try:
                    child.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)

    def receive():
        try:
            while True:
                frame = read_frame()
                if frame is None:
                    break
                inbox.put_nowait(frame)
        except Exception:
            pass
        finally:
            stop()

    threading.Thread(target=receive, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    try:
        verify(model_directory, manifest["model"]["files"])
        verify(runtime_directory, manifest["runtime"]["platforms"][start["platform"]]["files"], True)
        with tempfile.TemporaryDirectory(prefix="naome-d1-", dir="/tmp") as temporary:
            directory = Path(temporary)
            key, endpoint = secrets.token_hex(32), str(directory / "model.sock")
            key_path = directory / "key"
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as output:
                output.write(key)
            tokens, threads = str(config["max_input_tokens"]), str(config["threads"])
            args = [str(runtime_directory / "llama-server"), "-m",
                str(model_directory / manifest["model"]["files"][0]["file"]),
                "--host", endpoint, "--api-key-file", str(key_path),
                "-ngl", "0", "-np", "1", "-c", tokens, "-b", tokens, "-ub", tokens,
                "-t", threads, "-tb", threads, "--no-mmproj", "--no-cache-prompt",
                "--no-context-shift", "--no-ui", "--no-warmup", "--no-repack", "--fit", "off"]
            with custody:
                if stopped.is_set():
                    return
                child = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    close_fds=True, pass_fds=(slot,))
            until = time.monotonic() + 120
            while not stopped.is_set():
                if child.poll() is not None:
                    raise ValueError("model_load_failed")
                try:
                    if call(endpoint, key, "/health").get("status") == "ok":
                        break
                except (OSError, ValueError, http.client.HTTPException):
                    pass
                if time.monotonic() >= until:
                    raise ValueError("model_load_timeout")
                stopped.wait(0.05)
            if stopped.is_set():
                return
            emit({"kind": "ready", "model": start["model"], "pid": os.getpid(),
                "runtime": {"llama_cpp": manifest["runtime"]["source"],
                            "quantization": "Q8_0", "device": "cpu",
                            "python": sys.version.split()[0]}})
            while not stopped.is_set():
                try:
                    frame = inbox.get(timeout=0.05)
                except queue.Empty:
                    continue
                began = time.monotonic()
                sequence, request = frame["sequence"], frame["input"]
                try:
                    alternatives = request["alternatives"]
                    texts = [request["state"], request["instruction"]] + [a["description"] for a in alternatives]
                    # The pinned d1 template parses reserved control spellings.
                    # Reject those bytes explicitly instead of altering input.
                    if any("<|" in text or "|>" in text for text in texts):
                        raise ValueError("reserved_token_delimiter")
                    result = call(endpoint, key, "/v1/systemone", {
                        "state": request["state"], "questions": {"decision": {
                            "type": "choice", "instructions": request["instruction"],
                            "criteria": {a["id"]: a["description"] for a in alternatives}}}})
                    answer, usage = result["answers"]["decision"], result["usage"]
                    probabilities = answer["probabilities"]
                    if (answer["type"] != "choice" or set(probabilities) != {a["id"] for a in alternatives}
                            or any(type(p) not in (int, float) or not math.isfinite(p) or not 0 <= p <= 1
                                   for p in probabilities.values())
                            or abs(sum(probabilities.values()) - 1) > 1e-5):
                        raise ValueError("invalid_probabilities")
                    tokens = usage["input_tokens"]
                    # The pinned template contains no truncation; context shift
                    # is disabled and the server rejects an oversized prompt.
                    if type(tokens) is not int or not 0 < tokens < config["max_input_tokens"] or usage["output_tokens"] != 0:
                        raise ValueError("input_token_limit")
                    emit({"kind": "answer", "sequence": sequence, "distribution": {
                        "request": frame["request"], "model": start["model"],
                        "probabilities": [{"option": a["id"], "probability": probabilities[a["id"]]}
                            for a in alternatives], "input_tokens": tokens,
                        "elapsed_ms": round((time.monotonic() - began) * 1000),
                        # Native custody supplies the sampled process-group peak.
                        "peak_rss_bytes": 0, "accelerator_bytes": 0, "truncated": False}})
                except Exception as error:
                    known = {"reserved_token_delimiter", "invalid_probabilities", "input_token_limit"}
                    code = str(error) if isinstance(error, ValueError) and str(error) in known else "inference_failed"
                    emit({"kind": "error", "sequence": sequence, "code": "failed", "error": code})
    finally:
        stop()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # No request text, server response body or private API key is logged.
        print(type(error).__name__ + ": adapter failed", file=sys.stderr, flush=True)
        sys.exit(1)
