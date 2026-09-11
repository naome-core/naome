#!/usr/bin/env python3
"""Read-only health supervision for one private fixed-validator devnet role."""
import argparse
import collections
import fcntl
import hashlib
import http.server
import json
import logging
import logging.handlers
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from proxy import Proxy

MAX_FRAME = 16_384
MAX_DISK = 512 * 1024 * 1024
EVENTS = {
    "ready", "publisher_ready", "finality", "peer_session", "error", "stopped",
    "publisher_stopped", "publisher_offer_loaded", "publisher_offer_receipted",
    "acquisition_started", "acquisition_progress", "acquisition_complete",
    "acquisition_failed", "acquisition_cancelled", "supervisor_acquisition_waiting",
    "publication_prepared", "publication_complete", "publication_recovered",
    "timer_due", "driver_blocked", "driver_rejected", "admission",
}


def atomic(path, value):
    """One agent owns this diagnostic file; it is never signing authority."""
    path = Path(path)
    temporary = path.with_suffix(".pending")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def resources(pid, root):
    rss = cpu = None
    if sys.platform == "linux":
        try:
            rss = int(Path(f"/proc/{pid}/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            cpu = (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
        except (OSError, ValueError, IndexError):
            pass
    size = count = 0
    for directory, _, files in os.walk(root, followlinks=False):
        for name in files:
            count += 1
            if count > 100_000:
                raise RuntimeError("role file-count limit")
            try:
                size += os.stat(Path(directory) / name, follow_symlinks=False).st_size
            except FileNotFoundError:
                pass  # Concurrent atomic diagnostic/bundle replacement.
    return {"rss_bytes": rss, "cpu_seconds": cpu, "disk_bytes": size, "file_count": count}


class State:
    def __init__(self, role, stall_seconds):
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.progress = self.started
        self.stall_seconds = stall_seconds
        self.publisher = role["publisher"]
        self.peers = set()
        self.allowed_peers = {r["peer_id"] for r in role["deployment"]["roles"]}
        self.counts = collections.Counter()
        self.errors = collections.deque(maxlen=8)
        self.value = {
            "schema_version": 0, "role": role["name"], "generation": str(uuid.uuid4()),
            "publisher": self.publisher, "ready": False, "child_exit": None,
            "finalized_height": 0, "head": None, "acquisition_active": False,
            "last_receipts": {}, "resources": {}, "peak_rss_bytes": None,
        }

    def event(self, event):
        if not isinstance(event, dict):
            raise ValueError("non-object process report")
        kind = event.get("event")
        if kind == "command_result":
            outcome = event.get("outcome", {})
            if isinstance(outcome, dict) and outcome.get("event") in EVENTS:
                kind = outcome["event"]
        with self.lock:
            self.counts[kind if kind in EVENTS else "other"] += 1
            if kind in ("ready", "publisher_ready"):
                self.value["ready"] = True
            if kind == "acquisition_started":
                self.value["acquisition_active"] = True
            if kind in ("acquisition_complete", "acquisition_failed", "acquisition_cancelled"):
                self.value["acquisition_active"] = False
            state = event.get("state", {})
            driver = state.get("driver") if isinstance(state, dict) else None
            if isinstance(driver, dict) and isinstance(driver.get("height"), str):
                height = int(driver["height"]) - 1
                if height < self.value["finalized_height"]:
                    raise ValueError("reported height regressed")
                if height > self.value["finalized_height"] or kind == "ready":
                    self.progress = time.monotonic()
                    self.value["finalized_height"] = height
                    self.value["head"] = driver.get("head")
            if kind == "peer_session" and event.get("peer") in self.allowed_peers:
                if event.get("state") == "established":
                    self.peers.add(event["peer"])
                else:
                    self.peers.discard(event["peer"])
            if kind == "publisher_offer_receipted" and event.get("peer_id") in self.allowed_peers:
                self.value["last_receipts"][event["peer_id"]] = event.get("offer_sha256")
            if kind == "error":
                self.errors.append(str(event.get("code", "process_error"))[:160])

    def failure(self, text):
        with self.lock:
            self.errors.append(str(text)[:160])

    def sample(self, values, child_exit):
        with self.lock:
            self.value["resources"] = values
            self.value["child_exit"] = child_exit
            if values.get("rss_bytes") is not None:
                self.value["peak_rss_bytes"] = max(values["rss_bytes"], self.value["peak_rss_bytes"] or 0)

    def snapshot(self):
        with self.lock:
            value = dict(self.value)
            value["last_receipts"] = dict(value["last_receipts"])
            value["uptime_seconds"] = round(time.monotonic() - self.started, 3)
            value["seconds_without_finality"] = round(time.monotonic() - self.progress, 3)
            value["stalled"] = not self.publisher and value["seconds_without_finality"] > self.stall_seconds
            value["connected_peers"] = sorted(self.peers)
            value["events"] = dict(self.counts)
            value["errors"] = list(self.errors)
            value["healthy"] = value["ready"] and value["child_exit"] is None and not value["errors"] and not value["stalled"]
            return value


def metrics(value):
    result = ["# Read-only local observations; no consensus authority."]
    for name, number in {
        "healthy": int(value["healthy"]), "finalized_height": value["finalized_height"],
        "stalled": int(value["stalled"]), "connected_peers": len(value["connected_peers"]),
        "acquisition_active": int(value["acquisition_active"]),
        "rss_bytes": value["resources"].get("rss_bytes"),
        "disk_bytes": value["resources"].get("disk_bytes"),
        "cpu_seconds": value["resources"].get("cpu_seconds"),
    }.items():
        if number is not None:
            result.append(f"naome_devnet_{name} {number}")
    for event, count in sorted(value["events"].items()):
        result.append(f'naome_devnet_events_total{{event="{event}"}} {count}')
    return "\n".join(result) + "\n"


def server(state, host, port):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            value = state.snapshot()
            if self.path in ("/status", "/health"):
                body = json.dumps(value).encode()
                content_type = "application/json"
                code = 200 if self.path == "/status" or value["healthy"] else 503
            elif self.path == "/metrics":
                body = metrics(value).encode()
                content_type = "text/plain; version=0.0.4"
                code = 200
            else:
                self.send_error(404)
                return
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    class Server(http.server.HTTPServer):
        request_queue_size = 8

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(2)
            return connection, address

    result = Server((host, port), Handler)
    threading.Thread(target=result.serve_forever, daemon=True).start()
    return result


def run(args):
    root = args.role.resolve(strict=True)
    role = json.loads((root / "role.json").read_text())
    if not 10 <= args.stall_seconds <= 3600:
        raise ValueError("stall threshold must be 10..3600 seconds")
    descriptor = os.open(root / "agent.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    owner = os.fdopen(descriptor, "r+")
    fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
    digest = hashlib.sha256()
    for name in ("role.json", "create.toml", "open.toml"):
        digest.update((root / name).read_bytes())
    binding = {"configuration_sha256": digest.hexdigest()}
    initialized = root / "initialized.json"
    attempted = root / "startup-attempted.json"
    if initialized.exists():
        if json.loads(initialized.read_text()) != binding:
            raise RuntimeError("deployment configuration changed; explicit migration required")
        mode = "open"
    else:
        if attempted.exists():
            raise RuntimeError("incomplete first startup; inspect preserved state before recovery")
        atomic(attempted, binding)
        mode = "create"
    state = State(role, args.stall_seconds)
    state.value["startup_mode"] = mode
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    web = server(state, args.bind, args.port)
    log = logging.getLogger("devnet-child")
    log.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(root / "logs" / "process.log", maxBytes=8 * 1024 * 1024, backupCount=2)
    log.addHandler(handler)
    command = [args.validator]
    if role["publisher"]:
        command.append("--publisher")
    command.append(str(root / f"{mode}.toml"))
    child = None
    proxy = None
    readers = []
    try:
        own_role = next(r for r in role["deployment"]["roles"] if r["name"] == role["name"])
        if own_role["address"] != own_role["listen"]:
            proxy = Proxy(own_role["address"], own_role["listen"], args.delay_ms)
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        state.value["child_pid"] = child.pid

        def read(stream, structured):
            try:
                while True:
                    frame = stream.readline(MAX_FRAME + 2)
                    if not frame:
                        break
                    if len(frame) > MAX_FRAME + 1 or not frame.endswith(b"\n"):
                        raise ValueError("oversized or incomplete process report")
                    text = frame.decode("utf-8")
                    log.info(text.rstrip("\n"))
                    if structured:
                        event = json.loads(text)
                        state.event(event)
                        if event.get("event") in ("ready", "publisher_ready") and mode == "create":
                            atomic(initialized, binding)
                    else:
                        state.failure("child stderr; inspect bounded process log")
            except Exception as error:
                state.failure(f"report reader: {error}")
                stop.set()
            finally:
                stream.close()

        for stream, structured in ((child.stdout, True), (child.stderr, False)):
            reader = threading.Thread(target=read, args=(stream, structured), daemon=True)
            reader.start()
            readers.append(reader)
        while not stop.wait(0.5):
            values = resources(child.pid, root)
            state.sample(values, child.poll())
            if values["disk_bytes"] > MAX_DISK:
                state.failure("sampled role disk limit exceeded")
                break
            atomic(root / "status.json", state.snapshot())
            if child.poll() is not None:
                break
    finally:
        if child is not None:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                    state.failure("graceful shutdown exceeded bound; child killed")
            for reader in readers:
                reader.join(timeout=2)
            state.sample(resources(child.pid, root), child.returncode)
        atomic(root / "status.json", state.snapshot())
        web.shutdown()
        web.server_close()
        if proxy is not None:
            proxy.close()
        handler.close()
        owner.close()
    result = state.snapshot()
    print(json.dumps({"event": "agent_stopped", "role": role["name"], "child_exit": result["child_exit"], "errors": result["errors"]}), flush=True)
    return 0 if result["child_exit"] == 0 and not result["errors"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--role", type=Path, required=True)
    run_parser.add_argument("--validator", default="naome-validator")
    run_parser.add_argument("--bind", default="127.0.0.1")
    run_parser.add_argument("--port", type=int, default=8080)
    run_parser.add_argument("--stall-seconds", type=int, default=120)
    run_parser.add_argument("--delay-ms", type=int, default=0)
    health = commands.add_parser("health")
    health.add_argument("--url", default="http://127.0.0.1:8080/health")
    status = commands.add_parser("status")
    status.add_argument("--role", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "run":
        return run(args)
    if args.command == "health":
        with urllib.request.urlopen(args.url, timeout=3) as response:
            value = json.load(response)
            return 0 if value["healthy"] else 1
    print((args.role / "status.json").read_text(), end="")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"naome-devnet-agent: {error}", file=sys.stderr)
        sys.exit(1)
