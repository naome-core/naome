"""One immutable Qwen instance; kernel leases survive broker and client loss."""
import argparse
import array
import fcntl
import hashlib
import importlib.util
import importlib.metadata
import json
import os
from pathlib import Path
import resource
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

LIMIT = 128 * 1024
SEND_LOCK = threading.Lock()
BACKEND_MODELING_SHA = "bf1c6b2a43cf7c36fb79f37c981424dd6ae78eb863fcaa5d2a37e76c9828611d"
PROVIDER_SHA = "6656c6a7951610bb46ec809e5d46b6479f9197121c1b7936b1de12acd3e6d3bc"


def read_exact(channel, size):
    result = bytearray()
    while len(result) < size:
        value = channel.recv(size - len(result))
        if not value:
            raise EOFError("model channel EOF")
        result.extend(value)
    return bytes(result)


def receive(channel):
    fds = []
    try:
        header, ancillary, flags, _ = channel.recvmsg(4, socket.CMSG_SPACE(16 * array.array("i").itemsize))
        for level, kind, value in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise ValueError("unsupported ancillary message")
            descriptors = array.array("i")
            descriptors.frombytes(value[:len(value) - len(value) % descriptors.itemsize])
            fds.extend(descriptors)
        if flags & socket.MSG_CTRUNC or not header:
            raise ValueError("truncated ancillary data or EOF")
        header += read_exact(channel, 4 - len(header))
        size = struct.unpack(">I", header)[0]
        if not 0 < size <= LIMIT:
            raise ValueError("model frame byte limit")
        raw = read_exact(channel, size)
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
        return value, fds
    except BaseException:
        for fd in fds:
            os.close(fd)
        raise


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def invalid_constant(_):
    raise ValueError("nonfinite JSON")


def send(channel, value):
    data = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
    if len(data) > LIMIT:
        raise ValueError("model output byte limit")
    with SEND_LOCK:
        channel.sendall(struct.pack(">I", len(data)) + data)


def lease(fd):
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1:
        raise ValueError("model kernel lease identity differs")
    os.set_inheritable(fd, False)


def lifeline(stream):
    # Independent of Torch's synchronous forward; EOF kills the owned group.
    try:
        while stream.read(1):
            pass
    finally:
        os.killpg(os.getpgrp(), signal.SIGKILL)


def keeper(options):
    os.setsid()
    lease(options.lease_fd)
    expected = Path("/tmp") / ("naome-interest-uid-" + str(os.geteuid())) / "model.lock"
    current = os.fstat(options.lease_fd)
    path = os.stat(expected, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (path.st_dev, path.st_ino):
        raise ValueError("global model lease inode differs")
    probe = os.open(expected, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise ValueError("global model lease is not held")
    finally:
        os.close(probe)
    child = subprocess.Popen(
        [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker", "--channel-fd", str(options.channel_fd),
         "--lease-fd", str(options.lease_fd), "--model", str(options.model)],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        pass_fds=(options.channel_fd, options.lease_fd),
        env={"PATH": "/usr/bin:/bin", "PYTORCH_ENABLE_MPS_FALLBACK": "0"},
    )
    failure_channel=socket.socket(fileno=options.channel_fd)
    threading.Thread(target=lifeline, args=(sys.stdin.buffer,), daemon=True).start()
    try:
        returncode = child.wait()
        if returncode:
            failure_channel.settimeout(0.2)
            try:send(failure_channel,{"kind":"failed","reason":"model_worker_exit","returncode":returncode})
            except BaseException:pass
            raise RuntimeError("model worker failed")
    finally:
        child.stdin.close()
        # The current living keeper anchors this group. Never signal a saved PID.
        os.killpg(os.getpgrp(), signal.SIGKILL)


def stop_provider(code):
    # Exiting the actual worker closes every active kernel lease. The living
    # keeper observes its Child exit and cleans its own anchored group.
    os._exit(code)


def required_samples(channel, holder, heartbeat, stop, reader=resource.getrusage):
    while not stop.is_set():
        try:
            usage = reader(resource.RUSAGE_SELF)
            rss = usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024
            if rss > 12 * 1024**3:
                stop_provider(72)
            values = {"kind": "telemetry", "at": time.monotonic(), "pid": os.getpid(),
                      "rss_high_water": rss, "user_cpu": usage.ru_utime, "system_cpu": usage.ru_stime}
            model = holder.get("model")
            if model is not None:
                values.update(mps_tensor=model.torch.mps.current_allocated_memory(),
                              mps_driver=model.torch.mps.driver_allocated_memory())
            send(channel, values)
            heartbeat[0] = time.monotonic()
        except BaseException:
            stop_provider(73)
        stop.wait(0.25)


def monitor_samples(stop, heartbeat):
    while not stop.wait(0.1):
        if time.monotonic() - heartbeat[0] > 1:
            stop_provider(75)


def worker(options):
    lease(options.lease_fd)
    expected = Path("/tmp") / ("naome-interest-uid-" + str(os.geteuid())) / "model.lock"
    current = os.fstat(options.lease_fd)
    path = os.stat(expected, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (path.st_dev, path.st_ino):
        raise ValueError("global model lease inode differs")
    probe = os.open(expected, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise ValueError("global model lease is not held")
    finally:
        os.close(probe)
    threading.Thread(target=lifeline, args=(sys.stdin.buffer,), daemon=True).start()
    channel = socket.socket(fileno=options.channel_fd)
    path = Path(__file__).with_name("qwen.py")
    if hashlib.sha256(path.read_bytes()).hexdigest() != PROVIDER_SHA:
        raise ValueError("resident provider source differs")
    spec = importlib.util.spec_from_file_location("naome_qwen", path)
    qwen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(qwen)
    backend=Path(importlib.metadata.distribution("transformers").locate_file("transformers/modeling_utils.py"))
    if hashlib.sha256(backend.read_bytes()).hexdigest()!=BACKEND_MODELING_SHA:
        raise ValueError("qualified backend modeling source differs")
    manifest = qwen.parse_json(path.with_name("model.lock.json").read_bytes())
    started = time.monotonic()
    def observe(stage, values):
        send(channel, {"kind": "stage", "stage": stage, "at": time.monotonic() - started})
    holder = {}
    heartbeat = [time.monotonic()]
    sampled = threading.Event()
    threading.Thread(target=required_samples, args=(channel, holder, heartbeat, sampled), daemon=True).start()
    threading.Thread(target=monitor_samples, args=(sampled, heartbeat), daemon=True).start()
    model = qwen.ResidentModel(options.model, "mps", manifest, "cpu-staged-mps-v1", observe)
    holder["model"] = model
    send(channel, {"kind": "ready", "schema": 1, "model_revision": qwen.MODEL_REVISION,
                   "manifest_hash": qwen.MODEL_MANIFEST_HASH, "prompt_version": qwen.PROMPT_VERSION,
                   "prompt_hash": hashlib.sha256(qwen.PROMPT.encode()).hexdigest(),
                   "template_hash": model.template_hash, "labels": qwen.LABELS,
                   "inventory_hash": model.inventory_hash, "model_instance": model.model_object_id,
                   "parameter_bytes": qwen.MODEL_PARAMETER_BYTES, "tensor_inventory": model.tensor_inventory, "device": model.device,
                   "load_strategy": model.load_strategy, "verify_ms": model.verify_ms,
                   "load_ms": model.load_ms, "warm_ms": model.warm_ms, "pid": os.getpid()})
    for _ in range(qwen.MAX_DECISIONS):
        value, fds = receive(channel)
        try:
            if len(fds) != 1:
                raise ValueError("one node slot required")
            lease(fds[0])
            qwen.exact_fields(value, ["kind", "nonce", "contract", "client", "generation", "transport_id", "remaining_ms", "deadline_ns", "owner", "request"])
            owner = value["owner"]
            qwen.exact_fields(owner, ["version", "revision", "digest", "interest", "text_sha256"])
            request = qwen.validate_request(value["request"])
            if owner["version"] != 1 or owner["revision"] != request["profile"]["revision"] or owner["interest"] != request["profile"]["text"] or owner["text_sha256"] != hashlib.sha256(owner["interest"].encode()).hexdigest():
                raise ValueError("native owner binding differs")
            qwen.identity(owner["digest"])
            send(channel, {"kind": "lease_held", "transport_id": value["transport_id"]})
            if type(value["deadline_ns"]) is not int or value["deadline_ns"]<=time.clock_gettime_ns(time.CLOCK_MONOTONIC):
                for fd in fds:os.close(fd)
                fds=[]
                send(channel,{"kind":"declined","reason":"original_deadline","transport_id":value["transport_id"]})
                continue
            result = model.score(request)
            model.torch.mps.synchronize()
            if time.clock_gettime_ns(time.CLOCK_MONOTONIC)>=value["deadline_ns"]:
                raise TimeoutError("original query deadline")
            result.update(device=model.device, load_strategy=model.load_strategy, inventory_hash=model.inventory_hash, model_instance=model.model_object_id)
            result.update(kind="decision", schema=1, transport_id=value["transport_id"],
                          request_id=request["request_id"], owner=owner,
                          profile_revision=request["profile"]["revision"], profile_hash=request["profile"]["hash"],
                          source_hash=request["question"]["source_hash"], resolution_id=request["question"]["resolution_id"],
                          snapshot=request["snapshot"], policy=request["policy"])
            # Lease ownership ends only after actual device quiescence.
            for fd in fds:
                os.close(fd)
            fds = []
            send(channel, result)
        finally:
            if fds:
                # Unknown effects: process exit retains the lease until reaping.
                os.killpg(os.getpgrp(), signal.SIGKILL)
    raise RuntimeError("resident lifetime request limit")


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--keeper", action="store_true")
    mode.add_argument("--worker", action="store_true")
    parser.add_argument("--channel-fd", type=int, required=True)
    parser.add_argument("--lease-fd", type=int, required=True)
    parser.add_argument("--model", type=Path, required=True)
    options = parser.parse_args()
    if options.keeper:
        keeper(options)
    else:
        worker(options)


if __name__ == "__main__":
    main()
