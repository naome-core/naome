#!/usr/bin/env python3
"""Run finite Rust-only learning trials and retain source/resource receipts."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

EXECUTION_SECONDS = 7200
RSS_BYTES = 4 * 1024**3
ARTIFACT_BYTES = 2 * 1024**3


def sha256(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def group_members(group):
    result = subprocess.run(
        ["/bin/ps", "-eo", "pid=,pgid=,rss="], check=True,
        capture_output=True, text=True,
    )
    return [(int(pid), int(rss) * 1024) for line in result.stdout.splitlines()
            for pid, pgid, rss in [line.split()] if int(pgid) == group]


def output_size(directory):
    return sum(p.stat().st_size for p in directory.rglob("*") if p.is_file())


def native_peak_rss(raw):
    """Parse GNU time's KiB label and BSD time's byte label on either host."""
    gnu = re.findall(r"^\s*maximum resident set size \(kbytes\):\s*(\d+)\s*$",
                     raw, re.IGNORECASE | re.MULTILINE)
    bsd = re.findall(r"^\s*(\d+)\s+maximum resident set size\s*$",
                     raw, re.IGNORECASE | re.MULTILINE)
    return max([0] + [int(value) * 1024 for value in gnu] + [int(value) for value in bsd])


def verify_binary_identity(binary, toolchain, source_tree):
    identity = json.loads(subprocess.check_output([str(binary), "--identity"], text=True))
    if identity.get("schema") != 1 or identity.get("compiler") != toolchain:
        raise RuntimeError(f"binary was built by a different compiler or identity schema: {identity}")
    if identity.get("source_tree") != source_tree or identity.get("source_clean") is not True:
        raise RuntimeError(f"binary does not match the current clean source tree: {identity}")
    return identity


@contextmanager
def snapshot_inputs(binary, config):
    """Capture private input bytes before checking or executing them."""
    stop = [None]
    previous = {s: signal.getsignal(s) for s in [signal.SIGTERM, signal.SIGINT]}

    def request_stop(signum, _frame):
        stop[0] = signum

    def check_stop():
        if stop[0] is not None:
            raise RuntimeError(f"supervisor received {signal.Signals(stop[0]).name} during input preflight")

    for signum in previous:
        signal.signal(signum, request_stop)
    try:
        with tempfile.TemporaryDirectory(prefix="naome-proof-lab-inputs-") as name:
            directory = Path(name)
            frozen_binary = directory / "input-binary"
            frozen_config = directory / "input-config.json"
            shutil.copyfile(binary, frozen_binary)
            shutil.copyfile(config, frozen_config)
            frozen_binary.chmod(0o555)
            frozen_config.chmod(0o444)
            check_stop()
            yield frozen_binary, frozen_config, check_stop
            check_stop()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def terminate(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
    remaining = group_members(process.pid)
    if remaining:
        os.killpg(process.pid, signal.SIGKILL)
        deadline = time.monotonic() + 10
        while group_members(process.pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        if group_members(process.pid):
            raise RuntimeError("owned process group is still live after termination")


def run_stage(command, directory, stage, remaining_seconds,
              memory_limit=RSS_BYTES, artifact_limit=ARTIFACT_BYTES):
    log = directory / f"{stage}.log"
    resources = directory / f"{stage}-resources.txt"
    timed = (["/usr/bin/time", "-l"] if sys.platform == "darwin"
             else ["/usr/bin/time", "-v"])
    started = time.monotonic()
    peak = 0
    failure = None
    process = None
    with log.open("xb") as stream:
        stop = [None]
        previous = {s: signal.getsignal(s) for s in [signal.SIGTERM, signal.SIGINT]}

        def request_stop(signum, _frame):
            # Do not raise asynchronously across Popen or cleanup boundaries.
            stop[0] = signum

        for signum in previous:
            signal.signal(signum, request_stop)
        try:
            process = subprocess.Popen(
                timed + ["-o", str(resources)] + command,
                stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
            )
            (directory / f"{stage}-started.json").write_text(json.dumps(
                {"pid": process.pid, "group": process.pid, "command": command}) + "\n")
            while process.poll() is None:
                if stop[0] is not None:
                    failure = f"supervisor received {signal.Signals(stop[0]).name}"
                    break
                peak = max(peak, sum(rss for _, rss in group_members(process.pid)))
                if time.monotonic() - started > remaining_seconds:
                    failure = "shared active execution ceiling"
                elif peak > memory_limit:
                    failure = "process-group RSS ceiling"
                elif output_size(directory) > artifact_limit:
                    failure = "generated artifact ceiling"
                if failure:
                    break
                time.sleep(0.2)
        finally:
            try:
                if process is not None:
                    terminate(process)
            finally:
                for signum, handler in previous.items():
                    signal.signal(signum, handler)
    # A stop received after the child exits still interrupts the workflow.
    if stop[0] is not None:
        failure = failure or f"supervisor received {signal.Signals(stop[0]).name}"
    # /usr/bin/time records the native high-water RSS between polling samples.
    raw = resources.read_text() if resources.exists() else ""
    peak = max(peak, native_peak_rss(raw))
    if peak > memory_limit:
        failure = failure or "native peak RSS exceeded ceiling"
    size = output_size(directory)
    if size > artifact_limit:
        failure = failure or "retained artifacts exceeded ceiling"
    return {"stage": stage, "command": command, "pid": process.pid,
            "exit_code": process.returncode, "seconds": time.monotonic() - started,
            "peak_rss_bytes": peak, "artifact_bytes": size,
            "failure": failure, "log_sha256": sha256(log),
            "termination_signal": stop[0],
            "resource_log_sha256": sha256(resources) if resources.exists() else None,
            "owned_group_empty": not group_members(process.pid)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    binary = args.binary.resolve()
    config = args.config.resolve()
    directory = args.directory.resolve()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    source_tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo, text=True)
    if status.strip():
        raise RuntimeError("freeze experiments only on clean committed source")
    pinned = re.search(r'^channel\s*=\s*"([^"]+)"', (repo / "rust-toolchain.toml").read_text(), re.MULTILINE).group(1)
    toolchain = subprocess.check_output(["rustc", "--version"], cwd=repo, text=True).strip()
    cargo = subprocess.check_output(["cargo", "--version"], cwd=repo, text=True).strip()
    if not toolchain.startswith(f"rustc {pinned} ") or not cargo.startswith(f"cargo {pinned} "):
        raise RuntimeError(f"PATH does not use the pinned {pinned} toolchain: {toolchain}; {cargo}")
    source_binary = str(binary)
    source_config = str(config)
    retained_binary = directory / "input-binary"
    retained_config = directory / "input-config.json"
    created = False
    try:
        with snapshot_inputs(binary, config) as (frozen_binary, frozen_config, check_stop):
            identity = verify_binary_identity(frozen_binary, toolchain, source_tree)
            check_stop()
            # Validate the captured bytes before the attempt directory or lock.
            subprocess.run([str(frozen_binary), "--validate-config", str(frozen_config)], check=True)
            check_stop()
            binary_digest = sha256(frozen_binary)
            config_digest = sha256(frozen_config)
            directory.mkdir(mode=0o700, parents=True, exist_ok=False)
            created = True
            shutil.move(str(frozen_binary), retained_binary)
            shutil.move(str(frozen_config), retained_config)
            check_stop()
    except BaseException:
        if created:
            retained_binary.unlink(missing_ok=True)
            retained_config.unlink(missing_ok=True)
            directory.rmdir()
        raise
    binary, config = retained_binary, retained_config
    # Successful input snapshots are retained and counted as attempt artifacts.
    receipt = {"schema": 1, "source_revision": revision,
               "source_tree": source_tree, "binary_source_tree": identity["source_tree"],
               "binary_sha256": binary_digest, "config_sha256": config_digest,
               "input_snapshots": {"binary": binary.name, "config": config.name,
                                   "source_binary_path": source_binary,
                                   "source_config_path": source_config},
               "platform": platform.platform(), "machine": platform.machine(),
               "cpu": subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip() if sys.platform == "darwin" else platform.processor(),
               "toolchain": toolchain, "cargo": cargo, "binary_compiler": identity["compiler"],
               "profile": "release", "training_implementation": "owned Rust CPU f64",
               "ceilings": {"active_execution_seconds": EXECUTION_SECONDS,
                            "rss_bytes": RSS_BYTES, "artifact_bytes": ARTIFACT_BYTES},
               "runs": []}
    elapsed = 0.0
    for stage in ["generate", "train", "evaluate", "replay", "benchmark"]:
        if sha256(binary) != binary_digest or sha256(config) != config_digest:
            raise RuntimeError("retained input snapshot changed before stage launch")
        result = run_stage([str(binary), stage, str(config), str(directory)],
                           directory, stage, EXECUTION_SECONDS - elapsed)
        elapsed += result["seconds"]
        receipt["runs"].append(result)
        receipt["active_execution_seconds"] = elapsed
        (directory / "execution.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        if (result["failure"] or result["termination_signal"]
                or result["exit_code"] or not result["owned_group_empty"]):
            return 1
    manifest = {p.name: {"bytes": p.stat().st_size, "sha256": sha256(p)}
                for p in directory.iterdir() if p.is_file()}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
