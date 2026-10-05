#!/usr/bin/env python3
"""Run finite Rust-only learning trials and retain source/resource receipts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
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
        process = subprocess.Popen(
            timed + ["-o", str(resources)] + command,
            stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            while process.poll() is None:
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
            terminate(process)
    # /usr/bin/time records the native high-water RSS between polling samples.
    raw = resources.read_text() if resources.exists() else ""
    for line in raw.splitlines():
        if "maximum resident set size" in line:
            native = int(line.strip().split()[0]) if sys.platform == "darwin" else int(line.rsplit(":", 1)[1]) * 1024
            peak = max(peak, native)
    if peak > memory_limit:
        failure = failure or "native peak RSS exceeded ceiling"
    size = output_size(directory)
    if size > artifact_limit:
        failure = failure or "retained artifacts exceeded ceiling"
    return {"stage": stage, "command": command, "pid": process.pid,
            "exit_code": process.returncode, "seconds": time.monotonic() - started,
            "peak_rss_bytes": peak, "artifact_bytes": size,
            "failure": failure, "log_sha256": sha256(log),
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
    directory.mkdir(parents=True, exist_ok=False)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo, text=True)
    if status.strip():
        raise RuntimeError("freeze experiments only on clean committed source")
    pinned = re.search(r'^channel\s*=\s*"([^"]+)"', (repo / "rust-toolchain.toml").read_text(), re.MULTILINE).group(1)
    toolchain = subprocess.check_output(["rustc", "--version"], cwd=repo, text=True).strip()
    cargo = subprocess.check_output(["cargo", "--version"], cwd=repo, text=True).strip()
    if not toolchain.startswith(f"rustc {pinned} ") or not cargo.startswith(f"cargo {pinned} "):
        raise RuntimeError(f"PATH does not use the pinned {pinned} toolchain: {toolchain}; {cargo}")
    binary_compiler = subprocess.check_output([str(binary), "--identity"], text=True).strip()
    if binary_compiler != toolchain:
        raise RuntimeError(f"binary was built by a different compiler: {binary_compiler}")
    receipt = {"schema": 1, "source_revision": revision,
               "binary_sha256": sha256(binary), "config_sha256": sha256(config),
               "platform": platform.platform(), "machine": platform.machine(),
               "cpu": subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip() if sys.platform == "darwin" else platform.processor(),
               "toolchain": toolchain, "cargo": cargo, "binary_compiler": binary_compiler,
               "profile": "release", "training_implementation": "owned Rust CPU f64",
               "ceilings": {"active_execution_seconds": EXECUTION_SECONDS,
                            "rss_bytes": RSS_BYTES, "artifact_bytes": ARTIFACT_BYTES},
               "runs": []}
    elapsed = 0.0
    for stage in ["generate", "train", "evaluate", "replay", "benchmark"]:
        result = run_stage([str(binary), stage, str(config), str(directory)],
                           directory, stage, EXECUTION_SECONDS - elapsed)
        elapsed += result["seconds"]
        receipt["runs"].append(result)
        receipt["active_execution_seconds"] = elapsed
        (directory / "execution.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        if result["failure"] or result["exit_code"] or not result["owned_group_empty"]:
            return 1
    manifest = {p.name: {"bytes": p.stat().st_size, "sha256": sha256(p)}
                for p in directory.iterdir() if p.is_file()}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
