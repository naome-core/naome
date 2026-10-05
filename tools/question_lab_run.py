#!/usr/bin/env python3
"""Bound the offline question experiment and its binary decision process."""
import argparse
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

from proof_lab_run import (run_stage, sha256,
                           snapshot_inputs, verify_binary_identity)

POLICY = "question-catalog-experiment-v1"
FEATURES = "closed-question-full-context-graph-v1"
CPU_SECONDS = 900
RSS_BYTES = 512 * 1024**2
OUTPUT_BYTES = 64 * 1024**2
DECISION_MILLIS = 5000


def cpu_seconds(raw):
    bsd = re.search(r"([0-9.]+)\s+real\s+([0-9.]+)\s+user\s+([0-9.]+)\s+sys", raw)
    if bsd:
        return float(bsd[2]) + float(bsd[3])
    user = re.search(r"User time \(seconds\):\s*([0-9.]+)", raw)
    system = re.search(r"System time \(seconds\):\s*([0-9.]+)", raw)
    if user and system:
        return float(user[1]) + float(system[1])
    raise RuntimeError("native CPU time unavailable; cannot qualify the budget")


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def preflight(repo, binary):
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo, text=True)
    if status.strip():
        raise RuntimeError("question numerical work requires clean committed source")
    pinned = re.search(r'^channel\s*=\s*"([^"]+)"', (repo / "rust-toolchain.toml").read_text(), re.MULTILINE)[1]
    rustc = subprocess.check_output(["rustc", "--version"], cwd=repo, text=True).strip()
    cargo = subprocess.check_output(["cargo", "--version"], cwd=repo, text=True).strip()
    if not rustc.startswith(f"rustc {pinned} ") or not cargo.startswith(f"cargo {pinned} "):
        raise RuntimeError("question runner is not using the pinned compiler")
    identity = verify_binary_identity(binary, rustc, tree)
    return {"revision": revision, "tree": tree, "rustc": rustc, "cargo": cargo,
            "binary_identity": identity, "platform": platform.platform(),
            "machine": platform.machine()}


def numerical(binary, config, review_path, directory, repo):
    evidence = preflight(repo, binary)
    with snapshot_inputs(binary, config) as (frozen_binary, frozen_config, stopped):
        verify_binary_identity(frozen_binary, evidence["rustc"], evidence["tree"])
        subprocess.run([str(frozen_binary), "--validate-question-config", str(frozen_config)], check=True)
        review_bytes = review_path.read_bytes()
        if len(review_bytes) > 1024 * 1024:
            raise RuntimeError("label-review receipt ceiling")
        review = json.loads(review_bytes)
        if review.get("accepted") is not True or not review.get("reviewer"):
            raise RuntimeError("independent question labels are not accepted")
        stopped()
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        shutil.move(str(frozen_binary), directory / "input-binary")
        shutil.move(str(frozen_config), directory / "input-config.json")
        (directory / "question-label-review.json").write_bytes(review_bytes)
        stopped()
    binary = directory / "input-binary"
    config = directory / "input-config.json"
    bindings = {"binary": sha256(binary), "config": sha256(config),
                "label_review": sha256(directory / "question-label-review.json")}
    receipt = {"schema": 1, "source": evidence, "bindings": bindings,
               "implementation": "owned Rust graph network, CPU f64",
               "ceilings": {"active_cpu_seconds": CPU_SECONDS,
                            "stricter_shared_wall_seconds": CPU_SECONDS,
                            "rss_bytes": RSS_BYTES, "retained_output_bytes": OUTPUT_BYTES},
               "runs": [], "active_cpu_seconds": 0.0, "active_wall_seconds": 0.0,
               "complete": False}
    for stage in ["generate", "train", "evaluate", "replay"]:
        if sha256(binary) != bindings["binary"] or sha256(config) != bindings["config"] or sha256(directory / "question-label-review.json") != bindings["label_review"]:
            raise RuntimeError("captured question input changed before stage launch")
        result = run_stage([str(binary), f"questions-{stage}", str(config), str(directory)],
                           directory, f"question-{stage}",
                           CPU_SECONDS - receipt["active_wall_seconds"],
                           memory_limit=RSS_BYTES, artifact_limit=OUTPUT_BYTES)
        receipt["active_wall_seconds"] += result["seconds"]
        try:
            measured = cpu_seconds((directory / f"question-{stage}-resources.txt").read_text())
        except (OSError, RuntimeError) as error:
            measured = None
            result["failure"] = result["failure"] or str(error)
        result["native_cpu_seconds"] = measured
        if measured is not None:
            receipt["active_cpu_seconds"] += measured
        if receipt["active_cpu_seconds"] > CPU_SECONDS:
            result["failure"] = result["failure"] or "shared native CPU ceiling exceeded"
        if stage == "generate" and not result["failure"] and result["exit_code"] == 0:
            freeze = json.loads((directory / "question-freeze.json").read_text())
            if freeze["corpus_sha256"] != review.get("corpus_sha256") or freeze["fixtures_sha256"] != review.get("fixtures_sha256"):
                result["failure"] = "label review is for different frozen questions"
        receipt["runs"].append(result)
        # This single owned journal advances once per new stage, never restarts work.
        (directory / "question-execution.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        if result["failure"] or result["termination_signal"] or result["exit_code"] or not result["owned_group_empty"]:
            return 1
    receipt["complete"] = True
    (directory / "question-execution.json").write_text(json.dumps(receipt, indent=2) + "\n")
    save(directory / "question-manifest.json", {p.name: {"bytes": p.stat().st_size, "sha256": sha256(p)} for p in directory.iterdir() if p.is_file()})
    return 0


def decline(reason, raw_input_digest, milliseconds):
    return {"schema": 1, "decision": "DECLINE", "reason": reason,
            "policy": POLICY, "feature_schema": FEATURES,
            "raw_input_sha256": raw_input_digest,
            "question_id": None, "elapsed_millis": milliseconds,
            "checks": [{"id": f"GF{i:02}", "status": "FAIL" if i == 8 else "NOT_RUN",
                        "reason": reason if i == 8 else None} for i in range(1, 11)]}


def decision_members(group):
    """Bound process enumeration within the decision's cleanup reservation."""
    result = subprocess.run(["/bin/ps", "-eo", "pid=,pgid=,rss="], check=True,
                            capture_output=True, text=True, timeout=0.05)
    return [(int(pid), int(rss) * 1024) for line in result.stdout.splitlines()
            for pid, pgid, rss in [line.split()] if int(pgid) == group]


def decision_output_size(directory, deadline):
    total = 0
    entries = 0
    for parent, directories, files in os.walk(directory, followlinks=False):
        entries += len(directories) + len(files)
        if entries > 2048 or time.monotonic() >= deadline:
            raise ValueError("decision output enumeration ceiling")
        for name in files:
            total += (Path(parent) / name).stat().st_size
            if total > OUTPUT_BYTES:
                return total
    return total


def release_owned_lock(pid, group_empty):
    """A killed Rust child cannot run Drop; remove only its exact PID lock."""
    if not group_empty:
        return
    lock = Path(os.environ.get("TMPDIR") or tempfile.gettempdir()) / "naome-proof-lab.lock"
    try:
        with lock.open("rb") as stream:
            identity = os.fstat(stream.fileno())
            owned = stream.read(32) == f"{pid}\n".encode()
        current = lock.stat()
        if owned and (identity.st_dev, identity.st_ino) == (current.st_dev, current.st_ino):
            lock.unlink()
    except FileNotFoundError:
        pass


def run_decision(binary, config, directory, decision_millis=DECISION_MILLIS):
    """Kill one owned process on expiry; no human wait or automatic retry."""
    start = time.monotonic()
    deadline = start + min(decision_millis, DECISION_MILLIS) / 1000
    process = None
    raw_digest = None
    failure = None
    peak = 0
    group_empty = True
    previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    stopped = [None]

    def stop(signum, _frame):
        stopped[0] = signum

    def kill_owned():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    for signum in previous:
        signal.signal(signum, stop)
    try:
        request = directory / "question-request.json"
        with request.open("rb") as stream:
            raw = stream.read(2 * 1024**2 + 1)
        if len(raw) > 2 * 1024**2:
            failure = "RESOURCE_LIMIT"
        else:
            raw_digest = hashlib.sha256(raw).hexdigest()
        if (directory / "question-decision.json").exists():
            failure = failure or "ASSESSMENT_UNAVAILABLE"
        if not failure:
            with (directory / "question-decision-process.log").open("xb") as stream:
                process = subprocess.Popen([str(binary), "questions-decide", str(config), str(directory)],
                                           stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                while process.poll() is None:
                    # Reserve process enumeration, killing, reaping and receipt output.
                    if time.monotonic() >= deadline - min(0.25, decision_millis / 2000):
                        failure = "DECISION_DEADLINE"
                    elif stopped[0] is not None:
                        failure = "ASSESSMENT_UNAVAILABLE"
                    else:
                        peak = max(peak, sum(rss for _, rss in decision_members(process.pid)))
                        if peak > RSS_BYTES or decision_output_size(directory, deadline) > OUTPUT_BYTES:
                            failure = "RESOURCE_LIMIT"
                    if failure:
                        break
                    time.sleep(0.005)
    except (OSError, ValueError, subprocess.SubprocessError):
        failure = failure or "ASSESSMENT_UNAVAILABLE"
    finally:
        if process is not None:
            group_empty = False
            try:
                if process.poll() is None:
                    kill_owned()
                process.wait(timeout=0.05)
                members = decision_members(process.pid)
                if members:
                    kill_owned()
                    failure = failure or "ASSESSMENT_UNAVAILABLE"
                    members = decision_members(process.pid)
                group_empty = not members
                release_owned_lock(process.pid, group_empty)
            except (OSError, ValueError, subprocess.SubprocessError):
                failure = failure or "ASSESSMENT_UNAVAILABLE"
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    if process is not None and process.returncode != 0:
        failure = failure or "ASSESSMENT_UNAVAILABLE"
    if stopped[0] is not None or not group_empty:
        failure = failure or "ASSESSMENT_UNAVAILABLE"
    if time.monotonic() >= deadline:
        failure = "DECISION_DEADLINE"
    if not failure:
        try:
            if decision_output_size(directory, deadline) > OUTPUT_BYTES:
                failure = "RESOURCE_LIMIT"
        except (OSError, ValueError):
            failure = "RESOURCE_LIMIT"
    result = None
    if not failure:
        try:
            with (directory / "question-decision.json").open("rb") as stream:
                raw_receipt = stream.read(2 * 1024**2 + 1)
            if len(raw_receipt) > 2 * 1024**2:
                raise ValueError("receipt ceiling")
            result = json.loads(raw_receipt)
            checks = result["checks"]
            if (result.get("schema") != 1 or result["decision"] not in ("APPROVE", "DECLINE")
                    or [check["id"] for check in checks] != [f"GF{i:02}" for i in range(1, 11)]
                    or any(check["status"] not in ("PASS", "FAIL", "NOT_RUN") for check in checks)
                    or result.get("policy") != POLICY or result.get("feature_schema") != FEATURES
                    or result.get("input_sha256") != raw_digest
                    or result.get("input_digest_kind") != "raw-submission-json-v1"
                    or not isinstance(result.get("reason"), str)
                    or (result["decision"] == "APPROVE" and any(check["status"] != "PASS" for check in checks))):
                raise ValueError("invalid binary receipt")
        except (OSError, KeyError, TypeError, ValueError):
            failure = "ASSESSMENT_UNAVAILABLE"
    if time.monotonic() >= deadline:
        failure = "DECISION_DEADLINE"
    milliseconds = int((time.monotonic() - start) * 1000)
    if failure:
        result = decline(failure, raw_digest, milliseconds)
    result["raw_input_sha256"] = raw_digest
    result["process_supervision"] = {"deadline_millis": min(decision_millis, DECISION_MILLIS), "elapsed_millis": milliseconds,
                                     "exit_code": process.returncode if process else None,
                                     "peak_sampled_rss_bytes": peak,
                                     "owned_group_empty": group_empty,
                                     "automatic_retry": False}
    try:
        save(directory / "question-final-decision.json", result)
    except OSError as error:
        supervision = result["process_supervision"]
        result = decline("ASSESSMENT_UNAVAILABLE", raw_digest, milliseconds)
        result["process_supervision"] = supervision
        result["receipt_retention_error"] = type(error).__name__
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["experiment", "decide"])
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--label-review", type=Path)
    args = parser.parse_args()
    if args.mode == "experiment":
        if args.label_review is None:
            parser.error("experiment requires --label-review")
        return numerical(args.binary.resolve(), args.config.resolve(), args.label_review.resolve(),
                         args.directory.resolve(), Path(__file__).resolve().parents[1])
    result = run_decision(args.binary.resolve(), args.config.resolve(), args.directory.resolve())
    print(json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
