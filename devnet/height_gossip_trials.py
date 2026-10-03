#!/usr/bin/env python3
"""Run the offline Rust experiment with per-process and aggregate ceilings."""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import resource
import signal
import subprocess
import time

SCENARIOS = ("ordinary", "equal", "delayed", "partition", "withholding",
             "duplicates", "invalid", "cheap", "sybil", "eclipse", "restart", "policy")
POSITIVE = {"ordinary", "delayed", "duplicates", "invalid", "restart"}


def run(binary, config, ceiling):
    command = [str(binary), *map(str, config)]
    started = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=ceiling)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    elapsed = time.monotonic() - started
    receipt = {"command": command, "exit": process.returncode, "timeout": timed_out,
               "wall_seconds": elapsed, "cpu_seconds": after.ru_utime + after.ru_stime
               - before.ru_utime - before.ru_stime,
               "stdout": stdout.decode(), "stderr": stderr.decode()}
    if process.returncode == 0 and not timed_out:
        receipt["result"] = json.loads(stdout)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--prior-seconds", type=float, default=0,
                        help="Already consumed process time in this simulation allowance")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output / "trials.jsonl"
    if output.exists():
        parser.error("output already exists; retain it and choose a new directory")
    matrix = itertools.product((4,) if args.smoke else (4, 8, 16),
                               (1, 10, 100), (7,) if args.smoke else (7, 19, 73),
                               SCENARIOS, ("reversible", "lock"))
    if not 0 <= args.prior_seconds < 600:
        parser.error("prior process time must be in [0, 600)")
    spent = args.prior_seconds
    receipts = []
    failures = []
    with output.open("x") as log:
        for nodes, depth, seed, scenario, mode in matrix:
            if spent >= 600:
                failures.append("aggregate simulation ceiling reached")
                break
            delay = 20 if scenario == "delayed" else 3
            topology = "ring" if scenario == "delayed" else "random"
            config = (nodes, depth, seed, scenario, mode, delay, topology)
            receipt = run(binary, config, min(60, 600 - spent))
            spent += receipt["wall_seconds"]
            log.write(json.dumps(receipt, sort_keys=True) + "\n")
            log.flush()
            receipts.append(receipt)
            result = receipt.get("result")
            if result is None:
                failures.append([config, "process failure or timeout"])
                continue
            if result["invalid_accepted"] or result["queue_dropped"]:
                failures.append([config, "invalid acceptance or overloaded queue"])
            if scenario in POSITIVE and result["selected_tips"] != 1:
                failures.append([config, "positive propagation did not converge"])
            if scenario == "partition" and result["pre_rejoin_conflicting_pairs"] == 0:
                failures.append([config, "missing decisive partition observation"])
            if scenario == "partition" and mode == "reversible" and (
                    result["revoked_confirmations"] == 0 or result["selected_tips"] != 1):
                failures.append([config, "missing reversible reconnection observation"])
            if scenario == "partition" and mode == "lock" and result["current_conflicting_pairs"] == 0:
                failures.append([config, "missing permanent-lock conflict"])
        # Re-run one decisive seed at every depth. Timing is not deterministic.
        for original in [r for r in receipts if r.get("result", {}).get("scenario") == "partition"
                         and r["result"]["nodes"] == 4 and r["result"]["seed"] == 7]:
            if spent >= 600:
                failures.append("no remaining replay allowance")
                break
            repeat = run(binary, original["command"][1:], min(60, 600 - spent))
            spent += repeat["wall_seconds"]
            logical = lambda r: {k: v for k, v in r.get("result", {}).items() if k != "elapsed_micros"}
            repeat["logical_replay_equal"] = bool(repeat.get("result")) and logical(repeat) == logical(original)
            if not repeat["logical_replay_equal"]:
                failures.append("logical replay mismatch")
            log.write(json.dumps(repeat, sort_keys=True) + "\n")
    summary = {"schema": 1, "trials": len(receipts), "simulation_wall_seconds": spent,
               "per_process_ceiling_seconds": 60, "aggregate_ceiling_seconds": 600,
               "failures": failures, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
               "trials_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
               "prior_process_seconds": args.prior_seconds,
               "platform": platform.platform(), "machine": platform.machine(),
               "cpu_count": os.cpu_count(), "paid_inference_calls": 0,
               "simulation_hosts": 1, "network_processes": 0,
               "children_peak_rss": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
               "rss_unit": "bytes" if platform.system() == "Darwin" else "KiB",
               "gpu_usage": "unmeasured", "token_usage": "unavailable"}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
