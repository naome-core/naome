#!/usr/bin/env python3
"""Finite ordinary CLI owner configuration qualification with existing guardians."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import subprocess
from types import SimpleNamespace

from autonomous_lifecycle import (
    Node, Trial, digest, process_group, process_identity, retain_evidence,
)


def run(trial):
    first, other, before_start = Node(trial, 0), Node(trial, 1), Node(trial, 2)
    trial.summary["node_count"] = 3
    # Exercise a genuinely absent node directory before any identity exists.
    (before_start.directory / "config.json").unlink()
    before_start.directory.rmdir()
    fresh = SimpleNamespace(directory=before_start.directory, index=before_start.index)
    assert not fresh.directory.exists()
    trial.call(fresh, "interest", success=False)
    trial.call(fresh, "interest", text="x" * 1025, success=False)
    invalid = subprocess.run([os.fsencode(trial.binary), b"interest", b"\xff"],
        capture_output=True, env={**os.environ, "NAOME_NODE_DIR": str(fresh.directory)},
        timeout=trial.remaining())
    assert invalid.returncode != 0 and invalid.stdout == b""
    assert b"valid UTF-8" in invalid.stderr
    assert not fresh.directory.exists(), "invalid input mutated an absent node directory"
    initial = "  Mathematical logic\n\tλ and 🦀  "
    expected = {"running": False, "accepted_proofs": 0, "interest": initial}
    assert trial.call(fresh, "interest", text=initial) == expected
    assert trial.call(fresh, "status") == expected
    assert not (fresh.directory / "identity.key").exists(), "interest implicitly initialized identity"
    assert not (fresh.directory / "control.json").exists(), "interest implicitly started daemon"
    assert not (fresh.directory / "config.json").exists(), "interest initialized runtime configuration"
    before_start.start()
    assert (before_start.directory / "config.json").exists(), "first start did not seed runtime configuration"
    identity_before = digest(before_start.directory / "identity.key")
    assert trial.call(before_start, "status")["interest"] == initial
    stopped_default = before_start.stop()
    assert stopped_default["interest"] == initial
    assert stopped_default["accepted_proofs"] == len(before_start.ids())
    before_start.write_config()
    assert trial.call(before_start, "interest", text=initial) == stopped_default
    assert digest(before_start.directory / "identity.key") == identity_before
    assert trial.call(first, "status")["interest"] == ""
    assert trial.call(other, "status")["interest"] == ""
    assert trial.call(first, "interest", text=initial) == expected
    assert not (first.directory / "identity.key").exists()
    trial.summary["scenarios"]["pre_start_exact_text_and_directory_isolation"] = {"result": "pass"}

    for running in [False, True]:
        if running:
            first.start()
        for text in ["x" * 1024, "🦀" * 256, "\x01" * 1024, "  \n\t ", "", initial]:
            result = trial.call(first, "interest", text=text)
            assert result == {"running": running, "accepted_proofs": 0, "interest": text}
            assert trial.call(first, "status") == result
            for oversized in ["x" * 1025, "🦀" * 256 + "x"]:
                trial.call(first, "interest", text=oversized, success=False)
                assert trial.call(first, "status") == result
            assert trial.call(other, "status")["interest"] == ""
        with ThreadPoolExecutor(max_workers=4) as pool:
            updates = list(pool.map(lambda i: trial.call(first, "interest", text=f"update-{i}"), range(8)))
        assert {value["interest"] for value in updates} == {f"update-{i}" for i in range(8)}
        assert trial.call(first, "status")["interest"] in {value["interest"] for value in updates}
        trial.call(first, "interest", text=initial)
        # A nonregular incoming path forces a real filesystem failure before
        # mutation; the committed profile bytes remain exactly intact.
        original = (first.directory / "owner.json").read_bytes()
        incoming = first.directory / ".owner-incoming"
        incoming.mkdir()
        try:
            trial.call(first, "interest", text="must not replace", success=False)
            assert (first.directory / "owner.json").read_bytes() == original
        finally:
            incoming.rmdir()
        assert trial.call(first, "status")["interest"] == initial
        if running:
            first.stop()
    trial.summary["scenarios"]["stopped_live_boundaries_clear_concurrent_updates_and_failed_write"] = {"result": "pass"}

    first.config["runtime"]["question_interval_ms"] = 100
    first.write_config()
    first.start()
    accepted = trial.wait(lambda: first.ids() if len(first.ids()) == 3 else None, maximum=10)
    first.stop()
    first.config["runtime"]["question_interval_ms"] = 3600000
    first.write_config()
    identities = {str(path.relative_to(first.directory / "objects")): digest(path) for path in (first.directory / "objects").rglob("*.json")}
    identity = digest(first.directory / "identity.key")
    first.start()
    assert trial.call(first, "status") == {"running": True, "accepted_proofs": 3, "interest": initial}
    old_process = dict(first.process)
    assert process_identity(old_process["pid"]) == old_process
    os.killpg(old_process["group"], signal.SIGKILL)
    trial.wait(lambda: not process_group(old_process), maximum=5)
    assert trial.call(first, "status") == {"running": False, "accepted_proofs": 3, "interest": initial}
    first.start()
    assert digest(first.directory / "identity.key") == identity
    assert first.ids() == accepted
    assert {str(path.relative_to(first.directory / "objects")): digest(path) for path in (first.directory / "objects").rglob("*.json")} == identities
    trial.summary["scenarios"]["clean_crash_restart_preserves_interest_identity_and_proofs"] = {"result": "pass"}

    # Start/stop and interest use one lifecycle lock, regardless of completion order.
    first.stop()
    first.release_port()
    with ThreadPoolExecutor(max_workers=2) as pool:
        start = pool.submit(trial.call, first, "start")
        update = pool.submit(trial.call, first, "interest", text="race start")
        assert start.result()["running"]
        assert update.result()["interest"] == "race start"
    first.event_offset = len(first.logs()) - 1
    first.capture_process()
    assert trial.call(first, "status")["interest"] == "race start"
    with ThreadPoolExecutor(max_workers=2) as pool:
        stop = pool.submit(trial.call, first, "stop")
        update = pool.submit(trial.call, first, "interest", text="race stop")
        assert not stop.result()["running"]
        assert update.result()["interest"] == "race stop"
    assert not process_group(first.process)
    assert trial.call(first, "status") == {"running": False, "accepted_proofs": 3, "interest": "race stop"}
    assert first.ids() == accepted
    trial.summary["scenarios"]["start_stop_update_races_preserve_owner_text_and_checked_ids"] = {"result": "pass"}
    trial.summary["accepted_ids"] = sorted(accepted)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--mode", choices=["interest"], default="interest")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "interest")
    trial.summary["interest_driver_sha256"] = digest(__file__)
    try:
        run(trial)
        trial.summary["result"] = "pass"
    except Exception as error:
        trial.summary["result"] = "fail"
        trial.summary["error"] = str(error)
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "interest", args.profile)
    print(json.dumps({"result": trial.summary["result"], "output": str(trial.output)}))
    return 0 if trial.summary["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
