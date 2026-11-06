#!/usr/bin/env python3
"""Ordinary independent node processes exercising paired model exchange."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time

from autonomous_lifecycle import Node, Trial, retain_evidence, write_receipt


def cli(node, *arguments, error=None):
    trial = node.trial
    result = subprocess.run(
        [str(trial.binary), "models", *arguments],
        env={**os.environ, "NAOME_NODE_DIR": str(node.directory)},
        capture_output=True, text=True, timeout=trial.remaining(10),
    )
    if error is not None:
        assert result.returncode != 0 and error in result.stderr, result
        return None
    assert result.returncode == 0, result
    return json.loads(result.stdout)


def status(node):
    return cli(node, "status", "solver")


def done(node, wanted=None, seconds=90):
    deadline = time.monotonic() + node.trial.remaining(seconds)
    while time.monotonic() < deadline:
        report = status(node)
        if not report["working"] and report["last_operation"]:
            break
        time.sleep(0.2)
    else:
        raise AssertionError(f"model operation timed out: {report}")
    if wanted is not None:
        assert report["last_operation"]["state"] == wanted, report
    return report


def action(node, verb, *args, result, seconds=90):
    assert cli(node, verb, "solver", *args) == {"state": "queued"}
    return done(node, result, seconds)


def selection(node):
    path = node.directory / "research" / "jobs.sqlite3"
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1) as db:
        (state,) = db.execute(
            "SELECT payload FROM entries WHERE kind='learning' AND key='current'"
        ).fetchone()
    return json.loads(state)["model"]


def fixture(binary, node, seed, materialize):
    result = subprocess.run(
        [str(binary), "model-exchange-fixture", str(node.directory), str(seed), str(materialize).lower()],
        capture_output=True, text=True, timeout=node.trial.remaining(10),
    )
    assert result.returncode == 0, result
    return result.stdout.strip()


def run(trial, developer):
    high, low = Node(trial, 0), Node(trial, 1)
    for node in (high, low):
        node.config["runtime"].update(
            question_interval_ms=3600000, proof_interval_ms=3600000,
            jobs={"native_proof_learning": True},
        )
        node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
        node.write_config()
        node.start()
        node.stop()

    high_id = fixture(developer, high, 2, True)
    low_id = fixture(developer, low, 1, False)
    old_low, expected = selection(low), selection(high)
    assert expected["model"]["bytes"] > 1_000_000 and expected["optimizer"]["bytes"] > 1_000_000
    assert high_id != low_id

    for node, other in ((high, low), (low, high)):
        node.config["peers"] = [{"id": other.peer, "address": f"/ip4/127.0.0.1/tcp/{other.port}"}]
        node.write_config()
        node.start()
    assert high.process["pid"] != low.process["pid"]
    assert action(low, "share", result="shared")["shared"] == low_id
    assert action(high, "peer", low.peer, result="observed")["last_operation"]["model"] == low_id
    comparison = action(high, "compare", low.peer, low_id, result="verified")
    assert comparison["comparison"]["local"] > comparison["comparison"]["remote"], comparison
    comparison_id = comparison["comparison_id"]
    action(high, "offer", low.peer, comparison_id, result="offered")
    hint = status(low)["offer"]
    assert hint["model"] == high_id and hint["comparison_id"] == comparison_id, hint
    cli(low, "adopt", "solver", comparison_id, error="no locally replayed comparison")

    offset = len(low.logs())
    assert cli(low, "compare", "solver", high.peer, high_id) == {"state": "queued"}
    cli(low, "compare", "solver", high.peer, high_id, error="already running")
    first_chunk = trial.wait(lambda: next((
        event for event in low.logs()[offset:] if event.get("event") == "exchange_response"
        and event.get("kind") == "model_chunk_data"
    ), None), maximum=20)
    high.stop()
    stopped = done(low, "failed", seconds=20)
    assert selection(low) == old_low
    assert not stopped["retained_artifacts"]
    cli(low, "adopt", "solver", comparison_id, error="no locally replayed comparison")

    high.start()
    assert action(high, "share", result="shared")["shared"] == high_id
    audited = action(low, "audit", result="audited")
    assert audited["audit"]["comparison_id"] == comparison_id and audited["audit"]["complete"]
    comparison = action(low, "compare", high.peer, high_id, result="verified")
    assert comparison["comparison"]["remote"] > comparison["comparison"]["local"], comparison
    verified_id = comparison["comparison_id"]
    assert action(low, "adopt", verified_id, result="selected")["last_operation"]["model"] == high_id
    assert selection(low) == expected, "model and Adam identities must change together"
    cli(low, "adopt", "solver", verified_id, error="no locally replayed comparison")

    low.stop()
    low.start()
    assert status(low)["comparison_id"] == verified_id
    assert action(low, "share", result="shared")["shared"] == high_id
    assert selection(low) == expected
    assert action(low, "rollback", high_id, result="selected")["last_operation"]["model"] == low_id
    low.stop()
    low.start()
    assert selection(low) == old_low
    assert action(low, "share", result="shared")["shared"] == low_id
    assert not high.ids() and not low.ids(), "reference proofs must stay out of the training graph"

    trial.summary["scenarios"] = {
        "separate_peers": [high.peer, low.peer],
        "offer": hint,
        "interrupted_transfer": {"first_chunk": first_chunk, "status": stopped["last_operation"]},
        "independent_audit": audited["audit"],
        "recipient_comparison": comparison["comparison"],
        "adopted_checkpoint": expected,
        "rollback_after_restart": old_low,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--developer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--timeout", type=float, default=260)
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "model-exchange")
    config = trial.output / "resource-config.json"
    write_receipt(config, {"version": 1, "memory_bytes": 2 * 1024**3, "workers": [1, 1, 2, 2], "tuning": {}})
    os.environ["NAOME_RESOURCE_CONFIG"] = str(config)
    start = time.monotonic()
    trial.summary["claim"] = "local separate peers, real model/optimizer bytes and independently checked reference execution"
    try:
        run(trial, args.developer)
        trial.summary["result"] = "pass"
    except BaseException as error:
        trial.summary.update(result="fail", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        trial.summary["execution_seconds"] = time.monotonic() - start
        trial.close()
        retain_evidence(trial.output, trial.summary, "model-exchange", args.profile)
    assert trial.summary["result"] == "pass"


if __name__ == "__main__":
    main()
