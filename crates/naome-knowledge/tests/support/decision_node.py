#!/usr/bin/env python3
"""Finite real-model receiver screen with independent local node identities."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import time

from autonomous_lifecycle import Node, Trial, retain_evidence
from long_jobs import journal


def admitted(node):
    path = node.directory / "research/questions.sqlite3"
    if not path.exists():
        return 0
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as database:
        return database.execute("SELECT count(*) FROM entries WHERE kind='admitted'").fetchone()[0]


def records(node):
    state = journal(node)
    return [] if state is None else list(state["records"].values())


def interest_records(node):
    return [record for record in records(node) if record["input"]["role"] == "interest"]


def responsive(trial, node, samples=3):
    times = []
    for _ in range(samples):
        began = time.monotonic()
        status = trial.call(node, "status")
        times.append(time.monotonic() - began)
        assert status["running"], status
    assert max(times) < 2, times
    trial.summary.setdefault("control_seconds", []).append({"node": node.index, "samples": times})


def configure(node, provider, question_ms=1000):
    node.config["runtime"] = {"question_interval_ms": question_ms, "proof_interval_ms": 100,
        "jobs": {"interest_provider": provider,
                 "interest": {"limits": {"horizon_ms": 60000, "work_units": 64}}}}
    node.write_config()


def run(trial, args):
    source, receiver = Node(trial, 0), Node(trial, 1)
    configure(source, "deterministic")
    configure(receiver, "decision", 5000)
    model = {"version": 1, "python": str(args.python.resolve()),
        "model_directory": str(args.model.resolve()), "runtime_directory": str(args.runtime.resolve()), "threads": 2,
        "max_input_tokens": 1024, "memory_bytes": 4 * 1024**3}
    (receiver.directory / "decision.json").write_text(json.dumps(model))
    (receiver.directory / "resource-profile.json").write_text(json.dumps({"profile":"heavy", "custom":None}))
    trial.summary["receiver_resource_profile"] = "heavy"
    trial.call(receiver, "interest", text="All questions in set theory interest me.")
    # Obtain independent identities before connecting either active node. The
    # receiver has no model work during this first short isolated startup.
    receiver.start()
    receiver.stop()
    source.start()
    source.stop()
    assert source.peer != receiver.peer and source.port != receiver.port
    for node, other in [(source, receiver), (receiver, source)]:
        node.config["peers"] = [{"id": other.peer,
            "address": f"/ip4/127.0.0.1/tcp/{other.port}"}]
        node.write_config()
    receiver.start()
    source.start()
    trial.wait(lambda: trial.call(source, "status")["accepted_proofs"] > 0, maximum=20)
    trial.wait(lambda: any(event.get("event") == "decision_backend_started"
        for event in receiver.logs()), maximum=15)
    responsive(trial, receiver)
    responsive(trial, source)
    old_revision = json.loads((receiver.directory / "owner.json").read_text())["revision"]
    old_jobs = {record["id"] for record in interest_records(receiver)
        if record["input"]["assessment"]["owner_revision"] == old_revision}
    assert old_jobs, "no real in-flight interest evaluation"
    trial.call(receiver, "interest", text="Please reject every research question. I currently have no research interests.")
    trial.wait(lambda: any(record["id"] in old_jobs and record["state"] == "cancelled"
        for record in interest_records(receiver)), maximum=10)
    assert admitted(receiver) == 0
    assert trial.call(receiver, "status")["accepted_proofs"] == 0
    stable_offset = len(receiver.logs())
    current_revision = json.loads((receiver.directory / "owner.json").read_text())["revision"]

    def evaluated_both_lanes():
        selected = [record for record in interest_records(receiver)
            if record["state"] == "complete"
            and record["input"]["assessment"]["owner_revision"] == current_revision]
        return selected if (any(record["input"]["root"] is None for record in selected)
            and any(record["input"]["root"] is not None for record in selected)) else None

    completed = trial.wait(evaluated_both_lanes, maximum=45)
    for record in completed:
        assert record["provider"] == "naome-decision-interest-v1"
        assert record["result"]["kind"] == "decision"
        distribution = record["result"]["value"]
        assert distribution["truncated"] is False
        assert distribution["probabilities"][0]["probability"] < 0.8, record
    loaded = [event for event in receiver.logs()[stable_offset:]
        if event.get("event") == "decision_model_loaded"]
    assert len({event["pid"] for event in loaded}) == 1, loaded
    assert admitted(receiver) == 0
    assert trial.call(receiver, "status")["accepted_proofs"] == 0
    responsive(trial, receiver)
    trial.summary["scenarios"]["real_model_local_and_peer"] = {
        "old_revision": old_revision, "current_revision": current_revision,
        "cancelled_jobs": sorted(old_jobs), "completed_jobs": [record["id"] for record in completed],
        "loaded_models": loaded, "source_accepted_proofs": trial.call(source, "status")["accepted_proofs"],
        "receiver_accepted_proofs": 0, "receiver_admitted_questions": 0}
    receiver.stop()

    # A genuine model launch exceeding its explicit resident allowance must
    # produce a provider failure while the ordinary node controls stay usable.
    model["memory_bytes"] = 64 * 1024**2
    (receiver.directory / "decision.json").write_text(json.dumps(model))
    before = len(receiver.logs())
    receiver.start()
    failed = trial.wait(lambda: next((event for event in receiver.logs()[before:]
        if event.get("event") == "research_finished" and event.get("state") == "Failed"
        and "decision" in (event.get("error") or "")), None), maximum=20)
    responsive(trial, receiver)
    assert trial.call(receiver, "status")["accepted_proofs"] == 0
    assert admitted(receiver) == 0
    trial.summary["scenarios"]["real_model_memory_failure"] = failed
    receiver.stop()

    missing = Node(trial, 2)
    configure(missing, "decision", 100)
    missing.start()
    failure = trial.wait(lambda: next((event for event in missing.logs()
        if event.get("event") == "research_finished" and event.get("state") == "Failed"
        and "not configured" in (event.get("error") or "")), None), maximum=10)
    responsive(trial, missing)
    assert admitted(missing) == 0 and trial.call(missing, "status")["accepted_proofs"] == 0
    trial.summary["scenarios"]["unconfigured_model"] = failure
    missing.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, 180, "test", "real-decision-model")
    resources = trial.output / "installed-resources.json"
    resources.write_text(json.dumps({"decision_memory_bytes": 4 * 1024**3}))
    os.environ["NAOME_RESOURCE_CONFIG"] = str(resources)
    trial.summary["fixture"] = "real_decision_model_receiver"
    trial.summary["claim"] = "Local multiprocess evidence only: a real-model receiver and a deterministic fixture source, with real checking and independent identities/ports/directories."
    trial.summary["label_source"] = "synthetic explicit rejection interests; no human preference qualification"
    try:
        run(trial, args)
        trial.summary["result"] = "pass"
    except BaseException as failure:
        trial.summary["result"] = "fail"
        trial.summary["failure"] = repr(failure)
        raise
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "real-decision-model", "test")


if __name__ == "__main__":
    main()
