#!/usr/bin/env python3
"""Finite ordinary-node 1M learning, checked peer conversion and recovery."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import time

from autonomous_lifecycle import Node, Trial, retain_evidence, write_receipt
from automatic_computation import pressure, state


def snapshot(node):
    with sqlite3.connect((node.directory / "research/jobs.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        learning_raw = db.execute("SELECT payload FROM entries WHERE kind='learning' AND key='current'").fetchone()[0]
        record_rows = db.execute("SELECT key,payload FROM entries WHERE kind='record'").fetchall()
        receipt_rows = db.execute("SELECT key,payload FROM entries WHERE kind='peer_receipt'").fetchall()
    learning = json.loads(learning_raw)
    records = {int(key): json.loads(payload) for key, payload in record_rows}
    receipts = {key: json.loads(payload) for key, payload in receipt_rows}
    return {"learning": learning, "records": records, "peer_receipts": receipts}


def training(node):
    failures=[e for e in node.logs()[node.event_offset:] if e.get("event")=="fatal_error"]
    assert not failures, failures
    return [r for r in snapshot(node)["records"].values() if r["input"]["role"] == "train"]


def checkpoint_identity(record):
    return {key: record[key] for key in ("id", "input", "binding", "settings", "created_ms", "expires_ms")}


def verify_blobs(node, record):
    candidate = record["native"]["progress"]["candidate"]
    assert candidate and candidate["updates"] >= 10
    result = {}
    with sqlite3.connect((node.directory / "research/jobs.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        for name in ("model", "optimizer"):
            blob = candidate[name]
            rows = db.execute("SELECT payload FROM entries WHERE kind='model' AND key LIKE ? ORDER BY key", (blob["sha256"] + ":%",)).fetchall()
            payload = b"".join(row[0] for row in rows)
            assert len(payload) == blob["bytes"] and hashlib.sha256(payload).hexdigest() == blob["sha256"]
            result[name] = blob
    return result


def run(trial):
    a, b = Node(trial, 0), Node(trial, 1)
    for node in trial.nodes:
        node.config["runtime"]["jobs"] = {"native_proof_learning": True}
        node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
        node.write_config()
        node.start()
        initial = snapshot(node)["learning"]
        assert initial["accepted"] == initial["model"]["updates"] == 0
        assert initial["model"]["model"] is initial["model"]["optimizer"] is None
        assert not initial["replay"] and not node.ids()
        node.stop()
    for node, other in ((a, b), (b, a)):
        node.config["peers"] = [{"id": other.peer, "address": f"/ip4/127.0.0.1/tcp/{other.port}"}]
    a.config["runtime"]["question_interval_ms"] = 500
    for node in trial.nodes:
        node.write_config()
    b.start()
    a.start()

    def own_and_peer():
        own, peer = snapshot(a), snapshot(b)
        if own["learning"]["local_examples"] and peer["learning"]["peer_examples"]:
            assert peer["learning"]["local_examples"] == 0
            learned = [r for r in peer["peer_receipts"].values() if "Learned" in r["status"]]
            assert learned and all(r["admission"]["peer"] == a.peer for r in learned)
            assert all(r["admission"]["artifact"] in b.ids() for r in learned)
            return {"source": own["learning"], "receiver": peer["learning"], "receipts": learned}
        return None

    trial.summary["own_and_peer"] = trial.wait(own_and_peer, maximum=120)
    retained = {}
    for node in trial.nodes:
        record = trial.wait(lambda: next((r for r in training(node) if r["state"] == "running" and 0 < r["checkpoint"] < 25), None), maximum=60)
        pressure(node, True)
        trial.wait(lambda: state(trial, node, "paused"), maximum=8)
        # The current reserved quantum may finish before the next permit. Once
        # quiescent, every durable model IO/checkpoint and admitted set must hold.
        end = min(trial.deadline, time.monotonic() + 10)
        previous = None
        while time.monotonic() < end:
            current = snapshot(node)["records"][record["id"]]
            frozen = (current["checkpoint"], current["reserved_units"], current["native"]["io_bytes"])
            if frozen == previous:
                break
            previous = frozen
            time.sleep(0.5)
        else:
            raise AssertionError("reserved native quantum did not reach its paused boundary")
        assert 0 < current["checkpoint"] < 25
        blobs = verify_blobs(node, current)
        accepted = node.ids()
        for _ in range(3):
            assert state(trial, node, "paused")
            now = snapshot(node)["records"][current["id"]]
            assert (now["checkpoint"], now["reserved_units"], now["native"]["io_bytes"]) == frozen
            assert node.ids() == accepted
        retained[node.index] = {"record": current, "blobs": blobs, "accepted": sorted(accepted)}
        node.stop()
        node.config["runtime"]["question_interval_ms"] = 3600000
        node.write_config()
        pressure(node, False)
    write_receipt(trial.output / "retained-checkpoints.json", retained)

    for node in trial.nodes:
        node.start()
        original = retained[node.index]["record"]
        restored = snapshot(node)["records"][original["id"]]
        assert checkpoint_identity(restored) == checkpoint_identity(original)
        assert restored["checkpoint"] >= original["checkpoint"]
        assert restored["reserved_units"] >= original["reserved_units"]
        assert restored["spent_ms"] >= original["spent_ms"]
        assert restored["native"]["base_hash"] == original["native"]["base_hash"]

    qualifications = {}
    for node in trial.nodes:
        original = retained[node.index]["record"]
        completed = trial.wait(lambda: next((r for r in training(node) if r["id"] == original["id"] and r["state"] == "complete"), None), maximum=180)
        assert completed["checkpoint"] == 38 and completed["native"]["progress"]["unit"] == 38
        progress = completed["native"]["progress"]
        assert progress["candidate"] is None
        assert progress["diagnostic"] in {"candidate_promoted", "no_development_gain_rejected", "forgetting_rejected"}
        assert snapshot(node)["learning"]["accepted"] > 0
        assert checkpoint_identity(completed) == checkpoint_identity(original)
        if progress["diagnostic"] != "candidate_promoted":
            assert progress["state"]["model"] == completed["native"]["base"]["model"], "rejection must restore the exact model AND Adam pair"
        else:
            assert progress["state"]["model"]["updates"] == completed["native"]["base"]["model"]["updates"] + 250
        qualifications[node.index] = {"job": original["id"], "diagnostic": progress["diagnostic"], "incumbent_score": progress["incumbent_score"], "candidate_score": progress["candidate_score"], "anchor_regression": progress["anchor_regression"], "model": progress["state"]["model"], "io_bytes": completed["native"]["io_bytes"]}
    trial.summary["qualifications"] = qualifications
    trial.summary["restart_and_pause"] = {"result": "pass", "retained_training_jobs": [r["record"]["id"] for r in retained.values()]}
    trial.summary["claim"] = "Two ordinary loopback nodes, actual fresh 1,003,361-parameter CPU graph policy, own accepted and locally checked peer reconstruction, 250 candidate updates per retained job, native qualification/rollback, durable model+Adam recovery and automatic resource pause. No learned-performance or physical multi-host claim; interest remains the existing placeholder."
    trial.summary["result"] = "pass"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=480)
    parser.add_argument("--profile", default="release")
    parser.add_argument("--mode", default="native")
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "native")
    try:
        run(trial)
    except BaseException as error:
        trial.summary.update(result="fail", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "native", args.profile)
    assert trial.summary["result"] == "pass", trial.summary.get("cleanup")


if __name__ == "__main__":
    main()
