#!/usr/bin/env python3
"""Bounded longitudinal observation of an ordinary unseeded learning node.

This diagnostic never supplies questions, proofs, labels or checkpoints. Native
candidate admission remains unchanged. Runtime observations do not establish
independent learning quality or indefinite mathematical progress.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

from autonomous_lifecycle import Node, Trial, retain_evidence, write_receipt
from native_learning import verify_blobs, verify_meta


def audit_completed(record, candidate, selected_model):
    native = record["native"]
    base, progress = native["base"], native["progress"]
    assert record["input"]["role"] == "train" and record["state"] == "complete"
    assert record["checkpoint"] == progress["unit"] == record["reserved_units"] == 150
    assert progress["candidate"] is None
    assert candidate["updates"] == base["model"]["updates"] + 250
    transfer = progress["transfer"]
    assert transfer["observed"] == (1 << 24) - 1
    families = [((transfer["before"] >> (2*i) & 3).bit_count(),
                 (transfer["after"] >> (2*i) & 3).bit_count()) for i in range(12)]
    accepted = progress["diagnostic"] == "candidate_promoted"
    if accepted:
        assert progress["model"] == candidate
        assert progress["candidate_score"] > progress["incumbent_score"]
        assert not progress["anchor_regression"] and not progress["development_regression"]
        assert sum(a for _, a in families) > sum(b for b, _ in families)
        assert all(a >= b for b, a in families)
    else:
        assert progress["model"] == base["model"], "rejection must restore complete weights and Adam"
    assert selected_model == progress["model"], "native predicate is not proof of actual selected state"
    return {"job": record["id"], "accepted": accepted,
            "source_updates": base["model"]["updates"],
            "candidate_updates": candidate["updates"],
            "selected_updates": progress["model"]["updates"],
            "reason": progress["diagnostic"], "transfer_families": families,
            "development": [progress["incumbent_score"], progress["candidate_score"]],
            "cpu_micros": progress["cpu_micros"], "wall_micros": progress["wall_micros"]}


class JournalReader:
    """Read new records and live training only; never rescan old payloads."""
    def __init__(self):
        self.seen = set()
        self.active = set()
        self.bytes = 0

    def read(self, node):
        path = node.directory / "research/jobs.sqlite3"
        try:
            with sqlite3.connect(path.as_uri()+"?mode=ro", uri=True, timeout=.01) as db:
                db.execute("BEGIN")
                raw = db.execute("SELECT payload FROM entries WHERE kind='learning' AND key='current'").fetchone()[0]
                self.bytes += len(raw)
                ids = {int(r[0]) for r in db.execute("SELECT key FROM entries WHERE kind='record'")}
                assert len(ids) <= 200000, "observer record-index capacity"
                records = {}
                for identity in sorted((ids-self.seen) | self.active):
                    row = db.execute("SELECT payload FROM entries WHERE kind='record' AND key=?", (str(identity),)).fetchone()
                    assert row is not None, "active observed record disappeared"
                    self.bytes += len(row[0])
                    record = json.loads(row[0])
                    if record["input"]["role"] == "train":
                        self.active.add(identity)
                        records[identity] = record
                self.seen |= ids
            return {"learning": json.loads(raw), "records": records}
        except sqlite3.OperationalError as error:
            if any(s in str(error).lower() for s in ("locked", "busy", "unable to open")):
                return None
            raise


def finder_snapshot(node):
    path = node.directory / "research/evidence.sqlite3"
    try:
        with sqlite3.connect(path.as_uri()+"?mode=ro", uri=True, timeout=.01) as db:
            db.execute("BEGIN")
            row = db.execute("SELECT header FROM checkpoint WHERE singleton=1").fetchone()
        return json.loads(row[0]) if row else None
    except sqlite3.OperationalError as error:
        if any(s in str(error).lower() for s in ("locked", "busy", "unable to open")):
            return None
        raise


def capture_inputs(node, record):
    """Retain prepared input bytes before the journal's normal reclamation."""
    native = record["native"]
    progress = native["progress"]
    blobs = {}
    if native.get("history"):
        blobs["history-page"] = native["history"]["blob"]
    if progress.get("prepared"):
        blobs["prepared-history"] = progress["prepared"]["blob"]
    output = node.trial.output / f"checkpoints/node-{node.index}-job-{record['id']}"
    read_bytes = 0
    with sqlite3.connect((node.directory / "research/jobs.sqlite3").as_uri()+"?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        for name, blob in blobs.items():
            parts = db.execute("SELECT payload FROM entries WHERE kind='model' AND key LIKE ? ORDER BY key", (blob["sha256"]+":%",)).fetchall()
            payload = b"".join(row[0] for row in parts)
            read_bytes += len(payload)
            assert len(payload) == blob["bytes"] and hashlib.sha256(payload).hexdigest() == blob["sha256"]
            (output / f"{name}.bin").write_bytes(payload)
    write_receipt(output / "inputs.json", {"record": record, "blobs": blobs})
    return read_bytes


def retain_closed_snapshot(node):
    closed = node.trial.output / "closed-journal.json"
    if closed.exists():
        return
    # The raw closed journal is already retained. Export only learning and
    # training records, one payload at a time, without loading solved history.
    reader = JournalReader()
    final = reader.read(node)
    node.trial.summary["closed_observer_journal_read_bytes"] = reader.bytes
    if final is not None:
        write_receipt(closed, final)
        node.trial.summary.update(selected_solver_updates=final["learning"]["model"]["updates"],
            own_examples=final["learning"]["local_examples"])


def run(trial, maximum_trials):
    node = Node(trial, 0)
    trial.summary.update(node_count=1, injected_questions=0, imported_proofs=0,
                         imported_checkpoints=0, target_completed_trials=maximum_trials,
                         independent_quality_qualified=False)
    node.config["runtime"]["jobs"] = {"native_proof_learning": True}
    node.config["runtime"]["question_interval_ms"] = 500
    node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
    assert not node.config.get("formal_goal") and not node.config["producer_sources"]
    node.write_config()
    assert not node.ids()
    node.start()
    candidates, completed, last_finder = {}, {}, None
    reader = JournalReader()
    observations = []
    started = time.monotonic()
    while time.monotonic() < trial.deadline - 5:
        # Native admission remains active on both supported platforms. Darwin
        # additionally supplies a direct host-pressure observation to this run.
        pressure = None
        if sys.platform == "darwin":
            pressure = int(subprocess.check_output(
                ["/usr/sbin/sysctl", "-n", "kern.memorystatus_vm_pressure_level"], text=True))
            assert pressure == 1, "installed host-pressure admission is closed"
        events = node.logs()
        assert not [e for e in events if e.get("event") == "fatal_error"]
        current = reader.read(node)
        trial.summary["observer_journal_read_bytes"] = reader.bytes
        finder = finder_snapshot(node)
        if finder is not None and finder != last_finder:
            number = len(observations)
            write_receipt(trial.output / f"finder-{number}.json", finder)
            last_finder = finder
        if current is not None:
            for record in sorted(current["records"].values(), key=lambda r: r["id"]):
                if record["input"]["role"] != "train":
                    continue
                p = record["native"].get("progress")
                if p and p["candidate"] is not None and p["unit"] >= 25 and record["id"] not in candidates:
                    verify_blobs(node, record, "observed_candidate_not_yet_qualified", per_job=True)
                    trial.summary["observer_input_blob_read_bytes"] = trial.summary.get("observer_input_blob_read_bytes", 0) + capture_inputs(node, record)
                    candidates[record["id"]] = p["candidate"]
                    write_receipt(trial.output / "candidate-checkpoints.json", candidates)
                if record["state"] in ("failed", "expired", "in_doubt", "cancelled"):
                    write_receipt(trial.output / f"failed-trial-{record['id']}.json", record)
                    raise RuntimeError(f"native trial {record['id']} {record['state']}: {record.get('failure')}")
                if record["state"] == "complete" and record["id"] not in completed:
                    assert record["id"] in candidates, "complete candidate bytes were not observed"
                    # Completion and adoption are separate observations. Wait
                    # for the same transactional journal to select the exact
                    # model/Adam pair before counting a retained update.
                    if current["learning"]["model"] != p["model"]:
                        continue
                    row = audit_completed(record, candidates[record["id"]], current["learning"]["model"])
                    row["actual_selected_state"] = current["learning"]
                    verify_meta(node, record)
                    row["record"] = record
                    row["finder"] = finder
                    completed[record["id"]] = row
                    reader.active.discard(record["id"])
                    write_receipt(trial.output / f"trial-{record['id']}.json", row)
                    write_receipt(trial.output / "completed-trials.json", list(completed.values()))
                    print(json.dumps({k: v for k, v in row.items() if k not in ("record", "finder")}), flush=True)
            observations.append({"wall_seconds": time.monotonic()-started,
                "local_examples": current["learning"]["local_examples"],
                "selected_model": current["learning"]["model"],
                "solver_promotions": current["learning"]["promotions"],
                "finder_updates": finder["model"]["updates"] if finder else None,
                "finder_rehearsals": finder["model"]["rehearsals"] if finder else None,
                "finder_model_sha256": hashlib.sha256(json.dumps(finder["model"], sort_keys=True).encode()).hexdigest() if finder else None,
                "completed_trials": len(completed), "kernel_pressure": pressure})
            write_receipt(trial.output / "observations.json", observations)
            if len(completed) >= maximum_trials:
                break
        time.sleep(1)
    node.stop()
    final = reader.read(node)
    assert final is not None
    write_receipt(trial.output / "closed-journal.json", final)
    final_finder = finder_snapshot(node)
    write_receipt(trial.output / "closed-finder.json", final_finder)
    accepted = [r for r in completed.values() if r["accepted"]]
    trial.summary.update(result="diagnostic_complete" if len(completed) >= maximum_trials else "observation_incomplete", observation_complete=len(completed) >= maximum_trials,
        completed_trials=len(completed), accepted_trials=len(accepted), observer_journal_read_bytes=reader.bytes,
        selected_solver_updates=final["learning"]["model"]["updates"],
        finder_updates=final_finder["model"]["updates"] if final_finder else None,
        own_examples=final["learning"]["local_examples"], independent_quality_qualified=False,
        claim="Bounded actual unseeded online operation and exact native selected/rejected checkpoint lineage. Finder weight updates and accepted solver updates are measured separately. No claim of independent quality, beyond-human mathematics or indefinite progress.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--trials", type=int, default=8)
    args = parser.parse_args()
    assert args.trials == 8 and args.timeout == 1200, "use the frozen longitudinal envelope"
    trial = Trial(args.binary, args.output, args.timeout, "release", "continual")
    try:
        run(trial, args.trials)
    except BaseException as error:
        trial.summary.update(result="fail", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        trial.close()
        if trial.nodes:
            node = trial.nodes[0]
            try:
                retain_closed_snapshot(node)
                write_receipt(trial.output / "closed-finder.json", finder_snapshot(node))
            except (sqlite3.Error, TypeError, KeyError) as error:
                trial.summary.update(result="fail", closed_snapshot_error=f"{type(error).__name__}: {error}")
        retain_evidence(trial.output, trial.summary, "continual", "release")


if __name__ == "__main__":
    main()
