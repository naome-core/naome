#!/usr/bin/env python3
"""Bounded ordinary-node discovery from an empty graph and fresh local models."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import time
import traceback

from autonomous_lifecycle import Node, Trial, write_receipt
from native_learning import snapshot
from proof_network import stored_objects


def finder_state(node):
    path = node.directory / "research/evidence.sqlite3"
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.1) as database:
        return json.loads(database.execute("SELECT header FROM checkpoint").fetchone()[0])


def source_identity():
    root = Path(__file__).resolve().parents[4]
    paths = ["src/autonomous.rs", "src/frontier.rs", "src/frontier/evidence.rs", "src/frontier/finder.rs",
             "src/frontier/finder/model.rs", "src/jobs/provider.rs", "src/jobs/service.rs",
             "src/learning/mod.rs", "src/runtime/cli.rs", "tests/support/finder_cold_start.py"]
    crate = Path(__file__).resolve().parents[2]
    return {"commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
            "files": {str(Path("crates/naome-knowledge") / path):
                      hashlib.sha256((crate / path).read_bytes()).hexdigest() for path in paths}}


def run(trial, seconds, attempts, minimum):
    node = Node(trial, 0)
    node.config["runtime"]["jobs"] = {"native_proof_learning": True}
    node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
    node.write_config()
    assert not node.config["peers"] and not node.config["producer_sources"]
    assert "formal_goal" not in node.config
    node.start()
    initial = trial.wait(lambda: snapshot(node), maximum=10)
    assert not node.ids()
    assert initial["learning"]["accepted"] == initial["learning"]["model"]["updates"] == 0
    assert initial["learning"]["model"]["model"] is None
    assert initial["learning"]["model"]["optimizer"] is None
    assert not initial["learning"]["replay"] and not initial["learning"]["knowledge"]
    initial_finder = finder_state(node)
    assert initial_finder["model"]["updates"] == 0
    write_receipt(trial.output / "initial.json", {"learning": initial["learning"], "finder": initial_finder,
                                                "accepted_artifacts": []})
    node.stop()
    node.config["runtime"]["question_interval_ms"] = 500
    node.write_config()
    node.start()
    records = {}
    started = time.monotonic()
    deadline = min(trial.deadline - 20, started + seconds)
    reason = "measurement_deadline"
    while time.monotonic() < deadline:
        current = snapshot(node)
        if current is not None:
            for identity, record in current["records"].items():
                if record["input"]["role"] in {"solve", "find"}:
                    records[identity] = record
            assert len(records) <= 512, "bounded observation record capacity reached"
        events = node.logs()
        fatal = [event for event in events if event.get("event") == "fatal_error"]
        assert not fatal, fatal
        solved = {event["resolution_id"] for event in events if event.get("event") == "finder_learned"
                  and event["outcome"] == "checked_resolution"}
        completed = [record for record in records.values() if record["input"]["role"] == "solve"
                     and record["state"] in {"complete", "failed", "expired", "in_doubt"}]
        if len(completed) >= attempts and len(solved) >= minimum:
            reason = "attempt_and_resolution_target"
            break
        time.sleep(0.2)
    trial.summary["measurement_wall_seconds"] = time.monotonic() - started
    trial.summary["stopping_reason"] = reason
    trial.summary["live_status"] = trial.call(node, "status")
    trial.summary["final_finder"] = finder_state(node)
    final = trial.wait(lambda: snapshot(node), maximum=5)
    for identity, record in final["records"].items():
        if record["input"]["role"] in {"solve", "find"}:
            records[identity] = record
    node.stop()
    write_receipt(trial.output / "records.json", {str(key): value for key, value in records.items()})
    write_receipt(trial.output / "events.json", node.logs())
    objects = stored_objects(node)
    accepted = {item["artifact_id"] for item in objects}
    write_receipt(trial.output / "accepted-artifacts.json", objects)
    generated = {event["job"]: event for event in node.logs()
                 if event.get("event") == "proof_generated" and event["id"] in accepted}
    proofs = trial.output / "proofs"
    proofs.mkdir()
    results = []
    for identity, record in sorted(records.items()):
        if record["input"]["role"] != "solve":
            assert record["provider"] == "naome-structural-finder"
            continue
        assert record["provider"] == "naome-native-proof-learning"
        progress = (record.get("native") or {}).get("progress") or {}
        solution = progress.get("result")
        entry = {"job": identity, "question": record["input"]["question"],
                 "state": record["state"], "spent_ms": record["spent_ms"],
                 "diagnostic": progress.get("diagnostic"), "cost": progress.get("cost"),
                 "accepted": identity in generated}
        if identity in generated:
            assert solution is not None
            entry.update({"artifact_id": generated[identity]["id"], "proof_id": solution["proof_id"],
                          "outcome": "refuted" if solution["refuted"] else "proved",
                          "proof_file": f"proofs/job-{identity}.nao", "helpers": solution["helpers"]})
            (proofs / f"job-{identity}.nao").write_text(solution["source"] + "\n")
            for index, helper in enumerate(solution["helpers"]):
                (proofs / f"job-{identity}-helper-{index}.nao").write_text(helper + "\n")
        elif solution is not None and record["state"] == "complete":
            entry["outcome"] = "unaccepted_candidate"
        elif record["state"] == "complete":
            entry["outcome"] = "unresolved"
        elif record["state"] in {"queued", "running", "suspended"}:
            entry["outcome"] = "unfinished"
        else:
            entry["outcome"] = "unavailable"
        results.append(entry)
    write_receipt(trial.output / "questions-and-proofs.json", results)
    trial.summary["attempts"] = len(results)
    trial.summary["unique_attempted_questions"] = len({row["question"] for row in results})
    trial.summary["generated_questions"] = sum(record["input"]["role"] == "find" for record in records.values())
    trial.summary["completed_attempts"] = sum(row["state"] == "complete" for row in results)
    trial.summary["accepted_resolutions"] = sum(row["accepted"] for row in results)
    trial.summary["proved"] = sum(row["outcome"] == "proved" for row in results)
    trial.summary["refuted"] = sum(row["outcome"] == "refuted" for row in results)
    trial.summary["unresolved"] = sum(row["outcome"] == "unresolved" for row in results)
    trial.summary["unfinished"] = sum(row["outcome"] == "unfinished" for row in results)
    trial.summary["unavailable"] = sum(row["outcome"] == "unavailable" for row in results)
    trial.summary["unaccepted_candidates"] = sum(row["outcome"] == "unaccepted_candidate" for row in results)
    assert trial.summary["live_status"]["artifact_verification"] == "checked"
    assert trial.summary["accepted_resolutions"] >= minimum, "insufficient checked cold-start resolutions"
    assert trial.summary["final_finder"]["model"]["updates"] > 0
    assert not any(record["input"]["role"] == "peer" for record in final["records"].values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--attempts", type=int, default=16)
    parser.add_argument("--minimum-resolutions", type=int, default=4)
    args = parser.parse_args()
    assert 1 <= args.seconds <= 300 and 1 <= args.attempts <= 64
    assert 1 <= args.minimum_resolutions <= args.attempts
    trial = Trial(args.binary, args.output, args.seconds + 120, "release", "finder_cold_start")
    trial.summary.update({"fixture": "structural_finder_cold_start", "node_count": 1,
                          "source": source_identity(), "claim": "local empty-graph native discovery and checking; no general mathematical novelty or learning-gain claim"})
    try:
        run(trial, args.seconds, args.attempts, args.minimum_resolutions)
        trial.summary["result"] = "pass"
    except Exception:
        trial.summary["result"] = "fail"
        trial.summary["error"] = traceback.format_exc()
    finally:
        trial.close()
        write_receipt(trial.output / "summary.json", trial.summary)
    print(json.dumps({key: trial.summary.get(key) for key in ["result", "attempts", "completed_attempts", "accepted_resolutions", "proved", "refuted", "unresolved", "unfinished", "unavailable", "unaccepted_candidates", "stopping_reason", "error"]}))
    return 0 if trial.summary["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
