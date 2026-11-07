#!/usr/bin/env python3
"""Ordinary formal-goal input, autonomous ZFC construction, gossip and replay."""
import argparse
import json
from pathlib import Path
import sqlite3

from autonomous_lifecycle import Node, Trial, retain_evidence, write_receipt
from proof_network import stored_objects
from native_learning import snapshot
from types import SimpleNamespace


# Primitive encoding of the least inductive set membership characterization.
GOAL = (
    "02040204020303010100000000010000000104030203020402020304020101000000000100000001020101000000"
    "00010000000102040301010000000001000000010204020203040203030101000000000100000001030201010000"
    "00000100000002000100000000010000000202030302010100000000010000000200010000000001000000020101"
    "00000000010000000102010100000000010000000201010000000101000000000203040302030204020203040201"
    "01000000000100000001020101000000000100000001020403010100000000010000000102040202030402030301"
    "01000000000100000001030201010000000001000000020001000000000100000002020303020101000000000100"
    "00000200010000000001000000020101000000000100000001020101000000000100000002010100000001010000"
    "00000101000000000100000001"
)
UNPROVED = "02040204020303010100000000010000000102010100000000010000000002030201010000000001000000000101000000000100000001"


def records(node):
    try:
        path = node.directory / "research/jobs.sqlite3"
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.01) as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT payload FROM entries WHERE kind='record'")]
    except sqlite3.OperationalError as error:
        if "locked" in str(error).lower() or "busy" in str(error).lower():
            return []
        raise


def run(trial):
    trial.summary["claim"] = (
        "question-only Nat membership characterization; native ZFC schema "
        "search and checked definitions/lemmas; ordinary loopback peers and "
        "restart, no supplied proof or trained checkpoint; no Peano qualification")
    a, b = Node(trial, 0), Node(trial, 1)
    for node in trial.nodes:
        node.config["runtime"]["jobs"] = {"native_proof_learning": True}
        node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
        node.write_config()
        node.start()
        assert not node.ids()
        node.stop()
    for node, other in ((a, b), (b, a)):
        node.config["peers"] = [{"id": other.peer, "address": f"/ip4/127.0.0.1/tcp/{other.port}"}]
    goal = GOAL
    (trial.output / "goal.nao").write_bytes(bytes.fromhex(goal))
    a.config["formal_goal"] = goal
    a.config["runtime"]["question_interval_ms"] = 1000
    for node in trial.nodes:
        node.write_config()
    b.start()
    a.start()

    def published():
        assert not [event for node in trial.nodes for event in node.logs()
                    if event.get("event") == "fatal_error"]
        accepted = a.ids()
        return next((event for event in a.logs() if event.get("event") == "proof_generated"
                     and event["id"] in accepted), None)

    produced = trial.wait(published, maximum=45)
    root = produced["id"]
    source_record = trial.wait(lambda: next((r for r in records(a)
        if r["id"] == produced["job"] and r["native"]["progress"]["result"]), None))
    assert source_record["input"] == {"role": "solve", "question": goal}
    solution = source_record["native"]["progress"]["result"]
    assert "Program" in solution["tree"] and solution["source"] == ""
    assert not solution["refuted"]
    assert solution["cost"]["search_expansions"] <= 128
    assert source_record["reserved_units"] == source_record["checkpoint"] == 1
    # Publication precedes the journal owner's independent full-DAG replay.
    # That checked receipt takes about ten seconds for this 1,220-step closure;
    # retain the original overall 120-second trial bound while observing it.
    own_learning = trial.wait(lambda: next((current["learning"] for current in [snapshot(a)]
        if current and any(example["job"] == produced["job"]
            for example in current["learning"]["replay"])), None), maximum=30)
    learned = next(example for example in own_learning["replay"] if example["job"] == produced["job"])
    assert learned["origin"] == "Local" and learned["proof_id"] == solution["proof_id"]
    assert own_learning["accepted"] == own_learning["local_examples"] == 1
    assert own_learning["model"]["updates"] == 0, "one construction must not bypass diverse-batch readiness"
    trial.summary["scenarios"]["own_construction_learning"] = {
        "accepted": own_learning["accepted"], "local_examples": own_learning["local_examples"],
        "job": learned["job"], "proof_id": learned["proof_id"], "trace": learned["tree"],
        "retained_updates": own_learning["model"]["updates"],
    }
    public = trial.output / "generated"
    public.mkdir()
    for index, helper in enumerate(solution["helpers"]):
        (public / f"helper-{index:02}.nao").write_bytes(bytes.fromhex(helper))
    objects = stored_objects(SimpleNamespace(directory=a.directory))
    program = next(o["program_manifest"] for o in objects if o["artifact_id"] == root)
    checked_program = next(e for e in a.logs()
        if e.get("event") == "native_program_checked" and e.get("id") == root)
    assert checked_program["job"] == produced["job"]
    assert checked_program["input_bytes"] == program["input_bytes"]
    assert checked_program["checker_work"] > 0
    definitions = [o["artifact_id"] for o in objects if o["statement_id"] is None]
    proofs = [o["artifact_id"] for o in objects if o["statement_id"] is not None]
    assert len(definitions) >= 2 and len(proofs) >= 3
    assert len(objects) == len(solution["helpers"]) + 1
    assert source_record["input"]["question"] == goal
    all_ids = a.ids()
    trial.wait(lambda: root in b.ids(), maximum=45)
    assert b.ids() == all_ids, "the exact checked dependency closure must cross peers"

    def peer_replay():
        current = snapshot(b)
        if not current:
            return None
        return next((example for example in current["learning"]["replay"]
                     if isinstance(example["origin"], dict)
                     and example["origin"].get("Peer", {}).get("artifact") == root), None)

    received = trial.wait(peer_replay, maximum=30)
    receiver_record = next(record for record in records(b) if record["id"] == received["job"])
    receiver_result = receiver_record["native"]["progress"]["result"]
    assert receiver_record["input"]["evidence"]["program"]["manifest"] == program
    assert receiver_result["tree"]["Program"]["manifest"] == program
    assert receiver_result["source"] == "" and receiver_result["helpers"] == []
    assert receiver_result["proof_id"] == received["proof_id"] == solution["proof_id"]
    assert receiver_record["input"]["artifact"] == root
    assert receiver_result["cost"]["unique_states"] > 0
    assert receiver_result["cost"]["search_expansions"] == 0
    assert snapshot(b)["learning"]["model"]["updates"] == 0
    trial.summary["scenarios"]["peer_program_replay"] = {
        "artifact": root, "proof_id": received["proof_id"],
        "decision_states": receiver_result["cost"]["unique_states"],
        "replay_wall_micros": receiver_result["cost"]["generation_micros"],
        "worker_peak_rss_bytes": receiver_result["cost"].get("process_peak_rss_bytes"),
        "model_updates": 0,
    }
    trial.summary["scenarios"]["construction"] = {
        "root": root, "proof_id": solution["proof_id"], "definitions": definitions,
        "proofs": proofs, "cost": solution["cost"], "job": produced["job"],
        "reserved_units": source_record["reserved_units"],
        "program": program, "program_check": checked_program,
        "helper_artifact_bytes": sum(map(len, solution["helpers"])) // 2,
        "all_artifacts": sorted(all_ids), "actual_peer_closure": sorted(b.ids()),
    }
    for node in trial.nodes:
        node.stop()
        status = node.start()
        assert status["artifact_verification"] == "checked"
        assert node.ids() == all_ids
    assert peer_replay() == received, "the exact peer program replay must survive restart"
    a.stop()
    a.config["formal_goal"] = GOAL
    a.write_config()
    a.start()
    assert a.ids() == all_ids
    a.stop()
    a.config["formal_goal"] = "04"
    a.write_config()
    trial.call(a, "start", success=False)
    invalid = UNPROVED
    a.config["formal_goal"] = invalid
    a.write_config()
    a.start()

    def exhausted():
        for record in records(a):
            if record["input"] == {"role": "solve", "question": invalid}:
                progress = record["native"]["progress"]
                if progress and progress["unit"] == 1:
                    assert progress["result"] is None
                    return {"job": record["id"], "diagnostic": progress["diagnostic"],
                            "reserved_units": record["reserved_units"], "cost": progress["cost"]}
        return None

    trial.summary["scenarios"]["unproved_control"] = trial.wait(exhausted, maximum=20)
    assert a.ids() == b.ids() == all_ids
    for node in trial.nodes:
        node.stop()
    trial.summary["scenarios"]["restart"] = {"exact_closure_rechecked": True,
                                               "canonical_goal": GOAL}
    trial.summary["result"] = "pass"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--profile", default="release")
    parser.add_argument("--mode", default="native-goal")
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, args.mode)
    try:
        run(trial)
    except BaseException as error:
        trial.summary.update(result="fail", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, args.mode, args.profile)
    assert trial.summary["result"] == "pass", trial.summary.get("cleanup")


if __name__ == "__main__":
    main()
