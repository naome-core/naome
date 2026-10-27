#!/usr/bin/env python3
"""Ordinary formal-goal input, autonomous ZFC construction, gossip and replay."""
import argparse
import json
from pathlib import Path
import sqlite3

from autonomous_lifecycle import Node, Trial, retain_evidence, write_receipt
from proof_network import stored_objects
from types import SimpleNamespace


def inductive(variable):
    # This is part of the question's primitive meaning, not a proof, a supplied
    # definition artifact, or a witness. Production search has no Nat template.
    return (
        f"and(ex(e,and(all(z,not(mem(z,e))),mem(e,{variable}))),"
        f"all(n,imp(mem(n,{variable}),ex(s,and("
        "all(z,iff(mem(z,s),or(mem(z,n),eq(z,n)))),"
        f"mem(s,{variable}))))))"
    )


def question(set_name="w", element="x", bound="i"):
    return (f"goal=ex({set_name},all({element},iff(mem({element},{set_name}),"
            f"all({bound},imp({inductive(bound)},mem({element},{bound}))))))")


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
    a.config["runtime"]["jobs"] = {"native_proof_learning": True}
    for node in trial.nodes:
        node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
        node.write_config()
        node.start()
        assert not node.ids()
        node.stop()
    for node, other in ((a, b), (b, a)):
        node.config["peers"] = [{"id": other.peer, "address": f"/ip4/127.0.0.1/tcp/{other.port}"}]
    goal = question()
    assert len("formal: " + goal) <= 1024
    (trial.output / "goal.nao").write_text(goal + "\n")
    trial.call(a, "interest", text="formal: " + goal)
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
    assert "Constructed" in solution["tree"]
    assert not solution["refuted"]
    assert solution["cost"]["search_expansions"] <= 128
    assert source_record["reserved_units"] == source_record["checkpoint"] == 1
    public = trial.output / "generated"
    public.mkdir()
    (public / "proof.nao").write_text(solution["source"])
    for index, helper in enumerate(solution["helpers"]):
        (public / f"helper-{index:02}.nao").write_text(helper)
    objects = stored_objects(SimpleNamespace(directory=a.directory))
    definitions = [o["artifact_id"] for o in objects if o["statement_id"] is None]
    proofs = [o["artifact_id"] for o in objects if o["statement_id"] is not None]
    assert len(definitions) >= 2 and len(proofs) >= 3
    assert len(objects) == len(solution["helpers"]) + 1
    assert source_record["input"]["question"] == goal
    all_ids = a.ids()
    trial.wait(lambda: root in b.ids(), maximum=45)
    assert b.ids() == all_ids, "the exact checked dependency closure must cross peers"
    trial.summary["scenarios"]["construction"] = {
        "root": root, "proof_id": solution["proof_id"], "definitions": definitions,
        "proofs": proofs, "cost": solution["cost"], "job": produced["job"],
        "reserved_units": source_record["reserved_units"],
        "source_bytes": len(solution["source"]),
        "closure_source_bytes": len(solution["source"]) + sum(map(len, solution["helpers"])),
        "all_artifacts": sorted(all_ids), "actual_peer_closure": sorted(b.ids()),
    }
    for node in trial.nodes:
        node.stop()
        status = node.start()
        assert status["artifact_verification"] == "checked"
        assert node.ids() == all_ids
    trial.call(a, "interest", text="formal: " + question("omega", "value", "bound"))
    trial.call(a, "interest", text="formal: goal=ex(", success=False)
    assert a.ids() == all_ids
    invalid = "goal=ex(w,all(x,iff(mem(x,w),not(mem(x,x)))))"
    trial.call(a, "interest", text="formal: " + invalid)

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
                                               "alpha_renamed_goal": question("omega", "value", "bound")}
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
