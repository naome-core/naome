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
    try:
        return read_snapshot(node)
    except sqlite3.OperationalError as error:
        if "locked" in str(error).lower() or "busy" in str(error).lower():
            return None
        raise


def observe(node):
    return node.trial.wait(lambda: snapshot(node), maximum=5)


def read_snapshot(node):
    # The observer yields to the canonical writer; the original trial deadline
    # still bounds every retry and no production reservation is changed.
    with sqlite3.connect((node.directory / "research/jobs.sqlite3").as_uri() + "?mode=ro", uri=True, timeout=0.01) as db:
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
    current=snapshot(node)
    return [r for r in current["records"].values() if r["input"]["role"] == "train"] if current else []


def checkpoint_identity(record):
    return {key: record[key] for key in ("id", "input", "binding", "settings", "created_ms", "expires_ms")}


def verify_blobs(node, record):
    candidate = record["native"]["progress"]["candidate"]
    assert candidate and candidate["updates"] >= 10
    result = {}
    output=node.trial.output / "checkpoints" / f"node-{node.index}"
    output.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect((node.directory / "research/jobs.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        for name in ("model", "optimizer"):
            blob = candidate[name]
            rows = db.execute("SELECT payload FROM entries WHERE kind='model' AND key LIKE ? ORDER BY key", (blob["sha256"] + ":%",)).fetchall()
            payload = b"".join(row[0] for row in rows)
            assert len(payload) == blob["bytes"] and hashlib.sha256(payload).hexdigest() == blob["sha256"]
            (output / f"{name}.bpk").write_bytes(payload)
            result[name] = blob
    write_receipt(output / "manifest.json", {"status":"candidate_at_resource_pause_not_promoted", "job":checkpoint_identity(record), "checkpoint":candidate, "blobs":result})
    return result


def owner_question_bootstrap():
    # Behavioral input fixture: only original learning questions, never proofs,
    # model checkpoints, labels or held-out questions. Production question
    # selection stays with the ordinary frontier and stopped-node formal_goal.
    selected = [
        'bb0a38ed5a32be6924e0f40e13adcace4a5707380f5182079833bb79d56167e3',
        '93595ecf761e390236e9b80108cfd6ecc89063976f661681ce6e24e213048b29',
        'dfcee7f50acce5cbb6aa4f1d2e1ea2f3081e3fd8bd4b9d77a776ad000208e7df',
        '107052ea6c992e207ca6404504e4a44e5c25e57d176b3d0bd1bce7d15ef24177',
        'f12a94b9445e2fb85d7d74f4d79ba58fc8cca44286a0a6d351cf519201f7bc15',
        '72c9c8f5c102913bf453af11e24c297c1d21985a79bd5155430dd8c4f41e1e4b',
        '3c5f642a27a46cfd3276bb5f4d8f1af9615c6adea735d79a07b006366ec9fbe3',
        '0e1ae626b621ee8d82b8292a13d85c67a5b38a4be7257927b696c354e645f096',
        '6c24f3377213a87032d7699a0e9a45425b38c0fff6506121cb81f444a2f447b2',
        '4e34192bdfecc9bf55d31e6317abe33b0bf38e8cef52e3c3ae6a45728302a5b6',
        'c8a22023d7774563c9ffd5935c8bb08e272914b7ec258769cea6c31bdbafccf4',
        '55863d678b1514ca850945ce5eb0e425708838d075550dd747a6c86d4d934081',
        '88565fab041675cc6c37b77c1ed0fdece6f8e031aad77378dec561af945bc74d',
        'b00ac0a687d2283f21c3ebbef14e0e7d5e131a3ad2337ebbe83a571e9a635fb7',
        '691a2278ba2eed48c0a18e846483dd8a9d599c5a25d677686b29a6fd61003032',
        '2ae1be2e4a0d8fd78731e0fcf0550590bd1d9aa0a2f7d8d565054112680ad63e',
        'fbda6c392c3e439fa03c2707742d08c15ad49945a67bbddd0dcb1d28bba6d9af',
        '401cc9a2a7af5fef8e69e1cfbf9b0d31cee3a3fd3b4b4399a3c7573cd1a24625',
        'fa8c8dc4abe49bdb46471b70725d1f9a344d7cdd208b5e14e102a154d21ddd4b',
        'dc3264af465bb547e19b537eef5b0ff1bb9bd78271f34800116b9e9fcf71c849',
        'e4fb6549846a9632cf2e79195117145ca324399060e53582e0e77d18fed42bb9',
        '5dcd55bed5c5bed3b8d24e091f36c9c453f8ec5981c37329ee40d00b967cc650',
        '58041a7a1015ba8997b02ff6198632565a5c26989c7349089926e3433c00add9',
        '5bae5d154490977e9dd84bbc099bb774ab9c034904dbf79d6630c81d5552eb75',
    ]
    corpus = json.loads((Path(__file__).resolve().parents[2] / "src/learning/curriculum.json").read_text())
    cases = {case["id"]: case for case in corpus["cases"]}
    assert all(not cases[identity]["development"] for identity in selected)
    assert len({cases[identity]["dependency"] for identity in selected}) >= 3
    return [cases[identity] for identity in selected]


def finished_owner_goal(node, question):
    current = snapshot(node)
    if not current:
        return None
    for record in current["records"].values():
        if record["input"] != {"role": "solve", "question": question} or record["state"] != "complete":
            continue
        solution = record["native"]["progress"]["result"]
        if solution is not None:
            assert not solution["refuted"]
            if not any(event.get("event") == "proof_generated" and event["job"] == record["id"]
                       and event["id"] in node.ids() for event in node.logs()):
                return None
        return {"job": record["id"], "solved": solution is not None,
                "diagnostic": record["native"]["progress"]["diagnostic"],
                "local_examples": current["learning"]["local_examples"]}
    return None


def run(trial):
    a, b = Node(trial, 0), Node(trial, 1)
    for node in trial.nodes:
        node.config["runtime"]["jobs"] = {"native_proof_learning": True}
        node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
        node.write_config()
        node.start()
        initial = observe(node)["learning"]
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
    bootstrap = []
    for case in owner_question_bootstrap():
        a.config["formal_goal"] = case["source"]
        a.write_config()
        a.start()
        outcome = trial.wait(lambda: finished_owner_goal(a, case["source"]), maximum=20)
        bootstrap.append({"question_id": case["id"], "dependency": case["dependency"], **outcome})
        if observe(a)["learning"]["local_examples"] >= 8:
            break
        a.stop()
    else:
        raise AssertionError("ordinary question-only bootstrap did not produce a diverse learning batch")
    trial.summary["owner_question_bootstrap"] = bootstrap
    trial.summary["bootstrap_scope"] = "Question-only ordinary formal goals; automatic learning, publication and peer conversion. This does not qualify unseeded frontier learning."

    def own_and_peer():
        own, peer = snapshot(a), snapshot(b)
        if own is None or peer is None:
            return None
        if own["learning"]["local_examples"] and peer["learning"]["peer_examples"]:
            assert peer["learning"]["local_examples"] == 0
            learned = [r for r in peer["peer_receipts"].values() if "Learned" in r["status"]]
            assert learned and all(r["admission"]["peer"] == a.peer for r in learned)
            assert all(r["admission"]["artifact"] in b.ids() for r in learned)
            return {"source": own["learning"], "receiver": peer["learning"], "receipts": learned}
        return None

    trial.summary["own_and_peer"] = trial.wait(own_and_peer, maximum=120)
    retained = {}
    # Observe the sender first: its smaller own-proof batch can finish while
    # the receiver is still reconstructing enough peer trajectories. Resume it
    # immediately after its own pause/recovery check so ordinary discovery and
    # publication can continue supplying the receiver's unchanged quorum.
    for node in (a, b):
        record = trial.wait(lambda: next((r for r in training(node) if r["state"] == "running" and 0 < r["checkpoint"] < 25), None), maximum=180)
        pressure(node, True)
        trial.wait(lambda: state(trial, node, "paused"), maximum=8)
        # The current reserved quantum may finish before the next permit. Once
        # quiescent, every durable model IO/checkpoint and admitted set must hold.
        end = min(trial.deadline, time.monotonic() + 10)
        previous = None
        while time.monotonic() < end:
            current = observe(node)["records"][record["id"]]
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
            now = observe(node)["records"][current["id"]]
            assert (now["checkpoint"], now["reserved_units"], now["native"]["io_bytes"]) == frozen
            assert node.ids() == accepted
        retained[node.index] = {"record": current, "blobs": blobs, "accepted": sorted(accepted)}
        node.stop()
        if node is b:
            node.config["runtime"]["question_interval_ms"] = 3600000
            node.write_config()
        pressure(node, False)
        node.start()
        original = retained[node.index]["record"]
        restored = observe(node)["records"][original["id"]]
        assert checkpoint_identity(restored) == checkpoint_identity(original)
        assert restored["checkpoint"] >= original["checkpoint"]
        assert restored["reserved_units"] >= original["reserved_units"]
        assert restored["spent_ms"] >= original["spent_ms"]
        assert restored["native"]["base_hash"] == original["native"]["base_hash"]
    write_receipt(trial.output / "retained-checkpoints.json", retained)

    qualifications = {}
    for node in trial.nodes:
        original = retained[node.index]["record"]
        completed = trial.wait(lambda: next((r for r in training(node) if r["id"] == original["id"] and r["state"] == "complete"), None), maximum=180)
        assert completed["checkpoint"] == 126 and completed["native"]["progress"]["unit"] == 126
        progress = completed["native"]["progress"]
        assert progress["candidate"] is None
        assert progress["diagnostic"] in {"candidate_promoted", "no_development_gain_rejected", "forgetting_rejected", "development_regression_rejected"}
        assert observe(node)["learning"]["accepted"] > 0
        assert checkpoint_identity(completed) == checkpoint_identity(original)
        if progress["diagnostic"] != "candidate_promoted":
            assert progress["model"] == completed["native"]["base"]["model"], "rejection must restore the exact model AND Adam pair"
        else:
            assert progress["model"]["updates"] == completed["native"]["base"]["model"]["updates"] + 250
        qualifications[node.index] = {"job": original["id"], "diagnostic": progress["diagnostic"], "incumbent_score": progress["incumbent_score"], "candidate_score": progress["candidate_score"], "anchor_regression": progress["anchor_regression"], "model": progress["model"], "io_bytes": completed["native"]["io_bytes"]}
    trial.summary["qualifications"] = qualifications
    trial.summary["restart_and_pause"] = {"result": "pass", "retained_training_jobs": [r["record"]["id"] for r in retained.values()]}
    trial.summary["claim"] = "Two ordinary loopback nodes, actual fresh 1,004,001-parameter CPU graph policy, own accepted and locally checked peer reconstruction, 250 candidate updates per retained job, native qualification/rollback, durable model+Adam recovery and automatic resource pause. No learned-performance or physical multi-host claim; selection follows the current research policy."
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
