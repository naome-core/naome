#!/usr/bin/env python3
"""Two ordinary processes coordinate a finite request over real libp2p."""
import argparse
from pathlib import Path

from autonomous_lifecycle import Node, Trial, retain_evidence


def run(trial):
    requester, helper = Node(trial, 0), Node(trial, 1)
    for node in trial.nodes:
        node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
        node.write_config()
        node.start()
        node.stop()
    for node, other in ((requester, helper), (helper, requester)):
        node.config["peers"] = [{"id": other.peer, "address": f"/ip4/127.0.0.1/tcp/{other.port}"}]
    helper.config["runtime"]["jobs"] = {"native_proof_learning": True}
    requester.config["runtime"]["question_interval_ms"] = 100
    # This controlled failure makes the requester's need observable; the helper
    # uses the native solver and normal checked publication path.
    requester.config["runtime"]["jobs"] = {"solving": {"mock": {"outcome": "failed"}}}
    for node in trial.nodes:
        node.write_config()
    helper.start()
    requester.start()

    def completed():
        failures = [event for node in trial.nodes for event in node.logs()
                    if event.get("event") == 0x00170017]
        assert not failures, failures
        for joined in (e for e in helper.logs() if e.get("event") == 0x0017006c):
            for generated in (e for e in helper.logs() if e.get("event") == 0x00170046
                              and e.get("resolution_id") == joined["resolution_id"]):
                root = generated["id"]
                membership = any(e.get("event") == 0x0017006e
                                 and e.get("resolution_id") == joined["resolution_id"]
                                 and e.get("peer") == helper.peer for e in requester.logs())
                received = any(e.get("event") == 0x00170001 and e.get("id") == root
                               and e.get("source") == 0x00180001 for e in requester.logs())
                if membership and received and root in requester.ids() and root in helper.ids():
                    return {"resolution": joined["resolution_id"], "root": root}
        return None

    result = trial.wait(completed, maximum=60)
    assert any(e.get("event") == 0x00170001 and e.get("source") == 0x00180004
               and e.get("id") == result["root"] for e in helper.logs())
    assert any(e.get("event") == 0x0017004d for e in requester.logs())
    assert any(e.get("event") == 0x00170012 and e.get("kind") == 0x001a0011
               for e in helper.logs())
    assert any(e.get("event") == 0x0017006f and e.get("status") == 0x00050001
               for e in requester.logs())
    assert not any(e.get("event") == 0x00170051 and e.get("error") == 0x000b0024
                   for node in trial.nodes for e in node.logs())
    assert any(e.get("event") == 0x00170001 and e.get("id") == result["root"]
               and e.get("source") == 0x00180001 for e in requester.logs())
    trial.summary["claim"] = ("Two ordinary local node processes exchange a work offer and a "
                              "checked proof. The requester uses an injected solver failure; "
                              "the helper uses the native solver. No multi-host or "
                              "mathematical performance claim.")
    trial.summary["scenarios"]["cooperative_checked_proof"] = result
    trial.summary["result"] = "pass"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--profile", default="test")
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "workgroups")
    try:
        run(trial)
    except BaseException as error:
        trial.summary.update(result="fail", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "workgroups", args.profile)
    assert trial.summary["result"] == "pass", trial.summary.get("cleanup")


if __name__ == "__main__":
    main()
