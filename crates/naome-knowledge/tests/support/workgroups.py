#!/usr/bin/env python3
"""Two ordinary processes coordinate a finite request over real libp2p."""
import argparse
from pathlib import Path
import shutil

from native_goal import records

from autonomous_lifecycle import Node, Trial, retain_evidence


def run(trial, args):
    requester, helper = Node(trial, 0), Node(trial, 1)
    for node in trial.nodes:
        node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
        node.write_config()
        node.start()
        node.stop()
    if args.seed:
        shutil.copytree(args.seed, requester.directory, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("identity.key"))
        assert args.definition_id in requester.ids()
        assert args.definition_id not in helper.ids()
    for node, other in ((requester, helper), (helper, requester)):
        node.config["peers"] = [{"id": other.peer, "address": f"/ip4/127.0.0.1/tcp/{other.port}"}]
    if args.helper_provider == "native":
        helper.config["runtime"]["jobs"] = {"native_proof_learning": True}
    requester.config["runtime"]["question_interval_ms"] = 3600000 if args.seed else 100
    if args.seed:
        requester.config["runtime"]["proof_interval_ms"] = 2000
    # This controlled failure makes the requester's need observable; the helper
    # uses the native solver and normal checked publication path.
    requester.config["runtime"]["jobs"] = {"solving": {"mock": {"outcome": "failed"}}}
    for node in trial.nodes:
        node.write_config()
    helper.start()
    requester.start()

    def completed():
        failures = [event for node in trial.nodes for event in node.logs()
                    if event.get("event") == "fatal_error"]
        assert not failures, failures
        for joined in (e for e in helper.logs() if e.get("event") == "workgroup_joined"):
            if args.seed and joined["resolution_id"] != args.resolution:
                continue
            for generated in (e for e in helper.logs() if e.get("event") == "proof_generated"
                              and e.get("resolution_id") == joined["resolution_id"]):
                root = generated["id"]
                if args.seed and root != args.expected_proof:
                    continue
                membership = any(e.get("event") == "workgroup_member"
                                 and e.get("resolution_id") == joined["resolution_id"]
                                 and e.get("peer") == helper.peer for e in requester.logs())
                if membership and root in requester.ids() and root in helper.ids():
                    return {"resolution": joined["resolution_id"], "root": root,
                            "job": generated["job"]}
        return None

    result = trial.wait(completed, maximum=60)
    source = "native_solver" if args.helper_provider == "native" else "mock_producer"
    assert any(e.get("event") == "accepted" and e.get("source") == source
               and e.get("id") == result["root"] for e in helper.logs())
    if not args.seed:
        assert any(e.get("event") == "question_generated" for e in requester.logs())
    else:
        events = helper.logs()
        offer = next(i for i, e in enumerate(events) if e.get("event") == "exchange_request"
                     and e.get("kind") == "work_offer" and e.get("peer") == requester.peer)
        fetched = next(i for i, e in enumerate(events) if e.get("event") == "accepted"
                       and e.get("source") == "fetch" and e.get("id") == args.definition_id)
        joined = next(i for i, e in enumerate(events) if e.get("event") == "workgroup_joined"
                      and e.get("resolution_id") == result["resolution"])
        assert offer < fetched < joined, (offer, fetched, joined)
        assert args.definition_id in helper.ids()
        assert any(record.get("id") == result["job"]
                   and record.get("binding", {}).get("cooperative")
                   and record.get("input", {}).get("role") == "solve"
                   and record.get("result", {}).get("kind") == "proof"
                   for record in records(helper)), "no completed cooperative mock proof job"
    assert any(e.get("event") == "exchange_request" and e.get("kind") == "work_offer"
               for e in helper.logs())
    assert any(e.get("event") == "workgroup_receipt" and e.get("status") == "queued"
               for e in requester.logs())
    assert not any(e.get("event") == "rejected" and e.get("error") == "unexpected response kind"
                   for node in trial.nodes for e in node.logs())
    assert any(e.get("event") == "accepted" and e.get("id") == result["root"]
               and e.get("source") == "fetch" for e in requester.logs())
    if args.seed:
        requester.stop()
        assert result["root"] in requester.ids()
        requester.start()
        assert result["root"] in requester.ids(), "checked proof did not survive requester restart"
    trial.summary["claim"] = ("Two ordinary local node processes exchange a work offer and a "
                              "checked proof. The requester uses an injected solver failure; "
                              f"the helper uses the {args.helper_provider} solver. No multi-host or "
                              "mathematical performance claim.")
    trial.summary["helper_provider"] = args.helper_provider
    trial.summary["scenarios"]["cooperative_checked_proof"] = result
    trial.summary["result"] = "pass"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--profile", default="test")
    parser.add_argument("--helper-provider", choices=("native", "mock"), default="native")
    parser.add_argument("--seed", type=Path)
    parser.add_argument("--definition-id")
    parser.add_argument("--resolution")
    parser.add_argument("--expected-proof")
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "workgroups")
    try:
        run(trial, args)
    except BaseException as error:
        trial.summary.update(result="fail", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "workgroups", args.profile)
    assert trial.summary["result"] == "pass", trial.summary.get("cleanup")


if __name__ == "__main__":
    main()
