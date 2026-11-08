#!/usr/bin/env python3
"""An ordinary cold peer resolves definitions before joining a work offer."""
import argparse
from pathlib import Path
import shutil

from autonomous_lifecycle import Node, Trial, retain_evidence
from native_goal import records


def run(trial, args):
    requester, helper = Node(trial, 0), Node(trial, 1)
    for node in trial.nodes:
        node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
    shutil.copytree(args.seed, requester.directory, dirs_exist_ok=True)
    requester.config["runtime"]["jobs"] = {"native_proof_learning": True}
    helper.config["runtime"]["jobs"] = {"native_proof_learning": True}
    requester.write_config()
    helper.write_config()
    requester.start()
    assert args.definition_id in requester.ids()
    assert args.definition_id not in helper.ids()
    requester.stop()
    requester.config["formal_goal"] = args.question
    requester.config["runtime"]["question_interval_ms"] = 100
    # Initialize the helper's identity without connecting it to the requester.
    # Its graph is still empty before the work offer can arrive.
    helper.config["peers"] = []
    helper.write_config()
    helper.start()
    assert args.definition_id not in helper.ids()
    helper.stop()
    requester.config["peers"] = [{"id": helper.peer, "address": f"/ip4/127.0.0.1/tcp/{helper.port}"}]
    helper.config["peers"] = [{"id": requester.peer, "address": f"/ip4/127.0.0.1/tcp/{requester.port}"}]
    requester.write_config()
    helper.write_config()
    helper.start()
    assert args.definition_id not in helper.ids()
    requester.start()

    def joined():
        for node in trial.nodes:
            assert not [event for event in node.logs() if event.get("event") == "fatal_error"]
        events = helper.logs()
        offer = next((i for i, event in enumerate(events) if event.get("event") == "exchange_request"
                      and event.get("kind") == "work_offer" and event.get("peer") == requester.peer), None)
        accepted = next((i for i, event in enumerate(events) if event.get("event") == "accepted"
                         and event.get("source") == "fetch" and event.get("id") == args.definition_id), None)
        membership = next((i for i, event in enumerate(events) if event.get("event") == "workgroup_joined"
                           and event.get("peer") == requester.peer and event.get("resolution_id") == args.resolution), None)
        if offer is None or accepted is None or membership is None:
            return None
        assert offer < accepted < membership, (offer, accepted, membership)
        assert args.definition_id in helper.ids()
        jobs = [record for record in records(helper)
                if record.get("binding", {}).get("cooperative")
                and record.get("input") == {"role": "solve", "question": args.target}]
        jobs = [job for job in jobs if any(event.get("event") == "research_started"
                    and event.get("job") == job["id"] for event in events)
                and any(event.get("event") == "research_finished" and event.get("state") == "Complete"
                        and event.get("job") == job["id"] for event in events)]
        if not jobs or not any(event.get("event") == "workgroup_member"
                               and event.get("peer") == helper.peer and event.get("active") is True
                               and event.get("resolution_id") == args.resolution
                               for event in requester.logs()):
            return None
        return {"offer_event": offer, "definition_event": accepted,
                "joined_event": membership, "jobs": [job["id"] for job in jobs]}

    result = trial.wait(joined, maximum=80)
    assert any(event.get("event") == "workgroup_member" and event.get("peer") == helper.peer
               and event.get("resolution_id") == args.resolution and event.get("active") is True
               for event in requester.logs())
    trial.summary["claim"] = ("Two ordinary local processes: the helper fetched and checked a previously "
                              "missing relation after an autonomous work offer, then started and completed a solve job. "
                              "This fixture makes no proof-completion or multi-host claim.")
    trial.summary["scenarios"]["cold_defined_offer"] = result
    trial.summary["result"] = "pass"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--seed", type=Path, required=True)
    parser.add_argument("--profile", default="test")
    for option in ("definition-id", "question", "resolution", "target"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "workgroups")
    try:
        run(trial, args)
    except BaseException as error:
        trial.summary.update(result="fail", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "defined-workgroup", args.profile)
    assert trial.summary["result"] == "pass", trial.summary.get("cleanup")


if __name__ == "__main__":
    main()
