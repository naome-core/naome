#!/usr/bin/env python3
"""Native provider-to-owner feedback with unchanged durable job allowances."""
import argparse
import json
import os
from pathlib import Path

from autonomous_lifecycle import Node, Trial, write_receipt
from long_jobs import job_settings, journal
from proof_network import digest
from resource_observation import latest


ROLES = ("finding", "solving", "local_interest", "peer_interest")


def observe_budgets(previous, state):
    assert state and state["records"]
    for record in state["records"].values():
        assert record["settings"]["limits"] == {"horizon_ms": 60000, "work_units": 64}, record
        assert record["expires_ms"] == record["created_ms"] + 60000, record
        assert 0 <= record["checkpoint"] <= record["settings"]["mock"]["steps"] == 2, record
        assert record["checkpoint"] <= record["reserved_units"] <= 64, record
        before = previous.get(record["id"])
        if before is not None:
            for field in ("input", "binding", "provider", "configuration", "settings", "created_ms", "expires_ms"):
                assert record[field] == before[field], (field, before, record)
            for field in ("checkpoint", "reserved_units", "spent_ms"):
                assert record[field] >= before[field], (field, before, record)
        previous[record["id"]] = record


def run(trial):
    os.environ["NAOME_DEV_RESOURCE_OBSERVATIONS"] = "1"
    trial.summary["provider_feedback_driver_sha256"] = digest(__file__)
    source, receiver = (Node(trial, index) for index in range(2))
    settings = job_settings(**{role: {"steps": 2, "step_ms": 15, "cpu_ms": 10,
                                    "horizon_ms": 60000, "work_units": 64}
                               for role in ("finding", "solving", "interest")})
    for node in trial.nodes:
        node.config["runtime"]["jobs"] = settings
        node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
        node.write_config()
        node.start()
        node.stop()
    source.config["runtime"]["question_interval_ms"] = 100
    for node, peer in ((source, receiver), (receiver, source)):
        node.config["peers"] = [{"id": peer.peer, "address": f"/ip4/127.0.0.1/tcp/{peer.port}"}]
        node.write_config()
    receiver.start()
    source.start()
    # A ready native node may still be in the existing 30-second OS-pressure
    # recovery window. Wait for real admission without bypassing its sensors.
    trial.wait(lambda: all(trial.call(node, "status")["computation"] == "running"
                           for node in trial.nodes), maximum=40)
    budgets = {node.index: {} for node in trial.nodes}

    def observed():
        for node in trial.nodes:
            state = journal(node)
            if state and state["records"]:
                observe_budgets(budgets[node.index], state)
        observations = [latest(node) for node in trial.nodes]
        if not all(observations):
            return None
        assert all(report["capacity_bytes"] > 0 for report in observations)
        reports = [report["feedback"]["providers"] for report in observations]
        selected = {role: next((report[role] for report in reports
                                if report[role]["completed"] > 0), None) for role in ROLES}
        return (reports, selected) if all(selected.values()) else None

    reports, selected = trial.wait(observed, maximum=30)
    for role, report in selected.items():
        assert report["checkpointed_units"] >= 2, (role, report)
        assert report["service_nanos"] > 0, (role, report)
        for phase in ("setup", "work", "finalization"):
            cost = report[phase]
            assert cost["samples"] > 0, (role, phase, cost)
            assert cost["cpu_samples"] == cost["samples"], (role, phase, cost)
            assert cost["elapsed_nanos"] >= cost["blocked_nanos"], (role, phase, cost)
            assert cost["peak_rss_bytes"] > 0, (role, phase, cost)
        assert report["work"]["cpu_nanos"] > 0, (role, report)
    trial.wait(lambda: source.ids() & receiver.ids(), maximum=20)
    for node in trial.nodes:
        observe_budgets(budgets[node.index], journal(node))
        assert trial.call(node, "status")["running"]
    trial.summary.update(result="pass", provider_feedback=reports,
        observed_job_budgets={index: len(records) for index, records in budgets.items()},
        claim="real isolated provider workers report all phases and roles to the node owner; telemetry does not change durable job limits or proof admission")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--mode", choices=["provider-feedback"], default="provider-feedback")
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "provider-feedback")
    try:
        run(trial)
    except BaseException as error:
        trial.summary.update(result="fail", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        trial.close()
        write_receipt(trial.output / "result.json", trial.summary)
    assert trial.summary["result"] == "pass"


if __name__ == "__main__":
    main()
