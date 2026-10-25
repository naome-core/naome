#!/usr/bin/env python3
"""Native provider-to-owner feedback with unchanged durable job allowances."""
import argparse
import json
import os
import subprocess
from pathlib import Path

from autonomous_lifecycle import Node, Trial, write_receipt
from long_jobs import job_settings, journal
from proof_network import digest


ROLES = ("finding", "solving", "local_interest", "peer_interest")


def feedback(trial, node):
    command = [str(trial.binary), "--json", "resources"]
    result = subprocess.run(command, stdin=subprocess.DEVNULL,
        env={**os.environ, "NAOME_NODE_DIR": str(node.directory)},
        capture_output=True, text=True, timeout=trial.remaining(10))
    trial.summary["commands"].append({"node": node.index, "command": command,
        "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
    assert result.returncode == 0, result.stderr
    assert not result.stderr, result.stderr
    report = json.loads(result.stdout)
    assert report["installed_capacity"]["memory_bytes"] > 0
    return report["feedback"]["providers"]


def run(trial):
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

    def observed():
        reports = [feedback(trial, node) for node in trial.nodes]
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
        state = journal(node)
        assert state and state["records"]
        for record in state["records"].values():
            assert record["settings"]["limits"] == {"horizon_ms": 60000, "work_units": 64}, record
            assert record["expires_ms"] == record["created_ms"] + 60000, record
            assert record["checkpoint"] <= record["reserved_units"] <= 64, record
            assert record["reserved_units"] <= 2, record
        assert trial.call(node, "status")["running"]
    trial.summary.update(result="pass", provider_feedback=reports,
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
