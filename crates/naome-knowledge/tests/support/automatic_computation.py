#!/usr/bin/env python3
"""Automatic memory pause with real providers, live control and original budgets."""
import argparse
import os
from pathlib import Path

from autonomous_lifecycle import Node, Trial, process_identity, write_receipt
from long_jobs import Probe, job_settings, journal


def state(trial, node, expected):
    status = trial.call(node, "status")
    assert status["running"], status
    return status if status["computation"] == expected else None


def pressure(node, constrained):
    # Exercise the ordinary current-format soft memory target without consuming
    # host resources or changing immutable capacity. Actual memory shortage may
    # refuse payload allocations; CPU-only serving has a separate native test.
    selection = {"profile": "custom", "custom": {
        "memory_bytes": 8 * 1024 * 1024, "concurrency": 1,
        "cache_bytes": 4096, "batch_steps": 1, "network_requests": 1,
    }} if constrained else {"profile": "heavy", "custom": None}
    write_receipt(node.directory / "resource-profile.json", selection)


def checkpoints(node):
    return {record["id"]: (record["reserved_units"], record["checkpoint"])
            for record in journal(node)["records"].values()}


def run(trial):
    donor = Node(trial, 0)
    trial.summary["node_count"] = 1
    probe = Probe(trial)
    donor.config["runtime"].update(jobs=job_settings(
        finding={"steps": 64, "step_ms": 1000, "cpu_ms": 100, "horizon_ms": 120000}))
    for node in trial.nodes:
        node.write_config()
        node.start()
        node.stop()
    donor.config["runtime"]["question_interval_ms"] = 100
    for node in trial.nodes:
        node.write_config()
    donor.start()
    trial.wait(lambda: next((record for record in journal(donor)["records"].values()
        if record["state"] == "running" and record["input"]["role"] == "find"
        and record["checkpoint"] > 0), None), maximum=15)
    probe.observe(donor)
    original_process = dict(donor.process)
    original_peer = donor.peer
    endpoint = (donor.directory / "control.json").read_bytes()
    pressure(donor, True)
    paused = trial.wait(lambda: state(trial, donor, "paused"), maximum=5)
    assert paused["computation_reason"], paused
    probe.observe(donor)
    before = journal(donor)
    running = [record for record in before["records"].values()
               if record["state"] == "running" and record["input"]["role"] == "find"]
    assert running, "pause did not retain an in-flight provider at a safe boundary"
    retained = running[0]
    frozen = checkpoints(donor)
    accepted = donor.ids()
    assert not accepted, "controlled finding job completed before the automatic pause"
    offset = len(donor.logs())
    pressure(donor, True)
    assert state(trial, donor, "paused")
    assert trial.call(donor, "start")["computation"] == "paused"
    assert (donor.directory / "control.json").read_bytes() == endpoint
    assert process_identity(original_process["pid"]) == original_process

    # True memory exhaustion can refuse both payload and connection buffers.
    # Keep the native provider/control oracle independent of the CPU-pause
    # transport oracle, which tests new peering, gossip and checked delivery.
    for _ in range(3):
        status = trial.call(donor, "status")
        assert status["running"] and status["computation"] == "paused"
        assert status["computation_reason"], status
        assert checkpoints(donor) == frozen, "productive work advanced during resource pause"
        assert donor.ids() == accepted, "paused node published or admitted new work"
    assert not any(event.get("event") in {"question_generated", "research_started", "accepted"}
                   for event in donor.logs()[offset:])

    pressure(donor, False)
    trial.wait(lambda: state(trial, donor, "running"), maximum=40)
    resumed = trial.wait(lambda: next((record for record in journal(donor)["records"].values()
        if record["id"] == retained["id"] and record["checkpoint"] > retained["checkpoint"]), None), maximum=5)
    assert resumed["created_ms"] == retained["created_ms"]
    assert resumed["expires_ms"] == retained["expires_ms"]
    assert resumed["binding"] == retained["binding"]
    assert resumed["reserved_units"] >= retained["reserved_units"]
    assert resumed["spent_ms"] >= retained["spent_ms"]
    assert resumed["settings"] == retained["settings"]
    pressure(donor, True)
    trial.wait(lambda: state(trial, donor, "paused"), maximum=5)
    probe.observe(donor)
    donor.stop()
    donor.config["runtime"]["question_interval_ms"] = 3600000
    donor.write_config()
    pressure(donor, False)
    assert donor.start()["computation"] == "running"
    assert donor.peer == original_peer
    assert process_identity(donor.process["pid"]) == donor.process
    trial.summary.update(result="pass", fixture="automatic_resource_computation_pause",
        paused_checkpoints=frozen,
        resumed_job=resumed["id"],
        claim="native automatic memory-target pause; real provider checkpoint retention, live authenticated control and resume with original budgets; CPU-only transport service is qualified separately")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--mode", choices=["pause"], default="pause")
    args = parser.parse_args()
    assert os.name == "posix"
    trial = Trial(args.binary, args.output, args.timeout, args.profile, args.mode)
    try:
        run(trial)
    except BaseException as error:
        trial.summary.update(result="fail", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        trial.close()
        write_receipt(trial.output / "result.json", trial.summary)
    assert trial.summary["result"] == "pass", trial.summary


if __name__ == "__main__":
    main()
