#!/usr/bin/env python3
"""Automatic memory pause with real providers, live control and original budgets."""
import argparse
import os
from pathlib import Path
import time

from autonomous_lifecycle import Node, Trial, process_identity, retain_evidence, write_receipt
from long_jobs import Probe, job_settings, journal
from resource_observation import latest


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


def memory_recovery(trial, node, frozen, accepted):
    started = time.monotonic()
    receipt = {"elapsed_seconds": 0, "native_cpu_hold_observed": False}
    trial.summary["memory_recovery"] = receipt

    deadline = min(trial.deadline, started + 40)
    status = None
    while time.monotonic() < deadline:
        status = trial.call(node, "status")
        assert status["running"], status
        receipt["elapsed_seconds"] = time.monotonic() - started
        if status["computation"] == "running":
            receipt["result"] = "native_resume_observed"
            return status
        assert status["computation"] in {"pausing", "paused"}, status
        cpu_hold = status["computation_reason"] == "sustained external CPU pressure"
        receipt["native_cpu_hold_observed"] |= cpu_hold
        assert checkpoints(node) == frozen, "productive work advanced during resource pause"
        assert node.ids() == accepted, "paused node published or admitted new work"
        time.sleep(0.25)
    assert time.monotonic() < trial.deadline, "original whole-trial deadline expired"
    # Recovery from our memory target remains bounded by forty seconds. A
    # separate live CPU hold must remain closed, not be disabled for this test.
    # This outcome proves retained work and control, not native resumption.
    assert status and status["computation_reason"] == "sustained external CPU pressure", status
    receipt["result"] = "native_cpu_hold_preserved"
    return None


def run(trial):
    os.environ["NAOME_DEV_RESOURCE_OBSERVATIONS"] = "1"
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
    # Lifecycle readiness can correctly precede compute admission. Honor the
    # existing 30-second pressure recovery before the work-progress oracle;
    # the whole-driver deadline and the controlled pause checks are unchanged.
    trial.wait(lambda: state(trial, donor, "running"), maximum=40)
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
    recovered = memory_recovery(trial, donor, frozen, accepted)
    resumed = None
    finding_feedback = None
    if recovered:
        resumed = trial.wait(lambda: next((record for record in journal(donor)["records"].values()
            if record["id"] == retained["id"] and record["checkpoint"] > retained["checkpoint"]), None), maximum=5)
        for key in ("created_ms", "expires_ms", "binding", "settings"):
            assert resumed[key] == retained[key], key
        assert resumed["reserved_units"] >= retained["reserved_units"]
        assert resumed["spent_ms"] >= retained["spent_ms"]
        def observed_wait():
            observation = latest(donor)
            if observation is None:
                return None
            finding = observation["feedback"]["providers"]["finding"]
            return finding if finding["admission_wait_nanos"] >= 20_000_000_000 else None
        finding_feedback = trial.wait(observed_wait, maximum=5)
        pressure(donor, True)
        trial.wait(lambda: state(trial, donor, "paused"), maximum=5)
    probe.observe(donor)
    donor.stop()
    donor.config["runtime"]["question_interval_ms"] = 3600000
    donor.write_config()
    pressure(donor, False)
    donor.start()
    if recovered:
        trial.wait(lambda: state(trial, donor, "running"), maximum=40)
    restored = journal(donor)["records"][str(retained["id"])]
    for key in ("created_ms", "expires_ms", "binding", "settings"):
        assert restored[key] == retained[key], key
    assert restored["reserved_units"] >= retained["reserved_units"]
    assert restored["checkpoint"] >= retained["checkpoint"]
    assert donor.peer == original_peer
    assert process_identity(donor.process["pid"]) == donor.process
    trial.summary.update(result="pass", fixture="automatic_resource_computation_pause",
        paused_checkpoints=frozen,
        resumed_job=resumed["id"] if resumed else None,
        native_resume_observed=bool(resumed),
        finding_feedback=finding_feedback,
        claim="native automatic memory-target pause, retained provider budgets, live authenticated control and restart; native resumption is qualified only when explicitly observed; controlled gate recovery is tested independently")


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
        retain_evidence(trial.output, trial.summary, args.mode, args.profile)
    assert trial.summary["result"] == "pass", trial.summary


if __name__ == "__main__":
    main()
