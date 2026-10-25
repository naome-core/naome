#!/usr/bin/env python3
"""Automatic resource pause with real providers, live peering and original budgets."""
import argparse
import os
from pathlib import Path

from autonomous_lifecycle import Node, Trial, process_identity, write_receipt
from long_jobs import Probe, job_settings, journal
from program_replication import program_rows


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


def run(trial, donor_key):
    donor, receiver, publisher = (Node(trial, index) for index in range(3))
    trial.summary["node_count"] = 3
    probe = Probe(trial)
    donor.config["runtime"].update(jobs=job_settings(
        finding={"steps": 8, "step_ms": 1000, "cpu_ms": 100, "horizon_ms": 120000},
        solving={"program_units": 8, "cpu_ms": 50, "horizon_ms": 120000}))
    # A fixed test identity selects the streamed question first. The next
    # finding job stays in flight while that program is checked and published.
    key_path = donor.directory / "identity.key"
    with key_path.open("xb") as key:
        key.write(bytes.fromhex(donor_key))
    key_path.chmod(0o600)
    for node in trial.nodes:
        node.write_config()
        node.start()
        node.stop()
    for node in trial.nodes:
        node.config["discovery"] = {
            "mdns": False, "dht": True,
            "external_addresses": [f"/ip4/127.0.0.1/tcp/{node.port}"],
            "bootstrap": [] if node is donor else [
                {"id": donor.peer, "address": f"/ip4/127.0.0.1/tcp/{donor.port}"}],
        }
    donor.config["runtime"]["question_interval_ms"] = 100
    for node in trial.nodes:
        node.write_config()
    donor.start()
    published = trial.wait(lambda: next((row for row in program_rows(donor)
        if row["published"]), None), maximum=30)
    identity = published["id"]
    assert published["manifest"]["commands"] == 1024
    probe.observe(donor)
    original_process = dict(donor.process)
    original_peer = donor.peer
    endpoint = (donor.directory / "control.json").read_bytes()
    pressure(donor, True)
    trial.wait(lambda: state(trial, donor, "paused"), maximum=5)
    probe.observe(donor)
    before = journal(donor)
    running = [record for record in before["records"].values()
               if record["state"] == "running" and record["input"]["role"] == "find"]
    assert running, "pause did not retain an in-flight provider at a safe boundary"
    retained = running[0]
    frozen = checkpoints(donor)
    accepted = donor.ids()
    assert accepted == {identity}, "fixture published competing answers before pausing"
    offset = len(donor.logs())
    pressure(donor, True)
    assert state(trial, donor, "paused")
    assert trial.call(donor, "start")["computation"] == "paused"
    assert (donor.directory / "control.json").read_bytes() == endpoint
    assert process_identity(original_process["pid"]) == original_process

    # This peer starts after the pause and bootstraps through the paused node.
    receiver.start()
    trial.wait(lambda: any(event.get("event") == "identified" and event.get("peer") == receiver.peer
        for event in donor.logs()[offset:]), maximum=15)
    assert any(event.get("event") == "identified" and event.get("peer") == receiver.peer
               for event in donor.logs()[offset:]), "new peer was not admitted during pause"

    # Fresh publications must still reach the paused node's live gossip mesh.
    publisher.config["runtime"]["question_interval_ms"] = 1000
    publisher.write_config()
    publisher.start()
    trial.wait(lambda: any(event.get("event") == "identified"
        and event.get("peer") == publisher.peer for event in donor.logs()[offset:]))
    announcement = trial.wait(lambda: next((event for event in donor.logs()[offset:]
        if event.get("event") == "announcement" and event.get("id") not in accepted), None), maximum=15)
    assert state(trial, donor, "paused")
    assert checkpoints(donor) == frozen, "productive work advanced during network service"
    assert donor.ids() == accepted, "paused node admitted unchecked or newly fetched data"
    assert not any(event.get("event") in {"question_generated", "research_started", "accepted"}
                   for event in donor.logs()[offset:])
    probe.observe(publisher)
    probe.observe(receiver)

    pressure(donor, False)
    trial.wait(lambda: state(trial, donor, "running"), maximum=40)
    resumed = trial.wait(lambda: next((record for record in journal(donor)["records"].values()
        if record["id"] == retained["id"] and record["checkpoint"] > retained["checkpoint"]), None), maximum=5)
    assert resumed["created_ms"] == retained["created_ms"]
    assert resumed["expires_ms"] == retained["expires_ms"]
    assert resumed["binding"] == retained["binding"]
    assert resumed["reserved_units"] >= retained["reserved_units"]
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
        checked_program=identity, paused_checkpoints=frozen,
        resumed_job=resumed["id"], gossip_announcement=announcement,
        claim="native automatic memory-target pause; real provider checkpoint retention and resume with original budgets; DHT peering and gossip remain live; CPU-only checked delivery is qualified separately")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--mode", choices=["pause"], default="pause")
    parser.add_argument("--donor-key", required=True)
    args = parser.parse_args()
    assert os.name == "posix"
    trial = Trial(args.binary, args.output, args.timeout, args.profile, args.mode)
    try:
        run(trial, args.donor_key)
    except BaseException as error:
        trial.summary.update(result="fail", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        trial.close()
        write_receipt(trial.output / "result.json", trial.summary)
    assert trial.summary["result"] == "pass", trial.summary


if __name__ == "__main__":
    main()
