#!/usr/bin/env python3
"""Replay the checked membership case through isolated ordinary nodes.

Usage: typed_proof_pair.py NAOME KNOWLEDGE_UNIT_TEST_BINARY OUTPUT_DIRECTORY
A transparent loopback forwarder counts delivered encrypted TCP payloads.
It does not terminate Noise, decode yamux, or count TCP/IP headers.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import socket
import subprocess
import threading
import time

from autonomous_lifecycle import Trial, process_cpu_sample, write_receipt
from program_replication import AutonomousNode
from proof_network import digest, stored_objects


class Meter:
    def __init__(self, target, incoming):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.target = target
        self.incoming = incoming
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.bytes = Counter()
        self.workers = []
        self.errors = []
        self.acceptor = threading.Thread(target=self.accept)
        self.acceptor.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                stream, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError as error:
                if not self.stop.is_set():
                    self.errors.append(str(error))
                break
            if len(self.workers) == 16:
                stream.close()
                self.errors.append("meter connection limit")
                break
            worker = threading.Thread(target=self.forward, args=(stream,))
            self.workers.append(worker)
            worker.start()

    def forward(self, stream):
        with stream:
            try:
                with socket.create_connection(("127.0.0.1", self.target), timeout=1) as other, selectors.DefaultSelector() as ready:
                    outgoing = "receiver_to_donor" if self.incoming == "donor_to_receiver" else "donor_to_receiver"
                    for source, target, direction in [(stream, other, self.incoming), (other, stream, outgoing)]:
                        source.settimeout(1)
                        source.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        ready.register(source, selectors.EVENT_READ, (target, direction))
                    while ready.get_map() and not self.stop.is_set():
                        for key, _ in ready.select(0.1):
                            target, direction = key.data
                            data = key.fileobj.recv(8192)
                            if data:
                                target.sendall(data)
                                with self.lock:
                                    self.bytes[direction] += len(data)
                                    if self.bytes.total() > 2_000_000:
                                        raise RuntimeError("meter byte limit")
                            else:
                                ready.unregister(key.fileobj)
                                target.shutdown(socket.SHUT_WR)
            except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError):
                pass  # Startup and retirement of duplicate authenticated connections.
            except (OSError, RuntimeError) as error:
                if not self.stop.is_set():
                    self.errors.append(str(error))

    def snapshot(self):
        with self.lock:
            return self.bytes.copy()

    def close(self):
        self.stop.set()
        self.acceptor.join(2)
        self.listener.close()
        for worker in self.workers:
            worker.join(2)
        assert not self.acceptor.is_alive() and all(not worker.is_alive() for worker in self.workers)


def seed(binary, test, variable, directory):
    result = subprocess.run(
        [str(binary), "--exact", "network::tests::typed_proof::" + test, "--nocapture"],
        env={**os.environ, variable: str(directory)}, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0 and "1 passed" in result.stdout, result.stdout + result.stderr


def run(binary, fixture, seeds, metadata, output, arm, temperature):
    trial = Trial(binary, output, 100, "test", "typed-proof-pair")
    trial.cleanup_timeout = 30
    meters = []
    report = {"arm": arm, "context": temperature}
    root = metadata[{"source": "source_certificate", "source_program": "source_program", "typed": "typed_program", "witness": "short_witness"}[arm]]["artifact_id"]
    helpers = set() if arm == "witness" else set(metadata["exact_helper_artifacts"])
    try:
        donor, receiver = (AutonomousNode(trial, index) for index in range(2))
        shutil.copytree(seeds / arm, donor.directory, dirs_exist_ok=True)
        if temperature == "warm":
            seed(fixture, "warm_membership_dependencies", "NAOME_TYPED_PAIR_WARM", receiver.directory)
        for node in (donor, receiver):
            write_receipt(node.directory / "resource-profile.json", {
                "profile": "custom", "custom": {
                    "memory_bytes": 128 * 1024 * 1024, "concurrency": 1,
                    "cache_bytes": 1024 * 1024, "batch_steps": 512, "network_requests": 1,
                },
            })
            node.start()
            node.stop()
        assert set(donor.ids()) == helpers | {root}
        assert set(receiver.ids()) == (helpers if temperature == "warm" else set())
        assert donor.peer != receiver.peer
        meters = [Meter(donor.port, "receiver_to_donor"), Meter(receiver.port, "donor_to_receiver")]
        for node, remote, meter in [(receiver, donor, meters[0]), (donor, receiver, meters[1])]:
            node.config["peers"] = [{"id": remote.peer, "address": f"/ip4/127.0.0.1/tcp/{meter.port}"}]
            node.write_config()

        start = time.monotonic()
        donor.start()
        receiver.start()
        ready = time.monotonic()
        ready_cpu = {label: process_cpu_sample(node.process)["cpu_seconds"]
                     for label, node in [("donor", donor), ("receiver", receiver)]}
        received = trial.wait(lambda: next((event for event in receiver.launch_events()
            if event.get("event") == "accepted" and event.get("source") == "fetch"
            and event.get("id") == root), None), maximum=80)
        report["launch_to_accept_wall_seconds"] = time.monotonic() - start
        report["both_ready_to_accept_wall_seconds"] = time.monotonic() - ready
        report["acceptance"] = received
        report["node_cpu_at_accept"] = {
            "donor": process_cpu_sample(donor.process)["cpu_seconds"],
            "receiver": process_cpu_sample(receiver.process)["cpu_seconds"],
        }
        report["node_cpu_both_ready_to_accept"] = {
            label: round(value - ready_cpu[label], 6)
            for label, value in report["node_cpu_at_accept"].items()
        }
        report["encrypted_tcp_payload_bytes"] = dict(sum((meter.snapshot() for meter in meters), Counter()))
        assert len(report["encrypted_tcp_payload_bytes"]) == 2
        assert all(not meter.errors for meter in meters), [meter.errors for meter in meters]
        assert set(receiver.ids()) == helpers | {root}
        events = receiver.launch_events()
        responses = [event for event in events if event.get("event") == "exchange_response"]
        report["response_kinds"] = dict(Counter(event["kind"] for event in responses))
        assert any(event.get("object_id") == root for event in responses)
        fetched_helpers = {event.get("object_id") for event in responses} & helpers
        assert fetched_helpers == (helpers if temperature == "cold" else set()), fetched_helpers
        report["fetched_helper_artifacts"] = sorted(fetched_helpers)
        accepted_before_target = {event.get("id") for event in events[:events.index(received)]
                                  if event.get("event") == "accepted"}
        if temperature == "cold":
            assert helpers <= accepted_before_target

        donor.stop()
        receiver.stop()
        assert stored_objects(receiver) == stored_objects(donor)
        receiver.config["peers"] = []
        receiver.write_config()
        start = time.monotonic()
        reopened = receiver.start()
        report["offline_reopen_wall_seconds"] = time.monotonic() - start
        assert reopened["artifact_verification"] == "checked" and reopened["accepted_artifacts"] == len(helpers) + 1
        assert set(receiver.ids()) == helpers | {root}
        receiver.stop()
        report["result"] = "pass"
    finally:
        for meter in meters:
            meter.close()
        trial.close()
        report["cleanup"] = trial.summary["cleanup"]
        write_receipt(output / "result.json", report)
    assert report["cleanup"]["all_owned_groups_empty"] and not report["cleanup"]["errors"]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True)
    seeds = output / "seeds"
    seed(args.fixture.resolve(), "membership_certificate_and_typed_actions_replay_the_same_derivation",
         "NAOME_TYPED_PAIR_OUTPUT", seeds)
    metadata = json.loads((seeds / "seed.json").read_text())
    pairs = []
    for arm, temperature in [
        ("source", "warm"), ("source_program", "warm"), ("typed", "warm"),
        ("typed", "cold"), ("source_program", "cold"), ("source", "cold"), ("witness", "cold"),
    ]:
        pairs.append(run(args.binary.resolve(), args.fixture.resolve(), seeds, metadata,
                         output / f"{arm}-{temperature}", arm, temperature))
    baseline_path = Path(__file__).resolve().parent.parent / "fixtures/typed-membership/comparison.json"
    baseline = json.loads(baseline_path.read_text())
    assert baseline["seed"]["statement_id"] == metadata["statement_id"]
    assert baseline["seed"]["exact_helper_artifacts"] == metadata["exact_helper_artifacts"]
    before, after = baseline["seed"]["typed_program"], metadata["typed_program"]
    assert before["record_bytes"] + before["manifest_bytes"] == 24105
    assert (after["record_bytes"] + after["manifest_bytes"]) * 4 < 24105
    write_receipt(output / "comparison.json", {
        "environment": {"os": platform.system(), "architecture": platform.machine(), "cargo_profile": "test",
                        "node_sha256": digest(args.binary), "fixture_sha256": digest(args.fixture)},
        "measurement": "One observation per arm and checked-context condition. Observed network bytes are forwarded encrypted TCP payload through acceptance. Codec package bytes are the data frames, excluding inventory and requests.",
        "previous_head": {"sha": "1c00341b4a63875132f1ba6c9cd91a87150a87d6", "typed_program": before,
                          "pairs": [pair for pair in baseline["pairs"] if pair["arm"] == "typed"]},
        "seed": metadata, "pairs": pairs,
    })


if __name__ == "__main__":
    main()
