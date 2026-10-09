#!/usr/bin/env python3
"""Finite four-process proof-network acceptance driver; no inference provider."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import socket
import subprocess
import threading
import time
import traceback


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def proof_id(statement, proof):
    foundation = b"naome:zfc"
    data = bytes.fromhex(proof)
    return hashlib.sha256(
        b"naome:proof\0" + len(foundation).to_bytes(4, "big") + foundation
        + bytes.fromhex(statement) + len(data).to_bytes(4, "big") + data
    ).hexdigest()


def content_root(compatibility, ids):
    return hashlib.sha256(
        b"naome:knowledge:set:v1\0" + bytes.fromhex(compatibility)
        + len(ids).to_bytes(4, "big") + b"".join(bytes.fromhex(i) for i in sorted(ids))
    ).hexdigest()


def source(index):
    # Distinct closed schema instances do not settle one another through the
    # receiver's supported MP or one/two universal-instantiation rules.
    a = "all(x, eq(x,x))"
    b = "all(y, mem(y,y))"
    for bit in format(index, "b"):
        b = f"not({b})" if bit == "1" else f"all(z,{b})"
    statement = f"imp({a},imp({b},{a}))"
    return f'goal = {statement}\nproof:\n    p0 = simp({a},{b})\n    return p0\n'


def inventory_source(depth, used):
    return source(100 + depth * (depth - 1) // 2 + used)


def question_source(proof_source):
    return 'goal = ' + proof_source.split("goal = ")[1].split("\n")[0]


def stored_objects(node):
    objects = []
    directory = node.directory / "objects"
    paths = list(directory.glob("*.json"))
    batches = directory / "batches"
    if batches.exists():
        for batch in sorted(batches.iterdir()):
            manifest_path = batch / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            assert batch.name == digest(manifest_path)
            assert manifest["version"] == 1 and manifest["root"] in manifest["members"]
            assert sorted(path.name for path in batch.iterdir()) == sorted(
                ["manifest.json"] + [f"{id}.json" for id in manifest["members"]])
            for id, checksum in manifest["members"].items():
                path = batch / f"{id}.json"
                assert digest(path) == checksum
                paths.append(path)
    for path in paths:
        object = json.loads(path.read_text())
        assert path.name == f'{object["proof_id"]}.json'
        objects.append(object)
    assert len({object["proof_id"] for object in objects}) == len(objects)
    return objects


class Node:
    def __init__(self, driver, index, directory, identity, port):
        self.driver, self.index, self.directory = driver, index, directory
        self.identity, self.port = identity, port
        self.process = None
        self.events, self.responses = [], {}
        self.condition = threading.Condition()
        self.serial, self.generation = 0, 0
        self.threads = []

    def start(self, producer_sources=(), command_input=True, test_controls=True, network_config=None, interest="all"):
        assert self.process is None or self.process.poll() is not None
        self.generation += 1
        event_offset = len(self.events)
        config = {
            "directory": str(self.directory),
            "listen": f"/ip4/127.0.0.1/tcp/{self.port}",
            "peers": [{"id": other.identity, "address": f"/ip4/127.0.0.1/tcp/{other.port}"}
                      for other in self.driver.nodes if other is not self],
            "producer_sources": list(producer_sources),
            "discovery": {"mdns": False, "dht": False},
        }
        if network_config is not None:
            config.update(network_config)
        path = self.driver.output / f"node-{self.index}-{self.generation}.config.json"
        path.write_text(json.dumps(config, indent=2) + "\n")
        command = [str(self.driver.binary), "run", str(path)]
        if test_controls:
            command.append("--test-controls")
        selector = {"kind": "absent"}
        if interest == "all":
            command.extend(["--question-interest", "all"])
            selector = {"kind": "all-supported"}
        elif interest is not None:
            interest_path = self.driver.output / f"node-{self.index}-{self.generation}.interest.json"
            interest_path.write_text(json.dumps({"questions": interest}, indent=2) + "\n")
            command.extend(["--question-interest-file", str(interest_path)])
            selector = {"kind": "exact-questions", "file_sha256": digest(interest_path), "count": len(interest)}
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE if command_input else subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
        self.driver.summary["commands"].append({"command": command, "pid": self.process.pid})
        self.driver.summary["processes"].append({"node": self.index, "generation": self.generation,
                                               "pid": self.process.pid, "peer_id": self.identity,
                                               "directory": str(self.directory), "endpoint": config["listen"],
                                               "network_config": {key: config[key] for key in ["listen", "peers", "discovery"]},
                                               "config_bytes": path.stat().st_size,
                                               "config_sha256": digest(path),
                                               "command_input": "pipe" if command_input else "closed",
                                               "question_interest": selector,
                                               "producer_source_count": len(config["producer_sources"]),
                                               "producer_source_bytes": sum(len(s.encode()) for s in config["producer_sources"])})
        for name, stream in [("stdout", self.process.stdout), ("stderr", self.process.stderr)]:
            log = self.driver.output / f"node-{self.index}-{self.generation}.{name}.jsonl"
            thread = threading.Thread(target=self.read, args=(name, stream, log), daemon=True)
            thread.start()
            self.threads.append(thread)
        self.wait_event(lambda event: event.get("event") == "ready", timeout=15, since=event_offset)

    def read(self, name, stream, log):
        with log.open("w") as output:
            for line in stream:
                output.write(line)
                output.flush()
                if name != "stdout":
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                event["observed_monotonic"] = time.monotonic()
                with self.condition:
                    self.events.append(event)
                    if event.get("event") == "response":
                        self.responses[event["request"]] = event
                    self.condition.notify_all()
        with self.condition:
            self.condition.notify_all()

    def command(self, command, timeout=10, **fields):
        self.driver.check_deadline()
        self.serial += 1
        request = f"{self.index}-{self.generation}-{self.serial}"
        value = {"command": command, "request": request, **fields}
        transcript = self.driver.output / "commands.jsonl"
        with transcript.open("a") as out:
            out.write(json.dumps({"node": self.index, "generation": self.generation,
                                  "sent_monotonic": time.monotonic(), "value": value}) + "\n")
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + timeout
        with self.condition:
            while request not in self.responses:
                if self.process.poll() is not None:
                    raise AssertionError(f"node {self.index} exited {self.process.returncode}")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f"node {self.index} command timeout: {command}")
                self.condition.wait(min(remaining, 0.5))
            response = self.responses.pop(request)
        if "error" in response:
            raise AssertionError(f"node {self.index} {command}: {response['error']}")
        return response["result"]

    def wait_event(self, predicate, timeout=10, since=0):
        deadline = min(self.driver.deadline, time.monotonic() + timeout)
        with self.condition:
            while True:
                matches = [event for event in self.events[since:] if predicate(event)]
                if matches:
                    return matches[-1]
                if self.process.poll() is not None:
                    raise AssertionError(f"node {self.index} exited before expected event")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.driver.check_deadline()
                    raise AssertionError(f"node {self.index} event timeout")
                self.condition.wait(min(remaining, 0.5))

    def stop(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                if self.process.stdin is None:
                    self.process.terminate()
                else:
                    self.command("stop", timeout=3)
                self.process.wait(timeout=5)
            except (AssertionError, BrokenPipeError, subprocess.TimeoutExpired):
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        for thread in self.threads:
            thread.join(timeout=2)
        self.threads = []
        assert self.process.returncode == 0, f"node {self.index} unexpected stop: {self.process.returncode}"
        for stream in [self.process.stdin, self.process.stdout, self.process.stderr]:
            if stream is not None:
                stream.close()


class Driver:
    """Real transport qualification through the explicitly enabled developer harness."""
    def __init__(self, binary, output, timeout, profile):
        self.binary, self.output = binary.resolve(), output.resolve()
        self.deadline = time.monotonic() + timeout
        self.nodes = []
        output.mkdir(parents=True, exist_ok=False)
        contract = json.loads(self.helper_output([str(self.binary), "contract"]))
        repo = Path(__file__).resolve().parents[4]
        self.summary = {
            "schema": 1, "result": "running", "node_count": 4, "physical_host_count": 1,
            "producer": "finite deterministic formal source queues and checked-context authoring; no LLM inference",
            "contract": contract, "scenarios": {}, "commands": [], "processes": [], "proofs": {},
            "revision": self.helper_output(["git", "rev-parse", "HEAD"], cwd=repo).strip(),
            "dirty": bool(self.helper_output(["git", "status", "--porcelain"], cwd=repo).strip()),
            "profile": profile, "binary": str(self.binary), "binary_sha256": digest(self.binary),
            "driver_sha256": digest(__file__), "environment": platform.uname()._asdict(),
            "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "timeout_seconds": timeout,
        }

    def check_deadline(self):
        if time.monotonic() >= self.deadline:
            raise AssertionError("whole demonstration deadline exceeded")

    def helper_output(self, command, **arguments):
        self.check_deadline()
        return subprocess.check_output(command, text=True,
                                       timeout=max(0.001, self.deadline - time.monotonic()),
                                       **arguments)

    def init_identity(self, directory):
        command = [str(self.binary), "init", str(directory)]
        self.summary["commands"].append({"command": command})
        return json.loads(self.helper_output(command))["peer_id"]

    def topology(self, groups):
        for group in groups:
            for index in group:
                self.nodes[index].command("links", peers=[self.nodes[other].identity for other in group if other != index])
        expected = {index: {self.nodes[other].identity for other in group if other != index}
                    for group in groups for index in group}
        deadline = min(self.deadline, time.monotonic() + 15)
        statuses = {}
        while time.monotonic() < deadline:
            statuses = {index: self.nodes[index].command("status") for index in expected}
            if all(set(statuses[index]["connected"]) == peers for index, peers in expected.items()):
                return
            time.sleep(0.1)
        self.check_deadline()
        diagnostics = {
            str(index): {"connected": statuses.get(index, {}).get("connected"),
                         "expected": sorted(peers),
                         "events": [event for event in self.nodes[index].events
                                    if event.get("event") in ["connected", "disconnected", "dial_failed", "request_failed", "inbound_failed"]][-10:]}
            for index, peers in expected.items()
        }
        raise AssertionError(f"topology did not match configured partition: {json.dumps(diagnostics)}")

    def convergence(self, name, indices, expected, started, timeout=25, interval=0.1):
        expected = set(expected)
        root = content_root(self.summary["contract"]["compatibility"], expected)
        deadline = min(self.deadline, started + timeout)
        times, final = {}, {}
        while time.monotonic() < deadline:
            for index in indices:
                status = self.nodes[index].command("status")
                if set(status["ids"]) == expected and status["root"] == root and not status["pending"]:
                    times.setdefault(str(index), time.monotonic() - started)
                    final[str(index)] = status
                else:
                    times.pop(str(index), None)
                    final.pop(str(index), None)
            if len(times) == len(indices):
                result = {"result": "pass", "ids": sorted(expected), "root": root,
                          "all_node_seconds": max(times.values()), "per_node_seconds": times,
                          "statuses": final}
                self.summary["scenarios"][name] = result
                print(f"{name}: all {len(indices)} nodes converged in {result['all_node_seconds']:.3f}s", flush=True)
                return
            time.sleep(interval)
        counts = {str(index): len(self.nodes[index].command("status")["ids"]) for index in indices}
        raise AssertionError(f"{name}: all-node convergence timeout; accepted_counts={counts}")

    def retain_proof(self, label, object):
        assert proof_id(object["statement_id"], object["proof"]) == object["proof_id"]
        assert object["compatibility"] == self.summary["contract"]["compatibility"]
        path = self.output / f"{label}.envelope.json"
        path.write_text(json.dumps(object, indent=2) + "\n")
        self.summary["proofs"][label] = {"proof_id": object["proof_id"], "statement_id": object["statement_id"],
                                           "path": str(path), "sha256": digest(path)}
        return object["proof_id"]

    def produce(self, node, depth, label):
        result = self.nodes[node].command("produce", source=source(depth))
        assert result["result"]["status"] == "accepted"
        object = result["object"]
        self.retain_proof(label, object)
        return object

    def large_inventory(self):
        """Fetch ten real inventory pages from an initially disconnected supplier."""
        reservations = []
        try:
            self.summary["node_count"] = 2
            for index in range(2):
                directory = self.output / f"node-{index}"
                identity = self.init_identity(directory)
                reservation = socket.socket()
                reservation.bind(("127.0.0.1", 0))
                reservations.append(reservation)
                self.nodes.append(Node(self, index, directory, identity, reservation.getsockname()[1]))
            reservations[0].close()
            self.nodes[0].start()
            self.nodes[0].command("links", peers=[])
            ids = []
            for depth in range(1, 35):
                for used in range(depth):
                    self.check_deadline()
                    result = self.nodes[0].command("produce", source=inventory_source(depth, used))
                    assert result["result"]["status"] == "accepted"
                    ids.append(result["object"]["proof_id"])
            assert len(ids) == len(set(ids)) == 595
            reservations[1].close()
            self.nodes[1].start()
            self.nodes[1].command("links", peers=[])
            assert self.nodes[1].command("status")["ids"] == []
            started = time.monotonic()
            self.topology([[0, 1]])
            self.convergence("ten_page_inventory_complete_content_catchup", range(2), ids,
                             started, timeout=210, interval=0.5)
            pages = [event for event in self.nodes[1].events if event.get("event") == "inventory_page"]
            assert any(event["page"] >= 9 for event in pages)
            assert all(len(stored_objects(node)) == 595 for node in self.nodes)
            self.nodes[1].stop()
            self.nodes[1].start()
            self.convergence("ten_page_complete_batch_restart", range(2), ids, time.monotonic(), timeout=15)
            self.summary["scenarios"]["inventory_tail_discovery"] = {
                "result": "pass", "object_count": 595, "page_size": 64,
                "pages": pages, "tail_proof_id": max(ids),
                "receiver_tail_present": max(ids) in self.nodes[1].command("status")["ids"],
            }
            self.summary["accepted_ids"] = sorted(ids)
            self.summary["content_root"] = content_root(self.summary["contract"]["compatibility"], ids)
            self.summary["result"] = "pass"
        finally:
            for reservation in reservations:
                reservation.close()

    def run(self):
        reservations = []
        try:
            for index in range(4):
                directory = self.output / f"node-{index}"
                identity = self.init_identity(directory)
                reservation = socket.socket()
                reservation.bind(("127.0.0.1", 0))
                reservations.append(reservation)
                self.nodes.append(Node(self, index, directory, identity, reservation.getsockname()[1]))
            initial = []
            for index, node in enumerate(self.nodes):
                reservations[index].close()
                producer_source = source(index + 1)
                producer_source += "\n" * (65536 - len(producer_source.encode()))
                node.start([producer_source])
                node.command("links", peers=[])
            assert len({node.identity for node in self.nodes}) == 4
            assert len({node.process.pid for node in self.nodes}) == 4
            for index, node in enumerate(self.nodes):
                event = node.wait_event(lambda event: event.get("event") == "producer_result")
                id = event["result"]["id"]
                status = node.command("status")
                assert status["ids"] == [id]
                object = node.command("object", id=id)["object"]
                initial.append(self.retain_proof(f"independent-{index}", object))
            assert len(set(initial)) == 4
            escaped_source = source(1)
            escaped_source += "#" + "\u0001" * (65536 - len(escaped_source.encode()) - 2) + "\n"
            escaped_result = self.nodes[0].command("produce", source=escaped_source)
            assert escaped_result["result"]["status"] == "duplicate"
            assert escaped_result["object"]["proof_id"] == initial[0]
            self.summary["scenarios"]["full_source_with_worst_case_command_escaping"] = {
                "result": "pass", "source_bytes": len(escaped_source.encode()),
                "json_source_bytes": len(json.dumps(escaped_source).encode()),
                "proof_id": initial[0], "status": "duplicate",
            }
            started = time.monotonic()
            self.topology([[0, 1, 2, 3]])
            self.convergence("independent_producers", range(4), initial, started)

            # The parent bytes are fetched first, then its actual cited helper.
            # A missing helper leaves no checked/pending/durable orphan.
            self.topology([[0], [1, 3], [2]])
            parent = self.produce(0, 7, "delayed-parent")
            premise = question_source(source(7)).split("goal = ")[1]
            b = "all(z,mem(z,z))"
            child_source = f'goal = imp({b},{premise})\nproof: p0 = cite("{parent["proof_id"]}") p1 = simp({premise},{b}) p2 = mp(p0,p1) return p2'
            compiled_child = self.nodes[0].command("produce", source=child_source)
            child = compiled_child["object"]
            metadata = compiled_child["metadata"]
            self.retain_proof("dependent", child)
            before = len(self.nodes[3].events)
            self.nodes[1].command("test_offer", peer=self.nodes[3].identity, metadata=metadata, object=child)
            self.nodes[3].wait_event(lambda event: event.get("event") == "proof_skipped" and "required dependency missing" in event.get("error", ""), since=before)
            status = self.nodes[3].command("status")
            assert not status["pending"] and set(status["ids"]) == set(initial)
            assert len(stored_objects(self.nodes[3])) == len(initial)
            self.summary["scenarios"]["dependent_before_parent"] = {"result": "pass", "isolated_failed_closure": status, "no_orphan": True}
            started = time.monotonic()
            parent_metadata = self.nodes[0].command("describe", id=parent["proof_id"])["metadata"]
            self.nodes[1].command("test_offer", peer=self.nodes[3].identity, metadata=parent_metadata, object=parent)
            self.nodes[1].command("test_offer", peer=self.nodes[3].identity, metadata=metadata, object=child)
            union = initial + [parent["proof_id"], child["proof_id"]]
            self.convergence("dependency_resolution", [1, 3], union, started)
            self.topology([[0, 1, 2, 3]])
            self.convergence("dependency_all_node_union", range(4), union, time.monotonic())

            self.topology([[0, 1], [2, 3]])
            left = self.produce(0, 8, "partition-left")
            right = self.produce(2, 9, "partition-right")
            self.convergence("partition_left", [0, 1], union + [left["proof_id"]], time.monotonic())
            self.convergence("partition_right", [2, 3], union + [right["proof_id"]], time.monotonic())
            assert right["proof_id"] not in self.nodes[0].command("status")["ids"]
            assert left["proof_id"] not in self.nodes[2].command("status")["ids"]

            # Each malformed payload uses a distinct unresolved question and
            # real metadata approval/Get, never a full-payload Offer.
            baseline = self.nodes[1].command("status")
            controls = []
            for index, label in enumerate(["malformed", "claimed_id", "compatibility", "mathematical", "statement"]):
                proof_source = source(50 + index)
                object = self.nodes[0].command("test_compile", source=proof_source)["object"]
                q = question_source(proof_source)
                if label == "malformed":
                    object["proof"] = "00000001ff"
                    expected_error = "malformed certificate"
                elif label == "claimed_id":
                    object["proof_id"] = "00" * 32
                    expected_error = "claimed proof ID mismatch"
                elif label == "compatibility":
                    object["compatibility"] = "00" * 32
                    expected_error = "compatibility mismatch"
                elif label == "mathematical":
                    object["proof"] = "00000004" + "0600000000" + "210000000000000000" + "210000000100000001" + "200000000100000002"
                    expected_error = "mathematically invalid"
                else:
                    unrelated_source = source(60)
                    unrelated = self.nodes[0].command("test_compile", source=unrelated_source)["object"]
                    object["statement_id"] = unrelated["statement_id"]
                    q = question_source(unrelated_source)
                    expected_error = "checked identity mismatch"
                if label != "claimed_id":
                    object["proof_id"] = proof_id(object["statement_id"], object["proof"])
                metadata = {"proof_id": object["proof_id"], "statement_id": object["statement_id"], "question": q}
                offset = len(self.nodes[1].events)
                self.nodes[0].command("test_offer", peer=self.nodes[1].identity, metadata=metadata, object=object)
                event = self.nodes[1].wait_event(lambda event: event.get("event") == "proof_skipped" and expected_error in event.get("error", ""), since=offset)
                status = self.nodes[1].command("status")
                assert status["ids"] == baseline["ids"] and status["root"] == baseline["root"] and not status["pending"]
                assert len(stored_objects(self.nodes[1])) == len(baseline["ids"])
                self.summary["scenarios"][f"reject_{label}"] = {"result": "pass", "error": event["error"], "unchanged_root": status["root"], "metadata_first": True}
                time.sleep(0.2)
            offset = len(self.nodes[0].events)
            self.nodes[0].command("test_offer", peer=self.nodes[1].identity,
                                 metadata=self.nodes[0].command("describe", id=left["proof_id"])["metadata"],
                                 test_compatibility="00" * 32)
            self.nodes[0].wait_event(lambda event: event.get("event") == "peer_error" and event.get("error") == "compatibility mismatch", since=offset)
            self.summary["scenarios"]["reject_transport_compatibility"] = {"result": "pass"}
            for _ in range(3):
                offset = len(self.nodes[0].events)
                self.nodes[0].command("offer", peer=self.nodes[1].identity, id=left["proof_id"])
                self.nodes[0].wait_event(lambda event: event.get("event") == "offer_result" and event.get("status") == "duplicate", since=offset)
                self.nodes[0].command("announce", id=left["proof_id"])
                time.sleep(0.2)
            status = self.nodes[1].command("status")
            assert status["root"] == baseline["root"] and status["ids"] == baseline["ids"]
            self.summary["scenarios"]["duplicate_delivery_and_announcements"] = {"result": "pass", "deliveries": 3, "announcements": 3, "unchanged_root": status["root"]}
            started = time.monotonic()
            self.topology([[0, 1, 2, 3]])
            union += [left["proof_id"], right["proof_id"]]
            self.convergence("partition_reconnection_union", range(4), union, started)

            self.nodes[2].stop()
            new = self.produce(0, 10, "while-offline")
            union.append(new["proof_id"])
            self.convergence("offline_remaining_nodes", [0, 1, 3], union, time.monotonic())
            started = time.monotonic()
            self.nodes[2].start()
            self.convergence("restart_catchup", range(4), union, started)

            for node in self.nodes:
                node.stop()
            old_identity = self.nodes[3].identity
            self.nodes[3].directory = self.output / "new-node-3"
            self.nodes[3].identity = self.init_identity(self.nodes[3].directory)
            assert old_identity != self.nodes[3].identity
            started = time.monotonic()
            for node in self.nodes:
                node.start()
            self.convergence("new_identity_empty_store_catchup", range(4), union, started)
            for node in self.nodes:
                assert sorted(path.name for path in node.directory.iterdir()) == ["identity.key", "knowledge.lock", "objects"]
                assert len(stored_objects(node)) == len(union)
            self.summary["scenarios"]["economy_independence"] = {"result": "pass", "storage": "identity, exclusive lock and checked proof objects only; no ledger, reward, balance or selection state"}
            self.summary["accepted_ids"] = sorted(union)
            self.summary["content_root"] = content_root(self.summary["contract"]["compatibility"], union)
            self.summary["result"] = "pass"
        finally:
            for reservation in reservations:
                reservation.close()

    def finish(self):
        cleanup_errors = []
        for node in self.nodes:
            try:
                node.stop()
            except Exception as error:
                cleanup_errors.append(str(error))
        self.summary["cleanup"] = {"all_processes_exited": all(node.process is None or node.process.poll() is not None for node in self.nodes), "errors": cleanup_errors}
        if cleanup_errors:
            self.summary["result"] = "fail"
        # Keep transport identities private; digest only public reproduction inputs/evidence.
        files = [path for path in self.output.iterdir() if path.is_file() and path.name != "summary.json"]
        self.summary["artifacts"] = {str(path): digest(path) for path in sorted(files)}
        (self.output / "summary.json").write_text(json.dumps(self.summary, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True, help="developer-tools naome-knowledge-dev executable")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--profile", default="test")
    parser.add_argument("--large-inventory", action="store_true")
    args = parser.parse_args()
    driver = Driver(args.binary, args.output, args.timeout, args.profile)
    try:
        if args.large_inventory:
            driver.large_inventory()
        else:
            driver.run()
    except Exception as error:
        driver.summary["result"] = "fail"
        driver.summary["error"] = str(error)
        traceback.print_exc()
    finally:
        driver.finish()
    print(json.dumps({"result": driver.summary["result"], "summary": str(driver.output / "summary.json")}))
    return 0 if driver.summary["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
