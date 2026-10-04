#!/usr/bin/env python3
"""Finite real mDNS, bootstrap DHT, relay circuit and DCUtR process evidence."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import traceback

from proof_network import Driver, Node, digest, source


USED_PORTS = set()

def port():
    for _ in range(32):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            candidate = reservation.getsockname()[1]
            if candidate not in USED_PORTS:
                USED_PORTS.add(candidate)
                return candidate
    raise AssertionError("could not allocate distinct listener ports")


class Relay(Node):
    def start(self):
        self.generation += 1
        path = self.driver.output / "relay.config.json"
        config = {"directory": str(self.directory), "listen": f"/ip4/127.0.0.1/tcp/{self.port}"}
        path.write_text(json.dumps(config, indent=2) + "\n")
        command = [str(self.driver.binary), "relay", str(path)]
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
        self.driver.summary["commands"].append({"command": command, "pid": self.process.pid})
        self.driver.summary["processes"].append({"role": "relay", "pid": self.process.pid,
            "peer_id": self.identity, "directory": str(self.directory), "endpoint": config["listen"],
            "config_sha256": digest(path), "config_bytes": path.stat().st_size})
        for name, stream in [("stdout", self.process.stdout), ("stderr", self.process.stderr)]:
            log = self.driver.output / f"relay.{name}.jsonl"
            thread = threading.Thread(target=self.read, args=(name, stream, log), daemon=True)
            thread.start()
            self.threads.append(thread)
        self.wait_event(lambda event: event.get("event") == "ready", timeout=15)


class DiscoveryDriver(Driver):
    def __init__(self, binary, output, timeout, profile, mode):
        super().__init__(binary, output, timeout, profile)
        self.mode = mode
        self.relay = None
        self.summary.update({"fixture": mode, "discovery_driver_sha256": digest(__file__),
            "participant_roster_injected": False, "physical_nat_routers": 0,
            "physical_nat_traversal_qualified": False})

    def init_node(self, index):
        directory = self.output / f"node-{index}"
        identity = self.init_identity(directory)
        node = Node(self, index, directory, identity, port())
        self.nodes.append(node)
        return node

    def settings(self, node):
        relay_mode = self.mode in ["relay", "upgrade"]
        config = {"mdns": self.mode == "mdns", "dht": self.mode != "mdns",
                  "bootstrap": [], "relays": [], "hole_punch": self.mode == "upgrade",
                  "relay_only": relay_mode, "external_addresses": []}
        if relay_mode:
            endpoint = {"id": self.relay.identity, "address": f"/ip4/127.0.0.1/tcp/{self.relay.port}"}
            config["bootstrap"] = [endpoint]
            config["relays"] = [endpoint]
        elif self.mode == "dht":
            config["external_addresses"] = [f"/ip4/127.0.0.1/tcp/{node.port}"]
            if node.index != 0:
                config["bootstrap"] = [{"id": self.nodes[0].identity,
                                         "address": f"/ip4/127.0.0.1/tcp/{self.nodes[0].port}"}]
        return {"listen": f"/ip4/{'0.0.0.0' if self.mode != 'dht' else '127.0.0.1'}/tcp/{node.port}",
                "peers": [], "discovery": config}

    def start_node(self, node, produce=True):
        node.start([source(node.index + 1)] if produce else [], test_controls=False,
                   network_config=self.settings(node))

    def own_proof(self, node):
        event = node.wait_event(lambda event: event.get("event") == "producer_result", timeout=15)
        assert event["result"]["status"] in ["accepted", "duplicate"]
        object = node.command("object", id=event["result"]["id"])["object"]
        return self.retain_proof(f"independent-{node.index}", object)

    def assert_caps(self):
        for node in self.nodes:
            if node.process is None or node.process.poll() is not None:
                continue
            status = node.command("status")
            assert len(status["contacts"]) <= 16
            assert status["provider_records"] <= 16
            assert all(len(contact["addresses"]) <= 4 for contact in status["contacts"])
            assert len(status["connections"]) <= 32

    def discovery(self):
        for index in range(4):
            self.init_node(index)
        initial = []
        for node in self.nodes[:3]:
            self.start_node(node)
            initial.append(self.own_proof(node))
        started = time.monotonic()
        self.convergence("unlisted_initial_three", range(3), initial, started, timeout=40)
        expected_source = "mdns" if self.mode == "mdns" else "dht"
        if self.mode == "mdns":
            for node in self.nodes[1:3]:
                assert any(event.get("event") == "discovered" and event.get("source") == "mdns"
                           and event.get("peer") in {other.identity for other in self.nodes if other is not node}
                           for event in node.events)
        if self.mode == "dht":
            for node in self.nodes[1:3]:
                # Kademlia can dial its newly returned neighbors internally,
                # before the application receives a closest-peers result. Bind
                # discovery to actual participation records and the identified
                # non-seed peer, rather than a particular hint callback order.
                other = self.nodes[3 - node.index].identity
                node.wait_event(lambda event:event.get("event") == "dht_participant" and event.get("peer") == other, timeout=25)
                node.wait_event(lambda event:event.get("event") == "identified" and event.get("peer") == other, timeout=10)
        self.summary["scenarios"]["peer_discovery_without_roster"] = {"result": "pass", "mechanism": expected_source,
            "proof_ids": sorted(initial), "bootstrap_count_per_node": 0 if self.mode == "mdns" else 1,
            "configured_proof_peers": 0}

        started = time.monotonic()
        self.start_node(self.nodes[3])
        initial.append(self.own_proof(self.nodes[3]))
        self.convergence("unlisted_late_join_four", range(4), initial, started, timeout=40)
        assert len({node.process.pid for node in self.nodes}) == 4
        assert len({node.identity for node in self.nodes}) == 4
        self.assert_caps()

        # Stop/restart one real process, preserving its identity and checked
        # store. The remaining nodes add a proof while it cannot receive it.
        node = self.nodes[1]
        before = node.command("status")
        old_pid = node.process.pid
        node.stop()
        extra = self.produce(0, 6, "offline-new-proof")
        initial.append(extra["proof_id"])
        self.convergence("remaining_nodes_while_peer_offline", [0, 2, 3], initial, time.monotonic(), timeout=30)
        started = time.monotonic()
        self.start_node(node, produce=False)
        assert node.process.pid != old_pid
        assert extra["proof_id"] not in before["ids"]
        self.convergence("restart_rediscovery_and_catchup", range(4), initial, started, timeout=40)
        self.assert_caps()

        # A disappearing unpinned contact must be retired even while old DHT
        # or multicast hints are still in flight; repeated hints cannot renew it.
        stale = self.nodes[2]
        stale.stop()
        stale_peer = stale.identity
        deadline = min(self.deadline, time.monotonic() + 45)
        retired = set()
        while time.monotonic() < deadline:
            self.assert_caps()
            for active in [self.nodes[index] for index in [0, 1, 3]]:
                status = active.command("status")
                if stale_peer not in {contact["peer"] for contact in status["contacts"]}:
                    if any(event.get("event") == "contact_expired" and event.get("peer") == stale_peer for event in active.events):
                        retired.add(active.index)
            if retired == {0, 1, 3}:
                break
            time.sleep(0.5)
        assert retired == {0, 1, 3}, f"stale contact not retired on all active nodes: {sorted(retired)}"
        self.summary["scenarios"]["disappearing_contact_retirement"] = {"result":"pass", "peer":stale_peer,
            "active_nodes":sorted(retired), "deadline_seconds":45, "hint_ttl_seconds":30}
        self.convergence("retained_graph_after_contact_retirement", [0, 1, 3], initial, time.monotonic(), timeout=5)
        self.summary["accepted_ids"] = sorted(initial)
        self.summary["content_root"] = self.summary["scenarios"]["restart_rediscovery_and_catchup"]["root"]

    def circuit(self):
        directory = self.output / "relay"
        identity = self.init_identity(directory)
        self.relay = Relay(self, "relay", directory, identity, port())
        self.relay.start()
        self.summary["node_count"] = 2
        self.summary["relay_process_count"] = 1
        expected = []
        for index in range(2):
            node = self.init_node(index)
            self.start_node(node)
            expected.append(self.own_proof(node))
        started = time.monotonic()
        self.convergence("unlisted_circuit_participants", range(2), expected, started, timeout=45)
        self.assert_caps()
        if self.mode == "relay":
            transfers = []
            for node in self.nodes:
                connections = {event["connection_id"]:event for event in node.events
                    if event.get("event") == "connected" and event.get("peer") != self.relay.identity}
                assert connections and all(event["relayed"] is True for event in connections.values())
                objects = [event for event in node.events if event.get("event") == "exchange_response"
                    and event.get("kind") == "object" and event.get("relayed") is True
                    and event.get("object_id") in expected]
                assert objects, f"node {node.index} has no circuit object response"
                assert all(event["connection_id"] in connections for event in objects)
                assert any(event.get("event") == "accepted" and event.get("source") == "fetch" for event in node.events)
                transfers.append({"node":node.index, "connections":connections, "object_responses":objects})
            assert any("CircuitReqAccepted" in event.get("detail", "") for event in self.relay.events)
            self.summary["scenarios"]["proof_payload_requires_relay_circuit"] = {
                "result":"pass", "direct_proof_connections":0, "hole_punch_enabled":False, "transfers":transfers}
        else:
            deadline = min(self.deadline, time.monotonic() + 30)
            while time.monotonic() < deadline:
                native = [(node, event) for node in self.nodes for event in node.events
                          if event.get("event") == "hole_punch_result"]
                if native:
                    break
                time.sleep(0.05)
            assert native, "DCUtR has no native terminal outcome within 30 seconds"
            results = []
            for node in self.nodes:
                other = self.nodes[1 - node.index]
                attempts = [event for event in node.events if event.get("event") == "hole_punch_attempt"
                            and event.get("peer") == other.identity]
                assert attempts
                outcomes = [event for event in node.events if event.get("event") == "hole_punch_result"
                            and event.get("peer") == other.identity]
                results.append({"node":node.index, "peer_id":node.identity,
                                "attempts":attempts, "native_outcomes":outcomes})
            for node, event in native:
                assert event["peer"] == self.nodes[1 - node.index].identity
                if event["success"]:
                    # The pinned behaviour reports success only for its own
                    # outgoing upgrade. Bind the receiving endpoint as well;
                    # it need not emit another native DCUtR success event.
                    node.wait_event(lambda connection:connection.get("event") == "connected"
                                    and connection.get("connection_id") == event["connection_id"]
                                    and connection.get("relayed") is False, timeout=5)
                    other = self.nodes[1 - node.index]
                    other.wait_event(lambda connection:connection.get("event") == "connected"
                                     and connection.get("peer") == node.identity
                                     and connection.get("relayed") is False, timeout=5)
            self.summary["scenarios"]["bounded_dcutr_terminal_outcome"] = {
                "result":"pass", "outcomes":results, "physical_nat_traversal_qualified":False,
                "native_result_scope":"The pinned behaviour reports locally initiated outgoing upgrades; the counterpart is bound by its authenticated direct endpoint",
                "evidence":"Real local circuit followed by a DCUtR terminal result; one host, zero physical NAT routers"}
        self.summary["accepted_ids"] = sorted(expected)
        self.summary["content_root"] = self.summary["scenarios"]["unlisted_circuit_participants"]["root"]

    def finish(self):
        errors = []
        processes = self.nodes + ([self.relay] if self.relay is not None else [])
        for node in processes:
            try:
                node.stop()
            except Exception as error:
                errors.append(str(error))
        self.summary["cleanup"] = {"all_processes_exited":all(node.process is None or node.process.poll() is not None for node in processes),
            "errors":errors, "process_exit_codes":[node.process.returncode if node.process is not None else None for node in processes],
            "relay_shutdown":"SIGTERM" if os.name == "posix" else "TerminateProcess"}
        if errors:
            self.summary["result"] = "fail"
        self.summary["artifacts"] = {str(path):digest(path) for path in sorted(self.output.rglob("*"))
            if path.is_file() and path.name not in ["summary.json", "identity.key", "knowledge.lock"]}
        (self.output / "summary.json").write_text(json.dumps(self.summary, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--mode", required=True, choices=["mdns", "dht", "relay", "upgrade"])
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    driver = DiscoveryDriver(args.binary, args.output, args.timeout, args.profile, args.mode)
    try:
        if args.mode in ["mdns", "dht"]:
            driver.discovery()
        else:
            driver.circuit()
        driver.summary["result"] = "pass"
    except Exception as error:
        driver.summary["result"] = "fail"
        driver.summary["error"] = str(error)
        driver.summary["traceback"] = traceback.format_exc()
    finally:
        driver.finish()
    print(json.dumps({"result":driver.summary["result"], "output":str(driver.output), "error":driver.summary.get("error")}))
    return 0 if driver.summary["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
