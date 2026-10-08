#!/usr/bin/env python3
"""Bounded real-process control for autonomous operation after stdin EOF."""

import argparse
import json
import os
from pathlib import Path
import socket
import sys

from proof_network import Driver, Node, content_root, digest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path, help="developer-tools naome-knowledge-dev executable")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    driver = Driver(args.binary, args.output, args.timeout, args.profile)
    driver.summary["node_count"] = 1
    driver.summary["fixture"] = "closed_stdin_service"
    driver.summary["service_driver_sha256"] = digest(__file__)
    node = None
    errors = []
    try:
        directory = driver.output / "node-0"
        identity = driver.init_identity(directory)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        node = Node(driver, 0, directory, identity, port)
        driver.nodes = [node]
        # Preserve this service fixture's original proof address independently
        # of the distinct question family used by the inventory scenarios.
        producer_source = 'foundation = "naome:zfc" statement = forall(x, equal(x,x)) proof: p0 = equality_reflexivity(x) p1 = generalization(p0,x) return p1'
        producer_source += "#" + "\u0001" * (65536 - len(producer_source.encode()) - 2) + "\n"
        node.start([producer_source], command_input=False, test_controls=False)
        node.wait_event(lambda event: event.get("event") == "command_input_closed")
        event = node.wait_event(lambda event: event.get("event") == "producer_result")
        assert event["result"]["status"] == "accepted"
        id = event["result"]["id"]
        assert id == "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73", "original service proof address"
        assert node.process.poll() is None
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass
        assert node.process.poll() is None
        objects = list((directory / "objects").glob("*.json"))
        assert len(objects) == 1
        stored = json.loads(objects[0].read_text())
        assert stored["proof_id"] == id
        driver.summary["accepted_ids"] = [id]
        driver.summary["content_root"] = content_root(driver.summary["contract"]["compatibility"], [id])
        driver.summary["scenarios"]["autonomous_production_and_listener_after_input_eof"] = {
            "result": "pass", "proof_id": id, "stored_objects": 1,
            "producer_source_bytes": len(producer_source.encode()),
            "listener_tcp_connect": True,
            "listener_evidence": "TCP accepts a connection after checked production with closed stdin; this is not a separate libp2p exchange trial",
        }
        driver.summary["result"] = "pass"
    except Exception as error:
        driver.summary["result"] = "fail"
        driver.summary["error"] = str(error)
    finally:
        if node is not None:
            try:
                node.stop()
            except Exception as error:
                errors.append(str(error))
        driver.summary["cleanup"] = {
            "all_processes_exited": node is None or node.process is None or node.process.poll() is not None,
            "errors": errors,
            "method": "SIGTERM" if os.name == "posix" else "TerminateProcess",
            "graceful_shutdown_observed": os.name == "posix" and node is not None and node.process is not None and node.process.returncode == 0,
            "exit_code": node.process.returncode if node is not None and node.process is not None else None,
        }
        if errors:
            driver.summary["result"] = "fail"
        driver.summary["artifacts"] = {
            str(path): digest(path) for path in sorted(driver.output.iterdir())
            if path.is_file() and path.name != "summary.json"
        }
        (driver.output / "summary.json").write_text(json.dumps(driver.summary, indent=2) + "\n")
    print(json.dumps({"result": driver.summary["result"], "output": str(driver.output)}))
    return 0 if driver.summary["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
