#!/usr/bin/env python3
"""Bounded public DHT/relay acceptance, with no injected participant addresses."""
import argparse
import json
from pathlib import Path
import time
import traceback

from proof_network import Driver, Node, source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", default="test")
    parser.add_argument("--timeout", type=float, default=240)
    parser.add_argument("--participant", type=int, choices=[0, 1])
    parser.add_argument("--hold", type=float, default=0)
    args = parser.parse_args()
    driver = Driver(args.binary, args.output, args.timeout, args.profile)
    driver.summary.update({"fixture": "public_internet_discovery", "participant_roster_injected": False,
        "physical_host_count": 1, "public_network": "IPFS Amino DHT client and discovered circuit relay v2",
        "participant": args.participant, "physical_multi_host_qualified": False})
    participants = [0, 1] if args.participant is None else [args.participant]
    try:
        for participant in participants:
            directory = driver.output / f"node-{participant}"
            node = Node(driver, participant, directory, driver.init_identity(directory), 0)
            driver.nodes.append(node)
            node.start(network_config={"listen": "/ip4/0.0.0.0/tcp/0", "peers": [],
                "discovery": {"mdns": False, "dht": True, "internet": True}})
        expected = [driver.nodes[0].command("test_compile", source=source(700 + index))["object"]["proof_id"]
                    for index in range(2)]
        for participant, node in zip(participants, driver.nodes):
            result = node.command("produce", source=source(700 + participant))
            assert result["object"]["proof_id"] == expected[participant]
        driver.convergence("public_discovery_and_checked_exchange", range(len(driver.nodes)), expected,
                           time.monotonic(), timeout=args.timeout - 20, interval=1)
        for node in driver.nodes:
            assert any(event.get("event") == "accepted" and event.get("source") == "fetch" for event in node.events)
            assert any(event.get("event") == "identified" and event.get("proof_peer") is True for event in node.events)
        driver.summary["node_count"] = len(driver.nodes)
        driver.summary["peer_ids"] = [node.identity for node in driver.nodes]
        driver.summary["expected_ids"] = expected
        driver.summary["own_proof_id"] = expected[args.participant] if args.participant is not None else None
        driver.summary["public_connections"] = [[event for event in node.events
            if event.get("event") in ["connected", "identified", "external_confirmed", "exchange_response"]]
            for node in driver.nodes]
        until = min(driver.deadline - 5, time.monotonic() + args.hold)
        while time.monotonic() < until:
            for node in driver.nodes:
                assert node.process.poll() is None
            time.sleep(min(1, until - time.monotonic()))
        driver.summary["result"] = "pass"
    except Exception as error:
        driver.summary.update({"result": "fail", "error": str(error), "traceback": traceback.format_exc()})
    finally:
        driver.finish()
    print(json.dumps({"result": driver.summary["result"], "output": str(driver.output),
                      "error": driver.summary.get("error")}))
    return 0 if driver.summary["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
