#!/usr/bin/env python3
"""Live-node status and restart around direct, internal Rust wallet service calls."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import traceback
from autonomous_lifecycle import Node, Trial, retain_evidence


def run(trial, service_binary):
    nodes = [Node(trial, index) for index in range(3)]
    for node in nodes:
        node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
        node.write_config()
        node.start()
    keys = [(node.directory / "wallet.key").read_bytes() for node in nodes]
    for phase in ["initial", "restarted"]:
        input_path = trial.output / "wallet-service-input.json"
        input_path.write_text(json.dumps({"phase": phase,
            "directories": [str(node.directory) for node in nodes],
            "ledger": str(trial.output / "test-ledger"), "binary": str(trial.binary)}))
        result = subprocess.run([str(service_binary), "--exact",
            "internal_wallet_service_connects_nodes_and_preserves_payments_across_restart", "--nocapture"],
            env={**os.environ, "NAOME_WALLET_SERVICE_TEST_INPUT": str(input_path)},
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=trial.remaining(20))
        assert result.returncode == 0, (result.stdout, result.stderr)
        if phase == "initial":
            for node in nodes:
                node.stop()
                node.start()
    for node, key in zip(nodes, keys):
        assert (node.directory / "wallet.key").read_bytes() == key
        node.stop()
    trial.summary["node_count"] = 3
    trial.summary["claim"] = "direct internal wallet service; two node grants, local test-coin payments, restart, full spending authority, individual revocation, and live passive status; no wallet CLI or network settlement"
    trial.summary["scenarios"]["internal_wallet_service_nodes_restart_and_revocation"] = {"result": "pass"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--service-binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--mode", choices=["wallet-service"], default="wallet-service")
    parser.add_argument("--timeout", type=float, default=90)
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "wallet-service")
    try:
        run(trial, args.service_binary)
        trial.summary["result"] = "pass"
    except Exception as error:
        trial.summary.update(result="fail", error=str(error))
        traceback.print_exc()
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "wallet-service", args.profile)
    print(json.dumps({"result": trial.summary["result"], "output": str(trial.output)}))
    return 0 if trial.summary["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
