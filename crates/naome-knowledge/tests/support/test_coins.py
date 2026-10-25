#!/usr/bin/env python3
"""Existing-wallet payments, two node grants, restart, conflicts, and revocation."""
import argparse
import json
from pathlib import Path
import traceback

from autonomous_lifecycle import Node, Trial, retain_evidence
from wallet import call


def run(trial):
    nodes = [Node(trial, index) for index in range(3)]
    for node in nodes:
        node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
        node.write_config()
        node.start()
    owner, first, second = nodes
    addresses = [call(trial, node.directory, "address")["address"] for node in nodes]
    owner_address, first_address, second_address = addresses
    keys = [(node.directory / "wallet.key").read_bytes() for node in nodes]
    ledger = trial.output / "shared-test-coins"
    created = call(trial, owner.directory, "test-coins", "init", ledger, 1000)
    assert created["units"] == 1000 and created["scope"] == "local_test_coins"
    call(trial, owner.directory, "test-coins", "init", ledger, 1000, success=False)
    call(trial, first.directory, "connect", ledger, owner_address, success=False)
    for node, address in zip(nodes[1:], addresses[1:]):
        call(trial, owner.directory, "test-coins", "authorize", ledger, address)
        connected = call(trial, node.directory, "connect", ledger, owner_address)
        assert connected["can_spend"] and connected["connection"]["wallet"] == owner_address
        assert connected["connection"]["signer"] == address
    balance = call(trial, owner.directory, "test-coins", "balance", ledger)
    assert balance["units"] == 1000 and set(balance["authorized_nodes"]) == {first_address, second_address}
    call(trial, first.directory, "test-coins", "authorize", ledger, owner_address, success=False)

    payment = call(trial, first.directory, "test-coins", "prepare", ledger, first_address, 300)
    conflict = call(trial, second.directory, "test-coins", "prepare", ledger, first_address, 200)
    payment_file = trial.output / "payment.json"
    conflict_file = trial.output / "conflict.json"
    payment_file.write_text(json.dumps(payment))
    conflict_file.write_text(json.dumps(conflict))
    tampered = json.loads(json.dumps(payment))
    tampered["operation"]["outputs"][0]["amount"] = 301
    tampered_file = trial.output / "tampered-payment.json"
    tampered_file.write_text(json.dumps(tampered))
    call(trial, first.directory, "test-coins", "submit", ledger, tampered_file, success=False)
    assert call(trial, owner.directory, "test-coins", "balance", ledger)["units"] == 1000
    call(trial, first.directory, "test-coins", "submit", ledger, payment_file)
    call(trial, second.directory, "test-coins", "submit", ledger, conflict_file, success=False)
    call(trial, first.directory, "test-coins", "submit", ledger, payment_file, success=False)
    assert call(trial, first.directory, "test-coins", "balance", ledger)["units"] == 700
    assert call(trial, first.directory, "test-coins", "balance", ledger, first_address)["units"] == 300
    call(trial, second.directory, "test-coins", "send", ledger, first_address, 200)
    assert call(trial, owner.directory, "test-coins", "balance", ledger)["units"] == 500

    for node in nodes:
        node.stop()
        node.start()
    for node, key in zip(nodes, keys):
        assert (node.directory / "wallet.key").read_bytes() == key
    assert call(trial, first.directory, "connection")["can_spend"]
    assert call(trial, second.directory, "connection")["can_spend"]
    assert call(trial, owner.directory, "test-coins", "balance", ledger)["units"] == 500
    assert call(trial, owner.directory, "test-coins", "balance", ledger, first_address)["units"] == 500
    call(trial, first.directory, "disconnect")
    assert not call(trial, first.directory, "connection")["connected"]
    call(trial, first.directory, "connect", ledger, owner_address, success=False)
    assert call(trial, second.directory, "connection")["can_spend"]
    call(trial, second.directory, "test-coins", "send", ledger, first_address, 100)
    call(trial, owner.directory, "test-coins", "revoke", ledger, second_address)
    assert not call(trial, second.directory, "connection")["can_spend"]
    call(trial, second.directory, "test-coins", "send", ledger, first_address, 1, success=False)
    call(trial, second.directory, "disconnect")
    assert call(trial, owner.directory, "test-coins", "balance", ledger)["units"] == 400
    assert call(trial, owner.directory, "test-coins", "balance", ledger, first_address)["units"] == 600
    for node in nodes:
        node.stop()
    trial.summary["node_count"] = 3
    trial.summary["claim"] = "existing wallet custody; local test-coin payments; two node spending grants; restart, conflicting spends, and individual revocation; no distributed consensus or work-reward claim"
    trial.summary["scenarios"]["test_coins_shared_wallet_nodes_restart_and_revocation"] = {"result": "pass"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--mode", choices=["test-coins"], default="test-coins")
    parser.add_argument("--timeout", type=float, default=90)
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "test-coins")
    try:
        run(trial)
        trial.summary["result"] = "pass"
    except Exception as error:
        trial.summary.update(result="fail", error=str(error))
        traceback.print_exc()
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "test-coins", args.profile)
    print(json.dumps({"result": trial.summary["result"], "output": str(trial.output)}))
    return 0 if trial.summary["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
