#!/usr/bin/env python3
"""Ordinary startup retains independent wallet custody without a wallet CLI."""
import argparse
import json
from pathlib import Path
import traceback

from autonomous_lifecycle import Node, Trial, retain_evidence


def run(trial):
    node = Node(trial, 0)
    node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
    node.write_config()
    key_path = node.directory / "wallet.key"
    receipt = node.directory / "wallet.json"
    assert not key_path.exists() and not receipt.exists()
    node.start()
    identity = json.loads(receipt.read_text())
    address = identity["address"]
    assert set(identity) == {"version", "address"} and identity["version"] == 1
    assert address.startswith("nao1")
    key = key_path.read_bytes()
    assert key_path.stat().st_mode & 0o777 == 0o600
    assert key != (node.directory / "identity.key").read_bytes()
    assert not any(path.name.startswith(("resource-history", ".resource-history"))
                   for path in node.directory.iterdir()), "startup persisted removed resource history"
    node.stop()
    node.start()
    assert json.loads(receipt.read_text()) == identity
    assert key_path.read_bytes() == key
    node.stop()
    key_path.unlink()
    try:
        trial.call(node, "start", success=False)
        assert not key_path.exists(), "lost wallet key was silently regenerated"
        assert json.loads(receipt.read_text()) == identity
    finally:
        key_path.write_bytes(key)
        key_path.chmod(0o600)
    receipt.unlink()
    key_path.unlink()
    trial.call(node, "start", success=False)
    assert not key_path.exists() and not receipt.exists(), "established wallet was silently replaced"
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    node.start()
    assert json.loads(receipt.read_text()) == identity
    assert key_path.read_bytes() == key
    node.stop()
    trial.summary["node_count"] = 1
    trial.summary["claim"] = "ordinary startup preserves independent wallet custody across restart and rejects loss of the established key and both wallet files"
    trial.summary["scenarios"]["wallet_custody_restart_and_loss"] = {"result": "pass"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--mode", choices=["wallet-custody"], default="wallet-custody")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "wallet-custody")
    try:
        run(trial)
        trial.summary["result"] = "pass"
    except Exception as error:
        trial.summary.update(result="fail", error=str(error))
        traceback.print_exc()
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "wallet-custody", args.profile)
    print(json.dumps({"result": trial.summary["result"], "output": str(trial.output)}))
    return 0 if trial.summary["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
