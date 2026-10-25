#!/usr/bin/env python3
"""Bounded ordinary wallet custody and independent key-control verification."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import traceback

from autonomous_lifecycle import Node, Trial, retain_evidence


def call(trial, directory, *arguments, success=True):
    result = subprocess.run(
        [str(trial.binary), "--json", "wallet", *map(str, arguments)],
        env={**os.environ, "NAOME_NODE_DIR": str(directory)},
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=trial.remaining(5),
    )
    if success:
        assert result.returncode == 0 and result.stderr == "", result.stderr
        return json.loads(result.stdout)
    assert result.returncode != 0 and result.stderr, arguments
    assert result.stdout == "", result.stdout
    return result.stderr


def run(trial):
    node = Node(trial, 0)
    node.config["discovery"] = {"mdns": False, "dht": False, "internet": False}
    node.write_config()
    verifier = trial.output / "verifier-without-a-node"
    call(trial, node.directory, "address", success=False)
    assert not (node.directory / "wallet.key").exists()
    node.start()
    identity = call(trial, node.directory, "address")
    address = identity["address"]
    assert set(identity) == {"version", "address"} and identity["version"] == 1
    assert address.startswith("nao1")
    key_path = node.directory / "wallet.key"
    key = key_path.read_bytes()
    assert key_path.stat().st_mode & 0o777 == 0o600
    assert key != (node.directory / "identity.key").read_bytes()

    challenge = call(trial, verifier, "challenge", "naome.test/wallet-control")
    challenge_path = trial.output / "challenge.json"
    challenge_path.write_text(json.dumps(challenge))
    proof = call(trial, node.directory, "prove", challenge_path)
    assert proof["address"] == address and proof["challenge"] == challenge
    assert "balance" not in proof and key.hex() not in json.dumps(proof)
    proof_path = trial.output / "ownership.json"
    proof_path.write_text(json.dumps(proof))
    verified = call(trial, verifier, "verify", address, challenge_path, proof_path)
    assert verified == {"address": address, "verified": True, "scope": "wallet_key_control"}
    assert not verifier.exists(), "verification initialized an unrelated node or wallet"

    another = call(trial, verifier, "challenge", "naome.test/wallet-control")
    assert another["nonce"] != challenge["nonce"]
    fresh_path = trial.output / "fresh-challenge.json"
    fresh_path.write_text(json.dumps(another))
    call(trial, verifier, "verify", address, fresh_path, proof_path, success=False)
    tampered_path = trial.output / "tampered-proof.json"
    tampered_path.write_text(json.dumps({**proof, "signature": "00" * 64}))
    call(trial, verifier, "verify", address, challenge_path, tampered_path, success=False)

    node.stop()
    assert call(trial, node.directory, "address") == identity
    assert call(trial, node.directory, "prove", challenge_path) == proof
    node.start()
    assert call(trial, node.directory, "address") == identity
    assert key_path.read_bytes() == key
    node.stop()
    key_path.unlink()
    try:
        trial.call(node, "start", success=False)
        assert not key_path.exists(), "lost wallet key was silently regenerated"
        assert call(trial, node.directory, "address") == identity
        call(trial, node.directory, "prove", challenge_path, success=False)
    finally:
        key_path.write_bytes(key)
        key_path.chmod(0o600)
    trial.summary["node_count"] = 1
    trial.summary["claim"] = "ordinary CLI, persistent wallet custody, independent challenge-bound key control; no coin balance or payment claim"
    trial.summary["wallet_address"] = address
    trial.summary["scenarios"]["wallet_key_control_restart_and_loss"] = {"result": "pass"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--mode", choices=["wallet"], default="wallet")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "wallet")
    try:
        run(trial)
        trial.summary["result"] = "pass"
    except Exception as error:
        trial.summary.update(result="fail", error=str(error))
        traceback.print_exc()
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "wallet", args.profile)
    print(json.dumps({"result": trial.summary["result"], "output": str(trial.output)}))
    return 0 if trial.summary["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
