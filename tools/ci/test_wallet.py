"""Wallet private material must never enter lifecycle evidence archives."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "wallet_lifecycle_fixture",
    ROOT / "crates/naome-knowledge/tests/support/autonomous_lifecycle.py",
)
LIFECYCLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIFECYCLE)


class WalletEvidenceTests(unittest.TestCase):
    def test_archive_and_manifest_exclude_completed_and_pending_private_keys(self):
        with tempfile.TemporaryDirectory(prefix="naome-wallet-evidence-") as name:
            output = Path(name).resolve() / "evidence"
            node = output / "node-0"
            node.mkdir(parents=True)
            for filename in ["identity.key", "wallet.key", ".wallet-key-incoming"]:
                (node / filename).write_bytes(b"private test material")
            (node / "wallet.json").write_text('{"public":"address"}')
            summary = {"result": "pass"}
            with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
                LIFECYCLE.retain_evidence(output, summary, "wallet", "test")
            self.assertEqual(set(summary["artifacts"]), {"node-0/wallet.json"})
            with zipfile.ZipFile(summary["ci_archive"]) as archive:
                self.assertEqual(set(archive.namelist()), {"summary.json", "node-0/wallet.json"})
                self.assertNotIn(b"private test material", b"".join(
                    archive.read(item) for item in archive.namelist()
                ))
            self.assertEqual(json.loads((output / "summary.json").read_text()), summary)


if __name__ == "__main__":
    unittest.main()
