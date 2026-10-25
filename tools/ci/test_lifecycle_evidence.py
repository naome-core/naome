"""Node identity and control secrets must never enter lifecycle evidence archives."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crates/naome-knowledge/tests/support"))
SPEC = importlib.util.spec_from_file_location(
    "lifecycle_fixture",
    ROOT / "crates/naome-knowledge/tests/support/autonomous_lifecycle.py",
)
LIFECYCLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIFECYCLE)


class LifecycleEvidenceTests(unittest.TestCase):
    def test_archive_and_manifest_exclude_identity_keys_and_control_secrets(self):
        with tempfile.TemporaryDirectory(prefix="naome-lifecycle-evidence-") as name:
            output = Path(name).resolve() / "evidence"
            node = output / "node-0"
            node.mkdir(parents=True)
            for filename in ["identity.key", "control.json", ".control-incoming"]:
                (node / filename).write_bytes(b"private test material")
            (node / "identity.json").write_text('{"version":1,"peer_id":"public peer"}')
            summary = {"result": "pass"}
            with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
                LIFECYCLE.retain_evidence(output, summary, "identity", "test")
            self.assertEqual(set(summary["artifacts"]), {"node-0/identity.json"})
            with zipfile.ZipFile(summary["ci_archive"]) as archive:
                self.assertEqual(set(archive.namelist()), {"summary.json", "node-0/identity.json"})
                self.assertNotIn(b"private test material", b"".join(
                    archive.read(item) for item in archive.namelist()
                ))
            self.assertEqual(json.loads((output / "summary.json").read_text()), summary)


if __name__ == "__main__":
    unittest.main()
