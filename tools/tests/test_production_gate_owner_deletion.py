"""Distinguish later owner deletion from the promotion's selected deletion."""
import base64
import json
from pathlib import Path
import sys
import unittest
import test_production_gate as fixture
import test_production_gate_additional as promotion
import test_production_gate_recovery as recovery


class OwnerDeletionTests(unittest.TestCase):
    setUpClass = classmethod(fixture.AdmissionTests.setUpClass.__func__)
    tearDownClass = classmethod(fixture.AdmissionTests.tearDownClass.__func__)
    setUp = fixture.AdmissionTests.setUp
    tearDown = fixture.AdmissionTests.tearDown
    git = fixture.AdmissionTests.git
    add_object = fixture.AdmissionTests.add_object
    write_bundle = fixture.AdmissionTests.write_bundle
    destination = promotion.PromotionAndCITests.destination
    fingerprint = promotion.PromotionAndCITests.fingerprint
    recover = recovery.PromotionRecoveryTests.recover
    crash = recovery.PromotionRecoveryTests.crash

    def qualify_selected_index(self):
        self.git("add", "-A")
        self.tree = self.git("write-tree").stdout.decode().strip()
        entries = []
        for row in self.git("ls-tree", "-rz", "--full-tree", self.tree).stdout.split(b"\0"):
            if not row:
                continue
            header, path = row.split(b"\t", 1)
            mode, _, oid = header.decode().split()
            entries.append({"path": path.decode(), "mode": mode, "sha256": fixture.digest(self.git("cat-file", "blob", oid).stdout)})
        self.statement.update(tree=self.tree, patch_sha256=fixture.digest(self.git("diff", "--binary", "--full-index", self.base, self.tree).stdout), snapshot_sha256=fixture.digest(fixture.canonical(entries)))
        self.statement["classification"] = [{"path": entry["path"], "kind": "production_source", "consumer": "scratch health CLI", "license": "MIT", "provenance": "original scratch fixture"} for entry in entries]
        self.statement["artifacts"] = [{"name": "consumer-source.tar", "sha256": self.add_object(self.git("archive", self.tree).stdout)}]
        for category, digest in self.statement["evidence"].items():
            record = json.loads(base64.b64decode(self.objects[digest]))
            record["source_tree"] = self.tree
            self.statement["evidence"][category] = self.add_object(fixture.canonical(record))
        self.write_bundle()

    def test_owner_deletion_during_failed_promotion_preserved_without_any_other_restore(self):
        (self.repo / "LICENSE").write_text("SPDX-License-Identifier: MIT\nSelected license update\n")
        self.qualify_selected_index()
        destination = self.destination()
        baseline_health = (destination / "health.py").read_bytes()
        restore_marker = self.temp / "restore-attempted"
        runner = self.temp / "owner_delete_before_later_failure.py"
        runner.write_text("import importlib.util, os, types\n"
            + "from pathlib import Path\n"
            + "spec=importlib.util.spec_from_file_location('gate'," + repr(str(fixture.GATE)) + ")\n"
            + "gate=importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)\n"
            + "original=gate.os.replace\n"
            + "def inject(source,target):\n"
            + " if Path(source).parent.name=='originals' and Path(target).parent==Path(" + repr(str(destination)) + "): Path(" + repr(str(restore_marker)) + ").write_text(str(target))\n"
            + " if Path(source).parent.name=='selected' and os.path.realpath(target)==" + repr(str((destination / "health.py").resolve())) + ":\n"
            + "  Path(" + repr(str(destination / "LICENSE")) + ").unlink()\n"
            + "  raise OSError('later write failure after concurrent owner deletion')\n"
            + " return original(source,target)\n"
            + "gate.os.replace=inject\n"
            + "gate.promote(types.SimpleNamespace(repo=" + repr(str(self.repo)) + ",destination=" + repr(str(destination)) + ",policy=" + repr(str(self.policy_path)) + ",bundle=" + repr(str(self.bundle_path)) + "))\n")
        result = fixture.run(sys.executable, runner, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("owner deletion", result.stderr.decode())
        self.assertFalse((destination / "LICENSE").exists(), "concurrent owner deletion must be preserved")
        self.assertFalse(restore_marker.exists(), "all conflicts must be checked before any source restore")
        self.assertEqual((destination / "health.py").read_bytes(), baseline_health)
        self.assertTrue((destination / ".git/naome-factory-promotion").is_dir())
        self.assertTrue((destination / ".git/naome-factory-promotion.lock").is_file())
        before = self.fingerprint(destination)
        result = self.recover(destination)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("owner deletion", result.stderr.decode())
        self.assertEqual(self.fingerprint(destination), before, "conflict preflight must complete before any source/backup writes")

    def test_own_selected_source_deletion_is_recoverable(self):
        (self.repo / "LICENSE").unlink()
        self.qualify_selected_index()
        destination = self.destination()
        baseline = self.fingerprint(destination)
        self.crash(destination)
        self.assertFalse((destination / "LICENSE").exists())
        result = self.recover(destination)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(self.fingerprint(destination), baseline)
