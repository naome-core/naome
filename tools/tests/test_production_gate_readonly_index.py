"""Read-only staged admission must not materialize trees or refresh the index."""
import base64
import json
from pathlib import Path
import shutil
import sys
import unittest
import test_production_gate as fixture


class ReadOnlyIndexTests(unittest.TestCase):
    setUpClass = classmethod(fixture.AdmissionTests.setUpClass.__func__)
    tearDownClass = classmethod(fixture.AdmissionTests.tearDownClass.__func__)
    setUp = fixture.AdmissionTests.setUp
    tearDown = fixture.AdmissionTests.tearDown
    git = fixture.AdmissionTests.git
    add_object = fixture.AdmissionTests.add_object
    write_bundle = fixture.AdmissionTests.write_bundle
    check = fixture.AdmissionTests.check

    def staged_without_tree(self, approve=False):
        nested = self.repo / "nested/zebra/tool.py"
        nested.parent.mkdir(parents=True)
        nested.write_text("print('nested consumer')\n")
        nested.chmod(0o755)
        (self.repo / "nested.txt").write_text("name sorting boundary\n")
        self.git("add", ".")
        # Only the independent reference object database may materialize trees.
        reference = self.temp / "independent-reference"
        shutil.copytree(self.repo, reference)
        result = fixture.run("git", "-C", reference, "write-tree")
        self.new_tree = result.stdout.decode().strip()
        self.assertNotEqual(self.new_tree, self.tree)
        self.assertNotEqual(self.git("cat-file", "-e", self.new_tree, check=False).returncode, 0)
        if approve:
            self.tree = self.new_tree
            entries = []
            for line in fixture.run("git", "-C", reference, "ls-tree", "-rz", "--full-tree", self.tree).stdout.split(b"\0"):
                if not line:
                    continue
                header, path = line.split(b"\t", 1)
                mode, _, oid = header.decode().split()
                entries.append({"path": path.decode(), "mode": mode, "sha256": fixture.digest(self.git("cat-file", "blob", oid).stdout)})
            self.statement.update(tree=self.tree, patch_sha256=fixture.digest(fixture.run("git", "-C", reference, "diff", "--binary", "--full-index", self.base, self.tree).stdout), snapshot_sha256=fixture.digest(fixture.canonical(entries)))
            self.statement["classification"] = [{"path": entry["path"], "kind": "production_source", "consumer": "retained scratch health consumer", "license": "MIT", "provenance": "fixed regression fixture"} for entry in entries]
            self.statement["artifacts"] = [{"name": "consumer-source.tar", "sha256": self.add_object(fixture.run("git", "-C", reference, "archive", self.tree).stdout)}]
            for category, digest in self.statement["evidence"].items():
                record = json.loads(base64.b64decode(self.objects[digest]))
                record["source_tree"] = self.tree
                self.statement["evidence"][category] = self.add_object(fixture.canonical(record))
            self.write_bundle()
        shutil.rmtree(reference)

    def git_inventory(self):
        return {str(path.relative_to(self.repo)): (path.stat().st_mode, path.read_bytes()) for path in sorted((self.repo / ".git").rglob("*")) if path.is_file()}

    def test_identity_commit_and_candidate_are_completely_read_only(self):
        self.staged_without_tree()
        for mode in ("commit", "candidate"):
            with self.subTest(mode=mode):
                before = self.git_inventory()
                result = fixture.run(sys.executable, fixture.GATE, "identity", "--repo", self.repo, "--mode", mode, check=False)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(json.loads(result.stdout)["tree"], self.new_tree)
                self.assertEqual(self.git_inventory(), before)
                self.assertNotEqual(self.git("cat-file", "-e", self.new_tree, check=False).returncode, 0)

    def test_rejected_commit_and_candidate_are_completely_read_only(self):
        self.staged_without_tree()
        for mode in ("commit", "candidate"):
            with self.subTest(mode=mode):
                before = self.git_inventory()
                result = self.check(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("receipt_missing", result.stderr.decode())
                self.assertEqual(self.git_inventory(), before)

    def test_approved_commit_and_candidate_are_completely_read_only(self):
        self.staged_without_tree(approve=True)
        for mode in ("commit", "candidate"):
            with self.subTest(mode=mode):
                before = self.git_inventory()
                result = self.check(mode)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(json.loads(result.stdout)["tree"], self.new_tree)
                self.assertEqual(self.git_inventory(), before)
                self.assertNotEqual(self.git("cat-file", "-e", self.new_tree, check=False).returncode, 0)
