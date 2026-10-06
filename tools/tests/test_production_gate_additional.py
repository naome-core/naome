"""Additional controls frozen before guarded promotion and hosted-CI implementation."""
import base64
import gzip
import os
from pathlib import Path
import shutil
import sys
import test_production_gate as fixture


class PromotionAndCITests(fixture.AdmissionTests):
    def destination(self):
        destination = self.temp / "shared-checkout"
        fixture.run("git", "clone", "--no-hardlinks", "-q", self.repo, destination)
        fixture.run("git", "-C", destination, "remote", "remove", "origin")
        fixture.run("git", "-C", destination, "remote", "add", "origin", self.temp / "shared.git")
        return destination

    def fingerprint(self, path):
        return {str(p.relative_to(path)): fixture.digest(p.read_bytes()) for p in path.rglob("*") if p.is_file() and not p.is_symlink()}

    def promote(self, destination):
        return fixture.run(sys.executable, fixture.GATE, "promote", "--repo", self.repo, "--destination", destination, "--policy", self.policy_path, "--bundle", self.bundle_path, check=False)

    def test_guarded_promotion_copies_exact_source_without_git_objects(self):
        destination = self.destination()
        original_git = self.fingerprint(destination / ".git")
        result = self.promote(destination)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((destination / "health.py").read_bytes(), (self.repo / "health.py").read_bytes())
        self.assertEqual(self.fingerprint(destination / ".git"), original_git)

    def test_rejected_source_never_writes_shared_files_refs_or_objects(self):
        destination = self.destination()
        before = self.fingerprint(destination)
        self.statement["snapshot_sha256"] = "0" * 64
        self.write_bundle()
        result = self.promote(destination)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.fingerprint(destination), before)

    def test_wrong_destination_remote_never_writes(self):
        destination = self.destination()
        fixture.run("git", "-C", destination, "remote", "set-url", "origin", "https://example.invalid/wrong.git")
        before = self.fingerprint(destination)
        self.assertNotEqual(self.promote(destination).returncode, 0)
        self.assertEqual(self.fingerprint(destination), before)

    def test_destination_alias_symlink_never_writes(self):
        destination = self.destination()
        alias = self.temp / "alias"
        alias.symlink_to(destination)
        before = self.fingerprint(destination)
        self.assertNotEqual(self.promote(alias).returncode, 0)
        self.assertEqual(self.fingerprint(destination), before)

    def test_dirty_destination_never_writes(self):
        destination = self.destination()
        (destination / "health.py").write_text("owner changes\n")
        before = self.fingerprint(destination)
        self.assertNotEqual(self.promote(destination).returncode, 0)
        self.assertEqual(self.fingerprint(destination), before)

    def test_distinct_roles_cannot_use_one_shared_key(self):
        self.policy["verifiers"]["integrator"] = self.policy["verifiers"]["reviewer"]
        self.policy_path.write_bytes(fixture.canonical(self.policy))
        self.statement["policy_sha256"] = fixture.digest(self.policy_path.read_bytes())
        statement = self.temp / "same-key-statement"
        statement.write_bytes(fixture.canonical(self.statement))
        fixture.run("ssh-keygen", "-Y", "sign", "-f", self.keydir / "reviewer", "-n", "naome-factory-v1", statement)
        signature = Path(str(statement) + ".sig").read_text()
        self.bundle["receipts"] = [{"statement": self.statement, "signatures": [{"principal": p, "signature": signature} for p in ("reviewer", "integrator")]}]
        self.bundle_path.write_bytes(fixture.canonical(self.bundle))
        self.rejected("independence")

    def test_ci_materialization_uses_protected_external_bytes(self):
        directory = self.temp / "ci-trust"
        environment = dict(os.environ, NAOME_FACTORY_POLICY_JSON=self.policy_path.read_text(), NAOME_FACTORY_APPROVALS_GZIP_B64=base64.b64encode(gzip.compress(self.bundle_path.read_bytes(), mtime=0)).decode())
        import subprocess
        result = subprocess.run([sys.executable, str(fixture.GATE), "ci-materialize", "--directory", str(directory)], env=environment, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((directory / "bundle.json").read_bytes(), self.bundle_path.read_bytes())
        self.assertEqual((directory / "policy.json").read_bytes(), self.policy_path.read_bytes())

    def test_ci_missing_owner_trust_fails_closed(self):
        import subprocess
        environment = {k: v for k, v in os.environ.items() if not k.startswith("NAOME_FACTORY_")}
        result = subprocess.run([sys.executable, str(fixture.GATE), "ci-materialize", "--directory", str(self.temp / "ci-trust")], env=environment, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trust_missing", result.stderr.decode())
