"""Frozen end-to-end production admission controls; scratch keys are not live trust."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from native_admission_fixture import attach_native

GATE = Path(os.environ.get("FACTORY_GATE", str(Path(__file__).resolve().parents[1] / "production_gate.py")))
CATEGORIES = ["functional", "integration", "failure", "resource", "security", "recovery", "package", "install", "replay", "rollback", "provenance", "local_gates"]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def run(*args, cwd=None, check=True, input=None):
    return subprocess.run([str(a) for a in args], cwd=cwd, input=input, capture_output=True, check=check)


class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keydir = Path(tempfile.mkdtemp(prefix="factory-test-keys-"))
        for principal in ("reviewer", "integrator", "author", "intruder"):
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", cls.keydir / principal)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.keydir)

    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="factory-admission-test-"))
        self.repo = self.temp / "candidate"
        self.repo.mkdir()
        run("git", "init", "-q", self.repo)
        self.git("config", "user.name", "Test Author")
        self.git("config", "user.email", "test@example.invalid")
        (self.repo / "LICENSE").write_text("SPDX-License-Identifier: MIT\n")
        (self.repo / "health.py").write_text("import sys\nprint('ready') if sys.argv[1:] == ['--health'] else sys.exit(2)\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Baseline consumer")
        self.base = self.git("rev-parse", "HEAD").stdout.decode().strip()
        (self.repo / "health.py").write_text("import sys\nprint('ready-v2') if sys.argv[1:] == ['--health'] else sys.exit(2)\n")
        self.git("add", ".")
        self.tree = self.git("write-tree").stdout.decode().strip()
        self.policy_path = self.temp / "policy.json"
        self.bundle_path = self.temp / "bundle.json"
        self.policy = {
            "version": 1, "policy_id": "naome-factory-production-v1",
            "verifiers": {p: (self.keydir / (p + ".pub")).read_text().strip() for p in ("reviewer", "integrator", "author")},
            "production": {
                "evaluator_sha256": digest(GATE.read_bytes()) if GATE.exists() else "0" * 64,
                "allowed_publish_remotes": [str(self.temp / "shared.git")],
                "required_review_roles": {"reviewer": ["reviewer"], "integrator": ["integrator"]},
                "maximum_evidence_age_seconds": 86400,
                "required_evidence": CATEGORIES,
                "denied_path_segments": ["research"],
            },
        }
        self.native = attach_native(self.temp, self.policy, GATE, self.keydir / "reviewer")
        self.policy_path.write_bytes(canonical(self.policy))
        self.objects = {}
        log = run(sys.executable, self.repo / "health.py", "--health").stdout
        log_sha = self.add_object(log)
        archive_sha = self.add_object(self.git("archive", self.tree).stdout)
        evidence = {}
        for category in CATEGORIES:
            evidence[category] = self.add_object(canonical({
                "source_tree": self.tree, "category": category,
                "command": [sys.executable, "health.py", "--health"],
                "exit_code": 0, "checks": [{"name": "supported consumer output", "expected": "ready-v2", "observed": log.decode().strip()}],
                "log_sha256": log_sha,
            }))
        entries = []
        for line in self.git("ls-tree", "-rz", "--full-tree", self.tree).stdout.split(b"\0"):
            if not line:
                continue
            header, path = line.split(b"\t", 1)
            mode, kind, oid = header.decode().split()
            content_sha = digest(self.git("cat-file", "blob", oid).stdout)
            entries.append({"path": path.decode(), "mode": mode, "sha256": content_sha})
        self.statement = {
            "version": 1, "author": "author", "issued_at": int(time.time()), "expires_at": int(time.time()) + 3600,
            "base": self.base, "tree": self.tree,
            "patch_sha256": digest(self.git("diff", "--binary", "--full-index", self.base, self.tree).stdout),
            "snapshot_sha256": digest(canonical(entries)),
            "policy_sha256": digest(self.policy_path.read_bytes()),
            "evaluator_sha256": self.policy["production"]["evaluator_sha256"],
            "capability": {"id": "local-health-cli", "kind": "production", "consumer": "installed local health CLI", "deployment_contract": "Python 3 CLI exits 0 and prints ready-v2 for --health; invalid arguments exit 2"},
            "classification": [{"path": e["path"], "kind": "license" if e["path"] == "LICENSE" else "production_source", "consumer": "health.py --health", "license": "MIT", "provenance": "original scratch fixture"} for e in entries],
            "artifacts": [{"name": "deployable-source.tar", "sha256": archive_sha}],
            "evidence": evidence,
        }
        self.write_bundle()

    def tearDown(self):
        shutil.rmtree(self.temp)

    def git(self, *args, **kwargs):
        return run("git", "-C", self.repo, *args, **kwargs)

    def add_object(self, data):
        sha = digest(data)
        self.objects[sha] = base64.b64encode(data).decode()
        return sha

    def write_bundle(self, principals=("reviewer", "integrator")):
        statement_path = self.temp / "statement.json"
        statement_path.write_bytes(canonical(self.statement))
        signatures = []
        for principal in principals:
            signature_path = Path(str(statement_path) + ".sig")
            signature_path.unlink(missing_ok=True)
            run("ssh-keygen", "-Y", "sign", "-f", self.keydir / principal, "-n", "naome-factory-v1", statement_path)
            signatures.append({"principal": principal, "signature": signature_path.read_text()})
        self.bundle = {"version": 1, "receipts": [{"statement": self.statement, "signatures": signatures}], "objects": self.objects}
        self.bundle_path.write_bytes(canonical(self.bundle))

    def check(self, mode="commit", **kwargs):
        return run(sys.executable, GATE, "check", "--repo", self.repo, "--policy", self.policy_path, "--bundle", self.bundle_path, "--mode", mode, check=False, **kwargs)

    def rejected(self, code, mode="commit"):
        result = self.check(mode)
        self.assertNotEqual(result.returncode, 0, result.stdout.decode())
        self.assertIn(code, result.stderr.decode(), result.stderr.decode())

    def install(self, evaluator=None):
        installed=evaluator or GATE
        self.native['bind_evaluator'](installed)
        self.policy_path.write_bytes(canonical(self.policy))
        self.statement['policy_sha256']=digest(self.policy_path.read_bytes())
        self.write_bundle()
        return run(sys.executable, installed, "install-hooks", "--repo", self.repo, "--policy", self.policy_path, "--bundle", self.bundle_path, "--evaluator", installed, check=False)

    def test_deployable_positive_exact_index(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_disguised_research_is_rejected(self):
        self.statement["classification"][1]["kind"] = "research"
        self.write_bundle()
        self.rejected("classification")

    def test_failed_model_is_rejected(self):
        self.statement["capability"]["kind"] = "failed_model"
        self.write_bundle()
        self.rejected("capability")

    def test_wrong_source_receipt(self):
        self.statement["tree"] = self.git("rev-parse", "HEAD^{tree}").stdout.decode().strip()
        self.write_bundle()
        self.rejected("receipt_missing")

    def test_forged_signature(self):
        self.write_bundle(("intruder", "integrator"))
        self.rejected("signature")

    def test_author_cannot_review_self(self):
        self.statement["author"] = "reviewer"
        self.write_bundle()
        self.rejected("independence")

    def test_two_roles_need_distinct_principals(self):
        self.policy["production"]["required_review_roles"]["integrator"] = ["reviewer"]
        self.policy_path.write_bytes(canonical(self.policy))
        self.statement["policy_sha256"] = digest(self.policy_path.read_bytes())
        self.write_bundle(("reviewer",))
        self.rejected("independence")

    def test_missing_independent_approval(self):
        self.write_bundle(("reviewer",))
        self.rejected("approval")

    def test_expired_evidence(self):
        self.statement["expires_at"] = int(time.time()) - 1
        self.write_bundle()
        self.rejected("expired")

    def test_stale_evidence(self):
        self.statement["issued_at"] = int(time.time()) - 90000
        self.write_bundle()
        self.rejected("expired")

    def test_dirty_unstaged_patch(self):
        (self.repo / "health.py").write_text("print('mutated')\n")
        self.rejected("dirty")

    def test_untracked_research(self):
        (self.repo / "model.py").write_text("# experiment\n")
        self.rejected("dirty")

    def test_wrong_remote_even_fetch_only(self):
        self.git("remote", "add", "wrong", "https://example.invalid/naome.git")
        self.rejected("remote", "candidate")

    def test_shared_git_database(self):
        linked = self.temp / "linked"
        self.git("worktree", "add", "--detach", linked, self.base)
        self.repo = linked
        self.rejected("git_database", "candidate")

    def test_alternate_object_database(self):
        alternate = self.repo / ".git/objects/info/alternates"
        alternate.write_text(str(self.temp) + "\n")
        self.rejected("git_database", "candidate")

    def test_policy_tamper(self):
        self.policy["production"]["maximum_evidence_age_seconds"] += 1
        self.policy_path.write_bytes(canonical(self.policy))
        self.rejected("policy")

    def test_evaluator_tamper(self):
        self.policy["production"]["evaluator_sha256"] = "f" * 64
        self.policy_path.write_bytes(canonical(self.policy))
        self.rejected("evaluator")

    def test_candidate_mutable_policy_rejected(self):
        candidate_policy = self.repo / "policy.json"
        shutil.copyfile(self.policy_path, candidate_policy)
        self.policy_path = candidate_policy
        self.rejected("trust_location")

    def test_wrong_patch_digest(self):
        self.statement["patch_sha256"] = "f" * 64
        self.write_bundle()
        self.rejected("identity")

    def test_wrong_snapshot_digest(self):
        self.statement["snapshot_sha256"] = "f" * 64
        self.write_bundle()
        self.rejected("identity")

    def test_unclassified_baseline_path_is_not_legacy_exempt(self):
        self.statement["classification"] = self.statement["classification"][1:]
        self.write_bundle()
        self.rejected("classification")

    def test_evidence_objects_must_match_digest(self):
        key = self.statement["evidence"]["functional"]
        self.objects[key] = base64.b64encode(b"forged observation").decode()
        self.write_bundle()
        self.rejected("object_digest")

    def test_green_boolean_receipt_is_insufficient(self):
        self.statement["evidence"] = {category: True for category in CATEGORIES}
        self.write_bundle()
        self.rejected("evidence")

    def test_real_failed_observation(self):
        category = "integration"
        self.statement["evidence"][category] = self.add_object(canonical({"source_tree": self.tree, "category": category, "command": ["health.py", "--health"], "exit_code": 0, "checks": [{"name": "output", "expected": "ready-v2", "observed": "broken"}], "log_sha256": self.add_object(b"broken\n")}))
        self.write_bundle()
        self.rejected("evidence")

    def test_hook_install_and_real_precommit(self):
        evaluator = self.temp / "trusted/production_gate.py"
        evaluator.parent.mkdir()
        shutil.copyfile(GATE, evaluator)
        result = self.install(evaluator)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        result = self.git("commit", "-m", "Selected production", check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        (self.repo / "health.py").write_text("print('unreviewed')\n")
        self.git("add", ".")
        result = self.git("commit", "-m", "Unapproved", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("receipt_missing", result.stderr.decode())

    def test_hook_preserves_existing_and_safe_uninstall(self):
        hook = self.repo / ".git/hooks/pre-commit"
        original = b"#!/bin/sh\nexit 42\n"
        hook.write_bytes(original)
        hook.chmod(0o755)
        evaluator = self.temp / "trusted.py"
        shutil.copyfile(GATE, evaluator)
        result = self.install(evaluator)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        result = self.git("commit", "-m", "Production", check=False)
        self.assertNotEqual(result.returncode, 0)
        result = run(sys.executable, GATE, "uninstall-hooks", "--repo", self.repo, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(hook.read_bytes(), original)

    def test_prepush_rejects_unapproved_commit_created_with_no_verify(self):
        shared = self.temp / "shared.git"
        run("git", "init", "--bare", "-q", shared)
        self.git("remote", "add", "origin", shared)
        evaluator = self.temp / "trusted.py"
        shutil.copyfile(GATE, evaluator)
        self.assertEqual(self.install(evaluator).returncode, 0)
        self.git("commit", "--no-verify", "-qm", "Approved selected source")
        result = self.git("push", "origin", "HEAD:refs/heads/main", check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        (self.repo / "health.py").write_text("print('unqualified')\n")
        self.git("add", ".")
        self.git("commit", "--no-verify", "-qm", "Bypassed precommit")
        result = self.git("push", "origin", "HEAD:refs/heads/main", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("receipt_missing", result.stderr.decode())

    def test_audit_reports_complete_actual_tree(self):
        self.git("commit", "--no-verify", "-qm", "Selected")
        result = self.check("audit")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        report = json.loads(result.stdout)
        self.assertEqual(report["classified_paths"], 2)
        self.assertEqual(report["tree"], self.tree)


if __name__ == "__main__":
    unittest.main(verbosity=2)
