"""No candidate execution, finite JSON, and failed hook-install recovery."""
import json
import sys
import test_production_gate as fixture


class TrustedReadTests(fixture.AdmissionTests):
    def test_candidate_textconv_and_external_diff_never_execute(self):
        sentinel = self.temp / "unqualified-program-ran"
        script = self.temp / "unqualified_driver.py"
        script.write_text("from pathlib import Path\nPath(" + repr(str(sentinel)) + ").write_text('bad')\nprint('fake diff')\n")
        (self.repo / ".gitattributes").write_text("health.py diff=malicious\n")
        self.git("add", ".gitattributes")
        self.git("config", "diff.malicious.textconv", sys.executable + " " + str(script))
        self.git("config", "diff.malicious.command", sys.executable + " " + str(script))
        result = fixture.run(sys.executable, fixture.GATE, "identity", "--repo", self.repo, "--mode", "candidate", check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(sentinel.exists())
        self.assertNotEqual(self.check().returncode, 0)
        self.assertFalse(sentinel.exists())

    def test_nonfinite_json_policy_rejected(self):
        raw = self.policy_path.read_text().replace('"maximum_evidence_age_seconds":86400', '"maximum_evidence_age_seconds":NaN')
        self.policy_path.write_text(raw)
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("schema", result.stderr.decode())

    def test_numeric_overflow_json_rejected(self):
        raw = self.policy_path.read_text().replace('"maximum_evidence_age_seconds":86400', '"maximum_evidence_age_seconds":1e999')
        self.policy_path.write_text(raw)
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("schema", result.stderr.decode())

    def test_hook_install_failure_restores_existing_hooks(self):
        original = b"#!/bin/sh\nexit 17\n"
        hook = self.repo / ".git/hooks/pre-commit"
        hook.write_bytes(original)
        hook.chmod(0o755)
        evaluator = self.temp / "trusted.py"
        evaluator.write_bytes(fixture.GATE.read_bytes())
        runner = self.temp / "inject_install_failure.py"
        runner.write_text("import importlib.util, types\n"
            + "spec=importlib.util.spec_from_file_location('gate'," + repr(str(fixture.GATE)) + ")\n"
            + "gate=importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)\n"
            + "original=gate.atomic_write\n"
            + "def fail(path,data,mode=0o600):\n"
            + " if str(path).endswith('/hooks/pre-push'): raise OSError('forced install failure')\n"
            + " return original(path,data,mode)\n"
            + "gate.atomic_write=fail\n"
            + "gate.install_hooks(types.SimpleNamespace(repo=" + repr(str(self.repo)) + ",policy=" + repr(str(self.policy_path)) + ",bundle=" + repr(str(self.bundle_path)) + ",evaluator=" + repr(str(evaluator)) + "))\n")
        result = fixture.run(sys.executable, runner, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(hook.read_bytes(), original)
        self.assertFalse((self.repo / ".git/hooks/pre-push").exists())
        self.assertFalse((self.repo / ".git/naome-factory-hooks.json").exists())
