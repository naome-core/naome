"""Forced process interruption and guarded promotion rollback; frozen first."""
import json
from pathlib import Path
import sys
import test_production_gate as fixture
import test_production_gate_additional as promotion


class PromotionRecoveryTests(promotion.PromotionAndCITests):
    def crash(self, destination):
        runner = self.temp / "kill_after_source_replace.py"
        runner.write_text("import importlib.util, os, types\n"
            + "spec=importlib.util.spec_from_file_location('gate', " + repr(str(fixture.GATE)) + ")\n"
            + "gate=importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)\n"
            + "original=gate.os.replace\n"
            + "def crash(source,destination):\n"
            + " original(source,destination)\n"
            + " if os.path.realpath(destination) == " + repr(str((destination / "health.py").resolve())) + ": os._exit(77)\n"
            + "gate.os.replace=crash\n"
            + "gate.promote(types.SimpleNamespace(repo=" + repr(str(self.repo)) + ",destination=" + repr(str(destination)) + ",policy=" + repr(str(self.policy_path)) + ",bundle=" + repr(str(self.bundle_path)) + "))\n")
        result = fixture.run(sys.executable, runner, check=False)
        self.assertEqual(result.returncode, 77, result.stderr.decode())

    def recover(self, destination):
        return fixture.run(sys.executable, fixture.GATE, "recover-promotion", "--destination", destination, "--policy", self.policy_path, check=False)

    def test_forced_process_crash_retains_recoverable_baseline(self):
        destination = self.destination()
        before = self.fingerprint(destination)
        self.crash(destination)
        self.assertNotEqual(self.fingerprint(destination), before)
        result = self.recover(destination)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(self.fingerprint(destination), before)

    def test_recovery_preserves_later_owner_edits(self):
        destination = self.destination()
        self.crash(destination)
        (destination / "health.py").write_text("later owner edit\n")
        before = self.fingerprint(destination)
        self.assertNotEqual(self.recover(destination).returncode, 0)
        self.assertEqual(self.fingerprint(destination), before)

    def test_recovery_without_owned_transaction_is_rejected(self):
        destination = self.destination()
        before = self.fingerprint(destination)
        self.assertNotEqual(self.recover(destination).returncode, 0)
        self.assertEqual(self.fingerprint(destination), before)
