import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "proof_lab_run", Path(__file__).resolve().parents[1] / "proof_lab_run.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ProofLabLifetimeTests(unittest.TestCase):
    def test_success_retains_native_resources_and_reaps_group(self):
        with tempfile.TemporaryDirectory() as name:
            result = runner.run_stage([sys.executable, "-c", "print('control')"],
                                      Path(name), "success", 5)
            self.assertEqual(result["exit_code"], 0)
            self.assertIsNone(result["failure"])
            self.assertTrue(result["owned_group_empty"])
            self.assertGreater(result["peak_rss_bytes"], 0)
            self.assertIsNotNone(result["resource_log_sha256"])

    def test_timeout_stops_and_reaps_owned_process(self):
        with tempfile.TemporaryDirectory() as name:
            result = runner.run_stage(
                [sys.executable, "-c", "import time; time.sleep(20)"],
                Path(name), "timeout", 0.1)
            self.assertEqual(result["failure"], "shared active execution ceiling")
            self.assertNotEqual(result["exit_code"], 0)
            self.assertTrue(result["owned_group_empty"])
            self.assertLess(result["seconds"], 5)

    def test_memory_ceiling_stops_and_retains_attempt(self):
        with tempfile.TemporaryDirectory() as name:
            result = runner.run_stage(
                [sys.executable, "-c", "import time; x=bytearray(8*1024*1024); time.sleep(20)"],
                Path(name), "memory", 5, memory_limit=1)
            self.assertEqual(result["failure"], "process-group RSS ceiling")
            self.assertTrue(result["owned_group_empty"])
            self.assertTrue((Path(name) / "memory.log").exists())


if __name__ == "__main__":
    unittest.main()
