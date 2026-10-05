import importlib.util
import json
import os
from pathlib import Path
import sys
import signal
import subprocess
import tempfile
import unittest
import time

spec = importlib.util.spec_from_file_location(
    "proof_lab_run", Path(__file__).resolve().parents[1] / "proof_lab_run.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ProofLabLifetimeTests(unittest.TestCase):
    def test_one_supervisor_sigterm_reaps_only_its_owned_experiment_group(self):
        with tempfile.TemporaryDirectory() as name:
            directory=Path(name)
            code="""
import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('runner',sys.argv[1]);runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
result=runner.run_stage([sys.executable,'-c','import time;time.sleep(20)'],Path(sys.argv[2]),'supervisor',60)
(Path(sys.argv[2])/'result.json').write_text(json.dumps(result))
"""
            supervisor=subprocess.Popen([sys.executable,"-c",code,str(spec.origin),name],start_new_session=True)
            group=None
            try:
                deadline=time.monotonic()+5
                started=directory/'supervisor-started.json'
                while not started.exists() and time.monotonic()<deadline:
                    time.sleep(0.01)
                self.assertTrue(started.exists())
                group=json.loads(started.read_text())["group"]
                os.kill(supervisor.pid,signal.SIGTERM)
                self.assertEqual(supervisor.wait(timeout=5),0)
                result=json.loads((directory/'result.json').read_text())
                self.assertEqual(result['failure'],'supervisor received SIGTERM')
                self.assertEqual(result['termination_signal'],signal.SIGTERM)
                self.assertEqual(result['pid'],group)
                self.assertTrue(result['owned_group_empty'])
                self.assertEqual(runner.group_members(group),[])
            finally:
                if supervisor.poll() is None:
                    os.killpg(supervisor.pid,signal.SIGKILL);supervisor.wait(timeout=5)
                if group is not None and runner.group_members(group):
                    os.killpg(group,signal.SIGKILL)

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
