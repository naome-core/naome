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
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "proof_lab_run", Path(__file__).resolve().parents[1] / "proof_lab_run.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ProofLabLifetimeTests(unittest.TestCase):
    def test_capitalized_gnu_and_bsd_native_rss_units(self):
        gnu = "\tMaximum resident set size (kbytes): 12345\n"
        bsd = "              98765  maximum resident set size\n"
        self.assertEqual(runner.native_peak_rss(gnu), 12345 * 1024)
        self.assertEqual(runner.native_peak_rss(bsd), 98765)
        self.assertEqual(runner.native_peak_rss(gnu + bsd), 12345 * 1024)

    def test_actual_native_high_water_enforces_ceiling_when_polling_misses_peak(self):
        with tempfile.TemporaryDirectory() as name:
            # Deliberately remove sampled RSS while keeping the real native time
            # process and log. Linux exercises GNU's capitalized verbose label.
            with mock.patch.object(runner, "group_members", return_value=[]):
                result = runner.run_stage(
                    [sys.executable, "-c", "x=bytearray(8*1024*1024)"],
                    Path(name), "native-peak", 5, memory_limit=1)
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["failure"], "native peak RSS exceeded ceiling")
            self.assertGreater(result["peak_rss_bytes"], 1)
            self.assertGreater(runner.native_peak_rss(
                (Path(name) / "native-peak-resources.txt").read_text()), 1)

    def test_sigterm_during_successful_child_cleanup_interrupts_workflow(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            code = """
import importlib.util,json,signal,sys,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('runner',sys.argv[1]);runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
directory=Path(sys.argv[2]);original=runner.terminate
def cleanup(process):
    assert process.wait(timeout=5)==0
    received=[False];handler=signal.getsignal(signal.SIGTERM)
    def observe(signum,frame):
        handler(signum,frame);received[0]=True
    signal.signal(signal.SIGTERM,observe)
    (directory/'cleanup-ready.json').write_text(json.dumps({'group':process.pid}))
    deadline=time.monotonic()+5
    while not received[0] and time.monotonic()<deadline:time.sleep(0.01)
    assert received[0]
    original(process)
runner.terminate=cleanup
result=runner.run_stage([sys.executable,'-c','print(123)'],directory,'late-stop',10)
(directory/'result.json').write_text(json.dumps(result))
"""
            supervisor = subprocess.Popen(
                [sys.executable, "-c", code, str(spec.origin), name],
                start_new_session=True)
            group = None
            try:
                ready = directory / 'cleanup-ready.json'
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                group = json.loads(ready.read_text())['group']
                os.kill(supervisor.pid, signal.SIGTERM)
                self.assertEqual(supervisor.wait(timeout=5), 0)
                result = json.loads((directory / 'result.json').read_text())
                self.assertEqual(result['exit_code'], 0)
                self.assertEqual(result['failure'], 'supervisor received SIGTERM')
                self.assertEqual(result['termination_signal'], signal.SIGTERM)
                self.assertTrue(result['owned_group_empty'])
                self.assertEqual(runner.group_members(group), [])
            finally:
                if supervisor.poll() is None:
                    os.killpg(supervisor.pid, signal.SIGKILL)
                    supervisor.wait(timeout=5)
                if group is not None and runner.group_members(group):
                    os.killpg(group, signal.SIGKILL)

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


class ProofLabPreflightTests(unittest.TestCase):
    def command_outputs(self, identity):
        repo = Path(spec.origin).resolve().parents[1]
        pin = runner.re.search(r'^channel\s*=\s*"([^"]+)"',
                               (repo / "rust-toolchain.toml").read_text(),
                               runner.re.MULTILINE).group(1)

        def output(command, **_kwargs):
            if command[:2] == ["git", "rev-parse"]:
                return ("a" if command[2] == "HEAD^{tree}" else "b") * 40 + "\n"
            if command[:2] == ["git", "status"]:
                return ""
            if command == ["rustc", "--version"]:
                return f"rustc {pin} (control)\n"
            if command == ["cargo", "--version"]:
                return f"cargo {pin} (control)\n"
            if command[-1] == "--identity":
                return json.dumps({"schema": 1, "compiler": f"rustc {pin} (control)",
                                   "source_tree": "a" * 40, "source_clean": True, **identity})
            raise AssertionError(command)
        return output

    def test_same_compiler_stale_or_dirty_binary_rejected_before_run_directory(self):
        for identity in [{"source_tree": "c" * 40}, {"source_clean": False}]:
            with self.subTest(identity=identity), tempfile.TemporaryDirectory() as name:
                directory = Path(name) / "new-attempt"
                args = ["runner", "--binary", str(Path(name) / "binary"),
                        "--config", str(Path(name) / "config.json"),
                        "--directory", str(directory)]
                with (mock.patch.object(sys, "argv", args),
                      mock.patch.object(runner.subprocess, "check_output",
                                        side_effect=self.command_outputs(identity)),
                      mock.patch.object(runner.subprocess, "run") as validation,
                      mock.patch.object(runner, "run_stage") as stage):
                    with self.assertRaisesRegex(RuntimeError, "current clean source tree"):
                        runner.main()
                self.assertFalse(directory.exists())
                validation.assert_not_called()
                stage.assert_not_called()

    def test_rust_config_rejection_precedes_any_output_or_stage(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name) / "invalid-attempt"
            binary = Path(name) / "binary"
            config = Path(name) / "config.json"
            args = ["runner", "--binary", str(binary), "--config", str(config),
                    "--directory", str(directory)]
            command = [str(binary.resolve()), "--validate-config", str(config.resolve())]
            with (mock.patch.object(sys, "argv", args),
                  mock.patch.object(runner.subprocess, "check_output",
                                    side_effect=self.command_outputs({})),
                  mock.patch.object(runner.subprocess, "run",
                                    side_effect=subprocess.CalledProcessError(1, command)) as validation,
                  mock.patch.object(runner, "run_stage") as stage):
                with self.assertRaises(subprocess.CalledProcessError):
                    runner.main()
            validation.assert_called_once_with(command, check=True)
            self.assertFalse(directory.exists())
            stage.assert_not_called()


if __name__ == "__main__":
    unittest.main()
