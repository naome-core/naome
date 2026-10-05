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


class ProofLabBuildIdentityTests(unittest.TestCase):
    def test_cached_build_refreshes_after_untracked_removal_and_tracked_restore(self):
        root = Path(__file__).resolve().parents[2]
        pin = runner.re.search(r'^channel\s*=\s*"([^"]+)"',
                               (root / "rust-toolchain.toml").read_text(),
                               runner.re.MULTILINE).group(1)
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            repo = directory / "fixture"
            repo.mkdir()
            (repo / "src").mkdir()
            (repo / ".gitignore").write_text("/target/\n")
            (repo / "Cargo.toml").write_text(
                '[package]\nname="build-identity-control"\nversion="0.0.0"\nedition="2024"\n\n[workspace]\n')
            (repo / "Cargo.lock").write_text(
                'version = 4\n\n[[package]]\nname = "build-identity-control"\nversion = "0.0.0"\n')
            (repo / "build.rs").write_bytes(
                (root / "crates/naome-proof-lab/build.rs").read_bytes())
            source = repo / "src/main.rs"
            source.write_text('fn main() { println!("{} {}", '
                              'env!("NAOME_LAB_SOURCE_TREE"), env!("NAOME_LAB_SOURCE_CLEAN")); }\n')
            original = source.read_bytes()
            # Non-racy fixture timestamps keep Git's status observation from
            # refreshing the index and independently invalidating Cargo.
            previous_minute = time.time() - 60
            for path in repo.rglob("*"):
                if path.is_file():
                    os.utime(path, (previous_minute, previous_minute))

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=repo, text=True,
                                               stderr=subprocess.STDOUT, timeout=10)

            git("init", "--quiet")
            git("config", "core.excludesFile", "/dev/null")
            git("add", ".")
            git("-c", "user.name=Build identity control", "-c", "user.email=control@example.invalid",
                "-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null",
                "commit", "--quiet", "-m", "Freeze cached build control")
            # Match a populated repository's existing packed and loose refs;
            # missing metadata otherwise adds a broad directory watch.
            git("pack-refs", "--all", "--no-prune")
            tree = git("rev-parse", "HEAD^{tree}").strip()
            cargo = ["rustup", "run", pin, "cargo", "build", "-vv", "--color", "never",
                     "--offline", "--locked",
                     "--manifest-path", str(repo / "Cargo.toml"),
                     "--target-dir", str(repo / "target")]

            def build(stage):
                result = runner.run_stage(cargo, directory, stage, 30)
                self.assertEqual(result["exit_code"], 0,
                                 (directory / (stage + ".log")).read_text())
                self.assertIsNone(result["failure"])
                self.assertTrue(result["owned_group_empty"])
                identity = subprocess.check_output(
                    [str(repo / "target/debug/build-identity-control")], text=True, timeout=5).split()
                (directory / (stage + "-identity.json")).write_text(json.dumps(identity) + "\n")
                return identity

            transient = repo / "outside-crate/transient.rs"
            transient.parent.mkdir()
            transient.write_text("untracked control\n")
            self.assertEqual(build("untracked-build"), [tree, "false"])
            # Settle a newly initialized Git index before observing Cargo's
            # cached state; its first refresh can otherwise cause a rebuild.
            self.assertEqual(build("dirty-cache-warmup"), [tree, "false"])
            self.assertEqual(build("dirty-cache-confirm"), [tree, "false"])
            self.assertIn("Fresh build-identity-control",
                          (directory / "dirty-cache-confirm.log").read_text())
            transient.unlink()
            self.assertEqual(git("--no-optional-locks", "status", "--porcelain",
                                 "--untracked-files=all"), "")
            self.assertEqual(build("cached-untracked-removal"), [tree, "true"])
            source.write_bytes(original + b"// Tracked source mutation control.\n")
            self.assertEqual(build("tracked-edit"), [tree, "false"])
            source.write_bytes(original)
            self.assertEqual(build("cached-tracked-restore"), [tree, "true"])


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
    def setUp(self):
        for attribute, value in [("platform", "control platform"),
                                 ("machine", "control machine"),
                                 ("processor", "control processor")]:
            patch = mock.patch.object(runner.platform, attribute, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)

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
            if command == ["sysctl", "-n", "machdep.cpu.brand_string"]:
                return "control CPU\n"
            if command[-1] == "--identity":
                return json.dumps({"schema": 1, "compiler": f"rustc {pin} (control)",
                                   "source_tree": "a" * 40, "source_clean": True, **identity})
            raise AssertionError(command)
        return output

    def test_same_compiler_stale_or_dirty_binary_rejected_before_run_directory(self):
        for identity in [{"source_tree": "c" * 40}, {"source_clean": False}]:
            with self.subTest(identity=identity), tempfile.TemporaryDirectory() as name:
                directory = Path(name) / "new-attempt"
                (Path(name) / "binary").write_bytes(b"binary control")
                (Path(name) / "config.json").write_bytes(b"config control")
                args = ["runner", "--binary", str(Path(name) / "binary"),
                        "--config", str(Path(name) / "config.json"),
                        "--directory", str(directory)]
                with (mock.patch.object(sys, "argv", args),
                      mock.patch.object(runner.subprocess, "check_output",
                                        side_effect=self.command_outputs(identity)) as checks,
                      mock.patch.object(runner.subprocess, "run") as validation,
                      mock.patch.object(runner, "run_stage") as stage):
                    with self.assertRaisesRegex(RuntimeError, "current clean source tree"):
                        runner.main()
                self.assertFalse(directory.exists())
                validation.assert_not_called()
                stage.assert_not_called()
                checked = next(call.args[0][0] for call in checks.call_args_list
                               if call.args[0][-1] == "--identity")
                self.assertFalse(Path(checked).parent.exists())

    def test_rust_config_rejection_precedes_any_output_or_stage(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name) / "invalid-attempt"
            binary = Path(name) / "binary"
            config = Path(name) / "config.json"
            binary.write_bytes(b"binary control")
            config.write_bytes(b"config control")
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
            validation.assert_called_once()
            checked = validation.call_args.args[0]
            self.assertEqual(checked[1], "--validate-config")
            self.assertNotEqual(Path(checked[0]), binary.resolve())
            self.assertNotEqual(Path(checked[2]), config.resolve())
            self.assertFalse(Path(checked[0]).parent.exists())
            self.assertFalse(directory.exists())
            stage.assert_not_called()

    def stage_result(self, command, directory, stage, *_args):
        return {"stage": stage, "command": command, "seconds": 0,
                "failure": None, "termination_signal": None, "exit_code": 0,
                "owned_group_empty": True, "artifact_bytes": runner.output_size(directory)}

    def test_replaced_source_paths_do_not_change_verified_stage_snapshots(self):
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "binary"
            config = Path(name) / "config.json"
            directory = Path(name) / "attempt"
            binary.write_bytes(b"verified binary")
            config.write_bytes(b"verified config")
            temporary = []

            def validate(command, **_kwargs):
                temporary.append(Path(command[0]).parent)
                self.assertEqual(Path(command[0]).read_bytes(), b"verified binary")
                self.assertEqual(Path(command[2]).read_bytes(), b"verified config")

            def stage(command, *args):
                binary.write_bytes(b"replaced binary")
                config.write_bytes(b"replaced config")
                self.assertEqual(Path(command[0]).read_bytes(), b"verified binary")
                self.assertEqual(Path(command[2]).read_bytes(), b"verified config")
                self.assertEqual(Path(command[0]).stat().st_mode & 0o777, 0o555)
                self.assertEqual(Path(command[2]).stat().st_mode & 0o777, 0o444)
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                return self.stage_result(command, *args)

            argv = ["runner", "--binary", str(binary), "--config", str(config),
                    "--directory", str(directory)]
            with (mock.patch.object(sys, "argv", argv),
                  mock.patch.object(runner.subprocess, "check_output", side_effect=self.command_outputs({})),
                  mock.patch.object(runner.subprocess, "run", side_effect=validate),
                  mock.patch.object(runner, "run_stage", side_effect=stage) as stages):
                self.assertEqual(runner.main(), 0)
            self.assertEqual(stages.call_count, 5)
            self.assertTrue(temporary)
            self.assertTrue(all(not path.exists() for path in temporary))
            receipt = json.loads((directory / "execution.json").read_text())
            self.assertEqual(receipt["binary_sha256"], runner.sha256(directory / "input-binary"))
            self.assertEqual(receipt["config_sha256"], runner.sha256(directory / "input-config.json"))
            self.assertEqual(receipt["input_snapshots"]["source_binary_path"], str(binary.resolve()))
            manifest = json.loads((directory / "manifest.json").read_text())
            self.assertIn("input-binary", manifest)
            self.assertIn("input-config.json", manifest)

    def test_changed_retained_snapshot_vetoes_the_next_stage(self):
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "binary"
            config = Path(name) / "config.json"
            directory = Path(name) / "attempt"
            binary.write_bytes(b"verified binary")
            config.write_bytes(b"verified config")

            def stage(command, *args):
                retained_config = Path(command[2])
                retained_config.chmod(0o644)
                retained_config.write_bytes(b"changed retained config")
                return self.stage_result(command, *args)

            argv = ["runner", "--binary", str(binary), "--config", str(config),
                    "--directory", str(directory)]
            with (mock.patch.object(sys, "argv", argv),
                  mock.patch.object(runner.subprocess, "check_output", side_effect=self.command_outputs({})),
                  mock.patch.object(runner.subprocess, "run"),
                  mock.patch.object(runner, "run_stage", side_effect=stage) as stages):
                with self.assertRaisesRegex(RuntimeError, "snapshot changed before stage launch"):
                    runner.main()
            self.assertEqual(stages.call_count, 1)
            self.assertFalse((directory / "manifest.json").exists())
            self.assertEqual(len(json.loads((directory / "execution.json").read_text())["runs"]), 1)

    def test_snapshot_copy_failure_cleans_private_preflight_storage(self):
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "binary"
            config = Path(name) / "config.json"
            binary.write_bytes(b"verified binary")
            config.write_bytes(b"verified config")
            copy = runner.shutil.copyfile
            temporary = []

            def fail_config_copy(source, destination):
                temporary.append(destination.parent)
                if source == config:
                    raise OSError("injected config copy failure")
                return copy(source, destination)

            with mock.patch.object(runner.shutil, "copyfile", side_effect=fail_config_copy):
                with self.assertRaisesRegex(OSError, "injected config copy failure"):
                    with runner.snapshot_inputs(binary, config):
                        self.fail("copy failure must stop before yielding inputs")
            self.assertTrue(temporary)
            self.assertTrue(all(not path.exists() for path in temporary))

    def test_stage_exception_retains_checked_inputs_after_preflight_cleanup(self):
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "binary"
            config = Path(name) / "config.json"
            directory = Path(name) / "attempt"
            binary.write_bytes(b"verified binary")
            config.write_bytes(b"verified config")
            temporary = []

            def validate(command, **_kwargs):
                temporary.append(Path(command[0]).parent)

            argv = ["runner", "--binary", str(binary), "--config", str(config),
                    "--directory", str(directory)]
            with (mock.patch.object(sys, "argv", argv),
                  mock.patch.object(runner.subprocess, "check_output", side_effect=self.command_outputs({})),
                  mock.patch.object(runner.subprocess, "run", side_effect=validate),
                  mock.patch.object(runner, "run_stage", side_effect=OSError("injected stage failure"))):
                with self.assertRaisesRegex(OSError, "injected stage failure"):
                    runner.main()
            self.assertEqual((directory / "input-binary").read_bytes(), b"verified binary")
            self.assertEqual((directory / "input-config.json").read_bytes(), b"verified config")
            self.assertTrue(all(not path.exists() for path in temporary))

    def test_one_sigterm_during_preflight_cleans_inputs_and_restores_handlers(self):
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "binary"
            config = Path(name) / "config.json"
            directory = Path(name) / "attempt"
            binary.write_bytes(b"verified binary")
            config.write_bytes(b"verified config")
            previous = {signum: signal.getsignal(signum)
                        for signum in [signal.SIGTERM, signal.SIGINT]}
            temporary = []

            def validate(command, **_kwargs):
                temporary.append(Path(command[0]).parent)
                os.kill(os.getpid(), signal.SIGTERM)

            argv = ["runner", "--binary", str(binary), "--config", str(config),
                    "--directory", str(directory)]
            with (mock.patch.object(sys, "argv", argv),
                  mock.patch.object(runner.subprocess, "check_output",
                                    side_effect=self.command_outputs({})),
                  mock.patch.object(runner.subprocess, "run", side_effect=validate),
                  mock.patch.object(runner, "run_stage") as stages):
                with self.assertRaisesRegex(RuntimeError, "SIGTERM.*input preflight"):
                    runner.main()
            self.assertFalse(directory.exists())
            self.assertTrue(temporary)
            self.assertTrue(all(not path.exists() for path in temporary))
            stages.assert_not_called()
            for signum, handler in previous.items():
                self.assertEqual(signal.getsignal(signum), handler)

    def test_failed_second_input_transfer_cleans_partial_attempt_and_preflight(self):
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "binary"
            config = Path(name) / "config.json"
            directory = Path(name) / "attempt"
            binary.write_bytes(b"verified binary")
            config.write_bytes(b"verified config")
            move = runner.shutil.move
            temporary = []

            def transfer(source, destination):
                temporary.append(Path(source).parent)
                if Path(destination).name == "input-config.json":
                    raise OSError("injected second transfer failure")
                return move(source, destination)

            argv = ["runner", "--binary", str(binary), "--config", str(config),
                    "--directory", str(directory)]
            with (mock.patch.object(sys, "argv", argv),
                  mock.patch.object(runner.subprocess, "check_output",
                                    side_effect=self.command_outputs({})),
                  mock.patch.object(runner.subprocess, "run"),
                  mock.patch.object(runner.shutil, "move", side_effect=transfer),
                  mock.patch.object(runner, "run_stage") as stages):
                with self.assertRaisesRegex(OSError, "injected second transfer failure"):
                    runner.main()
            self.assertEqual(len(temporary), 2)
            self.assertTrue(all(not path.exists() for path in temporary))
            self.assertFalse(directory.exists())
            stages.assert_not_called()

    def test_sigterm_during_preflight_temporary_cleanup_vetoes_stage_launch(self):
        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / "binary"
            config = Path(name) / "config.json"
            directory = Path(name) / "attempt"
            binary.write_bytes(b"verified binary")
            config.write_bytes(b"verified config")
            cleanup = tempfile.TemporaryDirectory.cleanup
            temporary = []
            previous = signal.getsignal(signal.SIGTERM)

            def stop_during_cleanup(instance):
                temporary.append(Path(instance.name))
                os.kill(os.getpid(), signal.SIGTERM)
                cleanup(instance)

            argv = ["runner", "--binary", str(binary), "--config", str(config),
                    "--directory", str(directory)]
            with (mock.patch.object(sys, "argv", argv),
                  mock.patch.object(runner.subprocess, "check_output",
                                    side_effect=self.command_outputs({})),
                  mock.patch.object(runner.subprocess, "run"),
                  mock.patch.object(tempfile.TemporaryDirectory, "cleanup",
                                    new=stop_during_cleanup),
                  mock.patch.object(runner, "run_stage", side_effect=self.stage_result) as stages):
                with self.assertRaisesRegex(RuntimeError, "SIGTERM.*input preflight"):
                    runner.main()
            self.assertFalse(directory.exists())
            self.assertEqual(len(temporary), 1)
            self.assertTrue(all(not path.exists() for path in temporary))
            self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
            stages.assert_not_called()


if __name__ == "__main__":
    unittest.main()
