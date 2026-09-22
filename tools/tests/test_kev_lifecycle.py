"""Operator lifecycle recovery and exact ownership, without model dependencies."""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from naome_kev import config, runtime

SCRIPT = Path(__file__).resolve().parents[1] / 'agenda_agent_kev.py'
spec = importlib.util.spec_from_file_location('kev_lifecycle_cli', SCRIPT)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kev-life-', dir='/tmp')
        self.root = Path(self.temp.name) / 'run'
        config.configure(self.root)
        self.settings = config.load(self.root / 'kev.json')
        config._create(self.root / 'manifest.json', json.dumps({
            'source_revision': runtime.SOURCE_REVISION, 'model': config.MODEL}).encode())
        (self.root / 'venv/bin').mkdir(parents=True)
        (self.root / 'venv/bin/python').touch()
        self.process = None

    def tearDown(self):
        if self.process is not None and self.process.poll() is None:
            runtime._terminate_owned(self.process)
        self.temp.cleanup()

    def owned_start_failure(self, interrupt):
        popen = subprocess.Popen
        def spawn(*_args, **kwargs):
            self.assertTrue(kwargs['start_new_session'])
            self.process = popen([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
            return self.process
        # Interrupt status polling without also interrupting subprocess.wait cleanup.
        status = (patch.object(runtime, '_running', side_effect=[None, None, KeyboardInterrupt()])
                  if interrupt else patch.object(runtime, '_running', return_value=None))
        with status, patch.object(runtime.subprocess, 'Popen', side_effect=spawn):
            if interrupt:
                with self.assertRaises(KeyboardInterrupt):
                    runtime._ensure(self.settings, time.monotonic() + 1)
            else:
                with self.assertRaises(runtime.RuntimeFailure) as result:
                    runtime._ensure(self.settings, time.monotonic() + .15)
                self.assertEqual(result.exception.code, 'startup_timeout')
        self.assertIsNotNone(self.process.poll(), 'owned startup process survived failure')
        with self.assertRaises(ProcessLookupError):
            os.kill(self.process.pid, 0)
        self.assertFalse(runtime._lock_held(self.root, 'start.lock', create=False))

    def test_start_timeout_reaps_only_its_own_process(self):
        self.owned_start_failure(interrupt=False)

    def test_ctrl_c_reaps_only_its_own_process(self):
        self.owned_start_failure(interrupt=True)

    def test_cleanup_kills_descendant_even_when_leader_exits_on_term(self):
        child = ('import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                 'print(os.getpid(),flush=True); time.sleep(30)')
        parent = 'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",sys.argv[1]]); time.sleep(30)'
        self.process = subprocess.Popen([sys.executable, '-c', parent, child],
                                        start_new_session=True, stdout=subprocess.PIPE, text=True)
        descendant = int(self.process.stdout.readline())
        try:
            runtime._terminate_owned(self.process)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(descendant, 0)
                except ProcessLookupError:
                    break
                time.sleep(.02)
            else:
                self.fail('owned descendant survived process-group cleanup')
        finally:
            self.process.stdout.close()
            try:
                os.kill(descendant, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_waiting_for_existing_startup_never_spawns_or_terminates_it(self):
        with patch.object(runtime, '_running', return_value={'state': 'starting'}), \
             patch.object(runtime, '_lock_held', return_value=True), \
             patch.object(runtime.subprocess, 'Popen') as spawn, \
             patch.object(runtime, '_terminate_owned') as terminate, \
             self.assertRaises(runtime.RuntimeFailure):
            runtime._ensure(self.settings, time.monotonic() + .1)
        spawn.assert_not_called()
        terminate.assert_not_called()

    def test_status_neither_loads_nor_creates_files(self):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*'))
        with patch.object(runtime.subprocess, 'Popen') as spawn:
            result = runtime.inspect(self.root)
        self.assertEqual(result['state'], 'stopped')
        spawn.assert_not_called()
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*')))
        absent = self.root / 'missing'
        self.assertEqual(runtime.inspect(absent)['state'], 'not_installed')
        self.assertFalse(absent.exists())

    def test_corrupt_config_cannot_redirect_directory_stop_or_status(self):
        (self.root / 'kev.json').write_text('{"runtime_dir":"missing"}')
        custom = self.root / 'custom.conf'
        custom.write_text('broken configuration')
        custom.chmod(0o600)
        for command, method, answer in (
                ('stop', 'stop', {'stopped': True, 'state': 'stopped'}),
                ('status', 'inspect', {'state': 'needs_repair'})):
            for location in (self.root, self.root / 'kev.json', custom):
                with patch.object(runtime, method, return_value=answer) as operation, \
                     patch.object(sys, 'stdout', io.StringIO()):
                    self.assertEqual(cli.main([command, str(location), '--json']), 0)
                operation.assert_called_once_with(self.root)

    def test_arbitrary_exception_code_is_not_trusted_as_operator_text(self):
        class UntrustedError(Exception):
            code = 403
        output = io.StringIO()
        with patch.object(sys, 'argv', [str(SCRIPT), 'setup', '--json']), \
             patch.object(cli, 'main', side_effect=UntrustedError('private-sentinel')), \
             patch.object(sys, 'stderr', output):
            self.assertEqual(cli.cli(), 1)
        self.assertNotIn('private-sentinel', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['error']['code'], 'invalid_runtime')


if __name__ == '__main__':
    unittest.main()
