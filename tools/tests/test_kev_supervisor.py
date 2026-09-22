"""Real child-process lifecycle qualification; no Torch imports or GPU calls."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from naome_kev import config, runtime, worker


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kev-sup-', dir='/tmp')
        self.root = Path(self.temp.name)
        config.configure(self.root / 'run')
        self.root = self.root / 'run'
        config._create(self.root / 'manifest.json', json.dumps({
            'source_revision': runtime.SOURCE_REVISION, 'model': config.MODEL}).encode())
        self.thread = None
        self.supervisor = None
        self.pid = None
        self.errors = []

    def tearDown(self):
        if self.supervisor is not None and self.supervisor.poll() is None:
            runtime._terminate_owned(self.supervisor)
        if self.thread is not None and self.thread.is_alive():
            try:
                runtime._rpc(self.root, {'command': 'stop'}, 1)
            except (OSError, ValueError):
                pass
            self.thread.join(4)
            self.assertFalse(self.thread.is_alive(), 'supervisor leaked')
        if self.pid is not None:
            with self.assertRaises(ProcessLookupError):
                os.kill(self.pid, 0)
        self.assertFalse(self.errors)
        self.temp.cleanup()

    def command(self, mode):
        status = {'model': config.MODEL, 'fingerprint': runtime._fingerprint(self.root),
                  'calls': 0, 'device': 'fixture'}
        script = '''import json,os,signal,sys,time
status=json.loads(sys.argv[1]); mode=sys.argv[2]
def send(value): print(json.dumps(value),flush=True)
if mode == 'hang_load':
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 time.sleep(30)
if mode == 'failed_load':
 send({'event':'failed'}); sys.exit(1)
if mode == 'exit_load': sys.exit(7)
send({'event':'ready','status':status})
for line in sys.stdin:
 message=json.loads(line)
 if mode == 'exit_infer': sys.exit(9)
 if mode == 'hang_infer':
  signal.signal(signal.SIGTERM,signal.SIG_IGN)
  time.sleep(30)
 status['calls']+=1
 send({'event':'result','request':message['request'],
       'response':{'order':list(message['payload'])},'status':status})
'''
        return [sys.executable, '-u', '-c', script, json.dumps(status), mode]

    def start(self, mode, startup=2):
        command = self.command(mode)
        def run():
            try:
                worker.serve(self.root, startup, child_command=command)
            except BaseException as error:
                self.errors.append(error)
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        value = self.wait(lambda: self.status())
        self.pid = value['pid']
        return value

    def status(self):
        try:
            return runtime._rpc(self.root, {'command': 'status'}, .5)
        except (OSError, ValueError):
            return None

    def wait(self, predicate, timeout=4):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            time.sleep(.01)
        self.fail('fixture condition timed out')

    def state(self, name):
        value = self.status()
        return value if value and value['state'] == name else None

    def infer(self, seconds=1):
        return runtime._rpc(self.root, {'command': 'infer', 'budget_seconds': seconds,
                                       'payload': {'Z': 'last', 'A': 'first'}}, seconds + 1)

    def test_socket_is_responsive_and_stop_reaps_hung_loader(self):
        self.start('hang_load')
        self.assertEqual(self.status()['state'], 'starting')
        self.assertTrue(runtime._lock_held(self.root, 'daemon.lock'))
        started = time.monotonic()
        self.assertEqual(runtime._rpc(self.root, {'command': 'stop'}, 1)['state'], 'stopping')
        self.thread.join(3)
        self.assertFalse(self.thread.is_alive())
        self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(runtime._lock_held(self.root, 'daemon.lock'))
        self.assertFalse((self.root / 'worker.sock').exists())

    def test_startup_watchdog_reaps_hung_loader(self):
        self.start('hang_load', startup=.15)
        state = self.wait(lambda: self.state('failed'))
        self.assertEqual(state['error_code'], 'model_startup_timeout')
        self.wait(lambda: not self.child_exists())

    def child_exists(self):
        try:
            os.kill(self.pid, 0)
            return True
        except ProcessLookupError:
            return False

    def test_failed_and_abrupt_loads_are_observable(self):
        self.start('failed_load')
        state = self.wait(lambda: self.state('failed'))
        self.assertIn(state['error_code'], ('model_load_failed', 'model_process_exited'))
        self.wait(lambda: not self.child_exists())

    def test_unexpected_child_exit_during_load_is_observable(self):
        self.start('exit_load')
        state = self.wait(lambda: self.state('failed'))
        self.assertEqual(state['error_code'], 'model_process_exited')
        self.wait(lambda: not self.child_exists())

    def test_one_child_serves_multiple_requests_and_preserves_order(self):
        self.start('ready')
        before = self.wait(lambda: self.state('ready'))
        self.assertEqual(self.infer()['order'], ['Z', 'A'])
        self.assertEqual(self.infer()['order'], ['Z', 'A'])
        after = self.status()
        self.assertEqual(before['pid'], after['pid'])
        self.assertEqual(after['calls'], 2)
        self.assertEqual(after['device'], 'fixture')
        self.assertEqual(after['supervisor_pid'], os.getpid())
        self.assertNotEqual(after['supervisor_pid'], after['pid'])

    def test_daemon_ownership_prevents_a_second_model_load(self):
        self.start('ready')
        before = self.wait(lambda: self.state('ready'))
        marker = self.root / 'duplicate-load'
        duplicate = [sys.executable, '-c',
                     'from pathlib import Path; import sys; Path(sys.argv[1]).touch()', str(marker)]
        worker.serve(self.root, 1, child_command=duplicate)
        self.assertFalse(marker.exists())
        self.assertEqual(self.status()['pid'], before['pid'])
        self.assertTrue(runtime._lock_held(self.root, 'daemon.lock'))

    def test_stop_then_restart_has_no_surviving_old_child(self):
        self.start('hang_load')
        old_pid = self.pid
        self.assertTrue(runtime.stop(self.root)['stopped'])
        self.thread.join(1)
        self.assertFalse(self.thread.is_alive())
        with self.assertRaises(ProcessLookupError):
            os.kill(old_pid, 0)
        self.start('ready')
        self.wait(lambda: self.state('ready'))
        self.assertNotEqual(self.pid, old_pid)
        self.assertEqual(self.infer()['order'], ['Z', 'A'])

    def test_termination_signal_reaps_noncooperative_model_child(self):
        script = ('import json,sys; sys.path.insert(0,sys.argv[1]); '
                  'from naome_kev.worker import serve; '
                  'serve(sys.argv[2],10,child_command=json.loads(sys.argv[3]))')
        self.supervisor = subprocess.Popen(
            [sys.executable, '-c', script, str(Path(__file__).resolve().parents[1]),
             str(self.root), json.dumps(self.command('hang_load'))],
            stdin=subprocess.DEVNULL, start_new_session=True)
        state = self.wait(lambda: self.state('starting'))
        self.pid = state['pid']
        self.assertEqual(state['supervisor_pid'], self.supervisor.pid)
        self.supervisor.send_signal(signal.SIGTERM)
        self.assertEqual(self.supervisor.wait(timeout=4), 0)
        self.assertFalse(self.child_exists())
        self.assertFalse(runtime._lock_held(self.root, 'daemon.lock'))
        self.assertFalse((self.root / 'worker.sock').exists())

    def test_inference_watchdog_reaps_noncooperative_child(self):
        self.start('hang_infer')
        self.wait(lambda: self.state('ready'))
        with self.assertRaises((OSError, ValueError)):
            self.infer(.15)
        state = self.wait(lambda: self.state('failed'))
        self.assertEqual(state['error_code'], 'model_inference_timeout')
        self.wait(lambda: not self.child_exists())

    def test_unexpected_child_exit_during_inference_fails_request(self):
        self.start('exit_infer')
        self.wait(lambda: self.state('ready'))
        with self.assertRaises(ValueError):
            self.infer()
        self.assertEqual(self.wait(lambda: self.state('failed'))['error_code'], 'model_process_exited')


if __name__ == '__main__':
    unittest.main()
