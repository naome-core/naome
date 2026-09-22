"""Exercise the real private IPC boundary without downloading or loading a model."""
import json
import fcntl
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from naome_kev import config, runtime, worker


class FakeModel:
    def __init__(self):
        self.inference_lock = threading.Lock()
        self.calls = []
        self.entered = threading.Event()
        self.release = threading.Event()

    def status(self):
        return {'ready': True}

    def infer(self, payload, budget_seconds=2):
        self.calls.append(payload)
        self.entered.set()
        if payload.get('block'):
            self.release.wait(2)
        return {'order': list(payload['options']), 'value': 0.24800000000000003}


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='kev-', dir='/tmp')
        self.root = Path(self.directory.name)
        self.server = worker.Server(str(self.root / 'worker.sock'), worker.Handler)
        self.server.model = FakeModel()
        self.server.stopping = False
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.model.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(1)
        self.directory.cleanup()

    def infer(self, payload):
        return runtime._rpc(self.root, {'command': 'infer', 'payload': payload,
                                       'budget_seconds': 2}, 2)

    def test_wire_preserves_choice_order_and_full_precision(self):
        answer = self.infer({'options': {'Z': 'last', 'A': 'first'}})
        self.assertEqual(answer['order'], ['Z', 'A'])
        self.assertEqual(answer['value'], 0.24800000000000003)
        self.assertEqual(len(self.server.model.calls), 1)

    def test_busy_inference_does_not_block_status_or_start_another_inference(self):
        results = []
        first = threading.Thread(target=lambda: results.append(self.infer({'options': {'A': 'a'}, 'block': True})))
        first.start()
        self.assertTrue(self.server.model.entered.wait(1))
        self.assertEqual(runtime._rpc(self.root, {'command': 'status'}, .2), {'ready': True})
        with self.assertRaises(ValueError):
            self.infer({'options': {'B': 'b'}})
        self.assertEqual(len(self.server.model.calls), 1)
        self.server.model.release.set()
        first.join(1)
        self.assertEqual(len(results), 1)

    def test_expired_request_never_enters_model(self):
        with self.assertRaises(ValueError):
            runtime._rpc(self.root, {'command': 'infer', 'payload': {'options': {}},
                                      'budget_seconds': 0}, .5)
        self.assertEqual(self.server.model.calls, [])

    def test_oversized_request_never_enters_model(self):
        with self.assertRaises(ValueError):
            self.infer({'options': {'A': 'x' * runtime.MAX_FRAME}})
        self.assertEqual(self.server.model.calls, [])

    def test_symlink_or_shared_runtime_is_rejected(self):
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            runtime._directory(link)
        os.chmod(self.root, 0o755)
        with self.assertRaises(ValueError):
            runtime._directory(self.root)
        os.chmod(self.root, 0o700)


class TotalDeadlineTest(unittest.TestCase):
    def test_stop_holds_startup_lock_while_inspecting_daemon_ownership(self):
        with tempfile.TemporaryDirectory(prefix='kev-', dir='/tmp') as directory:
            root = Path(directory)
            (root / 'start.lock').touch(mode=0o600)
            original = runtime._lock_held
            observations = []

            def inspect(path, name, **kwargs):
                self.assertEqual(name, 'daemon.lock')
                observations.append(original(path, 'start.lock'))
                return original(path, name, **kwargs)

            with patch.object(runtime, '_lock_held', side_effect=inspect):
                self.assertTrue(runtime.stop(config.default(root))['stopped'])
            self.assertEqual(observations, [True])

    def test_stop_does_not_claim_success_while_worker_is_still_loading(self):
        with tempfile.TemporaryDirectory(prefix='kev-', dir='/tmp') as directory:
            root = Path(directory)
            with (root / 'daemon.lock').open('wb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                with patch.object(runtime, 'STOP_SECONDS', .1):
                    result = runtime.stop(config.default(root))
                self.assertFalse(result['stopped'])
            self.assertTrue(runtime.stop(config.default(root))['stopped'])

    def test_trickled_response_cannot_reset_total_socket_deadline(self):
        with tempfile.TemporaryDirectory(prefix='kev-', dir='/tmp') as directory:
            root = Path(directory)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(root / 'worker.sock'))
            listener.listen(1)

            def trickle():
                stream, _ = listener.accept()
                with stream:
                    stream.recv(1024)
                    for byte in b'{"result":true}\n':
                        try:
                            stream.sendall(bytes([byte]))
                        except OSError:
                            break
                        time.sleep(.04)

            thread = threading.Thread(target=trickle, daemon=True)
            thread.start()
            started = time.monotonic()
            try:
                with self.assertRaises((TimeoutError, socket.timeout)):
                    runtime._rpc(root, {'command': 'status'}, .15)
                self.assertLess(time.monotonic() - started, .4)
            finally:
                thread.join(1)
                listener.close()


if __name__ == '__main__':
    unittest.main()
