"""Canonical devnet oracles and ownership boundaries."""
import json
import os
import signal
import subprocess
import sys
import threading
import socket
from proxy import Proxy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from state_backend import Backend
from state_qualify import Qualification, atomic


class CanonicalQualification(unittest.TestCase):
    def qualification(self):
        q = object.__new__(Qualification)
        q.args = SimpleNamespace(backend='process', height_timeout=10)
        q.backend = Mock()
        q.backend.alive.return_value = True
        q.backend.resources.return_value = {'disk_bytes': 1, 'memory_bytes': 1}
        q.latest, q.resources = {}, {}
        q.report = {'limits': {'sampled_role_disk_bytes': 100, 'container_memory_bytes': 100}, 'faults': []}
        q.isolated = None
        return q

    @staticmethod
    def state(height=3, head='head'):
        return {'status': 'finalized', 'height': height, 'head': head, 'state': 'state', 'library_root': 'library'}

    def test_equal_height_conflict_and_restart_regression_fail(self):
        q = self.qualification()
        q.backend.cli.side_effect = [self.state(), self.state(head='conflicting')]
        with self.assertRaisesRegex(RuntimeError, 'disagree'):
            q.observe([0, 1])
        q.backend.cli.side_effect = [self.state(height=2)]
        with self.assertRaisesRegex(RuntimeError, 'regressed'):
            q.observe([0])

    def test_missing_initial_status_is_retryable_but_exited_process_is_not(self):
        q = self.qualification()
        q.backend.cli.return_value = None
        self.assertEqual(q.observe([0], starting=True), {})
        q.backend.alive.return_value = False
        with self.assertRaisesRegex(RuntimeError, 'exited'):
            q.observe([0], starting=True)

    def test_outage_heals_on_deadline_without_new_finality(self):
        q = self.qualification()
        q.isolated = (3, self.state(), 20)
        q.backend.cli.side_effect = [self.state(), self.state(height=4), self.state(height=4), self.state(height=4)]
        with patch('state_qualify.time.monotonic', return_value=21):
            q.service_fault()
        self.assertIsNone(q.isolated)
        q.backend.heal.assert_called_once_with(3)
        self.assertEqual(q.report['faults'][0]['operation'], 'partition_healed_on_deadline')

    def test_healing_still_occurs_but_missing_outage_progress_fails(self):
        q = self.qualification()
        q.isolated = (3, self.state(), 20)
        q.backend.cli.return_value = self.state()
        with patch('state_qualify.time.monotonic', return_value=21):
            with self.assertRaisesRegex(RuntimeError, 'no progress'):
                q.service_fault()
        q.backend.heal.assert_called_once_with(3)
        self.assertIsNone(q.isolated)

    def test_isolated_progress_and_resource_overflow_fail(self):
        q = self.qualification()
        q.isolated = (3, self.state(), 20)
        q.backend.cli.return_value = self.state(height=4)
        with patch('state_qualify.time.monotonic', return_value=21):
            with self.assertRaisesRegex(RuntimeError, 'isolated validator advanced'):
                q.service_fault()
        q.backend.heal.assert_not_called()
        q.backend.resources.return_value = {'disk_bytes': 101, 'memory_bytes': 1}
        with self.assertRaisesRegex(RuntimeError, 'disk cap'):
            q.observe([0])

    def test_atomic_reports_reject_pending_symlink_and_sync_file_and_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'untouched'
            original.write_bytes(b'keep')
            (root / 'report.pending').symlink_to(original)
            with self.assertRaises(OSError):
                atomic(root / 'report.json', {'ok': True})
            self.assertEqual(original.read_bytes(), b'keep')
            (root / 'report.pending').unlink()
            with patch('state_qualify.os.fsync', wraps=os.fsync) as sync:
                atomic(root / 'report.json', {'ok': True})
                self.assertEqual(sync.call_count, 2)
            self.assertTrue(json.loads((root / 'report.json').read_text())['ok'])

    def test_parallel_status_probes_preserve_every_failure(self):
        q = self.qualification()
        gate = threading.Barrier(4)
        failing = set()
        def status(index, *args, **kwargs):
            gate.wait(timeout=3)
            if index in failing:
                raise RuntimeError('failed node')
            return self.state()
        q.backend.cli.side_effect = status
        self.assertEqual(list(q.observe(range(4))), [0, 1, 2, 3])
        failing.add(3)
        with self.assertRaisesRegex(RuntimeError, 'failed node'):
            q.observe(range(4))

    def test_dead_wrapper_cleanup_stops_descendants(self):
        import select
        parent = subprocess.Popen([sys.executable, '-c',
            "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);print('ready',flush=True);time.sleep(30)"],
            stdout=subprocess.PIPE, start_new_session=True)
        backend = object.__new__(Backend)
        backend.args = SimpleNamespace(backend='process')
        backend.children = {0: parent}
        backend.logs = {0: open(os.devnull, 'w')}
        try:
            self.assertTrue(select.select([parent.stdout], [], [], 3)[0])
            self.assertEqual(parent.stdout.readline(), b'ready\n')
            parent.kill()
            parent.wait(timeout=3)
            with self.assertRaisesRegex(RuntimeError, 'stop cleanly'):
                backend.stop(0)
            self.assertTrue(select.select([parent.stdout], [], [], 3)[0])
            self.assertEqual(parent.stdout.read(), b'')
            self.assertFalse(backend.children)
        finally:
            try:
                os.killpg(parent.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            parent.wait(timeout=3)
            parent.stdout.close()
            for log in backend.logs.values():
                log.close()

    def test_cleanup_attempts_all_owned_processes_even_after_one_error(self):
        backend = object.__new__(Backend)
        backend.args = SimpleNamespace(backend='process')
        backend.children = {0: None, 1: None}
        backend.stop = Mock(side_effect=[RuntimeError('first failed'), None])
        with self.assertRaisesRegex(RuntimeError, 'first failed'):
            backend.cleanup()
        self.assertEqual(backend.stop.call_count, 2)

    def test_probe_timeout_is_cleaned_and_removal_failure_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = SimpleNamespace(backend='docker', subnet='172.30.88.0/24', image='fixture', bin_dir=Path(tmp), delay_ms=50)
            backend = Backend(args, Path(tmp))
            with patch('state_backend.command', side_effect=[SimpleNamespace(stdout='[{"Id":"image"}]'), subprocess.TimeoutExpired('docker', 60), SimpleNamespace(stdout='')]) as run:
                with self.assertRaises(subprocess.TimeoutExpired):
                    backend.prepare_containers()
                self.assertEqual(run.call_args_list[-1].args[0][:3], ['docker', 'rm', '--force'])
            with patch('state_backend.command', side_effect=[SimpleNamespace(stdout='[{"Id":"image"}]'), SimpleNamespace(stdout='{}'), RuntimeError('removal unconfirmed')]):
                with self.assertRaisesRegex(RuntimeError, 'removal unconfirmed'):
                    backend.prepare_containers()

    def test_containers_receive_only_own_node_anchors_and_public_genesis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = SimpleNamespace(backend='docker', subnet='172.30.88.0/24', image='fixture', bin_dir=root, delay_ms=50)
            for name in ('naome', 'naome-validator', 'naome-verifier'):
                (root / name).write_bytes(b'fixture')
            backend = Backend(args, root)
            backend.compose = Mock(return_value='container-id')
            import hashlib
            hashes = {name: hashlib.sha256(b'fixture').hexdigest() for name in ('naome', 'naome-validator', 'naome-verifier')}
            with patch('state_backend.command', side_effect=[SimpleNamespace(stdout='[{"Id":"immutable-image"}]'), SimpleNamespace(stdout=json.dumps(hashes)), SimpleNamespace(stdout='')]):
                backend.prepare_containers()
            manifest = json.loads(backend.compose_file.read_text())
            self.assertTrue(manifest['networks']['devnet']['internal'])
            for index in range(4):
                service = manifest['services'][f'validator-{index}']
                self.assertEqual({v['source'] for v in service['volumes']},
                    {str(root / 'run' / f'node-{index}'), str(root / 'anchors' / str(index)), str(root / 'run/genesis.bin')})
                self.assertEqual([v['read_only'] for v in service['volumes']], [False, False, True])
                self.assertEqual(service['cap_drop'], ['ALL'])
                self.assertEqual(service['mem_limit'], '512m')
                self.assertNotIn('ports', service)


class DelayedTransport(unittest.TestCase):
    def test_delayed_proxy_transfers_exact_bytes_and_releases_listener(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        holder.close()
        finished = threading.Event()

        def echo():
            with listener.accept()[0] as connection:
                connection.settimeout(3)
                while True:
                    data = connection.recv(8192)
                    if not data:
                        break
                    connection.sendall(data)
            finished.set()

        worker = threading.Thread(target=echo, daemon=True)
        worker.start()
        proxy = Proxy(f"/ip4/127.0.0.1/tcp/{port}", f"/ip4/127.0.0.1/tcp/{listener.getsockname()[1]}", 10)
        try:
            payload = bytes(range(256)) * 512
            with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                connection.sendall(payload)
                received = b""
                while len(received) < len(payload):
                    chunk = connection.recv(8192)
                    self.assertTrue(chunk)
                    received += chunk
                self.assertEqual(received, payload)
            self.assertTrue(finished.wait(3))
        finally:
            proxy.close()
            listener.close()
            worker.join(timeout=3)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)


if __name__ == '__main__':
    unittest.main()
