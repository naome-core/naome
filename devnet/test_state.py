"""Canonical devnet oracles and ownership boundaries."""
import asyncio
import json
import os
import signal
import struct
import subprocess
import sys
import threading
import time
import socket
from proxy import Proxy, copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from state_backend import Backend, MAX_PROBE_RESPONSE, STATUS_MEMORY, StatusProbe
from state_qualify import Qualification, atomic


class StatusSocket:
    """Serve actual framed control requests to a local persistent probe."""
    def __init__(self, path, responses):
        self.responses = responses
        self.requests = []
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen()
        self.listener.settimeout(3)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    @staticmethod
    def exact(connection, size):
        result = bytearray()
        while len(result) < size:
            part = connection.recv(size - len(result))
            if not part:
                raise RuntimeError('short test control request')
            result.extend(part)
        return bytes(result)

    def serve(self):
        try:
            for response in self.responses:
                with self.listener.accept()[0] as connection:
                    size = struct.unpack('>I', self.exact(connection, 4))[0]
                    self.requests.append(json.loads(self.exact(connection, size)))
                    connection.sendall(response())
        finally:
            self.listener.close()

    def join(self):
        self.thread.join(timeout=4)
        if self.thread.is_alive():
            raise AssertionError('control test server did not finish')


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

    def test_partition_requires_four_converged_available_signers(self):
        values = {i: {**self.state(), 'authority': {'active_slots': 4},
                      'consensus_position': {'height': 4}} for i in range(4)}
        self.assertTrue(Qualification.partition_ready(values))
        values[0]['authority']['active_slots'] = 3
        self.assertFalse(Qualification.partition_ready(values))
        values[0]['authority']['active_slots'] = 4
        values[0]['consensus_position'] = None
        self.assertFalse(Qualification.partition_ready(values))
        values[0]['consensus_position'] = {'height': 4}
        values[0]['head'] = 'another'
        self.assertFalse(Qualification.partition_ready(values))

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

    @staticmethod
    def voting(height, head, operation='operation', deadline=101):
        return {**CanonicalQualification.state(height, head), 'time': 100,
                'active': {'submission': operation, 'attempt': 1,
                           'phase': 'Voting', 'deadline': deadline}}

    def test_staggered_exact_voting_observations_satisfy_window(self):
        q = self.qualification()
        q.deadline = 100
        q.save = Mock()
        first = self.voting(4, 'opening', deadline=115)
        second = self.voting(5, 'later', deadline=115)
        second['time'] = 101
        q.observe = Mock(side_effect=[{0: first, 1: {**self.state(), 'active': None}},
                                      {0: {**self.state(height=5), 'active': None}, 1: second}])
        with patch('state_qualify.time.monotonic', return_value=0), \
             patch('state_qualify.time.sleep'):
            observed = q.wait_voting_window([0, 1], 'operation')
        self.assertIs(observed[0], first)
        self.assertIs(observed[1], second)
        self.assertNotIn('wait_timeout', q.report)
        q.save.assert_not_called()

    def test_voting_timeout_retains_public_observations_and_receipt_status(self):
        q = self.qualification()
        q.deadline = 100
        q.args.height_timeout = 1
        q.current_attempt = {'number': 29, 'owner': 1, 'operation': 'operation',
                             'checkpoint': 'await_voting'}
        q.save = Mock()
        first = self.voting(4, 'opening')
        first['validators'] = [{'index': 0, 'slot': 'slot', 'unit': 'unit',
                                'available': True, 'consensus_key': 'secret',
                                'endpoint': '/private/config'}]
        wrong = self.voting(4, 'opening', operation='other-operation')
        q.observe = Mock(return_value={0: first, 1: wrong})
        q.latest = {0: first, 1: wrong}
        q.backend.cli.return_value = {'status': 'pending', 'reason': '/private/log'}
        with patch('state_qualify.time.monotonic', side_effect=[0, 0, 2]), \
             patch('state_qualify.time.sleep'):
            with self.assertRaisesRegex(RuntimeError, 'deadline: full voting window opens'):
                q.wait_voting_window([0, 1], 'operation')
        timeout = q.report['wait_timeout']
        self.assertEqual(timeout['current_attempt']['number'], 29)
        self.assertEqual(timeout['required_indices'], [0, 1])
        self.assertEqual(timeout['missing_indices'], [])
        self.assertEqual(timeout['missing_voting_indices'], [1])
        self.assertEqual(timeout['retained_voting']['0']['height'], 4)
        self.assertEqual(timeout['owner_receipt_status'], 'pending')
        self.assertEqual(timeout['last_known']['1']['active']['submission'], 'other-operation')
        self.assertNotIn('secret', json.dumps(timeout))
        self.assertNotIn('/private/', json.dumps(timeout))
        q.save.assert_called_once()

    def test_missing_node_times_out_and_conflicting_voting_deadline_fails(self):
        q = self.qualification()
        q.deadline = 100
        q.args.height_timeout = 1
        q.save = Mock()
        first = self.voting(4, 'opening')
        q.observe = Mock(return_value={0: first})
        q.latest = {0: first}
        with patch('state_qualify.time.monotonic', side_effect=[0, 0, 2]), \
             patch('state_qualify.time.sleep'):
            with self.assertRaisesRegex(RuntimeError, 'deadline: full voting window opens'):
                q.wait_voting_window([0, 1], 'operation')
        self.assertEqual(q.report['wait_timeout']['missing_indices'], [1])
        self.assertEqual(q.report['wait_timeout']['missing_voting_indices'], [1])

        q = self.qualification()
        q.deadline = 100
        q.observe = Mock(return_value={0: first, 1: self.voting(4, 'opening', deadline=102)})
        with patch('state_qualify.time.monotonic', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'certified voting window disagreement'):
                q.wait_voting_window([0, 1], 'operation')
        self.assertNotIn('wait_timeout', q.report)

    def test_successful_wait_keeps_timeout_report_absent(self):
        q = self.qualification()
        q.deadline = 100
        q.save = Mock()
        q.observe = Mock(return_value={0: self.state()})
        with patch('state_qualify.time.monotonic', return_value=0):
            self.assertEqual(q.wait('ready', [0], lambda values: values[0]['height'] == 3),
                             {0: self.state()})
        self.assertNotIn('wait_timeout', q.report)
        q.save.assert_not_called()

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

    def test_docker_probe_preserves_liveness_and_memory_bounds(self):
        q = self.qualification()
        q.args.backend = 'docker'
        q.backend.status_memory.return_value = (self.state(), 12)
        q.observe([0])
        q.backend.resources.assert_called_once_with(0, memory_bytes=12)
        q.backend.alive.assert_not_called()
        q.backend.status_memory.return_value = None
        q.backend.alive.return_value = False
        with self.assertRaisesRegex(RuntimeError, 'exited'):
            q.observe([0], starting=True)
        q.backend.status_memory.return_value = (self.state(), 101)
        q.backend.resources.return_value = {'disk_bytes': 1, 'memory_bytes': 101}
        with self.assertRaisesRegex(RuntimeError, 'memory cap'):
            q.observe([0])

    def test_docker_status_and_cgroup_use_share_one_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = SimpleNamespace(backend='docker', subnet='172.30.88.0/24')
            backend = Backend(args, Path(tmp))
            backend.containers[0] = 'container-0'
            root = Path(tmp)
            memory = root / 'memory.current'
            memory.write_text('12')
            control = root / 'control.sock'
            backend.config(0).parent.mkdir(parents=True)
            backend.config(0).write_text(json.dumps({'control_socket': str(control)}))
            def frame(status, used):
                def response():
                    memory.write_text(str(used))
                    body = json.dumps(status).encode()
                    return struct.pack('>I', len(body)) + body
                return response
            server = StatusSocket(control, [frame(self.state(height=3), 12),
                                            frame(self.state(height=4), 13)])
            probe = StatusProbe([sys.executable, '-u', '-c', STATUS_MEMORY,
                                 str(backend.config(0)), str(memory)])
            backend.probes[0] = probe
            try:
                self.assertEqual(backend.status_memory(0), (self.state(height=3), 12))
                pid = probe.process.pid
                self.assertEqual(backend.status_memory(0), (self.state(height=4), 13))
                self.assertIs(backend.probes[0], probe)
                self.assertEqual(probe.process.pid, pid)
                self.assertEqual(server.requests, [{'command': 'status'}] * 2)
            finally:
                backend.cleanup()
                server.join()
            self.assertIsNotNone(probe.process.poll())

    def test_docker_probe_creation_uses_one_interactive_exec(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend = Backend(SimpleNamespace(backend='docker', subnet='172.30.88.0/24'), Path(tmp))
            backend.containers[0] = 'container-0'
            fake = Mock()
            fake.request.return_value = (self.state(), 12)
            with patch('state_backend.StatusProbe', return_value=fake) as constructor:
                self.assertEqual(backend.status_memory(0), (self.state(), 12))
                self.assertEqual(backend.status_memory(0), (self.state(), 12))
            constructor.assert_called_once()
            argv = constructor.call_args.args[0]
            self.assertEqual(argv[:4], ['docker', 'exec', '-i', 'container-0'])
            self.assertEqual(argv[4:7], ['python3', '-u', '-c'])
            self.assertEqual(argv[-1], str(backend.config(0)))
            backend.cleanup()

    def test_status_probe_rejects_control_errors_and_oversize_and_resets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = Backend(SimpleNamespace(backend='docker', subnet='172.30.88.0/24'), root)
            backend.containers[0] = 'container-0'
            control = root / 'control.sock'
            memory = root / 'memory.current'
            memory.write_text('17')
            backend.config(0).parent.mkdir(parents=True)
            backend.config(0).write_text(json.dumps({'control_socket': str(control)}))
            error = json.dumps({'error': 'denied'}).encode()
            server = StatusSocket(control, [lambda: struct.pack('>I', len(error)) + error,
                                            lambda: struct.pack('>I', 3 * 1024 * 1024 + 1)])
            try:
                for _ in range(2):
                    probe = StatusProbe([sys.executable, '-u', '-c', STATUS_MEMORY,
                                         str(backend.config(0)), str(memory)])
                    backend.probes[0] = probe
                    self.assertIsNone(backend.status_memory(0, tolerate=True))
                    self.assertNotIn(0, backend.probes)
                    self.assertIsNotNone(probe.process.poll())
                self.assertEqual(server.requests, [{'command': 'status'}] * 2)
            finally:
                backend.cleanup()
                server.join()

    def test_status_probe_early_closed_pipe_retries_without_hiding_hard_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = Backend(SimpleNamespace(backend='docker', subnet='172.30.88.0/24'), root)
            backend.containers[0] = 'container-0'
            def closed_stdin():
                marker = root / 'stdin-closed'
                marker.unlink(missing_ok=True)
                probe = StatusProbe([sys.executable, '-u', '-c',
                    "import os,sys,time;os.close(0);open(sys.argv[1],'w').close();time.sleep(30)",
                    str(marker)])
                deadline = time.monotonic() + 2
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists(), 'test child did not close stdin')
                return probe
            first = closed_stdin()
            backend.probes[0] = first
            self.assertIsNone(backend.status_memory(0, tolerate=True))
            self.assertNotIn(0, backend.probes)
            self.assertIsNotNone(first.process.poll())
            second = closed_stdin()
            backend.probes[0] = second
            with self.assertRaisesRegex(RuntimeError, 'pipe failed'):
                backend.status_memory(0)
            self.assertNotIn(0, backend.probes)
            self.assertIsNotNone(second.process.poll())

            control = root / 'control.sock'
            memory = root / 'memory.current'
            memory.write_text('19')
            backend.config(0).parent.mkdir(parents=True)
            backend.config(0).write_text(json.dumps({'control_socket': str(control)}))
            body = json.dumps(self.state(height=5)).encode()
            server = StatusSocket(control, [lambda: struct.pack('>I', len(body)) + body])
            third = StatusProbe([sys.executable, '-u', '-c', STATUS_MEMORY,
                                 str(backend.config(0)), str(memory)])
            backend.probes[0] = third
            try:
                self.assertEqual(backend.status_memory(0), (self.state(height=5), 19))
                self.assertEqual(server.requests, [{'command': 'status'}])
            finally:
                backend.cleanup()
                server.join()
            self.assertIsNotNone(third.process.poll())

    def test_status_probe_bounds_pipe_response_and_timeout(self):
        oversized = StatusProbe([sys.executable, '-u', '-c',
            "import struct,sys;sys.stdin.buffer.readline();sys.stdout.buffer.write(struct.pack('>I',int(sys.argv[1])));sys.stdout.buffer.flush();sys.stdin.buffer.read()",
            str(MAX_PROBE_RESPONSE + 1)])
        with self.assertRaisesRegex(RuntimeError, 'oversized'):
            oversized.request(timeout=2)
        self.assertTrue(oversized.closed)
        self.assertIsNotNone(oversized.process.poll())
        stalled = StatusProbe([sys.executable, '-u', '-c',
            'import sys,time;sys.stdin.buffer.readline();time.sleep(30)'])
        with self.assertRaisesRegex(TimeoutError, 'timed out'):
            stalled.request(timeout=0.1)
        self.assertTrue(stalled.closed)
        self.assertIsNotNone(stalled.process.poll())

    def test_status_probe_closes_on_restart_stop_and_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend = Backend(SimpleNamespace(backend='docker', subnet='172.30.88.0/24'), Path(tmp))
            backend.containers[0] = 'container-0'
            def idle_probe():
                return StatusProbe([sys.executable, '-u', '-c',
                                    'import sys;sys.stdin.buffer.read()'])
            first = idle_probe()
            backend.probes[0] = first
            backend.compose = Mock(return_value='')
            backend.start(0)
            self.assertIsNotNone(first.process.poll())
            second = idle_probe()
            backend.probes[0] = second
            state = SimpleNamespace(stdout=json.dumps([{'State': {
                'Running': False, 'ExitCode': 0, 'OOMKilled': False}}]))
            with patch('state_backend.command', return_value=state):
                backend.stop(0)
            self.assertIsNotNone(second.process.poll())
            third = idle_probe()
            backend.probes[0] = third
            backend.cleanup()
            self.assertIsNotNone(third.process.poll())

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


class ProxyScheduling(unittest.IsolatedAsyncioTestCase):
    async def test_each_chunk_waits_from_its_read_and_prefetch_preserves_order(self):
        class Clock:
            now = 0.0

            def time(self):
                return self.now

            async def sleep(self, duration):
                # Let the next read run before advancing this clock.
                await asyncio.sleep(0)
                self.now += duration

        clock = Clock()

        class Reader:
            chunks = [b"first", b"second", b""]
            reads = []

            async def read(self, size):
                self.reads.append((size, clock.time()))
                return self.chunks.pop(0)

        class Writer:
            writes = []

            def write(self, data):
                self.writes.append((data, clock.time()))

            async def drain(self):
                pass

        reader, writer = Reader(), Writer()
        await copy(reader, writer, 0.05, clock=clock.time, sleep=clock.sleep)
        self.assertEqual(writer.writes, [(b"first", 0.05), (b"second", 0.05)])
        self.assertEqual([size for size, _ in reader.reads], [32_768] * 3)
        self.assertEqual(reader.reads[1][1], 0.0)

    async def test_early_wakeup_rechecks_deadline(self):
        now = 0.0
        waits = []

        async def sleep(duration):
            nonlocal now
            waits.append(duration)
            now += 0.02 if len(waits) == 1 else duration

        class Reader:
            chunks = [b"a", b""]

            async def read(self, size):
                return self.chunks.pop(0)

        class Writer:
            written_at = None

            def write(self, data):
                self.written_at = now

            async def drain(self):
                pass

        writer = Writer()
        await copy(Reader(), writer, 0.05, clock=lambda: now, sleep=sleep)
        self.assertEqual(len(waits), 2)
        self.assertGreaterEqual(writer.written_at, 0.05)

    async def test_prefetch_is_one_chunk_and_cancellation_stops_pending_read(self):
        class Reader:
            reads = 0
            cancelled = False
            pending = asyncio.Event()

            async def read(self, size):
                self.reads += 1
                if self.reads == 1:
                    return b"first"
                try:
                    await self.pending.wait()
                except asyncio.CancelledError:
                    self.cancelled = True
                    raise
                return b"second"

        class Writer:
            wrote = asyncio.Event()
            draining = asyncio.Event()

            def write(self, data):
                self.wrote.set()

            async def drain(self):
                await self.draining.wait()

        reader, writer = Reader(), Writer()
        task = asyncio.create_task(copy(reader, writer, 0))
        await asyncio.wait_for(writer.wrote.wait(), 1)
        await asyncio.sleep(0)
        self.assertEqual(reader.reads, 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, 1)
        self.assertTrue(reader.cancelled)

    async def test_blocked_drain_allows_only_one_read_ahead(self):
        class Reader:
            chunks = [b"one", b"two", b"three", b""]
            reads = 0
            second_read = asyncio.Event()

            async def read(self, size):
                self.reads += 1
                if self.reads == 2:
                    self.second_read.set()
                return self.chunks.pop(0)

        class Writer:
            chunks = []
            first_write = asyncio.Event()
            release_drain = asyncio.Event()

            def write(self, data):
                self.chunks.append(data)
                self.first_write.set()

            async def drain(self):
                if len(self.chunks) == 1:
                    await self.release_drain.wait()

        reader, writer = Reader(), Writer()
        task = asyncio.create_task(copy(reader, writer, 0))
        await asyncio.wait_for(writer.first_write.wait(), 1)
        await asyncio.wait_for(reader.second_read.wait(), 1)
        self.assertEqual(reader.reads, 2)
        self.assertEqual(writer.chunks, [b"one"])
        writer.release_drain.set()
        await asyncio.wait_for(task, 1)
        self.assertEqual(writer.chunks, [b"one", b"two", b"three"])


class DelayedTransport(unittest.TestCase):
    def test_close_cancels_active_delayed_connection(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        holder.close()
        accepted = threading.Event()
        release = threading.Event()

        def hold():
            with listener.accept()[0]:
                accepted.set()
                release.wait(3)

        worker = threading.Thread(target=hold, daemon=True)
        worker.start()
        proxy = Proxy(f"/ip4/127.0.0.1/tcp/{port}", f"/ip4/127.0.0.1/tcp/{listener.getsockname()[1]}", 50)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                self.assertTrue(accepted.wait(3))
                connection.sendall(b"pending")
                proxy.close()
                self.assertFalse(proxy.thread.is_alive())
        finally:
            if proxy.thread.is_alive():
                proxy.close()
            release.set()
            listener.close()
            worker.join(timeout=3)

    def test_real_tcp_waits_at_least_50ms_in_each_direction(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        holder.close()
        times = {}

        def echo():
            with listener.accept()[0] as connection:
                connection.settimeout(3)
                self.assertEqual(connection.recv(1), b"x")
                times["received"] = time.monotonic()
                times["sent"] = time.monotonic()
                connection.sendall(b"y")

        worker = threading.Thread(target=echo, daemon=True)
        worker.start()
        proxy = Proxy(f"/ip4/127.0.0.1/tcp/{port}", f"/ip4/127.0.0.1/tcp/{listener.getsockname()[1]}", 50)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                sent = time.monotonic()
                connection.sendall(b"x")
                self.assertEqual(connection.recv(1), b"y")
                received = time.monotonic()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertGreaterEqual(times["received"] - sent, 0.05)
            self.assertGreaterEqual(received - times["sent"], 0.05)
        finally:
            proxy.close()
            listener.close()
            worker.join(timeout=3)

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
