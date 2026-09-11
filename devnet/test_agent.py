"""Boundary tests for diagnostic supervision and delayed TCP transport."""
import http.client
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from agent import EVENTS, State, atomic, metrics, resources, server
from proxy import Proxy
from qualify import Qualification
from backend import DockerBackend, ProcessBackend


def role():
    return {"name": "validator-0", "publisher": False, "deployment": {"roles": [{"peer_id": "known"}]}}


class Diagnostics(unittest.TestCase):
    def test_progress_restart_regression_stall_and_unknown_events_are_bounded(self):
        state = State(role(), 10)
        state.event({"event": "ready", "state": {"driver": {"height": "1", "head": "genesis"}}})
        state.event({"event": "finality", "state": {"driver": {"height": "2", "head": "one"}}})
        for i in range(1000):
            state.event({"event": f"unknown_{i}"})
        self.assertLessEqual(len(state.snapshot()["events"]), len(EVENTS) + 1)
        self.assertEqual(state.snapshot()["finalized_height"], 1)
        with self.assertRaises(ValueError):
            state.event({"event": "finality", "state": {"driver": {"height": "1", "head": "genesis"}}})
        with patch("agent.time.monotonic", return_value=state.progress + 11):
            self.assertTrue(state.snapshot()["stalled"])
            self.assertFalse(state.snapshot()["healthy"])

    def test_custody_and_peer_diagnostics_do_not_claim_unknown_connections(self):
        state = State(role(), 10)
        state.event({"event": "command_result", "outcome": {"event": "acquisition_started"}})
        self.assertTrue(state.snapshot()["acquisition_active"])
        state.event({"event": "acquisition_failed"})
        self.assertFalse(state.snapshot()["acquisition_active"])
        state.event({"event": "peer_session", "peer": "foreign", "state": "established"})
        self.assertEqual(state.snapshot()["connected_peers"], [])
        state.event({"event": "peer_session", "peer": "known", "state": "established"})
        self.assertEqual(state.snapshot()["connected_peers"], ["known"])
        state.event({"event": "peer_session", "peer": "known", "state": "disconnected"})
        self.assertEqual(state.snapshot()["connected_peers"], [])
        self.assertNotIn("naome_devnet_rss_bytes", metrics(state.snapshot()))

    def test_http_is_read_only_and_health_distinguishes_not_ready_from_ready(self):
        state = State(role(), 10)
        web = server(state, "127.0.0.1", 0)
        url = f"http://127.0.0.1:{web.server_port}"
        try:
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(url + "/health", timeout=2)
            self.assertEqual(error.exception.code, 503)
            state.event({"event": "ready"})
            with urllib.request.urlopen(url + "/health", timeout=2) as response:
                self.assertTrue(json.load(response)["healthy"])
            with urllib.request.urlopen(url + "/metrics", timeout=2) as response:
                self.assertIn(b"naome_devnet_healthy 1", response.read())
            connection = http.client.HTTPConnection("127.0.0.1", web.server_port, timeout=2)
            connection.request("POST", "/status", b'{"command":"author_fresh"}')
            self.assertEqual(connection.getresponse().status, 501)
            connection.close()
            self.assertEqual(state.snapshot()["finalized_height"], 0)
        finally:
            web.shutdown()
            web.server_close()

    def test_atomic_diagnostics_refuse_pending_symlink_and_sample_only_role_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "untouched"
            original.write_bytes(b"keep")
            (root / "status.pending").symlink_to(original)
            with self.assertRaises(OSError):
                atomic(root / "status.json", {"ok": True})
            self.assertEqual(original.read_bytes(), b"keep")
            (root / "status.pending").unlink()
            atomic(root / "status.json", {"ok": True})
            self.assertTrue(json.loads((root / "status.json").read_text())["ok"])
            self.assertGreater(resources(os.getpid(), root)["disk_bytes"], 0)


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


class FaultSchedule(unittest.TestCase):
    def test_outage_heals_on_timer_even_without_finality(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        run = Qualification.__new__(Qualification)
        run.args = SimpleNamespace(height_timeout=30, partition_seconds=5)
        run.deadline = 100
        run.offline = "validator-3"
        run.heal_at = 5
        run.backend = Mock()
        run.report = {"faults": []}
        run.observe = Mock(return_value={"validator-0": {"finalized_height": 0}})
        with patch("qualify.time.monotonic", return_value=6):
            run.wait("heal without progress", ["validator-0"], lambda _: run.offline is None)
        run.backend.heal.assert_called_once_with("validator-3")
        self.assertEqual(run.report["faults"][0]["operation"], "partition_healed")


class Cleanup(unittest.TestCase):
    def test_control_container_is_removed_when_attached_command_times_out(self):
        backend = DockerBackend.__new__(DockerBackend)
        backend.project = "test-owned"
        backend.control_label = "naome.devnet.owner=test-owned"
        backend.image_id = "test-image"
        calls = []

        def invoke(args, timeout=60):
            calls.append(args)
            if args[:2] == ["docker", "run"]:
                raise subprocess.TimeoutExpired(args, timeout)
            if args[:2] == ["docker", "ps"]:
                return "owned-container\n"
            return ""

        with patch("backend.command", side_effect=invoke):
            with self.assertRaises(subprocess.TimeoutExpired):
                backend.control([], "naome-devnet", "verify", "/data", "100")
        self.assertIn(backend.control_label, calls[0])
        self.assertEqual(calls[1][-1], "label=" + backend.control_label)
        self.assertEqual(calls[2], ["docker", "rm", "--force", "owned-container"])

    def test_dead_agent_does_not_leave_its_child_running(self):
        import select
        parent = subprocess.Popen([sys.executable, "-c",
            "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); print('ready',flush=True); time.sleep(30)"],
            stdout=subprocess.PIPE, start_new_session=True)
        backend = ProcessBackend.__new__(ProcessBackend)
        backend.children = {"validator-0": parent}
        backend.logs = {"validator-0": open(os.devnull, "w")}
        backend.paused = {}
        try:
            self.assertTrue(select.select([parent.stdout], [], [], 3)[0])
            self.assertEqual(parent.stdout.readline(), b"ready\n")
            parent.kill()
            parent.wait(timeout=3)
            with self.assertRaises(RuntimeError):
                backend.stop(["validator-0"])
            # The descendant inherited stdout: EOF proves it stopped as well.
            self.assertTrue(select.select([parent.stdout], [], [], 3)[0])
            self.assertEqual(parent.stdout.read(), b"")
            self.assertFalse(backend.children)
        finally:
            try:
                os.killpg(parent.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            parent.wait(timeout=3)
            parent.stdout.close()
            for output in backend.logs.values():
                output.close()


if __name__ == "__main__":
    unittest.main()
