"""No-model tests for real framed descriptor transfer and fail-closed parsing."""
import array
import fcntl
import importlib.util
import os
from pathlib import Path
import socket
import struct
import tempfile
import subprocess
import sys
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location("worker", Path(__file__).with_name("worker.py"))
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class Framing(unittest.TestCase):
    def fixture(self):
        directory = tempfile.TemporaryDirectory(prefix="naome-interest-ipc-")
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "lease"
        path.write_bytes(b"lease")
        lease = os.open(path, os.O_RDWR)
        probe = os.open(path, os.O_RDWR)
        self.addCleanup(os.close, probe)
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        sender, receiver = socket.socketpair()
        self.addCleanup(sender.close)
        self.addCleanup(receiver.close)
        return lease, probe, sender, receiver

    def transfer(self, sender, lease, raw):
        sender.sendmsg([struct.pack(">I", len(raw)) + raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [lease]))])
        os.close(lease)

    def test_real_descriptor_holds_after_sender_and_original_close(self):
        lease, probe, sender, receiver = self.fixture()
        self.transfer(sender, lease, b'{"kind":"hold"}')
        value, fds = worker.receive(receiver)
        self.assertEqual(value, {"kind": "hold"})
        self.assertEqual(len(fds), 1)
        sender.close()
        with self.assertRaises(BlockingIOError):
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        worker.lease(fds[0])
        os.close(fds[0])
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_malformed_json_closes_received_lease(self):
        lease, probe, sender, receiver = self.fixture()
        self.transfer(sender, lease, b'{')
        with self.assertRaises(ValueError):
            worker.receive(receiver)
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_duplicate_key_closes_received_lease(self):
        lease, probe, sender, receiver = self.fixture()
        self.transfer(sender, lease, b'{"key":1,"key":2}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            worker.receive(receiver)
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_nonfinite_json_closes_received_lease(self):
        lease, probe, sender, receiver = self.fixture()
        self.transfer(sender, lease, b'{"key":NaN}')
        with self.assertRaisesRegex(ValueError, "nonfinite"):
            worker.receive(receiver)
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_oversized_header_closes_received_lease(self):
        lease, probe, sender, receiver = self.fixture()
        sender.sendmsg([struct.pack(">I", worker.LIMIT + 1)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [lease]))])
        os.close(lease)
        with self.assertRaisesRegex(ValueError, "byte limit"):
            worker.receive(receiver)
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)


class RequiredTelemetry(unittest.TestCase):
    def actual_child(self, mode, expected):
        with tempfile.TemporaryDirectory(prefix="naome-telemetry-") as directory:
            path=Path(directory)/"lease"
            path.write_bytes(b"lease")
            lease=os.open(path,os.O_RDWR)
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            probe=os.open(path,os.O_RDWR)
            child=subprocess.Popen([sys.executable,"-B",str(Path(__file__).resolve()),"--telemetry-child",mode],pass_fds=(lease,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            os.close(lease)
            try:
                self.assertEqual(child.wait(timeout=5),expected)
                fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:
                if child.poll() is None:child.kill();child.wait()
                os.close(probe)

    def test_counter_failure_exits_actual_provider_and_releases_kernel_lease(self):
        self.actual_child("counter",73)

    def test_mps_counter_failure_exits_actual_provider_and_releases_kernel_lease(self):
        self.actual_child("mps",73)

    def test_counter_stall_heartbeat_exits_actual_provider_and_releases_kernel_lease(self):
        self.actual_child("stall",75)


def telemetry_child(mode):
    stop=threading.Event();heartbeat=[time.monotonic()]
    class Channel:
        def sendall(self,_):pass
    def reader(_):
        if mode=="counter":raise RuntimeError("injected counter failure")
        time.sleep(3)
        raise RuntimeError("deliberately stalled required counter")
    holder={}
    if mode=="mps":
        class Mps:
            def current_allocated_memory(self):raise RuntimeError("injected MPS counter failure")
        class Torch:mps=Mps()
        class Model:torch=Torch()
        holder["model"]=Model()
        reader=worker.resource.getrusage
    threading.Thread(target=worker.required_samples,args=(Channel(),holder,heartbeat,stop,reader),daemon=True).start()
    worker.monitor_samples(stop,heartbeat)


if __name__ == "__main__":
    if len(sys.argv)==3 and sys.argv[1]=="--telemetry-child":telemetry_child(sys.argv[2])
    else:unittest.main()
