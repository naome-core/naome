"""Read-only transfer observation respects SQLite ownership and busy windows."""
import json
import pathlib
import sqlite3
import sys
import tempfile
import unittest
from types import SimpleNamespace

SUPPORT = pathlib.Path(__file__).resolve().parents[2] / "crates/naome-knowledge/tests/support"
sys.path.insert(0, str(SUPPORT))
from program_replication import AutonomousNode, program_rows


class ProgramObservationTests(unittest.TestCase):
    def test_launch_observation_survives_rotation_and_rejects_stale_start(self):
        with tempfile.TemporaryDirectory() as directory:
            node = AutonomousNode.__new__(AutonomousNode)
            node.directory = pathlib.Path(directory)
            node._log_events = []
            node._log_offsets = {}
            node.process = {"pid": 42}
            node.launch_hash = "current"
            log = node.directory / "node.log"
            previous = node.directory / "node.log.previous"
            started = {"event": 0x00170068, "peer_id": "receiver"}
            accepted = {"event": 0x00170001, "source": 0x180001, "id": "proof"}
            stopped = {"event": 0x0017006a}

            def write(path, events):
                path.write_text("".join(json.dumps(event) + "\n" for event in events))

            marker = {"event": 0x00170069, "phase": 0x190002, "pid": 42,
                      "instance_sha256": "stale"}
            write(log, [marker, started])
            self.assertEqual(node.launch_events(), [])

            with log.open("a") as output:
                output.write(json.dumps(dict(marker, instance_sha256="current")) + "\n")
            log.rename(previous)
            write(log, [started, accepted, stopped, dict(marker, phase=0x190001), started])
            self.assertEqual(node.launch_events(), [started, accepted, stopped])
            self.assertEqual(node.launch_events(), [started, accepted, stopped])

    def test_locked_observation_waits_for_the_same_published_program(self):
        with tempfile.TemporaryDirectory() as directory:
            node = SimpleNamespace(directory=pathlib.Path(directory))
            with sqlite3.connect(node.directory / "proof-corpus.sqlite3") as writer:
                writer.executescript("CREATE TABLE programs(id BLOB,manifest BLOB,received INTEGER);"
                                     "CREATE TABLE artifacts(id BLOB);")
                manifest = bytes([4, 12]) + bytes(128)
                writer.execute("INSERT INTO programs VALUES(?,?,?)", (b"proof", manifest, 2))
                writer.commit()
                writer.execute("BEGIN EXCLUSIVE")
                self.assertEqual(program_rows(node), [])
                writer.rollback()
                self.assertEqual(program_rows(node), [{
                    "id": b"proof".hex(), "received": 2, "published": False,
                    "manifest": {"commands": 4, "input_bytes": 12,
                                 **{key: [0] * 32 for key in (
                                     "program_hash", "stream_root", "conclusion", "statement")}},
                }])
                writer.execute("UPDATE programs SET received=4")
                writer.execute("INSERT INTO artifacts VALUES(?)", (b"proof",))
                writer.commit()
                self.assertTrue(program_rows(node)[0]["published"])

    def test_invalid_schema_is_not_treated_as_a_busy_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            node = SimpleNamespace(directory=pathlib.Path(directory))
            with sqlite3.connect(node.directory / "proof-corpus.sqlite3"):
                with self.assertRaisesRegex(sqlite3.OperationalError, "no such table"):
                    program_rows(node)


if __name__ == "__main__":
    unittest.main()
