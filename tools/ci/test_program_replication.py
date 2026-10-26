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
from program_replication import program_rows


class ProgramObservationTests(unittest.TestCase):
    def test_locked_observation_waits_for_the_same_published_program(self):
        with tempfile.TemporaryDirectory() as directory:
            node = SimpleNamespace(directory=pathlib.Path(directory))
            with sqlite3.connect(node.directory / "proof-corpus.sqlite3") as writer:
                writer.executescript("CREATE TABLE programs(id BLOB,manifest TEXT,received INTEGER);"
                                     "CREATE TABLE artifacts(id BLOB);")
                writer.execute("INSERT INTO programs VALUES(?,?,?)", (b"proof", json.dumps({"commands": 4}), 2))
                writer.commit()
                writer.execute("BEGIN EXCLUSIVE")
                self.assertEqual(program_rows(node), [])
                writer.rollback()
                self.assertEqual(program_rows(node), [{"id": b"proof".hex(), "manifest": {"commands": 4},
                                                      "received": 2, "published": False}])
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
