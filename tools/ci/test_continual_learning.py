"""Transport checks for the longitudinal observer, never learning evidence."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import sqlite3
import json
import tempfile
from types import SimpleNamespace
import unittest

SUPPORT = Path(__file__).resolve().parents[2] / "crates/naome-knowledge/tests/support"
sys.path.insert(0, str(SUPPORT))
SPEC = importlib.util.spec_from_file_location("continual_learning", SUPPORT / "continual_learning.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ContinualObservation(unittest.TestCase):
    def record(self):
        # Synthetic metadata only: no weights, proof, search or training result.
        parent = {"updates": 0, "model": "parent", "optimizer": "parent-adam"}
        candidate = {"updates": 250, "model": "candidate", "optimizer": "candidate-adam"}
        progress = {"unit": 150, "candidate": None, "model": candidate,
                    "diagnostic": "candidate_promoted", "incumbent_score": 2,
                    "candidate_score": 3, "anchor_regression": False,
                    "development_regression": False, "cpu_micros": 1,
                    "wall_micros": 1,
                    "transfer": {"observed": (1 << 24)-1, "before": 1, "after": 3}}
        return {"id": 1, "input": {"role": "train"}, "state": "complete",
                "checkpoint": 150, "reserved_units": 150,
                "native": {"base": {"model": parent}, "progress": progress}}, candidate

    def test_selected_update_requires_complete_native_gates(self):
        record, candidate = self.record()
        self.assertTrue(MODULE.audit_completed(record, candidate, record["native"]["progress"]["model"])["accepted"])
        for field, value in [("anchor_regression", True), ("development_regression", True),
                             ("candidate_score", 2), ("unit", 149)]:
            wrong = copy.deepcopy(record)
            wrong["native"]["progress"][field] = value
            with self.assertRaises(AssertionError):
                MODULE.audit_completed(wrong, candidate, wrong["native"]["progress"]["model"])
        for before, after, observed in [(1, 1, (1 << 24)-1), (3, 12, (1 << 24)-1), (1, 3, 3)]:
            wrong = copy.deepcopy(record)
            wrong["native"]["progress"]["transfer"] = {"before": before, "after": after, "observed": observed}
            with self.assertRaises(AssertionError):
                MODULE.audit_completed(wrong, candidate, wrong["native"]["progress"]["model"])

    def test_rejection_requires_exact_model_and_optimizer_rollback(self):
        record, candidate = self.record()
        p = record["native"]["progress"]
        p["diagnostic"] = "no_transfer_gain_rejected"
        p["model"] = copy.deepcopy(record["native"]["base"]["model"])
        self.assertFalse(MODULE.audit_completed(record, candidate, record["native"]["progress"]["model"])["accepted"])
        p["model"]["optimizer"] = "rejected-candidate-momentum"
        with self.assertRaises(AssertionError):
            MODULE.audit_completed(record, candidate, record["native"]["progress"]["model"])

    def test_unadopted_candidate_is_not_a_retained_update(self):
        record, candidate = self.record()
        with self.assertRaises(AssertionError):
            MODULE.audit_completed(record, candidate, record["native"]["base"]["model"])

    def test_reader_does_not_rescan_historical_record_payloads(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory / "research").mkdir()
            path = directory / "research/jobs.sqlite3"
            learning = json.dumps({"model": "synthetic transport state"}).encode()
            solve = json.dumps({"id": 1, "input": {"role": "solve"}, "padding": "x"*4096}).encode()
            train = json.dumps({"id": 2, "input": {"role": "train"}}).encode()
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE entries(kind TEXT, key TEXT, payload BLOB, PRIMARY KEY(kind,key))")
                db.executemany("INSERT INTO entries VALUES(?,?,?)", [("learning", "current", learning), ("record", "1", solve), ("record", "2", train)])
            reader = MODULE.JournalReader()
            first = reader.read(SimpleNamespace(directory=directory))
            self.assertEqual(set(first["records"]), {2})
            measured = reader.bytes
            second = reader.read(SimpleNamespace(directory=directory))
            self.assertEqual(first, second)
            self.assertEqual(reader.bytes-measured, len(learning)+len(train))
            reader.active.discard(2)
            self.assertEqual(reader.read(SimpleNamespace(directory=directory))["records"], {})

    def test_unfinished_or_substituted_candidates_cannot_count(self):
        record, candidate = self.record()
        for field, value in [("state", "suspended"), ("checkpoint", 25), ("reserved_units", 25)]:
            wrong = copy.deepcopy(record)
            wrong[field] = value
            with self.assertRaises(AssertionError):
                MODULE.audit_completed(wrong, candidate, wrong["native"]["progress"]["model"])
        wrong = copy.deepcopy(candidate)
        wrong["updates"] = 500
        with self.assertRaises(AssertionError):
            MODULE.audit_completed(record, wrong, record["native"]["progress"]["model"])

    def test_later_candidate_does_not_replace_earlier_model_or_optimizer_evidence(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            node_dir = directory / "node-0"
            (node_dir / "research").mkdir(parents=True)
            node = SimpleNamespace(index=0, directory=node_dir, trial=SimpleNamespace(output=directory))
            path = node_dir / "research/jobs.sqlite3"
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE entries(kind TEXT, key TEXT, payload BLOB, PRIMARY KEY(kind,key))")
                for identity in (1, 2):
                    record, candidate = self.record()
                    record.update(id=identity, binding={}, settings={}, created_ms=1, expires_ms=2)
                    for field in ("model", "optimizer"):
                        payload = f"synthetic transport {field} {identity}".encode()
                        blob = {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
                        candidate[field] = blob
                        db.execute("INSERT INTO entries VALUES('model',?,?)", (blob["sha256"]+":000000", payload))
                    record["native"]["progress"]["candidate"] = candidate
                    db.commit()
                    MODULE.verify_blobs(node, record, per_job=True)
            for identity in (1, 2):
                retained = directory / f"checkpoints/node-0-job-{identity}"
                manifest = json.loads((retained / "manifest.json").read_text())
                self.assertEqual(manifest["job"]["id"], identity)
                for field in ("model", "optimizer"):
                    payload = (retained / f"{field}.bpk").read_bytes()
                    self.assertEqual(payload, f"synthetic transport {field} {identity}".encode())
                    self.assertEqual(hashlib.sha256(payload).hexdigest(), manifest["checkpoint"][field]["sha256"])

    def test_frozen_history_remains_available_after_live_blob_reclamation(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory / "research").mkdir()
            output = directory / "checkpoints/node-0-job-1"
            output.mkdir(parents=True)
            node = SimpleNamespace(index=0, directory=directory, trial=SimpleNamespace(output=directory))
            payload = b"synthetic transport of frozen original inputs"
            blob = {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
            record = {"id": 1, "native": {"history": {"blob": blob}, "progress": {"prepared": {"blob": blob}}}}
            with sqlite3.connect(directory / "research/jobs.sqlite3") as db:
                db.execute("CREATE TABLE entries(kind TEXT, key TEXT, payload BLOB)")
                db.execute("INSERT INTO entries VALUES('model',?,?)", (blob["sha256"]+":000000", payload))
                db.commit()
                self.assertEqual(MODULE.capture_inputs(node, record), 2*len(payload))
                db.execute("DELETE FROM entries")
                db.commit()
            self.assertEqual((output / "history-page.bin").read_bytes(), payload)
            self.assertEqual((output / "prepared-history.bin").read_bytes(), payload)
            self.assertEqual(json.loads((output / "inputs.json").read_text())["record"], record)


if __name__ == "__main__":
    unittest.main()
