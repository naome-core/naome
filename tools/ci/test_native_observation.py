"""Finite process observers retain exact evidence across GC and log rotation."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crates/naome-knowledge/tests/support"))
NATIVE = importlib.import_module("native_learning")
LIFECYCLE = importlib.import_module("autonomous_lifecycle")


class NativeObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="naome-native-observation-")
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def log_node(self):
        node = object.__new__(LIFECYCLE.Node)
        node.directory = self.root
        node._log_events = []
        node._log_offsets = {}
        return node

    def test_log_rotation_keeps_existing_session_offsets_and_no_duplicate_reads(self):
        node = self.log_node()
        path = self.root / "node.log"
        path.write_text('{"event":"starting"}\n{"event":"stopped"}\n')
        before_restart = len(node.logs())
        path.rename(self.root / "node.log.previous")
        path.write_text('{"event":"starting"}\n{"event":"accepted"}\n{"event":"stopped"}\n')
        self.assertEqual([v['event'] for v in node.logs()[before_restart:]],
                         ['starting', 'accepted', 'stopped'])
        self.assertEqual(len(node.logs()), 5)

    def test_log_partial_append_is_observed_exactly_once_after_rotation(self):
        node = self.log_node()
        path = self.root / "node.log"
        path.write_bytes(b'{"event":"starting"}\n{"event":')
        self.assertEqual(node.logs(), [{'event': 'starting'}])
        path.rename(self.root / "node.log.previous")
        with (self.root / "node.log.previous").open('ab') as output:
            output.write(b'"accepted"}\n')
        path.write_text('{"event":"stopped"}\n')
        expected = [{'event': 'starting'}, {'event': 'accepted'}, {'event': 'stopped'}]
        self.assertEqual(node.logs(), expected)
        self.assertEqual(node.logs(), expected)

    def meta_node(self):
        directory = self.root / 'node-0'
        (directory / 'research').mkdir(parents=True)
        node = SimpleNamespace(directory=directory, index=0, trial=SimpleNamespace(output=self.root))
        payloads = {'weights': b'checked weight bytes', 'optimizer': b'checked optimizer bytes'}
        blobs = {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                 for name, data in payloads.items()}
        transfer = {'before': 0, 'after': 0, 'observed': (1 << 24)-1}
        plan = {'phases': []}
        update = {'model': {'updates': 16, **blobs},
                  'experience': {'job': 42, 'plan': plan, 'context': [1], 'transfer': transfer}}
        record = {'id': 42, 'input': {'role': 'train', 'source': 'owned'},
                  'native': {'base': {'preparation': 'Meta', 'meta': {'model': {'updates': 8}}},
                             'progress': {'meta_update': update, 'plan': {'plan': plan, 'context': [1]},
                                          'transfer': transfer, 'diagnostic': 'no_transfer_gain_rejected',
                                          'meta_cpu_micros': 0, 'cpu_micros': 1,
                                          'meta_wall_micros': 0, 'wall_micros': 1}}}
        database = directory / 'research/jobs.sqlite3'
        with sqlite3.connect(database) as connection:
            connection.execute('CREATE TABLE entries(kind TEXT, key TEXT, payload BLOB)')
            for name, data in payloads.items():
                connection.execute('INSERT INTO entries VALUES(?,?,?)',
                                   ('model', blobs[name]['sha256']+':000000', data))
        return node, record, database

    def test_captured_meta_bytes_remain_verifiable_after_owner_gc(self):
        node, record, database = self.meta_node()
        expected = NATIVE.verify_meta(node, record)
        with sqlite3.connect(database) as connection:
            connection.execute("DELETE FROM entries WHERE kind='model'")
        self.assertEqual(NATIVE.verify_meta(node, record), expected)

    def test_captured_meta_corruption_is_not_silently_replaced_from_live_storage(self):
        node, record, _ = self.meta_node()
        NATIVE.verify_meta(node, record)
        (self.root / 'meta-checkpoints/node-0-job-42/weights.bin').write_bytes(b'corrupt')
        with self.assertRaises(AssertionError):
            NATIVE.verify_meta(node, record)

    def test_captured_meta_identity_cannot_be_rebound_to_another_record(self):
        node, record, _ = self.meta_node()
        NATIVE.verify_meta(node, record)
        altered = copy.deepcopy(record)
        altered['input']['source'] = 'different'
        with self.assertRaises(AssertionError):
            NATIVE.verify_meta(node, altered)


if __name__ == '__main__':
    unittest.main()
