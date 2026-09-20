"""Pilot evidence must never turn partial or inconsistent exports into success."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import pilot


class PilotEvidence(unittest.TestCase):
    def replay(self):
        value = {key: key for key in pilot.AGREEMENT}
        value.update(height=12, paid_completions=2, accounts=[{'balance_atoms': '1400000000'}], claims=['a', 'b'])
        return value

    def test_every_committed_state_field_must_agree(self):
        for field in pilot.AGREEMENT:
            with self.subTest(field=field):
                values = [self.replay() for _ in range(4)]
                values[3][field] = 'conflict'
                with self.assertRaises(RuntimeError):
                    pilot.compare(values, 2)

    def test_missing_exports_fields_completions_and_genesis_only_fail(self):
        for values in ([self.replay()] * 3, [self.replay()] * 5):
            with self.assertRaises(RuntimeError):
                pilot.compare(values, 2)
        for field in pilot.AGREEMENT:
            values = [self.replay() for _ in range(4)]
            del values[2][field]
            with self.assertRaises(RuntimeError):
                pilot.compare(values, 2)
        values = [self.replay() for _ in range(4)]
        with self.assertRaises(RuntimeError):
            pilot.compare(values, 3)
        for value in values:
            value['height'] = 0
        with self.assertRaises(RuntimeError):
            pilot.compare(values, 0)

    def test_replay_comparison_is_read_only_and_exact(self):
        values = [self.replay() for _ in range(4)]
        before = copy.deepcopy(values)
        self.assertEqual(pilot.compare(values, 2), before[0])
        self.assertEqual(values, before)

    def test_report_creation_never_overwrites_or_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'report.json'
            pilot.write(path, {'original': True})
            with self.assertRaises(FileExistsError):
                pilot.write(path, {'original': False})
            link = Path(temp) / 'linked.json'
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                pilot.write(link, {})
            with self.assertRaises(RuntimeError):
                pilot.read(link)
            self.assertEqual(pilot.read(path), {'original': True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_private_files_reject_public_modes_and_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / 'key'
            path.write_bytes(b'test fixture')
            path.chmod(0o600)
            pilot.private(path)
            path.chmod(0o644)
            with self.assertRaises(RuntimeError):
                pilot.private(path)
            link = root / 'link'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                pilot.private(link)
            with self.assertRaises(RuntimeError):
                pilot.private(root)

    def test_failed_native_command_cannot_supply_a_replay(self):
        with patch('pilot.subprocess.run') as command:
            command.return_value.returncode = 1
            command.return_value.stderr = 'verification failed'
            command.return_value.stdout = '{}'
            with self.assertRaisesRegex(RuntimeError, 'verification failed'):
                pilot.run('naome-verifier', 'verify', 'genesis', 'archive')
