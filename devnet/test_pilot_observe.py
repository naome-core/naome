"""Evidence gates reject partial directed reachability and nonfinal receipts."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import pilot
import pilot_observe


class ObservationEvidence(unittest.TestCase):
    def test_compare_rejects_nonfinal_receipt_or_changed_head(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reports = []
            status = {field: field for field in pilot_observe.LIVE_AGREEMENT}
            status.update(status='finalized', genesis='g', profile='p', height=3,
                          paid_completions=1)
            for index in range(4):
                report = root / f'live-{index}.json'
                pilot.write(report, {'version': 1, 'kind': 'live_observation',
                    'node_index': index, 'genesis': 'g', 'profile': 'p',
                    'stage': 'catch-up', 'host_label': 'one-machine', 'observer_sha256': 'test',
                    'provisioning_source': {'git_head': 'same'},
                    'status': status, 'receipts': {'op': {'status': 'finalized'}}})
                reports.append(report)
            args = SimpleNamespace(observations=reports, report=root / 'agreed.json')
            self.assertEqual(pilot_observe.compare(args)['height'], 3)
            args.report = root / 'reject.json'
            changed = pilot.read(reports[3])
            changed['status']['head'] = 'different'
            reports[3].unlink()
            pilot.write(reports[3], changed)
            with self.assertRaisesRegex(RuntimeError, 'heads or state differ'):
                pilot_observe.compare(args)
            self.assertFalse(args.report.exists())
            changed['status']['head'] = status['head']
            changed['receipts']['op']['status'] = 'pending'
            reports[3].unlink()
            pilot.write(reports[3], changed)
            with self.assertRaisesRegex(RuntimeError, 'receipt responses differ'):
                pilot_observe.compare(args)
            self.assertFalse(args.report.exists())

    def test_compare_probes_requires_every_directed_connection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reports = []
            for source in range(4):
                report = root / f'probe-{source}.json'
                pilot.write(report, {'version': 1, 'kind': 'directed_tcp_probe',
                    'node_index': source, 'genesis': 'g', 'profile': 'p',
                    'channel': 'primary', 'observer_sha256': 'test',
                    'provisioning_source': {'git_head': 'same'},
                    'host_label': 'one-machine',
                    'targets': [{'node_index': target, 'endpoint': f'127.0.0.1:{4000 + target}',
                                 'tcp_connected': True}
                                for target in range(4) if target != source]})
                reports.append(report)
            args = SimpleNamespace(probes=reports, report=root / 'tcp.json')
            self.assertEqual(pilot_observe.compare_probes(args)['outcome'],
                             'twelve_directed_tcp_connections_recorded')
            broken = pilot.read(reports[0])
            broken['targets'][0]['tcp_connected'] = False
            reports[0].unlink()
            pilot.write(reports[0], broken)
            args.report = root / 'reject.json'
            with self.assertRaisesRegex(RuntimeError, 'TCP probes failed'):
                pilot_observe.compare_probes(args)
            self.assertFalse(args.report.exists())


if __name__ == '__main__':
    unittest.main()
