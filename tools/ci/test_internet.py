"""Reject misleading public-network qualification receipts."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from check_internet import verify


class InternetReceiptTests(unittest.TestCase):
    def reports(self):
        return [{
            "participant": index, "environment": {"system": system, "node": f"host-{index}"},
            "revision": "tested-commit", "result": "pass", "dirty": False,
            "cleanup": {"all_processes_exited": True, "errors": []},
            "participant_roster_injected": False, "node_count": 1,
            "peer_ids": [f"peer-{index}"], "own_proof_id": f"proof-{index}",
            "expected_ids": ["proof-0", "proof-1"],
            "processes": [{"network_config": {"peers": [], "discovery": {
                "mdns": False, "dht": True, "internet": True}}}],
            "public_connections": [[{"event": "exchange_response", "kind": "object",
                "peer": f"peer-{1-index}", "object_id": f"proof-{1-index}"}]],
        } for index, system in enumerate(["Linux", "Darwin"])]

    def check(self, reports):
        with tempfile.TemporaryDirectory() as root:
            for index, report in enumerate(reports):
                folder = Path(root) / str(index)
                folder.mkdir()
                (folder / "summary.json").write_text(json.dumps(report))
            return verify(root, "tested-commit")

    def test_independent_hosts_with_counterpart_payload_receipts_pass(self):
        self.assertEqual(self.check(self.reports())["physical_host_count"], 2)

    def test_missing_or_misbound_evidence_cannot_qualify_public_discovery(self):
        mutations = [
            lambda reports: reports.pop(),
            lambda reports: reports[0].update(dirty=True),
            lambda reports: reports[0].update(revision="other-commit"),
            lambda reports: [report.update(revision="stale-commit") for report in reports],
            lambda reports: reports[0]["environment"].update(node="host-1"),
            lambda reports: reports[0].update(participant_roster_injected=True),
            lambda reports: reports[0]["cleanup"].update(all_processes_exited=False),
            lambda reports: reports[0]["public_connections"][0][0].update(peer="unrelated-peer"),
            lambda reports: reports[0]["public_connections"][0][0].update(object_id="unrelated-proof"),
            lambda reports: reports[0]["processes"][0]["network_config"].update(peers=["injected-peer"]),
            lambda reports: reports[0].update(processes=[]),
            lambda reports: reports[0].update(expected_ids=["proof-0"]),
        ]
        for index, mutate in enumerate(mutations):
            reports = copy.deepcopy(self.reports())
            mutate(reports)
            with self.subTest(case=index), self.assertRaises(AssertionError):
                self.check(reports)


if __name__ == "__main__":
    unittest.main()
