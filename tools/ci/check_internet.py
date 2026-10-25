"""Bind two independent public-network receipts to the actual counterpart peers."""
import json
import pathlib
import sys


def verify(root):
    reports = [json.loads(path.read_text()) for path in pathlib.Path(root).glob("*/summary.json")]
    assert len(reports) == 2, "both host receipts are required"
    reports.sort(key=lambda report: report["participant"])
    assert [report["participant"] for report in reports] == [0, 1]
    assert {report["environment"]["system"] for report in reports} == {"Linux", "Darwin"}
    assert len({report["environment"]["node"] for report in reports}) == 2
    assert len({report["revision"] for report in reports}) == 1
    for index, report in enumerate(reports):
        other = reports[1 - index]
        assert report["result"] == "pass" and not report["dirty"]
        assert report["cleanup"]["all_processes_exited"] and not report["cleanup"]["errors"]
        assert report["participant_roster_injected"] is False and report["node_count"] == 1
        assert len(report["peer_ids"]) == 1
        assert report["peer_ids"][0] != other["peer_ids"][0]
        for process in report["processes"]:
            config = process["network_config"]
            assert config["peers"] == []
            assert config["discovery"] == {"mdns": False, "dht": True, "internet": True}
        assert any(event.get("event") == "exchange_response" and event.get("kind") == "object"
                   and event.get("peer") == other["peer_ids"][0]
                   and event.get("object_id") == other["own_proof_id"]
                   for event in report["public_connections"][0]), "counterpart payload receipt required"
    return {"result": "pass", "physical_host_count": 2, "revision": reports[0]["revision"],
            "peer_ids": [report["peer_ids"][0] for report in reports]}


if __name__ == "__main__":
    print(json.dumps(verify(sys.argv[1])))
