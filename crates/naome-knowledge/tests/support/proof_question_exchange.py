#!/usr/bin/env python3
"""Finite receiver-first selection evidence through real direct and relay links."""
import argparse
from pathlib import Path
import time
import traceback

from proof_network import citation_id, proof_metadata, digest, question_source, source, stored_objects
from proof_network_discovery import DiscoveryDriver, Relay, port


class QuestionDriver(DiscoveryDriver):
    def __init__(self, binary, output, timeout, profile, mode):
        super().__init__(binary, output, timeout, profile, mode)
        self.summary["question_driver_sha256"] = digest(__file__)
        self.summary["fixture"] = f"receiver-question-{mode}"

    def wait_set(self, node, ids, timeout=25):
        deadline = min(self.deadline, time.monotonic() + timeout)
        while time.monotonic() < deadline:
            status = node.status_snapshot()
            if set(status["ids"]) == set(ids) and not status["pending"]:
                return status
            time.sleep(0.1)
        raise AssertionError(f"selected graph mismatch: {node.command('status')}")

    def start_participant(self, node):
        config = self.settings(node) if self.mode == "relay" else {
            "discovery": {"mdns": False, "dht": False},
        }
        node.start(test_controls=True, network_config=config)

    def run_questions(self):
        self.summary["node_count"] = 3
        for index in range(3):
            self.init_node(index)
        if self.mode == "relay":
            directory = self.output / "relay"
            self.relay = Relay(self, "relay", directory, self.init_identity(directory), port())
            self.relay.start()
            self.summary["relay_process_count"] = 1
        sender, spare, receiver = self.nodes
        for node in self.nodes:
            self.start_participant(node)
        for node in [spare, receiver]:
            node.wait_event(lambda event: event.get("event") == "identified" and event.get("peer") == sender.identity, timeout=40)
        first = sender.command("produce", source=source(11))
        helper = sender.command("produce", source=source(7))
        a = question_source(source(7)).split("goal = ")[1]
        b = "all(z,mem(z,z))"
        child_statement = f"imp({b},{a})"
        child_source = f'goal = {child_statement} proof: p0 = cite("{citation_id(helper["object"])}") p1 = simp({a},{b}) p2 = mp(p0,p1) return p2'
        child = sender.command("produce", source=child_source)
        expected = [value["object"]["artifact_id"] for value in [first, helper, child]]
        self.wait_set(receiver, expected)
        self.wait_set(spare, expected)
        assert len(stored_objects(receiver)) == 3
        responses = [event for event in receiver.events if event.get("event") == "exchange_response" and event.get("kind") == "object"]
        assert responses
        assert all(event["relayed"] is (self.mode == "relay") for event in responses)
        # Duplicate announcements cannot create another admission or proof fetch.
        time.sleep(1)
        offset = len(sender.events)
        sender.command("announce", id=first["object"]["artifact_id"])
        sender.command("offer", peer=receiver.identity, id=first["object"]["artifact_id"])
        self.wait_set(receiver, expected)
        time.sleep(1)
        assert not any(event.get("event") == "exchange_request" and event.get("kind") == "get"
                       and event.get("peer") == receiver.identity and event.get("object_id") == first["object"]["artifact_id"]
                       for event in sender.events[offset:])
        self.summary["scenarios"]["automatic_receiver_selection_and_parent_closure"] = {
            "result": "pass", "selected_ids": sorted(expected), "object_responses": responses,
            "duplicate_root_fetch_count": 0}
        receiver.stop()
        self.start_participant(receiver)
        self.wait_set(receiver, expected)
        assert len(stored_objects(receiver)) == 3
        self.summary["scenarios"]["automatic_selection_restart"] = {"result": "pass", "ids": sorted(expected)}
        # An unrelated description must never establish the actual solution.
        # A second supplier remains eligible after the false one is declined.
        receiver.stop()
        actual = sender.command("test_compile", source=source(31))["object"]
        unrelated = sender.command("test_compile", source=source(32))["object"]
        for supplier in [sender, spare]:
            supplier.command("ingest", object=actual)
        bad, good = sorted([sender, spare], key=lambda node: node.identity)
        wrong = proof_metadata(actual, question_source(source(32)))
        wrong["statement_id"] = unrelated["statement_id"]
        bad.command("test_descriptor", metadata=wrong)
        good.stop()
        bad_offset, good_offset = len(bad.events), len(good.events)
        receiver_offset = len(receiver.events)
        self.start_participant(receiver)
        receiver.wait_event(lambda event: event.get("event") == "proof_skipped" and event.get("id") == actual["artifact_id"], since=receiver_offset)
        assert set(receiver.ids()) == set(expected)
        self.start_participant(good)
        expected.append(actual["artifact_id"])
        self.wait_set(receiver, expected)
        good_gets = [event for event in good.events[good_offset:] if event.get("event") == "exchange_request" and event.get("kind") == "get"
                     and event.get("peer") == receiver.identity and event.get("object_id") == actual["artifact_id"]]
        assert good_gets and len(stored_objects(receiver)) == 4
        self.summary["scenarios"]["false_description_preserves_correct_supplier_rotation"] = {
            "result": "pass", "artifact_id": actual["artifact_id"], "bad_supplier": bad.identity,
            "good_supplier": good.identity, "good_gets": good_gets}
        if self.mode == "direct":
            sender.command("links", peers=[])
            formula = "eq(x0,x0)"
            steps = ["p0 = refl(x0)"]
            for index in range(34):
                formula = f"all(x{index},{formula})"
                steps.append(f"p{index + 1} = gen(p{index},x{index})")
            result = sender.command("produce", source=f'goal = {formula} proof: ' + " ".join(steps) + " return p34")
            assert result["result"]["status"] == "accepted" and result["metadata"] is None, result
            error = result["metadata_error"]
            assert error["schema_version"] == 1 and error["code"] == "input.invalid", error
            assert error["message"] == "question limit exceeded: question target depth", error
            assert error["retryable"] is False and error["fatal"] is False, error
            assert result["object"]["artifact_id"] in sender.ids()
            self.summary["scenarios"]["local_producer_outside_question_codec"] = {"result": "pass", "accepted_id": result["object"]["artifact_id"], "metadata_error": error}
        self.assert_caps()
        self.summary["accepted_ids"] = sorted(expected)
        self.summary["result"] = "pass"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True, help="developer-tools naome-knowledge-dev executable")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--profile", choices=["test", "release"], required=True)
    parser.add_argument("--mode", choices=["direct", "relay"], required=True)
    args = parser.parse_args()
    driver = QuestionDriver(args.binary, args.output, args.timeout, args.profile, args.mode)
    try:
        driver.run_questions()
    except Exception as error:
        driver.summary["result"] = "fail"
        driver.summary["error"] = str(error)
        driver.summary["traceback"] = traceback.format_exc()
        print(driver.summary["traceback"], flush=True)
    finally:
        driver.finish()
    return 0 if driver.summary["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
