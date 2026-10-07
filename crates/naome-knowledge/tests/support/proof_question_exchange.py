#!/usr/bin/env python3
"""Finite receiver-first selection evidence through real direct and relay links."""
import argparse
import json
from pathlib import Path
import time
import traceback

from proof_network import Node, digest, question_source, source, stored_objects
from proof_network_discovery import DiscoveryDriver, Relay, port


class QuestionDriver(DiscoveryDriver):
    def __init__(self, binary, output, timeout, profile, mode):
        super().__init__(binary, output, timeout, profile, mode)
        self.summary["question_driver_sha256"] = digest(__file__)
        self.summary["fixture"] = f"receiver-question-{mode}"

    def wait_set(self, node, ids, timeout=25):
        deadline = min(self.deadline, time.monotonic() + timeout)
        while time.monotonic() < deadline:
            status = node.command("status")
            if set(status["ids"]) == set(ids) and not status["pending"]:
                return status
            time.sleep(0.1)
        raise AssertionError(f"selected graph mismatch: {node.command('status')}")

    def start_participant(self, node, interest):
        config = self.settings(node) if self.mode == "relay" else {
            "discovery": {"mdns": False, "dht": False},
        }
        node.start(test_controls=True, network_config=config, interest=interest)

    def run_questions(self):
        self.summary["node_count"] = 3
        for index in range(3):
            self.init_node(index)
        if self.mode == "relay":
            directory = self.output / "relay"
            self.relay = Relay(self, "relay", directory, self.init_identity(directory), port())
            self.relay.start()
            self.summary["relay_process_count"] = 1
        sender, absent, selected = self.nodes
        a = question_source(source(7)).split("statement = ")[1]
        b = "forall(z,member(z,z))"
        child_statement = f"implies({b},{a})"
        child_question = f'foundation = "naome:zfc" statement = {child_statement}'
        allowlist = [question_source(source(11)), child_question, question_source(source(31))]
        self.start_participant(sender, "all")
        self.start_participant(absent, None)
        self.start_participant(selected, allowlist)
        for receiver in [absent, selected]:
            receiver.wait_event(lambda event: event.get("event") == "identified" and event.get("peer") == sender.identity, timeout=40)
        accepted = sender.command("produce", source=source(11))
        declined = sender.command("produce", source=source(12))
        helper = sender.command("produce", source=source(7))
        self.wait_set(selected, [accepted["object"]["proof_id"]])
        selected.wait_event(lambda event: event.get("event") == "proof_skipped" and event.get("id") == helper["object"]["proof_id"], timeout=10)
        sender.command("announce", id=declined["object"]["proof_id"])
        sender.command("offer", peer=selected.identity, id=declined["object"]["proof_id"])
        self.wait_set(absent, [])
        # The helper's own question is declined. Its exact bytes are required
        # only after the selected parent commits its actual citation.
        child_source = f'foundation = "naome:zfc"\nstatement = {child_statement}\nproof: p0 = cite("{helper["object"]["proof_id"]}") p1 = simplification({a},{b}) p2 = modus_ponens(p0,p1) return p2'
        child = sender.command("produce", source=child_source)
        expected = [accepted["object"]["proof_id"], helper["object"]["proof_id"], child["object"]["proof_id"]]
        self.wait_set(selected, expected)
        time.sleep(2)
        assert absent.command("status")["ids"] == []
        assert not any(event.get("event") == "exchange_response" and event.get("kind") == "object" for event in absent.events)
        gets = [event for event in sender.events if event.get("event") == "exchange_request" and event.get("kind") == "get"]
        assert not any(event["peer"] == absent.identity for event in gets)
        declined_id = declined["object"]["proof_id"]
        assert not any(event.get("event") == "exchange_response" and event.get("kind") == "object" and event.get("object_id") == declined_id for event in selected.events)
        assert not any(event["peer"] == selected.identity and event["object_id"] == declined_id for event in gets)
        helper_payloads = [event for event in selected.events if event.get("event") == "exchange_response" and event.get("kind") == "object" and event.get("object_id") == helper["object"]["proof_id"]]
        assert helper_payloads and all(event["root_id"] == child["object"]["proof_id"] for event in helper_payloads)
        helper_gets = [event for event in gets if event["peer"] == selected.identity and event["object_id"] == helper["object"]["proof_id"]]
        assert helper_gets and all(event["root_id"] == child["object"]["proof_id"] for event in helper_gets)
        assert len(stored_objects(selected)) == 3 and stored_objects(absent) == []
        responses = [event for event in selected.events if event.get("event") == "exchange_response" and event.get("kind") == "object"]
        if self.mode == "relay":
            assert responses and all(event["relayed"] is True for event in responses)
            proof_connections = [event for event in selected.events if event.get("event") == "connected" and event.get("peer") != self.relay.identity]
            assert proof_connections and all(event["relayed"] is True for event in proof_connections)
        else:
            assert responses and all(event["relayed"] is False for event in responses)
        self.summary["scenarios"]["receiver_first_inventory_gossip_offer_selection"] = {
            "result": "pass", "absent_interest_payload_count": 0,
            "declined_proof_payload_count": 0, "selected_ids": sorted(expected),
            "helper_payloads": helper_payloads, "object_responses": responses,
            "payload_requests": gets,
            "declined_question_skipped": declined_id,
        }
        selected.stop()
        self.start_participant(selected, allowlist)
        self.wait_set(selected, expected)
        assert len(stored_objects(selected)) == 3
        self.summary["scenarios"]["selected_parent_closure_restart"] = {"result": "pass", "ids": sorted(expected)}
        # Both suppliers hold the same real certificate. Only the supplier
        # advertising an unrelated statement/question pair is initially live;
        # its observed decline must not prevent a later correct supplier.
        selected.stop()
        actual = sender.command("test_compile", source=source(31))["object"]
        unrelated = sender.command("test_compile", source=source(32))["object"]
        for supplier in [sender, absent]:
            supplier.command("ingest", object=actual)
        bad, good = sorted([sender, absent], key=lambda node: node.identity)
        wrong = {"proof_id": actual["proof_id"], "statement_id": unrelated["statement_id"], "question": question_source(source(32))}
        bad.command("test_descriptor", metadata=wrong)
        # A live Good can finish fetching before Bad is identified, especially
        # in release builds. Isolate the initial probe in both transport modes.
        good.stop()
        bad_offset, good_offset = len(bad.events), len(good.events)
        selected_offset = len(selected.events)
        self.start_participant(selected, allowlist)
        bad.wait_event(lambda event: event.get("event") == "exchange_request" and event.get("kind") == "describe" and event.get("peer") == selected.identity and event.get("object_id") == actual["proof_id"], since=bad_offset)
        selected.wait_event(lambda event: event.get("event") == "proof_skipped" and event.get("id") == actual["proof_id"], since=selected_offset)
        assert not any(event.get("event") == "exchange_request" and event.get("kind") == "get" and event.get("peer") == selected.identity and event.get("object_id") == actual["proof_id"] for event in bad.events[bad_offset:])
        assert set(selected.command("status")["ids"]) == set(expected)
        self.start_participant(good, "all" if good is sender else None)
        expected.append(actual["proof_id"])
        self.wait_set(selected, expected)
        bad_describes = [event for event in bad.events[bad_offset:] if event.get("event") == "exchange_request" and event.get("kind") == "describe" and event.get("peer") == selected.identity and event.get("object_id") == actual["proof_id"]]
        good_describes = [event for event in good.events[good_offset:] if event.get("event") == "exchange_request" and event.get("kind") == "describe" and event.get("peer") == selected.identity and event.get("object_id") == actual["proof_id"]]
        good_gets = [event for event in good.events[good_offset:] if event.get("event") == "exchange_request" and event.get("kind") == "get" and event.get("peer") == selected.identity and event.get("object_id") == actual["proof_id"]]
        assert bad_describes and good_describes and good_gets
        assert bad_describes[0]["observed_monotonic"] < good_describes[0]["observed_monotonic"]
        assert not any(event.get("event") == "exchange_request" and event.get("kind") == "get" and event.get("peer") == selected.identity and event.get("object_id") == actual["proof_id"] for event in bad.events[bad_offset:])
        assert len(stored_objects(selected)) == 4
        self.summary["scenarios"]["false_description_preserves_correct_supplier_rotation"] = {
            "result": "pass", "proof_id": actual["proof_id"], "bad_supplier": bad.identity,
            "good_supplier": good.identity, "bad_describes": bad_describes,
            "good_describes": good_describes, "good_gets": good_gets, "bad_get_count": 0}
        if self.mode == "direct":
            sender.command("links", peers=[])
            # Local mathematical production is preserved beyond question limits.
            formula = "equal(x0,x0)"
            steps = ["p0 = equality_reflexivity(x0)"]
            for index in range(34):
                formula = f"forall(x{index},{formula})"
                steps.append(f"p{index + 1} = generalization(p{index},x{index})")
            result = sender.command("produce", source=f'foundation = "naome:zfc" statement = {formula} proof: ' + " ".join(steps) + " return p34")
            assert result["result"]["status"] == "accepted"
            assert result["metadata"] is None and "question" in result["metadata_error"]
            assert result["object"]["proof_id"] in sender.command("status")["ids"]
            self.summary["scenarios"]["local_producer_outside_question_codec"] = {"result": "pass", "accepted_id": result["object"]["proof_id"], "metadata_error": result["metadata_error"]}
        self.assert_caps()
        self.summary["accepted_ids"] = sorted(expected)
        self.summary["result"] = "pass"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
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
