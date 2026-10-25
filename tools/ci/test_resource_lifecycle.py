"""Lifecycle oracles keep native pressure and finite work limits independent."""
import pathlib
import sys
import unittest
from unittest.mock import patch

SUPPORT = pathlib.Path(__file__).resolve().parents[2] / "crates/naome-knowledge/tests/support"
sys.path.insert(0, str(SUPPORT))
from autonomous_lifecycle import Trial
from automatic_computation import memory_recovery
from proof_network_discovery import contact_retired


class Clock:
    now = 0.0

    def sleep(self, seconds):
        self.now += seconds


class RecoveryTrial:
    remaining = Trial.remaining
    wait = Trial.wait
    deadline = 120.0

    def __init__(self, clock, reason, resumes):
        self.clock, self.reason, self.resumes = clock, reason, resumes
        self.summary = {}

    def call(self, node, command):
        running = self.clock.now >= self.resumes
        reason = self.reason(self.clock.now) if callable(self.reason) else self.reason
        return {"running": True, "computation": "running" if running else "paused",
                "computation_reason": None if running else reason}


class ResourceLifecycleTests(unittest.TestCase):
    def recover(self, reason, resumes, *, progress=False, admission=False):
        clock = Clock()
        self.clock = clock
        trial = RecoveryTrial(clock, reason, resumes)
        node = type("Node", (), {"ids": lambda _: {1} if admission else set()})()
        with patch("time.monotonic", side_effect=lambda: clock.now), patch("time.sleep", side_effect=clock.sleep), \
                patch("automatic_computation.checkpoints", side_effect=lambda _: {1: (2, 3 if progress else 2)}):
            memory_recovery(trial, node, {1: (2, 2)}, set())
        return clock.now

    def test_memory_only_recovery_keeps_its_original_40_second_bound(self):
        self.assertGreaterEqual(self.recover("memory pressure", 35), 35)
        with self.assertRaises(AssertionError):
            self.recover("memory pressure", 45)

    def test_additional_cpu_hold_may_outlast_memory_recovery(self):
        reason = lambda now: "memory pressure" if now < 10 else "sustained external CPU pressure"
        self.assertGreaterEqual(self.recover(reason, 70), 70)

    def test_cpu_hold_cannot_extend_the_original_whole_deadline(self):
        with self.assertRaises(AssertionError):
            self.recover("sustained external CPU pressure", 125)
        self.assertGreaterEqual(self.clock.now, 120)
        self.assertLess(self.clock.now, 120.1)

    def test_cpu_hold_never_permits_progress_or_publication(self):
        for change, message in (({"progress": True}, "productive work advanced"),
                                ({"admission": True}, "paused node published")):
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, message):
                self.recover("sustained external CPU pressure", 70, **change)


class ContactRetirementTests(unittest.TestCase):
    def test_a_peer_never_observed_in_this_process_is_already_absent(self):
        self.assertTrue(contact_retired({"contacts": []}, [], "stale", False))
        self.assertFalse(contact_retired({"contacts": []}, [], "stale", True))

    def test_an_expiration_event_never_excuses_a_current_contact(self):
        events = [{"event": "contact_expired", "peer": "stale"}]
        for known in (False, True):
            self.assertFalse(contact_retired({"contacts": [{"peer": "stale"}]}, events, "stale", known))

    def test_an_observed_contact_requires_its_own_expiration_event(self):
        self.assertFalse(contact_retired({"contacts": []}, [
            {"event": "contact_expired", "peer": "other"}], "stale", True))
        self.assertTrue(contact_retired({"contacts": []}, [
            {"event": "contact_expired", "peer": "stale"}], "stale", True))


if __name__ == "__main__":
    unittest.main()
