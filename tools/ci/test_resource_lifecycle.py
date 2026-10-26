"""Lifecycle oracles keep native pressure and finite work limits independent."""
import pathlib
import sys
import unittest
from unittest.mock import patch

SUPPORT = pathlib.Path(__file__).resolve().parents[2] / "crates/naome-knowledge/tests/support"
sys.path.insert(0, str(SUPPORT))
from autonomous_lifecycle import Trial
from automatic_computation import memory_recovery
from long_jobs import observe_work
from owner_interest import assert_owner_status
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
    def recover(self, reason, resumes, *, progress=False, admission=False, deadline=120):
        clock = Clock()
        self.clock = clock
        trial = RecoveryTrial(clock, reason, resumes)
        trial.deadline = deadline
        node = type("Node", (), {"ids": lambda _: {1} if admission else set()})()
        with patch("time.monotonic", side_effect=lambda: clock.now), patch("time.sleep", side_effect=clock.sleep), \
                patch("automatic_computation.checkpoints", side_effect=lambda _: {1: (2, 3 if progress else 2)}):
            self.result = memory_recovery(trial, node, {1: (2, 2)}, set())
        self.receipt = trial.summary["memory_recovery"]
        return clock.now

    def test_memory_only_recovery_keeps_its_original_40_second_bound(self):
        self.assertGreaterEqual(self.recover("memory pressure", 35), 35)
        with self.assertRaises(AssertionError):
            self.recover("memory pressure", 45)

    def test_native_cpu_hold_is_retained_without_claiming_resume(self):
        reason = lambda now: "memory pressure" if now < 10 else "sustained external CPU pressure"
        self.assertGreaterEqual(self.recover(reason, 70), 40)
        self.assertIsNone(self.result)
        self.assertEqual(self.receipt["result"], "native_cpu_hold_preserved")

    def test_cleared_native_cpu_hold_can_qualify_observed_resume(self):
        self.assertGreaterEqual(self.recover("sustained external CPU pressure", 35), 35)
        self.assertEqual(self.receipt["result"], "native_resume_observed")

    def test_cpu_hold_cannot_extend_the_original_whole_deadline(self):
        with self.assertRaises(AssertionError):
            self.recover("sustained external CPU pressure", 125, deadline=30)
        self.assertGreaterEqual(self.clock.now, 30)
        self.assertLess(self.clock.now, 30.3)

    def test_cpu_hold_never_permits_progress_or_publication(self):
        for change, message in (({"progress": True}, "productive work advanced"),
                                ({"admission": True}, "paused node published")):
            with self.subTest(change=change), self.assertRaisesRegex(AssertionError, message):
                self.recover("sustained external CPU pressure", 70, **change)


class WorkWindowTests(unittest.TestCase):
    def observe(self, capacity, *, predicate=None, deadline=90, pid=7, age=0):
        clock = Clock()
        self.clock = clock
        def observation(node):
            value = capacity(clock.now) if callable(capacity) else capacity
            return {"snapshot": {"pid": pid, "timestamp_ms": 10000 - age, "budget": {"concurrency": value,
                "paused": "sustained external CPU pressure" if value == 0 else None}}}
        trial = type("Trial", (), {"deadline": deadline, "summary": {}})()
        node = type("Node", (), {"process": {"pid": 7}})()
        with patch("time.monotonic", side_effect=lambda: clock.now), patch("time.sleep", side_effect=clock.sleep), \
                patch("time.time", return_value=10), patch("long_jobs.latest", side_effect=observation):
            result = observe_work(trial, node, "overlap", predicate or (lambda: False), 15, 3)
        self.receipt = trial.summary["work_windows"]["overlap"]
        return result

    def test_missing_progress_under_sufficient_capacity_is_still_a_failure(self):
        with self.assertRaisesRegex(AssertionError, "despite sufficient admitted capacity"):
            self.observe(3)

    def test_real_constraints_are_reported_without_claiming_overlap(self):
        for capacity in (0, 1, 2):
            with self.subTest(capacity=capacity):
                self.assertIsNone(self.observe(capacity))
                self.assertEqual(self.receipt["result"], "resource_limited")

    def test_observed_progress_after_a_constraint_is_qualified(self):
        self.assertTrue(self.observe(lambda now: 2 if now < 4 else 3,
            predicate=lambda: self.clock.now >= 5))
        self.assertEqual(self.receipt["result"], "observed")

    def test_foreign_budget_and_expired_whole_trial_are_not_constraints(self):
        with self.assertRaises(AssertionError):
            self.observe(2, pid=8)
        with self.assertRaisesRegex(AssertionError, "whole-trial deadline"):
            self.observe(2, deadline=7)
        with self.assertRaisesRegex(AssertionError, "observation is stale"):
            self.observe(2, age=5001)

    def test_predicate_failures_cannot_be_hidden_by_a_resource_constraint(self):
        def corrupt():
            raise AssertionError("incorrect proof state")
        with self.assertRaisesRegex(AssertionError, "incorrect proof state"):
            self.observe(2, predicate=corrupt)


class OwnerStatusTests(unittest.TestCase):
    def status(self, **changes):
        return {"running": True, "accepted_artifacts": 0, "interest": "exact owner text",
                "artifact_verification": "checked", "computation": "running",
                "computation_reason": None, **changes}

    def check(self, value):
        assert_owner_status(value, running=True, interest="exact owner text", accepted_artifacts=0)

    def test_pressure_transitions_preserve_the_owner_contract(self):
        for computation in ("running", "pausing", "paused"):
            self.check(self.status(computation=computation,
                computation_reason=None if computation == "running" else "sustained external CPU pressure"))

    def test_pressure_cannot_excuse_an_owner_or_proof_state_change(self):
        for change in ({"interest": "changed"}, {"running": False}, {"accepted_artifacts": 1},
                       {"artifact_verification": "not_run"}, {"unknown": 1}):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                self.check(self.status(computation="paused", computation_reason="memory pressure", **change))

    def test_computation_state_and_reason_remain_validated(self):
        for computation, reason in (("paused", None), ("pausing", ""), ("running", "memory pressure"),
                                    ("stopped", None), ("unknown", "memory pressure")):
            with self.subTest(computation=computation, reason=reason), self.assertRaises(AssertionError):
                self.check(self.status(computation=computation, computation_reason=reason))


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
