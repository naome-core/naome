"""The native feedback oracle preserves original budgets across real retries."""
import copy
import pathlib
import sys
import unittest

SUPPORT = pathlib.Path(__file__).resolve().parents[2] / "crates/naome-knowledge/tests/support"
sys.path.insert(0, str(SUPPORT))
from provider_feedback import observe_budgets


def record():
    return {
        "id": 4, "input": {"role": "interest"}, "binding": {"snapshot": "fixed"},
        "provider": "naome-deterministic-mocks-v1", "configuration": "fixed",
        "settings": {"limits": {"horizon_ms": 60000, "work_units": 64}, "mock": {"steps": 2}},
        "created_ms": 1000, "expires_ms": 61000,
        "checkpoint": 1, "reserved_units": 2, "spent_ms": 50,
    }


def observe(previous, value):
    observe_budgets(previous, {"records": {str(value["id"]): value}})


class ProviderBudgetOracleTests(unittest.TestCase):
    def test_repeated_reserved_work_remains_charged_within_the_original_allowance(self):
        previous = {}
        observe(previous, record())
        retried = record()
        retried.update(checkpoint=2, reserved_units=4, spent_ms=100)
        observe(previous, retried)
        self.assertEqual(previous[4]["reserved_units"], 4)
        self.assertEqual(previous[4]["settings"]["limits"]["work_units"], 64)

    def test_progress_or_charge_cannot_reset_and_original_identity_limits_cannot_change(self):
        previous = {}
        baseline = record()
        baseline.update(checkpoint=2, reserved_units=4, spent_ms=100)
        observe(previous, baseline)
        mutations = [
            ("checkpoint", 1), ("checkpoint", 3), ("reserved_units", 2),
            ("reserved_units", 65), ("spent_ms", 0), ("created_ms", 1001),
            ("expires_ms", 61001), ("binding", {"snapshot": "different"}),
            ("configuration", "different"), ("provider", "different"),
            ("input", {"role": "find"}),
            ("settings", {"limits": {"horizon_ms": 60000, "work_units": 128}, "mock": {"steps": 2}}),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                changed = copy.deepcopy(baseline)
                changed[field] = value
                observe(copy.deepcopy(previous), changed)


if __name__ == "__main__":
    unittest.main()
