"""Scoring controls: failures, repairs, missing data and prompt leakage."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("inference_pilot", Path(__file__).parents[1] / "inference_pilot.py")
pilot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot)


class PilotScoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, cls.hash = pilot.load_corpus()
        cls.tasks = pilot.export_tasks(pilot.CORPUS)["tasks"]
        cls.golds = {g["case_id"]: g for g in cls.data["answer_gold"]["cases"]}
        cls.labels = {(j["case_id"], j["question_id"]): j["label"] for j in cls.data["evaluation_labels"]["judgments"]}

    def ledger(self):
        rows = []
        for task in self.tasks:
            role, id = task["role"], task["case_id"]
            if role == "answer":
                response = {"outcome": self.golds[id]["outcome"], **self.golds[id]["answer"]}
            elif role == "discovery":
                response = {"candidates": [], "encoding_gap_reason": "No candidate in this synthetic control."}
            else:
                response = {"judgments": [{"question_id": q["id"], "decision": "abstain" if self.labels[(id, q["id"])] == "contested" else self.labels[(id, q["id"])], "reason": "Synthetic rubric control."} for q in task["task"]["questions"]]}
            for repeat in range(3):
                raw = json.dumps(response)
                rows.append({"schema": 1, "corpus_manifest_sha256": self.hash, "plan_sha256": None, "run_id": "unit-synthetic", "configuration": "synthetic-baseline", "evidence_class": "synthetic", "role": role, "case_id": id, "repeat": repeat, "attempt": 0, "status": "ok", "response": copy.deepcopy(response), "raw_response": raw, "raw_response_sha256": pilot.digest(raw.encode()), "usage": {"input_tokens": None, "output_tokens": None, "reasoning_tokens": None}, "wall_ms": None, "memory_peak_bytes": None, "energy_wh": None, "cost_usd": None, "error": None})
        return rows

    def fake_oracle(self, oracle, command, value):
        if command == "question":
            for case in self.data["answers"]["cases"]:
                if value == case["formula"]:
                    return {"valid": True, "canonical_hex": self.golds[case["id"]]["question_canonical_hex"]}
            raise AssertionError("Unexpected mocked formula")
        for case in self.data["answers"]["cases"]:
            gold = self.golds[case["id"]]
            if value == {"formula": case["formula"], "outcome": gold["outcome"], "answer": gold["answer"]}:
                return gold["oracle_receipt"]
        return {"accepted": False, "error": "Synthetic negative oracle control"}

    def score(self, rows):
        with patch.object(pilot, "oracle_call", self.fake_oracle):
            return pilot.score(pilot.CORPUS, Path(__file__), rows)["configurations"]["synthetic-baseline"]

    def test_reference_ledger_denominators_and_unknown_costs(self):
        result = self.score(self.ledger())
        self.assertEqual(result["answer_pass_at_1"], {"accepted": 27, "denominator": 27})
        self.assertEqual(result["evaluation"]["agreement_with_provisional_labels"], 108)
        self.assertEqual(result["evaluation"]["resolved_denominator"], 108)
        self.assertEqual(result["evaluation"]["contested_denominator"], 36)
        self.assertEqual(result["evaluation"]["paired_flips"], 0)
        self.assertEqual(result["evaluation"]["observed_question_pairs"], 72)
        self.assertIsNone(result["measurements"]["cost_usd"]["sum_if_complete"])

    def test_timeout_stays_in_answer_denominator(self):
        rows = self.ledger(); rows[0].update(status="timeout", response=None, raw_response=None, raw_response_sha256=None, error="bounded timeout")
        self.assertEqual(self.score(rows)["answer_pass_at_1"], {"accepted": 26, "denominator": 27})

    def test_repair_success_is_not_pass_at_one(self):
        rows = self.ledger(); repair = copy.deepcopy(rows[0]); repair["attempt"] = 1
        rows[0].update(status="malformed", response=None, raw_response="not JSON", raw_response_sha256=pilot.digest(b"not JSON"), error="invalid JSON")
        rows.append(repair); result = self.score(rows)
        self.assertEqual(result["answer_pass_at_1"]["accepted"], 26)
        self.assertEqual(result["answer_accepted_after_repair_additional"], 1)

    def test_repair_after_success_rejected(self):
        rows = self.ledger(); repair = copy.deepcopy(rows[0]); repair["attempt"] = 1; rows.append(repair)
        with self.assertRaisesRegex(ValueError, "repair after accepted"):
            self.score(rows)

    def test_missing_duplicate_and_control_rows_rejected(self):
        rows = self.ledger()
        for changed, error in ((rows[1:], "missing primary"), (rows + [rows[0]], "duplicate result")):
            with self.assertRaisesRegex(ValueError, error): self.score(changed)
        rows[0]["case_id"] = "C01"
        with self.assertRaisesRegex(ValueError, "unknown/control"): self.score(rows)

    def test_raw_response_binding_and_metric_types(self):
        for field, value, error in (("raw_response_sha256", "0" * 64, "raw response hash"), ("cost_usd", float("nan"), "invalid metric"), ("memory_peak_bytes", 1.5, "must be integral")):
            rows = self.ledger(); rows[0][field] = value
            with self.assertRaisesRegex(ValueError, error): self.score(rows)
        rows = self.ledger(); rows[0]["usage"]["input_tokens"] = True
        with self.assertRaisesRegex(ValueError, "invalid token metric"): self.score(rows)

    def test_export_has_no_gold_control_or_label_fields(self):
        exported = pilot.export_tasks(pilot.CORPUS)
        self.assertEqual(len(exported["tasks"]), 45)
        self.assertFalse(any(t["case_id"].startswith("C") for t in exported["tasks"]))
        forbidden = ("oracle_receipt", "canonical_proof_hex", "expected_accept", "expected_error_contains", "outcome", "label_source", "pair_id", "condition", "provenance")
        self.assertNotIn('"provenance"', json.dumps(exported))
        self.assertNotIn('Refute the universal denial', json.dumps(exported))
        for task in exported["tasks"]:
            if task["role"] in ("answer", "evaluation"):
                text = json.dumps(task)
                for key in forbidden: self.assertNotIn('"' + key + '"', text)

    def test_role_contracts_and_explicit_encoding_gap(self):
        exported = pilot.export_tasks(pilot.CORPUS)
        contracts = exported["role_response_contracts"]
        self.assertEqual(set(contracts), {"common", "answer", "discovery", "evaluation"})
        rows = self.ledger()
        row = next(r for r in rows if r["case_id"] == "D11")
        row["response"]["encoding_gap_reason"] = None
        row["raw_response"] = json.dumps(row["response"])
        row["raw_response_sha256"] = pilot.digest(row["raw_response"].encode())
        with self.assertRaisesRegex(ValueError, "explicit encoding gap"):
            self.score(rows)
        task = next(t for t in exported["tasks"] if t["case_id"] == "D11")
        self.assertEqual(task["task"]["max_candidates"], 2)
        self.assertNotIn("required_candidates", task["task"])

    def test_tampered_corpus_rejected_before_export(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for source in pilot.CORPUS.iterdir():
                (target / source.name).write_bytes(source.read_bytes())
            (target / "answers.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "manifest mismatch"):
                pilot.export_tasks(target)

    def test_missing_evaluation_judgment_cannot_shrink_denominator(self):
        rows = self.ledger(); row = next(r for r in rows if r["role"] == "evaluation")
        row["response"]["judgments"].pop(); row["raw_response"] = json.dumps(row["response"]); row["raw_response_sha256"] = pilot.digest(row["raw_response"].encode())
        with self.assertRaisesRegex(ValueError, "judgment target coverage"):
            self.score(rows)

    def test_live_ledger_needs_a_frozen_plan_and_all_configurations(self):
        rows = self.ledger()
        for row in rows:
            row["evidence_class"] = "live_model"
        with self.assertRaisesRegex(ValueError, "predeclared frozen"):
            self.score(rows)
        plan = pilot.read_json(pilot.CORPUS / "run-plan.template.json")
        plan.update(run_id="unit-synthetic", corpus_manifest_sha256=self.hash, oracle_source_commit="a" * 40, oracle_sha256=pilot.digest(Path(__file__).read_bytes()), frozen_before_outputs=True)
        plan["admission"] = {"reference": "synthetic-schema-test-only", "expires_utc": "2099-01-01T00:00:00Z", "max_calls": 324, "max_cumulative_call_seconds": 3600, "max_input_tokens_per_call": 8000, "max_output_tokens_per_call": 2000, "max_total_cost_usd": 10}
        for configuration in plan["configurations"]:
            configuration.update(model_id="synthetic", immutable_model_revision="synthetic-v1", weights_or_provider_snapshot_sha256="a" * 64, runtime_or_api_version="synthetic")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"; path.write_text(json.dumps(plan))
            for row in rows:
                row.update(configuration="local-baseline", plan_sha256=pilot.digest(path.read_bytes()))
            with patch.object(pilot, "oracle_call", self.fake_oracle):
                with self.assertRaisesRegex(ValueError, "missing/unplanned configuration"):
                    pilot.score(pilot.CORPUS, Path(__file__), rows, path)
                other = copy.deepcopy(rows)
                for row in other: row["configuration"] = "hosted-candidate"
                result = pilot.score(pilot.CORPUS, Path(__file__), rows + other, path)
                self.assertEqual(set(result["configurations"]), {"local-baseline", "hosted-candidate"})
                self.assertEqual(result["admission_validity_at_execution"], "unverified_no_run_time_receipt")
                self.assertIn("missing_measurements", result["resource_qualification"])
                for field, value in (("wall_ms", 3_600_001), ("cost_usd", 11)):
                    changed = copy.deepcopy(rows + other); changed[0][field] = value
                    with self.assertRaisesRegex(ValueError, "aggregate resource ceiling"):
                        pilot.score(pilot.CORPUS, Path(__file__), changed, path)
                changed = copy.deepcopy(rows + other); changed[0]["usage"]["input_tokens"] = 8001
                with self.assertRaisesRegex(ValueError, "per-call resource ceiling"):
                    pilot.score(pilot.CORPUS, Path(__file__), changed, path)
                for field, value, error in (("weights_or_provider_snapshot_sha256", "z" * 64, "model snapshot digest"), ("oracle_sha256", "0" * 64, "oracle binary differs")):
                    invalid_plan = copy.deepcopy(plan)
                    if field == "oracle_sha256": invalid_plan[field] = value
                    else: invalid_plan["configurations"][0][field] = value
                    path.write_text(json.dumps(invalid_plan))
                    with self.assertRaisesRegex(ValueError, error):
                        pilot.score(pilot.CORPUS, Path(__file__), rows + other, path)


if __name__ == "__main__":
    unittest.main()
