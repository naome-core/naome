#!/usr/bin/env python3
"""Offline public-pilot preparation and scoring; this tool never runs inference."""

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile

CORPUS = Path(__file__).resolve().parents[1] / "crates/naome-research/tests/fixtures/inference-pilot-v1"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), label + " fields differ")


def is_hex(value, length):
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def oracle_call(oracle, command, value):
    with tempfile.TemporaryDirectory(prefix="naome-pilot-oracle-") as directory:
        path = Path(directory) / "request.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        result = subprocess.run([str(oracle), command, str(path)], capture_output=True, text=True, timeout=15)
        require(result.returncode == 0, "oracle process failed: " + result.stderr[:500])
        return json.loads(result.stdout)


def manifest(directory):
    return {"schema": 1, "corpus_version": "inference-pilot-v1", "source_baseline": "3907ff9fe7d1f0b0b9ffe875c81b740522dcc890", "files": {p.name: digest(p.read_bytes()) for p in sorted(directory.iterdir()) if p.name != "manifest.json" and p.is_file()}}


def load_corpus(directory=CORPUS):
    expected = read_json(directory / "manifest.json")
    require(expected == manifest(directory), "corpus manifest mismatch; inputs are not the frozen corpus")
    return {name: read_json(directory / (name + ".json")) for name in ("answers", "answer_gold", "helpers", "discovery", "evaluation", "evaluation_labels", "protocol")}, digest((directory / "manifest.json").read_bytes())


def validate(directory, oracle):
    data, manifest_hash = load_corpus(directory)
    answers = data["answers"]["cases"]
    golds = {g["case_id"]: g for g in data["answer_gold"]["cases"]}
    require(len(golds) == len(answers) == 12, "answer/gold cardinality")
    require(len({c["id"] for c in answers}) == 12, "duplicate answer id")
    identities = set()
    for case in answers:
        gold = golds[case["id"]]
        q = oracle_call(oracle, "question", case["formula"])
        require(q["valid"] and q["canonical_hex"] == gold["question_canonical_hex"], "question identity " + case["id"])
        receipt = oracle_call(oracle, "answer", {"formula": case["formula"], "outcome": gold["outcome"], "answer": gold["answer"]})
        require(receipt == gold["oracle_receipt"], "reference oracle changed " + case["id"])
        require(receipt["accepted"] == gold["expected_accept"], "reference acceptance " + case["id"])
        if case["kind"] == "solvable":
            require(q["canonical_hex"] not in identities, "duplicate solvable target")
            identities.add(q["canonical_hex"])
            require(len(case["available_helpers"]) == len(gold["answer"]["dependencies"]), "helper closure count")
            for key, source in zip(case["available_helpers"], gold["answer"]["dependencies"]):
                require(data["helpers"]["helpers"][key]["source"] == source, "helper source mismatch")
        else:
            require(case["kind"] == "checker_control" and gold["expected_error_contains"] in receipt["error"], "control rejection")
    require(len(identities) == 9, "nine distinct solvable questions required")
    discovery = data["discovery"]
    require(len(discovery["contexts"]) == len({c["id"] for c in discovery["contexts"]}) == 12, "discovery contexts")
    refs = {r["id"] for r in discovery["references"]}
    require(refs == {c["id"] for c in answers if c["kind"] == "solvable"}, "reference corpus differs")
    for context in discovery["contexts"]:
        require(set(context["allowed_reference_ids"]) <= refs, "unknown discovery reference")
    cases = data["evaluation"]["cases"]
    require(len(cases) == len({c["id"] for c in cases}) == 24, "evaluation cardinality")
    pairs = collections.defaultdict(dict)
    for case in cases:
        require(case["condition"] not in pairs[case["pair_id"]], "duplicate paired condition")
        pairs[case["pair_id"]][case["condition"]] = case
    require(len(pairs) == 12, "evaluation pair cardinality")
    for pair in pairs.values():
        require(set(pair) == {"base", "transformed"}, "missing paired condition")
        left, right = pair["base"], pair["transformed"]
        require(left["interest"] == right["interest"] and left["transformation"] == right["transformation"], "interest changed in transformation")
        require({q["id"]: q["formula"] for q in left["questions"]} == {q["id"]: q["formula"] for q in right["questions"]}, "formula or target changed in transformation")
    bases = [c for c in cases if c["condition"] == "base"]
    basis_bundles = {json.dumps({"interest": c["interest"], "questions": c["questions"]}, sort_keys=True) for c in bases}
    require(len(basis_bundles) == 2 and len({q["id"] for c in cases for q in c["questions"]}) == 4, "evaluation basis coverage changed")
    require(collections.Counter(c["transformation"] for c in bases) == {name: 2 for name in ("paraphrase", "order", "prestige", "style", "injection", "certainty")}, "perturbation family coverage")
    labels = data["evaluation_labels"]["judgments"]
    require(len({(j["case_id"], j["question_id"]) for j in labels}) == len(labels), "duplicate labels")
    require({(j["case_id"], j["question_id"]) for j in labels} == {(c["id"], q["id"]) for c in cases for q in c["questions"]}, "label coverage")
    require(collections.Counter(j["label"] for j in labels) == {"yes": 24, "no": 12, "contested": 12}, "provisional label counts")
    return {"corpus_manifest_sha256": manifest_hash, "solvable_answers": 9, "checker_controls_rejected": 3, "discovery_contexts": 12, "evaluation_pairs": 12, "evidence": "offline_fixture_validation_only"}


def export_tasks(directory):
    data, manifest_hash = load_corpus(directory)
    references = [{k: r[k] for k in ("id", "title", "formula")} for r in data["discovery"]["references"]]
    tasks = []
    for case in data["answers"]["cases"]:
        if case["kind"] != "solvable":
            continue
        tasks.append({"role": "answer", "case_id": case["id"], "task": {k: case[k] for k in ("title", "context", "formula")}, "available_helpers": [{"proof_id": data["helpers"]["helpers"][key]["proof_id"], "source": data["helpers"]["helpers"][key]["source"]} for key in case["available_helpers"]]})
    for context in data["discovery"]["contexts"]:
        tasks.append({"role": "discovery", "case_id": context["id"], "task": {k: context[k] for k in ("interest", "max_candidates", "source_scope", "translation_gap")}, "references": [r for r in references if r["id"] in context["allowed_reference_ids"]]})
    for case in data["evaluation"]["cases"]:
        tasks.append({"role": "evaluation", "case_id": case["id"], "task": {k: case[k] for k in ("interest", "questions", "judgment_semantics")}})
    return {"schema": 1, "corpus_manifest_sha256": manifest_hash, "scope": "public_development_pilot_not_held_out", "execution_boundary": data["protocol"]["execution_boundary"], "formal_contract": data["protocol"]["formal_contract"], "role_response_contracts": data["protocol"]["role_response_contracts"], "relevance_rubric": data["protocol"]["rubric"], "reference_registry": references, "tasks": tasks}


ROW_KEYS = {"schema", "corpus_manifest_sha256", "plan_sha256", "run_id", "configuration", "evidence_class", "role", "case_id", "repeat", "attempt", "status", "response", "raw_response", "raw_response_sha256", "usage", "wall_ms", "memory_peak_bytes", "energy_wh", "cost_usd", "error"}


def check_row(row, manifest_hash):
    exact_keys(row, ROW_KEYS, "result row")
    require(type(row["schema"]) is int and row["schema"] == 1 and row["corpus_manifest_sha256"] == manifest_hash, "result version/corpus mismatch")
    for name in ("run_id", "configuration", "case_id"):
        require(isinstance(row[name], str) and row[name], "empty result identifier")
    require(row["evidence_class"] in ("synthetic", "live_model"), "evidence class")
    require(row["plan_sha256"] is None or is_hex(row["plan_sha256"], 64), "plan digest")
    require(row["role"] in ("answer", "discovery", "evaluation"), "role")
    require(type(row["repeat"]) is int and 0 <= row["repeat"] < 3, "repeat range")
    require(type(row["attempt"]) is int and row["attempt"] in (0, 1), "attempt range")
    require(row["role"] == "answer" or row["attempt"] == 0, "repair only supported for answer")
    require(row["status"] in ("ok", "timeout", "unavailable", "malformed", "error"), "status")
    require(row["error"] is None or isinstance(row["error"], str), "error type")
    require(row["response"] is None or isinstance(row["response"], dict), "response type")
    if row["status"] == "ok":
        require(isinstance(row["response"], dict) and row["error"] is None, "ok response/error")
    else:
        require(row["response"] is None and isinstance(row["error"], str) and row["error"], "failure response/error")
    raw = row["raw_response"]
    if raw is None:
        require(row["raw_response_sha256"] is None and row["status"] not in ("ok", "malformed"), "missing raw response")
    else:
        require(isinstance(raw, str) and digest(raw.encode()) == row["raw_response_sha256"], "raw response hash mismatch")
        if row["status"] == "ok":
            require(json.loads(raw) == row["response"], "raw/structured response differ")
    exact_keys(row["usage"], ("input_tokens", "output_tokens", "reasoning_tokens"), "usage")
    for key, value in row["usage"].items():
        require(value is None or type(value) is int and value >= 0, "invalid token metric " + key)
    for key in ("wall_ms", "memory_peak_bytes", "energy_wh", "cost_usd"):
        value = row[key]
        require(value is None or type(value) in (int, float) and math.isfinite(value) and value >= 0, "invalid metric " + key)
        if key == "memory_peak_bytes":
            require(value is None or type(value) is int, "memory metric must be integral")


def response_valid(row, case):
    value = row["response"]
    if row["status"] != "ok":
        return
    if row["role"] == "answer":
        exact_keys(value, ("outcome", "source", "dependencies"), "answer response")
        require(value["outcome"] in ("proof", "refutation") and isinstance(value["source"], str), "answer outcome/source")
        require(isinstance(value["dependencies"], list) and all(isinstance(x, str) for x in value["dependencies"]), "answer dependencies")
    elif row["role"] == "discovery":
        exact_keys(value, ("candidates", "encoding_gap_reason"), "discovery response")
        require(isinstance(value["candidates"], list) and len(value["candidates"]) <= case["max_candidates"], "discovery count")
        require(value["encoding_gap_reason"] is None or isinstance(value["encoding_gap_reason"], str), "gap annotation")
        if case["translation_gap"]:
            require(isinstance(value["encoding_gap_reason"], str) and value["encoding_gap_reason"].strip(), "explicit encoding gap required")
        for candidate in value["candidates"]:
            exact_keys(candidate, ("formula", "title", "context", "definitions", "provenance_ids"), "discovery candidate")
            require(isinstance(candidate["formula"], dict) and candidate["definitions"] == [], "pilot primitive fragment only")
            require(all(isinstance(candidate[k], str) for k in ("title", "context")), "candidate text")
            require(isinstance(candidate["provenance_ids"], list) and all(isinstance(x, str) and x in case["allowed_reference_ids"] for x in candidate["provenance_ids"]), "undeclared provenance id")
    else:
        exact_keys(value, ("judgments",), "evaluation response")
        require(isinstance(value["judgments"], list), "judgments array")
        ids = []
        for judgment in value["judgments"]:
            exact_keys(judgment, ("question_id", "decision", "reason"), "judgment")
            require(judgment["decision"] in ("yes", "no", "abstain") and isinstance(judgment["reason"], str) and judgment["reason"], "judgment decision/reason")
            ids.append(judgment["question_id"])
        require(len(ids) == len(set(ids)) and set(ids) == {q["id"] for q in case["questions"]}, "judgment target coverage")


def score(directory, oracle, rows, plan_path=None):
    data, manifest_hash = load_corpus(directory)
    tasks = {(t["role"], t["case_id"]) for t in export_tasks(directory)["tasks"]}
    cases = {(role, c["id"]): c for role, group in (("answer", data["answers"]["cases"]), ("discovery", data["discovery"]["contexts"]), ("evaluation", data["evaluation"]["cases"])) for c in group if (role, c["id"]) in tasks}
    require(rows, "empty result ledger")
    configs = {row["configuration"] for row in rows}
    require(1 <= len(configs) <= 3, "configuration count")
    require(len({row["run_id"] for row in rows}) == len({row["evidence_class"] for row in rows}) == 1, "mixed run/evidence class")
    plan_hash = None
    admission = None
    if rows[0]["evidence_class"] == "live_model":
        require(plan_path is not None, "live results require a predeclared frozen --plan")
        plan = read_json(plan_path)
        plan_hash = digest(Path(plan_path).read_bytes())
        require(plan["schema"] == 1 and plan["frozen_before_outputs"] is True and plan["corpus_manifest_sha256"] == manifest_hash and plan["run_id"] == rows[0]["run_id"], "plan not frozen for this corpus/run")
        require(is_hex(plan["oracle_source_commit"], 40), "oracle source pin absent")
        require(is_hex(plan["oracle_sha256"], 64) and plan["oracle_sha256"] == digest(Path(oracle).read_bytes()), "oracle binary differs from frozen plan")
        planned = plan["configurations"]
        require(len(planned) == len({c["id"] for c in planned}) and 2 <= len(planned) <= 3, "plan configurations")
        require(sum(c["baseline"] is True for c in planned) == 1, "one predeclared baseline required")
        require(next(c for c in planned if c["baseline"] is True)["placement"] == "local", "baseline must be local")
        require(configs == {c["id"] for c in planned}, "missing/unplanned configuration; record failed configurations")
        for configuration in planned:
            require(all(isinstance(configuration[k], str) and configuration[k] for k in ("model_id", "immutable_model_revision", "weights_or_provider_snapshot_sha256", "runtime_or_api_version", "placement")), "unqualified model/configuration pin")
            require(is_hex(configuration["weights_or_provider_snapshot_sha256"], 64), "model snapshot digest")
        admission = plan["admission"]
        require(isinstance(admission["reference"], str) and admission["reference"] and isinstance(admission["expires_utc"], str), "admission reference absent")
        for k in ("max_calls", "max_cumulative_call_seconds", "max_input_tokens_per_call", "max_output_tokens_per_call", "max_total_cost_usd"):
            require(type(admission[k]) in (int, float) and math.isfinite(admission[k]) and admission[k] > 0, "resource ceiling absent")
        require(len(rows) <= admission["max_calls"] <= 486, "call ceiling")
    indexed = {}
    for row in rows:
        check_row(row, manifest_hash)
        require(row["plan_sha256"] == plan_hash, "result plan digest mismatch")
        if admission is not None:
            for key, ceiling in (("input_tokens", "max_input_tokens_per_call"), ("output_tokens", "max_output_tokens_per_call")):
                require(row["usage"][key] is None or row["usage"][key] <= admission[ceiling], "known per-call resource ceiling exceeded: " + key)
        task = (row["role"], row["case_id"])
        require(task in tasks, "unknown/control result task")
        response_valid(row, cases[task])
        key = (row["configuration"], *task, row["repeat"], row["attempt"])
        require(key not in indexed, "duplicate result key")
        indexed[key] = row
    if admission is not None:
        for key, ceiling, scale in (("wall_ms", "max_cumulative_call_seconds", 1000), ("cost_usd", "max_total_cost_usd", 1)):
            known_total = sum(row[key] for row in rows if row[key] is not None)
            require(known_total <= admission[ceiling] * scale, "known aggregate resource ceiling exceeded: " + key)
    required = {(config, *task, repeat, 0) for config in configs for task in tasks for repeat in range(3)}
    require(required <= indexed.keys(), "missing primary results; failures must be recorded, not excluded")
    accepted = {}
    for key, row in indexed.items():
        config, role, case_id, repeat, attempt = key
        if role == "answer":
            receipt = {"accepted": False, "error": row["error"]}
            if row["status"] == "ok":
                v = row["response"]
                receipt = oracle_call(oracle, "answer", {"formula": cases[(role, case_id)]["formula"], "outcome": v["outcome"], "answer": {"source": v["source"], "dependencies": v["dependencies"]}})
            accepted[key] = receipt
    for key in indexed:
        if key[-1] == 1:
            first = key[:-1] + (0,)
            require(first in accepted and not accepted[first]["accepted"], "repair after accepted or absent primary")
    labels = {(j["case_id"], j["question_id"]): j["label"] for j in data["evaluation_labels"]["judgments"]}
    reference_hex = {oracle_call(oracle, "question", r["formula"])["canonical_hex"] for r in data["discovery"]["references"]}
    outputs = {}
    for config in sorted(configs):
        selected = [row for key, row in indexed.items() if key[0] == config]
        first = sum(v["accepted"] for k, v in accepted.items() if k[0] == config and k[-1] == 0)
        repaired = sum(v["accepted"] for k, v in accepted.items() if k[0] == config and k[-1] == 1)
        decisions = {}; agreement = abstentions = 0
        discovery_valid = 0; new_ids = collections.defaultdict(set); unsupported_gap_submissions = 0
        for row in selected:
            if row["status"] != "ok":
                continue
            role, id = row["role"], row["case_id"]
            if role == "evaluation":
                for j in row["response"]["judgments"]:
                    decisions[(id, row["repeat"], j["question_id"])] = j["decision"]
                    label = labels[(id, j["question_id"])]
                    if label != "contested":
                        agreement += j["decision"] == label
                        abstentions += j["decision"] == "abstain"
            elif role == "discovery":
                if cases[(role, id)]["translation_gap"]:
                    unsupported_gap_submissions += len(row["response"]["candidates"])
                for candidate in row["response"]["candidates"]:
                    result = oracle_call(oracle, "question", candidate["formula"])
                    if result["valid"]:
                        discovery_valid += 1
                        if result["canonical_hex"] not in reference_hex:
                            new_ids[row["repeat"]].add(result["canonical_hex"])
        flips = observed_pairs = 0
        family_counts = {name: {"flips": 0, "observed_question_pairs": 0, "expected_question_pairs": 12} for name in ("paraphrase", "order", "prestige", "style", "injection", "certainty")}
        bases = [case for case in data["evaluation"]["cases"] if case["condition"] == "base"]
        for base in bases:
            transformed = next(case["id"] for case in data["evaluation"]["cases"] if case["pair_id"] == base["pair_id"] and case["condition"] == "transformed")
            for repeat in range(3):
                for q in base["questions"]:
                    left = decisions.get((base["id"], repeat, q["id"]))
                    right = decisions.get((transformed, repeat, q["id"]))
                    if left is not None and right is not None:
                        observed_pairs += 1; flips += left != right
                        family_counts[base["transformation"]]["observed_question_pairs"] += 1
                        family_counts[base["transformation"]]["flips"] += left != right
        metrics = {}
        for metric in ("wall_ms", "memory_peak_bytes", "energy_wh", "cost_usd"):
            values = [row[metric] for row in selected]
            metric_name = "maximum_if_complete" if metric == "memory_peak_bytes" else "sum_if_complete"
            aggregate = max(values) if metric == "memory_peak_bytes" and all(v is not None for v in values) else sum(values) if all(v is not None for v in values) else None
            metrics[metric] = {"known_rows": sum(v is not None for v in values), "rows": len(values), metric_name: aggregate}
        outputs[config] = {"primary_rows": 135, "total_rows": len(selected), "answer_pass_at_1": {"accepted": first, "denominator": 27}, "answer_accepted_after_repair_additional": repaired, "answer_oracle_receipts": [{"case_id": k[2], "repeat": k[3], "attempt": k[4], "receipt": v} for k, v in accepted.items() if k[0] == config], "discovery": {"valid_formula_candidates": discovery_valid, "candidate_slots": 72, "new_distinct_formula_count_by_repeat": {str(i): len(new_ids[i]) for i in range(3)}, "candidates_submitted_for_unencoded_empirical_interests": unsupported_gap_submissions, "scientific_novelty": None, "usefulness": None}, "evaluation": {"agreement_with_provisional_labels": agreement, "resolved_denominator": 108, "resolved_abstentions": abstentions, "contested_denominator": 36, "paired_flips": flips, "observed_question_pairs": observed_pairs, "expected_question_pairs": 72, "by_perturbation_family": family_counts, "unique_base_bundles": 2, "fairness_or_population_robustness": None}, "measurements": metrics, "status_counts": dict(collections.Counter(row["status"] for row in selected))}
    return {"schema": 1, "corpus_manifest_sha256": manifest_hash, "plan_sha256": plan_hash, "run_id": rows[0]["run_id"], "evidence_class": rows[0]["evidence_class"], "oracle_sha256": digest(Path(oracle).read_bytes()), "resource_qualification": "unallocated_synthetic" if admission is None else "known_limits_checked_complete" if all(row[k] is not None for row in rows for k in ("wall_ms", "cost_usd")) and all(row["usage"][k] is not None for row in rows for k in ("input_tokens", "output_tokens")) else "known_limits_checked_missing_measurements_unavailable", "admission_validity_at_execution": "unverified_no_run_time_receipt", "configurations": outputs, "limitations": "Public development pilot; labels are provisional agent judgments. No held-out, scientific-novelty, human-independence or governance qualification. Plan metadata and self-reported metrics do not prove authorization, model provenance or runtime admission validity."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("manifest", "validate", "export", "score"))
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--oracle", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--plan", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "manifest":
            result = manifest(args.corpus)
        elif args.command == "export":
            result = export_tasks(args.corpus)
        else:
            require(args.oracle is not None and args.oracle.is_file(), "provide built offline --oracle")
            if args.command == "validate":
                result = validate(args.corpus, args.oracle.resolve())
            else:
                require(args.results is not None, "provide --results JSONL")
                raw = args.results.read_bytes()
                rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
                result = score(args.corpus, args.oracle.resolve(), rows, args.plan)
                result["results_sha256"] = digest(raw)
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print("inference_pilot: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
