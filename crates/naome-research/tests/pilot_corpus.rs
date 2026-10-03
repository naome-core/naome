//! Public pilot fixtures exercise checker boundaries, not model performance.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use naome_checker::ArtifactState;
use naome_research::formal::{AnswerFile, FormulaInput, Outcome, check_answer};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cases {
    schema: u32,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    kind: String,
    stratum: String,
    title: String,
    context: String,
    formula: FormulaInput,
    available_helpers: Vec<String>,
    provenance: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Golds {
    schema: u32,
    label_source: String,
    cases: Vec<Gold>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Gold {
    case_id: String,
    outcome: Outcome,
    answer: AnswerFile,
    expected_accept: bool,
    expected_error_contains: Option<String>,
    question_canonical_hex: String,
    oracle_receipt: Value,
}

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/inference-pilot-v1")
}

fn load<T: serde::de::DeserializeOwned>(name: &str) -> T {
    serde_json::from_slice(&fs::read(directory().join(name)).unwrap()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn pilot_manifest_binds_every_input_byte() {
    let manifest: Value = load("manifest.json");
    assert_eq!(manifest["schema"], 1);
    let files = manifest["files"].as_object().unwrap();
    let actual: BTreeSet<_> = fs::read_dir(directory())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "manifest.json")
        .collect();
    assert_eq!(actual, files.keys().cloned().collect());
    for (name, digest) in files {
        assert!(!name.contains('/') && !name.contains('\\'));
        let bytes = fs::read(directory().join(name)).unwrap();
        assert_eq!(
            hex(&Sha256::digest(bytes)),
            digest.as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn pilot_reference_answers_and_rejection_controls_reproduce() {
    let cases: Cases = load("answers.json");
    let golds: Golds = load("answer_gold.json");
    assert_eq!((cases.schema, golds.schema), (1, 1));
    assert_eq!(golds.label_source, "agent_constructed_checker_reproduced");
    assert_eq!(cases.cases.len(), 12);
    assert_eq!(golds.cases.len(), 12);
    let mut targets = BTreeSet::new();
    let mut strata = BTreeMap::new();
    for case in &cases.cases {
        let gold = golds
            .cases
            .iter()
            .find(|gold| gold.case_id == case.id)
            .unwrap();
        assert!(!case.title.is_empty() && !case.context.is_empty() && !case.provenance.is_empty());
        let formula = case.formula.to_formula().unwrap();
        assert_eq!(
            hex(&formula.encode_canonical().unwrap()),
            gold.question_canonical_hex
        );
        let base = ArtifactState::new();
        let checked = check_answer(&gold.answer, &formula, gold.outcome, &base);
        if case.kind == "solvable" {
            assert!(gold.expected_accept);
            assert!(
                targets.insert(gold.question_canonical_hex.clone()),
                "duplicate target {}",
                case.id
            );
            *strata.entry(case.stratum.as_str()).or_insert(0) += 1;
            let checked = checked.unwrap_or_else(|error| panic!("{}: {error}", case.id));
            assert_eq!(
                hex(&checked.canonical_bytes),
                gold.oracle_receipt["canonical_proof_hex"]
            );
            assert_eq!(
                serde_json::json!(checked.artifact_ids),
                gold.oracle_receipt["artifact_ids"]
            );
            assert_eq!(
                hex(&checked.conclusion.encode_canonical().unwrap()),
                gold.oracle_receipt["conclusion_canonical_hex"]
            );
            assert_eq!(case.available_helpers.len(), gold.answer.dependencies.len());
        } else {
            assert_eq!(case.kind, "checker_control");
            assert!(!gold.expected_accept);
            let error = checked.unwrap_err();
            assert!(
                error.contains(gold.expected_error_contains.as_deref().unwrap()),
                "{error}"
            );
        }
    }
    assert_eq!(
        strata,
        BTreeMap::from([("short", 4), ("reuse", 4), ("refutation", 1)])
    );
    assert_eq!(targets.len(), 9);
}

#[test]
fn pilot_dependency_closure_is_necessary_for_the_selected_certificate() {
    let cases: Cases = load("answers.json");
    let golds: Golds = load("answer_gold.json");
    let case = cases.cases.iter().find(|case| case.id == "A07").unwrap();
    let gold = golds
        .cases
        .iter()
        .find(|gold| gold.case_id == "A07")
        .unwrap();
    let formula = case.formula.to_formula().unwrap();
    let check =
        |answer: &AnswerFile| check_answer(answer, &formula, Outcome::Proof, &ArtifactState::new());
    for index in 0..gold.answer.dependencies.len() {
        let mut missing = gold.answer.clone();
        missing.dependencies.remove(index);
        assert!(check(&missing).is_err());
    }
    let mut reordered = gold.answer.clone();
    reordered.dependencies.reverse();
    assert!(check(&reordered).is_err());
    let mut extra = gold.answer.clone();
    extra.dependencies.push(
        golds
            .cases
            .iter()
            .find(|gold| gold.case_id == "A02")
            .unwrap()
            .answer
            .source
            .clone(),
    );
    assert!(check(&extra).unwrap_err().contains("unrelated helper"));
    // Reuse in a pre-populated checked context needs no duplicate supplied closure.
    let checked = check(&gold.answer).unwrap();
    let final_only = AnswerFile {
        source: gold.answer.source.clone(),
        dependencies: vec![],
    };
    let repeated = check_answer(
        &final_only,
        &formula,
        Outcome::Proof,
        &checked.resulting_state,
    )
    .unwrap();
    assert_eq!(checked.canonical_bytes, repeated.canonical_bytes);
    assert!(
        check_answer(
            &gold.answer,
            &formula,
            Outcome::Refutation,
            &ArtifactState::new()
        )
        .is_err()
    );
}
