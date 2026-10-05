use super::{
    Config, dataset,
    decision::{Decision, Submission, assess},
    experiment::{Release, raw_approve},
};
use crate::{dataset::digest, model::Model};
use std::time::{Duration, Instant};
fn config() -> Config {
    serde_json::from_str(include_str!("../../fixtures/question-experiment.json")).unwrap()
}
fn submission(row: &dataset::Row) -> Submission {
    Submission {
        source: row.source.clone(),
        title: "Structural proof obligation".into(),
        context: row.rationale.clone(),
        profile_id: row.snapshot.profile_id.clone(),
    }
}
fn test_release(corpus: &dataset::Corpus) -> Release {
    let mut model = Model::new(17, corpus.digest());
    model.policy = dataset::POLICY.into();
    Release {
        schema: 1,
        policy: dataset::POLICY.into(),
        feature_schema: dataset::FEATURE_SCHEMA.into(),
        model_sha256: digest(&serde_json::to_vec(&model).unwrap()),
        model,
        threshold: 0.9,
        corpus_sha256: corpus.digest(),
        label_review_sha256: "0".repeat(64),
        source_tree: env!("NAOME_LAB_SOURCE_TREE").into(),
        qualified: false,
        qualification_reason: "UNQUALIFIED_TEST_ARTIFACT".into(),
        heldout: serde_json::json!({"meets_predeclared_targets":false,"added_utility_demonstrated":false}),
        max_question_nodes: 8192,
    }
}
#[test]
fn question_sources_all_replay_with_checked_context_and_exact_elementary_witnesses() {
    let corpus = dataset::generate().unwrap();
    let inputs = corpus.replay().unwrap();
    assert_eq!(inputs.len(), 128);
    assert_eq!(
        corpus
            .rows
            .iter()
            .filter(|r| r.witness_source.is_some())
            .count(),
        32
    );
    assert_eq!(corpus.rows[0].canonical, corpus.rows[1].canonical);
    assert_eq!(inputs[0].graph, inputs[1].graph);
    assert!(corpus.rows.iter().all(|r| !r.rules.contains_key("GF10")));
    let mut tampered: dataset::Corpus =
        serde_json::from_slice(&serde_json::to_vec(&corpus).unwrap()).unwrap();
    tampered.rows[0].source = "foundation = \"naome:zfc\"\nquestion = equal(free,free)".into();
    assert!(tampered.replay().is_err());
    tampered = serde_json::from_slice(&serde_json::to_vec(&corpus).unwrap()).unwrap();
    tampered.rows[0].snapshot.proof_sources[0] =
        tampered.rows[0].snapshot.proof_sources[0].replace("simplification", "not_a_rule");
    assert!(tampered.rows[0].snapshot.checked().is_err());
    tampered = serde_json::from_slice(&serde_json::to_vec(&corpus).unwrap()).unwrap();
    tampered.rows[0].label = 1;
    tampered.rows[0].split = "test".into();
    assert!(tampered.replay().is_err());
}
#[test]
fn question_weights_cannot_enter_the_previous_proof_model_policy() {
    let corpus = dataset::generate().unwrap();
    let release = test_release(&corpus);
    release.validate().unwrap();
    assert!(release.model.validate().is_err());
    let proof = Model::new(17, "old-policy-control".into());
    proof.validate().unwrap();
    assert!(proof.validate_policy(dataset::POLICY).is_err());
    assert_eq!(proof.parameters(), release.model.parameters());
    let mut corrupt = release;
    corrupt.model.layers[0].weights[0] += 0.125;
    assert!(corrupt.validate().is_err());
    corrupt = test_release(&corpus);
    corrupt.qualified = true;
    assert!(corrupt.validate().is_err());
}
#[test]
fn question_gate_finishes_in_binary_decline_for_missing_invalid_and_unqualified_inputs() {
    let corpus = dataset::generate().unwrap();
    let row = &corpus.rows[0];
    let s = submission(row);
    let config = config();
    let release = test_release(&corpus);
    let missing = assess(
        &s,
        Err("snapshot absent".into()),
        Err("model absent".into()),
        &config,
        Instant::now(),
    );
    assert_eq!(missing.decision, Decision::Decline);
    assert_eq!(missing.reason, "MISSING_REFERENCE");
    let unqualified = assess(&s, Ok(&row.snapshot), Ok(&release), &config, Instant::now());
    assert_eq!(unqualified.decision, Decision::Decline);
    assert_eq!(unqualified.reason, "MODEL_UNQUALIFIED");
    let unavailable = assess(
        &s,
        Ok(&row.snapshot),
        Err("model absent".into()),
        &config,
        Instant::now(),
    );
    assert_eq!(unavailable.reason, "ASSESSMENT_UNAVAILABLE");
    let expired = assess(
        &s,
        Ok(&row.snapshot),
        Ok(&release),
        &config,
        Instant::now() - Duration::from_millis(config.decision_millis),
    );
    assert_eq!(expired.reason, "DECISION_DEADLINE");
    assert_eq!(expired.decision, Decision::Decline);
    let mut invalid = submission(row);
    invalid.source = "foundation = \"naome:zfc\"\nquestion = equal(free,free)".into();
    let r = assess(
        &invalid,
        Ok(&row.snapshot),
        Ok(&release),
        &config,
        Instant::now(),
    );
    assert_eq!(r.reason, "INVALID_TARGET");
    assert_eq!(r.decision, Decision::Decline);
    let encoded = serde_json::to_value(&unqualified).unwrap();
    assert_eq!(encoded["decision"], "DECLINE");
    assert_eq!(encoded["checks"].as_array().unwrap().len(), 10);
    assert!(serde_json::from_str::<Decision>("\"UNCERTAIN\"").is_err());
}
#[test]
fn deterministic_question_failures_are_not_overridden_by_a_neural_artifact() {
    let corpus = dataset::generate().unwrap();
    let config = config();
    let release = test_release(&corpus);
    let row = &corpus.rows[0];
    let mut duplicate = submission(row);
    duplicate.source = row.snapshot.registry_sources[0].clone();
    let r = assess(
        &duplicate,
        Ok(&row.snapshot),
        Ok(&release),
        &config,
        Instant::now(),
    );
    assert_eq!(r.reason, "EXACT_DUPLICATE");
    let context = row.snapshot.checked().unwrap();
    let target = &context.knowledge[0];
    let mut settled = submission(row);
    settled.source = dataset::source(&target.to_source());
    let r = assess(
        &settled,
        Ok(&row.snapshot),
        Ok(&release),
        &config,
        Instant::now(),
    );
    assert_eq!(r.reason, "ALREADY_SETTLED");
    settled.source =
        dataset::source(&naome_foundation::Formula::negate(target.clone()).to_source());
    let r = assess(
        &settled,
        Ok(&row.snapshot),
        Ok(&release),
        &config,
        Instant::now(),
    );
    assert_eq!(r.reason, "SEMANTIC_REFORMULATION");
    for row in [&corpus.rows[4], &corpus.rows[5]] {
        let r = assess(
            &submission(row),
            Ok(&row.snapshot),
            Ok(&release),
            &config,
            Instant::now(),
        );
        assert_eq!(r.reason, "KNOWN_ELEMENTARY_INSTANCE");
        assert!(r.checked_witness.is_some());
        assert!(r.scores.is_none());
    }
}
#[test]
fn low_confidence_ties_and_nonfinite_outputs_never_approve() {
    assert!(!raw_approve(&[0.5, 0.5, 0.0, 0.0], 0.9));
    assert!(!raw_approve(&[f64::NAN, 0.0, 0.0, 0.0], 0.9));
    assert!(!raw_approve(&[0.89, 0.05, 0.03, 0.03], 0.9));
    assert!(raw_approve(&[0.91, 0.03, 0.03, 0.03], 0.9));
}
