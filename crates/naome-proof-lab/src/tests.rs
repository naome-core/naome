use crate::{
    dataset, experiment,
    graph::Graph,
    model::{Adam, Model},
};

fn tiny() -> (Graph, Graph) {
    let mut a = Graph {
        nodes: vec![[0.0; 24]; 3],
        edges: vec![vec![(1, 0), (2, 1)], vec![(2, 2)], vec![]],
        root: 0,
        cost: 2,
    };
    a.nodes[0][3] = 1.0;
    a.nodes[1][0] = 1.0;
    a.nodes[2][6] = 1.0;
    a.nodes[2][22] = 0.75;
    let mut b = a.clone();
    b.nodes[1][0] = 0.0;
    b.nodes[1][1] = 1.0;
    b.cost = 4;
    (a, b)
}
#[test]
fn every_parameter_matches_independent_central_differences() {
    let (a, b) = tiny();
    let mut model = Model::new(17, "numeric-control".into());
    for label in [0, 2] {
        let (_, analytic) = model.gradient(&a, &b, label);
        for (l, gradient) in analytic.iter().enumerate() {
            for (i, expected) in gradient.iter().enumerate() {
                let original = model.layers[l].weights[i];
                let eps = 1e-5;
                model.layers[l].weights[i] = original + eps;
                let plus = -model.score(&a, &b)[label].ln();
                model.layers[l].weights[i] = original - eps;
                let minus = -model.score(&a, &b)[label].ln();
                model.layers[l].weights[i] = original;
                let numerical = (plus - minus) / (2.0 * eps);
                assert!(
                    (numerical - expected).abs() < 2e-7,
                    "layer {l} parameter {i}: {numerical} vs {expected}"
                );
            }
        }
    }
}
#[test]
fn real_optimizer_changes_encoder_and_reduces_cross_entropy() {
    let (a, b) = tiny();
    let mut model = Model::new(29, "training-control".into());
    let before = model.clone();
    let loss = -model.score(&a, &b)[1].ln();
    let mut optimizer = Adam::new(&model);
    for _ in 0..32 {
        let (_, g) = model.gradient(&a, &b, 1);
        optimizer.update(&mut model, &g, 0.01);
    }
    assert!(-model.score(&a, &b)[1].ln() < loss * 0.25);
    for i in 0..3 {
        assert_ne!(model.layers[i].weights, before.layers[i].weights);
    }
}
#[test]
fn model_roundtrip_is_exact_and_rejects_invalid_weights_and_schema() {
    let (a, b) = tiny();
    let m = Model::new(43, "replay".into());
    let mut n: Model = serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap();
    n.validate().unwrap();
    assert_eq!(m.score(&a, &b), n.score(&a, &b));
    n.layers[0].weights[0] = f64::NAN;
    assert!(n.validate().is_err());
    n = m.clone();
    n.layers[0].weights.pop();
    assert!(n.validate().is_err());
    n = m;
    n.schema = 2;
    assert!(n.validate().is_err());
}
#[test]
fn checked_data_retains_aliases_shorter_proofs_witnesses_and_family_splits() {
    let corpus = dataset::generate(8).unwrap();
    corpus.replay().unwrap();
    let r = &corpus.records;
    assert_eq!(r[0].graph, r[2].graph);
    assert_eq!(r[0].derivation_id, r[2].derivation_id);
    assert_ne!(r[0].proof_id, r[2].proof_id);
    assert_eq!(r[0].proof_id, r[3].proof_id);
    assert_eq!(r[0].statement_id, r[1].statement_id);
    assert_ne!(r[0].derivation_id, r[1].derivation_id);
    assert!(r[0].graph.cost < r[1].graph.cost);
    assert_ne!(r[0].statement_id, r[4].statement_id);
    assert_ne!(r[0].graph, r[4].graph);
    let mut statements = std::collections::BTreeMap::new();
    let mut derivations = statements.clone();
    for r in &corpus.records {
        if let Some(old) = statements.insert(&r.statement_id, dataset::split(r.family)) {
            assert_eq!(old, dataset::split(r.family));
        }
        if let Some(old) = derivations.insert(&r.derivation_id, dataset::split(r.family)) {
            assert_eq!(old, dataset::split(r.family));
        }
    }
    let mut corrupt = corpus.clone();
    corrupt.records[0].canonical[0] ^= 1;
    assert!(corrupt.replay().is_err());
    corrupt = corpus.clone();
    corrupt
        .pairs
        .iter_mut()
        .find(|p| p.label == 2)
        .unwrap()
        .witnesses
        .reverse();
    assert!(corrupt.replay().is_err());
}
#[test]
fn authoring_rejects_changed_binding_quantifier_and_implication_claims() {
    let source = include_str!("../fixtures/binding-control.nao");
    let _ = naome_authoring::compile(source).unwrap();
    // Mutate the claim only; unchanged valid steps cannot prove the altered claim.
    let (claim, proof) = source.split_once("proof:").unwrap();
    for changed in [
        claim.replacen("forall(x, forall(y,", "forall(y, forall(x,", 1),
        claim.replacen("equal(x, y)", "equal(y, x)", 1),
        claim.replacen(
            "implies(member(x, y), equal(x, y))",
            "implies(equal(x, y), member(x, y))",
            1,
        ),
    ] {
        assert!(naome_authoring::compile(&format!("{changed}proof:{proof}")).is_err());
    }
}
#[test]
fn relabelled_duplicate_family_cannot_cross_frozen_partitions() {
    let corpus = dataset::generate(8).unwrap();
    let mut leaking = corpus.clone();
    let start = leaking.records.len();
    let mut copied = corpus.records[..8].to_vec();
    for r in &mut copied {
        r.family = 10;
    }
    leaking.records.extend(copied);
    leaking
        .pairs
        .extend(corpus.pairs[..8].iter().cloned().map(|mut p| {
            p.a += start;
            p.b += start;
            for w in &mut p.witnesses {
                *w += start;
            }
            p
        }));
    assert!(
        leaking
            .replay()
            .unwrap_err()
            .contains("crosses frozen partitions")
    );
}
#[test]
fn shared_citation_aliases_expand_to_the_same_unique_dag_and_cost() {
    let corpus = dataset::generate(8).unwrap();
    let r = &corpus.records;
    let mut state = naome_checker::ArtifactState::new();
    let mut expanded = std::collections::BTreeMap::new();
    for row in [&r[0], &r[2]] {
        let p = naome_checker::normalize_and_check_with_state(
            naome_proof::ProofCertificate::from_canonical_bytes(&row.canonical).unwrap(),
            &state,
        )
        .unwrap();
        let (_, certificate) = Graph::checked(&p, &state, &expanded).unwrap();
        let id = p.proof_id();
        state.register_proof_for_replication(p).unwrap();
        expanded.insert(id, certificate);
    }
    let (claim, proof) = r[1].source.split_once("proof:").unwrap();
    let proof = proof.replace("p0 = simplification(", "unreachable = simplification(");
    let proof = format!(
        "p0 = cite(\"{}\")\nother = cite(\"{}\")\n{}",
        r[0].proof_id,
        r[2].proof_id,
        proof.replace("p3 = modus_ponens(p0, p2)", "p3 = modus_ponens(other, p2)")
    );
    let compiled =
        naome_authoring::compile_against_proof_context(&format!("{claim}proof:\n{proof}"), &state)
            .unwrap();
    let checked = naome_checker::normalize_and_check_with_state(
        naome_proof::ProofCertificate::from_canonical_bytes(compiled.canonical_proof_bytes())
            .unwrap(),
        &state,
    )
    .unwrap();
    let (graph, _) = Graph::checked(&checked, &state, &expanded).unwrap();
    assert_eq!(graph, r[1].graph);
    assert_eq!(graph.cost, 4);
    assert_eq!(
        dataset::hex(checked.derivation_id().as_bytes()),
        r[1].derivation_id
    );
}
#[test]
fn saved_index_reconstructs_rows_vectors_and_rejects_model_or_content_changes() {
    let c = dataset::generate(8).unwrap();
    let m = Model::new(17, c.digest());
    let mut i = crate::index::Index::new(&m, &c);
    for r in &c.records {
        i.append(&m, r);
    }
    let saved: crate::index::Index =
        serde_json::from_slice(&serde_json::to_vec(&i).unwrap()).unwrap();
    saved.validate(&m, &c).unwrap();
    assert_eq!(saved.exact_matches(&c.records[0]).len(), 3);
    assert_eq!(saved.statement_matches(&c.records[0]).len(), 4);
    let mut changed = saved.clone();
    changed.entries[0].vector[0] += 0.1;
    assert!(changed.validate(&m, &c).is_err());
    assert!(saved.validate(&Model::new(29, c.digest()), &c).is_err());
}
#[test]
fn frozen_configuration_bounds_volume_and_execution() {
    let mut c: experiment::Config =
        serde_json::from_str(include_str!("../fixtures/experiment.json")).unwrap();
    c.validate().unwrap();
    c.scale_rows.push(65537);
    assert!(c.validate().is_err());
    c.scale_rows.pop();
    c.epochs = 101;
    assert!(c.validate().is_err());
}
#[test]
fn duplicate_seeds_and_scale_rows_are_rejected_before_experiment_work() {
    let mut c: experiment::Config =
        serde_json::from_str(include_str!("../fixtures/experiment.json")).unwrap();
    c.seeds.push(c.seeds[0]);
    assert!(c.validate().is_err());
    c.seeds.pop();
    c.validate().unwrap();
    c.scale_rows.push(c.scale_rows[0]);
    assert!(c.validate().is_err());
}

fn trained_tiny_corpus() -> (
    dataset::Corpus,
    experiment::Config,
    Model,
    serde_json::Value,
) {
    let c = dataset::generate(8).unwrap();
    let mut config: experiment::Config =
        serde_json::from_str(include_str!("../fixtures/experiment.json")).unwrap();
    config.families = 8;
    config.epochs = 1;
    let (model, report) = experiment::train(&c, &config, 17);
    (c, config, model, report)
}

#[test]
fn consumed_calibration_rejects_changed_threshold_and_development_results() {
    let (corpus, config, model, report) = trained_tiny_corpus();
    let threshold =
        experiment::verify_training_report(&corpus, &config, &model, 17, &report).unwrap();
    assert_eq!(report["threshold"].as_f64(), Some(threshold));
    for changed in [-0.1, 0.25, 1.1] {
        let mut corrupt = report.clone();
        corrupt["threshold"] = serde_json::json!(changed);
        assert!(
            experiment::verify_training_report(&corpus, &config, &model, 17, &corrupt)
                .unwrap_err()
                .contains("calibration threshold mismatch")
        );
    }
    let mut corrupt = report;
    corrupt["development"]["useful_false_rejections"] = serde_json::json!(1);
    assert!(
        experiment::verify_training_report(&corpus, &config, &model, 17, &corrupt)
            .unwrap_err()
            .contains("development report mismatch")
    );
}

#[test]
fn consumed_model_requires_training_seed_corpus_and_weight_digest() {
    let (corpus, config, model, report) = trained_tiny_corpus();
    experiment::verify_training_report(&corpus, &config, &model, 17, &report).unwrap();
    let mut changed = model.clone();
    changed.layers[0].weights[0] += 0.01;
    changed.validate().unwrap();
    assert!(
        experiment::verify_training_report(&corpus, &config, &changed, 17, &report)
            .unwrap_err()
            .contains("model digest mismatch")
    );
    changed = model.clone();
    changed.seed = 29;
    assert!(
        experiment::verify_training_report(&corpus, &config, &changed, 17, &report)
            .unwrap_err()
            .contains("seed mismatch")
    );
    let mut corrupt = report.clone();
    corrupt["corpus_sha256"] = serde_json::json!("changed");
    assert!(
        experiment::verify_training_report(&corpus, &config, &model, 17, &corrupt)
            .unwrap_err()
            .contains("corpus mismatch")
    );
    corrupt = report;
    corrupt["seed"] = serde_json::json!(29);
    assert!(
        experiment::verify_training_report(&corpus, &config, &model, 17, &corrupt)
            .unwrap_err()
            .contains("seed mismatch")
    );
}
