//! Explicit numerical interventions on an immutable owned training prefix.
use super::*;
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};

#[derive(Deserialize)]
struct Row {
    before: State,
    selection: Selection,
    experience: Experience,
    expected_draw: u64,
    expected_after: Checkpoint,
    weights_path: String,
    optimizer_path: String,
}
#[derive(Deserialize)]
struct Query {
    before: State,
    selection: Selection,
}
#[derive(Deserialize)]
struct Fixture {
    name: String,
    rows: Vec<Row>,
    query: Query,
}
#[derive(Deserialize)]
struct Inputs {
    fixtures: [Fixture; 2],
}

fn bytes(path: &str, blob: &Blob) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(Blob::of(&bytes), *blob);
    bytes
}

fn intervene(
    e: &Experience,
    alternate: &BTreeMap<u64, &Experience>,
    cost: bool,
    context: bool,
) -> Experience {
    let other = alternate[&e.job];
    assert_eq!(&e.context[..31], &other.context[..31]);
    assert_eq!(&e.targets()[..2], &other.targets()[..2]);
    assert_eq!(e.plan, other.plan);
    let mut changed = e.clone();
    if cost {
        changed.lower_cpu_micros = other.lower_cpu_micros;
    }
    if context {
        changed.context[31] = other.context[31];
    }
    changed
}

fn replay(
    fixture: &Fixture,
    alternate: &Fixture,
    cost: bool,
    context: bool,
    expected: &Fixture,
) -> model::Network {
    let alternate = alternate
        .rows
        .iter()
        .map(|r| (r.experience.job, &r.experience))
        .collect();
    let mut network = model::Network::fresh(fixture.rows[0].before.model.seed);
    for (index, row) in fixture.rows.iter().enumerate() {
        assert_eq!(row.before.model.updates, network.updates);
        let experience = intervene(&row.experience, &alternate, cost, context);
        let mut memory = row
            .before
            .memory
            .iter()
            .map(|e| intervene(e, &alternate, cost, context))
            .collect::<Vec<_>>();
        memory.push(experience.clone());
        let mut draw = row.selection.draw;
        // Reproduce the owner's exact batching. Matching every recorded weight,
        // Adam byte and RNG boundary is required before interpreting an intervention.
        for _ in 0..UPDATES {
            let mut batch = vec![&experience];
            for _ in 0..3 {
                batch.push(
                    &memory[(super::super::super::model::random(&mut draw) % memory.len() as u64)
                        as usize],
                );
            }
            network.update(&batch).unwrap();
        }
        assert_eq!(draw, row.expected_draw);
        if cost == context {
            let expected = &expected.rows[index];
            assert_eq!(network.updates, expected.expected_after.updates);
            assert_eq!(
                network.encode(),
                (
                    bytes(
                        &expected.weights_path,
                        expected.expected_after.weights.as_ref().unwrap()
                    ),
                    bytes(
                        &expected.optimizer_path,
                        expected.expected_after.optimizer.as_ref().unwrap()
                    ),
                )
            );
        }
    }
    network
}

fn prediction(network: &model::Network, query: &Query) -> serde_json::Value {
    let mut draw = query.before.draw;
    let mut plans = vec![Plan::balanced(), Plan::targeted(), Plan::mixture()];
    for _ in 0..13 {
        plans.push(Plan::random(&mut draw));
    }
    let predictions = plans
        .iter()
        .map(|p| network.forward(&features(&query.selection.context, p)).1)
        .collect::<Vec<_>>();
    let exploration =
        query.before.trials == 0 || super::super::super::model::random(&mut draw).is_multiple_of(5);
    assert!(
        !exploration,
        "the frozen divergence must be a neural selection"
    );
    assert_eq!(draw, query.selection.draw);
    let best = |cost: bool| {
        (0..plans.len())
            .max_by(|a, b| {
                let value = |i: usize| {
                    let p = predictions[i];
                    p[0].clamp(-1., 1.)
                        - p[1].clamp(0., 1.)
                        - if cost { 0.05 * p[2].clamp(0., 2.) } else { 0. }
                };
                value(*a).total_cmp(&value(*b)).then(b.cmp(a))
            })
            .unwrap()
    };
    let selected = best(true);
    serde_json::json!({"selected_index":selected,"selected_plan":plans[selected],
        "prediction":predictions[selected],"quality_only_index":best(false),
        "plans":plans,"all_predictions":predictions})
}

#[test]
#[ignore = "Explicit bounded owned-feedback intervention; no lower training or proof queries"]
fn owned_cost_feedback_sensitivity() {
    let input = std::env::var("NAOME_FEEDBACK_INPUT").expect("frozen diagnosis input");
    let output = std::env::var("NAOME_FEEDBACK_OUTPUT").expect("fresh diagnosis output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve earlier diagnoses");
    let inputs: Inputs = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let [baseline, current] = &inputs.fixtures;
    assert_eq!(baseline.rows.len(), 6);
    assert_eq!(current.rows.len(), 6);
    assert_eq!(
        Checkpoint::fresh().specification,
        current.query.before.model.specification,
        "only test code may differ from the frozen current mathematics"
    );
    let started = std::time::Instant::now();
    let cpu = cpu_micros().unwrap();
    let original = replay(baseline, baseline, false, false, baseline);
    let actual = replay(current, current, false, false, current);
    let both = replay(baseline, current, true, true, current);
    assert_eq!(both.encode(), actual.encode());
    for (network, query) in [(&original, &baseline.query), (&actual, &current.query)] {
        let row = prediction(network, query);
        let plan: Plan = serde_json::from_value(row["selected_plan"].clone()).unwrap();
        let values: [f32; 3] = serde_json::from_value(row["prediction"].clone()).unwrap();
        assert_eq!(plan, query.selection.plan);
        assert_eq!(
            values.map(f32::to_bits),
            query.selection.prediction.map(f32::to_bits)
        );
    }
    let targets_only = replay(baseline, current, true, false, baseline);
    let context_only = replay(baseline, current, false, true, baseline);
    let mut rows = Vec::new();
    for (name, network) in [
        ("baseline", original),
        ("current", actual),
        ("cpu_targets_only", targets_only),
        ("cpu_context_only", context_only),
        ("both", both),
    ] {
        for fixture in [baseline, current] {
            let result = prediction(&network, &fixture.query);
            rows.push(
                serde_json::json!({"training":name,"query_context":fixture.name,"result":result}),
            );
        }
    }
    let elapsed = started.elapsed().as_micros();
    let cpu = cpu_micros().unwrap() - cpu;
    assert!(elapsed < 120_000_000 && cpu < 90_000_000);
    std::fs::write(output, serde_json::to_vec_pretty(&serde_json::json!({
        "result":"pass","actual_replay_boundaries":12,"both_cpu_swap_boundaries":6,
        "upper_adam_updates":240,"lower_adam_updates":0,"new_proof_queries":0,
        "elapsed_wall_micros":elapsed,"elapsed_cpu_micros":cpu,
        "scope":"Numerical sensitivity of an owned training prefix; no held-out quality evidence.",
        "interventions":rows,
    })).unwrap()).unwrap();
}
