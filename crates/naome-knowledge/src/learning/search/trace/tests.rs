use super::*;
use crate::learning as native;

fn question() -> naome_authoring::CompiledQuestion {
    naome_authoring::CompiledQuestion::compile(&native::tests::own_question()).unwrap()
}
struct Ordered;
impl Ranker for Ordered {
    fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
        Ok(vec![0.; d.candidates.len()])
    }
}

#[test]
fn recording_preserves_actual_neural_choices_exploration_and_optimizer_bytes() {
    let q = question();
    let solution = native::tests::own_solution();
    let target = if solution.refuted {
        q.refuted_target()
    } else {
        q.proved_target()
    };
    let (_, graphs) = compile(target, &solution.tree).unwrap();
    assert!(!graphs.is_empty());
    let mut io = native::tests::MemoryStore::default();
    let checkpoint = native::model::test_update(
        &native::model::Checkpoint::fresh(),
        &graphs,
        &mut 71,
        &mut io,
    )
    .unwrap();
    let mut engine = native::Engine::default();
    let mut results = Vec::new();
    for capture in [false, true] {
        let result = engine
            .with(&checkpoint, &mut io, |runtime| {
                let mut ranker = native::Exploring {
                    model: runtime,
                    seed: 197,
                    explore: true,
                };
                let found = super::super::solve_recording(
                    target,
                    &mut ranker,
                    128,
                    Instant::now(),
                    &[],
                    capture,
                )?;
                Ok((found, ranker.seed))
            })
            .unwrap();
        assert_eq!(engine.snapshot(&checkpoint, &mut io).unwrap(), checkpoint);
        results.push(result);
    }
    let (plain, plain_rng) = &results[0];
    let (recorded, recorded_rng) = &results[1];
    assert_eq!(native::digest(&plain.tree), native::digest(&recorded.tree));
    assert_eq!(plain.expansions, recorded.expansions);
    assert_eq!(plain.terminal, recorded.terminal);
    assert_eq!(plain_rng, recorded_rng);
    assert!(plain.execution.is_none());
    let trace = recorded.execution.as_ref().unwrap();
    trace.validate_context(&q, &[]).unwrap();
    assert_eq!(trace.attempts, recorded.expansions);
    assert!(!trace.events.is_empty());
    let restored: Trace =
        crate::checkpoint::decode(&crate::checkpoint::encode(trace).unwrap()).unwrap();
    assert_eq!(&restored, trace);
}

#[test]
fn altered_state_action_scores_parent_or_work_are_rejected() {
    let q = question();
    let result = solve(q.proved_target(), &mut Ordered, 128).unwrap();
    let original = result.execution.unwrap();
    original.validate_context(&q, &[]).unwrap();
    assert!(!original.events.is_empty());
    for mutation in 0..6 {
        let mut trace = original.clone();
        match mutation {
            0 => trace.events[0].state = "f1".repeat(32),
            1 => trace.events[0].offered = "f1".repeat(32),
            2 => trace.events[0].selected = usize::MAX,
            3 => trace.events[0].parent = Some(Branch { event: 0, child: 0 }),
            4 => trace.events[0].end = trace.attempts + 1,
            _ => trace.events[0].ranks = Some(vec![f32::NAN.to_bits()]),
        }
        assert!(trace.validate().is_err(), "mutation {mutation}");
    }
    let other = naome_authoring::CompiledQuestion::compile("goal=all(a,mem(a,a))").unwrap();
    assert!(original.validate_context(&other, &[]).is_err());
}

#[test]
fn truncated_observations_keep_a_replayable_prefix_and_count_omitted_work() {
    let q = naome_authoring::CompiledQuestion::compile(
        "goal=all(a,all(b,imp(all(x,all(y,all(z,mem(x,x)))),mem(a,b))))",
    )
    .unwrap();
    let result = solve(q.proved_target(), &mut Ordered, 256).unwrap();
    assert!(result.tree.is_none());
    let trace = result.execution.unwrap();
    trace.validate_context(&q, &[]).unwrap();
    assert!(
        trace.omitted > 0,
        "fixture must exceed the bounded observation prefix"
    );
    assert_eq!(trace.events.len() + trace.omitted, result.expansions);
    assert!(crate::checkpoint::encode(&trace).unwrap().len() <= BYTES);
    assert!(trace.events.iter().all(|event| !event.closed));
}
