use super::*;
struct Ordered;
impl Ranker for Ordered {
    fn scores(&mut self, decision: &Decision) -> Result<Vec<f32>, String> {
        Ok(vec![0.; decision.candidates.len()])
    }
}
#[test]
fn a_conjunction_uses_both_checked_sources_within_three_constructor_steps() {
    let (goal, helpers) = crate::learning::tests::helper_goal();
    let mut graph = crate::Graph::default();
    let mut known = Vec::new();
    let mut ids = Vec::new();
    for helper in helpers {
        let solution = crate::learning::tests::symbolic_solution(&helper);
        let (root, batch) = graph
            .prepare_generated(&solution.source, &solution.helpers, &helper)
            .unwrap();
        graph
            .commit_batch(
                root,
                batch,
                std::time::Instant::now() + std::time::Duration::from_secs(10),
            )
            .unwrap();
        known.push(knowledge::Entry {
            packet: graph.learning_certificate(root).unwrap().unwrap(),
        });
        ids.push(root);
    }
    let (proof, work, _) = super::super::construct_with(
        goal.proved_target(),
        3,
        std::time::Instant::now(),
        &mut Ordered,
        &known,
        &[],
    )
    .unwrap();
    assert_eq!(work, 3);
    let proof = proof
        .expect("both closed prerequisites must compose without searching their derivations again");
    let source = super::super::super::proof::source(&proof).unwrap();
    let packet = super::super::super::evidence::pack(&proof).unwrap();
    let helpers = super::super::super::evidence::helpers(&packet).unwrap();
    let (root, batch) = graph.prepare_generated(&source, &helpers, &goal).unwrap();
    graph
        .commit_batch(
            root,
            batch,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        )
        .unwrap();
    let dependencies = graph.direct_dependencies(root).unwrap();
    assert!(ids.iter().all(|id| dependencies.contains(id)));
}
