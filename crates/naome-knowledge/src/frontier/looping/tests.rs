use super::*;
use crate::checkpoint::tests::Directory;
use std::time::{Duration, Instant};

fn failed(frontier: &mut Frontier, graph: &Graph, q: &CompiledQuestion, job: u64) {
    let completion = jobs::Completion {
        model_checkpoint: None,
        id: job,
        binding: jobs::Binding::new([0; 32], [0; 32]),
        spent_ms: 1,
        reserved_units: 1,
        state: jobs::State::Complete,
        result: Ok(jobs::Output::Native {
            solution: None,
            diagnostic: "search_budget".into(),
            frontier: Some(crate::learning::tests::stalled_frontier(q)),
        }),
    };
    frontier
        .attempted(q, graph, &completion, Outcome::NoCandidate)
        .unwrap();
}
fn resolve(frontier: &mut Frontier, graph: &mut Graph, q: &CompiledQuestion, job: u64) -> String {
    let solution = crate::learning::tests::symbolic_solution(q);
    let completion = jobs::Completion {
        model_checkpoint: None,
        id: job,
        binding: jobs::Binding::new([0; 32], [0; 32]),
        spent_ms: 1,
        reserved_units: 1,
        state: jobs::State::Complete,
        result: Ok(jobs::Output::Native {
            solution: Some(solution.clone()),
            diagnostic: "certified_candidate".into(),
            frontier: None,
        }),
    };
    frontier
        .attempted(q, graph, &completion, Outcome::Candidate)
        .unwrap();
    let (root, batch) = graph
        .prepare_generated(&solution.source, &solution.helpers, q)
        .unwrap();
    graph
        .commit_batch(root, batch, Instant::now() + Duration::from_secs(10))
        .unwrap();
    frontier.prepared(q, job, root).unwrap();
    frontier.verified(q, graph, job, root).unwrap();
    solution.proof_id
}
fn fixture() -> (CompiledQuestion, CompiledQuestion, [CompiledQuestion; 2]) {
    let (parent, leaves) = crate::learning::tests::helper_goal();
    let other =
        CompiledQuestion::compile("goal=all(a,all(b,all(c,imp(eq(a,b),imp(eq(b,c),eq(a,c))))))")
            .unwrap();
    let root = CompiledQuestion::from_formula(Formula::conjunction(
        other.formula().clone(),
        parent.formula().clone(),
    ))
    .unwrap();
    (root, parent, leaves)
}

#[test]
fn exhausted_optional_focus_survives_reopen_and_reactivates_only_for_fresh_checked_help() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let (goal, helpers) = crate::learning::tests::helper_goal();
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    failed(&mut frontier, &graph, &goal, 1);
    for (index, helper) in helpers.iter().enumerate() {
        frontier
            .attempted(
                helper,
                &graph,
                &jobs::Completion {
                    model_checkpoint: None,
                    id: index as u64 + 2,
                    binding: jobs::Binding::new([0; 32], [0; 32]),
                    spent_ms: 1,
                    reserved_units: 1,
                    state: jobs::State::Complete,
                    result: Ok(jobs::Output::NoCandidate),
                },
                Outcome::NoCandidate,
            )
            .unwrap();
    }
    assert!(frontier.loop_focus(&graph, |_| true).unwrap().is_none());
    let members = frontier.evidence.plan_members(&goal).unwrap();
    assert!(!members.is_empty());
    drop(frontier);
    let mut frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
    assert!(frontier.loop_focus(&graph, |_| true).unwrap().is_none());
    resolve(&mut frontier, &mut graph, &helpers[0], 10);
    let (focused, work) = frontier.loop_focus(&graph, |_| true).unwrap().unwrap();
    assert_eq!(focused.resolution_id(), goal.resolution_id());
    assert_eq!(work.required.len(), 1);
    assert_eq!(
        frontier
            .choose(&[&goal], &graph, settings.solving, false)
            .unwrap(),
        Some(0)
    );
    frontier
        .attempted(
            &goal,
            &graph,
            &jobs::Completion {
                model_checkpoint: None,
                id: 11,
                binding: jobs::Binding::new([0; 32], [0; 32]),
                spent_ms: 1,
                reserved_units: 1,
                state: jobs::State::Complete,
                result: Ok(jobs::Output::NoCandidate),
            },
            Outcome::NoCandidate,
        )
        .unwrap();
    assert!(frontier.loop_focus(&graph, |_| true).unwrap().is_none());
    assert_eq!(frontier.evidence.plan_members(&goal).unwrap(), members);
}
#[test]
fn exact_conjunction_leaves_precede_an_unattempted_composite_without_inventing_failure() {
    let directory = Directory::new();
    let graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let (root, parent, leaves) = fixture();
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    failed(&mut frontier, &graph, &root, 1);
    let previous = frontier
        .previous_loop_work(&root, &graph, |_| true)
        .unwrap();
    assert_eq!(previous.target.resolution_id(), root.resolution_id());
    assert!(
        previous
            .pending
            .iter()
            .any(|q| q.resolution_id() == parent.resolution_id())
    );
    let work = frontier.loop_work(&root, &graph, |_| true).unwrap();
    assert_eq!(work.target.resolution_id(), parent.resolution_id());
    assert_eq!(work.pending.len(), 2);
    assert!(work.pending.iter().all(|q| {
        leaves
            .iter()
            .any(|p| p.resolution_id() == q.resolution_id())
    }));
    assert_eq!(work.planned.len(), 4);
    assert!(frontier.evidence.get(&parent).unwrap().is_none());
    drop(frontier);
    let mut restored = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
    let work = restored.loop_work(&root, &graph, |_| true).unwrap();
    assert_eq!(work.target.resolution_id(), parent.resolution_id());
    assert_eq!(work.planned.len(), 4);
}
#[test]
fn failed_helper_descends_and_checked_children_release_its_original_parent_once() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let (root, parent, leaves) = fixture();
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    failed(&mut frontier, &graph, &root, 1);
    failed(&mut frontier, &graph, &parent, 9);
    let flat = frontier.flat_loop_work(&root, &graph).unwrap();
    assert!(
        !flat.pending.iter().any(|q| leaves
            .iter()
            .any(|p| p.resolution_id() == q.resolution_id())),
        "the frozen flat control does not descend"
    );
    let work = frontier.loop_work(&root, &graph, |_| true).unwrap();
    assert_eq!(work.target.resolution_id(), parent.resolution_id());
    assert_eq!(work.pending.len(), 2);
    for leaf in &leaves {
        assert!(
            work.pending
                .iter()
                .any(|q| q.resolution_id() == leaf.resolution_id())
        );
    }
    assert_eq!(work.planned.len(), 4);
    drop(work);
    drop(frontier);
    let mut frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
    assert_eq!(
        frontier
            .loop_work(&root, &graph, |_| true)
            .unwrap()
            .pending
            .len(),
        2
    );
    let first = resolve(&mut frontier, &mut graph, &leaves[0], 3);
    let work = frontier.loop_work(&root, &graph, |_| true).unwrap();
    assert_eq!(work.pending.len(), 1);
    assert_eq!(work.required, vec![first.clone()]);
    let released = frontier
        .loop_work(&root, &graph, |q| {
            q.resolution_id() != leaves[1].resolution_id()
        })
        .unwrap();
    assert_eq!(released.pending.len(), 1);
    assert_eq!(released.pending[0].resolution_id(), parent.resolution_id());
    assert_eq!(released.required, vec![first.clone()]);
    assert!(
        frontier.evidence.get(&leaves[1]).unwrap().is_none(),
        "declining intake cannot invent a failed proof attempt"
    );
    let second = resolve(&mut frontier, &mut graph, &leaves[1], 4);
    let work = frontier.loop_work(&root, &graph, |_| true).unwrap();
    assert_eq!(work.pending.len(), 1);
    assert_eq!(work.pending[0].resolution_id(), parent.resolution_id());
    assert_eq!(work.required, vec![first, second]);
    failed(&mut frontier, &graph, &parent, 10);
    assert!(
        !frontier
            .loop_work(&root, &graph, |_| true)
            .unwrap()
            .pending
            .iter()
            .any(|q| q.resolution_id() == parent.resolution_id()),
        "unchanged child proofs cannot grant another parent attempt"
    );
    assert_eq!(frontier.evidence.plan_members(&root).unwrap().len(), 4);
    let fifth =
        CompiledQuestion::compile("goal=all(a,all(b,all(c,imp(eq(a,b),imp(mem(a,c),mem(b,c))))))")
            .unwrap();
    assert!(!frontier.evidence.admit_loop_member(&root, &fifth).unwrap());
    drop(frontier);
    let mut frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
    assert!(!frontier.evidence.admit_loop_member(&root, &fifth).unwrap());
    assert!(!frontier.evidence.admit_loop_member(&root, &root).unwrap());
    frontier.evidence.bind_solver("44".repeat(32));
    failed(&mut frontier, &graph, &root, 11);
    assert!(
        !frontier.evidence.admit_loop_member(&root, &fifth).unwrap(),
        "a lower model checkpoint cannot refill the root plan"
    );
}

#[test]
fn admission_failure_does_not_spend_a_member_and_depth_two_leaves_do_not_expand() {
    let directory = Directory::new();
    let graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let (leaf, _) = crate::learning::tests::helper_goal();
    let parent = CompiledQuestion::from_formula(Formula::conjunction(
        leaf.formula().clone(),
        leaf.formula().clone(),
    ))
    .unwrap();
    let root = CompiledQuestion::from_formula(Formula::conjunction(
        parent.formula().clone(),
        parent.formula().clone(),
    ))
    .unwrap();
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    failed(&mut frontier, &graph, &root, 1);
    crate::checkpoint::fail_next_commit();
    assert!(frontier.loop_work(&root, &graph, |_| true).is_err());
    assert!(frontier.evidence.plan_members(&root).unwrap().is_empty());
    failed(&mut frontier, &graph, &parent, 2);
    failed(&mut frontier, &graph, &leaf, 3);
    let work = frontier.loop_work(&root, &graph, |_| true).unwrap();
    assert_eq!(
        work.planned.len(),
        2,
        "a third level must not consume the spare member slots"
    );
    assert_eq!(work.planned[0].resolution_id(), parent.resolution_id());
    assert_eq!(work.planned[1].resolution_id(), leaf.resolution_id());
    assert!(work.pending.is_empty());
}
