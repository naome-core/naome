use super::*;
use crate::{checkpoint::tests::Directory, mocks};

fn question(index: u64) -> CompiledQuestion {
    CompiledQuestion::compile(&mocks::create_question(index)).unwrap()
}
fn completion(id: u64, result: jobs::Output, state: jobs::State) -> jobs::Completion {
    jobs::Completion {
        id,
        binding: jobs::Binding::new([1; 32], [2; 32]),
        spent_ms: 7,
        reserved_units: 2,
        state,
        result: Ok(result),
    }
}
fn checked(graph: &mut Graph, question: &CompiledQuestion) -> ArtifactId {
    graph
        .produce(&mocks::create_proof(question).unwrap())
        .unwrap()
        .1
        .id
}

#[test]
fn structure_ignores_spelling_and_preserves_generalizations_as_candidates() {
    let a = CompiledQuestion::compile("goal = all(x,imp(mem(x,x),eq(x,x)))").unwrap();
    let b = CompiledQuestion::compile("goal=all(y, imp(mem(y,y), eq(y,y)))").unwrap();
    let generalized =
        CompiledQuestion::compile("goal=all(x,all(y,imp(mem(x,y),eq(x,y))))").unwrap();
    assert_eq!(Features::of(&a), Features::of(&b));
    assert_ne!(Features::of(&a), Features::of(&generalized));
    let directory = Directory::new();
    let graph = Graph::default();
    let mut frontier =
        Frontier::open(&directory.0, &graph, 41, jobs::RoleSettings::default()).unwrap();
    let candidates = [&a, &generalized];
    let mut observed = [false; 2];
    for _ in 0..128 {
        observed[frontier
            .choose(&candidates, &graph, jobs::RoleSettings::default(), false)
            .unwrap()
            .unwrap()] = true;
    }
    assert_eq!(observed, [true, true]);
}

#[test]
fn received_knowledge_changes_coverage_without_claiming_local_ability() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    let mut frontier =
        Frontier::open(&directory.0, &graph, 7, jobs::RoleSettings::default()).unwrap();
    let _ = checked(&mut graph, &question(0));
    frontier.refresh(&graph).unwrap();
    assert!(frontier.coverage.iter().any(|n| *n > 0));
    assert_eq!(frontier.successes, [0; SIGNALS]);
    let common = frontier
        .weight(&question(0), &graph, jobs::RoleSettings::default())
        .unwrap();
    let rare = CompiledQuestion::compile("goal=all(x,mem(x,x))").unwrap();
    assert!(
        frontier
            .weight(&rare, &graph, jobs::RoleSettings::default())
            .unwrap()
            > common
    );
    assert!(frontier.evidence.get(&question(0)).unwrap().is_none());
}

#[test]
fn raw_candidates_failures_and_expiry_never_become_solving_evidence() {
    let directory = Directory::new();
    let graph = Graph::default();
    let mut frontier =
        Frontier::open(&directory.0, &graph, 5, jobs::RoleSettings::default()).unwrap();
    let target = question(0);
    let cost = frontier
        .weight(&target, &graph, jobs::RoleSettings::default())
        .unwrap();
    let result = completion(1, jobs::Output::NoCandidate, jobs::State::Complete);
    frontier
        .attempted(&target, &graph, &result, Outcome::NoCandidate)
        .unwrap();
    let record = frontier.evidence.get(&target).unwrap().unwrap();
    assert_eq!(record.unverified_attempts(), 1);
    assert!(record.verified.is_none());
    assert!(
        frontier
            .weight(&target, &graph, jobs::RoleSettings::default())
            .unwrap()
            < cost
    );
    // Delivery retries neither duplicate observations nor refund work.
    frontier
        .attempted(&target, &graph, &result, Outcome::NoCandidate)
        .unwrap();
    assert_eq!(frontier.evidence.get(&target).unwrap().unwrap().units, 2);
    let result = completion(
        2,
        jobs::Output::Proof {
            source: "invalid proof".into(),
            helpers: vec![],
        },
        jobs::State::Complete,
    );
    frontier
        .attempted(&target, &graph, &result, Outcome::Candidate)
        .unwrap();
    assert_eq!(
        frontier
            .evidence
            .get(&target)
            .unwrap()
            .unwrap()
            .unverified_attempts(),
        2
    );
    frontier.rejected(&target, 2).unwrap();
    let result = completion(3, jobs::Output::NoCandidate, jobs::State::Expired);
    frontier
        .attempted(&target, &graph, &result, Outcome::Expired)
        .unwrap();
    assert_eq!(frontier.successes, [0; SIGNALS]);
    assert!(
        frontier
            .verified(&target, &graph, 3, ArtifactId::from_bytes([0; 32]))
            .is_err()
    );
    let record = frontier.evidence.get(&target).unwrap().unwrap();
    assert_eq!(record.outcomes, [0, 1, 1, 0, 1, 0]);
    assert_eq!(record.units, 6);
    assert_eq!(record.spent_ms, 21);
    drop(frontier);
    let frontier =
        Frontier::open(&directory.0, &graph, 999, jobs::RoleSettings::default()).unwrap();
    assert_eq!(frontier.successes, [0; SIGNALS]);
    assert_eq!(
        frontier.evidence.get(&target).unwrap().unwrap().outcomes,
        record.outcomes
    );
}

#[test]
fn fresh_checked_exact_solutions_restore_ability_and_random_state_after_restart() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    let mut frontier =
        Frontier::open(&directory.0, &graph, 13, jobs::RoleSettings::default()).unwrap();
    let target = question(0);
    let candidates = [&target];
    frontier
        .choose(&candidates, &graph, jobs::RoleSettings::default(), false)
        .unwrap();
    let draw = frontier.evidence.draws();
    let random = frontier.evidence.random();
    let source = mocks::create_proof(&target).unwrap();
    let result = completion(
        1,
        jobs::Output::Proof {
            source,
            helpers: vec![],
        },
        jobs::State::Complete,
    );
    frontier
        .attempted(&target, &graph, &result, Outcome::Candidate)
        .unwrap();
    let root = checked(&mut graph, &target);
    frontier.prepared(&target, 1, root).unwrap();
    // Simulate the cut after graph publication and before the final evidence write.
    drop(frontier);
    let mut frontier =
        Frontier::open(&directory.0, &graph, 99, jobs::RoleSettings::default()).unwrap();
    assert!(frontier.successes.iter().any(|n| *n > 0));
    assert_eq!(frontier.evidence.draws(), draw);
    assert_eq!(frontier.evidence.random(), random);
    frontier.verified(&target, &graph, 1, root).unwrap();
    drop(frontier);
    let frontier = Frontier::open(&directory.0, &graph, 99, jobs::RoleSettings::default()).unwrap();
    assert_eq!(frontier.successes.iter().copied().max(), Some(1));
    // An unverified saved success never transfers validity to another graph.
    let empty = Graph::default();
    drop(frontier);
    let frontier = Frontier::open(&directory.0, &empty, 99, jobs::RoleSettings::default()).unwrap();
    assert_eq!(frontier.successes, [0; SIGNALS]);
}

#[test]
fn local_definitions_generate_questions_and_relationships_without_a_user_profile() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    graph
        .produce("def member_self = relation(x): mem(x,x)")
        .unwrap();
    let mut frontier =
        Frontier::open(&directory.0, &graph, 11, jobs::RoleSettings::default()).unwrap();
    frontier.refresh(&graph).unwrap();
    let goal = CompiledQuestion::compile("goal = all(x,mem(x,x))").unwrap();
    assert!(
        frontier
            .candidates()
            .iter()
            .any(|q| q.resolution_id() == goal.resolution_id())
    );
    assert_eq!(frontier.successes, [0; SIGNALS]);
}

#[tokio::test]
async fn live_autonomy_uses_the_frontier_and_excludes_checked_answers_and_registered_duplicates() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    let _ = checked(&mut graph, &question(0));
    let mut questions =
        crate::question::LocalQuestions::new(Some(mocks::select_question as fn(_) -> _));
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = crate::autonomous::Autonomous::new(
        crate::autonomous::Intervals {
            question_interval_ms: 1,
            proof_interval_ms: 3_600_000,
            ..Default::default()
        },
        owner.client.clone(),
        owner.recovery(),
        vec![],
    );
    autonomous.attach_frontier(&directory.0, &graph, 3).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    autonomous.advance(&mut graph, &mut questions);
    let requests = owner.requests();
    assert_eq!(requests.len(), 1);
    let (
        id,
        jobs::Input::Find {
            question: source, ..
        },
    ) = &requests[0]
    else {
        panic!("finding work was not submitted");
    };
    let candidate = CompiledQuestion::compile(source).unwrap();
    assert_ne!(candidate.resolution_id(), question(0).resolution_id());
    owner.complete(*id, Ok(jobs::Output::Question(source.clone())));
    autonomous.advance(&mut graph, &mut questions);
    let selected = questions.completed().await;
    questions.finish(&graph, selected);
    autonomous.advance(&mut graph, &mut questions);
    let decision = questions.assess(&graph, &candidate);
    assert_eq!(
        decision.reason,
        Some(naome_checker::question::RejectionReason::ExactDuplicate)
    );
    assert!(autonomous.error().is_none());
}

#[test]
fn changing_solver_configuration_keeps_attempts_without_claiming_the_previous_ability() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    let target = question(0);
    let mut frontier =
        Frontier::open(&directory.0, &graph, 41, jobs::RoleSettings::default()).unwrap();
    let result = completion(
        1,
        jobs::Output::Proof {
            source: mocks::create_proof(&target).unwrap(),
            helpers: vec![],
        },
        jobs::State::Complete,
    );
    frontier
        .attempted(&target, &graph, &result, Outcome::Candidate)
        .unwrap();
    let root = checked(&mut graph, &target);
    frontier.prepared(&target, 1, root).unwrap();
    frontier.verified(&target, &graph, 1, root).unwrap();
    drop(frontier);
    let mut changed = jobs::RoleSettings::default();
    changed.mock.outcome = jobs::MockOutcome::Failed;
    let frontier = Frontier::open(&directory.0, &graph, 41, changed).unwrap();
    assert_eq!(frontier.successes, [0; SIGNALS]);
    assert!(frontier.evidence.get(&target).unwrap().is_none());
    drop(frontier);
    let frontier = Frontier::open(&directory.0, &graph, 41, jobs::RoleSettings::default()).unwrap();
    assert!(frontier.successes.iter().any(|count| *count > 0));
    assert_eq!(frontier.evidence.get(&target).unwrap().unwrap().units, 2);
}

#[test]
fn failed_implication_search_proposes_simpler_open_subgoals_and_restores_budget_bound_counts() {
    let directory = Directory::new();
    let graph = Graph::default();
    let target = CompiledQuestion::compile("goal=all(x,imp(mem(x,x),eq(x,x)))").unwrap();
    let mut frontier =
        Frontier::open(&directory.0, &graph, 11, jobs::RoleSettings::default()).unwrap();
    let result = completion(1, jobs::Output::NoCandidate, jobs::State::Complete);
    frontier
        .attempted(&target, &graph, &result, Outcome::NoCandidate)
        .unwrap();
    frontier
        .attempted(&target, &graph, &result, Outcome::NoCandidate)
        .unwrap();
    assert_eq!(frontier.attempts.iter().copied().max(), Some(1));
    let helper = CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    assert!(
        frontier
            .candidates()
            .iter()
            .any(|q| q.resolution_id() == helper.resolution_id())
    );
    drop(frontier);
    let mut frontier =
        Frontier::open(&directory.0, &graph, 11, jobs::RoleSettings::default()).unwrap();
    assert_eq!(frontier.attempts.iter().copied().max(), Some(1));
    let result = completion(2, jobs::Output::NoCandidate, jobs::State::Failed);
    frontier
        .attempted(&target, &graph, &result, Outcome::Failed)
        .unwrap();
    assert_eq!(frontier.attempts.iter().copied().max(), Some(1));
    drop(frontier);
    let mut changed = jobs::RoleSettings::default();
    changed.limits.work_units += 1;
    let frontier = Frontier::open(&directory.0, &graph, 11, changed).unwrap();
    assert_eq!(frontier.attempts, [0; SIGNALS]);
}
