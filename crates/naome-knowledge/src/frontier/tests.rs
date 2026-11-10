use super::*;
use crate::{checkpoint::tests::Directory, mocks};
use std::time::{Duration, Instant};

#[test]
fn finder_outcomes_have_distinct_numeric_codes() {
    let evidence = serde_json::to_value(Outcome::NoCandidate).unwrap();
    assert_eq!(evidence, 0x003d_0002u32);
    assert_eq!(
        serde_json::from_value::<Outcome>(evidence).unwrap(),
        Outcome::NoCandidate
    );
    assert!(serde_json::from_value::<Outcome>(0x003d_ffffu32.into()).is_err());
    let event =
        serde_json::json!({"outcome": crate::outcome::FinderLearningOutcome::CheckedResolution});
    assert_eq!(event["outcome"], 0x003c_0001u32);
}

#[test]
fn frozen_finder_parameters_survive_real_observations_and_five_sqlite_reopens() {
    let directory = Directory::new();
    let graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let target = ResearchQuestion::from_hex(&crate::learning::tests::own_question()).unwrap();
    let mut frontier = Frontier::open(&directory.0, &graph, 91, settings).unwrap();
    frontier.initial_parameters(91).unwrap();
    frontier.freeze_parameters();
    let initial = frontier.learning_snapshot()["model"].clone();
    for job in 1..=5 {
        frontier
            .attempted(
                &target,
                &graph,
                &native_failure(&target, job, None),
                Outcome::NoCandidate,
            )
            .unwrap();
        assert_eq!(frontier.learning_snapshot()["model"], initial);
        assert!(frontier.initial_parameters(97).is_err());
        drop(frontier);
        frontier = Frontier::open(&directory.0, &graph, 91, settings).unwrap();
        assert_eq!(
            frontier.learning_snapshot()["model"],
            initial,
            "replay cannot silently alter a completed frozen control"
        );
        frontier.freeze_parameters();
    }
    assert!(
        frontier.learning_snapshot()["curriculum"]["cursor"]
            .as_u64()
            .unwrap()
            > 0,
        "actual observations and bounded history still advance"
    );
}

#[test]
fn defined_question_evidence_replays_using_its_checked_primitive_target() {
    use naome_foundation::FreeVariable;
    use naome_proof::{DefinedFormula, DefinitionCertificate};
    let directory = Directory::new();
    let mut graph = Graph::default();
    let x = FreeVariable::new(0);
    let definition = DefinitionCertificate::relation(1, DefinedFormula::equal(x, x)).unwrap();
    graph
        .produce(&crate::test_inputs::definition(&definition))
        .unwrap();
    let source = DefinedFormula::for_all(
        x,
        DefinedFormula::defined_relation(definition.definition_id(), [x]),
    );
    let question = ResearchQuestion::from_defined_formula(source, graph.checked_context()).unwrap();
    let primitive = ResearchQuestion::from_formula(question.formula().clone()).unwrap();
    assert_ne!(question.to_hex(), primitive.to_hex());
    assert_eq!(question.resolution_id(), primitive.resolution_id());
    let settings = jobs::Settings::default();
    let mut frontier = Frontier::open(&directory.0, &graph, 1, settings).unwrap();
    frontier
        .attempted(
            &question,
            &graph,
            &completion(1, jobs::Output::NoCandidate, jobs::State::Complete),
            Outcome::NoCandidate,
        )
        .unwrap();
    assert_eq!(
        frontier.evidence.get(&question).unwrap().unwrap().question,
        primitive.to_hex()
    );
    drop(frontier);
    let reopened = Frontier::open(&directory.0, &graph, 1, settings).unwrap();
    assert_eq!(
        reopened.evidence.get(&question).unwrap().unwrap().last_job,
        1
    );
}

fn question(index: u64) -> ResearchQuestion {
    ResearchQuestion::from_hex(&mocks::create_question(index)).unwrap()
}
fn completion(id: u64, result: jobs::Output, state: jobs::State) -> jobs::Completion {
    jobs::Completion {
        experience: None,
        model_checkpoint: None,
        id,
        binding: jobs::Binding::new([1; 32], [2; 32]),
        spent_ms: 7,
        reserved_units: 2,
        state,
        result: Ok(result),
    }
}

fn native_failure(
    question: &ResearchQuestion,
    id: u64,
    frontier: Option<crate::learning::SearchFrontier>,
) -> jobs::Completion {
    evidence::observed_completion(
        question,
        id,
        crate::learning::experience::TerminalEvidence::Budget(
            crate::learning::experience::Budget::Expansions,
        ),
        128,
        frontier,
    )
}

#[test]
fn native_backoff_abstains_and_unrelated_peer_knowledge_does_not_reset_it() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    let target = ResearchQuestion::from_hex(&crate::learning::tests::own_question()).unwrap();
    frontier
        .attempted(
            &target,
            &graph,
            &native_failure(&target, 1, None),
            Outcome::NoCandidate,
        )
        .unwrap();
    let candidates = [&target];
    let random = frontier.random.0;
    assert_eq!(
        frontier
            .choose(&candidates, &graph, settings.solving, false)
            .unwrap(),
        None
    );
    assert_eq!(
        frontier.random.0, random,
        "abstention must not consume a random choice"
    );
    graph
        .produce(&mocks::create_proof(&question(0)).unwrap())
        .unwrap();
    assert_eq!(
        frontier
            .choose(&candidates, &graph, settings.solving, false)
            .unwrap(),
        None
    );
    drop(frontier);
    let mut frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
    assert_eq!(
        frontier
            .choose(&candidates, &graph, settings.solving, false)
            .unwrap(),
        Some(0),
        "bounded backoff must eventually release even a sole candidate after reopen"
    );
}

#[test]
fn finder_learning_is_atomic_idempotent_and_requires_a_checked_resolution_for_success() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let question = ResearchQuestion::from_hex(&crate::learning::tests::own_question()).unwrap();
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    let initial = frontier.evidence.model().clone();
    assert!(!frontier.helpers_needed(&question).unwrap());
    let unresolved = native_failure(&question, 1, None);
    crate::checkpoint::fail_next_commit();
    assert!(
        frontier
            .attempted(&question, &graph, &unresolved, Outcome::NoCandidate)
            .is_err()
    );
    assert_eq!(frontier.evidence.model(), &initial);
    assert!(!frontier.helpers_needed(&question).unwrap());
    frontier
        .attempted(&question, &graph, &unresolved, Outcome::NoCandidate)
        .unwrap();
    frontier
        .attempted(&question, &graph, &unresolved, Outcome::NoCandidate)
        .unwrap();
    assert_eq!(frontier.evidence.model().updates, 1);
    assert_eq!(frontier.evidence.model().unresolved, 1);
    assert!(frontier.helpers_needed(&question).unwrap());
    for (job, state, outcome) in [
        (2, jobs::State::Expired, Outcome::Expired),
        (3, jobs::State::Failed, Outcome::Failed),
        (4, jobs::State::InDoubt, Outcome::InDoubt),
    ] {
        let result = completion(job, jobs::Output::NoCandidate, state);
        frontier
            .attempted(&question, &graph, &result, outcome)
            .unwrap();
    }
    assert_eq!(frontier.evidence.model().updates, 1);
    let solution = crate::learning::tests::own_solution();
    let result = completion(
        5,
        jobs::Output::Proof {
            proof: solution.source.clone(),
            helpers: vec![],
        },
        jobs::State::Complete,
    );
    frontier
        .attempted(&question, &graph, &result, Outcome::Candidate)
        .unwrap();
    assert_eq!(frontier.evidence.model().resolved, 0);
    assert!(
        frontier
            .verified(&question, &graph, 5, ArtifactId::from_bytes([0; 32]))
            .is_err()
    );
    let root = graph.produce(&solution.source).unwrap().1.id;
    frontier.prepared(&question, 5, root).unwrap();
    assert_eq!(frontier.evidence.model().resolved, 0);
    frontier.verified(&question, &graph, 5, root).unwrap();
    frontier.verified(&question, &graph, 5, root).unwrap();
    assert_eq!(
        (
            frontier.evidence.model().updates,
            frontier.evidence.model().resolved
        ),
        (2, 1)
    );
    assert!(!frontier.helpers_needed(&question).unwrap());
    let model = frontier.evidence.model().clone();
    let generated = finder::questions(
        17,
        &frontier.predicates,
        &frontier.goals,
        12,
        64 * 1024,
        &mut |_| true,
    );
    let identities = |questions: Vec<ResearchQuestion>| {
        questions
            .into_iter()
            .take(generated.len())
            .map(|q| *q.resolution_id())
            .collect::<Vec<_>>()
    };
    let page = identities(frontier.candidate_page(17, |_| true));
    drop(frontier);
    let mut frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
    assert_eq!(frontier.evidence.model(), &model);
    assert_eq!(identities(frontier.candidate_page(17, |_| true)), page);
}

#[test]
fn finder_reopens_a_durable_observation_once_after_uncertain_acknowledgement() {
    let directory = Directory::new();
    let graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let question = ResearchQuestion::from_hex(&crate::learning::tests::own_question()).unwrap();
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    let result = native_failure(&question, 1, None);
    crate::checkpoint::fail_after_commit();
    assert!(
        frontier
            .attempted(&question, &graph, &result, Outcome::NoCandidate)
            .is_err()
    );
    assert_eq!(frontier.evidence.model().updates, 0);
    drop(frontier);
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    assert_eq!(frontier.evidence.model().updates, 1);
    frontier
        .attempted(&question, &graph, &result, Outcome::NoCandidate)
        .unwrap();
    assert_eq!(frontier.evidence.model().updates, 1);
    assert_eq!(frontier.evidence.model().resolved, 0);
}
fn checked(graph: &mut Graph, question: &ResearchQuestion) -> ArtifactId {
    graph
        .produce(&mocks::create_proof(question).unwrap())
        .unwrap()
        .1
        .id
}

#[test]
fn structure_ignores_spelling_and_preserves_generalizations_as_candidates() {
    let a = ResearchQuestion::from_hex("040301010000000001000000000001000000000100000000").unwrap();
    let b = ResearchQuestion::from_hex("040301010000000001000000000001000000000100000000").unwrap();
    let generalized =
        ResearchQuestion::from_hex("04040301010000000101000000000001000000010100000000").unwrap();
    assert_eq!(Features::of(&a), Features::of(&b));
    assert_ne!(Features::of(&a), Features::of(&generalized));
    let directory = Directory::new();
    let graph = Graph::default();
    let mut frontier = Frontier::open(&directory.0, &graph, 41, jobs::Settings::default()).unwrap();
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
    let mut frontier = Frontier::open(&directory.0, &graph, 7, jobs::Settings::default()).unwrap();
    let _ = checked(&mut graph, &question(0));
    frontier.refresh(&graph, |_| true).unwrap();
    assert!(frontier.coverage.iter().any(|n| *n > 0));
    assert_eq!(frontier.successes, [0; SIGNALS]);
    let common = frontier
        .weight(&question(0), &graph, jobs::RoleSettings::default())
        .unwrap();
    let rare = ResearchQuestion::from_hex("040101000000000100000000").unwrap();
    assert!(
        frontier
            .weight(&rare, &graph, jobs::RoleSettings::default())
            .unwrap()
            > common
    );
    assert!(frontier.evidence.get(&question(0)).unwrap().is_none());
}

#[test]
fn current_development_feedback_changes_the_actual_next_frontier_draw() {
    let directory = Directory::new();
    let graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..jobs::Settings::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 19, settings).unwrap();
    let easy =
        ResearchQuestion::from_hex("040301010000000001000000000101000000000100000000").unwrap();
    let hard = ResearchQuestion::from_hex(
        "040403010100000001010000000003010100000000010000000102030101000000010100000000020101000000000100000001",
    )
    .unwrap();
    let mut feedback = crate::learning::State::fresh().feedback();
    frontier.feedback(Some(feedback.clone()));
    let before = frontier.weight(&hard, &graph, settings.solving).unwrap();
    for _ in 0..64 {
        feedback.development.observe(&easy, 32, Some(true), 1_000);
    }
    feedback.revision += 1;
    frontier.feedback(Some(feedback.clone()));
    let after = frontier.weight(&hard, &graph, settings.solving).unwrap();
    assert_ne!(before, after);
    let candidates = [&easy, &hard];
    let index = frontier
        .choose(&candidates, &graph, settings.solving, false)
        .unwrap()
        .unwrap();
    let result = native_failure(candidates[index], 1, None);
    frontier
        .attempted(candidates[index], &graph, &result, Outcome::NoCandidate)
        .unwrap();
    assert!(!frontier.retry_ready(candidates[index], &graph).unwrap());
    let old = frontier.evidence.get(candidates[index]).unwrap().unwrap();
    assert_eq!(old.last_job, result.id);
    feedback.checkpoint = "22".repeat(32);
    feedback.attempts = crate::training::ability::Profile::new(feedback.checkpoint.clone());
    feedback.development = crate::training::ability::Profile::new(feedback.checkpoint.clone());
    frontier.feedback(Some(feedback));
    assert!(
        frontier.retry_ready(candidates[index], &graph).unwrap(),
        "old-model failures cannot cool down a new checkpoint"
    );
    let retained = frontier.evidence.get(candidates[index]).unwrap().unwrap();
    assert_eq!(retained.last_job, old.last_job);
    assert_eq!(retained.model_checkpoint, old.model_checkpoint);
    frontier.refresh(&graph, |_| true).unwrap();
    assert_eq!(
        frontier.learning_snapshot()["curriculum"]["checkpoint"],
        "22".repeat(32),
        "construction must use the current checkpoint before generating its page"
    );
}

#[test]
fn raw_candidates_failures_and_expiry_never_become_solving_evidence() {
    let directory = Directory::new();
    let graph = Graph::default();
    let mut frontier = Frontier::open(&directory.0, &graph, 5, jobs::Settings::default()).unwrap();
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
            proof: "invalid proof".into(),
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
    let frontier = Frontier::open(&directory.0, &graph, 999, jobs::Settings::default()).unwrap();
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
    let mut frontier = Frontier::open(&directory.0, &graph, 13, jobs::Settings::default()).unwrap();
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
            proof: source,
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
    let mut frontier = Frontier::open(&directory.0, &graph, 99, jobs::Settings::default()).unwrap();
    assert!(frontier.successes.iter().any(|n| *n > 0));
    assert_eq!(frontier.evidence.draws(), draw);
    assert_eq!(frontier.evidence.random(), random);
    frontier.verified(&target, &graph, 1, root).unwrap();
    drop(frontier);
    let frontier = Frontier::open(&directory.0, &graph, 99, jobs::Settings::default()).unwrap();
    assert_eq!(frontier.successes.iter().copied().max(), Some(1));
    // An unverified saved success never transfers validity to another graph.
    let empty = Graph::default();
    drop(frontier);
    let frontier = Frontier::open(&directory.0, &empty, 99, jobs::Settings::default()).unwrap();
    assert_eq!(frontier.successes, [0; SIGNALS]);
}

#[test]
fn local_definitions_generate_questions_and_relationships_without_a_user_profile() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    graph
        .produce("0100000000010000000b0100000000000000000000")
        .unwrap();
    let mut frontier = Frontier::open(&directory.0, &graph, 11, jobs::Settings::default()).unwrap();
    frontier.refresh(&graph, |_| true).unwrap();
    let goal = ResearchQuestion::from_hex("040101000000000100000000").unwrap();
    assert!(
        frontier
            .candidate_page(0, |_| true)
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
    let candidate = ResearchQuestion::from_hex(source).unwrap();
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
    let mut frontier = Frontier::open(&directory.0, &graph, 41, jobs::Settings::default()).unwrap();
    let result = completion(
        1,
        jobs::Output::Proof {
            proof: mocks::create_proof(&target).unwrap(),
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
    let mut changed = jobs::Settings::default();
    changed.solving.mock.outcome = jobs::MockOutcome::Failed;
    let frontier = Frontier::open(&directory.0, &graph, 41, changed).unwrap();
    assert_eq!(frontier.successes, [0; SIGNALS]);
    assert!(frontier.evidence.get(&target).unwrap().is_none());
    drop(frontier);
    let native = jobs::Settings {
        native_proof_learning: true,
        ..jobs::Settings::default()
    };
    let frontier = Frontier::open(&directory.0, &graph, 41, native).unwrap();
    assert_eq!(frontier.successes, [0; SIGNALS]);
    assert!(frontier.evidence.get(&target).unwrap().is_none());
    drop(frontier);
    let frontier = Frontier::open(&directory.0, &graph, 41, jobs::Settings::default()).unwrap();
    assert!(frontier.successes.iter().any(|count| *count > 0));
    assert_eq!(frontier.evidence.get(&target).unwrap().unwrap().units, 2);
}

#[test]
fn failed_implication_search_proposes_simpler_open_subgoals_and_restores_budget_bound_counts() {
    let directory = Directory::new();
    let graph = Graph::default();
    let target =
        ResearchQuestion::from_hex("040301010000000001000000000001000000000100000000").unwrap();
    let mut frontier = Frontier::open(&directory.0, &graph, 11, jobs::Settings::default()).unwrap();
    let result = completion(1, jobs::Output::NoCandidate, jobs::State::Complete);
    frontier
        .attempted(&target, &graph, &result, Outcome::NoCandidate)
        .unwrap();
    frontier
        .attempted(&target, &graph, &result, Outcome::NoCandidate)
        .unwrap();
    assert_eq!(frontier.attempts.iter().copied().max(), Some(1));
    let helper = ResearchQuestion::from_hex("040001000000000100000000").unwrap();
    assert!(
        frontier
            .candidate_page(0, |_| true)
            .iter()
            .any(|q| q.resolution_id() == helper.resolution_id())
    );
    drop(frontier);
    let mut frontier = Frontier::open(&directory.0, &graph, 11, jobs::Settings::default()).unwrap();
    assert_eq!(frontier.attempts.iter().copied().max(), Some(1));
    let result = completion(2, jobs::Output::NoCandidate, jobs::State::Failed);
    frontier
        .attempted(&target, &graph, &result, Outcome::Failed)
        .unwrap();
    assert_eq!(frontier.attempts.iter().copied().max(), Some(1));
    drop(frontier);
    let mut changed = jobs::Settings::default();
    changed.solving.limits.work_units += 1;
    let frontier = Frontier::open(&directory.0, &graph, 11, changed).unwrap();
    assert_eq!(frontier.attempts, [0; SIGNALS]);
}

#[test]
fn checked_catalog_yields_distinct_open_research_after_all_installed_answers_are_known() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    for index in 0..3 {
        let _ = checked(&mut graph, &question(index));
    }
    let mut frontier = Frontier::open(&directory.0, &graph, 11, jobs::Settings::default()).unwrap();
    frontier.refresh(&graph, |_| true).unwrap();
    let mut formal =
        crate::question::LocalQuestions::new(Some(mocks::select_question as fn(_) -> _));
    let candidates = frontier.candidate_page(0, |_| true);
    let eligible = candidates
        .iter()
        .filter(|q| formal.assess(&graph, q).passed())
        .collect::<Vec<_>>();
    assert!(
        eligible.len() >= 3,
        "closed theorem wrappers must not exhaust discovery"
    );
    let mut unique = std::collections::BTreeSet::new();
    for candidate in eligible {
        assert!((0..3).all(|i| question(i).resolution_id() != candidate.resolution_id()));
        assert!(unique.insert(*candidate.resolution_id()));
    }
    assert_eq!(graph.accepted_count(), 3);
    assert_eq!(frontier.successes, [0; SIGNALS]);
}

#[test]
fn open_definition_binders_do_not_collapse_distinct_variable_roles_in_conjectures() {
    let directory = Directory::new();
    let graph = Graph::default();
    let mut frontier = Frontier::open(&directory.0, &graph, 11, jobs::Settings::default()).unwrap();
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    frontier.explore(
        Formula::for_all(
            y,
            Formula::implies(Formula::member(x, y), Formula::equal(y, x)),
        ),
        &mut |_| true,
    );
    let expected =
        ResearchQuestion::from_hex("04040300010000000101000000000101000000000100000001").unwrap();
    assert!(
        frontier
            .candidate_page(0, |_| true)
            .iter()
            .any(|q| q.resolution_id() == expected.resolution_id())
    );
    assert_eq!(graph.accepted_count(), 0);
    assert_eq!(frontier.successes, [0; SIGNALS]);
}

#[test]
fn small_live_cache_keeps_new_eligible_obligations_instead_of_rejected_fragments() {
    const TEST: &str = "frontier::tests::small_live_cache_keeps_new_eligible_obligations_instead_of_rejected_fragments";
    if std::env::var_os("NAOME_FRONTIER_CACHE_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_FRONTIER_CACHE_TEST", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let mut budget = crate::resources::tests::snapshot(false);
    // Under the default installed capacity, this projects to the roughly
    // 9.6 KiB question cache observed in the ordinary node.
    budget.budget.cache_bytes = 18 << 20;
    crate::resources::adaptive::publish(budget);
    assert!((8192..=12_000).contains(&crate::resources::active_limits().question_cache_bytes));
    let directory = Directory::new();
    let mut graph = Graph::default();
    for index in 0..3 {
        let _ = checked(&mut graph, &question(index));
    }
    let mut frontier = Frontier::open(&directory.0, &graph, 17, jobs::Settings::default()).unwrap();
    let mut formal =
        crate::question::LocalQuestions::new(Some(mocks::select_question as fn(_) -> _));
    let mut pending = std::collections::BTreeSet::new();
    for _ in 0..3 {
        let mut diagnostics = Vec::new();
        let mut eligible = |question: &ResearchQuestion| {
            let decision = formal.assess(&graph, question);
            if diagnostics.len() < 12 {
                diagnostics.push((question.to_hex(), decision.rule, decision.reason));
            }
            !pending.contains(question.resolution_id()) && decision.passed()
        };
        frontier.refresh(&graph, &mut eligible).unwrap();
        let candidates = frontier
            .candidate_page(0, |_| true)
            .into_iter()
            .filter(&mut eligible)
            .collect::<Vec<_>>();
        assert!(
            !candidates.is_empty(),
            "the small cache discarded all useful research: cache={} pending={:?} assessments={:?}",
            crate::resources::active_limits().question_cache_bytes,
            pending,
            diagnostics
        );
        assert!(pending.insert(*candidates[0].resolution_id()));
        let bytes = frontier
            .proposals
            .iter()
            .map(|q| q.canonical_bytes().len() * 8 + 256)
            .sum::<usize>();
        assert!(bytes <= crate::resources::active_limits().question_cache_bytes / 4);
    }
    assert_eq!(pending.len(), 3);
    assert_eq!(graph.accepted_count(), 3);
    assert_eq!(frontier.successes, [0; SIGNALS]);
}

#[tokio::test]
async fn backlog_ranking_checks_only_the_selected_target_before_provider_work() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    let x = FreeVariable::new(0);
    let mut predicate = Formula::member(x, x);
    let mut backlog = Vec::new();
    for _ in 0..12 {
        let formula = Separation {
            predicate: predicate.clone(),
            element: x,
            source: FreeVariable::new(1),
            result: FreeVariable::new(2),
            parameters: vec![],
        }
        .formula()
        .unwrap();
        backlog.push(ResearchQuestion::from_formula(formula).unwrap());
        predicate = Formula::implies(predicate, Formula::equal(x, x));
    }
    let mut questions =
        crate::question::LocalQuestions::new(Some(mocks::select_question as fn(_) -> _));
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = crate::autonomous::Autonomous::new(
        crate::autonomous::Intervals {
            question_interval_ms: 3_600_000,
            proof_interval_ms: 1,
            ..Default::default()
        },
        owner.client.clone(),
        owner.recovery(),
        backlog,
    );
    autonomous
        .attach_frontier(&directory.0, &graph, 19)
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    autonomous.advance(&mut graph, &mut questions);
    assert_eq!(
        questions.computation_count(),
        1,
        "ranking must not repeatedly check the entire backlog"
    );
    let requests = owner.requests();
    assert_eq!(requests.len(), 1);
    assert!(matches!(requests[0].1, jobs::Input::Solve { .. }));
    assert!(autonomous.error().is_none());
}

fn helper_use_fixture() -> (
    Graph,
    ResearchQuestion,
    ArtifactId,
    ResearchQuestion,
    String,
) {
    let mut graph = Graph::default();
    let lemma = ResearchQuestion::from_hex(
        "0404040300010000000201000000010301010000000201000000000101000000010100000000",
    )
    .unwrap();
    use crate::test_inputs::{proof, variable};
    use naome_foundation::Formula;
    use naome_proof::ProofStep::{
        EqualitySubstitution, Generalization, ModusPonens, ProofReference, UniversalInstantiation,
    };
    let (a, b, c) = (variable(0), variable(1), variable(2));
    let source = proof(vec![
        EqualitySubstitution {
            from: a,
            to: b,
            body: Formula::member(a, c).into(),
        },
        Generalization {
            premise: 0,
            variable: c,
        },
        Generalization {
            premise: 1,
            variable: b,
        },
        Generalization {
            premise: 2,
            variable: a,
        },
    ]);
    let (artifact, admitted) = graph.produce(&source).unwrap();
    let proof_id = artifact.proof_id().unwrap().unwrap();
    let body = Formula::implies(
        Formula::equal(a, b),
        Formula::implies(Formula::member(a, c), Formula::member(b, c)),
    );
    let goal = crate::test_inputs::question(Formula::for_all(
        a,
        Formula::for_all(b, body.clone().substitute_free(c, a)),
    ));
    let consumer = proof(vec![
        ProofReference { proof_id },
        UniversalInstantiation {
            variable: a,
            replacement: a,
            body: Formula::for_all(b, Formula::for_all(c, body.clone())).into(),
        },
        ModusPonens {
            premise: 0,
            implication: 1,
        },
        UniversalInstantiation {
            variable: b,
            replacement: b,
            body: Formula::for_all(c, body.clone()).into(),
        },
        ModusPonens {
            premise: 2,
            implication: 3,
        },
        UniversalInstantiation {
            variable: c,
            replacement: a,
            body: body.into(),
        },
        ModusPonens {
            premise: 4,
            implication: 5,
        },
        Generalization {
            premise: 6,
            variable: b,
        },
        Generalization {
            premise: 7,
            variable: a,
        },
    ]);
    assert!(
        crate::learning::State::eligible(&lemma.to_hex()),
        "lemma must be eligible"
    );
    assert!(
        crate::learning::State::eligible(&goal.to_hex()),
        "goal must be eligible"
    );
    (graph, lemma, admitted.id, goal, consumer)
}
fn record_checked(
    frontier: &mut Frontier,
    graph: &Graph,
    question: &ResearchQuestion,
    job: u64,
    root: ArtifactId,
) {
    let result = completion(
        job,
        jobs::Output::Proof {
            proof: String::new(),
            helpers: vec![],
        },
        jobs::State::Complete,
    );
    frontier
        .attempted(question, graph, &result, Outcome::Candidate)
        .unwrap();
    frontier.prepared(question, job, root).unwrap();
    frontier.verified(question, graph, job, root).unwrap();
}
#[test]
fn checked_helper_support_is_durable_atomic_and_requires_an_earlier_unsolved_goal() {
    let (mut graph, lemma, lemma_root, goal, consumer) = helper_use_fixture();
    let directory = Directory::new();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    let missed = native_failure(&goal, 1, None);
    frontier
        .attempted(&goal, &graph, &missed, Outcome::NoCandidate)
        .unwrap();
    record_checked(&mut frontier, &graph, &lemma, 2, lemma_root);
    let root = graph.produce(&consumer).unwrap().1.id;
    assert_eq!(
        graph.direct_dependencies(root).unwrap().as_ref(),
        &[lemma_root]
    );
    let result = completion(
        3,
        jobs::Output::Proof {
            proof: consumer,
            helpers: vec![],
        },
        jobs::State::Complete,
    );
    frontier
        .attempted(&goal, &graph, &result, Outcome::Candidate)
        .unwrap();
    frontier.prepared(&goal, 3, root).unwrap();
    // Commit the checked resolution first to isolate the utility transaction.
    frontier.evidence.verified(&goal, 3, root).unwrap();
    let before = frontier.evidence.model().clone();
    crate::checkpoint::fail_next_commit();
    assert!(frontier.verified(&goal, &graph, 3, root).is_err());
    assert_eq!(frontier.evidence.model(), &before);
    assert_eq!(frontier.evidence.get(&lemma).unwrap().unwrap().supports, 0);
    frontier.verified(&goal, &graph, 3, root).unwrap();
    frontier.verified(&goal, &graph, 3, root).unwrap();
    assert_eq!(frontier.evidence.model().supports, 1);
    assert_eq!(frontier.evidence.get(&lemma).unwrap().unwrap().supports, 1);
    let model = frontier.evidence.model().clone();
    drop(frontier);
    let mut frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
    frontier.verified(&goal, &graph, 3, root).unwrap();
    assert_eq!(frontier.evidence.model(), &model);
}
#[test]
fn expiry_or_posthoc_helper_use_never_earns_support() {
    let (mut graph, lemma, lemma_root, goal, consumer) = helper_use_fixture();
    let root = graph.produce(&consumer).unwrap().1.id;
    for (state, outcome) in [
        (jobs::State::Expired, Outcome::Expired),
        (jobs::State::Failed, Outcome::Failed),
    ] {
        let directory = Directory::new();
        let settings = jobs::Settings {
            native_proof_learning: true,
            ..Default::default()
        };
        let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
        frontier
            .attempted(
                &goal,
                &graph,
                &completion(1, jobs::Output::NoCandidate, state),
                outcome,
            )
            .unwrap();
        record_checked(&mut frontier, &graph, &lemma, 2, lemma_root);
        record_checked(&mut frontier, &graph, &goal, 3, root);
        assert_eq!(frontier.evidence.model().supports, 0);
    }
    let directory = Directory::new();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    record_checked(&mut frontier, &graph, &lemma, 1, lemma_root);
    frontier
        .attempted(
            &goal,
            &graph,
            &native_failure(&goal, 2, None),
            Outcome::NoCandidate,
        )
        .unwrap();
    record_checked(&mut frontier, &graph, &goal, 3, root);
    assert_eq!(frontier.evidence.model().supports, 0);
}
#[test]
fn support_replay_recovers_a_missing_or_uncertain_credit_without_duplication() {
    for uncertain in [false, true] {
        let (mut graph, lemma, lemma_root, goal, consumer) = helper_use_fixture();
        let directory = Directory::new();
        let settings = jobs::Settings {
            native_proof_learning: true,
            ..Default::default()
        };
        let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
        frontier
            .attempted(
                &goal,
                &graph,
                &native_failure(&goal, 1, None),
                Outcome::NoCandidate,
            )
            .unwrap();
        record_checked(&mut frontier, &graph, &lemma, 2, lemma_root);
        let root = graph.produce(&consumer).unwrap().1.id;
        frontier
            .attempted(
                &goal,
                &graph,
                &completion(
                    3,
                    jobs::Output::Proof {
                        proof: consumer,
                        helpers: vec![],
                    },
                    jobs::State::Complete,
                ),
                Outcome::Candidate,
            )
            .unwrap();
        frontier.prepared(&goal, 3, root).unwrap();
        frontier.evidence.verified(&goal, 3, root).unwrap();
        if uncertain {
            crate::checkpoint::fail_after_commit();
            assert!(frontier.verified(&goal, &graph, 3, root).is_err());
        }
        assert_eq!(frontier.evidence.model().supports, 0);
        drop(frontier);
        let frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
        assert_eq!(frontier.evidence.model().supports, 1);
        let model = frontier.evidence.model().clone();
        drop(frontier);
        let frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
        assert_eq!(frontier.evidence.model(), &model);
    }
}
#[test]
fn solving_a_goal_without_using_its_helper_cannot_earn_support() {
    let (mut graph, lemma, lemma_root, goal, _) = helper_use_fixture();
    let directory = Directory::new();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    frontier
        .attempted(
            &goal,
            &graph,
            &native_failure(&goal, 1, None),
            Outcome::NoCandidate,
        )
        .unwrap();
    record_checked(&mut frontier, &graph, &lemma, 2, lemma_root);
    let source = "00000000060700000000000000010000000b0100000000000000000002210000000000000002050000000200000000000000230300000000000000000000010301000000000000000000020100000000010000000002200000000100000002210000000300000001210000000400000000";
    let root = graph.produce(source).unwrap().1.id;
    assert!(graph.direct_dependencies(root).unwrap().is_empty());
    record_checked(&mut frontier, &graph, &goal, 3, root);
    assert_eq!(frontier.evidence.model().supports, 0);
}
#[test]
fn completion_observations_not_job_allocation_order_establish_helper_timing() {
    let (mut graph, lemma, lemma_root, goal, consumer) = helper_use_fixture();
    let root = graph.produce(&consumer).unwrap().1.id;
    let directory = Directory::new();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    record_checked(&mut frontier, &graph, &lemma, 2, lemma_root);
    // This lower-ID job finishes only after the lemma was already checked.
    frontier
        .attempted(
            &goal,
            &graph,
            &native_failure(&goal, 1, None),
            Outcome::NoCandidate,
        )
        .unwrap();
    record_checked(&mut frontier, &graph, &goal, 3, root);
    assert_eq!(frontier.evidence.model().supports, 0);
}

#[test]
fn small_native_cache_keeps_the_owner_goal_and_rotates_its_actual_helpers() {
    const TEST: &str =
        "frontier::tests::small_native_cache_keeps_the_owner_goal_and_rotates_its_actual_helpers";
    if std::env::var_os("NAOME_NATIVE_GOAL_CACHE_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_NATIVE_GOAL_CACHE_TEST", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let mut profile = crate::resources::ResourceProfile::default();
    profile.tuning.question_cache_bytes = Some(4096);
    profile.tuning.question_page = Some(1);
    crate::resources::configure(profile).unwrap();
    let (goal, helpers) = crate::learning::tests::helper_goal();
    assert!(crate::learning::State::eligible(&goal.to_hex()));
    let cost = goal.to_hex().len() * 8 + 256;
    assert!(
        cost > 1024 && cost <= 4096,
        "exercise the real cache partition boundary"
    );
    let directory = Directory::new();
    let graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    frontier.focus(goal.clone());
    assert_eq!(frontier.goals.len(), 1);
    let candidates = (0..32)
        .flat_map(|cursor| frontier.candidate_page(cursor, |_| true))
        .collect::<Vec<_>>();
    assert!(candidates.iter().any(|q| q.core() == goal.core()));
    for helper in &helpers {
        assert!(
            candidates.iter().any(|q| q.core() == helper.core()),
            "a prerequisite must fit a rotating one-item page"
        );
    }
    assert!(
        frontier
            .goals
            .iter()
            .map(|q| q.to_hex().len() * 8 + 256)
            .sum::<usize>()
            <= 4096
    );
}
#[test]
fn native_checked_theorems_supply_proper_relations_without_posthoc_weakenings() {
    let (graph, lemma, _, _, _) = helper_use_fixture();
    let directory = Directory::new();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    frontier.refresh(&graph, |_| true).unwrap();
    assert!(
        frontier.proposals.is_empty(),
        "closed proofs must not create unconditional weakenings"
    );
    assert!(!frontier.predicates.is_empty());
    for relation in &frontier.predicates {
        assert_eq!(relation.free_variables().len(), 2);
        let mut closed = relation.clone();
        for variable in closed.free_variables().into_iter().rev() {
            closed = Formula::for_all(variable, closed);
        }
        let question = ResearchQuestion::from_formula(closed).unwrap();
        assert_ne!(finder::key(&question), finder::key(&lemma));
    }
}
#[test]
fn explicit_goal_exploration_contains_only_the_goal_and_its_conjunct_helpers() {
    let (goal, helpers) = crate::learning::tests::helper_goal();
    let directory = Directory::new();
    let graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    frontier.focus(ResearchQuestion::from_hex("040101000000000100000000").unwrap());
    let pool = (0..8)
        .flat_map(|cursor| frontier.goal_candidates(cursor, &goal))
        .collect::<Vec<_>>();
    for question in &pool {
        assert!(
            question.resolution_id() == goal.resolution_id()
                || helpers
                    .iter()
                    .any(|q| q.resolution_id() == question.resolution_id()),
            "unrelated exploration cannot replace an explicit goal"
        );
    }
    assert!(
        helpers
            .iter()
            .all(|h| pool.iter().any(|q| q.core() == h.core()))
    );
    assert!(pool.iter().any(|q| q.core() == goal.core()));
}

#[test]
fn failed_search_plan_is_atomic_recoverable_and_waits_for_checked_helper_roots() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    let (goal, helpers) = crate::learning::tests::helper_goal();
    let report = crate::learning::tests::stalled_frontier(&goal);
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    let failed = native_failure(&goal, 1, Some(report.clone()));
    crate::checkpoint::fail_next_commit();
    assert!(
        frontier
            .attempted(&goal, &graph, &failed, Outcome::NoCandidate)
            .is_err()
    );
    assert!(
        frontier
            .loop_work(&goal, &graph, |_| true)
            .unwrap()
            .planned
            .is_empty()
    );
    frontier
        .attempted(&goal, &graph, &failed, Outcome::NoCandidate)
        .unwrap();
    let plan = frontier.loop_work(&goal, &graph, |_| true).unwrap();
    for helper in &helpers {
        assert!(
            plan.pending
                .iter()
                .any(|q| q.resolution_id() == helper.resolution_id())
        );
    }
    let before = plan
        .planned
        .iter()
        .map(|q| *q.resolution_id())
        .collect::<Vec<_>>();
    drop(frontier);
    let mut frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
    assert_eq!(
        before,
        frontier
            .loop_work(&goal, &graph, |_| true)
            .unwrap()
            .planned
            .iter()
            .map(|q| *q.resolution_id())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        frontier
            .loop_focus(&graph, |_| true)
            .unwrap()
            .unwrap()
            .0
            .resolution_id(),
        goal.resolution_id()
    );
    for (i, helper) in helpers.iter().enumerate() {
        let solution = crate::learning::tests::symbolic_solution(helper);
        let job = 2 + i as u64;
        let result = completion(
            job,
            jobs::Output::Native {
                terminal: crate::learning::experience::TerminalEvidence::certified(&solution)
                    .into(),
                solution: Some(solution.clone()),
                frontier: None,
            },
            jobs::State::Complete,
        );
        frontier
            .attempted(helper, &graph, &result, Outcome::Candidate)
            .unwrap();
        assert!(
            frontier
                .loop_work(&goal, &graph, |_| true)
                .unwrap()
                .required
                .is_empty()
                || i > 0
        );
        let (root, batch) = graph
            .prepare_generated(&solution.source, &solution.helpers, helper)
            .unwrap();
        graph
            .commit_batch(root, batch, Instant::now() + Duration::from_secs(10))
            .unwrap();
        frontier.prepared(helper, job, root).unwrap();
        frontier.verified(helper, &graph, job, root).unwrap();
    }
    let work = frontier.loop_work(&goal, &graph, |_| true).unwrap();
    assert!(work.pending.is_empty());
    assert_eq!(work.required.len(), 2);
    assert_eq!(frontier.evidence.model().supports, 0);
    frontier.exhaust_helpers(&goal).unwrap();
    drop(frontier);
    let mut frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
    let work = frontier.loop_work(&goal, &graph, |_| true).unwrap();
    assert!(work.planned.is_empty() && work.required.is_empty());
}

#[test]
fn an_abandoned_candidate_does_not_hold_its_parent_or_create_a_failure_label() {
    let directory = Directory::new();
    let graph = Graph::default();
    let (goal, helpers) = crate::learning::tests::helper_goal();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    let failed = native_failure(
        &goal,
        1,
        Some(crate::learning::tests::stalled_frontier(&goal)),
    );
    frontier
        .attempted(&goal, &graph, &failed, Outcome::NoCandidate)
        .unwrap();
    for (i, helper) in helpers.iter().enumerate() {
        let candidate = completion(
            2 + i as u64,
            jobs::Output::Proof {
                proof: crate::learning::tests::symbolic_solution(helper).source,
                helpers: Vec::new(),
            },
            jobs::State::Complete,
        );
        frontier
            .attempted(helper, &graph, &candidate, Outcome::Candidate)
            .unwrap();
        frontier.abandon_publication(helper, candidate.id).unwrap();
    }
    assert!(
        frontier
            .loop_work(&goal, &graph, |_| true)
            .unwrap()
            .pending
            .is_empty()
    );
    assert_eq!(frontier.evidence.model().resolved, 0);
    assert_eq!(frontier.evidence.model().unresolved, 1);
    drop(frontier);
    let mut frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
    assert!(
        frontier
            .loop_work(&goal, &graph, |_| true)
            .unwrap()
            .pending
            .is_empty()
    );
}

#[test]
fn missing_established_evidence_remains_a_structured_start_failure() {
    let directory = Directory::new();
    let graph = Graph::default();
    drop(Frontier::open(&directory.0, &graph, 1, jobs::Settings::default()).unwrap());
    std::fs::remove_file(directory.0.join("research/evidence.sqlite3")).unwrap();
    let error = Frontier::open(&directory.0, &graph, 1, jobs::Settings::default())
        .err()
        .unwrap();
    assert_eq!(
        serde_json::to_value(error).unwrap()["code"],
        u32::from(crate::ResearchFailure::EvidenceMissing)
    );
}
