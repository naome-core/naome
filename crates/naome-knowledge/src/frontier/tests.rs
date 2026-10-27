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

#[test]
fn finder_learning_is_atomic_idempotent_and_requires_a_checked_resolution_for_success() {
    let directory = Directory::new();
    let mut graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let question = CompiledQuestion::compile(&crate::learning::tests::own_question()).unwrap();
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    let initial = frontier.evidence.model().clone();
    assert!(!frontier.helpers_needed(&question).unwrap());
    let unresolved = completion(1, jobs::Output::NoCandidate, jobs::State::Complete);
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
            source: solution.source.clone(),
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
    let generated = finder::questions(17, &frontier.predicates, &frontier.goals, 12, 64 * 1024);
    let identities = |questions: Vec<CompiledQuestion>| {
        questions
            .into_iter()
            .take(generated.len())
            .map(|q| *q.resolution_id())
            .collect::<Vec<_>>()
    };
    let page = identities(frontier.candidates(17));
    drop(frontier);
    let frontier = Frontier::open(&directory.0, &graph, 99, settings).unwrap();
    assert_eq!(frontier.evidence.model(), &model);
    assert_eq!(identities(frontier.candidates(17)), page);
}

#[test]
fn finder_reopens_a_durable_observation_once_after_uncertain_acknowledgement() {
    let directory = Directory::new();
    let graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let question = CompiledQuestion::compile(&crate::learning::tests::own_question()).unwrap();
    let mut frontier = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    let result = completion(1, jobs::Output::NoCandidate, jobs::State::Complete);
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
fn current_development_feedback_changes_the_actual_next_frontier_draw() {
    let directory = Directory::new();
    let graph = Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..jobs::Settings::default()
    };
    let mut frontier = Frontier::open(&directory.0, &graph, 19, settings).unwrap();
    let easy = CompiledQuestion::compile("goal=all(a,imp(mem(a,a),mem(a,a)))").unwrap();
    let hard = CompiledQuestion::compile(
        "goal=all(x,all(y,imp(mem(x,y),imp(mem(y,x),and(mem(x,y),mem(y,x))))))",
    )
    .unwrap();
    let mut feedback = crate::training::ability::Feedback::fresh("11".repeat(32));
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
    let result = completion(1, jobs::Output::NoCandidate, jobs::State::Complete);
    frontier
        .attempted(candidates[index], &graph, &result, Outcome::NoCandidate)
        .unwrap();
    assert!(frontier.evidence.get(candidates[index]).unwrap().is_some());
    feedback.checkpoint = "22".repeat(32);
    feedback.attempts = crate::training::ability::Profile::new(feedback.checkpoint.clone());
    feedback.development = crate::training::ability::Profile::new(feedback.checkpoint.clone());
    frontier.feedback(Some(feedback));
    assert!(frontier.recent.is_empty());
    assert!(
        frontier.evidence.get(candidates[index]).unwrap().is_none(),
        "old-model failures cannot cool down a new checkpoint"
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
        .produce("def member_self = relation(x): mem(x,x)")
        .unwrap();
    let mut frontier = Frontier::open(&directory.0, &graph, 11, jobs::Settings::default()).unwrap();
    frontier.refresh(&graph, |_| true).unwrap();
    let goal = CompiledQuestion::compile("goal = all(x,mem(x,x))").unwrap();
    assert!(
        frontier
            .candidates(0)
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
    let mut frontier = Frontier::open(&directory.0, &graph, 41, jobs::Settings::default()).unwrap();
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
    let target = CompiledQuestion::compile("goal=all(x,imp(mem(x,x),eq(x,x)))").unwrap();
    let mut frontier = Frontier::open(&directory.0, &graph, 11, jobs::Settings::default()).unwrap();
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
            .candidates(0)
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
    let candidates = frontier.candidates(0);
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
    let expected = CompiledQuestion::compile("goal=all(y,all(x,imp(eq(y,x),mem(x,y))))").unwrap();
    assert!(
        frontier
            .candidates(0)
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
        let mut eligible = |question: &CompiledQuestion| {
            let decision = formal.assess(&graph, question);
            if diagnostics.len() < 12 {
                diagnostics.push((question.source().to_owned(), decision.rule, decision.reason));
            }
            !pending.contains(question.resolution_id()) && decision.passed()
        };
        frontier.refresh(&graph, &mut eligible).unwrap();
        let candidates = frontier
            .candidates(0)
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
            .map(|q| q.source().len() * 8 + 256)
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
        backlog.push(CompiledQuestion::from_formula(formula).unwrap());
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
    CompiledQuestion,
    ArtifactId,
    CompiledQuestion,
    String,
) {
    let mut graph = Graph::default();
    let lemma =
        CompiledQuestion::compile("goal=all(a,all(b,all(c,imp(eq(a,b),imp(mem(a,c),mem(b,c))))))")
            .unwrap();
    let source = format!(
        "{} proof: p0=subst(a,b,mem(a,c)) p1=gen(p0,c) p2=gen(p1,b) p3=gen(p2,a) return p3",
        lemma.source()
    );
    let (artifact, admitted) = graph.produce(&source).unwrap();
    let proof = crate::hex(artifact.proof_id().unwrap().unwrap().as_bytes());
    let goal = CompiledQuestion::compile("goal=all(a,all(b,imp(eq(a,b),imp(mem(a,a),mem(b,a)))))")
        .unwrap();
    let consumer = format!(
        r#"{} proof:
        p0=cite("{}")
        p1=inst(a,a,all(b,all(c,imp(eq(a,b),imp(mem(a,c),mem(b,c))))))
        p2=mp(p0,p1)
        p3=inst(b,b,all(c,imp(eq(a,b),imp(mem(a,c),mem(b,c)))))
        p4=mp(p2,p3)
        p5=inst(c,a,imp(eq(a,b),imp(mem(a,c),mem(b,c))))
        p6=mp(p4,p5) p7=gen(p6,b) p8=gen(p7,a) return p8"#,
        goal.source(),
        proof
    );
    assert!(
        crate::learning::State::eligible(lemma.source()),
        "lemma must be eligible"
    );
    assert!(
        crate::learning::State::eligible(goal.source()),
        "goal must be eligible"
    );
    (graph, lemma, admitted.id, goal, consumer)
}
fn record_checked(
    frontier: &mut Frontier,
    graph: &Graph,
    question: &CompiledQuestion,
    job: u64,
    root: ArtifactId,
) {
    let result = completion(
        job,
        jobs::Output::Proof {
            source: String::new(),
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
    let missed = completion(1, jobs::Output::NoCandidate, jobs::State::Complete);
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
            source: consumer,
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
            &completion(2, jobs::Output::NoCandidate, jobs::State::Complete),
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
                &completion(1, jobs::Output::NoCandidate, jobs::State::Complete),
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
                        source: consumer,
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
            &completion(1, jobs::Output::NoCandidate, jobs::State::Complete),
            Outcome::NoCandidate,
        )
        .unwrap();
    record_checked(&mut frontier, &graph, &lemma, 2, lemma_root);
    let source = format!(
        "{} proof: p0=subst(a,b,mem(a,c)) p1=gen(p0,c) p2=inst(c,a,imp(eq(a,b),imp(mem(a,c),mem(b,c)))) p3=mp(p1,p2) p4=gen(p3,b) p5=gen(p4,a) return p5",
        goal.source()
    );
    let root = graph.produce(&source).unwrap().1.id;
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
            &completion(1, jobs::Output::NoCandidate, jobs::State::Complete),
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
    assert!(crate::learning::State::eligible(goal.source()));
    let cost = goal.source().len() * 8 + 256;
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
        .flat_map(|cursor| frontier.candidates(cursor))
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
            .map(|q| q.source().len() * 8 + 256)
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
        let question = CompiledQuestion::from_formula(closed).unwrap();
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
    frontier.focus(CompiledQuestion::compile("goal=all(a,mem(a,a))").unwrap());
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
