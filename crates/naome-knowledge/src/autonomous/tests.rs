use super::*;
mod calibration;
use crate::mocks;
use crate::question::{AdmissionOutcome, LocalQuestions};
use naome_checker::question::PrefilterPolicy;
use std::{
    future::Ready,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

type Questions = LocalQuestions<fn(CompiledQuestion) -> Ready<Result<bool, String>>>;
fn questions() -> Questions {
    LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _))
}
fn intervals(question_interval_ms: u64) -> Intervals {
    Intervals {
        question_interval_ms,
        proof_interval_ms: 100,
        ..Intervals::default()
    }
}
async fn admitted<F, Fut>(
    questions: &mut LocalQuestions<F>,
    graph: &Graph,
    question: &CompiledQuestion,
) where
    F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<bool, String>> + Send + 'static,
{
    let (reply, receiver) = oneshot::channel();
    questions.process(question::Command::Admit(question.clone(), reply), graph);
    assert!(!questions.available());
    let selection = tokio::time::timeout(Duration::from_secs(5), questions.completed())
        .await
        .unwrap();
    questions.finish(graph, selection);
    assert!(matches!(
        receiver.await.unwrap().outcome,
        AdmissionOutcome::Admitted(_)
    ));
}

fn recovered(id: u64, input: jobs::Input) -> jobs::Record {
    jobs::Record {
        id,
        input,
        binding: jobs::Binding::new([1; 32], [2; 32]),
        provider: "00".repeat(32),
        native: None,
        configuration: "00".repeat(32),
        settings: jobs::RoleSettings::default(),
        created_ms: 1,
        expires_ms: 60_001,
        accounted_ms: 1,
        spent_ms: 0,
        reserved_units: 0,
        checkpoint: 0,
        state: jobs::State::Queued,
        result: None,
        acknowledged: false,
        failure: None,
    }
}

#[tokio::test]
async fn exhausted_free_research_plan_releases_independent_finding() {
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = Graph::default();
    let mut questions = questions();
    let (goal, helpers) = crate::learning::tests::helper_goal();
    for q in std::iter::once(&goal).chain(helpers.iter()) {
        admitted(&mut questions, &graph, q).await;
    }
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = crate::frontier::Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    for (index, q) in std::iter::once(&goal).chain(helpers.iter()).enumerate() {
        frontier
            .attempted(
                q,
                &graph,
                &jobs::Completion {
                    id: index as u64 + 1,
                    binding: jobs::Binding::new([0; 32], [0; 32]),
                    spent_ms: 1,
                    reserved_units: 1,
                    state: jobs::State::Complete,
                    result: Ok(jobs::Output::Native {
                        solution: None,
                        diagnostic: "search_budget".into(),
                        frontier: (index == 0).then(|| crate::learning::tests::stalled_frontier(q)),
                    }),
                },
                crate::frontier::evidence::Outcome::NoCandidate,
            )
            .unwrap();
    }
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(500),
        owner.client.clone(),
        owner.recovery(),
        vec![goal.clone()],
    );
    autonomous.frontier = Some(frontier);
    autonomous.next_proof = Instant::now() + Duration::from_secs(3600);
    autonomous.next_question = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    let requests = owner.requests();
    assert!(
        requests.iter().any(
            |(_, input)| matches!(input,jobs::Input::Find{question,..} if question!=goal.source())
        ),
        "an exhausted optional plan cannot suppress all new finding"
    );
    assert!(
        autonomous
            .unanswered
            .iter()
            .any(|q| q.resolution_id() == goal.resolution_id()),
        "parking must preserve the unanswered original"
    );
    assert!(autonomous.error().is_none());
}

#[tokio::test]
async fn inconclusive_recovery_does_not_starve_later_records_or_archive_pages() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let mut policy = PrefilterPolicy::default();
    policy.limits.certificate_steps = 1;
    let (reply, receiver) = oneshot::channel();
    questions.process(question::Command::Policy(policy, reply), &graph);
    receiver.await.unwrap();
    let limited = jobs::Input::Solve {
        question: "goal=all(x,imp(mem(x,x),mem(x,x)))".into(),
    };
    let available = jobs::Input::Solve {
        question: "goal=all(x,mem(x,x))".into(),
    };
    let first = recovered(1, limited.clone());
    let original = serde_json::to_vec(&first).unwrap();
    let mut owner = jobs::tests::Manual::new();
    owner.queue_recovery(vec![recovered(3, limited.clone())], Some(3));
    owner.queue_recovery(
        vec![recovered(
            4,
            jobs::Input::Select {
                question: "goal=all(x,mem(x,x))".into(),
                purpose: jobs::Purpose::Admission,
                root: None,
            },
        )],
        None,
    );
    let mut recovery = owner.recovery();
    recovery.records = vec![first, recovered(2, available.clone())];
    recovery.archive_end = 5;
    let mut autonomous =
        Autonomous::new(intervals(3_600_000), owner.client.clone(), recovery, vec![]);
    let mut submitted = Vec::new();
    for _ in 0..10 {
        autonomous.advance(&mut graph, &mut questions);
        submitted.extend(owner.requests());
    }
    assert_eq!(
        submitted.iter().map(|(_, input)| input).collect::<Vec<_>>(),
        vec![&available]
    );
    assert_eq!(owner.recovery_requests(), &[(0, 5), (3, 5)]);
    assert!(autonomous.recovered_other.is_empty());
    assert!(autonomous.archive_after.is_none() && autonomous.recovery_reply.is_none());
    assert!(!owner.discarded().contains(&limited));
    assert!(
        !owner
            .acknowledgements()
            .iter()
            .any(|id| matches!(id, 1 | 3))
    );
    assert_eq!(autonomous.deferred_recovery.len(), 1);
    assert_eq!(
        serde_json::to_vec(autonomous.deferred_recovery.front().unwrap()).unwrap(),
        original
    );
    let computations = questions.computation_count();
    for _ in 0..100 {
        autonomous.advance(&mut graph, &mut questions);
        assert!(owner.requests().is_empty());
    }
    assert_eq!(questions.computation_count(), computations);
    // A timed retry also permits transient context reads to recover without
    // depending on a policy/graph change, but never retries on every owner wake.
    autonomous.recovery_retry.as_mut().unwrap().retry = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    owner.requests();
    assert_eq!(questions.computation_count(), computations + 1);
    assert_eq!(
        serde_json::to_vec(autonomous.deferred_recovery.front().unwrap()).unwrap(),
        original
    );
    // A policy change must make the preserved original work eligible again.
    let (reply, receiver) = oneshot::channel();
    questions.process(
        question::Command::Policy(PrefilterPolicy::default(), reply),
        &graph,
    );
    receiver.await.unwrap();
    for _ in 0..5 {
        autonomous.advance(&mut graph, &mut questions);
        owner.requests();
    }
    assert!(owner.discarded().contains(&limited));
    assert!(questions.computation_count() > computations);
    assert!(autonomous.deferred_recovery.is_empty());
}

#[tokio::test]
async fn rejected_unanswered_work_preserves_its_retry_and_independent_question_schedule() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mut questions = LocalQuestions::new(Some(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(true))
    }));
    let mut graph = Graph::default();
    let selected = CompiledQuestion::compile(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &selected).await;
    let mut policy = PrefilterPolicy::default();
    policy.limits.operations = 1;
    let (reply, receiver) = oneshot::channel();
    questions.process(question::Command::Policy(policy, reply), &graph);
    receiver.await.unwrap();
    let mut owner = jobs::tests::Manual::new();
    let mut recovery = owner.recovery();
    recovery.next_cursor = 1;
    let mut autonomous = Autonomous::new(
        intervals(100),
        owner.client.clone(),
        recovery,
        vec![selected],
    );
    autonomous.next_question = Instant::now();
    autonomous.next_proof = Instant::now();
    assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
    assert_eq!(
        autonomous.unanswered.len(),
        1,
        "formal rejection retains unanswered work"
    );
    assert!(
        autonomous.finding.is_some(),
        "independent finding job still runs"
    );
    assert!(
        autonomous.solving.is_empty(),
        "formal rejection never invokes solving"
    );
    assert!(matches!(
        owner.requests().as_slice(),
        [(_, jobs::Input::Find { cursor: 1, .. })]
    ));
    assert_eq!(autonomous.cursor, 2);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "formal rejection never invokes selection"
    );
    assert!(autonomous.next_proof > Instant::now());
}

#[tokio::test]
async fn changed_graph_rebuilds_generated_closure_without_repeating_selection() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let selected = CompiledQuestion::compile(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &selected).await;
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![selected.clone()],
    );
    autonomous.next_proof = Instant::now();
    assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
    let requests = owner.requests();
    assert!(matches!(
        requests.as_slice(),
        [(_, jobs::Input::Solve { .. })]
    ));
    owner.complete(
        requests[0].0,
        Ok(jobs::Output::Proof {
            source: mocks::create_proof(&selected).unwrap(),
            helpers: Vec::new(),
        }),
    );
    assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
    assert_eq!(autonomous.publications.len(), 1);
    let unrelated = CompiledQuestion::compile(&mocks::create_question(1)).unwrap();
    let object = graph
        .author(&mocks::create_proof(&unrelated).unwrap())
        .unwrap();
    graph.ingest(object, Instant::now()).unwrap();
    let selection = tokio::time::timeout(Duration::from_secs(5), questions.completed())
        .await
        .unwrap();
    questions.finish(&graph, selection);
    assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
    assert_eq!(
        graph.ids().len(),
        1,
        "stale staged closure publishes nothing"
    );
    assert_eq!(
        autonomous.publications.len(),
        1,
        "bounded candidate and its positive selection survive for fresh checking"
    );
    assert!(
        autonomous
            .publications
            .front()
            .unwrap()
            .assessment
            .is_some()
    );
    assert_eq!(autonomous.advance(&mut graph, &mut questions).len(), 1);
    assert!(
        questions.available(),
        "no second provider decision after unrelated graph growth"
    );
    assert_eq!(graph.ids().len(), 2);
    assert!(autonomous.publications.is_empty() && autonomous.unanswered.is_empty());
}

#[tokio::test]
async fn unsupported_questions_retry_boundedly_and_a_received_answer_cancels_generation() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let unsupported = CompiledQuestion::compile("goal = all(x,mem(x,x))").unwrap();
    admitted(&mut questions, &graph, &unsupported).await;
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![unsupported],
    );
    autonomous.next_proof = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    let requests = owner.requests();
    assert_eq!(requests.len(), 1);
    owner.complete(requests[0].0, Ok(jobs::Output::NoCandidate));
    assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
    assert_eq!(autonomous.unanswered.len(), 1);
    assert!(autonomous.solving.is_empty());
    assert!(autonomous.next_proof > Instant::now());
    autonomous.unanswered.clear();
    let answered = CompiledQuestion::compile(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &answered).await;
    let object = graph
        .author(&mocks::create_proof(&answered).unwrap())
        .unwrap();
    graph.ingest(object, Instant::now()).unwrap();
    autonomous.unanswered.push_back(answered);
    autonomous.next_proof = Instant::now();
    assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
    assert!(autonomous.unanswered.is_empty() && autonomous.solving.is_empty());
    assert!(owner.requests().is_empty());
    assert_eq!(graph.ids().len(), 1);
}

#[tokio::test]
async fn busy_gossip_wakes_do_not_repeat_formal_work_for_unchanged_pending_jobs() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let selected = CompiledQuestion::compile(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &selected).await;
    let owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![selected],
    );
    autonomous.next_proof = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    let before = questions.computation_count();
    for _ in 0..100 {
        autonomous.advance(&mut graph, &mut questions);
    }
    assert_eq!(questions.computation_count(), before);
    assert_eq!(autonomous.solving.len(), 1);
}

#[tokio::test]
async fn unchanged_successful_publication_retains_the_first_checked_batch() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let selected = CompiledQuestion::compile(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &selected).await;
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![selected.clone()],
    );
    autonomous.next_proof = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    let request = owner.requests().remove(0);
    owner.complete(
        request.0,
        Ok(jobs::Output::Proof {
            source: mocks::create_proof(&selected).unwrap(),
            helpers: Vec::new(),
        }),
    );
    autonomous.advance(&mut graph, &mut questions);
    assert_eq!(graph.checker_calls(), (1, 0));
    let selection = tokio::time::timeout(Duration::from_secs(5), questions.completed())
        .await
        .unwrap();
    questions.finish(&graph, selection);
    assert_eq!(autonomous.advance(&mut graph, &mut questions).len(), 1);
    assert_eq!(
        graph.checker_calls(),
        (1, 0),
        "unchanged root is compiled/checked once across selection and commit"
    );
    assert_eq!(graph.accepted_count(), 1);
}

#[test]
fn full_job_channel_retains_one_exact_receipt_and_defers_new_autonomous_work() {
    let input = jobs::Input::Solve {
        question: "goal=all(x,eq(x,x))".into(),
    };
    let binding = jobs::Binding::new([3; 32], [4; 32]);
    for receipt in [
        jobs::Receipt::Acknowledge(91),
        jobs::Receipt::Accepted {
            id: 92,
            root: "ab".repeat(32),
        },
        jobs::Receipt::Discard(input, binding),
    ] {
        let mut owner = jobs::tests::Manual::new();
        let mut autonomous = Autonomous::new(
            intervals(3_600_000),
            owner.client.clone(),
            owner.recovery(),
            vec![],
        );
        let mut graph = Graph::default();
        let mut questions = questions();
        for id in 1..=crate::resources::limits().job_commands {
            owner.client.acknowledge(id as u64).unwrap();
        }
        assert!(!autonomous.receipt(receipt.clone()));
        autonomous.next_question = Instant::now() - Duration::from_secs(1);
        for _ in 0..3 {
            assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
            assert_eq!(autonomous.pending_receipt.as_ref(), Some(&receipt));
            assert_eq!(
                autonomous.cursor, 0,
                "queue pressure cannot start another obligation"
            );
            assert!(autonomous.error().is_none());
        }
        assert!(owner.requests().is_empty());
        owner.receipts();
        autonomous.advance(&mut graph, &mut questions);
        assert!(autonomous.pending_receipt.is_none());
        assert_eq!(
            owner.receipts(),
            vec![receipt],
            "the original receipt must be delivered once with identical binding"
        );
        assert!(autonomous.error().is_none());
    }
}
#[test]
fn deferred_completion_receipt_preserves_the_unsolved_question_and_closed_service_still_fails() {
    let mut owner = jobs::tests::Manual::new();
    let question = CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let ticket = owner
        .client
        .submit(
            jobs::Input::Solve {
                question: question.source().into(),
            },
            jobs::Binding::new([0; 32], [0; 32]),
        )
        .unwrap();
    let id = owner.requests()[0].0;
    owner.complete(id, Ok(jobs::Output::NoCandidate));
    let mut graph = Graph::default();
    let mut questions = questions();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![],
    );
    autonomous.solving.insert(
        *question.resolution_id(),
        Solving {
            completion: None,
            question: question.clone(),
            ticket,
            seen: questions.revision(&graph),
        },
    );
    for index in 0..crate::resources::limits().job_commands {
        owner.client.acknowledge(100 + index as u64).unwrap();
    }
    autonomous.advance(&mut graph, &mut questions);
    assert_eq!(
        autonomous.pending_receipt,
        Some(jobs::Receipt::Acknowledge(id))
    );
    assert!(autonomous.unanswered.contains(&question));
    assert!(autonomous.solving.is_empty() && autonomous.error().is_none());
    owner.requests();
    autonomous.advance(&mut graph, &mut questions);
    assert!(autonomous.pending_receipt.is_none());
    drop(owner);
    assert!(!autonomous.acknowledge(999));
    assert!(autonomous.error().unwrap().contains("stopped"));
    assert!(
        autonomous.pending_receipt.is_none(),
        "a stopped owner is not an endless capacity retry"
    );
}

#[tokio::test]
async fn research_evidence_backpressure_retains_the_original_completion_until_durable() {
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = Graph::default();
    let mut questions = questions();
    let target = CompiledQuestion::compile(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &target).await;
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        Intervals {
            question_interval_ms: 3_600_000,
            proof_interval_ms: 1,
            ..Default::default()
        },
        owner.client.clone(),
        owner.recovery(),
        vec![target],
    );
    autonomous
        .attach_frontier(&directory.0, &graph, 43)
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2)).await;
    autonomous.advance(&mut graph, &mut questions);
    let requests = owner.requests();
    let [(id, jobs::Input::Solve { .. })] = requests.as_slice() else {
        panic!("original solve request missing");
    };
    owner.complete(*id, Ok(jobs::Output::NoCandidate));
    crate::checkpoint::fail_next_commit();
    autonomous.advance(&mut graph, &mut questions);
    assert!(autonomous.error().is_none());
    assert!(owner.acknowledgements().is_empty());
    assert_eq!(autonomous.solving.len(), 1);
    assert!(
        autonomous
            .solving
            .values()
            .all(|job| job.completion.is_some())
    );
    autonomous.advance(&mut graph, &mut questions);
    assert!(autonomous.error().is_none());
    assert!(owner.acknowledgements().contains(id));
}

#[tokio::test]
async fn stalled_owner_goal_waits_for_each_planned_helper_and_then_retries_once() {
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = Graph::default();
    let mut questions = questions();
    let (goal, helpers) = crate::learning::tests::helper_goal();
    for q in std::iter::once(&goal).chain(helpers.iter()) {
        admitted(&mut questions, &graph, q).await;
    }
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = crate::frontier::Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    frontier
        .attempted(
            &goal,
            &graph,
            &jobs::Completion {
                id: 1,
                binding: jobs::Binding::new([0; 32], [0; 32]),
                spent_ms: 1,
                reserved_units: 1,
                state: jobs::State::Complete,
                result: Ok(jobs::Output::Native {
                    solution: None,
                    diagnostic: "search_budget".into(),
                    frontier: Some(crate::learning::tests::stalled_frontier(&goal)),
                }),
            },
            crate::frontier::evidence::Outcome::NoCandidate,
        )
        .unwrap();
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![goal.clone()],
    );
    autonomous.frontier = Some(frontier);
    autonomous.formal_goal(Some(goal.clone()));
    let mut attempted = BTreeSet::new();
    let mut retried = false;
    for _ in 0..8 {
        autonomous.next_proof = Instant::now();
        autonomous.next_question = Instant::now() + Duration::from_secs(3600);
        autonomous.advance(&mut graph, &mut questions);
        for (id, input) in owner.requests() {
            let jobs::Input::Solve { question } = input else {
                panic!("unexpected non-solve request");
            };
            let q = CompiledQuestion::compile(&question).unwrap();
            if q.resolution_id() == goal.resolution_id() {
                assert_eq!(attempted.len(), 2);
                retried = true;
            } else {
                assert!(
                    helpers
                        .iter()
                        .any(|h| h.resolution_id() == q.resolution_id())
                );
                assert!(
                    attempted.insert(*q.resolution_id()),
                    "each helper has only one planned trial"
                );
            }
            owner.complete(id, Ok(jobs::Output::NoCandidate));
        }
        if retried {
            break;
        }
    }
    assert!(retried);
    assert!(graph.ids().is_empty());
    assert!(autonomous.error.is_none());
}

#[tokio::test]
async fn recursive_plan_offers_its_unadmitted_descendants_to_the_finding_owner() {
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = Graph::default();
    let mut questions = questions();
    let (parent, leaves) = crate::learning::tests::helper_goal();
    let other =
        CompiledQuestion::compile("goal=all(a,all(b,all(c,imp(eq(a,b),imp(eq(b,c),eq(a,c))))))")
            .unwrap();
    let root = CompiledQuestion::from_formula(naome_foundation::Formula::conjunction(
        other.formula().clone(),
        parent.formula().clone(),
    ))
    .unwrap();
    admitted(&mut questions, &graph, &root).await;
    admitted(&mut questions, &graph, &parent).await;
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut frontier = crate::frontier::Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    for (i, q) in [&root, &parent].into_iter().enumerate() {
        frontier
            .attempted(
                q,
                &graph,
                &jobs::Completion {
                    id: i as u64 + 1,
                    binding: jobs::Binding::new([0; 32], [0; 32]),
                    spent_ms: 1,
                    reserved_units: 1,
                    state: jobs::State::Complete,
                    result: Ok(jobs::Output::Native {
                        solution: None,
                        diagnostic: "search_budget".into(),
                        frontier: Some(crate::learning::tests::stalled_frontier(q)),
                    }),
                },
                crate::frontier::evidence::Outcome::NoCandidate,
            )
            .unwrap();
    }
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(1),
        owner.client.clone(),
        owner.recovery(),
        vec![root.clone()],
    );
    autonomous.frontier = Some(frontier);
    autonomous.formal_goal(Some(root.clone()));
    autonomous.next_question = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    let requests = owner.requests();
    let found = requests
        .iter()
        .filter_map(|(_, input)| {
            if let jobs::Input::Find { question, .. } = input {
                Some(CompiledQuestion::compile(question).unwrap())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(found.len(), 1);
    assert!(
        leaves
            .iter()
            .any(|q| q.resolution_id() == found[0].resolution_id())
    );
    assert_eq!(
        autonomous.formal_goal.as_ref().unwrap().resolution_id(),
        root.resolution_id()
    );
    assert!(graph.ids().is_empty());
    assert!(autonomous.error().is_none());
}
