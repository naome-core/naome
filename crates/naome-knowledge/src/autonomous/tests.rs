use super::*;
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
    LocalQuestions::new(Some(crate::mocks::assess_interest as fn(_) -> _))
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
    let interest = tokio::time::timeout(Duration::from_secs(5), questions.completed())
        .await
        .unwrap();
    questions.finish(graph, interest);
    assert!(matches!(
        receiver.await.unwrap().outcome,
        AdmissionOutcome::Admitted(_)
    ));
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
    assert!(
        autonomous
            .advance(&mut graph, &mut questions, None)
            .is_empty()
    );
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
    let requests = owner.requests();
    assert!(matches!(
        requests.as_slice(),
        [(_, jobs::Input::Find { cursor: 1 })]
    ));
    assert_eq!(owner.generation(requests[0].0).cursor().unwrap(), 1);
    assert_eq!(autonomous.cursor, 2);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "formal rejection never invokes interest"
    );
    assert!(autonomous.next_proof > Instant::now());
}

#[tokio::test]
async fn stale_generated_closure_is_not_published_and_unanswered_work_retries_freshly() {
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
    assert!(
        autonomous
            .advance(&mut graph, &mut questions, None)
            .is_empty()
    );
    let requests = owner.requests();
    assert!(matches!(
        requests.as_slice(),
        [(_, jobs::Input::Solve { .. })]
    ));
    assert_eq!(
        owner.generation(requests[0].0).question().unwrap(),
        selected
    );
    owner.complete(
        requests[0].0,
        Ok(jobs::Output::Proof {
            source: mocks::create_proof(&selected).unwrap(),
            helpers: Vec::new(),
        }),
    );
    assert!(
        autonomous
            .advance(&mut graph, &mut questions, None)
            .is_empty()
    );
    assert_eq!(autonomous.publications.len(), 1);
    let unrelated = CompiledQuestion::compile(&mocks::create_question(1)).unwrap();
    let object = graph
        .author(&mocks::create_proof(&unrelated).unwrap())
        .unwrap();
    graph.ingest(object, Instant::now()).unwrap();
    let interest = tokio::time::timeout(Duration::from_secs(5), questions.completed())
        .await
        .unwrap();
    questions.finish(&graph, interest);
    assert!(
        autonomous
            .advance(&mut graph, &mut questions, None)
            .is_empty()
    );
    assert_eq!(
        graph.ids().len(),
        1,
        "stale staged closure publishes nothing"
    );
    assert_eq!(
        autonomous.publications.len(),
        1,
        "bounded candidate survives for a fresh decision"
    );
    autonomous.publications.front_mut().unwrap().retry = Instant::now();
    autonomous.advance(&mut graph, &mut questions, None);
    let interest = tokio::time::timeout(Duration::from_secs(5), questions.completed())
        .await
        .unwrap();
    questions.finish(&graph, interest);
    assert_eq!(
        autonomous.advance(&mut graph, &mut questions, None).len(),
        1
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
    autonomous.advance(&mut graph, &mut questions, None);
    let requests = owner.requests();
    assert_eq!(requests.len(), 1);
    owner.complete(requests[0].0, Ok(jobs::Output::NoCandidate));
    assert!(
        autonomous
            .advance(&mut graph, &mut questions, None)
            .is_empty()
    );
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
    assert!(
        autonomous
            .advance(&mut graph, &mut questions, None)
            .is_empty()
    );
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
    autonomous.advance(&mut graph, &mut questions, None);
    let before = questions.computation_count();
    for _ in 0..100 {
        autonomous.advance(&mut graph, &mut questions, None);
    }
    assert_eq!(questions.computation_count(), before);
    assert_eq!(autonomous.solving.len(), 1);
}

#[tokio::test]
async fn ordinary_generation_passes_complete_requests_to_both_deterministic_producers() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let selected = CompiledQuestion::compile(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &selected).await;
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(100),
        owner.client.clone(),
        owner.recovery(),
        vec![selected.clone()],
    );
    autonomous.next_proof = Instant::now();
    autonomous.next_question = Instant::now();
    autonomous.advance(&mut graph, &mut questions, None);
    let requests = owner.requests();
    assert_eq!(requests.len(), 2);
    for (id, input) in requests {
        let request = owner.generation(id);
        match input {
            jobs::Input::Find { cursor } => {
                assert_eq!(
                    mocks::create_question_request(request).unwrap(),
                    mocks::create_question(cursor)
                );
            }
            jobs::Input::Solve { question } => {
                assert_eq!(request.question().unwrap().source(), question);
                let source = mocks::create_proof_request(request).unwrap().unwrap();
                assert_eq!(source, mocks::create_proof(&selected).unwrap());
                let _ = graph.prepare_generated(&source, &[], &selected).unwrap();
            }
            jobs::Input::Interest { .. } => panic!("generation does not impersonate interest"),
        }
    }
}

#[tokio::test]
async fn malformed_question_mock_output_never_becomes_an_admission_or_checked_fact() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(100),
        owner.client.clone(),
        owner.recovery(),
        Vec::new(),
    );
    autonomous.next_question = Instant::now();
    autonomous.advance(&mut graph, &mut questions, None);
    let requests = owner.requests();
    assert!(matches!(
        requests.as_slice(),
        [(_, jobs::Input::Find { .. })]
    ));
    owner.complete(
        requests[0].0,
        Ok(jobs::Output::Question("invalid question".into())),
    );
    autonomous.advance(&mut graph, &mut questions, None);
    assert!(autonomous.admissions.is_empty());
    assert!(autonomous.unanswered.is_empty() && autonomous.solving.is_empty());
    assert!(graph.ids().is_empty());
    assert_eq!(owner.acknowledgements(), vec![requests[0].0]);
}

#[tokio::test]
async fn obsolete_recovered_requests_are_retired_instead_of_retried_or_left_unacknowledged() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let selected = CompiledQuestion::compile(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &selected).await;
    let mut owner = jobs::tests::Manual::new();
    let (snapshot, policy) = questions.context_key(&graph);
    let binding = jobs::Binding::new(snapshot, policy);
    let inputs = [
        jobs::Input::Find { cursor: 3 },
        jobs::Input::Solve {
            question: selected.source().into(),
        },
    ];
    let records = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let request = generation::Request::build(
                input,
                &binding,
                &graph,
                generation::OwnerContext::Unavailable {
                    reason: "recovery fixture has no owner control".into(),
                },
            )
            .unwrap()
            .obsolete_for_test();
            jobs::Record {
                id: index as u64 + 1,
                input: input.clone(),
                binding: binding.clone(),
                generation: Some(request),
                provider: "naome-deterministic-mocks-v1".into(),
                configuration: "00".repeat(32),
                settings: jobs::RoleSettings::default(),
                created_ms: 0,
                expires_ms: 86_400_000,
                accounted_ms: 0,
                spent_ms: 1,
                reserved_units: 1,
                checkpoint: 1,
                state: jobs::State::Failed,
                result: None,
                acknowledged: false,
                failure: Some("generation instructions changed; retained request retired".into()),
            }
        })
        .collect();
    let mut autonomous = Autonomous::new(
        intervals(100),
        owner.client.clone(),
        jobs::Recovery {
            next_cursor: 4,
            records,
        },
        Vec::new(),
    );
    autonomous.next_question = Instant::now();
    autonomous.next_proof = Instant::now() + Duration::from_secs(60);
    autonomous.advance(&mut graph, &mut questions, None);
    assert!(autonomous.recovered_other.is_empty() && autonomous.recovered_finding.is_empty());
    assert!(autonomous.solving.is_empty() && autonomous.finding.is_none());
    assert!(owner.requests().is_empty());
    let discarded = owner.discards();
    assert_eq!(discarded.len(), 2);
    assert!(inputs.iter().all(|input| {
        discarded
            .iter()
            .any(|(found, found_binding)| found == input && found_binding == &binding)
    }));
    assert_eq!(autonomous.cursor, 4);
}
