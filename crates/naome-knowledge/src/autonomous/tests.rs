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
        [(_, jobs::Input::Find { cursor: 1 })]
    ));
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
    let interest = tokio::time::timeout(Duration::from_secs(5), questions.completed())
        .await
        .unwrap();
    questions.finish(&graph, interest);
    assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
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
    autonomous.advance(&mut graph, &mut questions);
    let interest = tokio::time::timeout(Duration::from_secs(5), questions.completed())
        .await
        .unwrap();
    questions.finish(&graph, interest);
    assert_eq!(autonomous.advance(&mut graph, &mut questions).len(), 1);
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
