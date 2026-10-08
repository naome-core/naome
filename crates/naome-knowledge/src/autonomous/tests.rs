use super::*;
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
    let mut autonomous = Autonomous::new(
        Intervals {
            question_interval_ms: 100,
            proof_interval_ms: 100,
        },
        1,
    );
    autonomous.unanswered.push_back(selected);
    autonomous.next_question = Instant::now();
    autonomous.next_proof = Instant::now();
    assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
    assert_eq!(
        autonomous.unanswered.len(),
        1,
        "formal rejection retains unanswered work"
    );
    assert!(
        matches!(autonomous.pending, Some(Pending::Question(..))),
        "independent scheduled question still runs"
    );
    assert_eq!(autonomous.cursor, 2);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "formal rejection never invokes interest"
    );
    assert!(
        autonomous.next_proof > Instant::now(),
        "retry observes the configured interval"
    );
}

#[tokio::test]
async fn stale_generated_closure_is_not_published_and_unanswered_work_retries_freshly() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let selected = CompiledQuestion::compile(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &selected).await;
    let mut autonomous = Autonomous::new(
        Intervals {
            question_interval_ms: 3600000,
            proof_interval_ms: 100,
        },
        0,
    );
    autonomous.unanswered.push_back(selected);
    autonomous.next_proof = Instant::now();
    assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
    assert!(matches!(autonomous.pending, Some(Pending::Proof { .. })));
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
        "stale prepared closure publishes nothing"
    );
    assert_eq!(autonomous.unanswered.len(), 1);
    autonomous.next_proof = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    let interest = tokio::time::timeout(Duration::from_secs(5), questions.completed())
        .await
        .unwrap();
    questions.finish(&graph, interest);
    assert_eq!(autonomous.advance(&mut graph, &mut questions).len(), 1);
    assert_eq!(graph.ids().len(), 2);
    assert!(autonomous.unanswered.is_empty());
}

#[tokio::test]
async fn unsupported_questions_retry_boundedly_and_a_received_answer_cancels_generation() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let unsupported =
        CompiledQuestion::compile("foundation = \"naome:zfc\" statement = forall(x,member(x,x))")
            .unwrap();
    admitted(&mut questions, &graph, &unsupported).await;
    let mut autonomous = Autonomous::new(
        Intervals {
            question_interval_ms: 3600000,
            proof_interval_ms: 100,
        },
        0,
    );
    autonomous.unanswered.push_back(unsupported);
    autonomous.next_proof = Instant::now();
    assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
    assert_eq!(autonomous.unanswered.len(), 1);
    assert!(autonomous.pending.is_none());
    assert!(autonomous.next_proof > Instant::now());
    autonomous.unanswered.clear();
    let answered = CompiledQuestion::compile(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &answered).await;
    graph
        .ingest(
            graph
                .author(&mocks::create_proof(&answered).unwrap())
                .unwrap(),
            Instant::now(),
        )
        .unwrap();
    autonomous.unanswered.push_back(answered);
    autonomous.next_proof = Instant::now();
    assert!(autonomous.advance(&mut graph, &mut questions).is_empty());
    assert!(autonomous.unanswered.is_empty());
    assert!(autonomous.pending.is_none());
    assert_eq!(graph.ids().len(), 1);
}
