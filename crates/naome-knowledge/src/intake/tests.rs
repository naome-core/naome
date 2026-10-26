use super::*;
use crate::{
    hex,
    object::{content_id, id_bytes},
    question::{AdmissionOutcome, Command},
    store::BatchCut,
};
use naome_checker::question::PrefilterPolicy;
use std::{
    future::{Ready, ready},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

fn source(index: usize) -> String {
    let question = CompiledQuestion::compile(&crate::mocks::create_question(0)).unwrap();
    let a = question.proved_target().to_source();
    let mut b = "mem(y,y)".to_owned();
    for bit in format!("{index:b}").bytes() {
        b = format!(
            "imp({}, {b})",
            if bit == b'1' { "eq(y,y)" } else { "mem(y,y)" }
        );
    }
    b = format!("all(y,{b})");
    let proof = crate::mocks::create_proof(&question).unwrap();
    let prefix = proof.rsplit_once("return p0").unwrap().0;
    let steps = prefix.split_once("proof:").unwrap().1;
    format!("goal = imp({b},{a}) proof:{steps} p1=simp({a},{b}) p2=mp(p0,p1) return p2")
}

fn fixture(index: usize) -> (Envelope, Metadata) {
    let mut producer = Graph::default();
    let object = producer.author(&source(index)).unwrap();
    let id = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    producer.ingest(object.clone(), Instant::now()).unwrap();
    (object, producer.describe(id).unwrap().unwrap())
}

fn accepting(_: CompiledQuestion) -> Ready<Result<bool, String>> {
    ready(Ok(true))
}
type Questions = LocalQuestions<fn(CompiledQuestion) -> Ready<Result<bool, String>>>;
fn new_questions() -> Questions {
    LocalQuestions::new(Some(accepting as fn(_) -> _))
}

#[tokio::test]
async fn managed_interest_survives_unrelated_graph_growth_without_provider_retry() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let mut owner = crate::jobs::tests::Manual::new();
    let mut questions =
        Questions::managed(owner.client.clone(), &directory.0, Duration::from_secs(60)).unwrap();
    let peer = PeerId::random();
    let mut intake = Intake::default();
    let metadata = fixture(41).1;
    assert_eq!(
        intake.enqueue(peer, metadata.clone(), &graph).unwrap(),
        "queued"
    );
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    let request = owner.requests().remove(0);
    // A separate checked proof changes the node while the old decision waits.
    graph.ingest(fixture(42).0, Instant::now()).unwrap();
    owner.complete(request.0, Ok(crate::jobs::Output::Interest(true)));
    let completed = questions.completed().await;
    questions.finish(&graph, completed);
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    assert!(
        owner.requests().is_empty(),
        "unrelated graph growth does not rerun interest"
    );
    assert_eq!(
        intake.enqueue(peer, metadata.clone(), &graph).unwrap(),
        "metadata_refreshed"
    );
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    let id = ArtifactId::from_bytes(id_bytes(&metadata.artifact_id).unwrap());
    assert_eq!(intake.needed(), [(peer, id, id)]);
}

async fn interest<F, Fut>(questions: &mut LocalQuestions<F>, graph: &Graph)
where
    F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<bool, String>> + Send + 'static,
{
    assert!(!questions.available());
    let result = questions.completed().await;
    questions.finish(graph, result);
}

fn registered<F, Fut>(questions: &mut LocalQuestions<F>, graph: &Graph) -> usize
where
    F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<bool, String>> + Send + 'static,
{
    let (sender, mut receiver) = oneshot::channel();
    questions.process(Command::Context(sender), graph);
    receiver.try_recv().unwrap().registered_questions
}

async fn approve<F, Fut>(intake: &mut Intake, questions: &mut LocalQuestions<F>, graph: &mut Graph)
where
    F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<bool, String>> + Send + 'static,
{
    assert!(matches!(
        intake.advance(graph, questions),
        Progress::Waiting
    ));
    assert!(intake.needed().is_empty());
    interest(questions, graph).await;
    assert!(matches!(
        intake.advance(graph, questions),
        Progress::Waiting
    ));
    assert_eq!(intake.needed().len(), 1);
}

#[test]
fn descriptions_bind_the_checked_statement_and_preserve_existing_proof_addresses() {
    let mut graph = Graph::default();
    let object = graph
        .author("goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1")
        .unwrap();
    assert_eq!(
        crate::hex(object.proof_id().unwrap().unwrap().as_bytes()),
        "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73"
    );
    let id = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    graph.ingest(object.clone(), Instant::now()).unwrap();
    let mut metadata = graph.describe(id).unwrap().unwrap();
    let (_, statement, question) = metadata.compile().unwrap();
    assert_eq!(hex(statement.as_bytes()), object.statement_id.unwrap());
    assert!(!question.negation_parity());
    metadata.statement_id = "00".repeat(32);
    assert!(metadata.compile().unwrap_err().contains("question target"));
}

#[tokio::test]
async fn metadata_capacity_keeps_one_active_root_and_eight_bounded_waiting_descriptions() {
    let peer = PeerId::random();
    let mut graph = Graph::default();
    let before = graph.content_root();
    let mut questions = new_questions();
    let mut intake = Intake::default();
    for index in 0..crate::resources::limits().queued_metadata {
        intake
            .enqueue(peer, fixture(100 + index).1, &graph)
            .unwrap();
    }
    let next = fixture(100 + crate::resources::limits().queued_metadata).1;
    assert_eq!(intake.description_capacity(), 0);
    assert!(
        intake
            .enqueue(peer, next.clone(), &graph)
            .unwrap_err()
            .contains("queue capacity")
    );
    assert!(intake.needed().is_empty());
    approve(&mut intake, &mut questions, &mut graph).await;
    let selected = intake.needed();
    assert_eq!(intake.description_capacity(), 1);
    assert_eq!(intake.enqueue(peer, next, &graph).unwrap(), "queued");
    assert_eq!(intake.description_capacity(), 0);
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    assert_eq!(
        intake.needed(),
        selected,
        "queued descriptions do not create additional grants"
    );
    assert_eq!(registered(&mut questions, &graph), 0);
    assert_eq!(graph.content_root(), before);
    intake.disconnected(peer);
    assert!(intake.needed().is_empty());
    assert_eq!(
        intake.description_capacity(),
        crate::resources::limits().queued_metadata
    );
}

#[tokio::test]
async fn valid_normal_proofs_respect_the_cumulative_transport_step_budget() {
    use naome_foundation::{Formula, FreeVariable};
    use naome_proof::{ProofCertificate, ProofStep};

    for count in [
        crate::resources::limits().closure_steps,
        crate::resources::limits().closure_steps + 1,
    ] {
        let variable = FreeVariable::new(0);
        let formula = Formula::equal(variable, variable);
        let mut steps = vec![
            ProofStep::EqualityReflexivity { variable },
            ProofStep::Simplification {
                antecedent: formula.clone().into(),
                consequent: formula.into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ];
        let mut premise = 0;
        while steps.len() < count - 3 {
            steps.push(ProofStep::ModusPonens {
                premise,
                implication: 2,
            });
            premise = (steps.len() - 1) as u32;
        }
        let weakening = steps.len() as u32;
        steps.push(ProofStep::Simplification {
            antecedent: Formula::equal(variable, variable).into(),
            consequent: Formula::member(variable, variable).into(),
        });
        steps.push(ProofStep::ModusPonens {
            premise,
            implication: weakening,
        });
        premise = (steps.len() - 1) as u32;
        steps.push(ProofStep::Generalization { premise, variable });
        let checked = naome_checker::check_normal_form_with_state(
            ProofCertificate::new(steps)
                .unwrap()
                .into_unchecked_normal_form(),
            &naome_checker::ArtifactState::default(),
        )
        .unwrap();
        assert_eq!(checked.normal_form().certificate().steps().len(), count);
        let bytes = checked.normal_form().canonical_bytes();
        assert!(bytes.len() < crate::resources::limits().proof_bytes);
        eprintln!(
            "checked_transport_boundary steps={count} canonical_bytes={} proof_id={}",
            bytes.len(),
            hex(checked.artifact_id().as_bytes())
        );
        let object = Envelope {
            compatibility: hex(&crate::compatibility()),
            artifact_id: hex(checked.artifact_id().as_bytes()),
            statement_id: Some(hex(checked.statement_id().as_bytes())),
            payload: format!("00{}", hex(bytes)),
            obligation_proof: None,
        };
        let id = checked.artifact_id();
        let mut producer = Graph::default();
        assert_eq!(
            producer
                .ingest(object.clone(), Instant::now())
                .unwrap()
                .status,
            "accepted"
        );
        let metadata = producer.describe(id).unwrap().unwrap();
        let peer = PeerId::random();
        let mut graph = Graph::default();
        let before = graph.content_root();
        let mut questions = new_questions();
        let mut intake = Intake::default();
        intake.enqueue(peer, metadata, &graph).unwrap();
        approve(&mut intake, &mut questions, &mut graph).await;
        if count == crate::resources::limits().closure_steps {
            intake.payload(peer, id, id, object, &graph).unwrap();
            assert_eq!(
                intake.active.as_ref().unwrap().closure.certificate_steps(),
                crate::resources::limits().closure_steps
            );
            intake.advance(&mut graph, &mut questions);
            interest(&mut questions, &graph).await;
            assert!(
                matches!(intake.advance(&mut graph, &mut questions), Progress::Accepted(ids) if ids == vec![id])
            );
            assert!(graph.contains(id).unwrap());
            assert_eq!(registered(&mut questions, &graph), 1);
        } else {
            assert!(
                intake
                    .payload(peer, id, id, object, &graph)
                    .unwrap_err()
                    .contains("step work limit")
            );
            assert!(intake.active.as_ref().unwrap().closure.certificate_count() == 0);
            intake.abort(id);
            assert_eq!(graph.content_root(), before);
            assert!(graph.pending_ids().unwrap().is_empty());
            assert_eq!(registered(&mut questions, &graph), 0);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn absent_false_error_and_timeout_interest_never_authorize_payloads() {
    let (_, metadata) = fixture(1);
    let mut graph = Graph::default();
    let root = graph.content_root();
    let peer = PeerId::random();
    let mut absent: Questions = LocalQuestions::new(None);
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata.clone(), &graph).unwrap();
    assert!(matches!(
        intake.advance(&mut graph, &mut absent),
        Progress::Skipped(..)
    ));
    assert!(intake.needed().is_empty());
    for mode in 0..3 {
        let mut questions = LocalQuestions::new(Some(move |_| async move {
            match mode {
                0 => Ok(false),
                1 => Err("interest failed".into()),
                _ => std::future::pending::<Result<bool, String>>().await,
            }
        }));
        let mut intake = Intake::default();
        intake.enqueue(peer, metadata.clone(), &graph).unwrap();
        assert!(matches!(
            intake.advance(&mut graph, &mut questions),
            Progress::Waiting
        ));
        interest(&mut questions, &graph).await;
        assert!(matches!(
            intake.advance(&mut graph, &mut questions),
            Progress::Skipped(..)
        ));
        assert!(intake.needed().is_empty());
        assert_eq!(registered(&mut questions, &graph), 0);
    }
    assert_eq!(graph.content_root(), root);
}

#[tokio::test]
async fn unrelated_context_refreshes_formal_checks_but_expired_grants_cannot_fetch_or_stage() {
    let (object, metadata) = fixture(2);
    let id = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    let peer = PeerId::random();
    let mut graph = Graph::default();
    let mut questions = new_questions();
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata.clone(), &graph).unwrap();
    intake.advance(&mut graph, &mut questions);
    graph.ingest(fixture(3).0, Instant::now()).unwrap();
    interest(&mut questions, &graph).await;
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    assert_eq!(intake.needed(), [(peer, id, id)]);
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata.clone(), &graph).unwrap();
    approve(&mut intake, &mut questions, &mut graph).await;
    intake
        .active
        .as_mut()
        .unwrap()
        .description
        .transfer
        .set_received_for_test(Instant::now() - crate::resources::limits().root_timeout);
    assert!(intake.needed().is_empty());
    assert!(!intake.authorizes(peer, id, id));
    assert!(
        intake
            .payload(peer, id, id, object, &graph)
            .unwrap_err()
            .contains("expired")
    );
    let mut queued = Intake::default();
    queued.enqueue(peer, metadata, &graph).unwrap();
    queued
        .queue
        .front_mut()
        .unwrap()
        .transfer
        .set_received_for_test(Instant::now() - crate::resources::limits().root_timeout);
    assert!(matches!(
        queued.advance(&mut graph, &mut questions),
        Progress::Skipped(..)
    ));
    assert!(
        questions.available(),
        "expired queued work must not construct interest"
    );
}

#[tokio::test]
async fn declined_metadata_does_not_poison_new_source_or_peer_for_same_proof() {
    let (object, metadata) = fixture(4);
    let peer = PeerId::random();
    let mut graph = Graph::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mut questions = LocalQuestions::new(Some(move |_| {
        ready(Ok(observed.fetch_add(1, Ordering::SeqCst) > 0))
    }));
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata.clone(), &graph).unwrap();
    intake.advance(&mut graph, &mut questions);
    interest(&mut questions, &graph).await;
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Skipped(..)
    ));
    assert_eq!(
        intake.enqueue(peer, metadata.clone(), &graph).unwrap(),
        "declined"
    );
    let mut changed = metadata.clone();
    changed.question = format!("# changed exact input\n{}", changed.question);
    assert_eq!(intake.enqueue(peer, changed, &graph).unwrap(), "queued");
    approve(&mut intake, &mut questions, &mut graph).await;
    let id = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    assert!(intake.authorizes(peer, id, id));
    assert_eq!(
        intake.enqueue(PeerId::random(), metadata, &graph).unwrap(),
        "queued"
    );
}

#[tokio::test]
async fn false_statement_question_pair_cannot_poison_later_correct_description() {
    let (object, metadata) = fixture(20);
    let mut wrong = fixture(21).1;
    wrong.artifact_id = object.artifact_id.clone();
    wrong.proof_id = metadata.proof_id.clone();
    let peer = PeerId::random();
    let mut graph = Graph::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mut questions = LocalQuestions::new(Some(move |_| {
        ready(Ok(observed.fetch_add(1, Ordering::SeqCst) > 0))
    }));
    let mut intake = Intake::default();
    intake.enqueue(peer, wrong, &graph).unwrap();
    intake.advance(&mut graph, &mut questions);
    interest(&mut questions, &graph).await;
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Skipped(..)
    ));
    assert!(intake.needed().is_empty());
    assert_eq!(intake.enqueue(peer, metadata, &graph).unwrap(), "queued");
    approve(&mut intake, &mut questions, &mut graph).await;
    let root = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    intake.payload(peer, root, root, object, &graph).unwrap();
    intake.advance(&mut graph, &mut questions);
    interest(&mut questions, &graph).await;
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Accepted(_)
    ));
    assert_eq!(graph.ids(), vec![root]);
}

fn dependent_fixture() -> (Envelope, Envelope, Metadata) {
    let mut producer = Graph::default();
    let helper = producer.author(&source(5)).unwrap();
    producer.ingest(helper.clone(), Instant::now()).unwrap();
    let premise = producer
        .describe(ArtifactId::from_bytes(
            id_bytes(&helper.artifact_id).unwrap(),
        ))
        .unwrap()
        .unwrap()
        .question
        .split("goal = ")
        .nth(1)
        .unwrap()
        .to_owned();
    let b = "all(z,mem(z,z))";
    let root = producer.author(&format!("goal = imp({b},{premise}) proof: p0 = cite(\"{}\") p1 = simp({premise},{b}) p2 = mp(p0,p1) return p2", crate::hex(helper.proof_id().unwrap().unwrap().as_bytes()))).unwrap();
    let id = ArtifactId::from_bytes(id_bytes(&root.artifact_id).unwrap());
    producer.ingest(root.clone(), Instant::now()).unwrap();
    (root, helper, producer.describe(id).unwrap().unwrap())
}

#[tokio::test]
async fn approved_parent_stages_only_committed_helpers_and_publishes_whole_closure() {
    let (object, helper, metadata) = dependent_fixture();
    let root = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    let helper_id = ArtifactId::from_bytes(id_bytes(&helper.artifact_id).unwrap());
    let peer = PeerId::random();
    let mut graph = Graph::default();
    let mut questions = new_questions();
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata, &graph).unwrap();
    approve(&mut intake, &mut questions, &mut graph).await;
    assert_eq!(intake.needed(), vec![(peer, root, root)]);
    assert!(
        intake
            .payload(peer, root, helper_id, helper.clone(), &graph)
            .is_err()
    );
    intake.payload(peer, root, root, object, &graph).unwrap();
    assert_eq!(intake.needed(), vec![(peer, root, helper_id)]);
    assert!(graph.accepted_count() == 0);
    assert!(graph.pending_ids().unwrap().is_empty());
    intake
        .payload(peer, root, helper_id, helper, &graph)
        .unwrap();
    intake.advance(&mut graph, &mut questions);
    assert!(
        graph.accepted_count() == 0,
        "math checking stages no stored local knowledge"
    );
    assert_eq!(registered(&mut questions, &graph), 0);
    interest(&mut questions, &graph).await;
    assert!(
        matches!(intake.advance(&mut graph, &mut questions), Progress::Accepted(ids) if ids.len() == 2)
    );
    assert_eq!(graph.accepted_count(), 2);
    assert!(graph.contains(root).unwrap() && graph.contains(helper_id).unwrap());
    assert_eq!(registered(&mut questions, &graph), 1);
}

#[tokio::test]
async fn successful_batch_enables_only_the_preexisting_local_owner_pending_transition() {
    let (object, helper, metadata) = dependent_fixture();
    let mut producer = Graph::default();
    producer.ingest(helper.clone(), Instant::now()).unwrap();
    let formula = producer
        .describe(ArtifactId::from_bytes(
            id_bytes(&helper.artifact_id).unwrap(),
        ))
        .unwrap()
        .unwrap()
        .compile()
        .unwrap()
        .2
        .core()
        .to_source();
    let owner = producer
        .author(&format!(
            "goal = {formula} proof: p0 = cite(\"{}\") return p0",
            crate::hex(helper.proof_id().unwrap().unwrap().as_bytes())
        ))
        .unwrap();
    let owner_id = ArtifactId::from_bytes(id_bytes(&owner.artifact_id).unwrap());
    let root = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    let helper_id = ArtifactId::from_bytes(id_bytes(&helper.artifact_id).unwrap());
    let mut graph = Graph::default();
    assert_eq!(
        graph.ingest(owner, Instant::now()).unwrap().status,
        "waiting"
    );
    let peer = PeerId::random();
    let mut questions = new_questions();
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata, &graph).unwrap();
    approve(&mut intake, &mut questions, &mut graph).await;
    intake.payload(peer, root, root, object, &graph).unwrap();
    intake
        .payload(peer, root, helper_id, helper, &graph)
        .unwrap();
    intake.advance(&mut graph, &mut questions);
    interest(&mut questions, &graph).await;
    assert!(
        matches!(intake.advance(&mut graph, &mut questions), Progress::Accepted(ids) if ids.len() == 2)
    );
    assert_eq!(graph.pending_ids().unwrap(), vec![owner_id]);
    assert_eq!(graph.accepted_count(), 2);
    let (admitted, rejected) = graph.resolve_pending().unwrap();
    assert_eq!(admitted, vec![owner_id]);
    assert!(rejected.is_empty());
    assert!(graph.pending_ids().unwrap().is_empty());
    assert_eq!(graph.accepted_count(), 3);
}

#[tokio::test]
async fn necessary_helper_outside_question_codec_is_checked_without_own_question_selection() {
    let mut producer = Graph::default();
    let mut formula = "eq(x0,x0)".to_owned();
    for index in 0..40 {
        formula = format!("all(x{index},{formula})");
    }
    let mut proof = "p0 = refl(x0)".to_owned();
    for index in 0..40 {
        proof.push_str(&format!(" p{} = gen(p{},x{index})", index + 1, index));
    }
    let helper = producer
        .author(&format!("goal = {formula} proof: {proof} return p40"))
        .unwrap();
    producer.ingest(helper.clone(), Instant::now()).unwrap();
    let helper_id = ArtifactId::from_bytes(id_bytes(&helper.artifact_id).unwrap());
    assert!(producer.describe(helper_id).is_err());
    let mut steps = format!(
        "p0 = cite(\"{}\")",
        crate::hex(helper.proof_id().unwrap().unwrap().as_bytes())
    );
    let mut previous = "p0".to_owned();
    for (offset, variable) in (1..40).rev().enumerate() {
        let mut body = "eq(x0,x0)".to_owned();
        for index in 0..variable {
            body = format!("all(x{index},{body})");
        }
        steps.push_str(&format!(
            " u{offset} = inst(x{variable},x{variable},{body}) r{offset} = mp({previous},u{offset})"
        ));
        previous = format!("r{offset}");
    }
    steps.push_str(&format!(" last=inst(x0,x0,eq(x0,x0)) opened=mp({previous},last) weakening=simp(eq(x0,x0),mem(x0,x0)) result=mp(opened,weakening) closed=gen(result,x0)"));
    let object = producer
        .author(&format!(
            "goal = all(x0,imp(mem(x0,x0),eq(x0,x0))) proof: {steps} return closed"
        ))
        .unwrap();
    let root = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    producer.ingest(object.clone(), Instant::now()).unwrap();
    let metadata = producer.describe(root).unwrap().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mut questions = LocalQuestions::new(Some(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        ready(Ok(true))
    }));
    let mut graph = Graph::default();
    let peer = PeerId::random();
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata, &graph).unwrap();
    approve(&mut intake, &mut questions, &mut graph).await;
    intake.payload(peer, root, root, object, &graph).unwrap();
    intake
        .payload(peer, root, helper_id, helper, &graph)
        .unwrap();
    intake.advance(&mut graph, &mut questions);
    interest(&mut questions, &graph).await;
    assert!(
        matches!(intake.advance(&mut graph, &mut questions), Progress::Accepted(ids) if ids.len() == 2)
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "only the root has initial and final interest assessment"
    );
    assert_eq!(registered(&mut questions, &graph), 1);
}

#[tokio::test(start_paused = true)]
async fn final_false_error_timeout_or_registry_change_discards_every_staged_object() {
    for mode in 0..4 {
        let (object, helper, metadata) = dependent_fixture();
        let peer = PeerId::random();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let mut questions = LocalQuestions::new(Some(move |_| {
            let first = observed.fetch_add(1, Ordering::SeqCst) == 0;
            async move {
                if first || mode == 3 {
                    Ok(true)
                } else if mode == 0 {
                    Ok(false)
                } else if mode == 1 {
                    Err("final selection failed".into())
                } else {
                    std::future::pending().await
                }
            }
        }));
        let mut graph = Graph::default();
        let before = graph.content_root();
        let mut intake = Intake::default();
        intake.enqueue(peer, metadata.clone(), &graph).unwrap();
        approve(&mut intake, &mut questions, &mut graph).await;
        let root = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
        let helper_id = ArtifactId::from_bytes(id_bytes(&helper.artifact_id).unwrap());
        intake.payload(peer, root, root, object, &graph).unwrap();
        intake
            .payload(peer, root, helper_id, helper, &graph)
            .unwrap();
        intake.advance(&mut graph, &mut questions);
        if mode == 3 {
            let (sender, _receiver) = oneshot::channel();
            questions.process(
                Command::ImportBaseline(metadata.compile().unwrap().2, sender),
                &graph,
            );
        }
        interest(&mut questions, &graph).await;
        assert!(matches!(
            intake.advance(&mut graph, &mut questions),
            Progress::Skipped(..)
        ));
        assert_eq!(graph.content_root(), before);
        assert!(graph.accepted_count() == 0 && graph.pending_ids().unwrap().is_empty());
        assert_eq!(registered(&mut questions, &graph), usize::from(mode == 3));
    }
}

#[tokio::test]
async fn invalid_parent_after_valid_helper_leaves_no_orphan_or_registry_effect() {
    let (mut object, helper, mut metadata) = dependent_fixture();
    // A real canonical citation certificate commits the helper, but its
    // conclusion cannot establish the advertised unrelated statement.
    let helper_id = ArtifactId::from_bytes(id_bytes(&helper.artifact_id).unwrap());
    let bytes = naome_proof::ProofCertificate::new(vec![naome_proof::ProofStep::ProofReference {
        proof_id: helper.proof_id().unwrap().unwrap(),
    }])
    .unwrap()
    .to_canonical_bytes();
    object.payload = format!("00{}", hex(&bytes));
    let statement =
        StatementId::from_bytes(id_bytes(object.statement_id.as_deref().unwrap()).unwrap());
    let root = content_id(statement, &bytes);
    object.artifact_id = hex(root.as_bytes());
    metadata.artifact_id = object.artifact_id.clone();
    metadata.proof_id = hex(
        naome_proof::ProofId::of_canonical_certificate(statement, &bytes)
            .unwrap()
            .as_bytes(),
    );
    let peer = PeerId::random();
    let mut graph = Graph::default();
    let mut questions = new_questions();
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata, &graph).unwrap();
    approve(&mut intake, &mut questions, &mut graph).await;
    intake.payload(peer, root, root, object, &graph).unwrap();
    intake
        .payload(peer, root, helper_id, helper, &graph)
        .unwrap();
    assert!(
        matches!(intake.advance(&mut graph, &mut questions), Progress::Skipped(_, error) if error.contains("checked identity mismatch"))
    );
    assert!(graph.accepted_count() == 0 && graph.pending_ids().unwrap().is_empty());
    assert_eq!(registered(&mut questions, &graph), 0);
}

#[tokio::test]
async fn delivered_original_admission_allows_fresh_current_policy_but_baseline_does_not() {
    let (object, metadata) = fixture(6);
    let derived = metadata.compile().unwrap().2;
    let original = CompiledQuestion::compile(&format!(
        "# original owner source\ngoal = not({})",
        derived.core().to_source()
    ))
    .unwrap();
    let mut graph = Graph::default();
    let mut questions = new_questions();
    let (sender, receiver) = oneshot::channel();
    questions.process(Command::Admit(original.clone(), sender), &graph);
    interest(&mut questions, &graph).await;
    let AdmissionOutcome::Admitted(receipt) = receiver.await.unwrap().outcome else {
        panic!("actual local admission required")
    };
    let historical = receipt.clone();
    let mut policy = PrefilterPolicy::default();
    policy.limits.operations -= 1;
    let (sender, _receiver) = oneshot::channel();
    questions.process(Command::Policy(policy, sender), &graph);
    let peer = PeerId::random();
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata.clone(), &graph).unwrap();
    approve(&mut intake, &mut questions, &mut graph).await;
    let approved = intake.active.as_ref().unwrap();
    assert_eq!(*approved.selection.question(), original);
    assert!(approved.selection.initial().unwrap().novelty().is_none());
    assert_eq!(historical, receipt);
    assert_ne!(
        approved.selection.initial().unwrap().prefilter.policy,
        receipt.policy()
    );
    let root = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    intake.payload(peer, root, root, object, &graph).unwrap();
    intake.advance(&mut graph, &mut questions);
    interest(&mut questions, &graph).await;
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Accepted(_)
    ));
    assert_eq!(registered(&mut questions, &graph), 1);
    let mut baseline = new_questions();
    let mut empty = Graph::default();
    let (sender, _receiver) = oneshot::channel();
    baseline.process(Command::ImportBaseline(original, sender), &empty);
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata, &empty).unwrap();
    assert!(matches!(
        intake.advance(&mut empty, &mut baseline),
        Progress::Skipped(..)
    ));
    assert!(intake.needed().is_empty());
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "naome-proof-batch-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn persistence_cuts_preserve_existing_state_and_recover_only_complete_catalog_batches() {
    for cut in [
        BatchCut::BeforeWrite,
        BatchCut::DuringWrite,
        BatchCut::BeforeCommit,
        BatchCut::AfterCommit,
    ] {
        let directory = Directory::new();
        let mut graph = Graph::open(&directory.0).unwrap();
        let existing = fixture(7).0;
        let existing_id = ArtifactId::from_bytes(id_bytes(&existing.artifact_id).unwrap());
        graph.ingest(existing, Instant::now()).unwrap();
        let before = graph.content_root();
        let (object, helper, metadata) = dependent_fixture();
        let root = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
        let helper_id = ArtifactId::from_bytes(id_bytes(&helper.artifact_id).unwrap());
        let peer = PeerId::random();
        let mut questions = new_questions();
        let mut intake = Intake::default();
        intake.enqueue(peer, metadata, &graph).unwrap();
        approve(&mut intake, &mut questions, &mut graph).await;
        intake.payload(peer, root, root, object, &graph).unwrap();
        intake
            .payload(peer, root, helper_id, helper, &graph)
            .unwrap();
        intake.advance(&mut graph, &mut questions);
        graph.test_batch_cut(cut);
        interest(&mut questions, &graph).await;
        assert!(matches!(
            intake.advance(&mut graph, &mut questions),
            Progress::Skipped(..)
        ));
        assert!(graph.storage_error().is_some());
        assert_eq!(graph.content_root(), before);
        assert_eq!(registered(&mut questions, &graph), 0);
        drop(graph);
        let restarted = Graph::open(&directory.0).unwrap();
        assert!(restarted.contains(existing_id).unwrap());
        assert_eq!(
            restarted.accepted_count(),
            if cut == BatchCut::AfterCommit { 3 } else { 1 }
        );
        if cut == BatchCut::AfterCommit {
            assert!(restarted.contains(root).unwrap() && restarted.contains(helper_id).unwrap());
        }
    }
}

#[tokio::test]
async fn final_interest_batch_prepared_before_copy_attach_never_reaches_persistence() {
    let mut graph = Graph::default();
    graph.ingest(fixture(7).0, Instant::now()).unwrap();
    let before = graph.content_root();
    let (object, helper, metadata) = dependent_fixture();
    let root = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    let helper_id = ArtifactId::from_bytes(id_bytes(&helper.artifact_id).unwrap());
    let peer = PeerId::random();
    let mut questions = new_questions();
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata, &graph).unwrap();
    approve(&mut intake, &mut questions, &mut graph).await;
    intake.payload(peer, root, root, object, &graph).unwrap();
    intake
        .payload(peer, root, helper_id, helper, &graph)
        .unwrap();
    intake.advance(&mut graph, &mut questions);
    assert!(matches!(
        &intake.active.as_ref().expect("held peer root").phase,
        Phase::Final(..)
    ));
    // The production event loop runs maintenance before intake.advance. Keep
    // this real batch alive across attach, with the physical copy unfinished.
    graph.test_batch_cut(BatchCut::BeforeWrite);
    assert!(graph.test_compaction_step(1).unwrap());
    interest(&mut questions, &graph).await;
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    let retained = intake
        .active
        .as_ref()
        .expect("stale publication is deferred");
    assert!(matches!(retained.phase, Phase::Fetch));
    assert!(retained.selection.ready(SelectionStage::Final));
    assert_eq!(
        retained.closure.certificate_count(),
        2,
        "retry retains inputs, never the stale checked batch"
    );
    assert!(
        graph.storage_error().is_none(),
        "persistence cut was never reached"
    );
    assert_eq!(graph.content_root(), before);
    assert_eq!(graph.accepted_count(), 1);
    assert!(!graph.contains(root).unwrap() && !graph.contains(helper_id).unwrap());
    assert_eq!(registered(&mut questions, &graph), 0);
}

#[tokio::test]
async fn committed_missing_corrupt_membership_or_root_batch_fails_startup() {
    for mode in 0..4 {
        let directory = Directory::new();
        let mut graph = Graph::open(&directory.0).unwrap();
        let (object, metadata) = fixture(8);
        let root = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
        let peer = PeerId::random();
        let mut questions = new_questions();
        let mut intake = Intake::default();
        intake.enqueue(peer, metadata, &graph).unwrap();
        approve(&mut intake, &mut questions, &mut graph).await;
        intake.payload(peer, root, root, object, &graph).unwrap();
        intake.advance(&mut graph, &mut questions);
        interest(&mut questions, &graph).await;
        assert!(matches!(
            intake.advance(&mut graph, &mut questions),
            Progress::Accepted(_)
        ));
        drop(graph);
        let database =
            rusqlite::Connection::open(directory.0.join(crate::store::DATABASE_FILE)).unwrap();
        database.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        let id = root.as_bytes().as_slice();
        match mode {
            0 => {
                database
                    .execute("DELETE FROM artifacts WHERE id=?1", [id])
                    .unwrap();
            }
            1 => {
                crate::store::corrupt_payload(&directory.0, &hex(root.as_bytes()));
            }
            2 => {
                database
                    .execute("DELETE FROM members WHERE artifact_id=?1", [id])
                    .unwrap();
            }
            _ => {
                database
                    .execute("UPDATE commits SET root=zeroblob(32)", [])
                    .unwrap();
            }
        }
        drop(database);
        assert!(Graph::open(&directory.0).is_err());
    }
}

mod retry;
mod staging;
