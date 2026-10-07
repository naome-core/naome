use super::*;
use crate::{
    hex,
    object::content_id,
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
    let a = "forall(x, equal(x,x))";
    let mut b = "member(y,y)".to_owned();
    for bit in format!("{index:b}").bytes() {
        b = format!(
            "implies({}, {b})",
            if bit == b'1' {
                "equal(y,y)"
            } else {
                "member(y,y)"
            }
        );
    }
    b = format!("forall(y,{b})");
    format!(
        "foundation = \"naome:zfc\" statement = implies({a},implies({b},{a})) proof: p0 = simplification({a},{b}) return p0"
    )
}

fn fixture(index: usize) -> (Envelope, Metadata) {
    let mut producer = Graph::default();
    let object = producer.author(&source(index)).unwrap();
    let id = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
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
    let object = graph.author("foundation = \"naome:zfc\" statement = forall(x,equal(x,x)) proof: p0 = equality_reflexivity(x) p1 = generalization(p0,x) return p1").unwrap();
    assert_eq!(
        object.proof_id,
        "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73"
    );
    let id = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
    graph.ingest(object.clone(), Instant::now()).unwrap();
    let mut metadata = graph.describe(id).unwrap().unwrap();
    let (_, statement, question) = metadata.compile().unwrap();
    assert_eq!(hex(statement.as_bytes()), object.statement_id);
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
    for index in 0..MAX_QUEUED_METADATA {
        intake
            .enqueue(peer, fixture(100 + index).1, &graph)
            .unwrap();
    }
    let next = fixture(100 + MAX_QUEUED_METADATA).1;
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
    assert_eq!(intake.description_capacity(), MAX_QUEUED_METADATA);
}

#[tokio::test]
async fn valid_normal_proofs_respect_the_cumulative_transport_step_budget() {
    use naome_foundation::{Formula, FreeVariable};
    use naome_proof::{ProofCertificate, ProofStep};

    for count in [MAX_CLOSURE_STEPS, MAX_CLOSURE_STEPS + 1] {
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
        while steps.len() < count - 1 {
            steps.push(ProofStep::ModusPonens {
                premise,
                implication: 2,
            });
            premise = (steps.len() - 1) as u32;
        }
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
        assert!(bytes.len() < crate::MAX_PROOF_BYTES);
        eprintln!(
            "checked_transport_boundary steps={count} canonical_bytes={} proof_id={}",
            bytes.len(),
            hex(checked.proof_id().as_bytes())
        );
        let object = Envelope {
            compatibility: hex(&crate::compatibility()),
            proof_id: hex(checked.proof_id().as_bytes()),
            statement_id: hex(checked.statement_id().as_bytes()),
            proof: hex(bytes),
        };
        let id = checked.proof_id();
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
        if count == MAX_CLOSURE_STEPS {
            intake.payload(peer, id, id, object, &graph).unwrap();
            assert_eq!(intake.active.as_ref().unwrap().steps, MAX_CLOSURE_STEPS);
            intake.advance(&mut graph, &mut questions);
            interest(&mut questions, &graph).await;
            assert!(
                matches!(intake.advance(&mut graph, &mut questions), Progress::Accepted(ids) if ids == vec![id])
            );
            assert!(graph.contains(id));
            assert_eq!(registered(&mut questions, &graph), 1);
        } else {
            assert!(
                intake
                    .payload(peer, id, id, object, &graph)
                    .unwrap_err()
                    .contains("step work limit")
            );
            assert!(intake.active.as_ref().unwrap().staged.is_empty());
            intake.abort(id);
            assert_eq!(graph.content_root(), before);
            assert!(graph.pending_ids().is_empty());
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
async fn changed_context_and_expired_grants_cannot_fetch_or_stage_proofs() {
    let (object, metadata) = fixture(2);
    let id = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
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
        Progress::Skipped(..)
    ));
    assert!(intake.needed().is_empty());
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata.clone(), &graph).unwrap();
    approve(&mut intake, &mut questions, &mut graph).await;
    intake.active.as_mut().unwrap().description.created = Instant::now() - ROOT_TTL;
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
    queued.queue.front_mut().unwrap().created = Instant::now() - ROOT_TTL;
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
    let id = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
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
    wrong.proof_id = object.proof_id.clone();
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
    let root = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
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
        .describe(ProofId::from_bytes(id_bytes(&helper.proof_id).unwrap()))
        .unwrap()
        .unwrap()
        .question
        .split("statement = ")
        .nth(1)
        .unwrap()
        .to_owned();
    let b = "forall(z,member(z,z))";
    let root = producer.author(&format!("foundation = \"naome:zfc\" statement = implies({b},{premise}) proof: p0 = cite(\"{}\") p1 = simplification({premise},{b}) p2 = modus_ponens(p0,p1) return p2", helper.proof_id)).unwrap();
    let id = ProofId::from_bytes(id_bytes(&root.proof_id).unwrap());
    producer.ingest(root.clone(), Instant::now()).unwrap();
    (root, helper, producer.describe(id).unwrap().unwrap())
}

#[tokio::test]
async fn approved_parent_stages_only_committed_helpers_and_publishes_whole_closure() {
    let (object, helper, metadata) = dependent_fixture();
    let root = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
    let helper_id = ProofId::from_bytes(id_bytes(&helper.proof_id).unwrap());
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
    assert!(graph.ids().is_empty());
    assert!(graph.pending_ids().is_empty());
    intake
        .payload(peer, root, helper_id, helper, &graph)
        .unwrap();
    intake.advance(&mut graph, &mut questions);
    assert!(
        graph.ids().is_empty(),
        "math checking stages no stored local knowledge"
    );
    assert_eq!(registered(&mut questions, &graph), 0);
    interest(&mut questions, &graph).await;
    assert!(
        matches!(intake.advance(&mut graph, &mut questions), Progress::Accepted(ids) if ids.len() == 2)
    );
    assert_eq!(graph.ids().len(), 2);
    assert!(graph.contains(root) && graph.contains(helper_id));
    assert_eq!(registered(&mut questions, &graph), 1);
}

#[tokio::test]
async fn successful_batch_enables_only_the_preexisting_local_owner_pending_transition() {
    let (object, helper, metadata) = dependent_fixture();
    let mut producer = Graph::default();
    producer.ingest(helper.clone(), Instant::now()).unwrap();
    let formula = producer
        .describe(ProofId::from_bytes(id_bytes(&helper.proof_id).unwrap()))
        .unwrap()
        .unwrap()
        .compile()
        .unwrap()
        .2
        .core()
        .to_source();
    let owner = producer
        .author(&format!(
            "foundation = \"naome:zfc\" statement = {formula} proof: p0 = cite(\"{}\") return p0",
            helper.proof_id
        ))
        .unwrap();
    let owner_id = ProofId::from_bytes(id_bytes(&owner.proof_id).unwrap());
    let root = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
    let helper_id = ProofId::from_bytes(id_bytes(&helper.proof_id).unwrap());
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
    assert_eq!(graph.pending_ids(), vec![owner_id]);
    assert_eq!(graph.ids().len(), 2);
    let (admitted, rejected) = graph.resolve_pending();
    assert_eq!(admitted, vec![owner_id]);
    assert!(rejected.is_empty());
    assert!(graph.pending_ids().is_empty());
    assert_eq!(graph.ids().len(), 3);
}

#[tokio::test]
async fn necessary_helper_outside_question_codec_is_checked_without_own_question_selection() {
    let mut producer = Graph::default();
    let mut formula = "equal(x0,x0)".to_owned();
    for index in 0..40 {
        formula = format!("forall(x{index},{formula})");
    }
    let mut proof = "p0 = equality_reflexivity(x0)".to_owned();
    for index in 0..40 {
        proof.push_str(&format!(
            " p{} = generalization(p{},x{index})",
            index + 1,
            index
        ));
    }
    let helper = producer
        .author(&format!(
            "foundation = \"naome:zfc\" statement = {formula} proof: {proof} return p40"
        ))
        .unwrap();
    producer.ingest(helper.clone(), Instant::now()).unwrap();
    let helper_id = ProofId::from_bytes(id_bytes(&helper.proof_id).unwrap());
    assert!(producer.describe(helper_id).is_err());
    let mut steps = format!("p0 = cite(\"{}\")", helper.proof_id);
    let mut previous = "p0".to_owned();
    for (offset, variable) in (1..40).rev().enumerate() {
        let mut body = "equal(x0,x0)".to_owned();
        for index in 0..variable {
            body = format!("forall(x{index},{body})");
        }
        steps.push_str(&format!(" u{offset} = universal_instantiation(x{variable},x{variable},{body}) r{offset} = modus_ponens({previous},u{offset})"));
        previous = format!("r{offset}");
    }
    let object = producer.author(&format!("foundation = \"naome:zfc\" statement = forall(x0,equal(x0,x0)) proof: {steps} return {previous}")).unwrap();
    let root = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
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
        let root = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
        let helper_id = ProofId::from_bytes(id_bytes(&helper.proof_id).unwrap());
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
        assert!(graph.ids().is_empty() && graph.pending_ids().is_empty());
        assert_eq!(registered(&mut questions, &graph), usize::from(mode == 3));
    }
}

#[tokio::test]
async fn invalid_parent_after_valid_helper_leaves_no_orphan_or_registry_effect() {
    let (mut object, helper, mut metadata) = dependent_fixture();
    // A real canonical citation certificate commits the helper, but its
    // conclusion cannot establish the advertised unrelated statement.
    let helper_id = ProofId::from_bytes(id_bytes(&helper.proof_id).unwrap());
    let bytes = naome_proof::ProofCertificate::new(vec![naome_proof::ProofStep::ProofReference {
        proof_id: helper_id,
    }])
    .unwrap()
    .to_canonical_bytes();
    object.proof = hex(&bytes);
    let statement = StatementId::from_bytes(id_bytes(&object.statement_id).unwrap());
    let root = content_id(statement, &bytes);
    object.proof_id = hex(root.as_bytes());
    metadata.proof_id = object.proof_id.clone();
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
    assert!(graph.ids().is_empty() && graph.pending_ids().is_empty());
    assert_eq!(registered(&mut questions, &graph), 0);
}

#[tokio::test]
async fn delivered_original_admission_allows_fresh_current_policy_but_baseline_does_not() {
    let (object, metadata) = fixture(6);
    let derived = metadata.compile().unwrap().2;
    let original = CompiledQuestion::compile(&format!(
        "# original owner source\nfoundation = \"naome:zfc\" statement = not_({})",
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
    policy.revision += 1;
    let (sender, _receiver) = oneshot::channel();
    questions.process(Command::Policy(policy, sender), &graph);
    let peer = PeerId::random();
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata.clone(), &graph).unwrap();
    approve(&mut intake, &mut questions, &mut graph).await;
    let approved = intake.active.as_ref().unwrap();
    assert_eq!(approved.question, original);
    assert!(approved.initial.as_ref().unwrap().novelty().is_none());
    assert_eq!(historical, receipt);
    assert_ne!(
        approved.initial.as_ref().unwrap().prefilter.policy,
        receipt.policy()
    );
    let root = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
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
async fn persistence_cuts_preserve_legacy_state_and_recover_only_complete_renamed_batches() {
    for cut in [
        BatchCut::BeforeWrite,
        BatchCut::DuringWrite,
        BatchCut::BeforeRename,
        BatchCut::AfterRename,
    ] {
        let directory = Directory::new();
        let mut graph = Graph::open(&directory.0).unwrap();
        let legacy = fixture(7).0;
        let legacy_id = ProofId::from_bytes(id_bytes(&legacy.proof_id).unwrap());
        graph.ingest(legacy, Instant::now()).unwrap();
        let before = graph.content_root();
        let (object, helper, metadata) = dependent_fixture();
        let root = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
        let helper_id = ProofId::from_bytes(id_bytes(&helper.proof_id).unwrap());
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
        assert!(restarted.contains(legacy_id));
        assert_eq!(
            restarted.ids().len(),
            if cut == BatchCut::AfterRename { 3 } else { 1 }
        );
        if cut == BatchCut::AfterRename {
            assert!(restarted.contains(root) && restarted.contains(helper_id));
        }
    }
}

#[tokio::test]
async fn committed_missing_corrupt_extra_or_misnamed_batch_fails_startup() {
    for mode in 0..4 {
        let directory = Directory::new();
        let mut graph = Graph::open(&directory.0).unwrap();
        let (object, metadata) = fixture(8);
        let root = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
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
        let batch = std::fs::read_dir(directory.0.join("objects/batches"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        match mode {
            0 => {
                std::fs::remove_file(batch.join(format!("{}.json", hex(root.as_bytes())))).unwrap()
            }
            1 => {
                std::fs::write(batch.join(format!("{}.json", hex(root.as_bytes()))), b"{}").unwrap()
            }
            2 => std::fs::write(batch.join("unexpected.json"), b"{}").unwrap(),
            _ => std::fs::rename(&batch, batch.parent().unwrap().join("00".repeat(32))).unwrap(),
        }
        assert!(Graph::open(&directory.0).is_err());
    }
}
