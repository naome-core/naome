use super::*;
use crate::{
    graph::CheckedBatch,
    object::ProofDescription,
    proof_work::Work,
    question::{AdmissionOutcome, LocalQuestions},
    resources::adaptive::Budget,
};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{
    DefinedFormula, DefinitionCertificate, ProofCertificate, ProofStep,
    program::{CHUNK_BYTES, CHUNK_RECORDS, Projection},
};

fn large_answer() -> (DefinitionCertificate, DefinedFormula, ProofCertificate) {
    let x = FreeVariable::new(0);
    let equality = Formula::equal(x, x);
    let mut premise = equality.clone();
    for _ in 0..9 {
        premise = Formula::implies(premise.clone(), premise);
    }
    for _ in 0..40 {
        premise = Formula::negate(premise);
    }
    let body = Formula::implies(premise.clone(), equality.clone());
    let definition =
        DefinitionCertificate::relation(1, DefinedFormula::from_primitive(&body).unwrap()).unwrap();
    let source = DefinedFormula::for_all(
        x,
        DefinedFormula::defined_relation(definition.definition_id(), [x]),
    );
    let answer = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Simplification {
            antecedent: equality.into(),
            consequent: premise.into(),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
        ProofStep::Generalization {
            premise: 2,
            variable: x,
        },
    ])
    .unwrap();
    (definition, source, answer)
}

fn stage_program(
    graph: &Graph,
    answer: ProofCertificate,
    question: &ResearchQuestion,
) -> (ArtifactId, CheckedBatch) {
    let certificate = naome_checker::normalize_and_check(answer).unwrap();
    let projection = Projection::from_normal_form(certificate.normal_form());
    let mut work =
        Work::open(&graph.ownership().directory().join("defined-answer.sqlite3")).unwrap();
    let budget = Budget {
        memory_bytes: 128 * 1024 * 1024,
        concurrency: 1,
        cache_bytes: 1024 * 1024,
        batch_steps: 512,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };
    work.append_group(projection.commands()).unwrap();
    while work.advance(&budget, graph.checked_context()).unwrap() {}
    while !work.prepare_export(&budget).unwrap() {}
    let checked = work.into_checked().unwrap();
    let proof = checked.proof().unwrap();
    assert_eq!(
        question.classify_checked_program(proof).unwrap(),
        naome_checker::question::QuestionOutcome::Proved
    );
    let manifest = proof.manifest();
    graph.ownership().start_program(manifest).unwrap();
    let mut start = 0;
    while start < manifest.commands {
        let chunk = proof
            .input_chunk(start, CHUNK_RECORDS, CHUNK_BYTES)
            .unwrap();
        graph.ownership().append_program(manifest, &chunk).unwrap();
        start += chunk.records.len() as u64;
    }
    let mut admission = graph.begin_program_admission(&checked).unwrap();
    while !admission.advance(graph, &checked, 512).unwrap() {}
    (
        manifest.artifact_id(),
        admission.finish(graph, &checked).unwrap(),
    )
}

fn init_peer(path: &Path, definition: &DefinitionCertificate) -> PeerId {
    std::fs::create_dir(path).unwrap();
    let key = identity::Keypair::generate_ed25519();
    std::fs::write(
        path.join("identity.key"),
        key.to_protobuf_encoding().unwrap(),
    )
    .unwrap();
    let mut graph = Graph::open(path).unwrap();
    let (_, receipt) = graph
        .produce(&crate::test_inputs::definition(definition))
        .unwrap();
    assert_eq!(receipt.status, "accepted");
    key.public().to_peer_id()
}

fn config(directory: PathBuf, port: u16, remote: PeerId, remote_port: u16) -> Config {
    Config {
        directory,
        listen: format!("/ip4/127.0.0.1/tcp/{port}"),
        peers: vec![Peer {
            id: remote.to_string(),
            address: format!("/ip4/127.0.0.1/tcp/{remote_port}"),
        }],
        discovery: Some(DiscoveryConfig {
            mdns: false,
            dht: false,
            ..Default::default()
        }),
        producer_artifacts: Vec::new(),
    }
}

async fn exchange_answer(program: bool) {
    let directory = ConfigFile::new();
    let donor_path = directory.0.join("donor");
    let receiver_path = directory.0.join("receiver");
    let (definition, source, answer) = large_answer();
    let donor_id = init_peer(&donor_path, &definition);
    let receiver_id = init_peer(&receiver_path, &definition);
    let mut donor = Graph::open(&donor_path).unwrap();
    let question = ResearchQuestion::from_defined_formula(source, donor.checked_context()).unwrap();
    assert!(ResearchQuestion::from_formula(question.formula().clone()).is_err());
    let compact = question.to_hex();

    // Exercise publication of an already admitted local question, where there
    // is no second question record to insert at proof publication.
    let mut publisher = LocalQuestions::new(Some(crate::mocks::select_question));
    publisher.attach_persistence(&donor_path, &donor).unwrap();
    let (reply, mut admitted) = tokio::sync::oneshot::channel();
    publisher.process(
        crate::question::Command::Admit(question.clone(), reply),
        &donor,
    );
    let admission = tokio::select! {
        admission = &mut admitted => admission.unwrap(),
        decision = publisher.completed() => {
            publisher.finish(&donor, decision);
            admitted.await.unwrap()
        }
    };
    assert!(
        matches!(admission.outcome, AdmissionOutcome::Admitted(_)),
        "{} ({:?})",
        admission.assessment.prefilter.rule,
        admission.assessment.prefilter.reason,
    );

    let (root, batch) = if program {
        stage_program(&donor, answer, &question)
    } else {
        let input = crate::test_inputs::proof(answer.steps().to_vec());
        donor.prepare_generated(&input, &[], &question).unwrap()
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    let (selected, mut reply) = publisher.begin_exchange(&donor, question.clone(), deadline);
    let assessment = tokio::select! {
        assessment = &mut reply => assessment.unwrap(),
        decision = publisher.completed() => {
            publisher.finish(&donor, decision);
            reply.await.unwrap()
        }
    };
    let delta = publisher
        .prepare_exchange(&donor, &selected, &assessment)
        .unwrap();
    assert_eq!(
        publisher
            .publish_exchange(&mut donor, root, batch, delta, None, deadline)
            .unwrap(),
        vec![root]
    );
    drop(publisher);
    drop(donor);

    let listeners = [
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let ports = listeners
        .each_ref()
        .map(|listener| listener.local_addr().unwrap().port());
    drop(listeners);
    let (_, donor_admin, donor_inbox) = crate::question::channel();
    let donor_task = tokio::spawn(run_with_questions(
        config(donor_path, ports[0], receiver_id, ports[1]),
        false,
        donor_inbox,
        crate::mocks::select_question,
    ));
    let (receiver_handle, receiver_admin, receiver_inbox) = crate::question::channel();
    let expected_source = compact.clone();
    let receiver_task = tokio::spawn(run_with_questions(
        config(receiver_path.clone(), ports[1], donor_id, ports[0]),
        false,
        receiver_inbox,
        move |candidate| {
            assert_eq!(candidate.to_hex(), expected_source);
            std::future::ready(Ok(true))
        },
    ));
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if receiver_handle.context().await.unwrap().checked_artifacts == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    receiver_admin.stop().await.unwrap();
    donor_admin.stop().await.unwrap();
    for task in [receiver_task, donor_task] {
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    let reopened = Graph::open(&receiver_path).unwrap();
    assert!(reopened.resolves_question(root, &question).unwrap());
    match reopened.description(root).unwrap().unwrap() {
        ProofDescription::Program(metadata) => {
            assert!(program);
            assert_eq!(metadata.question.as_deref(), Some(compact.as_str()));
        }
        ProofDescription::Certificate(metadata) => {
            assert!(!program);
            assert_eq!(metadata.question, compact);
        }
    }
}

#[tokio::test]
async fn checked_certificate_replicates_with_its_compact_definition_question() {
    exchange_answer(false).await;
}

#[tokio::test]
async fn checked_program_replicates_with_its_compact_definition_question() {
    exchange_answer(true).await;
}
