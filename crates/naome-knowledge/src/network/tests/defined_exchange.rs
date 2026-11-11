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

// The governor samples process resources. Run each multi-peer scenario
// outside the process containing the parallel library tests.
fn isolated(case: &str) -> bool {
    const ENV: &str = "NAOME_DEFINED_EXCHANGE_CASE";
    let case = format!("{}::{case}", module_path!().split_once("::").unwrap().1);
    if std::env::var(ENV).as_deref() == Ok(case.as_str()) {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &case, "--nocapture"])
        .env(ENV, &case)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("running 1 test"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

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

fn init_peer(path: &Path, definition: Option<&DefinitionCertificate>) -> PeerId {
    std::fs::create_dir(path).unwrap();
    let key = identity::Keypair::generate_ed25519();
    std::fs::write(
        path.join("identity.key"),
        key.to_protobuf_encoding().unwrap(),
    )
    .unwrap();
    let mut graph = Graph::open(path).unwrap();
    if let Some(definition) = definition {
        let (_, receipt) = graph
            .produce(&crate::test_inputs::definition(definition))
            .unwrap();
        assert_eq!(receipt.status, crate::IngestStatus::Accepted);
    }
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
        formal_goal: None,
        producer_artifacts: Vec::new(),
    }
}

async fn replicate(
    (donor_path, donor_id): (&Path, PeerId),
    (receiver_path, receiver_id): (&Path, PeerId),
    expected_artifacts: usize,
    select: impl Fn(ResearchQuestion) -> bool + Send + Sync + 'static,
) {
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
        config(donor_path.to_path_buf(), ports[0], receiver_id, ports[1]),
        false,
        donor_inbox,
        crate::mocks::select_question,
    ));
    let (receiver_handle, receiver_admin, receiver_inbox) = crate::question::channel();
    let receiver_task = tokio::spawn(run_with_questions(
        config(receiver_path.to_path_buf(), ports[1], donor_id, ports[0]),
        false,
        receiver_inbox,
        move |candidate| std::future::ready(Ok(select(candidate))),
    ));
    let reached = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if receiver_handle.context().await.unwrap().checked_artifacts == expected_artifacts {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    receiver_admin.stop().await.unwrap();
    donor_admin.stop().await.unwrap();
    for task in [receiver_task, donor_task] {
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    reached.expect("peer did not publish the expected checked closure");
}

async fn exchange_answer(program: bool) {
    let directory = ConfigFile::new();
    let donor_path = directory.0.join("donor");
    let receiver_path = directory.0.join("receiver");
    let (definition, source, answer) = large_answer();
    let donor_id = init_peer(&donor_path, Some(&definition));
    let receiver_id = init_peer(&receiver_path, None);
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

    let expected_source = compact.clone();
    replicate(
        (&donor_path, donor_id),
        (&receiver_path, receiver_id),
        2,
        move |candidate| candidate.to_hex() == expected_source,
    )
    .await;
    let reopened = Graph::open(&receiver_path).unwrap();
    assert!(
        reopened
            .contains(ArtifactId::from_definition_id(definition.definition_id()))
            .unwrap()
    );
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
    if isolated("checked_certificate_replicates_with_its_compact_definition_question") {
        return;
    }
    exchange_answer(false).await;
}

#[tokio::test]
async fn checked_program_replicates_with_its_compact_definition_question() {
    if isolated("checked_program_replicates_with_its_compact_definition_question") {
        return;
    }
    exchange_answer(true).await;
}

async fn relay_helper(program: bool) {
    let directory = ConfigFile::new();
    let donor_path = directory.0.join("donor");
    let relay_path = directory.0.join("relay");
    let receiver_path = directory.0.join("receiver");
    let (definition, source, answer) = large_answer();
    let donor_id = init_peer(&donor_path, Some(&definition));
    let relay_id = init_peer(&relay_path, None);
    let receiver_id = init_peer(&receiver_path, None);

    let mut donor = Graph::open(&donor_path).unwrap();
    let helper_question =
        ResearchQuestion::from_defined_formula(source.clone(), donor.checked_context()).unwrap();
    let (helper, batch) = if program {
        stage_program(&donor, answer, &helper_question)
    } else {
        let input = crate::test_inputs::proof(answer.steps().to_vec());
        donor
            .prepare_generated(&input, &[], &helper_question)
            .unwrap()
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    donor
        .commit_batch_granted(helper, batch, deadline, None, Some(&helper_question))
        .unwrap();

    // Only the helper's source refers to the first definition. The parent's
    // compact source names a different relation with the same primitive body
    // it would have used without abbreviations.
    let x = FreeVariable::new(0);
    let extra = Formula::member(x, x);
    let body = Formula::implies(extra.clone(), helper_question.formula().clone());
    let parent_definition =
        DefinitionCertificate::relation(1, DefinedFormula::from_primitive(&body).unwrap()).unwrap();
    donor
        .produce(&crate::test_inputs::definition(&parent_definition))
        .unwrap();
    let parent_question = ResearchQuestion::from_defined_formula(
        DefinedFormula::for_all(
            x,
            DefinedFormula::defined_relation(parent_definition.definition_id(), [x]),
        ),
        donor.checked_context(),
    )
    .unwrap();
    let proof = donor
        .checked_context()
        .artifact_proof_id(helper)
        .unwrap()
        .unwrap();
    let mut steps = crate::test_inputs::weaken(
        vec![ProofStep::ProofReference { proof_id: proof }],
        helper_question.formula().clone(),
        extra,
    );
    steps.push(ProofStep::Generalization {
        premise: (steps.len() - 1) as u32,
        variable: x,
    });
    let input = crate::test_inputs::proof(steps);
    let (parent, batch) = donor
        .prepare_generated(&input, &[], &parent_question)
        .unwrap();
    donor
        .commit_batch_granted(parent, batch, deadline, None, Some(&parent_question))
        .unwrap();
    drop(donor);

    // The relay selects only the parent, so it must acquire the other proof
    // under the parent's closure grant and keep its independently bound source.
    let parent_source = parent_question.to_hex();
    replicate(
        (&donor_path, donor_id),
        (&relay_path, relay_id),
        4,
        move |question| question.to_hex() == parent_source,
    )
    .await;
    let relay = Graph::open(&relay_path).unwrap();
    assert!(relay.resolves_question(parent, &parent_question).unwrap());
    assert!(relay.resolves_question(helper, &helper_question).unwrap());
    drop(relay);

    // The final peer selects only the former helper and knows no definitions.
    // The middle peer restarts before it serves this standalone request.
    let helper_source = helper_question.to_hex();
    replicate(
        (&relay_path, relay_id),
        (&receiver_path, receiver_id),
        3,
        move |question| question.to_hex() == helper_source,
    )
    .await;
    let receiver = Graph::open(&receiver_path).unwrap();
    assert!(!receiver.contains(parent).unwrap());
    assert!(
        receiver
            .resolves_question(helper, &helper_question)
            .unwrap()
    );
}

#[tokio::test]
async fn compact_certificate_helper_survives_relay_and_restart() {
    if isolated("compact_certificate_helper_survives_relay_and_restart") {
        return;
    }
    relay_helper(false).await;
}

#[tokio::test]
async fn compact_program_helper_survives_relay_and_restart() {
    if isolated("compact_program_helper_survives_relay_and_restart") {
        return;
    }
    relay_helper(true).await;
}

#[tokio::test]
async fn cold_peer_checks_function_witness_before_selecting_compact_question() {
    if isolated("cold_peer_checks_function_witness_before_selecting_compact_question") {
        return;
    }
    let directory = ConfigFile::new();
    let donor_path = directory.0.join("donor");
    let receiver_path = directory.0.join("receiver");
    let (relation, source, answer) = large_answer();
    let donor_id = init_peer(&donor_path, Some(&relation));
    let receiver_id = init_peer(&receiver_path, None);
    let mut donor = Graph::open(&donor_path).unwrap();

    let digits: String =
        include_str!("../../../../naome-checker/src/tests/fixtures/identity_unique.proof.hex")
            .split_whitespace()
            .collect();
    let witness = ProofCertificate::from_canonical_bytes(&crate::unhex(&digits).unwrap()).unwrap();
    let witness_input = crate::test_inputs::proof(witness.steps().to_vec());
    let (_, witness) = donor.produce(&witness_input).unwrap();
    let (function, function_receipt) = donor
        .produce(&crate::test_inputs::identity_function())
        .unwrap();
    let function = function.definition_id().unwrap().unwrap();

    let x = FreeVariable::new(0);
    let extra = DefinedFormula::for_all(x, DefinedFormula::defined_relation(function, [x, x]));
    let antecedent =
        ResearchQuestion::from_defined_formula(extra.clone(), donor.checked_context()).unwrap();
    let consequent =
        ResearchQuestion::from_defined_formula(source.clone(), donor.checked_context()).unwrap();
    let question = ResearchQuestion::from_defined_formula(
        DefinedFormula::implies(extra, source),
        donor.checked_context(),
    )
    .unwrap();
    let input = crate::test_inputs::proof(crate::test_inputs::weaken(
        answer.steps().to_vec(),
        consequent.formula().clone(),
        antecedent.formula().clone(),
    ));
    let (root, batch) = donor.prepare_generated(&input, &[], &question).unwrap();
    donor
        .commit_batch_granted(
            root,
            batch,
            Instant::now() + Duration::from_secs(15),
            None,
            Some(&question),
        )
        .unwrap();
    drop(donor);

    // The receiver's selection explicitly excludes the standalone witness.
    // Its only source of authority is checking the exact function obligation.
    let expected_source = question.to_hex();
    replicate(
        (&donor_path, donor_id),
        (&receiver_path, receiver_id),
        4,
        move |candidate| candidate.to_hex() == expected_source,
    )
    .await;
    let receiver = Graph::open(&receiver_path).unwrap();
    assert!(receiver.contains(witness.id).unwrap());
    assert!(receiver.contains(function_receipt.id).unwrap());
    assert!(receiver.resolves_question(root, &question).unwrap());
}

#[tokio::test]
async fn unsolicited_offers_do_not_schedule_missing_question_definitions() {
    if isolated("unsolicited_offers_do_not_schedule_missing_question_definitions") {
        return;
    }

    let directory = ConfigFile::new();
    let donor_path = directory.0.join("donor");
    let receiver_path = directory.0.join("receiver");
    let (definition, source, answer) = large_answer();
    init_peer(&donor_path, Some(&definition));
    let receiver_id = init_peer(&receiver_path, None);
    let mut donor = Graph::open(&donor_path).unwrap();
    let question = ResearchQuestion::from_defined_formula(source, donor.checked_context()).unwrap();
    let checked = naome_checker::normalize_and_check(answer.clone()).unwrap();
    let proof_id = checked.proof_id();
    let metadata = Metadata {
        artifact_id: hex(ArtifactId::from_proof_id(proof_id).as_bytes()),
        proof_id: hex(proof_id.as_bytes()),
        statement_id: hex(checked.statement_id().as_bytes()),
        question: question.to_hex(),
    };
    metadata.compile(donor.checked_context()).unwrap();
    let (program, batch) = stage_program(&donor, answer, &question);
    donor
        .commit_batch(program, batch, Instant::now() + Duration::from_secs(15))
        .unwrap();
    let Some(crate::object::ArtifactTransfer::Program(mut program_metadata)) =
        donor.transfer(program).unwrap()
    else {
        panic!("expected program metadata");
    };
    program_metadata.question = Some(question.to_hex());

    let mut client = isolated_transport();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let receiver = config(receiver_path, port, *client.local_peer_id(), 1);
    let address = receiver.listen.parse().unwrap();
    let (_, admin, inbox) = crate::question::channel();
    let running = tokio::spawn(run_with_questions(
        receiver,
        false,
        inbox,
        crate::mocks::select_question,
    ));
    connected(&mut client, receiver_id, address).await;
    for offer in [
        Body::Offer { metadata },
        Body::ProgramOffer {
            metadata: program_metadata,
        },
    ] {
        let response = request(&mut client, receiver_id, offer).await;
        assert!(
            matches!(
                response,
                Body::Error {
                    code: PeerFailure::InvalidRequest
                }
            ),
            "{response:?}"
        );
    }
    admin.stop().await.unwrap();
    running.await.unwrap().unwrap();
}
