use super::*;
use crate::object::{BinaryArtifact, id_bytes};
use naome_proof::ProofCertificate;

fn identity_definition(graph: &mut Graph) -> (Envelope, ArtifactId) {
    let bytes = crate::unhex(
        &include_str!("../../../../naome-checker/src/tests/fixtures/identity_unique.proof.hex")
            .split_whitespace()
            .collect::<String>(),
    )
    .unwrap();
    let proof = ProofCertificate::from_canonical_bytes(&bytes).unwrap();
    let checked = naome_checker::normalize_and_check(proof).unwrap();
    let witness = checked.artifact_id();
    graph
        .ingest(
            BinaryArtifact::from_checked(&checked).unwrap().envelope(),
            Instant::now(),
        )
        .unwrap();
    let (definition, _) = graph
        .produce(&crate::test_inputs::identity_function())
        .unwrap();
    (definition, witness)
}

#[test]
fn definition_preflight_cannot_fetch_the_unselected_parent_as_its_witness() {
    let (object, witness) = identity_definition(&mut Graph::default());
    let definition = object.definition_id().unwrap().unwrap();
    let id = ArtifactId::from_definition_id(definition);
    let peer = PeerId::random();
    let graph = Graph::default();
    let mut intake = Intake::default();
    intake
        .request_question_definition(
            DefinitionRequest {
                peer,
                definition,
                question_proof: Some(witness),
                helper_deadline: None,
                pending: None,
            },
            &graph,
            None,
        )
        .unwrap();

    let error = intake.payload(peer, id, id, object, &graph).unwrap_err();
    assert!(error.contains("unselected question proof"));
    assert_eq!(intake.needed(), [(peer, id, id)]);
    assert!(!graph.contains(id).unwrap());
    assert!(!graph.contains(witness).unwrap());
}

#[test]
fn unrelated_proof_cannot_authorize_a_function_definition() {
    let mut donor = Graph::default();
    let (mut object, witness) = identity_definition(&mut donor);
    let definition = object.definition_id().unwrap().unwrap();
    let id = ArtifactId::from_definition_id(definition);
    let input = crate::test_inputs::proof(crate::test_inputs::reflexivity([0]));
    let (unrelated, receipt) = donor.produce(&input).unwrap();
    object.obligation_proof = Some(crate::hex(
        unrelated.proof_id().unwrap().unwrap().as_bytes(),
    ));
    assert_ne!(receipt.id, witness);
    assert_eq!(id_bytes(&object.artifact_id).unwrap(), *id.as_bytes());

    let peer = PeerId::random();
    let mut graph = Graph::default();
    let mut intake = Intake::default();
    intake
        .request_question_definition(
            DefinitionRequest {
                peer,
                definition,
                question_proof: Some(ArtifactId::from_bytes([7; 32])),
                helper_deadline: None,
                pending: None,
            },
            &graph,
            None,
        )
        .unwrap();
    intake.payload(peer, id, id, object, &graph).unwrap();
    assert_eq!(intake.needed(), [(peer, id, receipt.id)]);
    intake
        .payload(peer, id, receipt.id, unrelated, &graph)
        .unwrap();

    let result = intake.advance_definition(&mut graph);
    assert!(
        matches!(result, Progress::Skipped(rejected, _) if rejected == id),
        "the unrelated witness must fail the exact obligation",
    );
    assert!(!graph.contains(id).unwrap());
    assert!(!graph.contains(receipt.id).unwrap());
}

#[test]
fn description_definition_stays_staged_until_parent_selection() {
    use naome_foundation::FreeVariable;
    use naome_proof::{DefinedFormula, ProofId};
    const CASE: &str =
        "intake::definition::tests::description_definition_stays_staged_until_parent_selection";
    if std::env::var("NAOME_DEFINITION_OFFER_CASE").as_deref() != Ok(CASE) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_DEFINITION_OFFER_CASE", CASE)
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
    crate::resources::adaptive::publish(crate::resources::adaptive::Snapshot {
        selection: Default::default(),
        observed: Default::default(),
        budget: crate::resources::adaptive::Budget {
            memory_bytes: 128 * 1024 * 1024,
            concurrency: 1,
            cache_bytes: 1024 * 1024,
            batch_steps: 512,
            network_requests: 1,
            yield_ms: 0,
            paused: None,
        },
        timestamp_ms: 0,
        pid: std::process::id(),
    });
    let mut donor = Graph::default();
    let (definition_object, witness) = identity_definition(&mut donor);
    let definition = definition_object.definition_id().unwrap().unwrap();
    let id = ArtifactId::from_definition_id(definition);
    let x = FreeVariable::new(0);
    let source = DefinedFormula::for_all(x, DefinedFormula::defined_relation(definition, [x, x]));
    let question = ResearchQuestion::from_defined_formula(source, donor.checked_context()).unwrap();
    let proof = ProofId::from_bytes([9; 32]);
    let artifact = ArtifactId::from_proof_id(proof);
    let metadata = crate::object::Metadata {
        artifact_id: crate::hex(artifact.as_bytes()),
        proof_id: crate::hex(proof.as_bytes()),
        statement_id: crate::hex(
            crate::object::target_id(question.positive_target())
                .unwrap()
                .as_bytes(),
        ),
        question: question.to_hex(),
    };
    let mut graph = Graph::default();
    assert!(
        matches!(ResearchQuestion::from_hex_with_context(&question.to_hex(), graph.checked_context()), Err(naome_proof::QuestionError::MissingDefinition(missing)) if missing == definition)
    );
    let peer = PeerId::random();
    let mut intake = Intake::default();
    intake
        .request_question_definition(
            DefinitionRequest {
                peer,
                definition,
                question_proof: Some(artifact),
                helper_deadline: None,
                pending: Some(PendingDescription::Certificate(metadata)),
            },
            &graph,
            None,
        )
        .unwrap();
    intake
        .payload(peer, id, id, definition_object.clone(), &graph)
        .unwrap();
    assert!(!graph.contains(id).unwrap());
    assert_eq!(intake.needed(), [(peer, id, witness)]);
    intake
        .payload(
            peer,
            id,
            witness,
            donor.object(witness).unwrap().unwrap(),
            &graph,
        )
        .unwrap();
    let result = intake.advance_definition(&mut graph);
    assert!(matches!(result, Progress::Waiting));
    assert!(!graph.contains(witness).unwrap());
    assert!(!graph.contains(id).unwrap());
    let queued = intake.queue.front().expect("resolved description queued");
    let prefix = queued.prefix.as_ref().expect("definition remains staged");
    assert_eq!(
        ResearchQuestion::from_hex_with_context(&question.to_hex(), prefix.context()).unwrap(),
        question
    );
    assert!(matches!(
        ResearchQuestion::from_hex_with_context(&question.to_hex(), graph.checked_context()),
        Err(naome_proof::QuestionError::MissingDefinition(_))
    ));

    // An unrelated proof cannot make the same offer usable.
    let (unrelated, receipt) = donor
        .produce(&crate::test_inputs::proof(crate::test_inputs::reflexivity(
            [0],
        )))
        .unwrap();
    let mut bad_definition = definition_object;
    bad_definition.obligation_proof = Some(crate::hex(
        unrelated.proof_id().unwrap().unwrap().as_bytes(),
    ));
    let mut cold = Graph::default();
    let mut rejected = Intake::default();
    rejected
        .request_question_definition(
            DefinitionRequest {
                peer,
                definition,
                question_proof: None,
                helper_deadline: Some(Instant::now() + Duration::from_secs(10)),
                pending: None,
            },
            &cold,
            None,
        )
        .unwrap();
    rejected
        .payload(peer, id, id, bad_definition, &cold)
        .unwrap();
    rejected
        .payload(peer, id, receipt.id, unrelated, &cold)
        .unwrap();
    assert!(
        matches!(rejected.advance_definition(&mut cold), Progress::Skipped(root, _) if root == id)
    );
    assert!(!cold.contains(id).unwrap());
    assert!(!cold.contains(receipt.id).unwrap());
    assert!(matches!(
        ResearchQuestion::from_hex_with_context(&question.to_hex(), cold.checked_context()),
        Err(naome_proof::QuestionError::MissingDefinition(_))
    ));
}
