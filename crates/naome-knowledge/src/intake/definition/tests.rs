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
                question_proof: witness,
                helper_deadline: None,
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
                question_proof: ArtifactId::from_bytes([7; 32]),
                helper_deadline: None,
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
