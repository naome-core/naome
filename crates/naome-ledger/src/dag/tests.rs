use crate::{ArtifactAdmissionError, ArtifactDag, ArtifactSetMembership};
use naome_checker::{ArtifactStateError, CheckError, normalize_and_check};
use naome_foundation::{FreeVariable, ZfcAxiom};
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofId, ProofStep};

fn proof_artifact_bytes(steps: Vec<ProofStep>) -> Vec<u8> {
    let certificate = ProofCertificate::new(steps)
        .unwrap()
        .into_unchecked_normal_form()
        .certificate()
        .clone();
    ArtifactPayload::Proof(certificate).to_canonical_bytes()
}

fn axiom_artifact_bytes(axiom: ZfcAxiom) -> Vec<u8> {
    proof_artifact_bytes(vec![ProofStep::ZfcAxiom(axiom)])
}

fn referenced_generalization_artifact_bytes(proof_id: ProofId, variable: u32) -> Vec<u8> {
    proof_artifact_bytes(vec![
        ProofStep::ProofReference { proof_id },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(variable),
        },
    ])
}

fn standalone_proof_id(bytes: &[u8]) -> ProofId {
    let ArtifactPayload::Proof(certificate) = ArtifactPayload::from_canonical_bytes(bytes).unwrap()
    else {
        panic!("the test helper accepts only proof artifacts")
    };
    normalize_and_check(certificate).unwrap().proof_id()
}

fn artifact_id_for(bytes: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(bytes.to_vec())
        .unwrap()
        .artifact_id()
}

#[test]
fn independent_proofs_form_an_authenticated_order_independent_set() {
    let pairing = axiom_artifact_bytes(ZfcAxiom::Pairing);
    let union = axiom_artifact_bytes(ZfcAxiom::Union);
    let pairing_id = artifact_id_for(&pairing);
    let union_id = artifact_id_for(&union);
    let mut first = ArtifactDag::new();
    first
        .apply_canonical_artifact_bytes(pairing.clone())
        .unwrap();
    first.apply_canonical_artifact_bytes(union.clone()).unwrap();
    let mut second = ArtifactDag::new();
    second.apply_canonical_artifact_bytes(union).unwrap();
    second.apply_canonical_artifact_bytes(pairing).unwrap();

    assert_eq!(first.artifact_set_root(), second.artifact_set_root());
    assert_eq!(first.len(), 2);
    for artifact_id in [pairing_id, union_id] {
        assert_eq!(
            first
                .artifact_set_proof(artifact_id)
                .verify(first.artifact_set_root(), artifact_id),
            Ok(ArtifactSetMembership::Present)
        );
    }
}

#[test]
fn dependencies_must_be_selected_before_artifact_admission() {
    let parent = axiom_artifact_bytes(ZfcAxiom::Pairing);
    let parent_artifact_id = artifact_id_for(&parent);
    let parent_proof_id = standalone_proof_id(&parent);
    let child = referenced_generalization_artifact_bytes(parent_proof_id, 7);
    let child_id = {
        let mut scratch = ArtifactDag::new();
        scratch
            .apply_canonical_artifact_bytes(parent.clone())
            .unwrap();
        scratch
            .apply_canonical_artifact_bytes(child.clone())
            .unwrap()
            .artifact_id()
    };
    let mut dag = ArtifactDag::new();
    let empty_root = dag.artifact_set_root();

    assert!(matches!(
        dag.apply_canonical_artifact_bytes_with_expected_id(child.clone(), child_id),
        Err(ArtifactAdmissionError::ProofCheck {
            source: CheckError::UnknownProofReference { proof_id, .. },
        }) if proof_id == parent_proof_id
    ));
    assert_eq!(dag.artifact_set_root(), empty_root);
    dag.apply_canonical_artifact_bytes_with_expected_id(parent, parent_artifact_id)
        .unwrap();
    dag.apply_canonical_artifact_bytes_with_expected_id(child, child_id)
        .unwrap();
    assert_eq!(dag.len(), 2);
}

#[test]
fn expected_address_and_duplicate_failures_never_mutate_the_dag() {
    let bytes = axiom_artifact_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_id_for(&bytes);
    let proof_id = standalone_proof_id(&bytes);
    let wrong = ArtifactId::from_bytes([0x55; 32]);
    let mut dag = ArtifactDag::new();
    let empty_root = dag.artifact_set_root();

    assert!(matches!(
        dag.apply_canonical_artifact_bytes_with_expected_id(bytes.clone(), wrong),
        Err(ArtifactAdmissionError::ArtifactIdMismatch { expected, actual })
            if expected == wrong && actual == artifact_id
    ));
    assert_eq!(dag.artifact_set_root(), empty_root);
    dag.apply_canonical_artifact_bytes_with_expected_id(bytes.clone(), artifact_id)
        .unwrap();
    let committed_root = dag.artifact_set_root();
    assert!(matches!(
        dag.apply_canonical_artifact_bytes_with_expected_id(bytes, artifact_id),
        Err(ArtifactAdmissionError::State {
            source: ArtifactStateError::DuplicateProof { proof_id: duplicate },
        }) if duplicate == proof_id
    ));
    assert_eq!(dag.artifact_set_root(), committed_root);
    assert_eq!(dag.len(), 1);
}

#[test]
fn metered_checked_admission_binds_expected_id_before_any_registration() {
    let bytes = axiom_artifact_bytes(ZfcAxiom::Pairing);
    let ArtifactPayload::Proof(certificate) =
        ArtifactPayload::from_canonical_bytes(&bytes).unwrap()
    else {
        unreachable!()
    };
    let checked = normalize_and_check(certificate).unwrap();
    let id = checked.proof_id();
    let mut dag = ArtifactDag::new();
    let root = dag.artifact_set_root();
    assert!(matches!(
        dag.admit_checked_proof(checked, ProofId::from_bytes([0xff; 32])),
        Err(ArtifactAdmissionError::ArtifactIdMismatch { .. })
    ));
    assert_eq!(dag.artifact_set_root(), root);
    assert!(dag.is_empty());
    assert!(!dag.artifact_state().contains_proof(id));
    let ArtifactPayload::Proof(certificate) =
        ArtifactPayload::from_canonical_bytes(&bytes).unwrap()
    else {
        unreachable!()
    };
    let checked = normalize_and_check(certificate).unwrap();
    dag.admit_checked_proof(checked, id).unwrap();
    assert_eq!(
        dag.artifact(ArtifactId::from_proof_id(id))
            .unwrap()
            .canonical_artifact_bytes(),
        bytes
    );
}
