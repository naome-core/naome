use naome_checker::{ArtifactStateError, CheckError, normalize_and_check};
use naome_foundation::{FreeVariable, ZfcAxiom};
use naome_ledger::LedgerError;
use naome_proof::{
    ArtifactId, ArtifactPayload, DefinedFormula, DefinitionCertificate, ProofCertificate, ProofId,
    ProofStep,
};

use super::{
    ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockApplyError, ArtifactBlockId,
    ArtifactBlockPrepareError, ArtifactChainDefinition, ArtifactChainState, ArtifactDag,
    ArtifactSetMembership, ArtifactSetRoot,
};

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

fn relation_definition_bytes() -> Vec<u8> {
    let body = DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0));
    let definition = DefinitionCertificate::relation(1, body).unwrap();
    ArtifactPayload::Definition(definition).to_canonical_bytes()
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

fn chain(byte: u8) -> ArtifactChainState {
    ArtifactChainState::new(ArtifactChainDefinition::new([byte; 32]))
}

fn payload(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

fn assert_empty_chain(state: &ArtifactChainState, head: ArtifactBlockId, root: ArtifactSetRoot) {
    assert_eq!(state.head_block_id(), head);
    assert_eq!(state.artifact_dag().artifact_set_root(), root);
    assert!(state.artifact_dag().is_empty());
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
        Err(LedgerError::ProofCheck {
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
        Err(LedgerError::ArtifactIdMismatch { expected, actual })
            if expected == wrong && actual == artifact_id
    ));
    assert_eq!(dag.artifact_set_root(), empty_root);
    dag.apply_canonical_artifact_bytes_with_expected_id(bytes.clone(), artifact_id)
        .unwrap();
    let committed_root = dag.artifact_set_root();
    assert!(matches!(
        dag.apply_canonical_artifact_bytes_with_expected_id(bytes, artifact_id),
        Err(LedgerError::State {
            source: ArtifactStateError::DuplicateProof { proof_id: duplicate },
        }) if duplicate == proof_id
    ));
    assert_eq!(dag.artifact_set_root(), committed_root);
    assert_eq!(dag.len(), 1);
}

#[test]
fn block_preparation_is_scalar_and_non_mutating() {
    let state = chain(0x31);
    let bytes = axiom_artifact_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_id_for(&bytes);
    let head = state.head_block_id();
    let root = state.artifact_dag().artifact_set_root();
    let block = state.prepare_block(artifact_id).unwrap();

    assert_eq!(block.parent_block_id(), head);
    assert_eq!(block.previous_artifact_set_root(), root);
    assert_ne!(block.resulting_artifact_set_root(), root);
    assert_eq!(block.artifact_id(), artifact_id);
    assert_eq!(block.to_canonical_bytes().len(), ARTIFACT_BLOCK_BYTES);
    assert_empty_chain(&state, head, root);
}

#[test]
fn read_only_validation_is_repeatable_and_application_makes_siblings_stale() {
    let pairing = axiom_artifact_bytes(ZfcAxiom::Pairing);
    let union = axiom_artifact_bytes(ZfcAxiom::Union);
    let pairing_id = artifact_id_for(&pairing);
    let union_id = artifact_id_for(&union);
    let mut state = chain(0x32);
    let anchor = state.head_block_id();
    let empty_root = state.artifact_dag().artifact_set_root();
    let pairing_block = state.prepare_block(pairing_id).unwrap();
    let union_block = state.prepare_block(union_id).unwrap();

    assert_eq!(
        state.validate_block(&pairing_block, payload(&pairing)),
        Ok(())
    );
    assert_eq!(
        state.validate_block(&pairing_block, payload(&pairing)),
        Ok(())
    );
    assert_empty_chain(&state, anchor, empty_root);
    state
        .apply_block(&pairing_block, payload(&pairing))
        .unwrap();
    assert!(matches!(
        state.validate_block(&union_block, payload(&union)),
        Err(ArtifactBlockApplyError::ParentBlockIdMismatch {
            expected,
            actual,
        }) if expected == pairing_block.id() && actual == anchor
    ));
}

#[test]
fn block_preflight_precedence_is_flat_and_preserves_state() {
    let bytes = axiom_artifact_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_id_for(&bytes);
    let mut state = chain(0x33);
    let anchor = state.head_block_id();
    let empty_root = state.artifact_dag().artifact_set_root();
    let valid = state.prepare_block(artifact_id).unwrap();

    let wrong_parent = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0x92; 32]),
        ArtifactSetRoot::from_bytes([0x93; 32]),
        ArtifactSetRoot::from_bytes([0x94; 32]),
        artifact_id,
    );
    assert!(matches!(
        state.apply_block(&wrong_parent, payload(&[0])),
        Err(ArtifactBlockApplyError::ParentBlockIdMismatch { .. })
    ));

    let wrong_previous = ArtifactBlock::new(
        anchor,
        ArtifactSetRoot::from_bytes([0x93; 32]),
        ArtifactSetRoot::from_bytes([0x94; 32]),
        artifact_id,
    );
    assert!(matches!(
        state.apply_block(&wrong_previous, payload(&[0])),
        Err(ArtifactBlockApplyError::PreviousArtifactSetRootMismatch { expected, actual })
            if expected == empty_root && actual == ArtifactSetRoot::from_bytes([0x93; 32])
    ));

    let wrong_result = ArtifactBlock::new(
        anchor,
        empty_root,
        ArtifactSetRoot::from_bytes([0x94; 32]),
        artifact_id,
    );
    assert!(matches!(
        state.apply_block(&wrong_result, payload(&[0])),
        Err(ArtifactBlockApplyError::ResultingArtifactSetRootMismatch { .. })
    ));

    assert!(matches!(
        state.apply_block(&valid, payload(&[0])),
        Err(ArtifactBlockApplyError::Admission {
            source: LedgerError::Decode { .. },
        })
    ));
    assert_empty_chain(&state, anchor, empty_root);
}

#[test]
fn validation_and_application_return_the_same_admission_error() {
    let bytes = axiom_artifact_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_id_for(&bytes);
    let block = chain(0x34).prepare_block(artifact_id).unwrap();
    let validation = chain(0x34)
        .validate_block(&block, payload(&[0]))
        .unwrap_err();
    let application = chain(0x34).apply_block(&block, payload(&[0])).unwrap_err();
    assert_eq!(validation, application);
}

#[test]
fn two_dependent_proofs_require_two_blocks_in_dependency_order() {
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
    let mut state = chain(0x35);
    let child_first = state.prepare_block(child_id).unwrap();
    let anchor = state.head_block_id();
    let empty_root = state.artifact_dag().artifact_set_root();

    assert!(matches!(
        state.apply_block(&child_first, payload(&child)),
        Err(ArtifactBlockApplyError::Admission {
            source: LedgerError::ProofCheck {
                source: CheckError::UnknownProofReference { proof_id, .. },
            },
        }) if proof_id == parent_proof_id
    ));
    assert_empty_chain(&state, anchor, empty_root);

    let parent_block = state.prepare_block(parent_artifact_id).unwrap();
    state.apply_block(&parent_block, payload(&parent)).unwrap();
    let child_block = state.prepare_block(child_id).unwrap();
    assert_eq!(child_block.parent_block_id(), parent_block.id());
    assert_eq!(
        child_block.previous_artifact_set_root(),
        parent_block.resulting_artifact_set_root()
    );
    state.apply_block(&child_block, payload(&child)).unwrap();

    assert_eq!(state.head_block_id(), child_block.id());
    assert_eq!(state.artifact_dag().len(), 2);
    assert!(state.artifact_dag().artifact(parent_artifact_id).is_some());
    assert!(state.artifact_dag().artifact(child_id).is_some());
}

#[test]
fn block_payload_is_bound_to_the_committed_artifact_id() {
    let pairing = axiom_artifact_bytes(ZfcAxiom::Pairing);
    let union = axiom_artifact_bytes(ZfcAxiom::Union);
    let pairing_id = artifact_id_for(&pairing);
    let union_id = artifact_id_for(&union);
    let mut state = chain(0x36);
    let block = state.prepare_block(pairing_id).unwrap();
    let anchor = state.head_block_id();
    let empty_root = state.artifact_dag().artifact_set_root();

    assert!(matches!(
        state.apply_block(&block, payload(&union)),
        Err(ArtifactBlockApplyError::Admission {
            source: LedgerError::ArtifactIdMismatch { expected, actual },
        }) if expected == pairing_id && actual == union_id
    ));
    assert_empty_chain(&state, anchor, empty_root);
}

#[test]
fn selected_artifact_cannot_be_prepared_or_reapplied() {
    let bytes = axiom_artifact_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_id_for(&bytes);
    let mut state = chain(0x37);
    let block = state.prepare_block(artifact_id).unwrap();
    state.apply_block(&block, payload(&bytes)).unwrap();
    assert_eq!(
        state.prepare_block(artifact_id),
        Err(ArtifactBlockPrepareError::AlreadySelectedArtifactId { artifact_id })
    );

    let head = state.head_block_id();
    let root = state.artifact_dag().artifact_set_root();
    let duplicate = ArtifactBlock::new(
        head,
        root,
        ArtifactSetRoot::from_bytes([0x99; 32]),
        artifact_id,
    );
    let expected = ArtifactBlockApplyError::AlreadySelectedArtifactId { artifact_id };
    assert_eq!(
        state
            .validate_block(&duplicate, payload(&bytes))
            .unwrap_err(),
        expected
    );
    assert_eq!(
        state.apply_block(&duplicate, payload(&bytes)).unwrap_err(),
        expected
    );
    assert_eq!(state.head_block_id(), head);
    assert_eq!(state.artifact_dag().artifact_set_root(), root);
    assert_eq!(state.artifact_dag().len(), 1);
}

#[test]
fn proof_and_definition_share_one_order_independent_artifact_set() {
    let proof = axiom_artifact_bytes(ZfcAxiom::Pairing);
    let definition = relation_definition_bytes();
    let proof_id = artifact_id_for(&proof);
    let definition_id = artifact_id_for(&definition);
    let mut first = chain(0x38);
    let mut second = chain(0x38);

    let first_proof = first.prepare_block(proof_id).unwrap();
    first.apply_block(&first_proof, payload(&proof)).unwrap();
    let first_definition = first.prepare_block(definition_id).unwrap();
    first
        .apply_block(&first_definition, payload(&definition))
        .unwrap();

    let second_definition = second.prepare_block(definition_id).unwrap();
    second
        .apply_block(&second_definition, payload(&definition))
        .unwrap();
    let second_proof = second.prepare_block(proof_id).unwrap();
    second.apply_block(&second_proof, payload(&proof)).unwrap();

    assert_eq!(
        first.artifact_dag().artifact_set_root(),
        second.artifact_dag().artifact_set_root()
    );
    assert_ne!(first.head_block_id(), second.head_block_id());
    for artifact_id in [proof_id, definition_id] {
        assert!(first.artifact_dag().artifact(artifact_id).is_some());
        assert_eq!(
            first
                .artifact_dag()
                .artifact_set_proof(artifact_id)
                .verify(first.artifact_dag().artifact_set_root(), artifact_id),
            Ok(ArtifactSetMembership::Present)
        );
    }
}
