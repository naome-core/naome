use naome_checker::{CheckError, ProofStateError};
use naome_foundation::{FreeVariable, ZfcAxiom};
use naome_ledger::LedgerError;
use naome_proof::{ProofCertificate, ProofId, ProofStep};

use super::{
    PROOF_BLOCK_BYTES, ProofBlock, ProofBlockApplyError, ProofBlockId, ProofBlockPrepareError,
    ProofChainDefinition, ProofChainState, ProofDag, ProofSetMembership, ProofSetRoot,
};

fn canonical_bytes(steps: Vec<ProofStep>) -> Vec<u8> {
    ProofCertificate::new(steps)
        .unwrap()
        .into_unchecked_normal_form()
        .canonical_bytes()
        .to_vec()
}

fn axiom_bytes(axiom: ZfcAxiom) -> Vec<u8> {
    canonical_bytes(vec![ProofStep::ZfcAxiom(axiom)])
}

fn referenced_generalization(proof_id: ProofId, variable: u32) -> Vec<u8> {
    canonical_bytes(vec![
        ProofStep::ProofReference { proof_id },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(variable),
        },
    ])
}

fn proof_id_for(bytes: &[u8]) -> ProofId {
    ProofDag::new()
        .apply_canonical_proof_bytes(bytes.to_vec())
        .unwrap()
        .proof_id()
}

fn chain(byte: u8) -> ProofChainState {
    ProofChainState::new(ProofChainDefinition::new([byte; 32]))
}

fn payload(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

fn assert_empty_chain(state: &ProofChainState, head: ProofBlockId, root: ProofSetRoot) {
    assert_eq!(state.head_block_id(), head);
    assert_eq!(state.proof_dag().proof_set_root(), root);
    assert!(state.proof_dag().is_empty());
}

#[test]
fn independent_proofs_form_an_authenticated_order_independent_set() {
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let pairing_id = proof_id_for(&pairing);
    let union_id = proof_id_for(&union);
    let mut first = ProofDag::new();
    first.apply_canonical_proof_bytes(pairing.clone()).unwrap();
    first.apply_canonical_proof_bytes(union.clone()).unwrap();
    let mut second = ProofDag::new();
    second.apply_canonical_proof_bytes(union).unwrap();
    second.apply_canonical_proof_bytes(pairing).unwrap();

    assert_eq!(first.proof_set_root(), second.proof_set_root());
    assert_eq!(first.len(), 2);
    for proof_id in [pairing_id, union_id] {
        assert_eq!(
            first
                .proof_set_proof(proof_id)
                .verify(first.proof_set_root(), proof_id),
            Ok(ProofSetMembership::Present)
        );
    }
}

#[test]
fn dependencies_must_be_selected_before_single_proof_admission() {
    let parent = axiom_bytes(ZfcAxiom::Pairing);
    let parent_id = proof_id_for(&parent);
    let child = referenced_generalization(parent_id, 7);
    let child_id = {
        let mut scratch = ProofDag::new();
        scratch.apply_canonical_proof_bytes(parent.clone()).unwrap();
        scratch
            .apply_canonical_proof_bytes(child.clone())
            .unwrap()
            .proof_id()
    };
    let mut dag = ProofDag::new();
    let empty_root = dag.proof_set_root();

    assert!(matches!(
        dag.apply_canonical_proof_bytes_with_expected_id(child.clone(), child_id),
        Err(LedgerError::Check {
            source: CheckError::UnknownProofReference { proof_id, .. },
        }) if proof_id == parent_id
    ));
    assert_eq!(dag.proof_set_root(), empty_root);
    dag.apply_canonical_proof_bytes_with_expected_id(parent, parent_id)
        .unwrap();
    dag.apply_canonical_proof_bytes_with_expected_id(child, child_id)
        .unwrap();
    assert_eq!(dag.len(), 2);
}

#[test]
fn expected_address_and_duplicate_failures_never_mutate_the_dag() {
    let bytes = axiom_bytes(ZfcAxiom::Pairing);
    let proof_id = proof_id_for(&bytes);
    let wrong = ProofId::from_bytes([0x55; 32]);
    let mut dag = ProofDag::new();
    let empty_root = dag.proof_set_root();

    assert!(matches!(
        dag.apply_canonical_proof_bytes_with_expected_id(bytes.clone(), wrong),
        Err(LedgerError::ProofIdMismatch { expected, actual })
            if expected == wrong && actual == proof_id
    ));
    assert_eq!(dag.proof_set_root(), empty_root);
    dag.apply_canonical_proof_bytes_with_expected_id(bytes.clone(), proof_id)
        .unwrap();
    let committed_root = dag.proof_set_root();
    assert!(matches!(
        dag.apply_canonical_proof_bytes_with_expected_id(bytes, proof_id),
        Err(LedgerError::State {
            source: ProofStateError::DuplicateProof { .. },
        })
    ));
    assert_eq!(dag.proof_set_root(), committed_root);
    assert_eq!(dag.len(), 1);
}

#[test]
fn block_preparation_is_scalar_and_non_mutating() {
    let state = chain(0x31);
    let bytes = axiom_bytes(ZfcAxiom::Pairing);
    let proof_id = proof_id_for(&bytes);
    let head = state.head_block_id();
    let root = state.proof_dag().proof_set_root();
    let block = state.prepare_block(proof_id).unwrap();

    assert_eq!(block.parent_block_id(), head);
    assert_eq!(block.previous_proof_set_root(), root);
    assert_ne!(block.resulting_proof_set_root(), root);
    assert_eq!(block.proof_id(), proof_id);
    assert_eq!(block.to_canonical_bytes().len(), PROOF_BLOCK_BYTES);
    assert_empty_chain(&state, head, root);
}

#[test]
fn read_only_validation_is_repeatable_and_application_makes_siblings_stale() {
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let pairing_id = proof_id_for(&pairing);
    let union_id = proof_id_for(&union);
    let mut state = chain(0x32);
    let anchor = state.head_block_id();
    let empty_root = state.proof_dag().proof_set_root();
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
        Err(ProofBlockApplyError::ParentBlockIdMismatch {
            expected,
            actual,
        }) if expected == pairing_block.id() && actual == anchor
    ));
}

#[test]
fn block_preflight_precedence_is_flat_and_preserves_state() {
    let bytes = axiom_bytes(ZfcAxiom::Pairing);
    let proof_id = proof_id_for(&bytes);
    let mut state = chain(0x33);
    let anchor = state.head_block_id();
    let empty_root = state.proof_dag().proof_set_root();
    let valid = state.prepare_block(proof_id).unwrap();

    let wrong_parent = ProofBlock::new(
        ProofBlockId::from_bytes([0x92; 32]),
        ProofSetRoot::from_bytes([0x93; 32]),
        ProofSetRoot::from_bytes([0x94; 32]),
        proof_id,
    );
    assert!(matches!(
        state.apply_block(&wrong_parent, payload(&[0])),
        Err(ProofBlockApplyError::ParentBlockIdMismatch { .. })
    ));

    let wrong_previous = ProofBlock::new(
        anchor,
        ProofSetRoot::from_bytes([0x93; 32]),
        ProofSetRoot::from_bytes([0x94; 32]),
        proof_id,
    );
    assert!(matches!(
        state.apply_block(&wrong_previous, payload(&[0])),
        Err(ProofBlockApplyError::PreviousProofSetRootMismatch { expected, actual })
            if expected == empty_root && actual == ProofSetRoot::from_bytes([0x93; 32])
    ));

    let wrong_result = ProofBlock::new(
        anchor,
        empty_root,
        ProofSetRoot::from_bytes([0x94; 32]),
        proof_id,
    );
    assert!(matches!(
        state.apply_block(&wrong_result, payload(&[0])),
        Err(ProofBlockApplyError::ResultingProofSetRootMismatch { .. })
    ));

    assert!(matches!(
        state.apply_block(&valid, payload(&[0])),
        Err(ProofBlockApplyError::Admission {
            source: LedgerError::Decode { .. },
        })
    ));
    assert_empty_chain(&state, anchor, empty_root);
}

#[test]
fn validation_and_application_return_the_same_admission_error() {
    let bytes = axiom_bytes(ZfcAxiom::Pairing);
    let proof_id = proof_id_for(&bytes);
    let block = chain(0x34).prepare_block(proof_id).unwrap();
    let validation = chain(0x34)
        .validate_block(&block, payload(&[0]))
        .unwrap_err();
    let application = chain(0x34).apply_block(&block, payload(&[0])).unwrap_err();
    assert_eq!(validation, application);
}

#[test]
fn two_dependent_proofs_require_two_blocks_in_dependency_order() {
    let parent = axiom_bytes(ZfcAxiom::Pairing);
    let parent_id = proof_id_for(&parent);
    let child = referenced_generalization(parent_id, 7);
    let child_id = {
        let mut scratch = ProofDag::new();
        scratch.apply_canonical_proof_bytes(parent.clone()).unwrap();
        scratch
            .apply_canonical_proof_bytes(child.clone())
            .unwrap()
            .proof_id()
    };
    let mut state = chain(0x35);
    let child_first = state.prepare_block(child_id).unwrap();
    let anchor = state.head_block_id();
    let empty_root = state.proof_dag().proof_set_root();

    assert!(matches!(
        state.apply_block(&child_first, payload(&child)),
        Err(ProofBlockApplyError::Admission {
            source: LedgerError::Check {
                source: CheckError::UnknownProofReference { proof_id, .. },
            },
        }) if proof_id == parent_id
    ));
    assert_empty_chain(&state, anchor, empty_root);

    let parent_block = state.prepare_block(parent_id).unwrap();
    state.apply_block(&parent_block, payload(&parent)).unwrap();
    let child_block = state.prepare_block(child_id).unwrap();
    assert_eq!(child_block.parent_block_id(), parent_block.id());
    assert_eq!(
        child_block.previous_proof_set_root(),
        parent_block.resulting_proof_set_root()
    );
    state.apply_block(&child_block, payload(&child)).unwrap();

    assert_eq!(state.head_block_id(), child_block.id());
    assert_eq!(state.proof_dag().len(), 2);
    assert!(state.proof_dag().proof(parent_id).is_some());
    assert!(state.proof_dag().proof(child_id).is_some());
}

#[test]
fn block_payload_is_bound_to_the_committed_proof_id() {
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let pairing_id = proof_id_for(&pairing);
    let union_id = proof_id_for(&union);
    let mut state = chain(0x36);
    let block = state.prepare_block(pairing_id).unwrap();
    let anchor = state.head_block_id();
    let empty_root = state.proof_dag().proof_set_root();

    assert!(matches!(
        state.apply_block(&block, payload(&union)),
        Err(ProofBlockApplyError::Admission {
            source: LedgerError::ProofIdMismatch { expected, actual },
        }) if expected == pairing_id && actual == union_id
    ));
    assert_empty_chain(&state, anchor, empty_root);
}

#[test]
fn selected_proof_cannot_be_prepared_or_reapplied() {
    let bytes = axiom_bytes(ZfcAxiom::Pairing);
    let proof_id = proof_id_for(&bytes);
    let mut state = chain(0x37);
    let block = state.prepare_block(proof_id).unwrap();
    state.apply_block(&block, payload(&bytes)).unwrap();
    assert_eq!(
        state.prepare_block(proof_id),
        Err(ProofBlockPrepareError::AlreadySelectedProofId { proof_id })
    );

    let head = state.head_block_id();
    let root = state.proof_dag().proof_set_root();
    let duplicate = ProofBlock::new(head, root, ProofSetRoot::from_bytes([0x99; 32]), proof_id);
    let expected = ProofBlockApplyError::AlreadySelectedProofId { proof_id };
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
    assert_eq!(state.proof_dag().proof_set_root(), root);
    assert_eq!(state.proof_dag().len(), 1);
}

#[test]
fn equal_final_proof_sets_from_different_block_orders_have_distinct_heads() {
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let pairing_id = proof_id_for(&pairing);
    let union_id = proof_id_for(&union);
    let mut first = chain(0x38);
    let mut second = chain(0x38);

    let first_pairing = first.prepare_block(pairing_id).unwrap();
    first
        .apply_block(&first_pairing, payload(&pairing))
        .unwrap();
    let first_union = first.prepare_block(union_id).unwrap();
    first.apply_block(&first_union, payload(&union)).unwrap();

    let second_union = second.prepare_block(union_id).unwrap();
    second.apply_block(&second_union, payload(&union)).unwrap();
    let second_pairing = second.prepare_block(pairing_id).unwrap();
    second
        .apply_block(&second_pairing, payload(&pairing))
        .unwrap();

    assert_eq!(
        first.proof_dag().proof_set_root(),
        second.proof_dag().proof_set_root()
    );
    assert_ne!(first.head_block_id(), second.head_block_id());
}
