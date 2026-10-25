use super::*;
use crate::state::disk::tests::{MemoryStorage, checked_program};
use crate::{DiskCopyBudget, check_normal_form_with_state};
use naome_proof::{ProofCertificate, ProofStep};

#[test]
fn small_program_facts_share_checked_membership_and_resolve_certificate_references() {
    let proof = checked_program(false);
    let state = DiskArtifactState::new(Arc::new(MemoryStorage::default()));
    let mut registration = state.begin_program_registration(&proof).unwrap();
    assert!(!state.contains_proof(proof.manifest().proof_id()).unwrap());
    registration.advance(&proof, 1).unwrap();
    let state = registration.finish().unwrap();
    let id = proof.manifest().proof_id();
    assert!(state.contains_proof(id).unwrap());
    let normal = ProofCertificate::new(vec![ProofStep::ProofReference { proof_id: id }])
        .unwrap()
        .into_unchecked_normal_form();
    let referenced = check_normal_form_with_state(normal, &state).unwrap();
    assert_eq!(referenced.conclusion(), proof.conclusion().unwrap());
    assert_eq!(referenced.statement_id(), proof.manifest().statement_id());
}

#[test]
fn huge_conclusions_register_and_survive_bounded_context_copy_without_tree_materialization() {
    let proof = checked_program(true);
    assert!(proof.conclusion().is_none());
    let state = DiskArtifactState::new(Arc::new(MemoryStorage::default()));
    let mut registration = state.begin_program_registration(&proof).unwrap();
    registration.advance(&proof, 1).unwrap();
    assert!(!registration.complete());
    while !registration.complete() {
        registration.advance(&proof, 17).unwrap();
    }
    let state = registration.finish().unwrap();
    let id = proof.manifest().proof_id();
    assert!(state.contains_proof(id).unwrap());
    let header = state.proof_header(id).unwrap().unwrap();
    assert_eq!(header.statement_id(), proof.manifest().statement_id());
    assert!(matches!(
        state.proof_formula(header, usize::MAX),
        Err(ContextError::Limit)
    ));
    let mut copy = state.begin_copy(Arc::new(MemoryStorage::default()));
    while !copy.complete() {
        copy.advance(DiskCopyBudget {
            records: 11,
            bytes: 4096,
        })
        .unwrap();
    }
    let copied = copy.finish(&state).unwrap();
    assert_eq!(copied.snapshot_id(), state.snapshot_id());
    assert!(copied.contains_proof(id).unwrap());
    assert_eq!(
        copied.proof_header(id).unwrap().unwrap().statement_id(),
        proof.manifest().statement_id()
    );
}
