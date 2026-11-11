use super::*;
use crate::state::disk::tests::{MemoryStorage, checked_program};
use crate::{DiskCopyBudget, check_normal_form_with_state};
use naome_proof::{ProofCertificate, ProofStep};

#[test]
fn program_node_reads_reject_canonical_bytes_under_the_wrong_address() {
    use naome_foundation::graph::{Node, Properties, Variable};
    use naome_proof::program::{graph_node_bytes, graph_node_hash};

    let storage = Arc::new(MemoryStorage::default());
    let mut map = DiskMap::new(storage.clone());
    let node = Node::Equal(Variable::Free(0), Variable::Free(1));
    let properties = Properties {
        has_free_variables: true,
        required_binders: 0,
    };
    let bytes = graph_node_bytes(node, properties);
    let address = graph_node_hash(node, properties);
    let mut wrong_address = address;
    wrong_address[0] ^= 1;
    assert!(map.insert(address, &bytes).unwrap());
    assert!(map.insert(wrong_address, &bytes).unwrap());
    let nodes = ProgramNodes(map);

    assert_eq!(
        crate::context::ProgramNodes::read(&nodes, address).unwrap(),
        (node, properties)
    );
    assert!(matches!(
        crate::context::ProgramNodes::read(&nodes, wrong_address),
        Err(ContextError::Corrupt)
    ));
    assert_eq!(*storage.failures.lock().unwrap(), [ContextError::Corrupt]);
}

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
fn program_registration_reads_dependency_identity_and_depth_together() {
    use crate::program::Engine;
    use crate::state::disk::tests::register_axiom;
    use naome_foundation::ZfcAxiom;
    use naome_proof::program::Command;
    use rusqlite::Connection;

    let storage = Arc::new(MemoryStorage::default());
    let mut state = DiskArtifactState::new(storage.clone());
    let (parent, _, _) = register_axiom(&mut state, ZfcAxiom::Pairing);
    let parent_address = state.proofs.root().unwrap().address;
    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    engine
        .append_group(&[
            Command::ProofReference {
                proof_id: *parent.as_bytes(),
            },
            Command::Seal { proof: 0 },
        ])
        .unwrap();
    while engine.advance(16, 4096, &state).unwrap() {}
    while !engine.prepare_export(16).unwrap() {}
    let proof = engine.checked().unwrap();
    assert!(proof.conclusion().is_some());

    let mut registration = state.begin_program_registration(&proof).unwrap();
    storage.reads.lock().unwrap().clear();
    registration.advance(&proof, 1).unwrap();
    assert_eq!(storage.reads.lock().unwrap().get(&parent_address), Some(&1));
    while !registration.complete() {
        registration.advance(&proof, 1).unwrap();
    }
    let registered = registration.finish().unwrap();
    assert_eq!(
        registered.proof_dependency_depth(proof.manifest().proof_id()),
        Ok(Some(2))
    );
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
