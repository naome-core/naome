use super::super::maps;
use super::super::tests::{MemoryStorage, register_axiom};
use super::*;
use crate::ContextView;
use naome_foundation::ZfcAxiom;
use naome_proof::{ProofCertificate, ProofStep};
use std::{collections::BTreeSet, sync::Arc};

#[test]
fn pending_frontier_matches_full_copy_including_formulas_and_nested_buckets() {
    let storage = Arc::new(MemoryStorage::default());
    let mut state = DiskArtifactState::new(storage.clone());
    let _ = register_axiom(&mut state, ZfcAxiom::Pairing);
    let old = Arc::new(MemoryStorage::default());
    let _ = state.copy_to(old.clone()).unwrap();
    let materialized = old
        .bytes
        .lock()
        .unwrap()
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    let _ = register_axiom(&mut state, ZfcAxiom::Union);
    let implication = crate::normalize_and_check(
        ProofCertificate::new(vec![ProofStep::Simplification {
            antecedent: ZfcAxiom::Pairing.formula().into(),
            consequent: ZfcAxiom::Union.formula().into(),
        }])
        .unwrap(),
    )
    .unwrap();
    state.register_proof_for_replication(implication).unwrap();
    let x = naome_foundation::FreeVariable::new(0);
    let definition =
        naome_proof::DefinitionCertificate::relation(1, naome_proof::DefinedFormula::equal(x, x))
            .unwrap();
    state
        .register_definition(crate::check_definition_with_state(definition, &state).unwrap())
        .unwrap();
    assert!(maps(&state)[..9].iter().all(|map| map.root().is_some()));
    let complete = Arc::new(MemoryStorage::default());
    let copied = state.copy_to(complete.clone()).unwrap();
    let expected = complete
        .bytes
        .lock()
        .unwrap()
        .keys()
        .filter(|id| !materialized.contains(*id))
        .copied()
        .collect::<BTreeSet<_>>();
    let mut visited = BTreeSet::new();
    storage.reads.lock().unwrap().clear();
    state
        .visit_pending_records(|id| {
            if materialized.contains(&id) {
                return Ok(false);
            }
            visited.insert(id);
            Ok(true)
        })
        .unwrap();
    assert_eq!(visited, expected);
    assert!(!visited.is_empty());
    assert_eq!(state.snapshot_id(), copied.snapshot_id());
    assert!(
        materialized
            .iter()
            .all(|id| !storage.reads.lock().unwrap().contains_key(id))
    );
}

#[test]
fn buffered_corruption_and_failed_selection_cannot_complete_a_frontier() {
    let storage = Arc::new(MemoryStorage::default());
    let mut state = DiskArtifactState::new(storage.clone());
    let _ = register_axiom(&mut state, ZfcAxiom::Pairing);
    assert!(
        state
            .visit_pending_records(|_| Err(ContextError::Limit))
            .is_err()
    );
    let address = maps(&state)[0].root().unwrap().address;
    storage.bytes.lock().unwrap().get_mut(&address).unwrap()[0] ^= 1;
    assert!(state.visit_pending_records(|_| Ok(true)).is_err());
    assert!(!storage.failures.lock().unwrap().is_empty());
}

#[test]
fn fully_materialized_roots_need_no_record_reads() {
    let storage = Arc::new(MemoryStorage::default());
    let mut state = DiskArtifactState::new(storage.clone());
    let _ = register_axiom(&mut state, ZfcAxiom::Pairing);
    storage.reads.lock().unwrap().clear();
    state.visit_pending_records(|_| Ok(false)).unwrap();
    assert!(storage.reads.lock().unwrap().is_empty());
}
