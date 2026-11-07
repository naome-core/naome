use super::*;
use crate::learning::tests::{MemoryStore, own_example};

#[test]
fn diagnostics_use_checked_local_training_sources_and_neutralize_seed_copies() {
    let mut state = State::fresh();
    state.accept(own_example()).unwrap();
    let mut engine = Engine::default();
    let mut io = MemoryStore::default();
    let report = state
        .finder_utility(&state.model, &[], &mut engine, &mut io)
        .unwrap()
        .unwrap();
    report.validate().unwrap();
    assert!(!report.scores.is_empty());
    assert!(report.scores.iter().all(|s| s.novelty == 0));
    assert_eq!(report.checkpoint, digest(&state.model));
    assert!(report.cpu_micros > 0);
    assert_eq!(report.gradient_passes, 2);
    let mut peer = own_example();
    peer.origin = Origin::Peer {
        artifact: "55".repeat(32),
        peer: "fixture".into(),
    };
    assert!(example(&peer, &[]).is_err());
    let mut corrupt = own_example();
    corrupt.proof_id = "55".repeat(32);
    assert!(example(&corrupt, &[]).is_err());
}

#[test]
fn no_eligible_reference_is_unavailable_not_a_negative_utility_label() {
    let state = State::fresh();
    let mut engine = Engine::default();
    let mut io = MemoryStore::default();
    assert!(
        state
            .finder_utility(&state.model, &[], &mut engine, &mut io)
            .unwrap()
            .is_none()
    );
}
