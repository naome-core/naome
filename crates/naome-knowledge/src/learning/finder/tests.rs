use super::*;
use crate::learning::tests::{MemoryStore, binary_program, own_example};

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
    assert_eq!(
        example(&peer, &[]).unwrap_err(),
        crate::ResearchFailure::FinderExampleEligibility.into()
    );
    let mut corrupt = own_example();
    corrupt.proof_id = "55".repeat(32);
    assert_eq!(
        example(&corrupt, &[]).unwrap_err(),
        crate::ResearchFailure::FinderProofIdentity.into()
    );
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

#[test]
fn checked_native_programs_supply_finder_utility_from_the_owned_trace() {
    const TEST: &str = "learning::finder::tests::checked_native_programs_supply_finder_utility_from_the_owned_trace";
    if std::env::var_os("NAOME_NATIVE_FINDER_UTILITY_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_NATIVE_FINDER_UTILITY_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }

    let (question, packet) = binary_program(&[], naome_foundation::ZfcAxiom::Pairing);
    let proof_id = crate::hex(packet.manifest.proof_id().as_bytes());
    let source = Example {
        origin: Origin::Local,
        job: 7,
        question,
        proof_id: proof_id.clone(),
        refuted: false,
        tree: search::Tree::Program(Box::new(packet)),
    };
    let evidence = [Evidence {
        job: source.job,
        proof_id: proof_id.clone(),
        trace: source.tree.clone(),
    }];
    let mut state = State::fresh();
    assert!(state.accept(source).unwrap());
    assert_eq!(state.replay[0].evidence_job(), Some(7));
    std::thread::spawn(move || {
        let report = state
            .finder_utility(
                &state.model,
                &evidence,
                &mut Engine::default(),
                &mut MemoryStore::default(),
            )
            .unwrap()
            .unwrap();
        report.validate().unwrap();
        assert_eq!(
            report.references.as_slice(),
            std::slice::from_ref(&proof_id)
        );
        assert_eq!(report.scores[0].proof, proof_id);
        assert_eq!(report.gradient_passes, 2);

        let mut corrupt = evidence;
        corrupt[0].trace = own_example().tree;
        assert!(example(&state.replay[0], &corrupt).is_err());
    })
    .join()
    .unwrap();
}
