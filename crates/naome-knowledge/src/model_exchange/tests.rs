use super::*;
use crate::model_exchange::plan::{self, Lane};

fn peer(seed: u8) -> libp2p::identity::Keypair {
    libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap()
}

fn solver(seed: u64) -> Registration {
    Registration::new(Model::Solver {
        checkpoint: Checkpoint {
            seed,
            ..Checkpoint::fresh()
        },
    })
}

fn challenge(nonce: u8, local: Registration, remote: Registration) -> Challenge {
    Challenge::new(
        [nonce; 32],
        &peer(1),
        peer(2).public().to_peer_id(),
        local,
        remote,
    )
    .unwrap()
}

fn bundle(registration: Registration, parts: Vec<Vec<u8>>) -> Bundle {
    let memory = Bundle::reserve(&registration).unwrap();
    Bundle::new(registration, parts, memory).unwrap()
}

#[test]
fn draws_are_reproducible_distinct_and_held_out() {
    let local = finder(3);
    let remote = finder(4);
    let challenge = challenge(0xcd, local.registration, remote.registration);
    let mut seen = std::collections::BTreeSet::new();
    for index in [0, 1, 2, 3, 10, 100, 1000, u64::MAX] {
        for lane in [Lane::Calibration, Lane::Score] {
            let block = plan::block(&challenge, index, lane).unwrap();
            assert_eq!(block.len(), 3);
            for (family, same) in block
                .iter()
                .zip(plan::block(&challenge, index, lane).unwrap())
            {
                assert_eq!(family.candidates.len(), 3);
                for (task, duplicate) in family.candidates.iter().zip(same.candidates) {
                    assert_eq!(task.resolution_id(), duplicate.resolution_id());
                    assert!(
                        seen.insert(*task.resolution_id()),
                        "duplicate task {}",
                        task.source()
                    );
                    assert!(reserved(task));
                    assert!(!crate::learning::State::eligible(task.source()));
                }
            }
        }
    }
}

fn finder(seed: u64) -> Bundle {
    let model = crate::frontier::RankingModel::seeded(seed);
    let (checkpoint, bytes) = encode_finder(&model).unwrap();
    bundle(Registration::new(Model::Finder { checkpoint }), vec![bytes])
}

#[test]
fn changed_registration_budget_and_artifact_bytes_are_rejected() {
    let honest = finder(3);
    let other = finder(4);
    let mut scope = challenge(
        0xcd,
        honest.registration.clone(),
        other.registration.clone(),
    );
    scope.local = other.registration.clone();
    assert!(scope.validate().unwrap_err().contains("signature"));
    let mut reference = honest.registration.clone();
    reference.reference = "00".repeat(32);
    assert!(reference.validate().unwrap_err().contains("reference"));
    assert!(
        Challenge::new(
            [0xcd; 32],
            &peer(1),
            peer(2).public().to_peer_id(),
            honest.registration.clone(),
            solver(2)
        )
        .is_err()
    );
    let blocked_adam = Registration::new(Model::Solver {
        checkpoint: Checkpoint {
            updates: u64::MAX,
            model: Some(Blob::of(b"model")),
            optimizer: Some(Blob::of(b"optimizer")),
            ..Checkpoint::fresh()
        },
    });
    assert!(
        blocked_adam
            .validate()
            .unwrap_err()
            .contains("update count")
    );
    let mut tampered = honest.parts().next().unwrap().to_vec();
    tampered[0] ^= 1;
    let memory = Bundle::reserve(&honest.registration).unwrap();
    assert!(Bundle::new(honest.registration, vec![tampered], memory).is_err());
    assert_eq!(
        protocol::decode(&protocol::encode(b"abc"), 3).unwrap(),
        b"abc"
    );
    assert!(protocol::decode("YWJ=", 3).is_err());
}

#[cfg(feature = "system-tests")]
#[test]
fn independent_nodes_replay_scored_proofs_and_reject_copied_receipts() {
    use super::{bundle::Artifacts, replay::Extension};
    // Peers A and B freeze separately initialized native checkpoints. A third
    // node receives the signed scope and runs it using newly opened engines.
    let local = bundle(solver(1), vec![]);
    let remote = bundle(solver(2), vec![]);
    let scope = challenge(
        0xcd,
        local.registration.clone(),
        remote.registration.clone(),
    );
    let receipt = replay::replay(scope.clone(), None, &mut Artifacts(&local, &remote)).unwrap();
    assert_eq!(receipt.blocks, 2, "{receipt:?}");
    assert_eq!(receipt.extension, Extension::Eligible);
    assert!(receipt.remote > receipt.local, "{receipt:?}");

    let auditor_local = bundle(solver(1), vec![]);
    let auditor_remote = bundle(solver(2), vec![]);
    let audited = replay::replay(
        scope.clone(),
        None,
        &mut Artifacts(&auditor_local, &auditor_remote),
    )
    .unwrap();
    assert_eq!(audited, receipt);
    assert_eq!(audited.audit_against(&receipt), Ok(true));

    let mut copied = receipt.clone();
    copied.transcript = "00".repeat(32);
    assert!(audited.audit_against(&copied).is_err());
    let mut inflated = receipt.clone();
    inflated.local = inflated.blocks * 3 + 1;
    assert!(inflated.validate().is_err());
    let fresh = challenge(
        0xab,
        local.registration.clone(),
        remote.registration.clone(),
    );
    copied.challenge = fresh.clone();
    assert!(audited.audit_against(&copied).is_err());
    assert!(replay::replay(fresh, Some(&receipt), &mut Artifacts(&local, &remote)).is_err());

    let tied = challenge(0x89, local.registration.clone(), local.registration.clone());
    let retained = replay::replay(tied.clone(), None, &mut Artifacts(&local, &local)).unwrap();
    assert_eq!(retained.blocks, 1);
    assert_eq!(retained.local, retained.remote);
    assert_eq!(retained.extension, Extension::NoCalibration);
    assert_eq!(
        replay::replay(tied, Some(&retained), &mut Artifacts(&local, &local)).unwrap(),
        retained
    );
}
