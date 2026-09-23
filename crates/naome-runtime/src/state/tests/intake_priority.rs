use super::registration::{finalize, prepare, registration_runtime};
use super::*;
use naome_ledger::{
    CommitmentId, SolutionRoundId, library::ProofPackage, operations::SignedOriginal,
};
use naome_proof::{ProofCertificate, ProofStep};

fn author(index: u8) -> AccountId {
    AccountId::for_key(account(index).verifying_key().as_bytes())
}

fn sign(runtime: &StateRuntime, index: u8, body: OperationBody) -> SignedOperation {
    let state = runtime.state().unwrap();
    body.sign(
        state.genesis(),
        state.next_nonce(author(index)).unwrap(),
        &account(index),
    )
    .unwrap()
}

fn assert_bounded(runtime: &StateRuntime) {
    assert!(runtime.pending.len() <= MAX_PENDING_OPERATIONS);
    assert!(runtime.deferred.len() <= MAX_PENDING_OPERATIONS);
    assert_eq!(
        runtime.pending_bytes,
        runtime
            .pending
            .values()
            .map(|op| op.encode().len())
            .sum::<usize>()
    );
    assert!(
        runtime.pending_bytes
            <= 2 * runtime
                .state()
                .unwrap()
                .genesis()
                .profile()
                .limits()
                .record_bytes as usize
    );
}

fn fill_registrations(runtime: &mut StateRuntime, start: u8) -> Vec<SignedOperation> {
    let genesis = runtime.state().unwrap().genesis().clone();
    let operations: Vec<_> = (start..start + MAX_PENDING_OPERATIONS as u8)
        .map(|index| {
            OperationBody::Register
                .sign(&genesis, 1, &account(index))
                .unwrap()
        })
        .collect();
    for operation in &operations {
        runtime.submit_operation(operation.clone()).unwrap();
    }
    assert_eq!(runtime.pending_operations(), MAX_PENDING_OPERATIONS);
    assert_bounded(runtime);
    operations
}

fn start_commit(
    runtime: &mut StateRuntime,
    directory: &Directory,
    anchors: &Directory,
) -> SolutionRoundId {
    let genesis = runtime.state().unwrap().genesis().clone();
    let registrations = (6..22)
        .map(|index| {
            OperationBody::Register
                .sign(&genesis, 1, &account(index))
                .unwrap()
        })
        .collect();
    finalize(runtime, directory, anchors, 101, registrations);
    finalize(
        runtime,
        directory,
        anchors,
        102,
        vec![operation(&genesis, 1)],
    );
    finalize(runtime, directory, anchors, 103, vec![]);
    let active = runtime.state().unwrap().active().unwrap();
    let votes = (0..3)
        .map(|index| {
            sign(
                runtime,
                index,
                OperationBody::Vote {
                    question: active.question,
                    attempt: active.number,
                    yes: true,
                },
            )
        })
        .collect();
    finalize(runtime, directory, anchors, 104, votes);
    let deadline = active.deadline.unwrap();
    finalize(runtime, directory, anchors, deadline, vec![]);
    finalize(runtime, directory, anchors, deadline, vec![]);
    runtime
        .state()
        .unwrap()
        .active()
        .unwrap()
        .solution_round
        .unwrap()
}

fn original(runtime: &StateRuntime, index: u8, round: SolutionRoundId) -> SignedOriginal {
    let x = naome_foundation::FreeVariable::new(0);
    let proof = naome_checker::normalize_and_check(
        ProofCertificate::new(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ])
        .unwrap(),
    )
    .unwrap();
    let root = proof.proof_id();
    let genesis = runtime.state().unwrap().genesis();
    let package = ProofPackage::new(
        author(index),
        root,
        vec![(root, proof.normal_form().canonical_bytes().to_vec())],
        genesis.profile(),
    )
    .unwrap();
    SignedOriginal::sign(genesis, round, package, &account(index)).unwrap()
}

#[tokio::test]
async fn ballot_displaces_registration_and_exact_deferred_bytes_can_retry() {
    let (_directory, _anchors, mut runtime) = registration_runtime();
    let genesis = runtime.state().unwrap().genesis().clone();
    finalize(
        &mut runtime,
        &_directory,
        &_anchors,
        101,
        vec![operation(&genesis, 1)],
    );
    finalize(&mut runtime, &_directory, &_anchors, 102, vec![]);
    let registrations = fill_registrations(&mut runtime, 6);
    let active = runtime.state().unwrap().active().unwrap();
    let vote = sign(
        &runtime,
        0,
        OperationBody::Vote {
            question: active.question,
            attempt: active.number,
            yes: true,
        },
    );
    let vote_id = runtime.submit_operation(vote.clone()).unwrap();
    assert_eq!(runtime.submit_operation(vote.clone()).unwrap(), vote_id);
    assert_eq!(runtime.pending_operations(), MAX_PENDING_OPERATIONS);
    let displaced = registrations
        .iter()
        .find(|op| runtime.operation_deferred(op.id()))
        .unwrap();
    assert!(runtime.operation_rejection(displaced.id()).is_none());
    assert!(
        runtime
            .state()
            .unwrap()
            .next_nonce(displaced.author())
            .is_none()
    );
    assert!(
        runtime
            .state()
            .unwrap()
            .account_key(displaced.author())
            .is_none()
    );
    assert_eq!(runtime.state().unwrap().next_nonce(author(0)), Some(1));
    let occupied = runtime.pending.clone();
    assert!(runtime.submit_operation(displaced.clone()).is_err());
    let conflicting = sign(
        &runtime,
        0,
        OperationBody::Vote {
            question: active.question,
            attempt: active.number,
            yes: false,
        },
    );
    assert!(runtime.submit_operation(conflicting).is_err());
    assert_eq!(runtime.pending, occupied);
    assert_bounded(&runtime);
    let record = prepare(&mut runtime, 103);
    assert_eq!(record.operations(), &[vote]);
    finalize(
        &mut runtime,
        &_directory,
        &_anchors,
        103,
        record.operations().to_vec(),
    );
    assert_eq!(
        runtime.submit_operation(displaced.clone()).unwrap(),
        displaced.id()
    );
    assert!(!runtime.operation_deferred(displaced.id()));
    let record = prepare(&mut runtime, 104);
    assert_eq!(record.operations().len(), MAX_PENDING_OPERATIONS);
    let reserved = runtime.state().unwrap().reserved_records();
    finalize(
        &mut runtime,
        &_directory,
        &_anchors,
        104,
        record.operations().to_vec(),
    );
    assert_eq!(runtime.state().unwrap().reserved_records(), reserved);
    assert_eq!(
        runtime.state().unwrap().next_nonce(displaced.author()),
        Some(2)
    );
    assert_eq!(
        runtime
            .state()
            .unwrap()
            .balances()
            .account(displaced.author()),
        Some(0)
    );
    assert!(runtime.state().unwrap().receipt(vote_id).is_some());
    assert_bounded(&runtime);
}

#[tokio::test]
async fn commit_and_reserved_reveal_survive_full_ordinary_pools_and_settle() {
    let (_directory, _anchors, mut runtime) = registration_runtime();
    let round = start_commit(&mut runtime, &_directory, &_anchors);
    let genesis = runtime.state().unwrap().genesis().clone();
    let original = original(&runtime, 4, round);
    let secret = [4; 32];
    let commitment = CommitmentId::for_original(
        &genesis,
        round,
        author(4),
        original.original_hash(),
        &secret,
    );
    let mut replaced = None;
    for (depth, index) in std::iter::once(4).chain(6..21).enumerate() {
        let mut statement = "forall(x,equal(x,x))".to_owned();
        for _ in 0..=depth {
            statement = format!("forall(y,{statement})");
        }
        let body = OperationBody::Submit {
            purpose: "Future research".into(),
            question: CompiledQuestion::compile(
                &format!("foundation = \"naome:zfc\"\nstatement = {statement}"),
                genesis.profile(),
            )
            .unwrap(),
        };
        let operation = sign(&runtime, index, body);
        if index == 4 {
            replaced = Some(operation.clone());
        }
        runtime.submit_operation(operation).unwrap();
    }
    assert_eq!(runtime.pending_operations(), MAX_PENDING_OPERATIONS);
    let replaced = replaced.unwrap();
    let commit = sign(&runtime, 4, OperationBody::Commit { round, commitment });
    runtime.submit_operation(commit.clone()).unwrap();
    assert!(runtime.operation_deferred(replaced.id()));
    assert!(!runtime.pending.contains_key(&replaced.id()));
    assert_eq!(runtime.state().unwrap().next_nonce(author(4)), Some(2));
    assert_bounded(&runtime);
    let now = runtime.state().unwrap().time();
    let record = prepare(&mut runtime, now);
    assert!(record.operations().contains(&commit));
    finalize(
        &mut runtime,
        &_directory,
        &_anchors,
        now,
        record.operations().to_vec(),
    );
    assert_eq!(runtime.state().unwrap().next_nonce(author(4)), Some(3));
    assert!(!runtime.operation_deferred(replaced.id()));
    assert!(
        runtime
            .operation_rejection(replaced.id())
            .unwrap()
            .contains("nonce consumed")
    );
    assert!(runtime.submit_operation(replaced).is_err());
    let deadline = runtime.state().unwrap().active().unwrap().deadline.unwrap();
    finalize(&mut runtime, &_directory, &_anchors, deadline, vec![]);
    finalize(&mut runtime, &_directory, &_anchors, deadline, vec![]);
    assert_eq!(runtime.pending_operations(), 0);
    fill_registrations(&mut runtime, 32);
    let before = runtime.pending.clone();
    let uncommitted = sign(
        &runtime,
        5,
        OperationBody::Reveal {
            round,
            secret,
            original: self::original(&runtime, 5, round),
        },
    );
    assert!(runtime.submit_operation(uncommitted).is_err());
    let mismatched = sign(
        &runtime,
        4,
        OperationBody::Reveal {
            round,
            secret: [5; 32],
            original: original.clone(),
        },
    );
    assert!(runtime.submit_operation(mismatched).is_err());
    assert_eq!(runtime.pending, before);
    let reveal = sign(
        &runtime,
        4,
        OperationBody::Reveal {
            round,
            secret,
            original: original.clone(),
        },
    );
    runtime.submit_operation(reveal.clone()).unwrap();
    assert!(runtime.pending.contains_key(&reveal.id()));
    assert_eq!(runtime.pending_operations(), MAX_PENDING_OPERATIONS);
    assert_bounded(&runtime);
    let record = prepare(&mut runtime, deadline);
    assert_eq!(record.operations(), &[reveal]);
    finalize(
        &mut runtime,
        &_directory,
        &_anchors,
        deadline,
        record.operations().to_vec(),
    );
    let repeated = sign(
        &runtime,
        4,
        OperationBody::Reveal {
            round,
            secret,
            original,
        },
    );
    assert!(runtime.submit_operation(repeated).is_err());
    let deadline = runtime.state().unwrap().active().unwrap().deadline.unwrap();
    finalize(&mut runtime, &_directory, &_anchors, deadline, vec![]);
    finalize(&mut runtime, &_directory, &_anchors, deadline, vec![]);
    assert_eq!(runtime.state().unwrap().balances().paid_completions(), 1);
    assert_eq!(
        runtime.state().unwrap().balances().account(author(4)),
        Some(700_000_000)
    );
    assert_eq!(runtime.state().unwrap().library().len(), 1);
    assert_bounded(&runtime);
}

#[tokio::test]
async fn active_entries_are_never_evicted_when_no_ordinary_slot_can_make_room() {
    let (_directory, _anchors, mut runtime) = registration_runtime();
    let round = start_commit(&mut runtime, &_directory, &_anchors);
    for index in 6..22 {
        let commit = sign(
            &runtime,
            index,
            OperationBody::Commit {
                round,
                commitment: CommitmentId::from_bytes([index; 32]),
            },
        );
        runtime.submit_operation(commit).unwrap();
    }
    let before = runtime.pending.clone();
    let extra = sign(
        &runtime,
        5,
        OperationBody::Commit {
            round,
            commitment: CommitmentId::from_bytes([5; 32]),
        },
    );
    assert!(runtime.submit_operation(extra).is_err());
    let registration = OperationBody::Register
        .sign(runtime.state().unwrap().genesis(), 1, &account(32))
        .unwrap();
    assert!(runtime.submit_operation(registration).is_err());
    assert_eq!(runtime.pending, before);
    assert!(runtime.deferred.is_empty());
    assert_eq!(runtime.state().unwrap().next_nonce(author(5)), Some(1));
    assert_bounded(&runtime);
}
