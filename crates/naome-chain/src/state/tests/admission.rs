use super::*;
use naome_ledger::profile::{Limits, Profile, TimingKind};

fn register(state: &mut LedgerState, index: u8) -> SignedOperation {
    let operation = OperationBody::Register
        .sign(state.genesis(), 1, &account(index))
        .unwrap();
    apply(state, state.time(), vec![operation.clone()]);
    operation
}

fn rejects_unchanged(state: &LedgerState, utc: u64, operations: Vec<SignedOperation>) {
    let before = state.canonical_bytes();
    assert!(
        state
            .prepare_record(time(state, utc), operations, handoff_plan(state))
            .is_err()
    );
    assert_eq!(state.canonical_bytes(), before);
}

#[test]
fn registration_is_zero_starting_nonce_bound_and_idempotent_without_validator_rights() {
    let mut state = LedgerState::new(genesis());
    let first = register(&mut state, 6);
    assert_eq!(state.accounts().len(), 7);
    assert_eq!(
        state.account_key(author(6)),
        Some(account(6).verifying_key().as_bytes())
    );
    assert_eq!(state.balances().account(author(6)), Some(0));
    assert_eq!(state.next_nonce(author(6)), Some(2));
    assert_eq!(state.receipt(first.id()).unwrap().nonce, 1);
    assert_eq!(state.balances().paid_completions(), 0);
    assert!(state.claims().is_empty());
    let receipt = *state.receipt(first.id()).unwrap();
    let second = OperationBody::Register
        .sign(state.genesis(), 1, &account(7))
        .unwrap();
    // A duplicate is inert even when another operation makes this record productive.
    apply(&mut state, 100, vec![first.clone(), second]);
    assert_eq!(state.accounts().len(), 8);
    assert_eq!(*state.receipt(first.id()).unwrap(), receipt);
    assert_eq!(state.next_nonce(author(6)), Some(2));
    let duplicate_key = OperationBody::Register
        .sign(state.genesis(), 2, &account(6))
        .unwrap();
    rejects_unchanged(&state, 100, vec![duplicate_key]);
    let submission = signed(
        &state,
        6,
        OperationBody::Submit {
            purpose: "new researcher target".into(),
            question: question(&state, "forall(x,equal(x,x))"),
        },
    );
    apply(&mut state, 100, vec![submission]);
    apply(&mut state, 100, vec![]);
    let active = state.active().unwrap();
    let vote = signed(
        &state,
        6,
        OperationBody::Vote {
            question: active.question,
            attempt: active.number,
            yes: true,
        },
    );
    rejects_unchanged(&state, 100, vec![vote]);
    assert_eq!(state.genesis().validators().len(), 4);
    assert!(
        !state
            .genesis()
            .validators()
            .iter()
            .any(|v| v.owner == author(6))
    );
}

#[test]
fn unregistered_actions_wrong_registration_nonce_and_validator_role_keys_are_rejected() {
    let state = LedgerState::new(genesis());
    let operation = OperationBody::Submit {
        purpose: "not yet registered".into(),
        question: question(&state, "forall(x,equal(x,x))"),
    }
    .sign(state.genesis(), 1, &account(6))
    .unwrap();
    rejects_unchanged(&state, 100, vec![operation]);
    for key in [
        account(6),
        validator(0),
        ed25519_dalek::SigningKey::from_bytes(&[201; 32]),
    ] {
        let nonce = if key.verifying_key() == account(6).verifying_key() {
            2
        } else {
            1
        };
        let operation = OperationBody::Register
            .sign(state.genesis(), nonce, &key)
            .unwrap();
        rejects_unchanged(&state, 100, vec![operation]);
    }
    let genesis_key = OperationBody::Register
        .sign(state.genesis(), 1, &account(0))
        .unwrap();
    rejects_unchanged(&state, 100, vec![genesis_key]);
}

#[test]
fn full_registry_preserves_existing_research_and_rejects_new_keys_atomically() {
    let profile = Profile::with_limits(
        TimingKind::ShortTest,
        Limits {
            genesis_accounts: 6,
            registered_accounts: 7,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut state = LedgerState::new(super::super::test_support::genesis_with_profile(profile));
    let batch = (6..8)
        .map(|i| {
            OperationBody::Register
                .sign(state.genesis(), 1, &account(i))
                .unwrap()
        })
        .collect();
    rejects_unchanged(&state, 100, batch);
    assert_eq!(state.accounts().len(), 6);
    register(&mut state, 6);
    assert!(!state.registration_available());
    let extra = OperationBody::Register
        .sign(state.genesis(), 1, &account(7))
        .unwrap();
    rejects_unchanged(&state, 100, vec![extra]);
    assert_eq!(state.next_nonce(author(7)), None);
    assert_eq!(state.balances().account(author(7)), None);
    submit(&mut state, "forall(x,equal(x,x))");
    let round = open_and_approve(&mut state);
    let original = commit_original(&mut state, 6, round, [6; 32]);
    start_reveal(&mut state);
    let reveal = signed(
        &state,
        6,
        OperationBody::Reveal {
            round,
            secret: [6; 32],
            original,
        },
    );
    let now = state.time();
    apply(&mut state, now, vec![reveal]);
    finish(&mut state);
    assert_eq!(state.balances().account(author(6)), Some(700_000_000));
    assert_eq!(state.accounts().len(), 7);
    state
        .balances()
        .verify_conservation(state.genesis(), state.accounts())
        .unwrap();
    let FamilyResult::Completed {
        normalization_receipt,
        ..
    } = state.families().values().next().unwrap()
    else {
        panic!("completion")
    };
    let receipt = naome_ledger::receipt::NormalizationReceipt::decode_recorded(
        normalization_receipt,
        state.genesis(),
    )
    .unwrap();
    assert_eq!(receipt.author, author(6));
}

#[test]
fn registration_and_first_submission_apply_atomically_in_operation_order() {
    let mut state = LedgerState::new(genesis());
    let registration = OperationBody::Register
        .sign(state.genesis(), 1, &account(6))
        .unwrap();
    let submission = OperationBody::Submit {
        purpose: "register before submitting".into(),
        question: question(&state, "forall(x,equal(x,x))"),
    }
    .sign(state.genesis(), 2, &account(6))
    .unwrap();
    rejects_unchanged(&state, 100, vec![submission.clone(), registration.clone()]);
    assert_eq!(state.accounts().len(), 6);
    let id = submission.id();
    apply(&mut state, 100, vec![registration, submission]);
    assert_eq!(state.next_nonce(author(6)), Some(3));
    assert_eq!(state.question(id).unwrap().author(), author(6));
    assert_eq!(state.receipt(id).unwrap().coordinate.operation_index, 1);
    assert_eq!(state.balances().account(author(6)), Some(0));
}

#[test]
fn additional_registered_accounts_do_not_expand_attempt_commitment_capacity() {
    let mut state = LedgerState::new(genesis());
    let registrations = (6..18)
        .map(|i| {
            OperationBody::Register
                .sign(state.genesis(), 1, &account(i))
                .unwrap()
        })
        .collect();
    apply(&mut state, 100, registrations);
    assert_eq!(state.accounts().len(), 18);
    submit(&mut state, "forall(x,equal(x,x))");
    let round = open_and_approve(&mut state);
    let commitments = (0..16)
        .map(|i| {
            signed(
                &state,
                i,
                OperationBody::Commit {
                    round,
                    commitment: CommitmentId::from_bytes([i; 32]),
                },
            )
        })
        .collect();
    let now = state.time();
    apply(&mut state, now, commitments);
    assert_eq!(state.active().unwrap().commitments, 16);
    let extra = signed(
        &state,
        16,
        OperationBody::Commit {
            round,
            commitment: CommitmentId::from_bytes([16; 32]),
        },
    );
    rejects_unchanged(&state, now, vec![extra]);
    assert_eq!(state.next_nonce(author(16)), Some(2));
}

#[test]
fn registration_cannot_ride_on_reserved_progress_or_automatic_opening() {
    let mut state = LedgerState::new(genesis());
    submit(&mut state, "forall(x,equal(x,x))");
    let registration = OperationBody::Register
        .sign(state.genesis(), 1, &account(6))
        .unwrap();
    rejects_unchanged(&state, 100, vec![registration.clone()]); // automatic opening
    apply(&mut state, 100, vec![]);
    let active = state.active().unwrap();
    let vote = signed(
        &state,
        0,
        OperationBody::Vote {
            question: active.question,
            attempt: active.number,
            yes: true,
        },
    );
    rejects_unchanged(&state, 100, vec![registration.clone(), vote.clone()]);
    rejects_unchanged(&state, active.deadline.unwrap(), vec![registration.clone()]);
    let reserved = state.reserved_records();
    apply(&mut state, 100, vec![registration]); // ordinary capacity while attempt waits
    assert_eq!(state.reserved_records(), reserved);
    apply(&mut state, 100, vec![vote]);
    assert_eq!(state.reserved_records(), reserved - 1);
}

#[test]
fn registration_respects_exhausted_ordinary_capacity_and_terminal_run() {
    let profile = Profile::with_limits(
        TimingKind::ShortTest,
        Limits {
            run_records: 66,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut state = LedgerState::new(super::super::test_support::genesis_with_profile(profile));
    submit(&mut state, "forall(x,equal(x,x))");
    apply(&mut state, 100, vec![]);
    assert_eq!(state.remaining_records(), state.reserved_records() + 1);
    assert!(!state.registration_available());
    let operation = OperationBody::Register
        .sign(state.genesis(), 1, &account(6))
        .unwrap();
    rejects_unchanged(&state, 100, vec![operation.clone()]);
    let active = state.active().unwrap();
    apply(&mut state, active.deadline.unwrap(), vec![]); // not approved, reservation released
    rejects_unchanged(&state, state.time(), vec![operation.clone()]); // terminal boundary
    let now = state.time();
    apply(&mut state, now, vec![]);
    assert!(state.terminated());
    rejects_unchanged(&state, now, vec![operation]);
    assert_eq!(state.next_nonce(author(6)), None);
}
