use super::*;
use naome_ledger::profile::{Genesis, Limits, Profile, TimingKind};

#[test]
fn minimum_run_reserves_all_sixteen_authors_through_delayed_atomic_settlement() {
    let profile = Profile::with_limits(
        TimingKind::ShortTest,
        Limits {
            run_records: 66,
            ..Limits::default()
        },
    )
    .unwrap();
    let fixture = genesis();
    let genesis = Genesis::new(
        profile,
        fixture.foundation().into(),
        fixture.checker_profile().into(),
        naome_ledger::profile::STATE_PROTOCOL_VERSION,
        100,
        [19; 32],
        (0..16)
            .map(|index| account(index).verifying_key().to_bytes())
            .collect(),
        fixture.validators().to_vec(),
        fixture.retirement_order().to_vec(),
    )
    .unwrap();
    let mut state = LedgerState::new(genesis);
    assert_eq!(
        state.genesis().profile().limits().commitments_per_attempt,
        16
    );
    let submission = submit(&mut state, "forall(x,equal(x,x))");
    let now = state.time();
    apply(&mut state, now, vec![]);
    assert_eq!(state.remaining_records(), 64);
    assert_eq!(state.reserved_records(), 63);
    let active = state.active().unwrap();
    // Separate finalized records deliberately consume the full per-owner path,
    // rather than packing all votes/commitments/reveals into a single record.
    for index in 0..4 {
        let vote = signed(
            &state,
            index,
            OperationBody::Vote {
                question: active.question,
                attempt: active.number,
                yes: true,
            },
        );
        apply(&mut state, now, vec![vote]);
        assert_eq!(state.remaining_records(), state.reserved_records() + 1);
    }
    assert_eq!(state.active().unwrap().phase, Phase::Voting);
    apply(&mut state, active.deadline.unwrap(), vec![]);
    let now = state.time();
    apply(&mut state, now, vec![]);
    let round = state.active().unwrap().solution_round.unwrap();
    let mut originals = Vec::new();
    for index in (4..16).chain(0..4) {
        let secret = [index; 32];
        let original = commit_original(&mut state, index, round, secret);
        originals.push((index, secret, original));
        assert_eq!(state.remaining_records(), state.reserved_records() + 1);
        assert!(state.library().is_empty());
    }
    assert_eq!(state.active().unwrap().commitments, 16);
    let excess = signed(
        &state,
        4,
        OperationBody::Commit {
            round,
            commitment: CommitmentId::from_bytes([99; 32]),
        },
    );
    let before = state.commitment();
    let nonce = state.next_nonce(author(4));
    assert!(
        state
            .prepare_record(time(&state, state.time()), vec![excess])
            .is_err()
    );
    assert_eq!(state.commitment(), before);
    assert_eq!(state.next_nonce(author(4)), nonce);
    start_reveal(&mut state);
    let winning_root = originals[0].2.package().root();
    for (index, secret, original) in originals.into_iter().rev() {
        let reveal = signed(
            &state,
            index,
            OperationBody::Reveal {
                round,
                secret,
                original,
            },
        );
        let now = state.time();
        apply(&mut state, now, vec![reveal]);
        assert_eq!(state.remaining_records(), state.reserved_records() + 1);
        assert!(state.library().is_empty());
        assert_eq!(state.balances().paid_completions(), 0);
        assert!(state.claims().is_empty());
    }
    assert_eq!(state.active().unwrap().reveals, 16);
    let deadline = state.active().unwrap().deadline.unwrap();
    apply(&mut state, deadline, vec![]);
    assert_eq!(state.active().unwrap().phase, Phase::SettlementPending);
    assert_eq!(state.remaining_records(), state.reserved_records() + 1);
    // Certified time can jump after a long outage without invalidating any of
    // the sixteen already-finalized timely reveals or its reserved settlement.
    apply(&mut state, deadline + 10000, vec![]);
    assert_eq!(
        state.question(submission).unwrap().status(),
        QuestionStatus::Completed
    );
    assert_eq!(state.library().len(), 1);
    assert!(state.library().lookup(winning_root).is_some());
    assert_eq!(state.balances().paid_completions(), 1);
    assert_eq!(state.balances().account(author(4)), Some(700_000_000));
    assert_eq!(state.claims().len(), 1);
    assert_eq!(state.reserved_records(), 0);
    state
        .balances()
        .verify_conservation(state.genesis(), state.accounts())
        .unwrap();
    let settled = state.commitment();
    let unrelated = signed(
        &state,
        5,
        OperationBody::Submit {
            purpose: "no capacity for a second complete attempt".into(),
            question: question(&state, "forall(x,member(x,x))"),
        },
    );
    assert!(
        state
            .prepare_record(time(&state, state.time()), vec![unrelated])
            .is_err()
    );
    assert_eq!(state.commitment(), settled);
    let now = state.time();
    apply(&mut state, now, vec![]);
    assert!(state.terminated());
    assert_eq!(state.balances().paid_completions(), 1);
    assert_eq!(state.claims().len(), 1);
    assert!(state.library().lookup(winning_root).is_some());
    assert!(state.prepare_record(time(&state, now), vec![]).is_err());
}
