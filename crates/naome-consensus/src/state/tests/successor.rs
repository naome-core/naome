use super::*;
use naome_ledger::profile::{Limits, TimingKind};

fn short_run() -> StateBranch {
    let base = genesis();
    let profile = Profile::with_limits(
        TimingKind::ShortTest,
        Limits {
            run_records: 65,
            ..Limits::default()
        },
    )
    .unwrap();
    let linked = Genesis::new(
        profile,
        base.foundation().into(),
        base.checker_profile().into(),
        naome_ledger::profile::STATE_PROTOCOL_VERSION,
        base.start_utc(),
        *base.run_nonce(),
        base.accounts().iter().map(|a| *a.key()).collect(),
        base.validators().to_vec(),
        base.retirement_order().to_vec(),
    )
    .unwrap();
    StateBranch::from_genesis(LedgerState::new(linked)).unwrap()
}

fn empty_record(branch: &StateBranch) -> Vec<u8> {
    let state = branch.state();
    let reports = (0..4)
        .map(|i| {
            SignedTimeReport::sign(
                state.genesis(),
                state.authority(),
                state.head(),
                state.height() + 1,
                state.time(),
                &period_key(i, state.authority().effective_height()),
            )
            .unwrap()
        })
        .collect();
    let time = TimeCertificate::new(
        reports,
        state.genesis(),
        state.authority(),
        state.head(),
        state.height() + 1,
        state.time(),
    )
    .unwrap();
    state
        .prepare_record(time, Vec::new(), plan(branch))
        .unwrap()
        .record()
        .encode()
        .unwrap()
}

#[test]
fn sealed_terminal_creates_one_linked_state_with_preserved_slots_and_replay_barrier() {
    let opening = short_run();
    let first_record = empty_record(&opening);
    let first_proposal = proposal(&opening, first_record, 0, None);
    let first_quorum = quorum(
        &opening,
        0,
        ConsensusVoteRole::Precommit,
        target(&first_proposal),
    );
    let first = opening
        .finalize(&first_proposal, &first_quorum, MAX_ROUND)
        .unwrap();
    let parent = first.branch();
    assert!(!parent.state().terminated());
    assert_eq!(parent.state().remaining_records(), 64);
    assert!(StateBranch::from_terminal_finality(&first).is_err());

    let terminal_record = empty_record(parent);
    let terminal_proposal = proposal(parent, terminal_record, 0, None);
    let terminal_quorum = quorum(
        parent,
        0,
        ConsensusVoteRole::Precommit,
        target(&terminal_proposal),
    );
    let agreement = parent
        .verify_agreement(&terminal_proposal, &terminal_quorum, MAX_ROUND)
        .unwrap();
    assert!(agreement.state().terminated());
    let full_seal = seal(&agreement);
    assert!(
        StateSeal::new(
            full_seal.ready()[..2].to_vec(),
            full_seal.terminal().to_vec(),
            agreement.seal_context(),
            agreement.outgoing(),
            agreement.incoming(),
        )
        .is_err()
    );
    assert!(
        StateSeal::new(
            full_seal.ready().to_vec(),
            full_seal.terminal()[..2].to_vec(),
            agreement.seal_context(),
            agreement.outgoing(),
            agreement.incoming(),
        )
        .is_err()
    );
    let terminal = parent
        .verify_finality(&terminal_proposal, &terminal_quorum, &full_seal, MAX_ROUND)
        .unwrap();
    let next = StateBranch::from_terminal_finality(&terminal).unwrap();
    let next_again = StateBranch::from_terminal_finality(&terminal).unwrap();
    assert_eq!(next.commitment(), next_again.commitment());
    assert_eq!(next.state().height(), 0);
    assert_eq!(next.state().lineage_height(), 2);
    assert!(!next.state().terminated());
    assert_eq!(next.state().remaining_records(), 65);
    assert_eq!(
        next.state().balances().accounts(),
        opening.state().balances().accounts()
    );
    assert_eq!(
        next.state().used_period_keys(),
        terminal.branch().state().used_period_keys()
    );
    assert_eq!(
        next.authority()
            .units()
            .iter()
            .map(|u| (u.slot(), u.id(), u.owner(), u.origin()))
            .collect::<Vec<_>>(),
        terminal
            .branch()
            .authority()
            .units()
            .iter()
            .map(|u| (u.slot(), u.id(), u.owner(), u.origin()))
            .collect::<Vec<_>>(),
    );
    let linked = next.state().genesis();
    assert_eq!(Genesis::decode(&linked.encode()).unwrap(), *linked);
    assert_eq!(
        linked.predecessor().unwrap().terminal_head(),
        terminal.branch().state().head()
    );
    assert_eq!(
        linked.predecessor().unwrap().terminal_state(),
        terminal.branch().state().commitment()
    );
    assert!(StateBranch::from_genesis(LedgerState::new(linked.clone())).is_err());
    let old = OperationBody::Register
        .sign(opening.state().genesis(), 1, &account(5))
        .unwrap();
    assert!(old.verify_signature(linked).is_err());
}
