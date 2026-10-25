use super::*;

#[test]
fn shared_spent_time_expires_overlapping_attempts_during_reconciliation() {
    let (_directory, mut owner) = fixture(2);
    let _first = submit(&mut owner, 1);
    let _second = submit(&mut owner, 2);
    for id in [1, 2] {
        owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    }
    let account = owner.journal.accounts.values_mut().next().unwrap();
    account.spent_ms = account.settings.limits.horizon_ms;
    owner.journal.total_spent_ms = account.spent_ms;
    owner.reconcile().unwrap();
    for id in [1, 2] {
        assert_eq!(owner.journal.records[&id].state, State::Expired);
        assert_eq!(owner.journal.records[&id].reserved_units, 0);
    }
}

#[test]
fn recovery_applies_shared_original_time_without_renewing_an_attempts_deadline() {
    let (directory, mut owner) = fixture(2);
    let _ticket = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    let original = owner.journal.records[&1].clone();
    let account = owner.journal.accounts.values_mut().next().unwrap();
    account.spent_ms = account.settings.limits.horizon_ms;
    owner.journal.total_spent_ms = account.spent_ms;
    owner.save().unwrap();
    let settings = owner.settings;
    drop(owner);
    let (_, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let recovered = &journal.records[&1];
    assert_eq!(recovered.state, State::Expired);
    assert_eq!(recovered.created_ms, original.created_ms);
    assert_eq!(recovered.expires_ms, original.expires_ms);
    assert_eq!(recovered.reserved_units, original.reserved_units);
}

#[test]
fn the_last_reserved_unit_can_complete_without_a_new_reservation() {
    let (_directory, mut owner) = fixture(1);
    let _ticket = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    assert_eq!(owner.reserve(1, 1).unwrap(), Reservation::Granted);
    owner.journal.records.get_mut(&1).unwrap().checkpoint = 1;
    owner.reconcile().unwrap();
    assert_eq!(owner.journal.records[&1].state, State::Running);
    owner
        .complete(
            1,
            process::Outcome {
                state: State::Complete,
                result: Ok(Output::NoCandidate),
            },
        )
        .unwrap();
    assert_eq!(owner.journal.records[&1].state, State::Complete);
    assert_eq!(owner.journal.records[&1].reserved_units, 1);
    assert_eq!(
        owner
            .journal
            .accounts
            .values()
            .next()
            .unwrap()
            .reserved_units,
        1
    );
}
