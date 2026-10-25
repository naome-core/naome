use super::*;

#[test]
fn program_group_backpressure_retains_the_original_reservation_after_a_known_unwritten_save() {
    use naome_proof::program::Command;
    let (_directory, mut owner) = fixture(2);
    let _ticket = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    owner.reserve(1, 1).unwrap();
    let original = owner.journal.records[&1].clone();
    let records = vec![Command::Reflexivity { variable: 0 }];
    let (reply, mut receipt) = oneshot::channel();
    owner.programs.insert(
        1,
        PendingProgram {
            unit: 1,
            records: records.clone(),
            reply,
        },
    );
    crate::checkpoint::fail_next_commit();
    owner.persist_programs().unwrap();
    assert_eq!(owner.programs.len(), 1);
    assert!(matches!(
        receipt.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(owner.disk.program_group(1, 1).is_err());
    owner.persist_programs().unwrap();
    assert!(receipt.try_recv().unwrap().is_ok());
    assert!(owner.programs.is_empty());
    assert_eq!(owner.disk.program_group(1, 1).unwrap(), records);
    assert_eq!(
        owner.journal.records[&1].reserved_units,
        original.reserved_units
    );
    assert_eq!(owner.journal.records[&1].checkpoint, original.checkpoint);
    assert_eq!(owner.journal.records[&1].expires_ms, original.expires_ms);
}

#[test]
fn uncertain_journal_save_stops_candidate_delivery_until_recovery() {
    use naome_proof::program::Command;
    let (directory, mut owner) = fixture(2);
    let _ticket = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    owner.reserve(1, 1).unwrap();
    let original = owner.journal.records[&1].clone();
    let (reply, mut receipt) = oneshot::channel();
    owner.programs.insert(
        1,
        PendingProgram {
            unit: 1,
            records: vec![Command::Reflexivity { variable: 0 }],
            reply,
        },
    );
    crate::checkpoint::fail_after_commit();
    assert!(owner.persist_programs().is_err());
    assert!(receipt.try_recv().unwrap().is_err());
    assert!(owner.disk.saved().is_err());
    let settings = owner.settings;
    drop(owner);
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    assert!(disk.program_group(1, 1).is_err());
    assert_eq!(journal.records[&1].state, State::Suspended);
    assert_eq!(journal.records[&1].reserved_units, original.reserved_units);
    assert_eq!(journal.records[&1].expires_ms, original.expires_ms);
}
