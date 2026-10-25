use super::*;
use naome_proof::program::Command;

fn candidate(directory: &Directory, job: u64) -> crate::proof_work::Work {
    let mut work = crate::proof_work::Work::open(
        &directory
            .0
            .join(format!(".program-work/candidate-{job}.sqlite3")),
    )
    .unwrap();
    work.append(&Command::Reflexivity { variable: 0 }).unwrap();
    work
}

#[test]
fn candidate_cache_is_retired_only_after_the_acknowledgement_commits() {
    let (directory, mut owner) = fixture(2);
    let _ticket = submit(&mut owner, 1);
    drop(candidate(&directory, 1));
    let path = directory.0.join(".program-work/candidate-1.sqlite3");
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.state = State::Failed;
    owner.save().unwrap();
    assert!(
        path.exists(),
        "an unacknowledged result must remain recoverable"
    );
    owner.journal.records.get_mut(&1).unwrap().acknowledged = true;
    crate::checkpoint::fail_next_commit();
    assert!(owner.save().is_err());
    assert!(
        path.exists(),
        "failed acknowledgement must not retire candidate bytes"
    );
    owner.save().unwrap();
    assert!(!path.exists());
    assert!(!path.with_extension("proof-work.lock").exists());
    let original = owner.journal.records[&1].clone();
    drop(owner);
    let (_, journal) = Disk::open(&directory.0, Settings::default(), 0).unwrap();
    assert!(journal.records[&1].acknowledged);
    assert_eq!(journal.records[&1].created_ms, original.created_ms);
    assert_eq!(journal.records[&1].reserved_units, original.reserved_units);
}

#[test]
fn restart_reconciles_acknowledged_cache_left_while_native_custody_was_active() {
    let (directory, mut owner) = fixture(2);
    let _ticket = submit(&mut owner, 1);
    owner.journal.records.get_mut(&1).unwrap().state = State::Running;
    owner.reserve(1, 1).unwrap();
    let group = vec![Command::Reflexivity { variable: 0 }];
    owner
        .disk
        .save_program_group(&owner.journal, 1, 1, group.clone())
        .unwrap();
    let work = candidate(&directory, 1);
    let path = directory.0.join(".program-work/candidate-1.sqlite3");
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.state = State::Failed;
    record.acknowledged = true;
    owner.save().unwrap();
    assert!(path.exists(), "live native custody prevents reclamation");
    drop(owner);
    drop(work);
    let (disk, journal) = Disk::open(&directory.0, Settings::default(), 0).unwrap();
    assert!(
        !path.exists(),
        "durable acknowledgement permits startup reconciliation"
    );
    assert!(journal.records[&1].acknowledged);
    assert_eq!(
        disk.program_group(1, 1).unwrap(),
        group,
        "canonical provider input is retained"
    );
}

#[test]
fn unacknowledged_partial_cache_survives_restart_and_is_replayed_from_zero() {
    let (directory, mut owner) = fixture(2);
    let _ticket = submit(&mut owner, 1);
    owner.save().unwrap();
    drop(candidate(&directory, 1));
    drop(owner);
    let (_disk, journal) = Disk::open(&directory.0, Settings::default(), 0).unwrap();
    assert!(!journal.records[&1].acknowledged);
    let work =
        crate::proof_work::Work::open(&directory.0.join(".program-work/candidate-1.sqlite3"))
            .unwrap();
    assert_eq!(work.status().unwrap().commands, 1);
    assert_eq!(work.status().unwrap().checked_commands, 0);
}

#[test]
fn restart_finishes_retirement_interrupted_between_database_and_lock_unlink() {
    let (directory, mut owner) = fixture(2);
    let _ticket = submit(&mut owner, 1);
    let work = candidate(&directory, 1);
    let record = owner.journal.records.get_mut(&1).unwrap();
    record.state = State::Failed;
    record.acknowledged = true;
    owner.save().unwrap();
    drop(work);
    let path = directory.0.join(".program-work/candidate-1.sqlite3");
    fs::remove_file(&path).unwrap();
    let lock = path.with_extension("proof-work.lock");
    assert!(lock.exists());
    drop(owner);
    let (_, journal) = Disk::open(&directory.0, Settings::default(), 0).unwrap();
    assert!(journal.records[&1].acknowledged);
    assert!(!lock.exists());
}

#[test]
#[ignore = "Manual matched architecture measurement"]
fn measure_acknowledged_candidate_storage() {
    let (directory, mut owner) = fixture(64);
    for epoch in 1..=16 {
        let _ticket = submit(&mut owner, epoch);
        let id = u64::from(epoch);
        drop(candidate(&directory, id));
        let record = owner.journal.records.get_mut(&id).unwrap();
        record.state = State::Failed;
        record.acknowledged = true;
        owner.save().unwrap();
    }
    let mut files = 0;
    let mut bytes = 0;
    for entry in fs::read_dir(directory.0.join(".program-work")).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().is_some_and(|ext| ext == "sqlite3") {
            files += 1;
            bytes += entry.metadata().unwrap().len();
        }
    }
    println!(
        "architecture_candidates acknowledged=16 retained_files={files} retained_bytes={bytes}"
    );
    assert_eq!(
        owner
            .journal
            .records
            .values()
            .filter(|record| record.acknowledged)
            .count(),
        16
    );
}
