use super::*;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "naome-publication-snapshot-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

// These tests exercise only private receipt-file mechanics; no fabricated
// completion or receipt can enter the public runtime/signing boundary.
fn journal(directory: &Directory) -> PublicationJournal {
    let lock = regular_options(true, true)
        .create(true)
        .truncate(false)
        .open(directory.0.join("progress.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    PublicationJournal {
        directory: directory.0.clone(),
        file_name: "progress".into(),
        binding: HEADER.to_vec(),
        deliveries: Vec::new(),
        peer_count: 2,
        poisoned: false,
        _lock: Lock(lock),
    }
}

#[test]
fn ambiguous_receipt_replacement_never_turns_an_unobserved_receipt_into_acknowledged_debt() {
    use faults::Stage;
    for stage in [
        Stage::Create,
        Stage::Write,
        Stage::FileSync,
        Stage::Rename,
        Stage::DirectorySync,
    ] {
        let directory = Directory::new();
        let id = StateId::from_bytes([1; 32]);
        let mut owner = journal(&directory);
        owner.insert(id).unwrap();
        owner.save(true).unwrap();
        owner.attempt(id, 0).unwrap();
        let before = fs::read(directory.0.join("progress")).unwrap();
        faults::FAIL.with(|failure| failure.set(Some(stage)));
        assert!(owner.acknowledge(id, 0).is_err());
        assert!(owner.poisoned);
        assert!(matches!(
            owner.attempt(id, 1),
            Err(FixedValidatorPublicationJournalErrorV0::Poisoned)
        ));
        drop(owner);
        let bytes = fs::read(directory.0.join("progress")).unwrap();
        if stage != Stage::DirectorySync {
            assert_eq!(bytes, before);
        }
        let mut reopened = journal(&directory);
        reopened.decode(&bytes, &[id]).unwrap();
        // Only a completely installed record of an actually observed receipt
        // can suppress resend. Earlier failure keeps the exact debt unacked.
        assert_eq!(reopened.received(id, 0), stage == Stage::DirectorySync);
        assert!(!reopened.received(id, 1));
    }
}

#[test]
fn receipt_snapshot_rejects_truncation_corruption_foreign_identity_and_false_ack_masks() {
    let directory = Directory::new();
    let id = StateId::from_bytes([7; 32]);
    let mut owner = journal(&directory);
    owner.insert(id).unwrap();
    owner.save(true).unwrap();
    owner.attempt(id, 0).unwrap();
    owner.acknowledge(id, 0).unwrap();
    let bytes = fs::read(directory.0.join("progress")).unwrap();
    drop(owner);
    let mut reopened = journal(&directory);
    for end in 0..bytes.len() {
        assert!(reopened.decode(&bytes[..end], &[id]).is_err());
    }
    let mut corrupt = bytes.clone();
    corrupt[HEADER.len() + 8] ^= 1;
    assert!(reopened.decode(&corrupt, &[id]).is_err());
    let split = corrupt.len() - 32;
    let digest = checksum(&corrupt[..split]);
    corrupt[split..].copy_from_slice(&digest);
    assert!(
        reopened.decode(&corrupt, &[id]).is_err(),
        "valid framing cannot import a foreign completion identity"
    );
    let mut false_ack = bytes.clone();
    false_ack[split - 1] |= 2; // Peer 1 has never had a transport attempt.
    let digest = checksum(&false_ack[..split]);
    false_ack[split..].copy_from_slice(&digest);
    assert!(reopened.decode(&false_ack, &[id]).is_err());
    let mut wrong_binding = bytes.clone();
    wrong_binding[0] ^= 1;
    let digest = checksum(&wrong_binding[..split]);
    wrong_binding[split..].copy_from_slice(&digest);
    assert!(reopened.decode(&wrong_binding, &[id]).is_err());
    assert!(reopened.decode(&bytes, &[]).is_err());
    reopened.decode(&bytes, &[id]).unwrap();
    assert!(reopened.received(id, 0));
    assert!(!reopened.received(id, 1));
}

#[test]
fn receipt_owner_explicitly_unlocks_even_with_a_duplicate_file_description() {
    let directory = Directory::new();
    let owner = journal(&directory);
    let duplicate = owner._lock.0.try_clone().unwrap();
    let contender = regular_options(true, true)
        .open(directory.0.join("progress.lock"))
        .unwrap();
    assert!(matches!(
        contender.try_lock(),
        Err(TryLockError::WouldBlock)
    ));
    drop(owner);
    contender.try_lock().unwrap();
    drop(duplicate);
    contender.unlock().unwrap();
}
