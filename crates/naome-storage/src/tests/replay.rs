use super::*;

#[test]
fn every_incomplete_first_entry_cut_recovers_to_empty_prefix() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let (payloads, proof_ids) = dependency_chain_with_len(1);
    let block = one_block(definition, proof_ids[0]);
    let complete = journal_image(id, &[(block, payloads[0].clone(), proof_ids[0])]);
    let prefix = journal_prefix(id);

    for cut in JOURNAL_PREFIX_BYTES + 1..complete.len() {
        let directory = TestDirectory::new();
        directory.write_image(&complete[..cut]);
        let journal =
            ProofChainJournal::open_recovering_unverified(&directory.path, definition).unwrap();
        assert!(journal.is_empty().unwrap(), "cut={cut}");
        assert_eq!(
            journal.head_block_id().unwrap(),
            ProofChainState::new(definition).head_block_id(),
            "cut={cut}"
        );
        drop(journal);
        assert_eq!(
            fs::read(directory.journal_path()).unwrap(),
            prefix,
            "cut={cut}"
        );
    }
}

#[test]
fn every_incomplete_second_entry_cut_recovers_exact_first_block() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let entries = two_block_chain(definition);
    let first_image = journal_image(id, &entries[..1]);
    let complete = journal_image(id, &entries);
    let first_id = entries[0].2;
    let first_head = entries[0].0.id();
    let second_head = entries[1].0.id();

    for cut in first_image.len() + 1..complete.len() {
        let directory = TestDirectory::new();
        directory.write_image(&complete[..cut]);
        let journal =
            ProofChainJournal::open_recovering_unverified(&directory.path, definition).unwrap();
        assert_eq!(journal.len().unwrap(), 1, "cut={cut}");
        assert_eq!(journal.head_block_id().unwrap(), first_head, "cut={cut}");
        assert!(journal.proof(first_id).unwrap().is_some(), "cut={cut}");
        assert_eq!(
            journal.block(first_head).unwrap(),
            Some(&entries[0].0),
            "cut={cut}"
        );
        assert_eq!(journal.block(second_head).unwrap(), None, "cut={cut}");
        drop(journal);
        assert_eq!(
            fs::read(directory.journal_path()).unwrap(),
            first_image,
            "cut={cut}"
        );
    }
}

#[test]
fn complete_payload_and_footer_corruption_fail_without_recovery() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let (payloads, proof_ids) = dependency_chain_with_len(1);
    let block = one_block(definition, proof_ids[0]);
    let complete = journal_image(id, &[(block, payloads[0].clone(), proof_ids[0])]);
    let payload_offset = JOURNAL_PREFIX_BYTES + 4 + block.to_canonical_bytes().len();
    let directory = TestDirectory::new();
    let mut corrupt_payload = complete.clone();
    corrupt_payload[payload_offset] ^= 0x01;
    directory.write_image(&corrupt_payload);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, definition),
        Err(ProofChainJournalError::Replay { entry: 0, .. })
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), corrupt_payload);

    for offset in [complete.len() - 32, complete.len() - 1] {
        let directory = TestDirectory::new();
        let mut corrupt = complete.clone();
        corrupt[offset] ^= 0x01;
        directory.write_image(&corrupt);
        assert!(
            matches!(
                ProofChainJournal::open_recovering_unverified(&directory.path, definition),
                Err(ProofChainJournalError::BlockIdMismatch { entry: 0, .. })
            ),
            "offset={offset}"
        );
        assert_eq!(fs::read(directory.journal_path()).unwrap(), corrupt);
    }
}

#[test]
fn prefix_and_chain_context_are_never_recovered_as_a_tail() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let prefix = journal_prefix(id);
    for cut in 0..JOURNAL_PREFIX_BYTES {
        let directory = TestDirectory::new();
        directory.write_image(&prefix[..cut]);
        assert!(matches!(
            ProofChainJournal::open_recovering_unverified(&directory.path, definition),
            Err(ProofChainJournalError::InvalidHeader)
        ));
        assert_eq!(fs::read(directory.journal_path()).unwrap(), &prefix[..cut]);
    }

    let directory = TestDirectory::new();
    let mut wrong_magic = prefix.clone();
    wrong_magic[0] ^= 1;
    directory.write_image(&wrong_magic);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, definition),
        Err(ProofChainJournalError::InvalidHeader)
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), wrong_magic);

    let directory = TestDirectory::new();
    directory.write_image(&prefix);
    let wrong_definition = chain_definition(0x22);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, wrong_definition),
        Err(ProofChainJournalError::ChainIdMismatch { expected, actual })
            if expected == wrong_definition.id() && actual == id
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), prefix);
}

#[test]
fn complete_framing_errors_fail_closed() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();

    let directory = TestDirectory::new();
    let mut invalid_outer = journal_prefix(id);
    invalid_outer.extend_from_slice(&(ENTRY_MIN_BODY_BYTES - 1).to_be_bytes());
    directory.write_image(&invalid_outer);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, definition),
        Err(ProofChainJournalError::InvalidEntryLength { entry: 0, actual, .. })
            if actual == ENTRY_MIN_BODY_BYTES - 1
    ));

    let invalid_block_body = vec![0_u8; ENTRY_MIN_BODY_BYTES as usize];
    let invalid_block_entry = raw_entry(&invalid_block_body, ProofBlockId::from_bytes([0_u8; 32]));
    let directory = TestDirectory::new();
    let mut invalid_block = journal_prefix(id);
    invalid_block.extend_from_slice(&invalid_block_entry);
    directory.write_image(&invalid_block);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, definition),
        Err(ProofChainJournalError::BlockIdMismatch { entry: 0, .. })
    ));

    let mut invalid_outer = journal_prefix(id);
    invalid_outer.extend_from_slice(&(ENTRY_MAX_BODY_BYTES + 1).to_be_bytes());
    let directory = TestDirectory::new();
    directory.write_image(&invalid_outer);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, definition),
        Err(ProofChainJournalError::InvalidEntryLength { entry: 0, actual, .. })
            if actual == ENTRY_MAX_BODY_BYTES + 1
    ));
}

#[test]
fn block_id_valid_parent_payload_and_entry_order_attacks_fail_replay() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let (payloads, proof_ids) = dependency_chain_with_len(1);
    let valid = one_block(definition, proof_ids[0]);

    let stale = ProofBlock::new(
        ProofBlockId::from_bytes([0xaa; 32]),
        valid.previous_proof_set_root(),
        valid.resulting_proof_set_root(),
        valid.proof_id(),
    );
    assert_replay_parent_failure(definition, vec![(stale, payloads[0].clone(), proof_ids[0])]);

    let directory = TestDirectory::new();
    let substituted = axiom_bytes(ZfcAxiom::Union);
    let swapped_image = journal_image(id, &[(valid, substituted, proof_ids[0])]);
    directory.write_image(&swapped_image);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, definition),
        Err(ProofChainJournalError::Replay { entry: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBlockApplyError::Admission { .. }
            )
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), swapped_image);

    let entries = two_block_chain(definition);
    assert_replay_parent_failure(definition, vec![entries[1].clone()]);
    assert_replay_parent_failure(definition, vec![entries[1].clone(), entries[0].clone()]);
    assert_replay_parent_failure(definition, vec![entries[0].clone(), entries[0].clone()]);
}

#[test]
fn verified_open_rejects_rollback_and_does_not_truncate_untrusted_tail() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let entries = two_block_chain(definition);
    let first_image = journal_image(id, &entries[..1]);
    let full_image = journal_image(id, &entries);
    let full_head = entries[1].0.id();
    let first_head = entries[0].0.id();
    let directory = TestDirectory::new();

    directory.write_image(&first_image);
    assert!(ProofChainJournal::open_recovering_unverified(&directory.path, definition).is_ok());
    assert!(matches!(
        ProofChainJournal::open_verified(&directory.path, definition, full_head),
        Err(ProofChainJournalError::HeadBlockIdMismatch { expected, actual })
            if expected == full_head && actual == first_head
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), first_image);

    let cut = first_image.len() + 7;
    let incomplete = full_image[..cut].to_vec();
    directory.write_image(&incomplete);
    assert!(matches!(
        ProofChainJournal::open_verified(&directory.path, definition, full_head),
        Err(ProofChainJournalError::HeadBlockIdMismatch { expected, actual })
            if expected == full_head && actual == first_head
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), incomplete);

    let recovered =
        ProofChainJournal::open_recovering_unverified(&directory.path, definition).unwrap();
    assert_eq!(recovered.head_block_id().unwrap(), first_head);
    drop(recovered);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), first_image);
}

fn assert_replay_parent_failure(
    definition: ProofChainDefinition,
    entries: Vec<JournalEntryFixture>,
) {
    let directory = TestDirectory::new();
    let id = definition.id();
    let image = journal_image(id, &entries);
    directory.write_image(&image);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, definition),
        Err(ProofChainJournalError::Replay { source, .. })
            if matches!(
                source.as_ref(),
                ProofBlockApplyError::ParentBlockIdMismatch { .. }
            )
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);
}
