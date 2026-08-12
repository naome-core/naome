use super::*;

#[test]
fn every_incomplete_first_entry_cut_recovers_to_empty_prefix() {
    let id = chain_id(CHAIN_BYTE);
    let (payloads, proof_ids) = dependency_chain_with_len(1);
    let block = one_block(id, &payloads, &proof_ids);
    let complete = journal_image(id, &[(block, payloads, proof_ids)]);
    let prefix = journal_prefix(id);

    for cut in JOURNAL_PREFIX_BYTES + 1..complete.len() {
        let directory = TestDirectory::new();
        directory.write_image(&complete[..cut]);
        let journal = ProofChainJournal::open_recovering_unverified(&directory.path, id).unwrap();
        assert!(journal.is_empty().unwrap(), "cut={cut}");
        assert_eq!(
            journal.head_block_id().unwrap(),
            ProofChainState::new(id).head_block_id(),
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
    let id = chain_id(CHAIN_BYTE);
    let entries = two_block_chain(id);
    let first_image = journal_image(id, &entries[..1]);
    let complete = journal_image(id, &entries);
    let first_id = entries[0].2[0];
    let first_head = entries[0].0.id();
    let second_head = entries[1].0.id();

    for cut in first_image.len() + 1..complete.len() {
        let directory = TestDirectory::new();
        directory.write_image(&complete[..cut]);
        let journal = ProofChainJournal::open_recovering_unverified(&directory.path, id).unwrap();
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
    let id = chain_id(CHAIN_BYTE);
    let (payloads, proof_ids) = dependency_chain_with_len(1);
    let block = one_block(id, &payloads, &proof_ids);
    let complete = journal_image(id, &[(block.clone(), payloads.clone(), proof_ids)]);
    let payload_offset = JOURNAL_PREFIX_BYTES + 4 + 2 + block.to_canonical_bytes().len() + 4;
    let directory = TestDirectory::new();
    let mut corrupt_payload = complete.clone();
    corrupt_payload[payload_offset] ^= 0x01;
    directory.write_image(&corrupt_payload);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, id),
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
                ProofChainJournal::open_recovering_unverified(&directory.path, id),
                Err(ProofChainJournalError::BlockIdMismatch { entry: 0, .. })
            ),
            "offset={offset}"
        );
        assert_eq!(fs::read(directory.journal_path()).unwrap(), corrupt);
    }
}

#[test]
fn prefix_and_chain_context_are_never_recovered_as_a_tail() {
    let id = chain_id(CHAIN_BYTE);
    let prefix = journal_prefix(id);
    for cut in 0..JOURNAL_PREFIX_BYTES {
        let directory = TestDirectory::new();
        directory.write_image(&prefix[..cut]);
        assert!(matches!(
            ProofChainJournal::open_recovering_unverified(&directory.path, id),
            Err(ProofChainJournalError::InvalidHeader)
        ));
        assert_eq!(fs::read(directory.journal_path()).unwrap(), &prefix[..cut]);
    }

    let directory = TestDirectory::new();
    let mut wrong_magic = prefix.clone();
    wrong_magic[0] ^= 1;
    directory.write_image(&wrong_magic);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, id),
        Err(ProofChainJournalError::InvalidHeader)
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), wrong_magic);

    let directory = TestDirectory::new();
    directory.write_image(&prefix);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, chain_id(0x22)),
        Err(ProofChainJournalError::ChainIdMismatch { expected, actual })
            if expected == chain_id(0x22) && actual == id
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), prefix);
}

#[test]
fn complete_framing_errors_fail_closed() {
    let id = chain_id(CHAIN_BYTE);

    let directory = TestDirectory::new();
    let mut invalid_outer = journal_prefix(id);
    invalid_outer.extend_from_slice(&(ENTRY_MIN_BODY_BYTES - 1).to_be_bytes());
    directory.write_image(&invalid_outer);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, id),
        Err(ProofChainJournalError::InvalidEntryLength { entry: 0, actual, .. })
            if actual == ENTRY_MIN_BODY_BYTES - 1
    ));

    let mut invalid_block_body = vec![0_u8; ENTRY_MIN_BODY_BYTES as usize];
    invalid_block_body[..2].copy_from_slice(&0_u16.to_be_bytes());
    let invalid_block_entry = raw_entry(&invalid_block_body, ProofBlockId::from_bytes([0_u8; 32]));
    let directory = TestDirectory::new();
    let mut invalid_block = journal_prefix(id);
    invalid_block.extend_from_slice(&invalid_block_entry);
    directory.write_image(&invalid_block);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, id),
        Err(ProofChainJournalError::InvalidBlockLength {
            entry: 0,
            actual: 0,
            ..
        })
    ));

    let (payloads, proof_ids) = dependency_chain_with_len(1);
    let block = one_block(id, &payloads, &proof_ids);
    let block_bytes = block.to_canonical_bytes();
    let mut zero_proof_body = Vec::new();
    zero_proof_body.extend_from_slice(&u16::try_from(block_bytes.len()).unwrap().to_be_bytes());
    zero_proof_body.extend_from_slice(&block_bytes);
    zero_proof_body.extend_from_slice(&0_u32.to_be_bytes());
    zero_proof_body.push(0);
    let zero_proof_entry = raw_entry(&zero_proof_body, block.id());
    let directory = TestDirectory::new();
    let mut zero_proof = journal_prefix(id);
    zero_proof.extend_from_slice(&zero_proof_entry);
    directory.write_image(&zero_proof);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, id),
        Err(ProofChainJournalError::InvalidProofLength {
            entry: 0,
            proof: 0,
            actual: 0,
            ..
        })
    ));

    let mut trailing_body = Vec::new();
    trailing_body.extend_from_slice(&u16::try_from(block_bytes.len()).unwrap().to_be_bytes());
    trailing_body.extend_from_slice(&block_bytes);
    trailing_body.extend_from_slice(&u32::try_from(payloads[0].len()).unwrap().to_be_bytes());
    trailing_body.extend_from_slice(&payloads[0]);
    trailing_body.push(0xff);
    let trailing_entry = raw_entry(&trailing_body, block.id());
    let directory = TestDirectory::new();
    let mut trailing = journal_prefix(id);
    trailing.extend_from_slice(&trailing_entry);
    directory.write_image(&trailing);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, id),
        Err(ProofChainJournalError::InvalidEntryBody { entry: 0, .. })
    ));
}

#[test]
fn block_id_valid_parent_payload_and_entry_order_attacks_fail_replay() {
    let id = chain_id(CHAIN_BYTE);
    let (payloads, proof_ids) = dependency_chain_with_len(2);
    let valid = one_block(id, &payloads, &proof_ids);

    let stale = ProofBlock::new(
        ProofBlockId::from_bytes([0xaa; 32]),
        valid.transition().clone(),
    );
    assert_replay_parent_failure(id, vec![(stale, payloads.clone(), proof_ids.clone())]);

    let directory = TestDirectory::new();
    let swapped = vec![payloads[1].clone(), payloads[0].clone()];
    let swapped_image = journal_image(id, &[(valid.clone(), swapped, proof_ids.clone())]);
    directory.write_image(&swapped_image);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, id),
        Err(ProofChainJournalError::Replay { entry: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBlockApplyError::Transition {
                    source: ProofTransitionApplyError::Batch { source }
                } if matches!(
                    source,
                    ProofBatchError::Candidate {
                        index: 0,
                        ..
                    }
                )
            )
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), swapped_image);

    let entries = two_block_chain(id);
    assert_replay_parent_failure(id, vec![entries[1].clone()]);
    assert_replay_parent_failure(id, vec![entries[1].clone(), entries[0].clone()]);
    assert_replay_parent_failure(id, vec![entries[0].clone(), entries[0].clone()]);
}

#[test]
fn verified_open_rejects_rollback_and_does_not_truncate_untrusted_tail() {
    let id = chain_id(CHAIN_BYTE);
    let entries = two_block_chain(id);
    let first_image = journal_image(id, &entries[..1]);
    let full_image = journal_image(id, &entries);
    let full_head = entries[1].0.id();
    let first_head = entries[0].0.id();
    let directory = TestDirectory::new();

    directory.write_image(&first_image);
    assert!(ProofChainJournal::open_recovering_unverified(&directory.path, id).is_ok());
    assert!(matches!(
        ProofChainJournal::open_verified(&directory.path, id, full_head),
        Err(ProofChainJournalError::HeadBlockIdMismatch { expected, actual })
            if expected == full_head && actual == first_head
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), first_image);

    let cut = first_image.len() + 7;
    let incomplete = full_image[..cut].to_vec();
    directory.write_image(&incomplete);
    assert!(matches!(
        ProofChainJournal::open_verified(&directory.path, id, full_head),
        Err(ProofChainJournalError::HeadBlockIdMismatch { expected, actual })
            if expected == full_head && actual == first_head
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), incomplete);

    let recovered = ProofChainJournal::open_recovering_unverified(&directory.path, id).unwrap();
    assert_eq!(recovered.head_block_id().unwrap(), first_head);
    drop(recovered);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), first_image);
}

fn assert_replay_parent_failure(id: ProofChainId, entries: Vec<JournalEntryFixture>) {
    let directory = TestDirectory::new();
    let image = journal_image(id, &entries);
    directory.write_image(&image);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, id),
        Err(ProofChainJournalError::Replay { source, .. })
            if matches!(
                source.as_ref(),
                ProofBlockApplyError::ParentBlockIdMismatch { .. }
            )
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);
}
