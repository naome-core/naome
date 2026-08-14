use super::*;

#[test]
fn journal_prefix_and_entry_encoding_are_exact() {
    assert_eq!(JOURNAL_HEADER.len(), 32);
    assert_eq!(JOURNAL_PREFIX_BYTES, 64);
    assert_eq!(ARTIFACT_BLOCK_BYTES, 128);
    assert_eq!(ENTRY_MIN_BODY_BYTES, 129);
    assert_eq!(ENTRY_MAX_BODY_BYTES, 4_194_433);

    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let payloads = vec![axiom_bytes(ZfcAxiom::Pairing)];
    let artifact_ids = addressed_artifact_ids(&payloads);
    let block = one_block(definition, artifact_ids[0]);
    let expected = journal_image(id, &[(block, payloads[0].clone(), artifact_ids[0])]);
    assert_eq!(
        expected,
        hex_bytes(
            "6e616f6d653a61727469666163742d636861696e2d6a6f75726e616c3a763000\
             1007f212015cb2d5bd3e58e93fb0941e6dbb8496bf3669093303cf65d3895de0\
             00000087\
             31ca052e8c2660d98d4eb0586adc388702841cf31a924c4c3563dfc920d2850\
             c976e576ec6145d57b5e192d1c37a0938bb5c76663532d0354fcd98ba3fbf597\
             a689e27706ea99f45e7988e6fd9b144ef3a8582b3bfefb645369e5a8a8a0aa\
             89fbca9828587bc6c94c243dc078329163d64de54becc1bacc7bc9ca136f3908ce0\
             00000000011001\
             017bd0c6ed92afb89c5dbc8876dfd6b646c59a8fc1218714be91881d8fc57475"
                .replace([' ', '\n'], "")
                .as_str(),
        )
    );

    let directory = TestDirectory::new();
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let record = snapshot(
        journal
            .apply_block(&block, artifact_bytes(&payloads[0]))
            .unwrap(),
    );
    assert_eq!(record.artifact_id, artifact_ids[0]);
    drop(journal);

    assert_eq!(fs::read(directory.journal_path()).unwrap(), expected);
}

#[test]
fn create_open_chain_binding_and_same_process_lock_are_strict() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let other_definition = chain_definition(0x22);
    let id = definition.id();
    let other_id = other_definition.id();
    let genesis = ArtifactChainState::new(definition).head_block_id();
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();

    assert_eq!(journal.chain_id(), id);
    assert!(journal.is_empty().unwrap());
    assert_eq!(journal.len().unwrap(), 0);
    assert_eq!(journal.head_block_id().unwrap(), genesis);
    assert_eq!(journal.block(genesis).unwrap(), None);
    assert_eq!(
        journal
            .block(ArtifactBlockId::from_bytes([0x55; 32]))
            .unwrap(),
        None
    );
    let empty_root = journal.artifact_set_root().unwrap();
    let unknown = ArtifactId::from_bytes([0x55; 32]);
    assert_eq!(
        journal
            .artifact_set_proof(unknown)
            .unwrap()
            .verify(empty_root, unknown),
        Ok(ArtifactSetMembership::Absent)
    );
    assert!(matches!(
        ArtifactChainJournal::open_recovering_unverified(&directory.path, definition),
        Err(ArtifactChainJournalError::Locked)
    ));
    drop(journal);

    assert!(matches!(
        ArtifactChainJournal::open_recovering_unverified(&directory.path, other_definition),
        Err(ArtifactChainJournalError::ChainIdMismatch { expected, actual })
            if expected == other_id && actual == id
    ));
    let reopened =
        ArtifactChainJournal::open_recovering_unverified(&directory.path, definition).unwrap();
    assert_eq!(reopened.chain_id(), id);
    assert_eq!(reopened.head_block_id().unwrap(), genesis);
    assert_eq!(reopened.block(genesis).unwrap(), None);
    drop(reopened);
    assert!(matches!(
        ArtifactChainJournal::create(&directory.path, definition),
        Err(ArtifactChainJournalError::Create { .. })
    ));
}

#[test]
fn wrong_definition_precedes_corruption_tail_recovery_and_head_verification() {
    let definition = chain_definition(CHAIN_BYTE);
    let wrong_definition = chain_definition(0x22);
    let chain_id = definition.id();
    let wrong_chain_id = wrong_definition.id();
    let genesis = chain_id.virtual_genesis_block_id();
    let wrong_expected_head = ArtifactBlockId::from_bytes([0x77; 32]);
    let prefix = journal_prefix(chain_id);

    let corrupt_directory = TestDirectory::new();
    let mut corrupt = prefix.clone();
    corrupt.extend_from_slice(&raw_entry(
        &vec![0_u8; ENTRY_MIN_BODY_BYTES as usize],
        ArtifactBlockId::from_bytes([0_u8; 32]),
    ));
    corrupt_directory.write_image(&corrupt);
    assert!(matches!(
        ArtifactChainJournal::open_verified(
            &corrupt_directory.path,
            wrong_definition,
            wrong_expected_head,
        ),
        Err(ArtifactChainJournalError::ChainIdMismatch { expected, actual })
            if expected == wrong_chain_id && actual == chain_id
    ));
    assert_eq!(fs::read(corrupt_directory.journal_path()).unwrap(), corrupt);
    assert!(matches!(
        ArtifactChainJournal::open_recovering_unverified(&corrupt_directory.path, definition),
        Err(ArtifactChainJournalError::BlockIdMismatch { entry: 0, .. })
    ));
    assert_eq!(fs::read(corrupt_directory.journal_path()).unwrap(), corrupt);

    let tail_directory = TestDirectory::new();
    let mut incomplete_tail = prefix.clone();
    incomplete_tail.push(0xa5);
    tail_directory.write_image(&incomplete_tail);
    assert!(matches!(
        ArtifactChainJournal::open_verified(
            &tail_directory.path,
            wrong_definition,
            wrong_expected_head,
        ),
        Err(ArtifactChainJournalError::ChainIdMismatch { expected, actual })
            if expected == wrong_chain_id && actual == chain_id
    ));
    assert_eq!(
        fs::read(tail_directory.journal_path()).unwrap(),
        incomplete_tail
    );
    drop(ArtifactChainJournal::open_verified(&tail_directory.path, definition, genesis).unwrap());
    assert_eq!(fs::read(tail_directory.journal_path()).unwrap(), prefix);

    let head_directory = TestDirectory::new();
    head_directory.write_image(&prefix);
    assert!(matches!(
        ArtifactChainJournal::open_verified(
            &head_directory.path,
            wrong_definition,
            wrong_expected_head,
        ),
        Err(ArtifactChainJournalError::ChainIdMismatch { expected, actual })
            if expected == wrong_chain_id && actual == chain_id
    ));
    assert_eq!(fs::read(head_directory.journal_path()).unwrap(), prefix);
    assert!(matches!(
        ArtifactChainJournal::open_verified(
            &head_directory.path,
            definition,
            wrong_expected_head,
        ),
        Err(ArtifactChainJournalError::HeadBlockIdMismatch { expected, actual })
            if expected == wrong_expected_head && actual == genesis
    ));
    assert_eq!(fs::read(head_directory.journal_path()).unwrap(), prefix);

    let truncated_directory = TestDirectory::new();
    let truncated_prefix = &prefix[..prefix.len() - 1];
    truncated_directory.write_image(truncated_prefix);
    assert!(matches!(
        ArtifactChainJournal::open_recovering_unverified(
            &truncated_directory.path,
            wrong_definition,
        ),
        Err(ArtifactChainJournalError::InvalidHeader)
    ));
    assert_eq!(
        fs::read(truncated_directory.journal_path()).unwrap(),
        truncated_prefix
    );
}

#[test]
fn two_blocks_reopen_exact_head_records_root_and_witnesses() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let entries = two_block_chain(definition);
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let mut expected_records = Vec::new();
    for (block, payload, _) in &entries {
        expected_records.push(snapshot(
            journal.apply_block(block, artifact_bytes(payload)).unwrap(),
        ));
    }
    let expected_head = entries[1].0.id();
    let expected_root = journal.artifact_set_root().unwrap();
    assert_eq!(journal.head_block_id().unwrap(), expected_head);
    for (block, _, _) in &entries {
        assert_eq!(journal.block(block.id()).unwrap(), Some(block));
    }
    let image = fs::read(directory.journal_path()).unwrap();
    assert_eq!(
        journal
            .block(ArtifactBlockId::from_bytes([0x55; 32]))
            .unwrap(),
        None
    );
    assert_eq!(journal.head_block_id().unwrap(), expected_head);
    assert_eq!(journal.artifact_set_root().unwrap(), expected_root);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);
    drop(journal);

    let reopened =
        ArtifactChainJournal::open_verified(&directory.path, definition, expected_head).unwrap();
    assert_eq!(reopened.chain_id(), id);
    assert_eq!(reopened.len().unwrap(), 2);
    assert_eq!(reopened.head_block_id().unwrap(), expected_head);
    assert_eq!(reopened.artifact_set_root().unwrap(), expected_root);
    for (block, _, _) in &entries {
        assert_eq!(reopened.block(block.id()).unwrap(), Some(block));
    }
    for record in expected_records {
        assert_eq!(
            snapshot(reopened.artifact(record.artifact_id).unwrap().unwrap()),
            record
        );
        assert_eq!(
            reopened
                .artifact_set_proof(record.artifact_id)
                .unwrap()
                .verify(expected_root, record.artifact_id),
            Ok(ArtifactSetMembership::Present)
        );
    }
}

#[test]
fn mixed_definition_and_proof_blocks_replay_with_exact_typed_payloads() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let definition_payload = relation_definition_bytes();
    let proof_payload = axiom_bytes(ZfcAxiom::Pairing);

    let mut expected = ArtifactDag::new();
    let definition_record = expected
        .apply_canonical_artifact_bytes(definition_payload.clone())
        .unwrap();
    let definition_artifact_id = definition_record.artifact_id();
    let definition_id = definition_record.as_definition().unwrap().definition_id();
    let proof_record = expected
        .apply_canonical_artifact_bytes(proof_payload.clone())
        .unwrap();
    let proof_artifact_id = proof_record.artifact_id();
    let proof_id = proof_record.as_proof().unwrap().proof_id();

    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let definition_block = journal.prepare_block(definition_artifact_id).unwrap();
    let accepted_definition = journal
        .apply_block(&definition_block, definition_payload.clone())
        .unwrap();
    assert_eq!(accepted_definition.artifact_id(), definition_artifact_id);
    assert_eq!(
        accepted_definition.as_definition().unwrap().definition_id(),
        definition_id
    );

    let proof_block = journal.prepare_block(proof_artifact_id).unwrap();
    let accepted_proof = journal
        .apply_block(&proof_block, proof_payload.clone())
        .unwrap();
    assert_eq!(accepted_proof.artifact_id(), proof_artifact_id);
    assert_eq!(accepted_proof.as_proof().unwrap().proof_id(), proof_id);
    let expected_head = proof_block.id();
    let expected_root = journal.artifact_set_root().unwrap();
    drop(journal);

    let reopened =
        ArtifactChainJournal::open_verified(&directory.path, definition, expected_head).unwrap();
    assert_eq!(reopened.len().unwrap(), 2);
    assert_eq!(reopened.artifact_set_root().unwrap(), expected_root);
    assert_eq!(
        reopened
            .artifact(definition_artifact_id)
            .unwrap()
            .unwrap()
            .canonical_artifact_bytes(),
        definition_payload
    );
    assert!(
        reopened
            .artifact(definition_artifact_id)
            .unwrap()
            .unwrap()
            .as_definition()
            .is_some()
    );
    assert_eq!(
        reopened
            .artifact(proof_artifact_id)
            .unwrap()
            .unwrap()
            .canonical_artifact_bytes(),
        proof_payload
    );
    assert!(
        reopened
            .artifact(proof_artifact_id)
            .unwrap()
            .unwrap()
            .as_proof()
            .is_some()
    );
}

#[test]
fn prepare_is_read_only_and_rejects_an_already_selected_artifact() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let image = fs::read(directory.journal_path()).unwrap();
    let head = journal.head_block_id().unwrap();
    let root = journal.artifact_set_root().unwrap();
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let artifact_id = addressed_artifact_ids(std::slice::from_ref(&payload))[0];

    let block = journal.prepare_block(artifact_id).unwrap();
    assert_eq!(block.parent_block_id(), head);
    assert_eq!(block.previous_artifact_set_root(), root);
    assert_eq!(journal.head_block_id().unwrap(), head);
    assert_eq!(journal.artifact_set_root().unwrap(), root);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);

    drop(journal);
    let mut journal =
        ArtifactChainJournal::open_recovering_unverified(&directory.path, definition).unwrap();
    journal.apply_block(&block, payload).unwrap();
    let committed = fs::read(directory.journal_path()).unwrap();
    assert!(matches!(
        journal.prepare_block(artifact_id),
        Err(ArtifactChainJournalError::Preparation { .. })
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), committed);
}

#[test]
fn parent_rejection_writes_nothing_and_allows_retry() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (payloads, artifact_ids) = dependency_chain_with_len(1);
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let block = journal.prepare_block(artifact_ids[0]).unwrap();
    let original_image = fs::read(directory.journal_path()).unwrap();
    let original_head = journal.head_block_id().unwrap();
    let original_root = journal.artifact_set_root().unwrap();
    let stale = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0x99; 32]),
        block.previous_artifact_set_root(),
        block.resulting_artifact_set_root(),
        block.artifact_id(),
    );
    assert!(matches!(
        journal.apply_block(&stale, vec![0x00]),
        Err(ArtifactChainJournalError::BlockAdmission {
            source: ArtifactBlockApplyError::ParentBlockIdMismatch { .. }
        })
    ));
    assert_unchanged(
        &journal,
        &directory,
        &original_image,
        original_head,
        original_root,
    );
    assert_eq!(journal.block(stale.id()).unwrap(), None);
    assert_eq!(journal.block(block.id()).unwrap(), None);

    let root = journal
        .apply_block(&block, artifact_bytes(&payloads[0]))
        .unwrap();
    assert_eq!(root.artifact_id(), artifact_ids[0]);
    assert_eq!(journal.len().unwrap(), 1);
    assert_eq!(journal.head_block_id().unwrap(), block.id());
    assert_eq!(journal.block(block.id()).unwrap(), Some(&block));
}

#[test]
fn verified_open_binds_history_even_when_artifact_set_root_matches() {
    let definition = chain_definition(CHAIN_BYTE);
    let (payloads, artifact_ids) = independent_axioms();
    let first_directory = TestDirectory::new();
    let second_directory = TestDirectory::new();

    let first_head = commit_separate_blocks(&first_directory, definition, &payloads, &artifact_ids);
    let reversed_payloads = vec![payloads[1].clone(), payloads[0].clone()];
    let reversed_ids = vec![artifact_ids[1], artifact_ids[0]];
    let second_head = commit_separate_blocks(
        &second_directory,
        definition,
        &reversed_payloads,
        &reversed_ids,
    );
    assert_ne!(first_head, second_head);

    let first = ArtifactChainJournal::open_recovering_unverified(&first_directory.path, definition)
        .unwrap();
    let first_root = first.artifact_set_root().unwrap();
    drop(first);
    let second =
        ArtifactChainJournal::open_recovering_unverified(&second_directory.path, definition)
            .unwrap();
    assert_eq!(second.artifact_set_root().unwrap(), first_root);
    drop(second);

    assert!(matches!(
        ArtifactChainJournal::open_verified(&second_directory.path, definition, first_head),
        Err(ArtifactChainJournalError::HeadBlockIdMismatch { expected, actual })
            if expected == first_head && actual == second_head
    ));
    assert!(
        ArtifactChainJournal::open_verified(&second_directory.path, definition, second_head)
            .is_ok()
    );
}

#[test]
fn formula_budget_rejection_is_atomic_and_complete_replay_fails_closed() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let directory = TestDirectory::new();
    let valid_payload = axiom_bytes(ZfcAxiom::Pairing);
    let valid_id = addressed_artifact_ids(std::slice::from_ref(&valid_payload))[0];
    let over_budget = over_formula_node_budget_bytes();
    let over_id = ArtifactId::from_bytes([0x51; 32]);
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let invalid_block = journal.prepare_block(over_id).unwrap();
    let before = fs::read(directory.journal_path()).unwrap();

    assert!(matches!(
        journal.apply_block(&invalid_block, over_budget.clone()),
        Err(ArtifactChainJournalError::BlockAdmission {
            source: ArtifactBlockApplyError::Admission {
                source: LedgerError::Decode {
                    source: ArtifactPayloadError::Proof(
                        ProofCertificateError::FormulaNodeLimitExceeded { maximum },
                    ),
                },
            }
        }) if maximum == CERTIFICATE_MAX_FORMULA_NODES
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), before);
    assert!(journal.is_empty().unwrap());

    let valid_block = journal.prepare_block(valid_id).unwrap();
    journal.apply_block(&valid_block, valid_payload).unwrap();
    drop(journal);

    let replay_directory = TestDirectory::new();
    let invalid_block = one_block(definition, over_id);
    let invalid_image = journal_image(id, &[(invalid_block, over_budget, over_id)]);
    replay_directory.write_image(&invalid_image);
    assert!(matches!(
        ArtifactChainJournal::open_recovering_unverified(&replay_directory.path, definition),
        Err(ArtifactChainJournalError::Replay { entry: 0, source, .. })
            if matches!(
                source.as_ref(),
                ArtifactBlockApplyError::Admission {
                    source: LedgerError::Decode {
                        source: ArtifactPayloadError::Proof(
                            ProofCertificateError::FormulaNodeLimitExceeded { maximum },
                        ),
                    },
                } if *maximum == CERTIFICATE_MAX_FORMULA_NODES
            )
    ));
    assert_eq!(
        fs::read(replay_directory.journal_path()).unwrap(),
        invalid_image
    );
}

fn addressed_artifact_ids(payloads: &[Vec<u8>]) -> Vec<ArtifactId> {
    let mut dag = ArtifactDag::new();
    payloads
        .iter()
        .map(|payload| {
            dag.apply_canonical_artifact_bytes(payload.clone())
                .unwrap()
                .artifact_id()
        })
        .collect()
}

fn assert_unchanged(
    journal: &ArtifactChainJournal,
    directory: &TestDirectory,
    image: &[u8],
    head: ArtifactBlockId,
    root: ArtifactSetRoot,
) {
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);
    assert_eq!(journal.head_block_id().unwrap(), head);
    assert_eq!(journal.artifact_set_root().unwrap(), root);
    assert!(journal.is_empty().unwrap());
}

fn commit_separate_blocks(
    directory: &TestDirectory,
    definition: ArtifactChainDefinition,
    payloads: &[Vec<u8>],
    artifact_ids: &[ArtifactId],
) -> ArtifactBlockId {
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    for (payload, artifact_id) in payloads.iter().zip(artifact_ids.iter().copied()) {
        let block = journal.prepare_block(artifact_id).unwrap();
        journal.apply_block(&block, payload.clone()).unwrap();
    }
    journal.head_block_id().unwrap()
}
