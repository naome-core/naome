use super::*;

#[test]
fn journal_prefix_and_entry_encoding_are_exact() {
    assert_eq!(JOURNAL_HEADER.len(), 26);
    assert_eq!(JOURNAL_PREFIX_BYTES, 58);
    assert_eq!(PROOF_BLOCK_MIN_BYTES, 129);
    assert_eq!(ENTRY_MIN_BODY_BYTES, 136);
    assert_eq!(ENTRY_MAX_BODY_BYTES, 33_554_819);

    let id = chain_id(CHAIN_BYTE);
    let payloads = vec![axiom_bytes(ZfcAxiom::Pairing)];
    let proof_ids = addressed_proof_ids(&payloads);
    let block = one_block(id, &payloads, &proof_ids);
    let expected = journal_image(id, &[(block.clone(), payloads.clone(), proof_ids.clone())]);
    assert_eq!(
        expected,
        hex_bytes(
            "6e616f6d653a70726f6f662d636861696e2d6a6f75726e616c0011111111111111111111111111111111111111111111111111111111111111110000008d0081f47ee4acce1f5797ff773e7b620cfc66b101dfadb0b87cb4f83e3b94765c8b98e9a980287e770ac389d3735ff064e7447f11c9640efdb90b91781766497f16ca8cf486cdd001c39de9da117a0fe882d1cba7e785645af4016bdf2f29726f195a015285fedf4eee3753a08eabac642e5eab8b6ef99e6357b592a5c34760a4aa04b700000006000000011001f5347dca996ef4b07ec2934064ee4fce6f9d740758fb2213ba7c131f547ea0bd"
        )
    );

    let directory = TestDirectory::new();
    let mut journal = ProofChainJournal::create(&directory.path, id).unwrap();
    let record = snapshot(
        journal
            .apply_block(&block, addressed_candidates(&payloads, &proof_ids))
            .unwrap(),
    );
    assert_eq!(record.proof_id, proof_ids[0]);
    drop(journal);

    assert_eq!(fs::read(directory.journal_path()).unwrap(), expected);
}

#[test]
fn create_open_chain_binding_and_same_process_lock_are_strict() {
    let directory = TestDirectory::new();
    let id = chain_id(CHAIN_BYTE);
    let other_id = chain_id(0x22);
    let genesis = ProofChainState::new(id).head_block_id();
    let journal = ProofChainJournal::create(&directory.path, id).unwrap();

    assert_eq!(journal.chain_id(), id);
    assert!(journal.is_empty().unwrap());
    assert_eq!(journal.len().unwrap(), 0);
    assert_eq!(journal.head_block_id().unwrap(), genesis);
    assert_eq!(journal.block(genesis).unwrap(), None);
    assert_eq!(
        journal.block(ProofBlockId::from_bytes([0x55; 32])).unwrap(),
        None
    );
    let empty_root = journal.proof_set_root().unwrap();
    let unknown = ProofId::from_bytes([0x55; 32]);
    assert_eq!(
        journal
            .proof_set_proof(unknown)
            .unwrap()
            .verify(empty_root, unknown),
        Ok(ProofSetMembership::Absent)
    );
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, id),
        Err(ProofChainJournalError::Locked)
    ));
    drop(journal);

    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, other_id),
        Err(ProofChainJournalError::ChainIdMismatch { expected, actual })
            if expected == other_id && actual == id
    ));
    let reopened = ProofChainJournal::open_recovering_unverified(&directory.path, id).unwrap();
    assert_eq!(reopened.chain_id(), id);
    assert_eq!(reopened.head_block_id().unwrap(), genesis);
    assert_eq!(reopened.block(genesis).unwrap(), None);
    drop(reopened);
    assert!(matches!(
        ProofChainJournal::create(&directory.path, id),
        Err(ProofChainJournalError::Create { .. })
    ));
}

#[test]
fn two_blocks_reopen_exact_head_records_root_and_witnesses() {
    let directory = TestDirectory::new();
    let id = chain_id(CHAIN_BYTE);
    let entries = two_block_chain(id);
    let mut journal = ProofChainJournal::create(&directory.path, id).unwrap();
    let mut expected_records = Vec::new();
    for (block, payloads, proof_ids) in &entries {
        expected_records.push(snapshot(
            journal
                .apply_block(block, addressed_candidates(payloads, proof_ids))
                .unwrap(),
        ));
    }
    let expected_head = entries[1].0.id();
    let expected_root = journal.proof_set_root().unwrap();
    assert_eq!(journal.head_block_id().unwrap(), expected_head);
    for (block, _, _) in &entries {
        assert_eq!(journal.block(block.id()).unwrap(), Some(block));
    }
    let image = fs::read(directory.journal_path()).unwrap();
    assert_eq!(
        journal.block(ProofBlockId::from_bytes([0x55; 32])).unwrap(),
        None
    );
    assert_eq!(journal.head_block_id().unwrap(), expected_head);
    assert_eq!(journal.proof_set_root().unwrap(), expected_root);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);
    drop(journal);

    let reopened = ProofChainJournal::open_verified(&directory.path, id, expected_head).unwrap();
    assert_eq!(reopened.chain_id(), id);
    assert_eq!(reopened.len().unwrap(), 2);
    assert_eq!(reopened.head_block_id().unwrap(), expected_head);
    assert_eq!(reopened.proof_set_root().unwrap(), expected_root);
    for (block, _, _) in &entries {
        assert_eq!(reopened.block(block.id()).unwrap(), Some(block));
    }
    for record in expected_records {
        assert_eq!(
            snapshot(reopened.proof(record.proof_id).unwrap().unwrap()),
            record
        );
        assert_eq!(
            reopened
                .proof_set_proof(record.proof_id)
                .unwrap()
                .verify(expected_root, record.proof_id),
            Ok(ProofSetMembership::Present)
        );
    }
}

#[test]
fn maximum_eight_proof_block_is_one_entry_and_replays() {
    let directory = TestDirectory::new();
    let id = chain_id(CHAIN_BYTE);
    let (payloads, proof_ids) = dependency_chain_with_len(PROOF_BATCH_MAX_CANDIDATES);
    let block = one_block(id, &payloads, &proof_ids);
    let expected_image = journal_image(id, &[(block.clone(), payloads.clone(), proof_ids.clone())]);
    let mut journal = ProofChainJournal::create(&directory.path, id).unwrap();

    let root = journal
        .apply_block(&block, addressed_candidates(&payloads, &proof_ids))
        .unwrap();
    assert_eq!(root.proof_id(), *proof_ids.last().unwrap());
    assert_eq!(journal.len().unwrap(), PROOF_BATCH_MAX_CANDIDATES);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), expected_image);
    let expected_root = journal.proof_set_root().unwrap();
    drop(journal);

    let reopened = ProofChainJournal::open_recovering_unverified(&directory.path, id).unwrap();
    assert_eq!(reopened.len().unwrap(), PROOF_BATCH_MAX_CANDIDATES);
    assert_eq!(reopened.proof_set_root().unwrap(), expected_root);
    assert_eq!(reopened.head_block_id().unwrap(), block.id());
    for proof_id in proof_ids {
        assert!(reopened.proof(proof_id).unwrap().is_some());
    }
}

#[test]
fn prepare_is_read_only_and_wraps_transition_errors() {
    let directory = TestDirectory::new();
    let id = chain_id(CHAIN_BYTE);
    let journal = ProofChainJournal::create(&directory.path, id).unwrap();
    let image = fs::read(directory.journal_path()).unwrap();
    let head = journal.head_block_id().unwrap();
    let root = journal.proof_set_root().unwrap();
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let proof_id = addressed_proof_ids(std::slice::from_ref(&payload))[0];

    let block = journal.prepare_block(vec![proof_id]).unwrap();
    assert_eq!(block.parent_block_id(), head);
    assert_eq!(block.transition().previous_proof_set_root(), root);
    assert_eq!(journal.head_block_id().unwrap(), head);
    assert_eq!(journal.proof_set_root().unwrap(), root);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);

    assert!(matches!(
        journal.prepare_block(Vec::new()),
        Err(ProofChainJournalError::Preparation { .. })
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);
}

#[test]
fn parent_and_transition_rejections_write_nothing_and_allow_retry() {
    let directory = TestDirectory::new();
    let id = chain_id(CHAIN_BYTE);
    let (payloads, proof_ids) = dependency_chain_with_len(2);
    let mut journal = ProofChainJournal::create(&directory.path, id).unwrap();
    let block = journal.prepare_block(proof_ids.clone()).unwrap();
    let original_image = fs::read(directory.journal_path()).unwrap();
    let original_head = journal.head_block_id().unwrap();
    let original_root = journal.proof_set_root().unwrap();
    let unknown = ProofId::from_bytes([0x77; 32]);

    let stale = ProofBlock::new(
        ProofBlockId::from_bytes([0x99; 32]),
        block.transition().clone(),
    );
    assert!(matches!(
        journal.apply_block(
            &stale,
            vec![AddressedProofCandidate::new(unknown, vec![0x00])]
        ),
        Err(ProofChainJournalError::BlockAdmission {
            source: ProofBlockApplyError::ParentBlockIdMismatch { .. }
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

    let mut wrong_ids = proof_ids.clone();
    wrong_ids[0] = unknown;
    assert!(matches!(
        journal.apply_block(&block, addressed_candidates(&payloads, &wrong_ids)),
        Err(ProofChainJournalError::BlockAdmission {
            source: ProofBlockApplyError::Transition {
                source: ProofTransitionApplyError::CandidateProofIdMismatch { index: 0, .. }
            }
        })
    ));
    assert_unchanged(
        &journal,
        &directory,
        &original_image,
        original_head,
        original_root,
    );
    assert_eq!(journal.block(block.id()).unwrap(), None);

    let root = journal
        .apply_block(&block, addressed_candidates(&payloads, &proof_ids))
        .unwrap();
    assert_eq!(root.proof_id(), proof_ids[1]);
    assert_eq!(journal.len().unwrap(), 2);
    assert_eq!(journal.head_block_id().unwrap(), block.id());
    assert_eq!(journal.block(block.id()).unwrap(), Some(&block));
}

#[test]
fn verified_open_binds_history_even_when_proof_set_root_matches() {
    let id = chain_id(CHAIN_BYTE);
    let (payloads, proof_ids) = independent_axioms();
    let first_directory = TestDirectory::new();
    let second_directory = TestDirectory::new();

    let first_head = commit_separate_blocks(&first_directory, id, &payloads, &proof_ids);
    let reversed_payloads = vec![payloads[1].clone(), payloads[0].clone()];
    let reversed_ids = vec![proof_ids[1], proof_ids[0]];
    let second_head =
        commit_separate_blocks(&second_directory, id, &reversed_payloads, &reversed_ids);
    assert_ne!(first_head, second_head);

    let first = ProofChainJournal::open_recovering_unverified(&first_directory.path, id).unwrap();
    let first_root = first.proof_set_root().unwrap();
    drop(first);
    let second = ProofChainJournal::open_recovering_unverified(&second_directory.path, id).unwrap();
    assert_eq!(second.proof_set_root().unwrap(), first_root);
    drop(second);

    assert!(matches!(
        ProofChainJournal::open_verified(&second_directory.path, id, first_head),
        Err(ProofChainJournalError::HeadBlockIdMismatch { expected, actual })
            if expected == first_head && actual == second_head
    ));
    assert!(ProofChainJournal::open_verified(&second_directory.path, id, second_head).is_ok());
}

#[test]
fn formula_budget_rejection_is_atomic_and_complete_replay_fails_closed() {
    let id = chain_id(CHAIN_BYTE);
    let directory = TestDirectory::new();
    let valid_payload = axiom_bytes(ZfcAxiom::Pairing);
    let valid_id = addressed_proof_ids(std::slice::from_ref(&valid_payload))[0];
    let over_budget = over_formula_node_budget_bytes();
    let over_id = ProofId::from_bytes([0x51; 32]);
    let mut journal = ProofChainJournal::create(&directory.path, id).unwrap();
    let invalid_block = journal.prepare_block(vec![over_id]).unwrap();
    let before = fs::read(directory.journal_path()).unwrap();

    assert!(matches!(
        journal.apply_block(
            &invalid_block,
            vec![AddressedProofCandidate::new(over_id, over_budget.clone())],
        ),
        Err(ProofChainJournalError::BlockAdmission {
            source: ProofBlockApplyError::Transition {
                source: ProofTransitionApplyError::Batch { source }
            }
        }) if matches!(
            &source,
            ProofBatchError::Candidate {
                index: 0,
                source: LedgerError::Decode {
                    source: ProofCertificateError::FormulaNodeLimitExceeded { maximum },
                },
                ..
            } if *maximum == CERTIFICATE_MAX_FORMULA_NODES
        )
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), before);
    assert!(journal.is_empty().unwrap());

    let valid_block = journal.prepare_block(vec![valid_id]).unwrap();
    journal
        .apply_block(
            &valid_block,
            vec![AddressedProofCandidate::new(valid_id, valid_payload)],
        )
        .unwrap();
    drop(journal);

    let replay_directory = TestDirectory::new();
    let invalid_block = one_block(id, std::slice::from_ref(&over_budget), &[over_id]);
    let invalid_image = journal_image(id, &[(invalid_block, vec![over_budget], vec![over_id])]);
    replay_directory.write_image(&invalid_image);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&replay_directory.path, id),
        Err(ProofChainJournalError::Replay { entry: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBlockApplyError::Transition {
                    source: ProofTransitionApplyError::Batch { source }
                } if matches!(
                    source,
                    ProofBatchError::Candidate {
                        index: 0,
                        source: LedgerError::Decode {
                            source: ProofCertificateError::FormulaNodeLimitExceeded { maximum },
                        },
                        ..
                    } if *maximum == CERTIFICATE_MAX_FORMULA_NODES
                )
            )
    ));
    assert_eq!(
        fs::read(replay_directory.journal_path()).unwrap(),
        invalid_image
    );
}

fn addressed_proof_ids(payloads: &[Vec<u8>]) -> Vec<ProofId> {
    let mut dag = ProofDag::new();
    payloads
        .iter()
        .map(|payload| {
            dag.apply_canonical_proof_bytes(payload.clone())
                .unwrap()
                .proof_id()
        })
        .collect()
}

fn assert_unchanged(
    journal: &ProofChainJournal,
    directory: &TestDirectory,
    image: &[u8],
    head: ProofBlockId,
    root: ProofSetRoot,
) {
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);
    assert_eq!(journal.head_block_id().unwrap(), head);
    assert_eq!(journal.proof_set_root().unwrap(), root);
    assert!(journal.is_empty().unwrap());
}

fn commit_separate_blocks(
    directory: &TestDirectory,
    id: ProofChainId,
    payloads: &[Vec<u8>],
    proof_ids: &[ProofId],
) -> ProofBlockId {
    let mut journal = ProofChainJournal::create(&directory.path, id).unwrap();
    for (payload, proof_id) in payloads.iter().zip(proof_ids.iter().copied()) {
        let block = journal.prepare_block(vec![proof_id]).unwrap();
        journal
            .apply_block(
                &block,
                vec![AddressedProofCandidate::new(proof_id, payload.clone())],
            )
            .unwrap();
    }
    journal.head_block_id().unwrap()
}
