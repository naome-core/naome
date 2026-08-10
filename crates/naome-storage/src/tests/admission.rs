use super::*;

#[test]
fn journal_header_and_transaction_are_exact_golden_bytes() {
    assert_eq!(JOURNAL_HEADER.len(), 36);
    assert_eq!(GENESIS_DOMAIN.len(), 44);
    assert_eq!(TRANSACTION_DOMAIN.len(), 28);
    assert_eq!(TRANSACTION_MIN_BODY_BYTES, 6);
    assert_eq!(TRANSACTION_MAX_BODY_BYTES, 33_554_465);
    assert_eq!(
        genesis_digest().as_slice(),
        hex_bytes("7127edbfaed6d7b39d6a9ef69b3e3412a5ade11c0c13b2622b0ca33f11523764")
    );

    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    assert_eq!(pairing, hex_bytes("000000011001"));
    let (pairing_transaction, digest) =
        transaction(genesis_digest(), std::slice::from_ref(&pairing));
    assert_eq!(
        digest.as_slice(),
        hex_bytes("a7ac477d54ca4421cfbeb77a1bace81be2b98588af20d2f5abeae8ffc6a84b4f")
    );
    assert_eq!(
        pairing_transaction,
        hex_bytes(
            "0000000b0100000006000000011001a7ac477d54ca4421cfbeb77a1bace81be2b98588af20d2f5abeae8ffc6a84b4f"
        )
    );
    assert_eq!(
        journal_image(std::slice::from_ref(&pairing)),
        hex_bytes(
            "6e616f6d653a70726f6f662d6461672d7472616e73616374696f6e2d6a6f75726e616c000000000b0100000006000000011001a7ac477d54ca4421cfbeb77a1bace81be2b98588af20d2f5abeae8ffc6a84b4f"
        )
    );

    let directory = TestDirectory::new();
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let _ = journal
        .apply_canonical_proof_bytes(pairing.clone())
        .unwrap();
    drop(journal);
    assert_eq!(
        fs::read(directory.journal_path()).unwrap(),
        journal_image(&[pairing])
    );
}

#[test]
fn create_open_and_exclusive_lock_preserve_one_empty_journal() {
    let directory = TestDirectory::new();
    let journal = ProofDagJournal::create(&directory.path).unwrap();
    assert!(journal.is_empty().unwrap());
    assert_eq!(journal.len().unwrap(), 0);
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
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Locked)
    ));
    drop(journal);

    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert!(reopened.is_empty().unwrap());
    assert_eq!(reopened.proof_set_root().unwrap(), empty_root);
    assert!(matches!(
        ProofDagJournal::create(&directory.path),
        Err(JournalError::Locked)
    ));
    drop(reopened);
    assert!(matches!(
        ProofDagJournal::create(&directory.path),
        Err(JournalError::Create { .. })
    ));
}

#[test]
fn reopen_replays_dependency_chain_exactly() {
    let directory = TestDirectory::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let root = snapshot(
        journal
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap(),
    );
    let child_bytes = referenced_generalization(root.proof_id, FreeVariable::new(0));
    let child = snapshot(
        journal
            .apply_canonical_proof_bytes(child_bytes.clone())
            .unwrap(),
    );
    let grandchild_bytes = referenced_generalization(child.proof_id, FreeVariable::new(1));
    let grandchild = snapshot(
        journal
            .apply_canonical_proof_bytes(grandchild_bytes.clone())
            .unwrap(),
    );
    assert_eq!(child.dependencies, [root.proof_id]);
    assert_eq!(grandchild.dependencies, [child.proof_id]);
    let expected_root = journal.proof_set_root().unwrap();
    drop(journal);

    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert_eq!(reopened.len().unwrap(), 3);
    assert_eq!(
        snapshot(reopened.proof(root.proof_id).unwrap().unwrap()),
        root
    );
    assert_eq!(
        snapshot(reopened.proof(child.proof_id).unwrap().unwrap()),
        child
    );
    assert_eq!(
        snapshot(reopened.proof(grandchild.proof_id).unwrap().unwrap()),
        grandchild
    );
    assert_eq!(reopened.proof_set_root().unwrap(), expected_root);
    for proof_id in [root.proof_id, child.proof_id, grandchild.proof_id] {
        assert_eq!(
            reopened
                .proof_set_proof(proof_id)
                .unwrap()
                .verify(expected_root, proof_id),
            Ok(ProofSetMembership::Present)
        );
    }
}

#[test]
fn maximum_rooted_batch_is_one_transaction_and_replays_the_complete_closure() {
    let directory = TestDirectory::new();
    let (payloads, proof_ids) = dependency_chain_with_len(PROOF_BATCH_MAX_CANDIDATES);
    let requested_root = *proof_ids.last().unwrap();
    let expected_image = journal_transaction_image(std::slice::from_ref(&payloads));
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();

    let root = journal
        .apply_rooted_canonical_proof_batch(
            requested_root,
            addressed_candidates(&payloads, &proof_ids),
        )
        .unwrap();
    assert_eq!(root.proof_id(), requested_root);
    assert_eq!(journal.len().unwrap(), payloads.len());
    assert_eq!(fs::read(directory.journal_path()).unwrap(), expected_image);
    let expected_root = journal.proof_set_root().unwrap();
    for proof_id in &proof_ids {
        assert!(journal.proof(*proof_id).unwrap().is_some());
    }
    drop(journal);

    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert_eq!(reopened.len().unwrap(), payloads.len());
    assert_eq!(reopened.proof_set_root().unwrap(), expected_root);
    for proof_id in proof_ids {
        assert!(reopened.proof(proof_id).unwrap().is_some());
    }
}

#[test]
fn verified_open_checks_the_exact_replayed_set_after_all_format_checks() {
    let directory = TestDirectory::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let _ = journal
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap();
    let prefix_root = journal.proof_set_root().unwrap();
    let prefix_len = fs::metadata(directory.journal_path()).unwrap().len();
    let _ = journal
        .apply_canonical_proof_bytes(union_bytes.clone())
        .unwrap();
    let complete_root = journal.proof_set_root().unwrap();
    drop(journal);

    let verified = ProofDagJournal::open_verified(&directory.path, complete_root).unwrap();
    assert_eq!(verified.len().unwrap(), 2);
    drop(verified);

    assert!(matches!(
        ProofDagJournal::open_verified(&directory.path, prefix_root),
        Err(JournalError::ProofSetRootMismatch { expected, actual })
            if expected == prefix_root && actual == complete_root
    ));

    let mut corrupt = journal_image(&[root_bytes.clone(), union_bytes]);
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    directory.write_image(&corrupt);
    assert!(matches!(
        ProofDagJournal::open_verified(&directory.path, prefix_root),
        Err(JournalError::TransactionDigestMismatch { .. })
    ));

    directory.write_image(&journal_image(&[root_bytes]));
    fs::OpenOptions::new()
        .write(true)
        .open(directory.journal_path())
        .unwrap()
        .set_len(prefix_len)
        .unwrap();
    assert!(matches!(
        ProofDagJournal::open_verified(&directory.path, complete_root),
        Err(JournalError::ProofSetRootMismatch { expected, actual })
            if expected == complete_root && actual == prefix_root
    ));
}

#[test]
fn physical_journal_order_does_not_change_the_proof_set_root() {
    let first_directory = TestDirectory::new();
    let second_directory = TestDirectory::new();
    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);

    let mut first = ProofDagJournal::create(&first_directory.path).unwrap();
    let _ = first.apply_canonical_proof_bytes(pairing.clone()).unwrap();
    let _ = first.apply_canonical_proof_bytes(union.clone()).unwrap();
    let first_root = first.proof_set_root().unwrap();
    drop(first);

    let mut second = ProofDagJournal::create(&second_directory.path).unwrap();
    let _ = second.apply_canonical_proof_bytes(union).unwrap();
    let _ = second.apply_canonical_proof_bytes(pairing).unwrap();
    let second_root = second.proof_set_root().unwrap();
    drop(second);

    assert_eq!(first_root, second_root);
    assert_ne!(
        fs::read(first_directory.journal_path()).unwrap(),
        fs::read(second_directory.journal_path()).unwrap()
    );
}

#[test]
fn rejected_admissions_write_nothing_and_leave_the_journal_healthy() {
    let directory = TestDirectory::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let mut union_control = ProofDag::new();
    let union_id = union_control
        .apply_canonical_proof_bytes(union_bytes.clone())
        .unwrap()
        .proof_id();
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let root_id = journal
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();
    let committed_len = fs::metadata(directory.journal_path()).unwrap().len();
    let committed_root = journal.proof_set_root().unwrap();
    let committed_image = fs::read(directory.journal_path()).unwrap();

    assert_ne!(root_id, union_id);
    assert!(matches!(
        journal.apply_canonical_proof_bytes_with_expected_id(union_bytes.clone(), root_id),
        Err(JournalError::Admission {
            source: LedgerError::ProofIdMismatch {
                expected,
                actual,
            },
        }) if expected == root_id && actual == union_id
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), committed_image);
    assert_eq!(journal.len().unwrap(), 1);
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);
    assert!(journal.proof(union_id).unwrap().is_none());

    let locked_child = referenced_generalization(union_id, FreeVariable::new(1));
    assert!(matches!(
        journal.apply_canonical_proof_bytes(locked_child.clone()),
        Err(JournalError::Admission {
            source: LedgerError::Check {
                source: CheckError::UnknownProofReference { proof_id, .. }
            }
        }) if proof_id == union_id
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), committed_image);
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);

    assert!(matches!(
        journal.apply_canonical_proof_bytes(root_bytes),
        Err(JournalError::Admission {
            source: LedgerError::State {
                source: ProofStateError::DuplicateProof { .. }
            }
        })
    ));
    assert_eq!(
        fs::metadata(directory.journal_path()).unwrap().len(),
        committed_len
    );
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);

    let missing_id = ProofId::from_bytes([0x55; 32]);
    let missing = canonical_bytes(vec![ProofStep::ProofReference {
        proof_id: missing_id,
    }]);
    assert!(matches!(
        journal.apply_canonical_proof_bytes(missing),
        Err(JournalError::Admission {
            source: LedgerError::Check {
                source: CheckError::UnknownProofReference { proof_id, .. }
            }
        }) if proof_id == missing_id
    ));
    assert_eq!(
        fs::metadata(directory.journal_path()).unwrap().len(),
        committed_len
    );
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);
    assert!(journal.proof(root_id).unwrap().is_some());

    let child = referenced_generalization(root_id, FreeVariable::new(0));
    let child_id = journal
        .apply_canonical_proof_bytes(child)
        .unwrap()
        .proof_id();
    assert!(journal.proof(child_id).unwrap().is_some());

    let accepted_union = journal
        .apply_canonical_proof_bytes_with_expected_id(union_bytes, union_id)
        .unwrap();
    assert_eq!(accepted_union.proof_id(), union_id);
    let locked_child_id = journal
        .apply_canonical_proof_bytes(locked_child)
        .unwrap()
        .proof_id();
    assert!(journal.proof(locked_child_id).unwrap().is_some());

    drop(journal);
    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert!(reopened.proof(root_id).unwrap().is_some());
    assert!(reopened.proof(union_id).unwrap().is_some());
    assert!(reopened.proof(locked_child_id).unwrap().is_some());
}

#[test]
fn formula_node_limit_rejection_is_atomic_and_complete_replay_fails_closed() {
    let directory = TestDirectory::new();
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let next_bytes = axiom_bytes(ZfcAxiom::Union);
    let over_budget = over_formula_node_budget_bytes();
    let mut journal = ProofDagJournal::create(&directory.path).unwrap();
    let root_id = journal
        .apply_canonical_proof_bytes(root_bytes)
        .unwrap()
        .proof_id();
    let committed_image = fs::read(directory.journal_path()).unwrap();
    let committed_root = journal.proof_set_root().unwrap();

    assert!(matches!(
        journal.apply_canonical_proof_bytes_with_expected_id(
            over_budget.clone(),
            ProofId::from_bytes([0x51; 32]),
        ),
        Err(JournalError::Admission {
            source: LedgerError::Decode {
                source: ProofCertificateError::FormulaNodeLimitExceeded { maximum },
            },
        }) if maximum == CERTIFICATE_MAX_FORMULA_NODES
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), committed_image);
    assert_eq!(journal.len().unwrap(), 1);
    assert_eq!(journal.proof_set_root().unwrap(), committed_root);
    assert!(journal.proof(root_id).unwrap().is_some());

    let next_id = journal
        .apply_canonical_proof_bytes(next_bytes)
        .unwrap()
        .proof_id();
    drop(journal);
    let reopened = ProofDagJournal::open(&directory.path).unwrap();
    assert!(reopened.proof(root_id).unwrap().is_some());
    assert!(reopened.proof(next_id).unwrap().is_some());
    drop(reopened);

    let replay_directory = TestDirectory::new();
    let complete_over_budget_image = journal_image(std::slice::from_ref(&over_budget));
    replay_directory.write_image(&complete_over_budget_image);
    assert!(matches!(
        ProofDagJournal::open(&replay_directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::Decode {
                        source: ProofCertificateError::FormulaNodeLimitExceeded { maximum },
                    },
                    ..
                } if *maximum == CERTIFICATE_MAX_FORMULA_NODES
            )
    ));
    assert_eq!(
        fs::read(replay_directory.journal_path()).unwrap(),
        complete_over_budget_image
    );
}
