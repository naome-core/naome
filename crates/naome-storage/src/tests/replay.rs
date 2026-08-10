use super::*;

#[test]
fn every_incomplete_final_transaction_recovers_only_the_committed_prefix() {
    let root_bytes = axiom_bytes(ZfcAxiom::Pairing);
    let union_bytes = axiom_bytes(ZfcAxiom::Union);
    let full = journal_image(&[root_bytes.clone(), union_bytes.clone()]);
    let prefix = journal_image(std::slice::from_ref(&root_bytes));
    let (root_id, prefix_root) = {
        let directory = TestDirectory::new();
        let mut journal = ProofDagJournal::create(&directory.path).unwrap();
        let root_id = journal
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap()
            .proof_id();
        (root_id, journal.proof_set_root().unwrap())
    };

    for cut in prefix.len()..full.len() {
        let directory = TestDirectory::new();
        directory.write_image(&full[..cut]);
        let mut recovered = ProofDagJournal::open(&directory.path).unwrap();
        assert_eq!(recovered.len().unwrap(), 1, "cut={cut}");
        assert!(recovered.proof(root_id).unwrap().is_some(), "cut={cut}");
        assert_eq!(
            recovered.proof_set_root().unwrap(),
            prefix_root,
            "cut={cut}"
        );
        assert_eq!(
            fs::metadata(directory.journal_path()).unwrap().len(),
            prefix.len() as u64,
            "cut={cut}"
        );

        let child_bytes = referenced_generalization(root_id, FreeVariable::new(3));
        let child_id = recovered
            .apply_canonical_proof_bytes(child_bytes)
            .unwrap()
            .proof_id();
        drop(recovered);
        let reopened = ProofDagJournal::open(&directory.path).unwrap();
        assert_eq!(reopened.len().unwrap(), 2, "cut={cut}");
        assert!(reopened.proof(child_id).unwrap().is_some(), "cut={cut}");
    }

    let directory = TestDirectory::new();
    directory.write_image(&full);
    assert_eq!(
        ProofDagJournal::open(&directory.path)
            .unwrap()
            .len()
            .unwrap(),
        2
    );
}

#[test]
fn complete_corruption_deletion_and_reordering_fail_closed() {
    let root = axiom_bytes(ZfcAxiom::Pairing);
    let union = axiom_bytes(ZfcAxiom::Union);
    let infinity = axiom_bytes(ZfcAxiom::Infinity);
    let (root_transaction, root_digest) =
        transaction(genesis_digest(), std::slice::from_ref(&root));
    let (union_transaction, union_digest) = transaction(root_digest, std::slice::from_ref(&union));
    let (infinity_transaction, _) = transaction(union_digest, std::slice::from_ref(&infinity));

    for index in 9..union_transaction.len() {
        let directory = TestDirectory::new();
        let mut image = JOURNAL_HEADER.to_vec();
        image.extend_from_slice(&root_transaction);
        let union_start = image.len();
        image.extend_from_slice(&union_transaction);
        image.extend_from_slice(&infinity_transaction);
        image[union_start + index] ^= 0x01;
        directory.write_image(&image);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::TransactionDigestMismatch { transaction: 1, .. })
        ));
    }

    for transactions in [
        vec![root_transaction.clone(), infinity_transaction.clone()],
        vec![
            root_transaction.clone(),
            infinity_transaction.clone(),
            union_transaction.clone(),
        ],
        vec![
            root_transaction.clone(),
            union_transaction.clone(),
            union_transaction.clone(),
            infinity_transaction.clone(),
        ],
    ] {
        let directory = TestDirectory::new();
        let mut image = JOURNAL_HEADER.to_vec();
        for transaction in transactions {
            image.extend_from_slice(&transaction);
        }
        directory.write_image(&image);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::TransactionDigestMismatch { .. })
        ));
    }

    let directory = TestDirectory::new();
    let mut bad_header = journal_image(&[root]);
    bad_header[0] ^= 1;
    directory.write_image(&bad_header);
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::InvalidHeader)
    ));
}

#[test]
fn transaction_lengths_are_preflighted_before_payload_allocation() {
    for actual in [
        0,
        TRANSACTION_MIN_BODY_BYTES - 1,
        TRANSACTION_MAX_BODY_BYTES + 1,
        u32::MAX,
    ] {
        let directory = TestDirectory::new();
        let mut image = JOURNAL_HEADER.to_vec();
        image.extend_from_slice(&actual.to_be_bytes());
        directory.write_image(&image);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::InvalidTransactionLength {
                transaction: 0,
                actual: found,
                ..
            }) if found == actual
        ));
    }

    let directory = TestDirectory::new();
    let mut short_maximum = JOURNAL_HEADER.to_vec();
    short_maximum.extend_from_slice(&TRANSACTION_MAX_BODY_BYTES.to_be_bytes());
    directory.write_image(&short_maximum);
    let recovered = ProofDagJournal::open(&directory.path).unwrap();
    assert!(recovered.is_empty().unwrap());
    assert_eq!(
        fs::metadata(directory.journal_path()).unwrap().len(),
        JOURNAL_HEADER.len() as u64
    );
}

#[test]
fn transaction_inner_shape_is_preflighted_without_payload_overread() {
    let cases = [
        (vec![0, 0, 0, 0, 1, 0], "zero proof count", 0_u8, None),
        (
            vec![(PROOF_BATCH_MAX_CANDIDATES + 1) as u8, 0, 0, 0, 1, 0],
            "over-limit proof count",
            (PROOF_BATCH_MAX_CANDIDATES + 1) as u8,
            None,
        ),
        (vec![1, 0, 0, 0, 0, 0], "zero proof length", 1, Some(0)),
        (
            {
                let mut body = vec![1];
                body.extend_from_slice(&(CERTIFICATE_MAX_BYTES as u32 + 1).to_be_bytes());
                body.push(0);
                body
            },
            "over-limit proof length",
            1,
            Some(CERTIFICATE_MAX_BYTES as u32 + 1),
        ),
    ];

    for (body, name, proof_count, proof_length) in cases {
        let directory = TestDirectory::new();
        let (encoded, _) = raw_transaction(genesis_digest(), &body);
        let mut image = JOURNAL_HEADER.to_vec();
        image.extend_from_slice(&encoded);
        directory.write_image(&image);
        let error = match ProofDagJournal::open(&directory.path) {
            Err(error) => error,
            Ok(_) => panic!("case={name}: malformed transaction opened"),
        };
        if let Some(expected_length) = proof_length {
            assert!(
                matches!(
                    &error,
                    JournalError::InvalidTransactionProofLength {
                        transaction: 0,
                        proof: 0,
                        actual,
                        ..
                    } if *actual == expected_length
                ),
                "case={name}: {error:?}"
            );
        } else {
            assert!(
                matches!(
                    &error,
                    JournalError::InvalidTransactionProofCount {
                        transaction: 0,
                        actual,
                        ..
                    } if *actual == proof_count
                ),
                "case={name}: {error:?}"
            );
        }
    }

    for body in [
        vec![1, 0, 0, 0, 2, 0],
        vec![1, 0, 0, 0, 1, 0, 0],
        vec![2, 0, 0, 0, 1, 0],
    ] {
        let directory = TestDirectory::new();
        let (encoded, _) = raw_transaction(genesis_digest(), &body);
        let mut image = JOURNAL_HEADER.to_vec();
        image.extend_from_slice(&encoded);
        directory.write_image(&image);
        assert!(matches!(
            ProofDagJournal::open(&directory.path),
            Err(JournalError::InvalidTransactionBody { transaction: 0, .. })
        ));
    }
}

#[test]
fn digest_valid_batch_replay_enforces_dependency_order_and_root_reachability() {
    let (payloads, _) = dependency_chain();
    let reversed = payloads.iter().cloned().rev().collect::<Vec<_>>();
    let directory = TestDirectory::new();
    let reversed_image = journal_transaction_image(&[reversed]);
    directory.write_image(&reversed_image);
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::Check {
                        source: CheckError::UnknownProofReference { .. },
                    },
                    ..
                }
            )
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), reversed_image);

    let unrelated = axiom_bytes(ZfcAxiom::Union);
    let closure_with_unrelated = vec![payloads[0].clone(), unrelated, payloads[1].clone()];
    let directory = TestDirectory::new();
    let unrelated_image = journal_transaction_image(&[closure_with_unrelated]);
    directory.write_image(&unrelated_image);
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::UnreachableCandidate { index: 1, .. }
            )
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), unrelated_image);
}

#[test]
fn every_batch_payload_and_footer_mutation_fails_the_transaction_digest() {
    let (payloads, _) = dependency_chain();
    let full = journal_transaction_image(std::slice::from_ref(&payloads));
    let transaction_start = JOURNAL_HEADER.len();
    let mut cursor = transaction_start + 4 + 1;
    let mut mutation_offsets = Vec::new();
    for payload in &payloads {
        cursor += 4;
        mutation_offsets.extend(cursor..cursor + payload.len());
        cursor += payload.len();
    }
    mutation_offsets.extend(full.len() - 32..full.len());

    for offset in mutation_offsets {
        let directory = TestDirectory::new();
        let mut mutated = full.clone();
        mutated[offset] ^= 0x01;
        directory.write_image(&mutated);
        assert!(
            matches!(
                ProofDagJournal::open(&directory.path),
                Err(JournalError::TransactionDigestMismatch { transaction: 0, .. })
            ),
            "offset={offset}"
        );
    }
}

#[test]
fn committed_transactions_are_strictly_revalidated_in_physical_order() {
    let malformed = vec![0x00];
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[malformed]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::Decode { .. },
                    ..
                }
            )
    ));

    let noncanonical = certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::ZfcAxiom(ZfcAxiom::Union),
    ])
    .to_canonical_bytes();
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[noncanonical]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::NonCanonicalProof,
                    ..
                }
            )
    ));

    let missing_id = ProofId::from_bytes([0x77; 32]);
    let missing = canonical_bytes(vec![ProofStep::ProofReference {
        proof_id: missing_id,
    }]);
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[missing]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 0, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::Check {
                        source: CheckError::UnknownProofReference { proof_id, .. }
                    },
                    ..
                } if *proof_id == missing_id
            )
    ));

    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[pairing.clone(), pairing]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 1, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::State {
                        source: ProofStateError::DuplicateProof { .. }
                    },
                    ..
                }
            )
    ));

    let pairing = axiom_bytes(ZfcAxiom::Pairing);
    let pairing_id = {
        let mut dag = ProofDag::new();
        dag.apply_canonical_proof_bytes(pairing.clone())
            .unwrap()
            .proof_id()
    };
    let alias = canonical_bytes(vec![ProofStep::ProofReference {
        proof_id: pairing_id,
    }]);
    let directory = TestDirectory::new();
    directory.write_image(&journal_image(&[pairing, alias]));
    assert!(matches!(
        ProofDagJournal::open(&directory.path),
        Err(JournalError::Replay { transaction: 1, source, .. })
            if matches!(
                source.as_ref(),
                ProofBatchError::Candidate {
                    index: 0,
                    source: LedgerError::State {
                        source: ProofStateError::DuplicateDerivation { .. }
                    },
                    ..
                }
            )
    ));
}
