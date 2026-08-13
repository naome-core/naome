use super::*;

#[test]
fn batch_shape_and_candidate_order_fail_before_mutation() {
    let root = ProofId::from_bytes([0x81; 32]);
    let other = ProofId::from_bytes([0x82; 32]);
    let mut ledger = LedgerState::new();

    assert_eq!(
        ledger.apply_rooted_canonical_proof_batch(root, Vec::new()),
        Err(ProofBatchError::Empty)
    );

    let oversized_count = (0..=PROOF_BATCH_MAX_CANDIDATES)
        .map(|index| {
            AddressedProofCandidate::new(
                ProofId::from_bytes([u8::try_from(index).unwrap(); 32]),
                vec![0],
            )
        })
        .collect();
    assert_eq!(
        ledger.apply_rooted_canonical_proof_batch(root, oversized_count),
        Err(ProofBatchError::TooManyCandidates {
            actual: PROOF_BATCH_MAX_CANDIDATES + 1,
            maximum: PROOF_BATCH_MAX_CANDIDATES,
        })
    );

    assert_eq!(
        ledger.apply_rooted_canonical_proof_batch(
            root,
            vec![
                AddressedProofCandidate::new(root, vec![0]),
                AddressedProofCandidate::new(root, vec![0]),
            ],
        ),
        Err(ProofBatchError::DuplicateExpectedProofId {
            first_index: 0,
            duplicate_index: 1,
            proof_id: root,
        })
    );
    assert_eq!(
        ledger.apply_rooted_canonical_proof_batch(
            root,
            vec![AddressedProofCandidate::new(other, vec![0])],
        ),
        Err(ProofBatchError::RootNotLast {
            requested: root,
            actual: other,
        })
    );
    assert_eq!(
        ledger.apply_rooted_canonical_proof_batch(
            root,
            vec![
                AddressedProofCandidate::new(other, vec![0]),
                AddressedProofCandidate::new(root, Vec::new()),
            ],
        ),
        Err(ProofBatchError::Candidate {
            index: 0,
            expected: Some(other),
            source: LedgerError::Decode {
                source: ProofCertificateError::UnexpectedEnd,
            },
        })
    );
    assert!(!ledger.contains_proof(root));
    assert!(!ledger.contains_proof(other));
}

#[test]
fn addressed_candidate_debug_omits_proof_payload() {
    let candidate =
        AddressedProofCandidate::new(ProofId::from_bytes([0x11; 32]), vec![222, 173, 190, 239]);
    let debug = format!("{candidate:?}");

    assert!(debug.contains("canonical_proof_bytes_len: 4"));
    assert!(debug.contains("expected_proof_id"));
    assert!(!debug.contains("222"));
}

#[test]
fn later_candidate_failures_discard_every_earlier_candidate() {
    let (parent_bytes, parent_id) = axiom_candidate(ZfcAxiom::Pairing);
    let parent_checked =
        normalize_and_check(certificate(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)])).unwrap();
    let (valid_root_bytes, valid_root_id) = axiom_candidate(ZfcAxiom::Union);
    let malformed_expected = ProofId::from_bytes([0x83; 32]);
    let noncanonical_expected = ProofId::from_bytes([0x84; 32]);
    let invalid_expected = ProofId::from_bytes([0x85; 32]);
    let mismatch_expected = ProofId::from_bytes([0x86; 32]);
    let noncanonical = certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::ZfcAxiom(ZfcAxiom::Union),
    ])
    .to_canonical_bytes();
    let invalid = canonical_bytes(certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::ZfcAxiom(ZfcAxiom::Union),
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ]));

    let cases = [
        (
            malformed_expected,
            vec![0],
            LedgerError::Decode {
                source: ProofCertificateError::UnexpectedEnd,
            },
        ),
        (
            noncanonical_expected,
            noncanonical,
            LedgerError::NonCanonicalProof,
        ),
        (
            invalid_expected,
            invalid,
            LedgerError::Check {
                source: CheckError::Logic {
                    step: 2,
                    source: LogicError::ModusPonensMismatch,
                },
            },
        ),
        (
            mismatch_expected,
            valid_root_bytes,
            LedgerError::ProofIdMismatch {
                expected: mismatch_expected,
                actual: valid_root_id,
            },
        ),
    ];

    for (expected, bytes, source) in cases {
        let mut ledger = LedgerState::new();
        assert_eq!(
            ledger.apply_rooted_canonical_proof_batch(
                expected,
                vec![
                    AddressedProofCandidate::new(parent_id, parent_bytes.clone()),
                    AddressedProofCandidate::new(expected, bytes),
                ],
            ),
            Err(ProofBatchError::Candidate {
                index: 1,
                expected: Some(expected),
                source,
            })
        );
        assert!(!ledger.contains_proof(parent_id));
        assert!(!ledger.contains_derivation(parent_checked.derivation_id()));
        assert!(!ledger.contains_statement(parent_checked.statement_id()));
        assert!(!ledger.contains_proof(valid_root_id));
    }
}

#[test]
fn rooted_batch_rejects_smuggling_and_wrong_root_then_retries_cleanly() {
    let (parent_bytes, parent_id) = axiom_candidate(ZfcAxiom::Pairing);
    let (unrelated_bytes, unrelated_id) = axiom_candidate(ZfcAxiom::Union);
    let root_bytes = referenced_generalization_bytes(parent_id, FreeVariable::new(0));
    let mut control = LedgerState::new();
    let _ = control
        .apply_canonical_proof_bytes(parent_bytes.clone())
        .unwrap();
    let root_id = control
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();

    let mut ledger = LedgerState::new();
    assert_eq!(
        ledger.validate_rooted_canonical_proof_batch(
            root_id,
            vec![
                AddressedProofCandidate::new(unrelated_id, unrelated_bytes.clone()),
                AddressedProofCandidate::new(parent_id, parent_bytes.clone()),
                AddressedProofCandidate::new(root_id, root_bytes.clone()),
            ],
        ),
        Err(ProofBatchError::UnreachableCandidate {
            index: 0,
            proof_id: unrelated_id,
        })
    );
    assert_eq!(
        ledger.apply_rooted_canonical_proof_batch(
            root_id,
            vec![
                AddressedProofCandidate::new(unrelated_id, unrelated_bytes),
                AddressedProofCandidate::new(parent_id, parent_bytes.clone()),
                AddressedProofCandidate::new(root_id, root_bytes.clone()),
            ],
        ),
        Err(ProofBatchError::UnreachableCandidate {
            index: 0,
            proof_id: unrelated_id,
        })
    );
    assert!(!ledger.contains_proof(unrelated_id));
    assert!(!ledger.contains_proof(parent_id));
    assert!(!ledger.contains_proof(root_id));

    let wrong_root = ProofId::from_bytes([0x87; 32]);
    assert_eq!(
        ledger.apply_rooted_canonical_proof_batch(
            wrong_root,
            vec![
                AddressedProofCandidate::new(parent_id, parent_bytes.clone()),
                AddressedProofCandidate::new(wrong_root, root_bytes.clone()),
            ],
        ),
        Err(ProofBatchError::Candidate {
            index: 1,
            expected: Some(wrong_root),
            source: LedgerError::ProofIdMismatch {
                expected: wrong_root,
                actual: root_id,
            },
        })
    );
    assert!(!ledger.contains_proof(parent_id));
    assert!(!ledger.contains_proof(root_id));

    let records = ledger
        .apply_rooted_canonical_proof_batch(
            root_id,
            vec![
                AddressedProofCandidate::new(parent_id, parent_bytes),
                AddressedProofCandidate::new(root_id, root_bytes),
            ],
        )
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].proof_id(), parent_id);
    assert_eq!(records[1].proof_id(), root_id);
    assert_eq!(records[1].direct_dependencies(), [parent_id]);
    assert!(ledger.contains_proof(parent_id));
    assert!(ledger.contains_proof(root_id));
}

#[test]
fn rooted_batch_allows_selected_external_dependencies() {
    let (external_bytes, external_id) = axiom_candidate(ZfcAxiom::Union);
    let root_bytes = referenced_generalization_bytes(external_id, FreeVariable::new(2));
    let mut control = LedgerState::new();
    let _ = control
        .apply_canonical_proof_bytes(external_bytes.clone())
        .unwrap();
    let root_id = control
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();
    let mut ledger = LedgerState::new();
    let _ = ledger.apply_canonical_proof_bytes(external_bytes).unwrap();

    let records = ledger
        .apply_rooted_canonical_proof_batch(
            root_id,
            vec![AddressedProofCandidate::new(root_id, root_bytes)],
        )
        .unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].proof_id(), root_id);
    assert_eq!(records[0].direct_dependencies(), [external_id]);
    assert!(ledger.contains_proof(external_id));
    assert!(ledger.contains_proof(root_id));
}

#[test]
fn rooted_batch_validation_matches_application_without_registration() {
    let (parent_bytes, parent_id) = axiom_candidate(ZfcAxiom::Pairing);
    let root_bytes = referenced_generalization_bytes(parent_id, FreeVariable::new(3));
    let mut control = LedgerState::new();
    let _ = control
        .apply_canonical_proof_bytes(parent_bytes.clone())
        .unwrap();
    let root_id = control
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();
    let candidates = || {
        vec![
            AddressedProofCandidate::new(parent_id, parent_bytes.clone()),
            AddressedProofCandidate::new(root_id, root_bytes.clone()),
        ]
    };

    let ledger = LedgerState::new();
    assert_eq!(
        ledger.validate_rooted_canonical_proof_batch(root_id, candidates()),
        Ok(())
    );
    assert_eq!(
        ledger.validate_rooted_canonical_proof_batch(root_id, candidates()),
        Ok(())
    );
    assert!(!ledger.contains_proof(parent_id));
    assert!(!ledger.contains_proof(root_id));

    let mut applied = LedgerState::new();
    let records = applied
        .apply_rooted_canonical_proof_batch(root_id, candidates())
        .unwrap();
    assert_eq!(records.len(), 2);
    assert!(applied.contains_proof(parent_id));
    assert!(applied.contains_proof(root_id));

    let malformed = || {
        vec![
            AddressedProofCandidate::new(parent_id, parent_bytes.clone()),
            AddressedProofCandidate::new(root_id, vec![0]),
        ]
    };
    let validation_error = LedgerState::new()
        .validate_rooted_canonical_proof_batch(root_id, malformed())
        .unwrap_err();
    let application_error = LedgerState::new()
        .apply_rooted_canonical_proof_batch(root_id, malformed())
        .unwrap_err();
    assert_eq!(validation_error, application_error);
}

#[test]
fn duplicate_derivation_rejects_the_complete_rooted_batch() {
    let direct = identity(FreeVariable::new(0));
    let direct_checked = normalize_and_check(direct.clone()).unwrap();
    let direct_id = direct_checked.proof_id();
    let direct_bytes = canonical_bytes(direct);
    let alias = certificate(vec![ProofStep::ProofReference {
        proof_id: direct_id,
    }]);
    let mut control = LedgerState::new();
    let _ = control
        .apply_canonical_proof_bytes(direct_bytes.clone())
        .unwrap();
    let alias_checked =
        normalize_and_check_with_state(alias.clone(), &control.proof_state).unwrap();
    let alias_id = alias_checked.proof_id();
    let alias_bytes = canonical_bytes(alias);
    assert_ne!(alias_id, direct_id);
    assert_eq!(
        alias_checked.derivation_id(),
        direct_checked.derivation_id()
    );

    let mut ledger = LedgerState::new();
    let duplicate_error = ProofBatchError::Candidate {
        index: 1,
        expected: Some(alias_id),
        source: LedgerError::State {
            source: ProofStateError::DuplicateDerivation {
                derivation_id: direct_checked.derivation_id(),
            },
        },
    };
    assert_eq!(
        ledger.validate_rooted_canonical_proof_batch(
            alias_id,
            vec![
                AddressedProofCandidate::new(direct_id, direct_bytes.clone()),
                AddressedProofCandidate::new(alias_id, alias_bytes.clone()),
            ],
        ),
        Err(duplicate_error)
    );
    assert_eq!(
        ledger.apply_rooted_canonical_proof_batch(
            alias_id,
            vec![
                AddressedProofCandidate::new(direct_id, direct_bytes),
                AddressedProofCandidate::new(alias_id, alias_bytes),
            ],
        ),
        Err(ProofBatchError::Candidate {
            index: 1,
            expected: Some(alias_id),
            source: LedgerError::State {
                source: ProofStateError::DuplicateDerivation {
                    derivation_id: direct_checked.derivation_id(),
                },
            },
        })
    );
    assert!(!ledger.contains_proof(direct_id));
    assert!(!ledger.contains_proof(alias_id));
    assert!(!ledger.contains_derivation(direct_checked.derivation_id()));
    assert!(!ledger.contains_statement(direct_checked.statement_id()));
}
