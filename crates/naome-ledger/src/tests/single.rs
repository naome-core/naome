use super::*;

#[test]
fn canonical_bytes_match_authoring_admission_and_duplicate_semantics() {
    let variable = FreeVariable::new(42);
    let bytes = canonical_bytes(identity(variable));
    let mut strict = LedgerState::new();
    let strict_applied = strict.apply_canonical_proof_bytes(bytes.clone()).unwrap();

    let mut authoring = LedgerState::new();
    let authoring_applied = authoring.apply(identity(variable)).unwrap();
    assert_eq!(strict_applied, authoring_applied);
    assert!(
        strict
            .proof_state()
            .contains_proof(strict_applied.proof_id())
    );
    assert_eq!(strict_applied.canonical_proof_bytes(), bytes);
    assert!(strict_applied.direct_proof_dependencies().is_empty());
    assert_eq!(
        strict.apply_canonical_proof_bytes(bytes),
        Err(LedgerError::State {
            source: ArtifactStateError::DuplicateProof {
                proof_id: strict_applied.proof_id(),
            },
        })
    );
}

#[test]
fn expected_proof_id_is_checked_before_registration_and_duplicate_state() {
    let variable = FreeVariable::new(41);
    let bytes = canonical_bytes(identity(variable));
    let checked = normalize_and_check(identity(variable)).unwrap();
    let actual = checked.proof_id();
    let expected = ProofId::from_bytes([0x91; 32]);
    assert_ne!(expected, actual);
    let mut ledger = LedgerState::new();

    let mismatch = ledger
        .apply_canonical_proof_bytes_with_expected_id(bytes.clone(), expected)
        .unwrap_err();
    assert_eq!(
        mismatch,
        LedgerError::ArtifactIdMismatch {
            expected: ArtifactId::from_proof_id(expected),
            actual: ArtifactId::from_proof_id(actual),
        }
    );
    assert!(mismatch.source().is_none());
    assert!(!ledger.contains_proof(actual));
    assert!(!ledger.contains_derivation(checked.derivation_id()));
    assert!(!ledger.contains_statement(checked.statement_id()));

    let applied = ledger
        .apply_canonical_proof_bytes_with_expected_id(bytes.clone(), actual)
        .unwrap();
    assert_eq!(applied.proof_id(), actual);
    assert_eq!(applied.canonical_proof_bytes(), bytes);

    assert_eq!(
        ledger.apply_canonical_proof_bytes_with_expected_id(bytes.clone(), expected),
        Err(LedgerError::ArtifactIdMismatch {
            expected: ArtifactId::from_proof_id(expected),
            actual: ArtifactId::from_proof_id(actual),
        })
    );
    assert_eq!(
        ledger.apply_canonical_proof_bytes_with_expected_id(bytes, actual),
        Err(LedgerError::State {
            source: ArtifactStateError::DuplicateProof { proof_id: actual },
        })
    );
}

#[test]
fn addressed_validation_matches_single_admission_without_mutating() {
    let bytes = canonical_bytes(identity(FreeVariable::new(41)));
    let checked = normalize_and_check(identity(FreeVariable::new(41))).unwrap();
    let proof_id = checked.proof_id();
    let mut ledger = LedgerState::new();

    ledger
        .validate_canonical_proof_bytes_with_expected_id(bytes.clone(), proof_id)
        .unwrap();
    ledger
        .validate_canonical_proof_bytes_with_expected_id(bytes.clone(), proof_id)
        .unwrap();
    assert!(!ledger.contains_proof(proof_id));
    assert!(!ledger.contains_derivation(checked.derivation_id()));
    assert!(!ledger.contains_statement(checked.statement_id()));

    let _ = ledger
        .apply_canonical_proof_bytes_with_expected_id(bytes.clone(), proof_id)
        .unwrap();
    let expected = Err(LedgerError::State {
        source: ArtifactStateError::DuplicateProof { proof_id },
    });
    assert_eq!(
        ledger.validate_canonical_proof_bytes_with_expected_id(bytes, proof_id),
        expected
    );
    assert!(ledger.contains_proof(proof_id));
    assert!(ledger.contains_derivation(checked.derivation_id()));
    assert!(ledger.contains_statement(checked.statement_id()));
}

#[test]
fn validation_errors_precede_expected_proof_id_binding() {
    let expected = ProofId::from_bytes([0x92; 32]);
    let variable = FreeVariable::new(0);
    let noncanonical = identity(FreeVariable::new(42)).to_canonical_bytes();
    let invalid_inference = canonical_bytes(certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::ZfcAxiom(ZfcAxiom::Union),
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ]));
    let missing = ProofId::from_bytes([0x93; 32]);
    let missing_reference = canonical_bytes(certificate(vec![ProofStep::ProofReference {
        proof_id: missing,
    }]));
    let mut ledger = LedgerState::new();

    assert_eq!(
        ledger.apply_canonical_proof_bytes_with_expected_id(vec![0], expected),
        Err(LedgerError::Decode {
            source: ArtifactPayloadError::Proof(ProofCertificateError::UnexpectedEnd),
        })
    );
    assert_eq!(
        ledger.apply_canonical_proof_bytes_with_expected_id(noncanonical, expected),
        Err(LedgerError::NonCanonicalProof)
    );
    assert_eq!(
        ledger.apply_canonical_proof_bytes_with_expected_id(invalid_inference, expected),
        Err(LedgerError::ProofCheck {
            source: CheckError::Logic {
                step: 2,
                source: LogicError::ModusPonensMismatch,
            },
        })
    );
    assert_eq!(
        ledger.apply_canonical_proof_bytes_with_expected_id(missing_reference, expected),
        Err(LedgerError::ProofCheck {
            source: CheckError::UnknownProofReference {
                step: 0,
                proof_id: missing,
            },
        })
    );

    let valid = canonical_bytes(identity(variable));
    let actual = normalize_and_check(identity(variable)).unwrap().proof_id();
    assert!(
        ledger
            .apply_canonical_proof_bytes_with_expected_id(valid, actual)
            .is_ok()
    );
}

#[test]
fn representation_mutations_are_noncanonical_and_atomic() {
    let zero = FreeVariable::new(0);
    let result = FreeVariable::new(3);
    let cases = [
        ("renamed free variable", identity(FreeVariable::new(42))),
        (
            "alternate topological order",
            reordered_identity_detour(zero),
        ),
        (
            "unreachable valid step",
            certificate(vec![
                ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
                ProofStep::EqualityReflexivity { variable: zero },
                ProofStep::Generalization {
                    premise: 1,
                    variable: zero,
                },
            ]),
        ),
        (
            "unreachable invalid step",
            certificate(vec![
                ProofStep::Separation(
                    Separation {
                        predicate: Formula::equal(result, result),
                        element: FreeVariable::new(1),
                        source: FreeVariable::new(2),
                        result,
                        parameters: Vec::new(),
                    }
                    .into(),
                ),
                ProofStep::EqualityReflexivity { variable: zero },
                ProofStep::Generalization {
                    premise: 1,
                    variable: zero,
                },
            ]),
        ),
        ("reachable duplicate nodes", duplicate_identity(zero)),
    ];

    for (name, certificate) in cases {
        let submitted = certificate.to_canonical_bytes();
        let canonical = canonical_bytes(certificate);
        assert_ne!(submitted, canonical, "{name}");

        let mut ledger = LedgerState::new();
        assert_eq!(
            ledger.apply_canonical_proof_bytes(submitted),
            Err(LedgerError::NonCanonicalProof),
            "{name}"
        );
        let applied = ledger
            .apply_canonical_proof_bytes(canonical)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(ledger.contains_proof(applied.proof_id()));
    }
}

#[test]
fn decode_errors_precede_canonicality_without_mutation() {
    let valid = canonical_bytes(identity(FreeVariable::new(0)));
    let mut trailing = valid.clone();
    trailing.push(0);
    let over_limit = vec![0; CERTIFICATE_MAX_BYTES + 1];
    let cases = [
        (
            &[0][..],
            ArtifactPayloadError::Proof(ProofCertificateError::UnexpectedEnd),
        ),
        (
            trailing.as_slice(),
            ArtifactPayloadError::Proof(ProofCertificateError::TrailingBytes { remaining: 1 }),
        ),
        (
            over_limit.as_slice(),
            ArtifactPayloadError::InputTooLong {
                actual: CERTIFICATE_MAX_BYTES + 2,
                maximum: CERTIFICATE_MAX_BYTES + 1,
            },
        ),
    ];

    let mut ledger = LedgerState::new();
    for (bytes, source) in cases {
        let error = ledger
            .apply_canonical_proof_bytes(bytes.to_vec())
            .unwrap_err();
        assert_eq!(error, LedgerError::Decode { source });
        assert!(error.source().is_some());
    }
    let applied = ledger.apply_canonical_proof_bytes(valid).unwrap();
    assert!(ledger.contains_proof(applied.proof_id()));
}

#[test]
fn canonicality_precedes_reachable_reference_checking() {
    let missing = ProofId::from_bytes([0x44; 32]);
    let invalid_inference = canonical_bytes(certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::ZfcAxiom(ZfcAxiom::Union),
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ]));
    let submitted = certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::ProofReference { proof_id: missing },
    ]);
    let canonical = canonical_bytes(submitted.clone());
    let mut ledger = LedgerState::new();

    assert_eq!(
        ledger.apply_canonical_proof_bytes(submitted.to_canonical_bytes()),
        Err(LedgerError::NonCanonicalProof)
    );
    assert_eq!(
        ledger.apply_canonical_proof_bytes(canonical),
        Err(LedgerError::ProofCheck {
            source: CheckError::UnknownProofReference {
                step: 0,
                proof_id: missing,
            },
        })
    );
    assert_eq!(
        ledger.apply_canonical_proof_bytes(invalid_inference),
        Err(LedgerError::ProofCheck {
            source: CheckError::Logic {
                step: 2,
                source: LogicError::ModusPonensMismatch,
            },
        })
    );
}

#[test]
fn canonical_five_reference_proof_requires_complete_pre_transition_state() {
    let axioms = [
        ZfcAxiom::Extensionality,
        ZfcAxiom::Pairing,
        ZfcAxiom::Union,
        ZfcAxiom::PowerSet,
        ZfcAxiom::Infinity,
    ];
    let parents = axioms
        .iter()
        .copied()
        .map(|axiom| {
            let proof = certificate(vec![ProofStep::ZfcAxiom(axiom)]);
            let proof_id = normalize_and_check(proof.clone()).unwrap().proof_id();
            (canonical_bytes(proof), proof_id, axiom.formula())
        })
        .collect::<Vec<_>>();
    let references = parents
        .iter()
        .map(|(_, proof_id, conclusion)| (*proof_id, conclusion.clone()))
        .collect::<Vec<_>>();
    let target = proof_using_every_reference(&references, ZfcAxiom::Choice);
    let target_bytes = canonical_bytes(target);
    let mut ledger = LedgerState::new();

    for (bytes, _, _) in &parents[..parents.len() - 1] {
        let _ = ledger.apply_canonical_proof_bytes(bytes.clone()).unwrap();
    }
    assert_eq!(
        ledger.apply_canonical_proof_bytes(target_bytes.clone()),
        Err(LedgerError::ProofCheck {
            source: CheckError::UnknownProofReference {
                step: 4,
                proof_id: parents[4].1,
            },
        })
    );

    let _ = ledger
        .apply_canonical_proof_bytes(parents[4].0.clone())
        .unwrap();
    let applied = ledger
        .apply_canonical_proof_bytes(target_bytes.clone())
        .unwrap();
    assert_eq!(applied.canonical_proof_bytes(), target_bytes);
    assert_eq!(
        applied.direct_proof_dependencies(),
        parents
            .iter()
            .map(|(_, proof_id, _)| *proof_id)
            .collect::<Vec<_>>()
    );
    assert!(ledger.contains_proof(applied.proof_id()));
}

#[test]
fn records_keep_only_unique_direct_dependencies_and_replay_in_dependency_order() {
    let source_proof = certificate(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)]);
    let source_bytes = canonical_bytes(source_proof);
    let mut original = LedgerState::new();
    let source = original.apply_canonical_proof_bytes(source_bytes).unwrap();
    let repeated = vec![
        (source.proof_id(), ZfcAxiom::Pairing.formula()),
        (source.proof_id(), ZfcAxiom::Pairing.formula()),
    ];
    let child_bytes = canonical_bytes(proof_using_every_reference(&repeated, ZfcAxiom::Choice));
    let child = original.apply_canonical_proof_bytes(child_bytes).unwrap();
    assert_eq!(child.direct_proof_dependencies(), [source.proof_id()]);

    let grandchild_bytes = canonical_bytes(proof_using_every_reference(
        &[(child.proof_id(), ZfcAxiom::Choice.formula())],
        ZfcAxiom::Infinity,
    ));
    let grandchild = original
        .apply_canonical_proof_bytes(grandchild_bytes)
        .unwrap();
    assert_eq!(grandchild.direct_proof_dependencies(), [child.proof_id()]);
    assert!(
        !grandchild
            .direct_proof_dependencies()
            .contains(&source.proof_id())
    );

    let mut replay = LedgerState::new();
    assert_eq!(
        replay.apply_canonical_proof_bytes(child.canonical_proof_bytes().to_vec()),
        Err(LedgerError::ProofCheck {
            source: CheckError::UnknownProofReference {
                step: 0,
                proof_id: source.proof_id(),
            },
        })
    );
    let replayed_source = replay
        .apply_canonical_proof_bytes(source.canonical_proof_bytes().to_vec())
        .unwrap();
    let replayed_child = replay
        .apply_canonical_proof_bytes(child.canonical_proof_bytes().to_vec())
        .unwrap();
    let replayed_grandchild = replay
        .apply_canonical_proof_bytes(grandchild.canonical_proof_bytes().to_vec())
        .unwrap();
    assert_eq!(replayed_source, source);
    assert_eq!(replayed_child, child);
    assert_eq!(replayed_grandchild, grandchild);
}

#[test]
fn authoring_record_excludes_unreachable_unknown_dependencies() {
    let missing = ProofId::from_bytes([0x77; 32]);
    let expected_bytes = canonical_bytes(certificate(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)]));
    let candidate = certificate(vec![
        ProofStep::ProofReference { proof_id: missing },
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
    ]);
    let mut ledger = LedgerState::new();

    let record = ledger.apply(candidate).unwrap();

    assert_eq!(record.canonical_proof_bytes(), expected_bytes);
    assert!(record.direct_proof_dependencies().is_empty());
    assert!(!ledger.contains_proof(missing));
    assert!(ledger.contains_proof(record.proof_id()));
}

#[test]
fn alternative_derivations_share_a_statement_and_register_distinct_identities() {
    let variable = FreeVariable::new(7);
    let mut ledger = LedgerState::new();

    let direct = ledger.apply(identity(variable)).unwrap();
    assert!(ledger.contains_proof(direct.proof_id()));
    assert!(ledger.contains_derivation(direct.derivation_id()));
    assert!(ledger.contains_statement(direct.statement_id()));

    let detour = ledger.apply(identity_detour(variable)).unwrap();
    assert_eq!(detour.statement_id(), direct.statement_id());
    assert_ne!(detour.derivation_id(), direct.derivation_id());
    assert_ne!(detour.proof_id(), direct.proof_id());
    assert!(ledger.contains_proof(detour.proof_id()));
    assert!(ledger.contains_derivation(detour.derivation_id()));
}

#[test]
fn accepted_record_content_is_independent_of_the_selected_state() {
    let variable = FreeVariable::new(7);
    let direct_bytes = canonical_bytes(identity(variable));

    let mut absent = LedgerState::new();
    let new = absent
        .apply_canonical_proof_bytes(direct_bytes.clone())
        .unwrap();

    let mut present = LedgerState::new();
    let detour = present.apply(identity_detour(variable)).unwrap();
    let existing = present.apply_canonical_proof_bytes(direct_bytes).unwrap();

    assert_eq!(existing.statement_id(), detour.statement_id());
    assert_eq!(new, existing);
}

#[test]
fn references_resolve_only_from_the_selected_pre_transition_state() {
    let variable = FreeVariable::new(9);
    let mut selected = LedgerState::new();
    let source = selected.apply(identity(variable)).unwrap();
    let dependent = referenced_generalization(source.proof_id(), variable);

    let mut independent = LedgerState::new();
    assert_eq!(
        independent.apply(dependent.clone()),
        Err(LedgerError::ProofCheck {
            source: CheckError::UnknownProofReference {
                step: 0,
                proof_id: source.proof_id(),
            },
        })
    );
    assert!(!independent.contains_proof(source.proof_id()));

    let applied = selected.apply(dependent).unwrap();
    assert!(selected.contains_proof(applied.proof_id()));
    assert!(!independent.contains_proof(applied.proof_id()));
}

#[test]
fn one_proof_can_use_five_members_of_the_pre_transition_state() {
    let axioms = [
        ZfcAxiom::Extensionality,
        ZfcAxiom::Pairing,
        ZfcAxiom::Union,
        ZfcAxiom::PowerSet,
        ZfcAxiom::Infinity,
    ];
    let mut ledger = LedgerState::new();
    let references = axioms
        .iter()
        .copied()
        .map(|axiom| {
            let applied = ledger
                .apply(certificate(vec![ProofStep::ZfcAxiom(axiom)]))
                .unwrap();
            (applied.proof_id(), axiom.formula())
        })
        .collect::<Vec<_>>();
    let proof = proof_using_every_reference(&references, ZfcAxiom::Choice);
    assert_eq!(proof.steps().len(), 21);

    let applied = ledger.apply(proof.clone()).unwrap();
    assert!(ledger.contains_proof(applied.proof_id()));

    for missing in 0..references.len() {
        let mut incomplete = LedgerState::new();
        for (index, axiom) in axioms.iter().copied().enumerate() {
            if index == missing {
                continue;
            }

            let accepted = incomplete
                .apply(certificate(vec![ProofStep::ZfcAxiom(axiom)]))
                .unwrap();
            assert_eq!(accepted.proof_id(), references[index].0);
        }

        assert!(matches!(
            incomplete.apply(proof.clone()),
            Err(LedgerError::ProofCheck {
                source: CheckError::UnknownProofReference { proof_id, .. }
            }) if proof_id == references[missing].0
        ));
        for (index, (proof_id, _)) in references.iter().enumerate() {
            assert_eq!(incomplete.contains_proof(*proof_id), index != missing);
        }
        assert!(!incomplete.contains_proof(applied.proof_id()));
    }
}

#[test]
fn duplicate_artifacts_and_reference_aliases_leave_state_unchanged() {
    let variable = FreeVariable::new(11);
    let mut ledger = LedgerState::new();
    let source = ledger.apply(identity(variable)).unwrap();

    assert_eq!(
        ledger.apply(identity(FreeVariable::new(42))),
        Err(LedgerError::State {
            source: ArtifactStateError::DuplicateProof {
                proof_id: source.proof_id(),
            },
        })
    );
    let alias = certificate(vec![ProofStep::ProofReference {
        proof_id: source.proof_id(),
    }]);
    let alias_id = normalize_and_check_with_state(alias.clone(), ledger.proof_state())
        .unwrap()
        .proof_id();
    let alias_bytes = canonical_bytes(alias.clone());
    assert_eq!(
        ledger.apply(alias),
        Err(LedgerError::State {
            source: ArtifactStateError::DuplicateDerivation {
                derivation_id: source.derivation_id(),
            },
        })
    );
    let wrong_expected = ProofId::from_bytes([0x94; 32]);
    assert_ne!(wrong_expected, alias_id);
    let mismatch =
        ledger.apply_canonical_proof_bytes_with_expected_id(alias_bytes.clone(), wrong_expected);
    assert_eq!(
        mismatch,
        Err(LedgerError::ArtifactIdMismatch {
            expected: ArtifactId::from_proof_id(wrong_expected),
            actual: ArtifactId::from_proof_id(alias_id),
        })
    );
    assert_eq!(
        ledger.apply_canonical_proof_bytes_with_expected_id(alias_bytes, alias_id),
        Err(LedgerError::State {
            source: ArtifactStateError::DuplicateDerivation {
                derivation_id: source.derivation_id(),
            },
        })
    );

    assert!(!ledger.contains_proof(alias_id));
    assert!(ledger.contains_proof(source.proof_id()));
    assert!(ledger.contains_derivation(source.derivation_id()));
    assert!(ledger.contains_statement(source.statement_id()));
}

#[test]
fn checker_and_registration_errors_expose_sources_without_partial_updates() {
    let variable = FreeVariable::new(13);
    let mut ledger = LedgerState::new();
    let open = certificate(vec![ProofStep::EqualityReflexivity { variable }]);
    let open_error = ledger.apply(open).unwrap_err();
    assert!(matches!(
        open_error,
        LedgerError::ProofCheck {
            source: CheckError::OpenConclusion { step: 0 }
        }
    ));
    assert!(open_error.source().is_some());
    assert!(open_error.to_string().contains("proof checking failed"));

    let applied = ledger.apply(identity(variable)).unwrap();
    let duplicate_error = ledger.apply(identity(variable)).unwrap_err();
    assert!(matches!(
        duplicate_error,
        LedgerError::State {
            source: ArtifactStateError::DuplicateProof { .. }
        }
    ));
    assert!(duplicate_error.source().is_some());
    assert!(
        duplicate_error
            .to_string()
            .contains("artifact registration failed")
    );
    assert!(ledger.contains_proof(applied.proof_id()));
    assert!(ledger.contains_derivation(applied.derivation_id()));
    assert!(ledger.contains_statement(applied.statement_id()));
}
