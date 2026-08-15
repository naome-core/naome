use super::*;

#[test]
fn equality_reflexivity_generalization_round_trips_from_canonical_bytes() {
    let x = FreeVariable::new(0x0102_0304);
    let direct = certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ]);
    let decoded = ProofCertificate::from_canonical_bytes(&direct.to_canonical_bytes())
        .expect("the canonical certificate round-trips");

    assert_eq!(check(&direct), check(&decoded));
    assert_eq!(check(&decoded), Ok(closed_equality(x)));
}

#[test]
fn reordered_and_renamed_proofs_share_one_checked_normal_form() {
    let first = identity_proof(FreeVariable::new(7), false);
    let reordered = identity_proof(FreeVariable::new(42), true);
    let first = normalize_and_check(first).unwrap();
    let reordered = normalize_and_check(reordered).unwrap();

    assert_eq!(reordered, first);
    assert_eq!(
        first.normal_form().certificate().to_canonical_bytes(),
        reordered.normal_form().certificate().to_canonical_bytes()
    );
    assert_eq!(first.statement_id(), reordered.statement_id());
    assert_eq!(first.proof_id(), reordered.proof_id());
}

#[test]
fn alternative_derivations_keep_distinct_normal_forms() {
    let x = FreeVariable::new(5);
    let direct = certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ]);
    let detour = identity_proof(x, false);

    let direct = normalize_and_check(direct).unwrap();
    let detour = normalize_and_check(detour).unwrap();

    assert_eq!(direct.conclusion(), detour.conclusion());
    assert_eq!(direct.statement_id(), detour.statement_id());
    assert_ne!(direct.derivation_id(), detour.derivation_id());
    assert_ne!(direct.proof_id(), detour.proof_id());
    assert_ne!(
        direct.normal_form().certificate().to_canonical_bytes(),
        detour.normal_form().certificate().to_canonical_bytes()
    );
}

#[test]
fn content_identity_golden_binds_the_closed_statement_and_normal_proof() {
    let x = FreeVariable::new(42);
    let checked = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ]))
    .unwrap();

    assert_eq!(
        checked.conclusion().encode_canonical().unwrap(),
        [
            0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]
    );
    assert_eq!(
        checked.normal_form().certificate().to_canonical_bytes(),
        [
            0x00, 0x00, 0x00, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]
    );
    assert_eq!(
        checked.statement_id().as_bytes(),
        &[
            0xf9, 0x02, 0xf7, 0x99, 0xc2, 0x4f, 0x06, 0x4e, 0xa9, 0x8b, 0xf7, 0xfa, 0x33, 0xc1,
            0x2c, 0x51, 0x78, 0xf1, 0x72, 0x2f, 0xdf, 0xd9, 0x4b, 0x22, 0x3c, 0x64, 0xea, 0x1a,
            0xa9, 0xae, 0x3d, 0x19,
        ]
    );
    assert_eq!(
        checked.proof_id().as_bytes(),
        &[
            0xc6, 0x17, 0xc9, 0x22, 0x2d, 0xf9, 0x01, 0xd9, 0x94, 0x04, 0x86, 0x8a, 0xab, 0x41,
            0x5e, 0x91, 0x7a, 0xf7, 0x6c, 0xe6, 0x56, 0x99, 0x87, 0x63, 0x42, 0xfe, 0x0c, 0x0f,
            0xf1, 0xe6, 0x2e, 0x73,
        ]
    );
    assert_eq!(
        checked.derivation_id().as_bytes(),
        &[
            0x59, 0x21, 0x9d, 0x63, 0xc7, 0xc2, 0x35, 0x3d, 0xcb, 0x6f, 0xfd, 0x1e, 0x60, 0x41,
            0x53, 0x14, 0x33, 0x80, 0xae, 0x66, 0x02, 0xe0, 0x42, 0x15, 0x70, 0x3b, 0xc0, 0xea,
            0x04, 0x32, 0x43, 0xfb,
        ]
    );
}

#[test]
fn every_inline_reference_partition_has_one_derivation_identity() {
    let baseline = partitioned_weakening_proof(0).0;
    let statement_id = baseline.statement_id();
    let derivation_id = baseline.derivation_id();
    let conclusion = baseline.conclusion().clone();
    let mut proof_ids = BTreeSet::new();

    for cuts in 0..16 {
        let (partitioned, mut state) = partitioned_weakening_proof(cuts);
        let partitioned_proof_id = partitioned.proof_id();
        assert_eq!(partitioned.conclusion(), &conclusion);
        assert_eq!(partitioned.statement_id(), statement_id);
        assert_eq!(partitioned.derivation_id(), derivation_id);
        assert!(proof_ids.insert(partitioned_proof_id));

        let inline = partitioned_weakening_proof(0).0;
        state.register_proof(inline).unwrap();
        let expected = if cuts == 0 {
            ArtifactStateError::DuplicateProof {
                proof_id: partitioned_proof_id,
            }
        } else {
            ArtifactStateError::DuplicateDerivation { derivation_id }
        };
        assert_eq!(state.register_proof(partitioned), Err(expected));
        assert!(!state.contains_proof(partitioned_proof_id) || cuts == 0);
    }

    assert_eq!(proof_ids.len(), 16);
}

#[test]
fn closed_fragment_variable_names_do_not_cross_reference_boundaries() {
    let shared_identifier = FreeVariable::new(7);
    let distinct_outer = FreeVariable::new(42);
    let shared = inline_closed_fragment(shared_identifier, shared_identifier);
    let distinct = inline_closed_fragment(shared_identifier, distinct_outer);

    let source = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity {
            variable: shared_identifier,
        },
        ProofStep::Generalization {
            premise: 0,
            variable: shared_identifier,
        },
    ]))
    .unwrap();
    let source_id = source.proof_id();
    let theorem = source.conclusion().clone();
    let outer = Formula::equal(distinct_outer, distinct_outer);
    let mut state = ArtifactState::new();
    state.register_proof(source).unwrap();
    let referenced = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::ProofReference {
                proof_id: source_id,
            },
            ProofStep::Simplification {
                antecedent: theorem.into(),
                consequent: outer.into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStep::Generalization {
                premise: 2,
                variable: distinct_outer,
            },
        ]),
        &state,
    )
    .unwrap();

    assert_eq!(shared.conclusion(), distinct.conclusion());
    assert_eq!(distinct.conclusion(), referenced.conclusion());
    assert_eq!(shared.derivation_id(), distinct.derivation_id());
    assert_eq!(distinct.derivation_id(), referenced.derivation_id());
    assert_ne!(distinct.proof_id(), referenced.proof_id());
}

#[test]
fn hidden_variable_identifiers_can_be_reused_above_open_fragments() {
    let hidden = FreeVariable::new(7);
    let remaining = FreeVariable::new(42);
    let reused = hidden_variable_proof(hidden, hidden, remaining);
    let fresh = hidden_variable_proof(hidden, FreeVariable::new(99), remaining);

    assert_eq!(reused.conclusion(), fresh.conclusion());
    assert_eq!(reused.statement_id(), fresh.statement_id());
    assert_eq!(reused.derivation_id(), fresh.derivation_id());
    assert_ne!(reused.proof_id(), fresh.proof_id());
}

#[test]
fn statement_identity_is_structural_not_logical_equivalence() {
    let x = FreeVariable::new(3);
    let y = FreeVariable::new(4);
    let once = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ]))
    .unwrap();
    let twice = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
        ProofStep::Generalization {
            premise: 1,
            variable: y,
        },
    ]))
    .unwrap();

    assert_ne!(once.conclusion(), twice.conclusion());
    assert_ne!(once.statement_id(), twice.statement_id());
}

#[test]
fn a_root_proof_reference_resolves_only_from_checked_state() {
    let x = FreeVariable::new(42);
    let source = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ]))
    .unwrap();
    let source_proof_id = source.proof_id();
    let source_derivation_id = source.derivation_id();
    let source_statement_id = source.statement_id();
    let source_conclusion = source.conclusion().clone();
    let reference = || {
        certificate(vec![ProofStep::ProofReference {
            proof_id: source_proof_id,
        }])
    };

    assert_eq!(
        normalize_and_check(reference()),
        Err(CheckError::UnknownProofReference {
            step: 0,
            proof_id: source_proof_id,
        })
    );

    let mut state = ArtifactState::new();
    state.register_proof(source).unwrap();
    let cited = normalize_and_check_with_state(reference(), &state).unwrap();

    assert_eq!(cited.conclusion(), &source_conclusion);
    assert_eq!(cited.statement_id(), source_statement_id);
    assert_eq!(cited.derivation_id(), source_derivation_id);
    assert_eq!(
        cited.normal_form().certificate().to_canonical_bytes(),
        [
            0x00, 0x00, 0x00, 0x01, 0x30, 0xc6, 0x17, 0xc9, 0x22, 0x2d, 0xf9, 0x01, 0xd9, 0x94,
            0x04, 0x86, 0x8a, 0xab, 0x41, 0x5e, 0x91, 0x7a, 0xf7, 0x6c, 0xe6, 0x56, 0x99, 0x87,
            0x63, 0x42, 0xfe, 0x0c, 0x0f, 0xf1, 0xe6, 0x2e, 0x73,
        ]
    );
    assert_eq!(
        cited.proof_id().as_bytes(),
        &[
            0xbf, 0xd4, 0x27, 0xb4, 0x47, 0xe1, 0x51, 0x46, 0x86, 0xcf, 0xa3, 0x1b, 0x0b, 0x5a,
            0xa1, 0xdd, 0x50, 0x36, 0x46, 0x4c, 0xd8, 0xc5, 0xd7, 0x3d, 0x0c, 0x31, 0x12, 0xcb,
            0x46, 0xb0, 0x51, 0x9b,
        ]
    );
    assert!(state.contains_proof(source_proof_id));
}

#[test]
fn unreachable_references_are_pruned_but_direct_check_still_resolves_every_step() {
    let missing = ProofId::from_bytes([0xff; 32]);
    let x = FreeVariable::new(9);
    let proof = || {
        certificate(vec![
            ProofStep::ProofReference { proof_id: missing },
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 1,
                variable: x,
            },
        ])
    };

    assert_eq!(
        check(&proof()),
        Err(CheckError::UnknownProofReference {
            step: 0,
            proof_id: missing,
        })
    );
    let checked = normalize_and_check_with_state(proof(), &ArtifactState::new()).unwrap();
    assert_eq!(checked.conclusion(), &closed_equality(x));
    assert_eq!(checked.normal_form().certificate().steps().len(), 2);
}

#[test]
fn referenced_theorems_participate_in_inference_without_rechecking_their_proof() {
    let x = FreeVariable::new(7);
    let source = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ]))
    .unwrap();
    let source_id = source.proof_id();
    let theorem = source.conclusion().clone();
    let expected = Formula::implies(theorem.clone(), theorem.clone());
    let mut state = ArtifactState::new();
    state.register_proof(source).unwrap();

    let checked = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::ProofReference {
                proof_id: source_id,
            },
            ProofStep::Simplification {
                antecedent: theorem.clone().into(),
                consequent: theorem.into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]),
        &state,
    )
    .unwrap();

    assert_eq!(checked.conclusion(), &expected);
}

#[test]
fn selected_alternative_citations_change_proof_identity_not_statement_identity() {
    let x = FreeVariable::new(5);
    let direct = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ]))
    .unwrap();
    let detour = normalize_and_check(identity_proof(x, false)).unwrap();
    let direct_id = direct.proof_id();
    let detour_id = detour.proof_id();
    let theorem = direct.conclusion().clone();
    let mut state = ArtifactState::new();
    state.register_proof(direct).unwrap();
    state.register_proof(detour).unwrap();

    let dependent = |proof_id| {
        normalize_and_check_with_state(
            certificate(vec![
                ProofStep::ProofReference { proof_id },
                ProofStep::Simplification {
                    antecedent: theorem.clone().into(),
                    consequent: theorem.clone().into(),
                },
                ProofStep::ModusPonens {
                    premise: 0,
                    implication: 1,
                },
            ]),
            &state,
        )
        .unwrap()
    };
    let cites_direct = dependent(direct_id);
    let cites_detour = dependent(detour_id);

    assert_eq!(cites_direct.conclusion(), cites_detour.conclusion());
    assert_eq!(cites_direct.statement_id(), cites_detour.statement_id());
    assert_ne!(cites_direct.derivation_id(), cites_detour.derivation_id());
    assert_ne!(cites_direct.proof_id(), cites_detour.proof_id());
}

#[test]
fn artifact_state_rejects_duplicates_and_remains_dependency_closed() {
    let x = FreeVariable::new(3);
    let checked = || {
        normalize_and_check(certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ]))
        .unwrap()
    };
    let first = checked();
    let proof_id = first.proof_id();
    let derivation_id = first.derivation_id();
    let mut source_state = ArtifactState::new();
    source_state.register_proof(first).unwrap();
    assert_eq!(
        source_state.register_proof(checked()),
        Err(ArtifactStateError::DuplicateProof { proof_id })
    );

    let dependent = normalize_and_check_with_state(
        certificate(vec![ProofStep::ProofReference { proof_id }]),
        &source_state,
    )
    .unwrap();
    assert_eq!(
        ArtifactState::new().register_proof(dependent),
        Err(ArtifactStateError::MissingProofDependency { proof_id })
    );

    let mut target_state = ArtifactState::new();
    target_state.register_proof(checked()).unwrap();
    let cited_alias = normalize_and_check_with_state(
        certificate(vec![ProofStep::ProofReference { proof_id }]),
        &source_state,
    )
    .unwrap();
    let cited_alias_id = cited_alias.proof_id();
    assert_eq!(cited_alias.derivation_id(), derivation_id);
    assert_eq!(
        target_state.register_proof(cited_alias),
        Err(ArtifactStateError::DuplicateDerivation { derivation_id })
    );
    assert!(!target_state.contains_proof(cited_alias_id));
    assert_eq!(
        normalize_and_check_with_state(
            certificate(vec![ProofStep::ProofReference {
                proof_id: cited_alias_id,
            }]),
            &target_state,
        ),
        Err(CheckError::UnknownProofReference {
            step: 0,
            proof_id: cited_alias_id,
        })
    );

    let theorem = closed_equality(x);
    let dependent = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::ProofReference { proof_id },
            ProofStep::Simplification {
                antecedent: theorem.clone().into(),
                consequent: theorem.into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]),
        &source_state,
    )
    .unwrap();
    let dependent_id = dependent.proof_id();
    target_state.register_proof(dependent).unwrap();
    assert!(target_state.contains_proof(dependent_id));
}
