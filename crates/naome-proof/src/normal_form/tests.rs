use naome_foundation::{Formula, FreeVariable, Replacement, Separation, ZfcAxiom};

use crate::{CERTIFICATE_MAX_STEPS, ProofCertificate, ProofId, ProofStep};

#[test]
fn topological_order_and_free_variable_names_do_not_change_the_normal_form() {
    let first = identity_proof(FreeVariable::new(7), false).into_unchecked_normal_form();
    let reordered = identity_proof(FreeVariable::new(42), true).into_unchecked_normal_form();

    assert_eq!(
        first.certificate().to_canonical_bytes(),
        reordered.certificate().to_canonical_bytes()
    );
    assert_eq!(
        first.certificate().steps(),
        identity_proof(FreeVariable::new(0), false).steps()
    );
}

#[test]
fn normal_form_golden_prunes_renames_deduplicates_and_remaps_references() {
    let first = [
        0x00, 0x00, 0x00, 0x06, 0x10, 0x01, 0x06, 0x00, 0x00, 0x00, 0x07, 0x06, 0x00, 0x00, 0x00,
        0x07, 0x21, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x21, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x07, 0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
    ];
    let reordered = [
        0x00, 0x00, 0x00, 0x06, 0x06, 0x00, 0x00, 0x00, 0x2a, 0x10, 0x06, 0x21, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x2a, 0x06, 0x00, 0x00, 0x00, 0x2a, 0x21, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x2a, 0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04,
    ];
    let expected = [
        0x00, 0x00, 0x00, 0x03, 0x06, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    ];

    for encoded in [&first[..], &reordered[..]] {
        let normal = ProofCertificate::from_canonical_bytes(encoded)
            .unwrap()
            .into_unchecked_normal_form();
        assert_eq!(normal.certificate().to_canonical_bytes(), expected);
    }
}

#[test]
fn exact_reachable_nodes_are_shared_without_sorting_dependency_roles() {
    let x = FreeVariable::new(9);
    let duplicate = duplicate_identity_proof(x);
    let original_steps = duplicate.steps().len();
    let original_bytes = duplicate.to_canonical_bytes().len();
    let normal = duplicate.into_unchecked_normal_form();

    assert_eq!(original_steps, 9);
    assert_eq!(normal.certificate().steps().len(), 7);
    assert!(normal.certificate().to_canonical_bytes().len() < original_bytes);
    assert!(matches!(
        normal.certificate().steps()[2],
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        }
    ));
    assert!(matches!(
        normal.certificate().steps()[5],
        ProofStep::ModusPonens {
            premise: 2,
            implication: 4,
        }
    ));

    let formula = Formula::equal(x, x);
    let correct = certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Simplification {
            antecedent: formula.clone(),
            consequent: formula,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ])
    .into_unchecked_normal_form();
    let swapped = certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Simplification {
            antecedent: Formula::equal(x, x),
            consequent: Formula::equal(x, x),
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 0,
        },
    ])
    .into_unchecked_normal_form();

    assert_ne!(
        correct.certificate().to_canonical_bytes(),
        swapped.certificate().to_canonical_bytes()
    );
}

#[test]
fn proof_reference_leaves_deduplicate_only_by_exact_proof_id() {
    let first_id = ProofId::from_bytes([0x11; 32]);
    let second_id = ProofId::from_bytes([0x22; 32]);
    let duplicate = certificate(vec![
        ProofStep::ProofReference { proof_id: first_id },
        ProofStep::ProofReference { proof_id: first_id },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ])
    .into_unchecked_normal_form();
    let distinct = certificate(vec![
        ProofStep::ProofReference { proof_id: first_id },
        ProofStep::ProofReference {
            proof_id: second_id,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ])
    .into_unchecked_normal_form();

    assert_eq!(duplicate.certificate().steps().len(), 2);
    assert!(matches!(
        duplicate.certificate().steps()[1],
        ProofStep::ModusPonens {
            premise: 0,
            implication: 0,
        }
    ));
    assert_eq!(distinct.certificate().steps().len(), 3);
    assert_ne!(
        duplicate.certificate().to_canonical_bytes(),
        distinct.certificate().to_canonical_bytes()
    );
}

#[test]
fn unreachable_steps_are_removed_and_normalization_is_idempotent() {
    let x = FreeVariable::new(13);
    let certificate = certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 1,
            variable: x,
        },
    ]);
    let original_bytes = certificate.to_canonical_bytes().len();
    let normal = certificate.into_unchecked_normal_form();

    assert_eq!(normal.certificate().steps().len(), 2);
    assert!(normal.canonical_bytes().len() < original_bytes);
    assert_eq!(
        normal.canonical_bytes(),
        normal.certificate().to_canonical_bytes()
    );

    let first_bytes = normal.canonical_bytes().to_vec();
    let second_bytes = normal
        .certificate()
        .clone()
        .into_unchecked_normal_form()
        .into_canonical_bytes();
    assert_eq!(second_bytes.as_ref(), first_bytes);
}

#[test]
fn equal_conclusions_with_different_derivations_remain_different_proofs() {
    let x = FreeVariable::new(4);
    let direct = certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ])
    .into_unchecked_normal_form();
    let detour = identity_proof(x, false).into_unchecked_normal_form();

    assert_ne!(
        direct.certificate().to_canonical_bytes(),
        detour.certificate().to_canonical_bytes()
    );
}

#[test]
fn every_non_reference_step_payload_is_normalized_in_wire_order() {
    let a = FreeVariable::new(10);
    let b = FreeVariable::new(20);
    let c = FreeVariable::new(30);
    let d = FreeVariable::new(40);
    let e = FreeVariable::new(50);
    let f = FreeVariable::new(60);
    let g = FreeVariable::new(70);
    let h = FreeVariable::new(80);
    let n = FreeVariable::new;
    let cases = vec![
        (
            ProofStep::Simplification {
                antecedent: Formula::member(b, a),
                consequent: Formula::equal(c, b),
            },
            ProofStep::Simplification {
                antecedent: Formula::member(n(0), n(1)),
                consequent: Formula::equal(n(2), n(0)),
            },
        ),
        (
            ProofStep::Frege {
                first: Formula::equal(a, b),
                second: Formula::member(c, a),
                third: Formula::equal(d, c),
            },
            ProofStep::Frege {
                first: Formula::equal(n(0), n(1)),
                second: Formula::member(n(2), n(0)),
                third: Formula::equal(n(3), n(2)),
            },
        ),
        (
            ProofStep::ClassicalContraposition {
                antecedent: Formula::member(b, a),
                consequent: Formula::equal(c, b),
            },
            ProofStep::ClassicalContraposition {
                antecedent: Formula::member(n(0), n(1)),
                consequent: Formula::equal(n(2), n(0)),
            },
        ),
        (
            ProofStep::UniversalDistribution {
                variable: c,
                antecedent: Formula::equal(a, b),
                consequent: Formula::member(b, c),
            },
            ProofStep::UniversalDistribution {
                variable: n(0),
                antecedent: Formula::equal(n(1), n(2)),
                consequent: Formula::member(n(2), n(0)),
            },
        ),
        (
            ProofStep::VacuousUniversal {
                formula: Formula::implies(Formula::equal(a, b), Formula::member(c, a)),
            },
            ProofStep::VacuousUniversal {
                formula: Formula::implies(Formula::equal(n(0), n(1)), Formula::member(n(2), n(0))),
            },
        ),
        (
            ProofStep::UniversalInstantiation {
                variable: c,
                replacement: a,
                body: Formula::member(b, c),
            },
            ProofStep::UniversalInstantiation {
                variable: n(0),
                replacement: n(1),
                body: Formula::member(n(2), n(0)),
            },
        ),
        (
            ProofStep::EqualityReflexivity { variable: a },
            ProofStep::EqualityReflexivity { variable: n(0) },
        ),
        (
            ProofStep::EqualitySubstitution {
                from: b,
                to: c,
                body: Formula::implies(Formula::member(a, b), Formula::equal(c, a)),
            },
            ProofStep::EqualitySubstitution {
                from: n(0),
                to: n(1),
                body: Formula::implies(Formula::member(n(2), n(0)), Formula::equal(n(1), n(2))),
            },
        ),
        (
            ProofStep::ZfcAxiom(ZfcAxiom::Choice),
            ProofStep::ZfcAxiom(ZfcAxiom::Choice),
        ),
        (
            ProofStep::Separation(Separation {
                predicate: Formula::equal(c, b),
                element: a,
                source: d,
                result: e,
                parameters: vec![b, f, a],
            }),
            ProofStep::Separation(Separation {
                predicate: Formula::equal(n(0), n(1)),
                element: n(2),
                source: n(3),
                result: n(4),
                parameters: vec![n(1), n(5), n(2)],
            }),
        ),
        (
            ProofStep::Replacement(Replacement {
                predicate: Formula::member(d, c),
                input: b,
                output: e,
                uniqueness_witness: a,
                source: f,
                result: g,
                parameters: vec![c, h, b],
            }),
            ProofStep::Replacement(Replacement {
                predicate: Formula::member(n(0), n(1)),
                input: n(2),
                output: n(3),
                uniqueness_witness: n(4),
                source: n(5),
                result: n(6),
                parameters: vec![n(1), n(7), n(2)],
            }),
        ),
    ];

    for (input, expected) in cases {
        let normal = certificate(vec![input]).into_unchecked_normal_form();
        assert_eq!(normal.certificate().steps(), [expected]);
    }
}

#[test]
fn maximum_step_chain_normalizes_iteratively() {
    let x = FreeVariable::new(u32::MAX);
    let mut steps = Vec::with_capacity(CERTIFICATE_MAX_STEPS);
    steps.push(ProofStep::EqualityReflexivity { variable: x });
    while steps.len() < CERTIFICATE_MAX_STEPS {
        let premise = u32::try_from(steps.len() - 1).unwrap();
        steps.push(ProofStep::Generalization {
            premise,
            variable: x,
        });
    }

    let normal = certificate(steps).into_unchecked_normal_form();
    assert_eq!(normal.certificate().steps().len(), CERTIFICATE_MAX_STEPS);
}

fn identity_proof(variable: FreeVariable, reordered: bool) -> ProofCertificate {
    let formula = Formula::equal(variable, variable);
    let axiom = ProofStep::Simplification {
        antecedent: formula.clone(),
        consequent: formula,
    };
    let reflexivity = ProofStep::EqualityReflexivity { variable };
    let mut steps = if reordered {
        vec![axiom, reflexivity]
    } else {
        vec![reflexivity, axiom]
    };
    let (premise, implication) = if reordered { (1, 0) } else { (0, 1) };
    steps.push(ProofStep::ModusPonens {
        premise,
        implication,
    });
    steps.push(ProofStep::ModusPonens {
        premise,
        implication: 2,
    });
    steps.push(ProofStep::Generalization {
        premise: 3,
        variable,
    });
    certificate(steps)
}

fn duplicate_identity_proof(variable: FreeVariable) -> ProofCertificate {
    let equality = Formula::equal(variable, variable);
    let identity = Formula::implies(equality.clone(), equality.clone());
    certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Simplification {
            antecedent: equality.clone(),
            consequent: equality,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 2,
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
        ProofStep::Simplification {
            antecedent: identity.clone(),
            consequent: identity,
        },
        ProofStep::ModusPonens {
            premise: 3,
            implication: 5,
        },
        ProofStep::ModusPonens {
            premise: 4,
            implication: 6,
        },
        ProofStep::Generalization {
            premise: 7,
            variable,
        },
    ])
}

fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
    ProofCertificate::new(steps).expect("the test proof is structurally valid")
}
