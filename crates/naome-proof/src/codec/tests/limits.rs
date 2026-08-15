use super::*;

#[test]
fn decoder_rejects_every_truncated_golden_prefix_and_trailing_bytes() {
    let certificate = ProofCertificate::new(vec![ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(7),
    }])
    .unwrap();
    let encoded = certificate.to_canonical_bytes();

    for end in 0..encoded.len() {
        assert!(ProofCertificate::from_canonical_bytes(&encoded[..end]).is_err());
    }

    let mut trailing = encoded;
    trailing.push(0xff);
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&trailing),
        Err(ProofCertificateError::TrailingBytes { remaining: 1 })
    );
}

#[test]
fn decoder_rejects_unknown_tags_and_legacy_prefixes() {
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&[1]),
        Err(ProofCertificateError::UnexpectedEnd)
    );
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0xff]),
        Err(ProofCertificateError::UnknownStepTag(0xff))
    );
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, ZFC_AXIOM, 0xff,]),
        Err(ProofCertificateError::UnknownZfcAxiomTag(0xff))
    );
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&[0, 0, 0, 0, 1, ZFC_AXIOM, 0x01]),
        Err(ProofCertificateError::EmptyCertificate)
    );
}

#[test]
fn removed_envelope_prefixes_cannot_bypass_step_count_decoding() {
    for encoded in [[0, 0, 0, 1, 0], [0, 0, 1, 0, 0]] {
        assert_eq!(
            ProofCertificate::from_canonical_bytes(&encoded),
            Err(ProofCertificateError::UnexpectedEnd)
        );
    }
}

#[test]
fn decoder_rejects_empty_extreme_and_non_acyclic_certificates() {
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&[0, 0, 0, 0]),
        Err(ProofCertificateError::EmptyCertificate)
    );
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&[0xff, 0xff, 0xff, 0xff]),
        Err(ProofCertificateError::TooManySteps {
            actual: u32::MAX as usize,
            maximum: CERTIFICATE_MAX_STEPS,
        })
    );

    let self_reference_before_a_missing_second_step =
        [0, 0, 0, 2, MODUS_PONENS, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&self_reference_before_a_missing_second_step,),
        Err(ProofCertificateError::ReferenceNotEarlier {
            step: 0,
            reference: 0,
        })
    );
}

#[test]
fn decoder_enforces_certificate_byte_and_step_limits_before_payload_work() {
    let at_byte_limit = vec![0xff; CERTIFICATE_MAX_BYTES];
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&at_byte_limit),
        Err(ProofCertificateError::TooManySteps {
            actual: u32::MAX as usize,
            maximum: CERTIFICATE_MAX_STEPS,
        })
    );

    let over_byte_limit = vec![0x00; CERTIFICATE_MAX_BYTES + 1];
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&over_byte_limit),
        Err(ProofCertificateError::InputTooLong {
            actual: CERTIFICATE_MAX_BYTES + 1,
            maximum: CERTIFICATE_MAX_BYTES,
        })
    );

    let maximum_step_count = u32::try_from(CERTIFICATE_MAX_STEPS).unwrap();
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&maximum_step_count.to_be_bytes()),
        Err(ProofCertificateError::UnexpectedEnd)
    );

    let excessive_step_count = u32::try_from(CERTIFICATE_MAX_STEPS + 1).unwrap();
    let encoded = excessive_step_count.to_be_bytes();
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&encoded),
        Err(ProofCertificateError::TooManySteps {
            actual: CERTIFICATE_MAX_STEPS + 1,
            maximum: CERTIFICATE_MAX_STEPS,
        })
    );
}

#[test]
fn certificate_formula_node_budget_spans_steps_and_fields() {
    let half_limit = half_limit_formula();
    let leaf = Formula::equal(FreeVariable::new(9), FreeVariable::new(9));
    let exact = ProofCertificate::new(vec![
        ProofStep::VacuousUniversal {
            formula: (half_limit.clone()).into(),
        },
        ProofStep::VacuousUniversal {
            formula: (half_limit.clone()).into(),
        },
    ])
    .unwrap();
    let exact_bytes = exact.to_canonical_bytes();

    assert_eq!(CERTIFICATE_MAX_FORMULA_NODES, 65_536);
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&exact_bytes).unwrap(),
        exact
    );

    let across_steps = vec![
        ProofStep::VacuousUniversal {
            formula: (half_limit.clone()).into(),
        },
        ProofStep::VacuousUniversal {
            formula: (half_limit.clone()).into(),
        },
        ProofStep::VacuousUniversal {
            formula: (leaf.clone()).into(),
        },
    ];
    assert_eq!(
        ProofCertificate::new(across_steps),
        Err(ProofCertificateError::FormulaNodeLimitExceeded {
            maximum: CERTIFICATE_MAX_FORMULA_NODES,
        })
    );

    let half_bytes = half_limit.encode_canonical().unwrap();
    let leaf_bytes = leaf.encode_canonical().unwrap();
    let across_steps_bytes = raw_certificate(&[
        raw_formula_step(VACUOUS_UNIVERSAL, &[&half_bytes]),
        raw_formula_step(VACUOUS_UNIVERSAL, &[&half_bytes]),
        raw_formula_step(VACUOUS_UNIVERSAL, &[&leaf_bytes]),
    ]);
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&across_steps_bytes),
        Err(ProofCertificateError::FormulaNodeLimitExceeded {
            maximum: CERTIFICATE_MAX_FORMULA_NODES,
        })
    );

    let across_fields = ProofStep::Frege {
        first: (half_limit.clone()).into(),
        second: (half_limit).into(),
        third: (leaf).into(),
    };
    assert_eq!(
        ProofCertificate::new(vec![across_fields]),
        Err(ProofCertificateError::FormulaNodeLimitExceeded {
            maximum: CERTIFICATE_MAX_FORMULA_NODES,
        })
    );
    let across_fields_bytes = raw_certificate(&[raw_formula_step(
        FREGE,
        &[&half_bytes, &half_bytes, &leaf_bytes],
    )]);
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&across_fields_bytes),
        Err(ProofCertificateError::FormulaNodeLimitExceeded {
            maximum: CERTIFICATE_MAX_FORMULA_NODES,
        })
    );

    let invalid_suffix_bytes = raw_certificate(&[
        raw_formula_step(VACUOUS_UNIVERSAL, &[&half_bytes]),
        raw_formula_step(VACUOUS_UNIVERSAL, &[&half_bytes]),
        raw_formula_step(VACUOUS_UNIVERSAL, &[&[0xff]]),
    ]);
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&invalid_suffix_bytes),
        Err(ProofCertificateError::FormulaNodeLimitExceeded {
            maximum: CERTIFICATE_MAX_FORMULA_NODES,
        })
    );
}

#[test]
fn every_formula_step_field_uses_the_shared_node_budget() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let leaf = Formula::equal(x, y);
    let cases = [
        (
            ProofStep::Simplification {
                antecedent: (leaf.clone()).into(),
                consequent: (leaf.clone()).into(),
            },
            2,
        ),
        (
            ProofStep::Frege {
                first: (leaf.clone()).into(),
                second: (leaf.clone()).into(),
                third: (leaf.clone()).into(),
            },
            3,
        ),
        (
            ProofStep::ClassicalContraposition {
                antecedent: (leaf.clone()).into(),
                consequent: (leaf.clone()).into(),
            },
            2,
        ),
        (
            ProofStep::UniversalDistribution {
                variable: x,
                antecedent: (leaf.clone()).into(),
                consequent: (leaf.clone()).into(),
            },
            2,
        ),
        (
            ProofStep::VacuousUniversal {
                formula: (leaf.clone()).into(),
            },
            1,
        ),
        (
            ProofStep::UniversalInstantiation {
                variable: x,
                replacement: y,
                body: (leaf.clone()).into(),
            },
            1,
        ),
        (
            ProofStep::EqualitySubstitution {
                from: x,
                to: y,
                body: (leaf.clone()).into(),
            },
            1,
        ),
        (
            ProofStep::Separation(ProofSeparation {
                predicate: (leaf.clone()).into(),
                element: x,
                source: y,
                result: x,
                parameters: Vec::new(),
            }),
            1,
        ),
        (
            ProofStep::Replacement(ProofReplacement {
                predicate: (leaf).into(),
                input: x,
                output: y,
                uniqueness_witness: x,
                source: y,
                result: x,
                parameters: Vec::new(),
            }),
            1,
        ),
    ];

    for (step, formula_fields) in cases {
        let expected = ProofCertificateError::FormulaNodeLimitExceeded {
            maximum: CERTIFICATE_MAX_FORMULA_NODES,
        };
        let mut remaining = formula_fields - 1;
        assert_eq!(
            encode_step_with_formula_budget(&step, &mut Vec::new(), &mut remaining),
            Err(expected.clone()),
            "encode omitted a formula field for {step:?}"
        );

        let mut encoded = Vec::new();
        encode_step(&step, &mut encoded).unwrap();
        let mut cursor = Cursor::new(&encoded);
        let mut remaining = formula_fields - 1;
        assert_eq!(
            decode_step(&mut cursor, &mut remaining),
            Err(expected),
            "decode omitted a formula field for {step:?}"
        );
    }
}

#[test]
fn byte_limit_attack_shaped_certificate_stops_at_the_cumulative_node_budget() {
    let mut formula = vec![0x02; 255];
    formula.extend_from_slice(&[0x00, 0x00, 0, 0, 0, 0, 0x00, 0, 0, 0, 0]);
    assert_eq!(formula.len(), 266);

    let formula_step_bytes = 1 + 4 + formula.len();
    let formula_steps = (CERTIFICATE_MAX_BYTES - 4 - 33) / formula_step_bytes;
    let framed_formula_step = raw_formula_step(VACUOUS_UNIVERSAL, &[&formula]);
    let mut encoded = Vec::with_capacity(CERTIFICATE_MAX_BYTES);
    encoded.extend_from_slice(&u32::try_from(formula_steps + 1).unwrap().to_be_bytes());
    for _ in 0..formula_steps {
        encoded.extend_from_slice(&framed_formula_step);
    }
    encoded.push(PROOF_REFERENCE);
    encoded.extend_from_slice(&[0; 32]);

    assert_eq!(encoded.len(), CERTIFICATE_MAX_BYTES);
    assert_eq!(formula_steps * 256, 3_962_112);
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&encoded),
        Err(ProofCertificateError::FormulaNodeLimitExceeded {
            maximum: CERTIFICATE_MAX_FORMULA_NODES,
        })
    );
}

#[test]
fn decoder_propagates_canonical_formula_failures() {
    let dangling_bound_formula = [
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut encoded = vec![0, 0, 0, 1, super::SIMPLIFICATION, 0, 0, 0, 11];
    encoded.extend_from_slice(&dangling_bound_formula);

    assert!(matches!(
        ProofCertificate::from_canonical_bytes(&encoded),
        Err(ProofCertificateError::Formula(_))
    ));
}
