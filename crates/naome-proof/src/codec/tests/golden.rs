use super::*;
use crate::{DefinedFormula, DefinitionId, ProofFormula};
use naome_foundation::FormulaCodecError;

#[test]
fn equality_reflexivity_has_stable_big_endian_golden_bytes() {
    let certificate = ProofCertificate::new(vec![ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(0x0102_0304),
    }])
    .unwrap();

    assert_eq!(
        certificate.to_canonical_bytes(),
        [0, 0, 0, 1, EQUALITY_REFLEXIVITY, 1, 2, 3, 4]
    );
}

#[test]
fn every_step_variant_round_trips_canonically() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let z = FreeVariable::new(3);
    let w = FreeVariable::new(4);
    let first = Formula::equal(x, x);
    let second = Formula::member(x, y);
    let third = Formula::equal(y, y);
    let separation = ProofSeparation {
        predicate: (Formula::member(x, w)).into(),
        element: x,
        source: y,
        result: z,
        parameters: vec![w],
    };
    let replacement = ProofReplacement {
        predicate: (Formula::equal(x, y)).into(),
        input: x,
        output: y,
        uniqueness_witness: z,
        source: w,
        result: FreeVariable::new(5),
        parameters: vec![],
    };
    let steps = vec![
        ProofStep::Simplification {
            antecedent: (first.clone()).into(),
            consequent: (second.clone()).into(),
        },
        ProofStep::Frege {
            first: (first.clone()).into(),
            second: (second.clone()).into(),
            third: (third.clone()).into(),
        },
        ProofStep::ClassicalContraposition {
            antecedent: (first.clone()).into(),
            consequent: (second.clone()).into(),
        },
        ProofStep::UniversalDistribution {
            variable: x,
            antecedent: (first.clone()).into(),
            consequent: (second.clone()).into(),
        },
        ProofStep::VacuousUniversal {
            formula: (first.clone()).into(),
        },
        ProofStep::UniversalInstantiation {
            variable: x,
            replacement: y,
            body: (second.clone()).into(),
        },
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::EqualitySubstitution {
            from: x,
            to: y,
            body: (first).into(),
        },
        ProofStep::ZfcAxiom(ZfcAxiom::Extensionality),
        ProofStep::Separation(separation),
        ProofStep::Replacement(replacement),
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
        ProofStep::Generalization {
            premise: 11,
            variable: x,
        },
        ProofStep::ProofReference {
            proof_id: ProofId::from_bytes([0x5a; 32]),
        },
    ];
    let certificate = ProofCertificate::new(steps).unwrap();

    let encoded = certificate.to_canonical_bytes();
    let decoded = ProofCertificate::from_canonical_bytes(&encoded).unwrap();

    assert_eq!(decoded, certificate);
    assert_eq!(decoded.to_canonical_bytes(), encoded);
}

#[test]
fn definition_application_round_trips_inside_a_proof_formula() {
    let definition_id = DefinitionId::from_bytes([0x7d; DefinitionId::BYTE_LENGTH]);
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let antecedent = DefinedFormula::defined_relation(definition_id, [x, y]);
    let step = ProofStep::Simplification {
        antecedent: ProofFormula::from_defined(antecedent).unwrap(),
        consequent: Formula::equal(x, x).into(),
    };
    let certificate = ProofCertificate::new(vec![step.clone()]).unwrap();

    let encoded = certificate.to_canonical_bytes();

    // step count | simplification tag | antecedent length | defined-relation tag
    assert_eq!(
        &encoded[..10],
        &[0, 0, 0, 1, SIMPLIFICATION, 0, 0, 0, 47, 0x05]
    );
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&encoded).unwrap(),
        certificate
    );
    assert_eq!(step.definition_references(), vec![definition_id]);

    let mut unknown_tag = encoded;
    unknown_tag[9] = 0x06;
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&unknown_tag),
        Err(ProofCertificateError::Formula(
            FormulaCodecError::UnknownFormulaTag(0x06)
        ))
    );
}

#[test]
fn logical_step_payloads_have_stable_field_order() {
    let x = FreeVariable::new(0x0102_0304);
    let y = FreeVariable::new(0x1112_1314);
    let z = FreeVariable::new(0x2122_2324);
    let first = Formula::equal(x, x);
    let second = Formula::member(y, y);
    let third = Formula::equal(z, z);
    let first_field = framed_formula(&[
        0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04,
    ]);
    let second_field = framed_formula(&[
        0x01, 0x00, 0x11, 0x12, 0x13, 0x14, 0x00, 0x11, 0x12, 0x13, 0x14,
    ]);
    let third_field = framed_formula(&[
        0x00, 0x00, 0x21, 0x22, 0x23, 0x24, 0x00, 0x21, 0x22, 0x23, 0x24,
    ]);

    assert_step_bytes(
        &ProofStep::Simplification {
            antecedent: (first.clone()).into(),
            consequent: (second.clone()).into(),
        },
        concatenate(&[&[0x00], &first_field, &second_field]),
    );
    assert_step_bytes(
        &ProofStep::Frege {
            first: (first.clone()).into(),
            second: (second.clone()).into(),
            third: (third.clone()).into(),
        },
        concatenate(&[&[0x01], &first_field, &second_field, &third_field]),
    );
    assert_step_bytes(
        &ProofStep::ClassicalContraposition {
            antecedent: (first.clone()).into(),
            consequent: (second.clone()).into(),
        },
        concatenate(&[&[0x02], &first_field, &second_field]),
    );
    assert_step_bytes(
        &ProofStep::UniversalDistribution {
            variable: x,
            antecedent: (first.clone()).into(),
            consequent: (second.clone()).into(),
        },
        concatenate(&[&[0x03, 0x01, 0x02, 0x03, 0x04], &first_field, &second_field]),
    );
    assert_step_bytes(
        &ProofStep::VacuousUniversal {
            formula: (first.clone()).into(),
        },
        concatenate(&[&[0x04], &first_field]),
    );
    assert_step_bytes(
        &ProofStep::UniversalInstantiation {
            variable: x,
            replacement: y,
            body: (first.clone()).into(),
        },
        concatenate(&[
            &[0x05, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14],
            &first_field,
        ]),
    );
    assert_step_bytes(
        &ProofStep::EqualitySubstitution {
            from: x,
            to: y,
            body: (second).into(),
        },
        concatenate(&[
            &[0x07, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14],
            &second_field,
        ]),
    );
    assert_step_bytes(
        &ProofStep::Generalization {
            premise: 0x3132_3334,
            variable: z,
        },
        vec![0x21, 0x31, 0x32, 0x33, 0x34, 0x21, 0x22, 0x23, 0x24],
    );
}

#[test]
fn all_fixed_zfc_axiom_tags_round_trip() {
    let axioms = [
        ZfcAxiom::Extensionality,
        ZfcAxiom::Pairing,
        ZfcAxiom::Union,
        ZfcAxiom::PowerSet,
        ZfcAxiom::Infinity,
        ZfcAxiom::Foundation,
        ZfcAxiom::Choice,
    ];

    for (tag, axiom) in axioms.into_iter().enumerate() {
        let certificate = ProofCertificate::new(vec![ProofStep::ZfcAxiom(axiom)]).unwrap();
        let encoded = certificate.to_canonical_bytes();

        assert_eq!(encoded, [0, 0, 0, 1, ZFC_AXIOM, tag as u8]);
        assert_eq!(
            ProofCertificate::from_canonical_bytes(&encoded).unwrap(),
            certificate
        );
    }
}

#[test]
fn schema_steps_have_stable_formula_framing_and_field_order() {
    let input = FreeVariable::new(0x0102_0304);
    let output = FreeVariable::new(0x1112_1314);
    let witness = FreeVariable::new(0x2122_2324);
    let source = FreeVariable::new(0x3132_3334);
    let result = FreeVariable::new(0x4142_4344);
    let parameter = FreeVariable::new(0x5152_5354);

    let separation = ProofCertificate::new(vec![ProofStep::Separation(ProofSeparation {
        predicate: (Formula::member(input, source)).into(),
        element: input,
        source: output,
        result: witness,
        parameters: vec![source],
    })])
    .unwrap();
    let separation_bytes = [
        0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x31, 0x32, 0x33, 0x34, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22,
        0x23, 0x24, 0x00, 0x00, 0x00, 0x01, 0x31, 0x32, 0x33, 0x34,
    ];
    assert_eq!(separation.to_canonical_bytes(), separation_bytes);
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&separation_bytes).unwrap(),
        separation
    );

    let replacement = ProofCertificate::new(vec![ProofStep::Replacement(ProofReplacement {
        predicate: (Formula::equal(input, output)).into(),
        input,
        output,
        uniqueness_witness: witness,
        source,
        result,
        parameters: vec![parameter],
    })])
    .unwrap();
    let replacement_bytes = [
        0x00, 0x00, 0x00, 0x01, 0x12, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x11, 0x12, 0x13, 0x14, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22,
        0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x01, 0x51,
        0x52, 0x53, 0x54,
    ];
    assert_eq!(replacement.to_canonical_bytes(), replacement_bytes);
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&replacement_bytes).unwrap(),
        replacement
    );

    for end in 0..replacement_bytes.len() {
        assert!(ProofCertificate::from_canonical_bytes(&replacement_bytes[..end]).is_err());
    }
}

#[test]
fn inference_references_have_stable_big_endian_field_order() {
    let mut encoded = Vec::new();
    encode_step(
        &ProofStep::ModusPonens {
            premise: 0x0102_0304,
            implication: 0x0506_0708,
        },
        &mut encoded,
    )
    .unwrap();

    assert_eq!(
        encoded,
        [0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    );
}

#[test]
fn proof_reference_has_one_fixed_width_canonical_representation() {
    let proof_id = ProofId::from_bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ]);
    let certificate = ProofCertificate::new(vec![ProofStep::ProofReference { proof_id }]).unwrap();
    let expected = [
        0,
        0,
        0,
        1,
        PROOF_REFERENCE,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1a,
        0x1b,
        0x1c,
        0x1d,
        0x1e,
        0x1f,
    ];

    assert_eq!(certificate.to_canonical_bytes(), expected);
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&expected).unwrap(),
        certificate
    );
    for end in 0..expected.len() {
        assert!(ProofCertificate::from_canonical_bytes(&expected[..end]).is_err());
    }
}
