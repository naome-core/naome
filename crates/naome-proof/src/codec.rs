use naome_foundation::{Formula, FreeVariable, Replacement, Separation, ZfcAxiom};

use crate::{
    CERTIFICATE_V0_MAX_BYTES, CERTIFICATE_V0_MAX_STEPS, ProofCertificateError, ProofCertificateV0,
    ProofId, ProofStepV0, validate_step_references,
};

const VERSION: u8 = 0x00;

const SIMPLIFICATION: u8 = 0x00;
const FREGE: u8 = 0x01;
const CLASSICAL_CONTRAPOSITION: u8 = 0x02;
const UNIVERSAL_DISTRIBUTION: u8 = 0x03;
const VACUOUS_UNIVERSAL: u8 = 0x04;
const UNIVERSAL_INSTANTIATION: u8 = 0x05;
const EQUALITY_REFLEXIVITY: u8 = 0x06;
const EQUALITY_SUBSTITUTION: u8 = 0x07;
const ZFC_AXIOM: u8 = 0x10;
const SEPARATION: u8 = 0x11;
const REPLACEMENT: u8 = 0x12;
const MODUS_PONENS: u8 = 0x20;
const GENERALIZATION: u8 = 0x21;
const PROOF_REFERENCE: u8 = 0x30;

pub(super) fn encode_steps(steps: &[ProofStepV0]) -> Result<Vec<u8>, ProofCertificateError> {
    let step_count =
        u32::try_from(steps.len()).expect("ProofCertificateV0 validates its step count");

    let mut output = Vec::new();
    output.push(VERSION);
    write_u32(step_count, &mut output);

    for step in steps {
        encode_step(step, &mut output)?;
        ensure_within_byte_limit(output.len())?;
    }

    Ok(output)
}

pub(super) fn decode(bytes: &[u8]) -> Result<ProofCertificateV0, ProofCertificateError> {
    ensure_within_byte_limit(bytes.len())?;

    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u8()?;
    if version != VERSION {
        return Err(ProofCertificateError::UnsupportedVersion(version));
    }

    let step_count = cursor.read_u32()?;
    if step_count == 0 {
        return Err(ProofCertificateError::EmptyCertificate);
    }
    if step_count as usize > CERTIFICATE_V0_MAX_STEPS {
        return Err(ProofCertificateError::TooManySteps {
            actual: step_count as usize,
            maximum: CERTIFICATE_V0_MAX_STEPS,
        });
    }

    let mut steps = Vec::new();
    for position in 0..step_count {
        let step = decode_step(&mut cursor)?;
        validate_step_references(position, &step)?;
        steps.push(step);
    }

    if cursor.remaining() != 0 {
        return Err(ProofCertificateError::TrailingBytes {
            remaining: cursor.remaining(),
        });
    }

    Ok(ProofCertificateV0 { steps })
}

pub(super) fn encode_step(
    step: &ProofStepV0,
    output: &mut Vec<u8>,
) -> Result<(), ProofCertificateError> {
    match step {
        ProofStepV0::Simplification {
            antecedent,
            consequent,
        } => {
            output.push(SIMPLIFICATION);
            write_formula(antecedent, output)?;
            write_formula(consequent, output)?;
        }
        ProofStepV0::Frege {
            first,
            second,
            third,
        } => {
            output.push(FREGE);
            write_formula(first, output)?;
            write_formula(second, output)?;
            write_formula(third, output)?;
        }
        ProofStepV0::ClassicalContraposition {
            antecedent,
            consequent,
        } => {
            output.push(CLASSICAL_CONTRAPOSITION);
            write_formula(antecedent, output)?;
            write_formula(consequent, output)?;
        }
        ProofStepV0::UniversalDistribution {
            variable,
            antecedent,
            consequent,
        } => {
            output.push(UNIVERSAL_DISTRIBUTION);
            write_variable(*variable, output);
            write_formula(antecedent, output)?;
            write_formula(consequent, output)?;
        }
        ProofStepV0::VacuousUniversal { formula } => {
            output.push(VACUOUS_UNIVERSAL);
            write_formula(formula, output)?;
        }
        ProofStepV0::UniversalInstantiation {
            variable,
            replacement,
            body,
        } => {
            output.push(UNIVERSAL_INSTANTIATION);
            write_variable(*variable, output);
            write_variable(*replacement, output);
            write_formula(body, output)?;
        }
        ProofStepV0::EqualityReflexivity { variable } => {
            output.push(EQUALITY_REFLEXIVITY);
            write_variable(*variable, output);
        }
        ProofStepV0::EqualitySubstitution { from, to, body } => {
            output.push(EQUALITY_SUBSTITUTION);
            write_variable(*from, output);
            write_variable(*to, output);
            write_formula(body, output)?;
        }
        ProofStepV0::ZfcAxiom(axiom) => {
            output.push(ZFC_AXIOM);
            output.push(encode_zfc_axiom(*axiom));
        }
        ProofStepV0::Separation(instance) => {
            output.push(SEPARATION);
            write_formula(&instance.predicate, output)?;
            write_variable(instance.element, output);
            write_variable(instance.source, output);
            write_variable(instance.result, output);
            write_variables(&instance.parameters, output)?;
        }
        ProofStepV0::Replacement(instance) => {
            output.push(REPLACEMENT);
            write_formula(&instance.predicate, output)?;
            write_variable(instance.input, output);
            write_variable(instance.output, output);
            write_variable(instance.uniqueness_witness, output);
            write_variable(instance.source, output);
            write_variable(instance.result, output);
            write_variables(&instance.parameters, output)?;
        }
        ProofStepV0::ProofReference { proof_id } => {
            output.push(PROOF_REFERENCE);
            output.extend_from_slice(proof_id.as_bytes());
        }
        ProofStepV0::ModusPonens {
            premise,
            implication,
        } => {
            output.push(MODUS_PONENS);
            write_u32(*premise, output);
            write_u32(*implication, output);
        }
        ProofStepV0::Generalization { premise, variable } => {
            output.push(GENERALIZATION);
            write_u32(*premise, output);
            write_variable(*variable, output);
        }
    }

    Ok(())
}

fn decode_step(cursor: &mut Cursor<'_>) -> Result<ProofStepV0, ProofCertificateError> {
    match cursor.read_u8()? {
        SIMPLIFICATION => Ok(ProofStepV0::Simplification {
            antecedent: read_formula(cursor)?,
            consequent: read_formula(cursor)?,
        }),
        FREGE => Ok(ProofStepV0::Frege {
            first: read_formula(cursor)?,
            second: read_formula(cursor)?,
            third: read_formula(cursor)?,
        }),
        CLASSICAL_CONTRAPOSITION => Ok(ProofStepV0::ClassicalContraposition {
            antecedent: read_formula(cursor)?,
            consequent: read_formula(cursor)?,
        }),
        UNIVERSAL_DISTRIBUTION => Ok(ProofStepV0::UniversalDistribution {
            variable: read_variable(cursor)?,
            antecedent: read_formula(cursor)?,
            consequent: read_formula(cursor)?,
        }),
        VACUOUS_UNIVERSAL => Ok(ProofStepV0::VacuousUniversal {
            formula: read_formula(cursor)?,
        }),
        UNIVERSAL_INSTANTIATION => Ok(ProofStepV0::UniversalInstantiation {
            variable: read_variable(cursor)?,
            replacement: read_variable(cursor)?,
            body: read_formula(cursor)?,
        }),
        EQUALITY_REFLEXIVITY => Ok(ProofStepV0::EqualityReflexivity {
            variable: read_variable(cursor)?,
        }),
        EQUALITY_SUBSTITUTION => Ok(ProofStepV0::EqualitySubstitution {
            from: read_variable(cursor)?,
            to: read_variable(cursor)?,
            body: read_formula(cursor)?,
        }),
        ZFC_AXIOM => Ok(ProofStepV0::ZfcAxiom(decode_zfc_axiom(cursor.read_u8()?)?)),
        SEPARATION => Ok(ProofStepV0::Separation(Separation {
            predicate: read_formula(cursor)?,
            element: read_variable(cursor)?,
            source: read_variable(cursor)?,
            result: read_variable(cursor)?,
            parameters: read_variables(cursor)?,
        })),
        REPLACEMENT => Ok(ProofStepV0::Replacement(Replacement {
            predicate: read_formula(cursor)?,
            input: read_variable(cursor)?,
            output: read_variable(cursor)?,
            uniqueness_witness: read_variable(cursor)?,
            source: read_variable(cursor)?,
            result: read_variable(cursor)?,
            parameters: read_variables(cursor)?,
        })),
        PROOF_REFERENCE => Ok(ProofStepV0::ProofReference {
            proof_id: ProofId::from_bytes(
                cursor
                    .take(32)?
                    .try_into()
                    .expect("the checked slice has exactly 32 bytes"),
            ),
        }),
        MODUS_PONENS => Ok(ProofStepV0::ModusPonens {
            premise: cursor.read_u32()?,
            implication: cursor.read_u32()?,
        }),
        GENERALIZATION => Ok(ProofStepV0::Generalization {
            premise: cursor.read_u32()?,
            variable: read_variable(cursor)?,
        }),
        tag => Err(ProofCertificateError::UnknownStepTag(tag)),
    }
}

fn write_formula(formula: &Formula, output: &mut Vec<u8>) -> Result<(), ProofCertificateError> {
    let bytes = formula.encode_canonical_v0()?;
    let length = u32::try_from(bytes.len())
        .expect("the canonical V0 formula limit is smaller than u32::MAX");
    ensure_additional_bytes(output.len(), 4 + bytes.len())?;
    write_u32(length, output);
    output.extend_from_slice(&bytes);
    Ok(())
}

fn read_formula(cursor: &mut Cursor<'_>) -> Result<Formula, ProofCertificateError> {
    let length = usize::try_from(cursor.read_u32()?)
        .expect("u32 is representable as usize on supported Rust targets");
    Ok(Formula::decode_canonical_v0(cursor.take(length)?)?)
}

fn write_variables(
    variables: &[FreeVariable],
    output: &mut Vec<u8>,
) -> Result<(), ProofCertificateError> {
    let variable_bytes = variables
        .len()
        .checked_mul(4)
        .and_then(|length| length.checked_add(4))
        .unwrap_or(usize::MAX);
    ensure_additional_bytes(output.len(), variable_bytes)?;
    let count = u32::try_from(variables.len())
        .expect("the certificate byte limit bounds schema parameter counts");
    write_u32(count, output);
    for variable in variables {
        write_variable(*variable, output);
    }
    Ok(())
}

fn read_variables(cursor: &mut Cursor<'_>) -> Result<Vec<FreeVariable>, ProofCertificateError> {
    let count = cursor.read_u32()?;
    let count = usize::try_from(count).expect("u32 is representable on supported Rust targets");
    if count > cursor.remaining() / 4 {
        return Err(ProofCertificateError::UnexpectedEnd);
    }

    let mut variables = Vec::new();
    for _ in 0..count {
        variables.push(read_variable(cursor)?);
    }
    Ok(variables)
}

fn write_variable(variable: FreeVariable, output: &mut Vec<u8>) {
    write_u32(variable.identifier(), output);
}

fn read_variable(cursor: &mut Cursor<'_>) -> Result<FreeVariable, ProofCertificateError> {
    Ok(FreeVariable::new(cursor.read_u32()?))
}

const fn encode_zfc_axiom(axiom: ZfcAxiom) -> u8 {
    match axiom {
        ZfcAxiom::Extensionality => 0x00,
        ZfcAxiom::Pairing => 0x01,
        ZfcAxiom::Union => 0x02,
        ZfcAxiom::PowerSet => 0x03,
        ZfcAxiom::Infinity => 0x04,
        ZfcAxiom::Foundation => 0x05,
        ZfcAxiom::Choice => 0x06,
    }
}

fn decode_zfc_axiom(tag: u8) -> Result<ZfcAxiom, ProofCertificateError> {
    match tag {
        0x00 => Ok(ZfcAxiom::Extensionality),
        0x01 => Ok(ZfcAxiom::Pairing),
        0x02 => Ok(ZfcAxiom::Union),
        0x03 => Ok(ZfcAxiom::PowerSet),
        0x04 => Ok(ZfcAxiom::Infinity),
        0x05 => Ok(ZfcAxiom::Foundation),
        0x06 => Ok(ZfcAxiom::Choice),
        tag => Err(ProofCertificateError::UnknownZfcAxiomTag(tag)),
    }
}

fn write_u32(value: u32, output: &mut Vec<u8>) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn ensure_additional_bytes(current: usize, additional: usize) -> Result<(), ProofCertificateError> {
    let actual = current.saturating_add(additional);
    ensure_within_byte_limit(actual)
}

fn ensure_within_byte_limit(actual: usize) -> Result<(), ProofCertificateError> {
    if actual > CERTIFICATE_V0_MAX_BYTES {
        return Err(ProofCertificateError::InputTooLong {
            actual,
            maximum: CERTIFICATE_V0_MAX_BYTES,
        });
    }

    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, ProofCertificateError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(ProofCertificateError::UnexpectedEnd)?;
        self.position += 1;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, ProofCertificateError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(
            bytes
                .try_into()
                .expect("the checked slice has exactly four bytes"),
        ))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProofCertificateError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ProofCertificateError::UnexpectedEnd)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ProofCertificateError::UnexpectedEnd)?;
        self.position = end;
        Ok(value)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EQUALITY_REFLEXIVITY, MODUS_PONENS, PROOF_REFERENCE, VERSION, ZFC_AXIOM, encode_step,
    };
    use crate::{
        CERTIFICATE_V0_MAX_BYTES, CERTIFICATE_V0_MAX_STEPS, ProofCertificateError,
        ProofCertificateV0, ProofId, ProofStepV0,
    };
    use naome_foundation::{Formula, FreeVariable, Replacement, Separation, ZfcAxiom};

    #[test]
    fn equality_reflexivity_has_stable_big_endian_golden_bytes() {
        let certificate = ProofCertificateV0::new(vec![ProofStepV0::EqualityReflexivity {
            variable: FreeVariable::new(0x0102_0304),
        }])
        .unwrap();

        assert_eq!(
            certificate.to_canonical_bytes(),
            [VERSION, 0, 0, 0, 1, EQUALITY_REFLEXIVITY, 1, 2, 3, 4]
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
        let separation = Separation {
            predicate: Formula::member(x, w),
            element: x,
            source: y,
            result: z,
            parameters: vec![w],
        };
        let replacement = Replacement {
            predicate: Formula::equal(x, y),
            input: x,
            output: y,
            uniqueness_witness: z,
            source: w,
            result: FreeVariable::new(5),
            parameters: vec![],
        };
        let steps = vec![
            ProofStepV0::Simplification {
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            ProofStepV0::Frege {
                first: first.clone(),
                second: second.clone(),
                third: third.clone(),
            },
            ProofStepV0::ClassicalContraposition {
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            ProofStepV0::UniversalDistribution {
                variable: x,
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            ProofStepV0::VacuousUniversal {
                formula: first.clone(),
            },
            ProofStepV0::UniversalInstantiation {
                variable: x,
                replacement: y,
                body: second.clone(),
            },
            ProofStepV0::EqualityReflexivity { variable: x },
            ProofStepV0::EqualitySubstitution {
                from: x,
                to: y,
                body: first,
            },
            ProofStepV0::ZfcAxiom(ZfcAxiom::Extensionality),
            ProofStepV0::Separation(separation),
            ProofStepV0::Replacement(replacement),
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStepV0::Generalization {
                premise: 11,
                variable: x,
            },
            ProofStepV0::ProofReference {
                proof_id: ProofId::from_bytes([0x5a; 32]),
            },
        ];
        let certificate = ProofCertificateV0::new(steps).unwrap();

        let encoded = certificate.to_canonical_bytes();
        let decoded = ProofCertificateV0::from_canonical_bytes(&encoded).unwrap();

        assert_eq!(decoded, certificate);
        assert_eq!(decoded.to_canonical_bytes(), encoded);
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
            &ProofStepV0::Simplification {
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            concatenate(&[&[0x00], &first_field, &second_field]),
        );
        assert_step_bytes(
            &ProofStepV0::Frege {
                first: first.clone(),
                second: second.clone(),
                third: third.clone(),
            },
            concatenate(&[&[0x01], &first_field, &second_field, &third_field]),
        );
        assert_step_bytes(
            &ProofStepV0::ClassicalContraposition {
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            concatenate(&[&[0x02], &first_field, &second_field]),
        );
        assert_step_bytes(
            &ProofStepV0::UniversalDistribution {
                variable: x,
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            concatenate(&[&[0x03, 0x01, 0x02, 0x03, 0x04], &first_field, &second_field]),
        );
        assert_step_bytes(
            &ProofStepV0::VacuousUniversal {
                formula: first.clone(),
            },
            concatenate(&[&[0x04], &first_field]),
        );
        assert_step_bytes(
            &ProofStepV0::UniversalInstantiation {
                variable: x,
                replacement: y,
                body: first.clone(),
            },
            concatenate(&[
                &[0x05, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14],
                &first_field,
            ]),
        );
        assert_step_bytes(
            &ProofStepV0::EqualitySubstitution {
                from: x,
                to: y,
                body: second,
            },
            concatenate(&[
                &[0x07, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14],
                &second_field,
            ]),
        );
        assert_step_bytes(
            &ProofStepV0::Generalization {
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
            let certificate = ProofCertificateV0::new(vec![ProofStepV0::ZfcAxiom(axiom)]).unwrap();
            let encoded = certificate.to_canonical_bytes();

            assert_eq!(encoded, [VERSION, 0, 0, 0, 1, ZFC_AXIOM, tag as u8]);
            assert_eq!(
                ProofCertificateV0::from_canonical_bytes(&encoded).unwrap(),
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

        let separation = ProofCertificateV0::new(vec![ProofStepV0::Separation(Separation {
            predicate: Formula::member(input, source),
            element: input,
            source: output,
            result: witness,
            parameters: vec![source],
        })])
        .unwrap();
        let separation_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x00, 0x31, 0x32, 0x33, 0x34, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13,
            0x14, 0x21, 0x22, 0x23, 0x24, 0x00, 0x00, 0x00, 0x01, 0x31, 0x32, 0x33, 0x34,
        ];
        assert_eq!(separation.to_canonical_bytes(), separation_bytes);
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&separation_bytes).unwrap(),
            separation
        );

        let replacement = ProofCertificateV0::new(vec![ProofStepV0::Replacement(Replacement {
            predicate: Formula::equal(input, output),
            input,
            output,
            uniqueness_witness: witness,
            source,
            result,
            parameters: vec![parameter],
        })])
        .unwrap();
        let replacement_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x12, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x00, 0x11, 0x12, 0x13, 0x14, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13,
            0x14, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43, 0x44, 0x00,
            0x00, 0x00, 0x01, 0x51, 0x52, 0x53, 0x54,
        ];
        assert_eq!(replacement.to_canonical_bytes(), replacement_bytes);
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&replacement_bytes).unwrap(),
            replacement
        );

        for end in 0..replacement_bytes.len() {
            assert!(ProofCertificateV0::from_canonical_bytes(&replacement_bytes[..end]).is_err());
        }
    }

    #[test]
    fn inference_references_have_stable_big_endian_field_order() {
        let mut encoded = Vec::new();
        encode_step(
            &ProofStepV0::ModusPonens {
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
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        let certificate =
            ProofCertificateV0::new(vec![ProofStepV0::ProofReference { proof_id }]).unwrap();
        let expected = [
            VERSION,
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
            ProofCertificateV0::from_canonical_bytes(&expected).unwrap(),
            certificate
        );
        for end in 0..expected.len() {
            assert!(ProofCertificateV0::from_canonical_bytes(&expected[..end]).is_err());
        }
    }

    #[test]
    fn decoder_rejects_every_truncated_golden_prefix_and_trailing_bytes() {
        let certificate = ProofCertificateV0::new(vec![ProofStepV0::EqualityReflexivity {
            variable: FreeVariable::new(7),
        }])
        .unwrap();
        let encoded = certificate.to_canonical_bytes();

        for end in 0..encoded.len() {
            assert!(ProofCertificateV0::from_canonical_bytes(&encoded[..end]).is_err());
        }

        let mut trailing = encoded;
        trailing.push(0xff);
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&trailing),
            Err(ProofCertificateError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn decoder_rejects_unknown_versions_and_tags() {
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&[1]),
            Err(ProofCertificateError::UnsupportedVersion(1))
        );
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&[VERSION, 0, 0, 0, 1, 0xff]),
            Err(ProofCertificateError::UnknownStepTag(0xff))
        );
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&[VERSION, 0, 0, 0, 1, ZFC_AXIOM, 0xff,]),
            Err(ProofCertificateError::UnknownZfcAxiomTag(0xff))
        );
    }

    #[test]
    fn decoder_rejects_empty_extreme_and_non_acyclic_certificates() {
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&[VERSION, 0, 0, 0, 0]),
            Err(ProofCertificateError::EmptyCertificate)
        );
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&[VERSION, 0xff, 0xff, 0xff, 0xff]),
            Err(ProofCertificateError::TooManySteps {
                actual: u32::MAX as usize,
                maximum: CERTIFICATE_V0_MAX_STEPS,
            })
        );

        let self_reference_before_a_missing_second_step =
            [VERSION, 0, 0, 0, 2, MODUS_PONENS, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&self_reference_before_a_missing_second_step,),
            Err(ProofCertificateError::ReferenceNotEarlier {
                step: 0,
                reference: 0,
            })
        );
    }

    #[test]
    fn decoder_enforces_certificate_byte_and_step_limits_before_payload_work() {
        let at_byte_limit = vec![0xff; CERTIFICATE_V0_MAX_BYTES];
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&at_byte_limit),
            Err(ProofCertificateError::UnsupportedVersion(0xff))
        );

        let over_byte_limit = vec![0x00; CERTIFICATE_V0_MAX_BYTES + 1];
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&over_byte_limit),
            Err(ProofCertificateError::InputTooLong {
                actual: CERTIFICATE_V0_MAX_BYTES + 1,
                maximum: CERTIFICATE_V0_MAX_BYTES,
            })
        );

        let excessive_step_count = u32::try_from(CERTIFICATE_V0_MAX_STEPS + 1).unwrap();
        let mut encoded = vec![VERSION];
        encoded.extend_from_slice(&excessive_step_count.to_be_bytes());
        assert_eq!(
            ProofCertificateV0::from_canonical_bytes(&encoded),
            Err(ProofCertificateError::TooManySteps {
                actual: CERTIFICATE_V0_MAX_STEPS + 1,
                maximum: CERTIFICATE_V0_MAX_STEPS,
            })
        );
    }

    #[test]
    fn decoder_propagates_canonical_formula_failures() {
        let dangling_bound_formula = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut encoded = vec![VERSION, 0, 0, 0, 1, super::SIMPLIFICATION, 0, 0, 0, 11];
        encoded.extend_from_slice(&dangling_bound_formula);

        assert!(matches!(
            ProofCertificateV0::from_canonical_bytes(&encoded),
            Err(ProofCertificateError::Formula(_))
        ));
    }

    fn framed_formula(formula: &[u8]) -> Vec<u8> {
        let mut framed = Vec::from(u32::try_from(formula.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(formula);
        framed
    }

    fn concatenate(parts: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for part in parts {
            bytes.extend_from_slice(part);
        }
        bytes
    }

    fn assert_step_bytes(step: &ProofStepV0, expected: Vec<u8>) {
        let mut actual = Vec::new();
        encode_step(step, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }
}
