use naome_foundation::{
    Formula, FormulaCodecError, FreeVariable, Replacement, Separation, ZfcAxiom,
};

use crate::{
    CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_FORMULA_NODES, CERTIFICATE_MAX_STEPS,
    CLASSICAL_CONTRAPOSITION, EQUALITY_REFLEXIVITY, EQUALITY_SUBSTITUTION, FREGE, GENERALIZATION,
    MODUS_PONENS, PROOF_REFERENCE, ProofCertificate, ProofCertificateError, ProofId, ProofStep,
    REPLACEMENT, SEPARATION, SIMPLIFICATION, UNIVERSAL_DISTRIBUTION, UNIVERSAL_INSTANTIATION,
    VACUOUS_UNIVERSAL, ZFC_AXIOM, validate_step_references,
};

pub(super) fn encode_steps(steps: &[ProofStep]) -> Result<Vec<u8>, ProofCertificateError> {
    let step_count = u32::try_from(steps.len()).expect("ProofCertificate validates its step count");

    let mut output = Vec::new();
    let mut remaining_formula_nodes = CERTIFICATE_MAX_FORMULA_NODES;
    write_u32(step_count, &mut output);

    for step in steps {
        encode_step_with_formula_budget(step, &mut output, &mut remaining_formula_nodes)?;
        ensure_within_byte_limit(output.len())?;
    }

    Ok(output)
}

pub(super) fn decode(bytes: &[u8]) -> Result<ProofCertificate, ProofCertificateError> {
    ensure_within_byte_limit(bytes.len())?;

    let mut cursor = Cursor::new(bytes);
    let step_count = cursor.read_u32()?;
    if step_count == 0 {
        return Err(ProofCertificateError::EmptyCertificate);
    }
    if step_count as usize > CERTIFICATE_MAX_STEPS {
        return Err(ProofCertificateError::TooManySteps {
            actual: step_count as usize,
            maximum: CERTIFICATE_MAX_STEPS,
        });
    }

    let mut steps = Vec::new();
    let mut remaining_formula_nodes = CERTIFICATE_MAX_FORMULA_NODES;
    for position in 0..step_count {
        let step = decode_step(&mut cursor, &mut remaining_formula_nodes)?;
        validate_step_references(position, &step)?;
        steps.push(step);
    }

    if cursor.remaining() != 0 {
        return Err(ProofCertificateError::TrailingBytes {
            remaining: cursor.remaining(),
        });
    }

    Ok(ProofCertificate { steps })
}

pub(super) fn encode_step(
    step: &ProofStep,
    output: &mut Vec<u8>,
) -> Result<(), ProofCertificateError> {
    let mut remaining_formula_nodes = CERTIFICATE_MAX_FORMULA_NODES;
    encode_step_with_formula_budget(step, output, &mut remaining_formula_nodes)
}

fn encode_step_with_formula_budget(
    step: &ProofStep,
    output: &mut Vec<u8>,
    remaining_formula_nodes: &mut usize,
) -> Result<(), ProofCertificateError> {
    output.push(step.canonical_tag());
    match step {
        ProofStep::Simplification {
            antecedent,
            consequent,
        } => {
            write_formula(antecedent, output, remaining_formula_nodes)?;
            write_formula(consequent, output, remaining_formula_nodes)?;
        }
        ProofStep::Frege {
            first,
            second,
            third,
        } => {
            write_formula(first, output, remaining_formula_nodes)?;
            write_formula(second, output, remaining_formula_nodes)?;
            write_formula(third, output, remaining_formula_nodes)?;
        }
        ProofStep::ClassicalContraposition {
            antecedent,
            consequent,
        } => {
            write_formula(antecedent, output, remaining_formula_nodes)?;
            write_formula(consequent, output, remaining_formula_nodes)?;
        }
        ProofStep::UniversalDistribution {
            variable,
            antecedent,
            consequent,
        } => {
            write_variable(*variable, output);
            write_formula(antecedent, output, remaining_formula_nodes)?;
            write_formula(consequent, output, remaining_formula_nodes)?;
        }
        ProofStep::VacuousUniversal { formula } => {
            write_formula(formula, output, remaining_formula_nodes)?;
        }
        ProofStep::UniversalInstantiation {
            variable,
            replacement,
            body,
        } => {
            write_variable(*variable, output);
            write_variable(*replacement, output);
            write_formula(body, output, remaining_formula_nodes)?;
        }
        ProofStep::EqualityReflexivity { variable } => {
            write_variable(*variable, output);
        }
        ProofStep::EqualitySubstitution { from, to, body } => {
            write_variable(*from, output);
            write_variable(*to, output);
            write_formula(body, output, remaining_formula_nodes)?;
        }
        ProofStep::ZfcAxiom(axiom) => {
            output.push(encode_zfc_axiom(*axiom));
        }
        ProofStep::Separation(instance) => {
            write_formula(&instance.predicate, output, remaining_formula_nodes)?;
            write_variable(instance.element, output);
            write_variable(instance.source, output);
            write_variable(instance.result, output);
            write_variables(&instance.parameters, output)?;
        }
        ProofStep::Replacement(instance) => {
            write_formula(&instance.predicate, output, remaining_formula_nodes)?;
            write_variable(instance.input, output);
            write_variable(instance.output, output);
            write_variable(instance.uniqueness_witness, output);
            write_variable(instance.source, output);
            write_variable(instance.result, output);
            write_variables(&instance.parameters, output)?;
        }
        ProofStep::ProofReference { proof_id } => {
            output.extend_from_slice(proof_id.as_bytes());
        }
        ProofStep::ModusPonens {
            premise,
            implication,
        } => {
            write_u32(*premise, output);
            write_u32(*implication, output);
        }
        ProofStep::Generalization { premise, variable } => {
            write_u32(*premise, output);
            write_variable(*variable, output);
        }
    }

    Ok(())
}

fn decode_step(
    cursor: &mut Cursor<'_>,
    remaining_formula_nodes: &mut usize,
) -> Result<ProofStep, ProofCertificateError> {
    match cursor.read_u8()? {
        SIMPLIFICATION => Ok(ProofStep::Simplification {
            antecedent: read_formula(cursor, remaining_formula_nodes)?,
            consequent: read_formula(cursor, remaining_formula_nodes)?,
        }),
        FREGE => Ok(ProofStep::Frege {
            first: read_formula(cursor, remaining_formula_nodes)?,
            second: read_formula(cursor, remaining_formula_nodes)?,
            third: read_formula(cursor, remaining_formula_nodes)?,
        }),
        CLASSICAL_CONTRAPOSITION => Ok(ProofStep::ClassicalContraposition {
            antecedent: read_formula(cursor, remaining_formula_nodes)?,
            consequent: read_formula(cursor, remaining_formula_nodes)?,
        }),
        UNIVERSAL_DISTRIBUTION => Ok(ProofStep::UniversalDistribution {
            variable: read_variable(cursor)?,
            antecedent: read_formula(cursor, remaining_formula_nodes)?,
            consequent: read_formula(cursor, remaining_formula_nodes)?,
        }),
        VACUOUS_UNIVERSAL => Ok(ProofStep::VacuousUniversal {
            formula: read_formula(cursor, remaining_formula_nodes)?,
        }),
        UNIVERSAL_INSTANTIATION => Ok(ProofStep::UniversalInstantiation {
            variable: read_variable(cursor)?,
            replacement: read_variable(cursor)?,
            body: read_formula(cursor, remaining_formula_nodes)?,
        }),
        EQUALITY_REFLEXIVITY => Ok(ProofStep::EqualityReflexivity {
            variable: read_variable(cursor)?,
        }),
        EQUALITY_SUBSTITUTION => Ok(ProofStep::EqualitySubstitution {
            from: read_variable(cursor)?,
            to: read_variable(cursor)?,
            body: read_formula(cursor, remaining_formula_nodes)?,
        }),
        ZFC_AXIOM => Ok(ProofStep::ZfcAxiom(decode_zfc_axiom(cursor.read_u8()?)?)),
        SEPARATION => Ok(ProofStep::Separation(Separation {
            predicate: read_formula(cursor, remaining_formula_nodes)?,
            element: read_variable(cursor)?,
            source: read_variable(cursor)?,
            result: read_variable(cursor)?,
            parameters: read_variables(cursor)?,
        })),
        REPLACEMENT => Ok(ProofStep::Replacement(Replacement {
            predicate: read_formula(cursor, remaining_formula_nodes)?,
            input: read_variable(cursor)?,
            output: read_variable(cursor)?,
            uniqueness_witness: read_variable(cursor)?,
            source: read_variable(cursor)?,
            result: read_variable(cursor)?,
            parameters: read_variables(cursor)?,
        })),
        PROOF_REFERENCE => Ok(ProofStep::ProofReference {
            proof_id: ProofId::from_bytes(
                cursor
                    .take(32)?
                    .try_into()
                    .expect("the checked slice has exactly 32 bytes"),
            ),
        }),
        MODUS_PONENS => Ok(ProofStep::ModusPonens {
            premise: cursor.read_u32()?,
            implication: cursor.read_u32()?,
        }),
        GENERALIZATION => Ok(ProofStep::Generalization {
            premise: cursor.read_u32()?,
            variable: read_variable(cursor)?,
        }),
        tag => Err(ProofCertificateError::UnknownStepTag(tag)),
    }
}

fn write_formula(
    formula: &Formula,
    output: &mut Vec<u8>,
    remaining_formula_nodes: &mut usize,
) -> Result<(), ProofCertificateError> {
    let (bytes, used_nodes) = formula
        .encode_canonical_with_node_limit(*remaining_formula_nodes)
        .map_err(map_formula_error)?;
    *remaining_formula_nodes = remaining_formula_nodes
        .checked_sub(used_nodes)
        .expect("Formula reports no more nodes than the supplied limit");
    let length =
        u32::try_from(bytes.len()).expect("the canonical formula limit is smaller than u32::MAX");
    ensure_additional_bytes(output.len(), 4 + bytes.len())?;
    write_u32(length, output);
    output.extend_from_slice(&bytes);
    Ok(())
}

fn read_formula(
    cursor: &mut Cursor<'_>,
    remaining_formula_nodes: &mut usize,
) -> Result<Formula, ProofCertificateError> {
    let length = usize::try_from(cursor.read_u32()?)
        .expect("u32 is representable as usize on supported Rust targets");
    let (formula, used_nodes) =
        Formula::decode_canonical_with_node_limit(cursor.take(length)?, *remaining_formula_nodes)
            .map_err(map_formula_error)?;
    *remaining_formula_nodes = remaining_formula_nodes
        .checked_sub(used_nodes)
        .expect("Formula reports no more nodes than the supplied limit");
    Ok(formula)
}

fn map_formula_error(source: FormulaCodecError) -> ProofCertificateError {
    match source {
        FormulaCodecError::NodeLimitExceeded { .. } => {
            ProofCertificateError::FormulaNodeLimitExceeded {
                maximum: CERTIFICATE_MAX_FORMULA_NODES,
            }
        }
        source => ProofCertificateError::Formula(source),
    }
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
    if actual > CERTIFICATE_MAX_BYTES {
        return Err(ProofCertificateError::InputTooLong {
            actual,
            maximum: CERTIFICATE_MAX_BYTES,
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
        Cursor, EQUALITY_REFLEXIVITY, FREGE, MODUS_PONENS, PROOF_REFERENCE, VACUOUS_UNIVERSAL,
        ZFC_AXIOM, decode_step, encode_step, encode_step_with_formula_budget,
    };
    use crate::{
        CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_FORMULA_NODES, CERTIFICATE_MAX_STEPS,
        ProofCertificate, ProofCertificateError, ProofId, ProofStep,
    };
    use naome_foundation::{Formula, FreeVariable, Replacement, Separation, ZfcAxiom};

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
            ProofStep::Simplification {
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            ProofStep::Frege {
                first: first.clone(),
                second: second.clone(),
                third: third.clone(),
            },
            ProofStep::ClassicalContraposition {
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            ProofStep::UniversalDistribution {
                variable: x,
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            ProofStep::VacuousUniversal {
                formula: first.clone(),
            },
            ProofStep::UniversalInstantiation {
                variable: x,
                replacement: y,
                body: second.clone(),
            },
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::EqualitySubstitution {
                from: x,
                to: y,
                body: first,
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
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            concatenate(&[&[0x00], &first_field, &second_field]),
        );
        assert_step_bytes(
            &ProofStep::Frege {
                first: first.clone(),
                second: second.clone(),
                third: third.clone(),
            },
            concatenate(&[&[0x01], &first_field, &second_field, &third_field]),
        );
        assert_step_bytes(
            &ProofStep::ClassicalContraposition {
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            concatenate(&[&[0x02], &first_field, &second_field]),
        );
        assert_step_bytes(
            &ProofStep::UniversalDistribution {
                variable: x,
                antecedent: first.clone(),
                consequent: second.clone(),
            },
            concatenate(&[&[0x03, 0x01, 0x02, 0x03, 0x04], &first_field, &second_field]),
        );
        assert_step_bytes(
            &ProofStep::VacuousUniversal {
                formula: first.clone(),
            },
            concatenate(&[&[0x04], &first_field]),
        );
        assert_step_bytes(
            &ProofStep::UniversalInstantiation {
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
            &ProofStep::EqualitySubstitution {
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

        let separation = ProofCertificate::new(vec![ProofStep::Separation(Separation {
            predicate: Formula::member(input, source),
            element: input,
            source: output,
            result: witness,
            parameters: vec![source],
        })])
        .unwrap();
        let separation_bytes = [
            0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x00, 0x31, 0x32, 0x33, 0x34, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14,
            0x21, 0x22, 0x23, 0x24, 0x00, 0x00, 0x00, 0x01, 0x31, 0x32, 0x33, 0x34,
        ];
        assert_eq!(separation.to_canonical_bytes(), separation_bytes);
        assert_eq!(
            ProofCertificate::from_canonical_bytes(&separation_bytes).unwrap(),
            separation
        );

        let replacement = ProofCertificate::new(vec![ProofStep::Replacement(Replacement {
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
            0x00, 0x00, 0x00, 0x01, 0x12, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x00, 0x11, 0x12, 0x13, 0x14, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14,
            0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43, 0x44, 0x00, 0x00,
            0x00, 0x01, 0x51, 0x52, 0x53, 0x54,
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
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        let certificate =
            ProofCertificate::new(vec![ProofStep::ProofReference { proof_id }]).unwrap();
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
                formula: half_limit.clone(),
            },
            ProofStep::VacuousUniversal {
                formula: half_limit.clone(),
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
                formula: half_limit.clone(),
            },
            ProofStep::VacuousUniversal {
                formula: half_limit.clone(),
            },
            ProofStep::VacuousUniversal {
                formula: leaf.clone(),
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
            first: half_limit.clone(),
            second: half_limit,
            third: leaf,
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
                    antecedent: leaf.clone(),
                    consequent: leaf.clone(),
                },
                2,
            ),
            (
                ProofStep::Frege {
                    first: leaf.clone(),
                    second: leaf.clone(),
                    third: leaf.clone(),
                },
                3,
            ),
            (
                ProofStep::ClassicalContraposition {
                    antecedent: leaf.clone(),
                    consequent: leaf.clone(),
                },
                2,
            ),
            (
                ProofStep::UniversalDistribution {
                    variable: x,
                    antecedent: leaf.clone(),
                    consequent: leaf.clone(),
                },
                2,
            ),
            (
                ProofStep::VacuousUniversal {
                    formula: leaf.clone(),
                },
                1,
            ),
            (
                ProofStep::UniversalInstantiation {
                    variable: x,
                    replacement: y,
                    body: leaf.clone(),
                },
                1,
            ),
            (
                ProofStep::EqualitySubstitution {
                    from: x,
                    to: y,
                    body: leaf.clone(),
                },
                1,
            ),
            (
                ProofStep::Separation(Separation {
                    predicate: leaf.clone(),
                    element: x,
                    source: y,
                    result: x,
                    parameters: Vec::new(),
                }),
                1,
            ),
            (
                ProofStep::Replacement(Replacement {
                    predicate: leaf,
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

    fn half_limit_formula() -> Formula {
        let variable = FreeVariable::new(1);
        let mut formula = Formula::equal(variable, variable);
        for _ in 0..14 {
            formula = Formula::implies(formula.clone(), formula);
        }
        Formula::negate(formula)
    }

    fn raw_formula_step(tag: u8, formulas: &[&[u8]]) -> Vec<u8> {
        let mut step = vec![tag];
        for formula in formulas {
            step.extend_from_slice(&u32::try_from(formula.len()).unwrap().to_be_bytes());
            step.extend_from_slice(formula);
        }
        step
    }

    fn raw_certificate(steps: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::try_from(steps.len()).unwrap().to_be_bytes());
        for step in steps {
            bytes.extend_from_slice(step);
        }
        bytes
    }

    fn assert_step_bytes(step: &ProofStep, expected: Vec<u8>) {
        let mut actual = Vec::new();
        encode_step(step, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }
}
