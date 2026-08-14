use naome_foundation::{FormulaCodecError, FreeVariable, ZfcAxiom};

use crate::{
    CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_FORMULA_NODES, CERTIFICATE_MAX_STEPS,
    CLASSICAL_CONTRAPOSITION, EQUALITY_REFLEXIVITY, EQUALITY_SUBSTITUTION, FREGE, GENERALIZATION,
    MODUS_PONENS, PROOF_REFERENCE, ProofCertificate, ProofCertificateError, ProofFormula, ProofId,
    ProofReplacement, ProofSeparation, ProofStep, REPLACEMENT, SEPARATION, SIMPLIFICATION,
    UNIVERSAL_DISTRIBUTION, UNIVERSAL_INSTANTIATION, VACUOUS_UNIVERSAL, ZFC_AXIOM,
    proof_formula::ProofFormulaCodecError, validate_step_references,
};

pub(super) fn encode_steps(steps: &[ProofStep]) -> Result<Vec<u8>, ProofCertificateError> {
    let mut output = Vec::with_capacity(4 + steps.len());
    encode_steps_into(steps, &mut output)?;
    Ok(output)
}

pub(super) fn validate_steps_encoding(steps: &[ProofStep]) -> Result<(), ProofCertificateError> {
    encode_steps_into(steps, &mut LengthSink::default())
}

pub(super) fn steps_match_encoding(steps: &[ProofStep], expected: &[u8]) -> bool {
    let mut output = MatchingSink::new(expected);
    encode_steps_into(steps, &mut output)
        .expect("ProofCertificate construction guarantees canonical encodability");
    output.matches()
}

fn encode_steps_into(
    steps: &[ProofStep],
    output: &mut impl ByteSink,
) -> Result<(), ProofCertificateError> {
    let step_count = u32::try_from(steps.len()).expect("ProofCertificate validates its step count");

    let mut remaining_formula_nodes = CERTIFICATE_MAX_FORMULA_NODES;
    write_u32(step_count, output);

    for step in steps {
        encode_step_with_formula_budget(step, output, &mut remaining_formula_nodes)?;
        ensure_within_byte_limit(output.len())?;
    }

    Ok(())
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
    output: &mut impl ByteSink,
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
        SEPARATION => Ok(ProofStep::Separation(ProofSeparation {
            predicate: read_formula(cursor, remaining_formula_nodes)?,
            element: read_variable(cursor)?,
            source: read_variable(cursor)?,
            result: read_variable(cursor)?,
            parameters: read_variables(cursor)?,
        })),
        REPLACEMENT => Ok(ProofStep::Replacement(ProofReplacement {
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
                    .take(ProofId::BYTE_LENGTH)?
                    .try_into()
                    .expect("the checked slice has exactly one ProofId"),
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
    formula: &ProofFormula,
    output: &mut impl ByteSink,
    remaining_formula_nodes: &mut usize,
) -> Result<(), ProofCertificateError> {
    let (bytes, used_nodes) = formula
        .encode_canonical_with_node_limit(*remaining_formula_nodes)
        .map_err(map_proof_formula_error)?;
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
) -> Result<ProofFormula, ProofCertificateError> {
    let length = usize::try_from(cursor.read_u32()?)
        .expect("u32 is representable as usize on supported Rust targets");
    let (formula, used_nodes) = ProofFormula::decode_canonical_with_node_limit(
        cursor.take(length)?,
        *remaining_formula_nodes,
    )
    .map_err(map_proof_formula_error)?;
    *remaining_formula_nodes = remaining_formula_nodes
        .checked_sub(used_nodes)
        .expect("Formula reports no more nodes than the supplied limit");
    Ok(formula)
}

fn map_proof_formula_error(source: ProofFormulaCodecError) -> ProofCertificateError {
    match source {
        ProofFormulaCodecError::Primitive(source) => map_formula_error(source),
        ProofFormulaCodecError::Defined(crate::DefinedFormulaCodecError::NodeLimitExceeded {
            ..
        }) => ProofCertificateError::FormulaNodeLimitExceeded {
            maximum: CERTIFICATE_MAX_FORMULA_NODES,
        },
        ProofFormulaCodecError::Defined(source) => ProofCertificateError::DefinedFormula(source),
    }
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
    output: &mut impl ByteSink,
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

    let mut variables = Vec::with_capacity(count);
    for _ in 0..count {
        variables.push(read_variable(cursor)?);
    }
    Ok(variables)
}

fn write_variable(variable: FreeVariable, output: &mut impl ByteSink) {
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

fn write_u32(value: u32, output: &mut impl ByteSink) {
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

trait ByteSink {
    fn len(&self) -> usize;
    fn push(&mut self, byte: u8);
    fn extend_from_slice(&mut self, bytes: &[u8]);
}

impl ByteSink for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn push(&mut self, byte: u8) {
        Vec::push(self, byte);
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        Vec::extend_from_slice(self, bytes);
    }
}

#[derive(Default)]
struct LengthSink {
    length: usize,
}

impl ByteSink for LengthSink {
    fn len(&self) -> usize {
        self.length
    }

    fn push(&mut self, _byte: u8) {
        self.length += 1;
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.length += bytes.len();
    }
}

struct MatchingSink<'a> {
    expected: &'a [u8],
    position: usize,
    matching: bool,
}

impl<'a> MatchingSink<'a> {
    const fn new(expected: &'a [u8]) -> Self {
        Self {
            expected,
            position: 0,
            matching: true,
        }
    }

    const fn matches(&self) -> bool {
        self.matching && self.position == self.expected.len()
    }
}

impl ByteSink for MatchingSink<'_> {
    fn len(&self) -> usize {
        self.position
    }

    fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        let end = self.position + bytes.len();
        self.matching &= self.expected.get(self.position..end) == Some(bytes);
        self.position = end;
    }
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
mod tests;
