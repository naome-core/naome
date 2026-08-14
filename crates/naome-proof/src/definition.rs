//! Canonical conservative graph-definition artifacts.

use std::error::Error;
use std::fmt;

use naome_foundation::FOUNDATION_ID;
use sha2::{Digest, Sha256};

use crate::{DefinedFormula, DefinedFormulaCodecError, DefinitionId, ProofId};

const RELATION: u8 = 0x00;
const CONSTANT: u8 = 0x01;
const FUNCTION: u8 = 0x02;
const DEFINITION_ID_DOMAIN: &[u8] = b"naome:definition:v0\0";

/// Maximum encoded byte length admitted for one definition certificate.
pub const DEFINITION_MAX_BYTES: usize = 4_194_304;

/// The conservative interface and exact selected proof obligation of a definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DefinitionKind {
    /// An eliminable relation abbreviation with the declared arity.
    Relation { arity: u32 },
    /// A zero-argument term represented by a uniquely satisfied unary graph.
    Constant { unique_existence_proof: ProofId },
    /// A term constructor represented by a total-unique graph.
    Function {
        input_arity: u32,
        total_unique_proof: ProofId,
    },
}

/// One canonical conservative definition over Foundation formulas.
///
/// The body uses canonical formal free variables. Relation arguments are
/// `0..arity`; a constant value is variable `0`; function inputs are
/// `0..input_arity` and its output is variable `input_arity`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct DefinitionCertificate {
    kind: DefinitionKind,
    body: DefinedFormula,
}

impl DefinitionCertificate {
    /// Constructs and structurally validates one definition certificate.
    pub fn new(
        kind: DefinitionKind,
        body: DefinedFormula,
    ) -> Result<Self, DefinitionCertificateError> {
        let certificate = Self { kind, body };
        certificate.validate()?;
        Ok(certificate)
    }

    /// Constructs a relation definition.
    pub fn relation(arity: u32, body: DefinedFormula) -> Result<Self, DefinitionCertificateError> {
        Self::new(DefinitionKind::Relation { arity }, body)
    }

    /// Constructs a constant graph definition.
    pub fn constant(
        body: DefinedFormula,
        unique_existence_proof: ProofId,
    ) -> Result<Self, DefinitionCertificateError> {
        Self::new(
            DefinitionKind::Constant {
                unique_existence_proof,
            },
            body,
        )
    }

    /// Constructs a positive-arity function graph definition.
    pub fn function(
        input_arity: u32,
        body: DefinedFormula,
        total_unique_proof: ProofId,
    ) -> Result<Self, DefinitionCertificateError> {
        Self::new(
            DefinitionKind::Function {
                input_arity,
                total_unique_proof,
            },
            body,
        )
    }

    /// Returns the definition kind and exact proof obligation, if any.
    #[must_use]
    pub const fn kind(&self) -> DefinitionKind {
        self.kind
    }

    /// Returns the compact definition body.
    #[must_use]
    pub const fn body(&self) -> &DefinedFormula {
        &self.body
    }

    /// Returns cited definitions in canonical body-prefix order.
    #[must_use]
    pub fn definition_references(&self) -> Vec<DefinitionId> {
        self.body.definition_references()
    }

    /// Returns the graph relation arity used by canonical formula applications.
    #[must_use]
    pub const fn relation_arity(&self) -> u32 {
        match self.kind {
            DefinitionKind::Relation { arity } => arity,
            DefinitionKind::Constant { .. } => 1,
            DefinitionKind::Function { input_arity, .. } => input_arity + 1,
        }
    }

    /// Returns the exact selected proof required by a constant or function.
    #[must_use]
    pub const fn obligation_proof_id(&self) -> Option<ProofId> {
        match self.kind {
            DefinitionKind::Relation { .. } => None,
            DefinitionKind::Constant {
                unique_existence_proof,
            } => Some(unique_existence_proof),
            DefinitionKind::Function {
                total_unique_proof, ..
            } => Some(total_unique_proof),
        }
    }

    /// Returns the canonical certificate bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let body = self
            .body
            .encode_canonical()
            .expect("DefinitionCertificate validates its body encoding");
        let mut output = Vec::with_capacity(1 + 8 + body.len() + ProofId::BYTE_LENGTH);
        match self.kind {
            DefinitionKind::Relation { arity } => {
                output.push(RELATION);
                output.extend_from_slice(&arity.to_be_bytes());
            }
            DefinitionKind::Constant { .. } => output.push(CONSTANT),
            DefinitionKind::Function { input_arity, .. } => {
                output.push(FUNCTION);
                output.extend_from_slice(&input_arity.to_be_bytes());
            }
        }
        let body_length =
            u32::try_from(body.len()).expect("the formula byte limit is smaller than u32::MAX");
        output.extend_from_slice(&body_length.to_be_bytes());
        output.extend_from_slice(&body);
        match self.kind {
            DefinitionKind::Relation { .. } => {}
            DefinitionKind::Constant {
                unique_existence_proof,
            } => {
                output.extend_from_slice(unique_existence_proof.as_bytes());
            }
            DefinitionKind::Function {
                total_unique_proof, ..
            } => output.extend_from_slice(total_unique_proof.as_bytes()),
        }
        output
    }

    /// Decodes one complete canonical definition certificate.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DefinitionCertificateError> {
        if bytes.len() > DEFINITION_MAX_BYTES {
            return Err(DefinitionCertificateError::InputTooLong {
                actual: bytes.len(),
                maximum: DEFINITION_MAX_BYTES,
            });
        }
        let mut cursor = Cursor::new(bytes);
        let tag = cursor.read_u8()?;
        let (kind, body_length) = match tag {
            RELATION => {
                let arity = cursor.read_u32()?;
                (DefinitionKind::Relation { arity }, cursor.read_u32()?)
            }
            CONSTANT => {
                let body_length = cursor.read_u32()?;
                let body_bytes = cursor.take(body_length as usize)?;
                let unique_existence_proof = ProofId::from_bytes(
                    cursor
                        .take(ProofId::BYTE_LENGTH)?
                        .try_into()
                        .expect("the checked slice has one ProofId"),
                );
                if cursor.remaining() != 0 {
                    return Err(DefinitionCertificateError::TrailingBytes {
                        remaining: cursor.remaining(),
                    });
                }
                let body = DefinedFormula::decode_canonical(body_bytes)
                    .map_err(DefinitionCertificateError::Formula)?;
                return Self::new(
                    DefinitionKind::Constant {
                        unique_existence_proof,
                    },
                    body,
                );
            }
            FUNCTION => {
                let input_arity = cursor.read_u32()?;
                let body_length = cursor.read_u32()?;
                let body_bytes = cursor.take(body_length as usize)?;
                let total_unique_proof = ProofId::from_bytes(
                    cursor
                        .take(ProofId::BYTE_LENGTH)?
                        .try_into()
                        .expect("the checked slice has one ProofId"),
                );
                if cursor.remaining() != 0 {
                    return Err(DefinitionCertificateError::TrailingBytes {
                        remaining: cursor.remaining(),
                    });
                }
                let body = DefinedFormula::decode_canonical(body_bytes)
                    .map_err(DefinitionCertificateError::Formula)?;
                return Self::new(
                    DefinitionKind::Function {
                        input_arity,
                        total_unique_proof,
                    },
                    body,
                );
            }
            tag => return Err(DefinitionCertificateError::UnknownKindTag(tag)),
        };
        let body_bytes = cursor.take(body_length as usize)?;
        if cursor.remaining() != 0 {
            return Err(DefinitionCertificateError::TrailingBytes {
                remaining: cursor.remaining(),
            });
        }
        let body = DefinedFormula::decode_canonical(body_bytes)
            .map_err(DefinitionCertificateError::Formula)?;
        Self::new(kind, body)
    }

    /// Returns the Foundation-scoped identity of this complete certificate.
    pub fn definition_id(&self) -> DefinitionId {
        let bytes = self.to_canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(DEFINITION_ID_DOMAIN);
        update_framed(&mut hasher, FOUNDATION_ID.as_bytes());
        update_framed(&mut hasher, &bytes);
        DefinitionId::from_bytes(hasher.finalize().into())
    }

    fn validate(&self) -> Result<(), DefinitionCertificateError> {
        if let DefinitionKind::Function { input_arity: 0, .. } = self.kind {
            return Err(DefinitionCertificateError::ZeroFunctionArity);
        }
        if let DefinitionKind::Function { input_arity, .. } = self.kind {
            input_arity
                .checked_add(1)
                .ok_or(DefinitionCertificateError::ArityOverflow)?;
        }
        let body = self
            .body
            .encode_canonical()
            .map_err(DefinitionCertificateError::Formula)?;
        let arity = self.relation_arity();
        if let Some(variable) = self
            .body
            .free_variables()
            .into_iter()
            .find(|variable| variable.identifier() >= arity)
        {
            return Err(DefinitionCertificateError::UndeclaredFormalVariable {
                identifier: variable.identifier(),
                arity,
            });
        }
        let fixed_bytes = match self.kind {
            DefinitionKind::Relation { .. } => 1 + 4 + 4,
            DefinitionKind::Constant { .. } => 1 + 4 + ProofId::BYTE_LENGTH,
            DefinitionKind::Function { .. } => 1 + 4 + 4 + ProofId::BYTE_LENGTH,
        };
        let actual = fixed_bytes + body.len();
        if actual > DEFINITION_MAX_BYTES {
            return Err(DefinitionCertificateError::InputTooLong {
                actual,
                maximum: DEFINITION_MAX_BYTES,
            });
        }
        Ok(())
    }
}

fn update_framed(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).expect("canonical definition fields fit u32");
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, DefinitionCertificateError> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or(DefinitionCertificateError::UnexpectedEnd)?;
        self.position += 1;
        Ok(byte)
    }

    fn read_u32(&mut self) -> Result<u32, DefinitionCertificateError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(
            bytes.try_into().expect("the checked slice has four bytes"),
        ))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DefinitionCertificateError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DefinitionCertificateError::UnexpectedEnd)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(DefinitionCertificateError::UnexpectedEnd)?;
        self.position = end;
        Ok(bytes)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
}

/// A structural or canonical definition-certificate failure.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DefinitionCertificateError {
    /// The certificate exceeds the deterministic byte limit.
    InputTooLong { actual: usize, maximum: usize },
    /// The encoded certificate ended before the current field was complete.
    UnexpectedEnd,
    /// The certificate uses an unknown definition-kind tag.
    UnknownKindTag(u8),
    /// Zero-input function graphs must use the distinct constant kind.
    ZeroFunctionArity,
    /// The function input and output arities do not fit the canonical count.
    ArityOverflow,
    /// The canonical body uses a free variable outside its formal interface.
    UndeclaredFormalVariable { identifier: u32, arity: u32 },
    /// The definition body is not a canonical definition-aware formula.
    Formula(DefinedFormulaCodecError),
    /// A complete certificate was followed by additional bytes.
    TrailingBytes { remaining: usize },
}

impl fmt::Display for DefinitionCertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "definition certificate has {actual} bytes; the limit is {maximum}"
            ),
            Self::UnexpectedEnd => formatter.write_str("definition certificate ended unexpectedly"),
            Self::UnknownKindTag(tag) => write!(formatter, "unknown definition kind {tag:#04x}"),
            Self::ZeroFunctionArity => {
                formatter.write_str("a zero-input function must be encoded as a constant")
            }
            Self::ArityOverflow => formatter.write_str("definition graph arity overflows u32"),
            Self::UndeclaredFormalVariable { identifier, arity } => write!(
                formatter,
                "definition body uses formal variable {identifier} outside arity {arity}"
            ),
            Self::Formula(source) => write!(formatter, "invalid definition body: {source}"),
            Self::TrailingBytes { remaining } => {
                write!(
                    formatter,
                    "definition certificate has {remaining} trailing bytes"
                )
            }
        }
    }
}

impl Error for DefinitionCertificateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Formula(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use naome_foundation::{FORMULA_MAX_BYTES, FreeVariable};

    fn equality_body() -> DefinedFormula {
        let value = FreeVariable::new(0);
        DefinedFormula::equal(value, value)
    }

    #[test]
    fn every_definition_kind_round_trips_and_retains_exact_obligation() {
        let proof = ProofId::from_bytes([0x55; 32]);
        let definitions = [
            DefinitionCertificate::relation(1, equality_body()).unwrap(),
            DefinitionCertificate::constant(equality_body(), proof).unwrap(),
            DefinitionCertificate::function(1, equality_body(), proof).unwrap(),
        ];
        for definition in &definitions {
            let bytes = definition.to_canonical_bytes();
            assert_eq!(
                &DefinitionCertificate::from_canonical_bytes(&bytes).unwrap(),
                definition
            );
        }
        assert_eq!(definitions[0].obligation_proof_id(), None);
        assert_eq!(definitions[1].obligation_proof_id(), Some(proof));
        assert_eq!(definitions[2].relation_arity(), 2);
    }

    #[test]
    fn interface_validation_rejects_undeclared_and_redundant_function_forms() {
        let proof = ProofId::from_bytes([0x66; 32]);
        assert_eq!(
            DefinitionCertificate::relation(
                1,
                DefinedFormula::equal(FreeVariable::new(1), FreeVariable::new(1)),
            ),
            Err(DefinitionCertificateError::UndeclaredFormalVariable {
                identifier: 1,
                arity: 1,
            })
        );
        assert_eq!(
            DefinitionCertificate::function(0, equality_body(), proof),
            Err(DefinitionCertificateError::ZeroFunctionArity)
        );
        assert_eq!(
            DefinitionCertificate::function(u32::MAX, equality_body(), proof),
            Err(DefinitionCertificateError::ArityOverflow)
        );
    }

    #[test]
    fn kind_body_arity_and_obligation_are_identity_bearing() {
        let first = ProofId::from_bytes([0x77; 32]);
        let second = ProofId::from_bytes([0x78; 32]);
        let relation = DefinitionCertificate::relation(1, equality_body()).unwrap();
        let wider = DefinitionCertificate::relation(2, equality_body()).unwrap();
        let constant = DefinitionCertificate::constant(equality_body(), first).unwrap();
        let alternate = DefinitionCertificate::constant(equality_body(), second).unwrap();
        assert_ne!(relation.definition_id(), wider.definition_id());
        assert_ne!(relation.definition_id(), constant.definition_id());
        assert_ne!(constant.definition_id(), alternate.definition_id());
    }

    #[test]
    fn relation_definition_identity_has_a_stable_domain_golden() {
        let definition = DefinitionCertificate::relation(1, equality_body()).unwrap();
        assert_eq!(
            definition.definition_id().as_bytes(),
            &[
                0x8f, 0x45, 0x06, 0x22, 0x29, 0x01, 0xbb, 0x6e, 0x08, 0x76, 0x15, 0x06, 0x3e, 0x7d,
                0x1d, 0xb4, 0x9b, 0xe6, 0x84, 0x2d, 0x96, 0xe7, 0xe1, 0xad, 0xfb, 0xcd, 0x01, 0xc8,
                0x4f, 0xf2, 0x80, 0x18,
            ]
        );
    }

    #[test]
    fn strict_decoder_rejects_every_truncation_unknown_tag_and_trailing_byte() {
        let definition =
            DefinitionCertificate::constant(equality_body(), ProofId::from_bytes([0x88; 32]))
                .unwrap();
        let bytes = definition.to_canonical_bytes();
        for end in 0..bytes.len() {
            assert!(DefinitionCertificate::from_canonical_bytes(&bytes[..end]).is_err());
        }
        assert_eq!(
            DefinitionCertificate::from_canonical_bytes(&[0xff]),
            Err(DefinitionCertificateError::UnknownKindTag(0xff))
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            DefinitionCertificate::from_canonical_bytes(&trailing),
            Err(DefinitionCertificateError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn formula_and_complete_certificate_byte_limits_are_enforced_in_precedence_order() {
        const ARGUMENT_COUNT: usize = 78_635;

        let definition_id = DefinitionId::from_bytes([0x91; 32]);
        let formal = FreeVariable::new(0);
        let body = |negations| {
            let mut formula = DefinedFormula::defined_relation(
                definition_id,
                std::iter::repeat_n(formal, ARGUMENT_COUNT),
            );
            for _ in 0..negations {
                formula = DefinedFormula::negate(formula);
            }
            formula
        };

        let exact = DefinitionCertificate::relation(1, body(4)).unwrap();
        assert_eq!(
            exact.body().encode_canonical().unwrap().len(),
            FORMULA_MAX_BYTES
        );
        assert_eq!(exact.to_canonical_bytes().len(), FORMULA_MAX_BYTES + 9);
        drop(exact);

        assert_eq!(
            DefinitionCertificate::relation(1, body(5)),
            Err(DefinitionCertificateError::Formula(
                DefinedFormulaCodecError::InputTooLong {
                    actual: FORMULA_MAX_BYTES + 1,
                    maximum: FORMULA_MAX_BYTES,
                }
            ))
        );
        assert_eq!(
            DefinitionCertificate::from_canonical_bytes(&vec![0; DEFINITION_MAX_BYTES + 1]),
            Err(DefinitionCertificateError::InputTooLong {
                actual: DEFINITION_MAX_BYTES + 1,
                maximum: DEFINITION_MAX_BYTES
            })
        );
    }
}
