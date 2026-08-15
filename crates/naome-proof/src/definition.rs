//! Canonical conservative graph-definition artifacts.

use std::error::Error;
use std::fmt;

use naome_foundation::{FORMULA_MAX_BYTES, FOUNDATION_ID};
use sha2::{Digest, Sha256};

use crate::{DefinedFormula, DefinedFormulaCodecError, DefinitionId};

const RELATION: u8 = 0x00;
const FUNCTION: u8 = 0x02;
const DEFINITION_ID_DOMAIN: &[u8] = b"naome:definition:v1\0";

/// Maximum number of formal graph arguments admitted by one definition.
pub const DEFINITION_MAX_GRAPH_ARITY: u32 = 256;

/// Maximum encoded byte length admitted for one definition certificate.
pub const DEFINITION_MAX_BYTES: usize = 1 + 4 + 4 + FORMULA_MAX_BYTES;

/// The conservative graph interface of a definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DefinitionKind {
    /// An eliminable relation abbreviation with the declared arity.
    Relation { arity: u32 },
    /// A term constructor represented by a total-unique graph.
    Function { input_arity: u32 },
}

/// One canonical conservative definition over Foundation formulas.
///
/// The body uses canonical formal free variables. Relation arguments are
/// `0..arity`; function inputs are `0..input_arity` and its output is
/// variable `input_arity`.
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

    /// Constructs a positive-arity function graph definition.
    pub fn function(
        input_arity: u32,
        body: DefinedFormula,
    ) -> Result<Self, DefinitionCertificateError> {
        Self::new(DefinitionKind::Function { input_arity }, body)
    }

    /// Returns the conservative graph kind.
    #[must_use]
    pub const fn kind(&self) -> DefinitionKind {
        self.kind
    }

    /// Returns the compact definition body.
    #[must_use]
    pub const fn body(&self) -> &DefinedFormula {
        &self.body
    }

    /// Returns the graph relation arity used by canonical formula applications.
    #[must_use]
    pub const fn relation_arity(&self) -> u32 {
        match self.kind {
            DefinitionKind::Relation { arity } => arity,
            DefinitionKind::Function { input_arity } => input_arity + 1,
        }
    }

    /// Returns the canonical certificate bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let body = self
            .body
            .encode_canonical()
            .expect("DefinitionCertificate validates its body encoding");
        let mut output = Vec::with_capacity(1 + 8 + body.len());
        match self.kind {
            DefinitionKind::Relation { arity } => {
                output.push(RELATION);
                output.extend_from_slice(&arity.to_be_bytes());
            }
            DefinitionKind::Function { input_arity } => {
                output.push(FUNCTION);
                output.extend_from_slice(&input_arity.to_be_bytes());
            }
        }
        let body_length =
            u32::try_from(body.len()).expect("the formula byte limit is smaller than u32::MAX");
        output.extend_from_slice(&body_length.to_be_bytes());
        output.extend_from_slice(&body);
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
            FUNCTION => {
                let input_arity = cursor.read_u32()?;
                (DefinitionKind::Function { input_arity }, cursor.read_u32()?)
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
        let graph_arity = match self.kind {
            DefinitionKind::Relation { arity: 0 } => {
                return Err(DefinitionCertificateError::ZeroRelationArity);
            }
            DefinitionKind::Relation { arity } => u64::from(arity),
            DefinitionKind::Function { input_arity: 0 } => {
                return Err(DefinitionCertificateError::ZeroFunctionArity);
            }
            DefinitionKind::Function { input_arity } => u64::from(input_arity) + 1,
        };
        if graph_arity > u64::from(DEFINITION_MAX_GRAPH_ARITY) {
            return Err(DefinitionCertificateError::ArityTooLarge {
                actual: graph_arity,
                maximum: DEFINITION_MAX_GRAPH_ARITY,
            });
        }
        let arity =
            u32::try_from(graph_arity).expect("the checked definition graph-arity limit fits u32");
        let body = self
            .body
            .encode_canonical()
            .map_err(DefinitionCertificateError::Formula)?;
        if let Some(definition_id) = self.body.first_definition_reference() {
            return Err(DefinitionCertificateError::DefinitionReference { definition_id });
        }
        let free_variables = self.body.free_variables();
        if let Some(variable) = free_variables
            .iter()
            .find(|variable| variable.identifier() >= arity)
        {
            return Err(DefinitionCertificateError::UndeclaredFormalVariable {
                identifier: variable.identifier(),
                arity,
            });
        }
        for identifier in 0..arity {
            if !free_variables
                .iter()
                .any(|variable| variable.identifier() == identifier)
            {
                return Err(DefinitionCertificateError::MissingFormalVariable {
                    identifier,
                    arity,
                });
            }
        }
        let actual = 1 + 4 + 4 + body.len();
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
    /// Relations require at least one formal argument.
    ZeroRelationArity,
    /// A function graph must declare at least one input.
    ZeroFunctionArity,
    /// The graph interface exceeds the definition-specific arity limit.
    ArityTooLarge { actual: u64, maximum: u32 },
    /// Canonical definition bodies must contain only primitive Foundation nodes.
    DefinitionReference { definition_id: DefinitionId },
    /// The canonical body uses a free variable outside its formal interface.
    UndeclaredFormalVariable { identifier: u32, arity: u32 },
    /// The canonical body omits one declared formal variable.
    MissingFormalVariable { identifier: u32, arity: u32 },
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
            Self::ZeroRelationArity => {
                formatter.write_str("a relation definition must have at least one argument")
            }
            Self::ZeroFunctionArity => {
                formatter.write_str("a function definition must have at least one input")
            }
            Self::ArityTooLarge { actual, maximum } => write!(
                formatter,
                "definition graph arity {actual} exceeds the limit {maximum}"
            ),
            Self::DefinitionReference { definition_id } => write!(
                formatter,
                "canonical definition body contains selected definition {definition_id:?}"
            ),
            Self::UndeclaredFormalVariable { identifier, arity } => write!(
                formatter,
                "definition body uses formal variable {identifier} outside arity {arity}"
            ),
            Self::MissingFormalVariable { identifier, arity } => write!(
                formatter,
                "definition body omits formal variable {identifier} from arity {arity}"
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

    fn identity_body() -> DefinedFormula {
        DefinedFormula::equal(FreeVariable::new(1), FreeVariable::new(0))
    }

    fn body_using_all(arity: u32) -> DefinedFormula {
        let mut body = equality_body();
        for identifier in 1..arity {
            let variable = FreeVariable::new(identifier);
            body = DefinedFormula::implies(body, DefinedFormula::equal(variable, variable));
        }
        body
    }

    #[test]
    fn every_definition_kind_round_trips_without_an_obligation_address() {
        let definitions = [
            DefinitionCertificate::relation(1, equality_body()).unwrap(),
            DefinitionCertificate::function(1, identity_body()).unwrap(),
        ];
        for definition in &definitions {
            let bytes = definition.to_canonical_bytes();
            assert_eq!(
                &DefinitionCertificate::from_canonical_bytes(&bytes).unwrap(),
                definition
            );
        }
        assert_eq!(definitions[0].relation_arity(), 1);
        assert_eq!(definitions[1].relation_arity(), 2);
    }

    #[test]
    fn interface_validation_requires_exact_used_bounded_formals() {
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
            DefinitionCertificate::relation(2, equality_body()),
            Err(DefinitionCertificateError::MissingFormalVariable {
                identifier: 1,
                arity: 2,
            })
        );
        assert_eq!(
            DefinitionCertificate::relation(0, equality_body()),
            Err(DefinitionCertificateError::ZeroRelationArity)
        );
        assert_eq!(
            DefinitionCertificate::function(0, equality_body()),
            Err(DefinitionCertificateError::ZeroFunctionArity)
        );
        assert_eq!(
            DefinitionCertificate::relation(DEFINITION_MAX_GRAPH_ARITY + 1, equality_body()),
            Err(DefinitionCertificateError::ArityTooLarge {
                actual: u64::from(DEFINITION_MAX_GRAPH_ARITY) + 1,
                maximum: DEFINITION_MAX_GRAPH_ARITY,
            })
        );
        assert_eq!(
            DefinitionCertificate::function(DEFINITION_MAX_GRAPH_ARITY, identity_body()),
            Err(DefinitionCertificateError::ArityTooLarge {
                actual: u64::from(DEFINITION_MAX_GRAPH_ARITY) + 1,
                maximum: DEFINITION_MAX_GRAPH_ARITY,
            })
        );
        assert_eq!(
            DefinitionCertificate::function(u32::MAX, equality_body()),
            Err(DefinitionCertificateError::ArityTooLarge {
                actual: u64::from(u32::MAX) + 1,
                maximum: DEFINITION_MAX_GRAPH_ARITY,
            })
        );
        let _ = DefinitionCertificate::relation(
            DEFINITION_MAX_GRAPH_ARITY,
            body_using_all(DEFINITION_MAX_GRAPH_ARITY),
        )
        .unwrap();
        let _ = DefinitionCertificate::function(
            DEFINITION_MAX_GRAPH_ARITY - 1,
            body_using_all(DEFINITION_MAX_GRAPH_ARITY),
        )
        .unwrap();
    }

    #[test]
    fn kind_body_and_arity_are_identity_bearing() {
        let relation = DefinitionCertificate::relation(1, equality_body()).unwrap();
        let wider = DefinitionCertificate::relation(2, identity_body()).unwrap();
        let function = DefinitionCertificate::function(1, identity_body()).unwrap();
        let alternate = DefinitionCertificate::relation(
            1,
            DefinedFormula::member(FreeVariable::new(0), FreeVariable::new(0)),
        )
        .unwrap();
        assert_ne!(relation.definition_id(), wider.definition_id());
        assert_ne!(wider.definition_id(), function.definition_id());
        assert_ne!(relation.definition_id(), alternate.definition_id());
    }

    #[test]
    fn canonical_definition_body_rejects_selected_definition_applications() {
        let definition_id = DefinitionId::from_bytes([0x77; 32]);
        assert_eq!(
            DefinitionCertificate::relation(
                1,
                DefinedFormula::defined_relation(definition_id, [FreeVariable::new(0)]),
            ),
            Err(DefinitionCertificateError::DefinitionReference { definition_id })
        );
    }

    #[test]
    fn relation_definition_identity_has_a_stable_domain_golden() {
        let definition = DefinitionCertificate::relation(1, equality_body()).unwrap();
        assert_eq!(
            definition.definition_id().as_bytes(),
            &[
                0x01, 0x96, 0xe7, 0x6e, 0xe0, 0xec, 0xab, 0xbe, 0x9e, 0x86, 0x3a, 0x19, 0xf1, 0x91,
                0xde, 0xd8, 0x7b, 0x59, 0x9a, 0x4b, 0x15, 0x8c, 0x52, 0xf7, 0x5d, 0x8e, 0xce, 0x35,
                0xba, 0x79, 0x60, 0x35,
            ]
        );
    }

    #[test]
    fn strict_decoder_rejects_every_truncation_unknown_tag_and_trailing_byte() {
        let definition = DefinitionCertificate::function(1, identity_body()).unwrap();
        let bytes = definition.to_canonical_bytes();
        for end in 0..bytes.len() {
            assert!(DefinitionCertificate::from_canonical_bytes(&bytes[..end]).is_err());
        }
        assert_eq!(
            DefinitionCertificate::from_canonical_bytes(&[0x01]),
            Err(DefinitionCertificateError::UnknownKindTag(0x01))
        );
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
    fn complete_certificate_byte_limit_is_derived_from_the_formula_limit() {
        assert_eq!(DEFINITION_MAX_BYTES, FORMULA_MAX_BYTES + 9);
        assert_eq!(
            DefinitionCertificate::from_canonical_bytes(&vec![0; DEFINITION_MAX_BYTES + 1]),
            Err(DefinitionCertificateError::InputTooLong {
                actual: DEFINITION_MAX_BYTES + 1,
                maximum: DEFINITION_MAX_BYTES
            })
        );
    }
}
