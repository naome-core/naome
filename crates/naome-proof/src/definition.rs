//! Canonical conservative graph-definition artifacts.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use naome_foundation::{FORMULA_MAX_BYTES, FOUNDATION_ID};
use sha2::{Digest, Sha256};

use crate::{DefinedFormula, DefinedFormulaCodecError, DefinitionId};

const RELATION: u8 = 0x00;
const FUNCTION: u8 = 0x02;
const DEFINITION_ID_DOMAIN: &[u8] = b"naome:definition:v1\0";
mod instantiation;
pub use instantiation::DefinitionInstantiation;

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
#[derive(Clone)]
#[must_use]
pub struct DefinitionCertificate {
    kind: DefinitionKind,
    body: Arc<DefinedFormula>,
    canonical: Arc<[u8]>,
    id: DefinitionId,
}
impl PartialEq for DefinitionCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}
impl Eq for DefinitionCertificate {}
impl fmt::Debug for DefinitionCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DefinitionCertificate")
            .field("kind", &self.kind)
            .field("body", &self.body)
            .finish()
    }
}

impl DefinitionCertificate {
    /// Constructs and structurally validates one definition certificate.
    pub fn new(
        kind: DefinitionKind,
        body: DefinedFormula,
    ) -> Result<Self, DefinitionCertificateError> {
        Self::validate_kind(kind)?;
        let encoded = body
            .encode_canonical()
            .map_err(DefinitionCertificateError::Formula)?;
        Self::validate(kind, &body, encoded.len())?;
        let mut canonical = Vec::with_capacity(9 + encoded.len());
        match kind {
            DefinitionKind::Relation { arity } => {
                canonical.push(RELATION);
                canonical.extend_from_slice(&arity.to_be_bytes());
            }
            DefinitionKind::Function { input_arity } => {
                canonical.push(FUNCTION);
                canonical.extend_from_slice(&input_arity.to_be_bytes());
            }
        }
        canonical.extend_from_slice(
            &u32::try_from(encoded.len())
                .expect("bounded definition length fits u32")
                .to_be_bytes(),
        );
        canonical.extend_from_slice(&encoded);
        Ok(Self::from_parts(kind, body, canonical.into()))
    }

    fn from_parts(kind: DefinitionKind, body: DefinedFormula, canonical: Arc<[u8]>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DEFINITION_ID_DOMAIN);
        update_framed(&mut hasher, FOUNDATION_ID.as_bytes());
        update_framed(&mut hasher, &canonical);
        Self {
            kind,
            body: Arc::new(body),
            canonical,
            id: DefinitionId::from_bytes(hasher.finalize().into()),
        }
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
    pub fn body(&self) -> &DefinedFormula {
        &self.body
    }

    /// A shared expansion view of this exact, structurally checked certificate.
    pub fn resolution(&self) -> crate::DefinitionResolution<'static> {
        crate::DefinitionResolution::shared(self.relation_arity(), self.body.clone())
    }
    /// Streams primitive nodes in prefix order with capture-safe free arguments.
    pub fn instantiate(
        &self,
        arguments: &[u32],
    ) -> Result<DefinitionInstantiation, crate::DefinitionExpansionError> {
        DefinitionInstantiation::new(self, arguments)
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
        self.canonical.to_vec()
    }

    /// Borrows the single canonical encoding retained by this certificate.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
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
        Self::validate(kind, &body, body_bytes.len())?;
        Ok(Self::from_parts(kind, body, bytes.into()))
    }

    /// Returns the Foundation-scoped identity of this complete certificate.
    pub const fn definition_id(&self) -> DefinitionId {
        self.id
    }

    fn validate_kind(kind: DefinitionKind) -> Result<u32, DefinitionCertificateError> {
        let graph_arity = match kind {
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
        Ok(u32::try_from(graph_arity).expect("the checked definition graph-arity limit fits u32"))
    }
    fn validate(
        kind: DefinitionKind,
        formula: &DefinedFormula,
        body_length: usize,
    ) -> Result<(), DefinitionCertificateError> {
        let arity = Self::validate_kind(kind)?;
        if let Some(definition_id) = formula.first_definition_reference() {
            return Err(DefinitionCertificateError::DefinitionReference { definition_id });
        }
        let free_variables = formula.free_variables();
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
        let actual = 1 + 4 + 4 + body_length;
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
mod tests;
