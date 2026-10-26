//! Fallible access to complete, checker-owned mathematical contexts.
//!
//! Storage supplies immutable bytes only. It cannot construct a checked view,
//! select its roots, truncate an index, or restore validity from a stored flag.

use crate::ArtifactState;
mod program;
use naome_foundation::Formula;
use naome_proof::{
    ArtifactId, DefinitionId, DefinitionKind, DefinitionResolver, DerivationId, ProofId,
    StatementId,
};
pub use program::ProgramSource;
pub(crate) use program::{ProgramNodes, ProgramRepresentation};
use std::{borrow::Cow, error::Error, fmt};

/// Bounded parsed reads for one operation. This is an allocation policy, not a
/// language bound or part of mathematical validity/snapshot identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadCacheLimits {
    pub entries: usize,
    pub bytes: usize,
}
impl ReadCacheLimits {
    pub const DEFAULT: Self = Self {
        entries: 64,
        bytes: 2 * 1024 * 1024,
    };
    pub fn new(entries: usize, bytes: usize) -> Result<Self, ContextError> {
        if entries.checked_mul(512).is_none_or(|n| n > bytes) {
            return Err(ContextError::Limit);
        }
        Ok(Self { entries, bytes })
    }
}
impl Default for ReadCacheLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A cold context access failed; failure never means authenticated absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextError {
    Storage(String),
    Corrupt,
    Limit,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(message) => write!(f, "checked context storage: {message}"),
            Self::Corrupt => f.write_str("checked context integrity failure"),
            Self::Limit => f.write_str("checked context access limit"),
        }
    }
}
impl Error for ContextError {}

/// Byte storage used by the checker for authenticated immutable nodes.
/// Reads must reject missing or oversized records before allocating beyond
/// `maximum`. Writes must preserve an existing address's exact bytes.
pub trait ContextStorage: Send + Sync {
    fn read(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError>;
    fn write(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError>;
    /// Report integrity failures discovered by the checker after a byte read.
    /// The owner may halt its process; this notification grants no validity.
    fn record_failure(&self, _error: &ContextError) {}
}

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// The existing finite structural indexes; projections are never proof facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BucketKind {
    Outgoing,
    Deductions,
    Instances,
}

#[derive(Clone, Copy)]
pub(crate) struct FormulaLocation {
    pub(crate) address: [u8; 32],
    pub(crate) snapshot: [u8; 32],
}

/// Authenticated proof metadata, read before reserving and loading its formula.
#[derive(Clone, Copy)]
pub struct ProofHeader {
    pub(crate) location: Option<FormulaLocation>,
    pub(crate) derivation: DerivationId,
    pub(crate) statement: StatementId,
    pub(crate) length: usize,
}
impl ProofHeader {
    pub const fn derivation_id(self) -> DerivationId {
        self.derivation
    }
    pub const fn statement_id(self) -> StatementId {
        self.statement
    }
    pub const fn canonical_length(self) -> usize {
        self.length
    }
}

/// The deterministic minimum concrete proof witness for an accepted statement.
#[derive(Clone, Copy)]
pub struct StatementHeader {
    pub(crate) location: Option<FormulaLocation>,
    pub(crate) proof: ProofId,
    pub(crate) length: usize,
}
impl StatementHeader {
    pub const fn proof_id(self) -> ProofId {
        self.proof
    }
    pub const fn canonical_length(self) -> usize {
        self.length
    }
}

/// An ascending complete structural bucket. An error is not end of iteration.
pub type StatementCursor<'a> = Box<dyn Iterator<Item = Result<StatementId, ContextError>> + 'a>;

/// Sealed mathematical access implemented only by checker-owned contexts.
/// Header lengths must be reserved by the caller before formula materialization.
/// Cache residency must change neither membership nor logical work accounting.
pub trait ContextView: sealed::Sealed + DefinitionResolver {
    fn read_cache_limits(&self) -> ReadCacheLimits {
        ReadCacheLimits::DEFAULT
    }
    fn snapshot_id(&self) -> [u8; 32];
    fn contains_artifact(&self, id: ArtifactId) -> Result<bool, ContextError>;
    fn proof_header(&self, id: ProofId) -> Result<Option<ProofHeader>, ContextError>;
    /// A sealed mathematical source for a program citation. Bounded formulas
    /// use the existing canonical representation; disk contexts also supply
    /// authenticated DAG nodes without materializing a large formula tree.
    fn program_source(&self, id: ProofId) -> Result<Option<ProgramSource>, ContextError> {
        let Some(header) = self.proof_header(id)? else {
            return Ok(None);
        };
        if header.length > crate::CHECKER_MAX_FORMULA_WORK_BYTES {
            return Err(ContextError::Limit);
        }
        let formula = self
            .proof_formula(header, header.length)?
            .ok_or(ContextError::Corrupt)?;
        Ok(Some(ProgramSource::formula(
            id,
            header,
            formula.into_owned(),
        )))
    }
    fn statement_header(&self, id: StatementId) -> Result<Option<StatementHeader>, ContextError>;
    fn statement_formula(
        &self,
        id: StatementId,
        maximum: usize,
    ) -> Result<Option<Cow<'_, Formula>>, ContextError>;
    /// Reuse an authenticated header from this exact snapshot without another
    /// metadata traversal. Logical work must still be reserved by the caller.
    fn proof_formula(
        &self,
        header: ProofHeader,
        maximum: usize,
    ) -> Result<Option<Cow<'_, Formula>>, ContextError> {
        self.statement_formula(header.statement, maximum)
    }
    fn statement_formula_from_header(
        &self,
        id: StatementId,
        header: StatementHeader,
        maximum: usize,
    ) -> Result<Option<Cow<'_, Formula>>, ContextError> {
        let _ = header;
        self.statement_formula(id, maximum)
    }
    fn bucket(
        &self,
        kind: BucketKind,
        target: StatementId,
    ) -> Result<StatementCursor<'_>, ContextError>;
    fn definition_kind(&self, id: DefinitionId) -> Result<Option<DefinitionKind>, ContextError>;
}

impl sealed::Sealed for ArtifactState {}
impl ContextView for ArtifactState {
    fn snapshot_id(&self) -> [u8; 32] {
        ArtifactState::snapshot_id(self)
    }
    fn contains_artifact(&self, id: ArtifactId) -> Result<bool, ContextError> {
        Ok(self.question_index.contains_artifact(&id))
    }
    fn proof_header(&self, id: ProofId) -> Result<Option<ProofHeader>, ContextError> {
        Ok(self.resolve_proof(id))
    }
    fn statement_header(&self, id: StatementId) -> Result<Option<StatementHeader>, ContextError> {
        Ok(self
            .known_statement(id)
            .map(|(proof, _, length)| StatementHeader {
                proof,
                length,
                location: None,
            }))
    }
    fn statement_formula(
        &self,
        id: StatementId,
        maximum: usize,
    ) -> Result<Option<Cow<'_, Formula>>, ContextError> {
        let Some((_, _, length)) = self.known_statement(id) else {
            return Ok(None);
        };
        if length > maximum {
            return Err(ContextError::Limit);
        }
        Ok(self.resolve_statement(id).map(Cow::Borrowed))
    }
    fn bucket(
        &self,
        kind: BucketKind,
        target: StatementId,
    ) -> Result<StatementCursor<'_>, ContextError> {
        Ok(match kind {
            BucketKind::Outgoing => Box::new(self.question_index.outgoing(target).map(Ok)),
            BucketKind::Deductions => Box::new(self.question_index.deductions(target).map(Ok)),
            BucketKind::Instances => Box::new(self.question_index.instances(target).map(Ok)),
        })
    }
    fn definition_kind(&self, id: DefinitionId) -> Result<Option<DefinitionKind>, ContextError> {
        Ok(ArtifactState::definition_kind(self, id))
    }
}

pub(crate) mod cache;

pub(crate) mod fingerprint;
pub use fingerprint::SetFingerprint;

impl From<naome_proof::DefinitionAccessError> for ContextError {
    fn from(error: naome_proof::DefinitionAccessError) -> Self {
        match error {
            naome_proof::DefinitionAccessError::Storage(message) => Self::Storage(message),
            naome_proof::DefinitionAccessError::Corrupt => Self::Corrupt,
            naome_proof::DefinitionAccessError::Limit => Self::Limit,
        }
    }
}
impl From<ContextError> for naome_proof::DefinitionAccessError {
    fn from(error: ContextError) -> Self {
        match error {
            ContextError::Storage(message) => Self::Storage(message),
            ContextError::Corrupt => Self::Corrupt,
            ContextError::Limit => Self::Limit,
        }
    }
}
