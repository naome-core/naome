//! Operation outcomes retain their meaning until the presentation boundary.
use crate::{
    EvidenceFailure, InputFault, InputLimit,
    outcome::{DurabilityCode, FormatReasonCode, FormatResource, FormatTagClass, OperationCode},
};
use std::{error::Error as StdError, fmt, num::NonZeroI32};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatFailure {
    EmptyCertificate,
    Limit {
        resource: FormatResource,
        actual: Option<u64>,
        maximum: u64,
    },
    ReferenceNotEarlier {
        step: u32,
        reference: u32,
    },
    UnexpectedEnd,
    UnknownTag {
        domain: FormatTagClass,
        tag: u8,
    },
    Formula {
        reason: naome_checker::diagnostics::FormulaFailure,
    },
    TrailingBytes {
        remaining: usize,
    },
    ZeroRelationArity,
    ZeroFunctionArity,
    DefinitionReference {
        definition_id: naome_proof::DefinitionId,
    },
    UndeclaredFormalVariable {
        identifier: u32,
        arity: u32,
    },
    MissingFormalVariable {
        identifier: u32,
        arity: u32,
    },
    Unsupported,
}
impl serde::Serialize for FormatFailure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut value = serializer.serialize_map(None)?;
        let code = match self {
            Self::EmptyCertificate => FormatReasonCode::EmptyCertificate,
            Self::Limit { .. } => FormatReasonCode::Limit,
            Self::ReferenceNotEarlier { .. } => FormatReasonCode::ReferenceNotEarlier,
            Self::UnexpectedEnd => FormatReasonCode::UnexpectedEnd,
            Self::UnknownTag { .. } => FormatReasonCode::UnknownTag,
            Self::Formula { .. } => FormatReasonCode::Formula,
            Self::TrailingBytes { .. } => FormatReasonCode::TrailingBytes,
            Self::ZeroRelationArity => FormatReasonCode::ZeroRelationArity,
            Self::ZeroFunctionArity => FormatReasonCode::ZeroFunctionArity,
            Self::DefinitionReference { .. } => FormatReasonCode::DefinitionReference,
            Self::UndeclaredFormalVariable { .. } => FormatReasonCode::UndeclaredFormalVariable,
            Self::MissingFormalVariable { .. } => FormatReasonCode::MissingFormalVariable,
            Self::Unsupported => FormatReasonCode::Unsupported,
        };
        value.serialize_entry("code", &code)?;
        match self {
            Self::Limit {
                resource,
                actual,
                maximum,
            } => {
                value.serialize_entry("resource", resource)?;
                value.serialize_entry("actual", actual)?;
                value.serialize_entry("maximum", maximum)?;
            }
            Self::ReferenceNotEarlier { step, reference } => {
                value.serialize_entry("step", step)?;
                value.serialize_entry("reference", reference)?;
            }
            Self::UnknownTag { domain, tag } => {
                value.serialize_entry("domain", domain)?;
                value.serialize_entry("tag", tag)?;
            }
            Self::Formula { reason } => value.serialize_entry("reason", reason)?,
            Self::TrailingBytes { remaining } => value.serialize_entry("remaining", remaining)?,
            Self::DefinitionReference { definition_id } => {
                value.serialize_entry("definition", definition_id.as_bytes())?
            }
            Self::UndeclaredFormalVariable { identifier, arity }
            | Self::MissingFormalVariable { identifier, arity } => {
                value.serialize_entry("identifier", identifier)?;
                value.serialize_entry("arity", arity)?;
            }
            Self::EmptyCertificate
            | Self::UnexpectedEnd
            | Self::ZeroRelationArity
            | Self::ZeroFunctionArity
            | Self::Unsupported => {}
        }
        value.end()
    }
}

impl From<&naome_proof::ProofCertificateError> for FormatFailure {
    fn from(error: &naome_proof::ProofCertificateError) -> Self {
        use naome_proof::ProofCertificateError;
        match *error {
            ProofCertificateError::EmptyCertificate => Self::EmptyCertificate,
            ProofCertificateError::TooManySteps { actual, maximum } => Self::Limit {
                resource: FormatResource::Steps,
                actual: Some(actual as u64),
                maximum: maximum as u64,
            },
            ProofCertificateError::InputTooLong { actual, maximum } => Self::Limit {
                resource: FormatResource::Bytes,
                actual: Some(actual as u64),
                maximum: maximum as u64,
            },
            ProofCertificateError::FormulaNodeLimitExceeded { maximum } => Self::Limit {
                resource: FormatResource::Nodes,
                actual: None,
                maximum: maximum as u64,
            },
            ProofCertificateError::ReferenceNotEarlier { step, reference } => {
                Self::ReferenceNotEarlier { step, reference }
            }
            ProofCertificateError::UnexpectedEnd => Self::UnexpectedEnd,
            ProofCertificateError::UnknownStepTag(tag) => Self::UnknownTag {
                domain: FormatTagClass::ProofStep,
                tag,
            },
            ProofCertificateError::UnknownZfcAxiomTag(tag) => Self::UnknownTag {
                domain: FormatTagClass::ZfcAxiom,
                tag,
            },
            ProofCertificateError::Formula(ref reason) => Self::Formula {
                reason: reason.into(),
            },
            ProofCertificateError::DefinedFormula(ref reason) => Self::Formula {
                reason: reason.into(),
            },
            ProofCertificateError::TrailingBytes { remaining } => Self::TrailingBytes { remaining },
            _ => Self::Unsupported,
        }
    }
}

impl From<&naome_proof::DefinitionCertificateError> for FormatFailure {
    fn from(error: &naome_proof::DefinitionCertificateError) -> Self {
        use naome_proof::DefinitionCertificateError as E;
        match *error {
            E::InputTooLong { actual, maximum } => Self::Limit {
                resource: FormatResource::Bytes,
                actual: Some(actual as u64),
                maximum: maximum as u64,
            },
            E::UnexpectedEnd => Self::UnexpectedEnd,
            E::UnknownKindTag(tag) => Self::UnknownTag {
                domain: FormatTagClass::DefinitionKind,
                tag,
            },
            E::ZeroRelationArity => Self::ZeroRelationArity,
            E::ZeroFunctionArity => Self::ZeroFunctionArity,
            E::ArityTooLarge { actual, maximum } => Self::Limit {
                resource: FormatResource::Arity,
                actual: Some(actual),
                maximum: u64::from(maximum),
            },
            E::DefinitionReference { definition_id } => Self::DefinitionReference { definition_id },
            E::UndeclaredFormalVariable { identifier, arity } => {
                Self::UndeclaredFormalVariable { identifier, arity }
            }
            E::MissingFormalVariable { identifier, arity } => {
                Self::MissingFormalVariable { identifier, arity }
            }
            E::Formula(ref reason) => Self::Formula {
                reason: reason.into(),
            },
            E::TrailingBytes { remaining } => Self::TrailingBytes { remaining },
            _ => Self::Unsupported,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateFormatError {
    pub input_digest: naome_checker::diagnostics::Digest,
    pub reason: FormatFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DurabilityFailure {
    pub code: DurabilityCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sqlite_code: Option<NonZeroI32>,
}

impl DurabilityFailure {
    pub(crate) fn new(code: DurabilityCode) -> Self {
        Self {
            code,
            sqlite_code: None,
        }
    }

    pub(crate) fn sqlite(code: DurabilityCode, error: &rusqlite::Error) -> Self {
        Self {
            code,
            sqlite_code: naome_storage::sqlite_code(error),
        }
    }
}

impl From<naome_storage::UncertainCommit> for DurabilityFailure {
    fn from(error: naome_storage::UncertainCommit) -> Self {
        use naome_storage::UncertainCommit;
        let (code, sqlite_code) = match error {
            UncertainCommit::Commit { sqlite_code } => {
                (DurabilityCode::CommitUnconfirmed, sqlite_code)
            }
            UncertainCommit::Rollback { sqlite_code } => {
                (DurabilityCode::RollbackUnconfirmed, sqlite_code)
            }
        };
        Self { code, sqlite_code }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelDigestMismatch {
    pub expected: [u8; 32],
    pub actual: [u8; 32],
}

/// Bounded identity for a backend error whose upstream detail is unstructured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFailure {
    /// Stable category of the backend failure.
    pub code: crate::ResearchFailure,
    /// SHA-256 of upstream detail, if available. Guessable details can be inferred.
    pub detail_digest: Option<[u8; 32]>,
    /// Expected or source tensor element class, when the backend reports it.
    pub expected_type: Option<crate::TensorElementType>,
    /// Actual or destination tensor element class, when the backend reports it.
    pub actual_type: Option<crate::TensorElementType>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    MemoryOverload {
        requested: usize,
        charged: usize,
        budget: usize,
    },
    DiskOverload {
        available: u128,
        required: u128,
    },
    ExecutionLimit,
    InputLimit(InputLimit),
    InputFault(InputFault),
    QuestionLimit(naome_proof::QuestionLimit),
    StaleAuthority,
    Deadline,
    InvalidInput(String),
    MissingQuestionDefinition(naome_proof::DefinitionId),
    MissingRequiredTheorem(naome_proof::ProofId),
    Proof(std::sync::Arc<naome_checker::diagnostics::ProofDiagnostic>),
    DiagnosticInspection(naome_checker::diagnostics::InspectionError),
    CertificateFormat(Box<CertificateFormatError>),
    CertificateConstruction(FormatFailure),
    DefinedFormula(naome_checker::diagnostics::FormulaFailure),
    DefinitionExpansion(naome_checker::diagnostics::ExpansionFailure),
    Schema {
        reason: crate::SchemaFailure,
        variable: u32,
    },
    /// Invalid data read from owned storage remains fatal while retaining the
    /// original structured diagnostic. It is never a candidate repair request.
    Stored(Box<Error>),
    CorruptStorage(String),
    CheckedContext(naome_checker::ContextError),
    UncertainDurability(DurabilityFailure),
    LearningEvidence(EvidenceFailure),
    LearningGraph(crate::LearningGraphFailure),
    ProgramCodec(naome_proof::program::CodecFailure),
    ProgramProjection(naome_proof::program::ProjectionFailure),
    Compression(crate::CompressionFailure),
    ProgramInput(naome_checker::program::ProgramFault),
    Formula(naome_foundation::FormulaCodecError),
    QuestionInput(Box<naome_proof::QuestionError>),
    QuestionRegistration(naome_checker::question::RejectionReason),
    DefinitionCheck(Box<naome_checker::DefinitionCheckError>),
    CheckpointDecode {
        reason: crate::JsonFault,
        line: usize,
        column: usize,
    },
    ObservationUnavailable(Box<Error>),
    ProofCommandInput {
        reason: crate::ProofCommandFault,
        appended: u64,
    },
    RecordDecode {
        reason: crate::JsonFault,
        line: usize,
        column: usize,
    },
    ConfigDecode {
        reason: crate::JsonFault,
        line: usize,
        column: usize,
    },
    ResourceValidation {
        reason: crate::ResourceValidationReason,
        field: Option<crate::resources::ResourceField>,
        actual: Option<u64>,
        minimum: Option<u64>,
        maximum: Option<u64>,
    },
    ResourceProfileDecode {
        reason: crate::JsonFault,
        line: usize,
        column: usize,
    },
    CheckpointSql {
        reason: crate::SqlFault,
        sqlite_code: Option<NonZeroI32>,
    },
    ProgramSql {
        reason: crate::SqlFault,
        sqlite_code: Option<NonZeroI32>,
    },
    CatalogSql {
        reason: crate::SqlFault,
        sqlite_code: Option<NonZeroI32>,
    },
    BacklogSql {
        reason: crate::SqlFault,
        sqlite_code: Option<NonZeroI32>,
    },
    CheckedIndexCloseSql {
        reason: crate::SqlFault,
        sqlite_code: Option<NonZeroI32>,
    },
    CheckedIndexSql {
        reason: crate::SqlFault,
        sqlite_code: Option<NonZeroI32>,
    },
    StorageContext {
        code: crate::InputFault,
        cause: Box<Error>,
    },
    Io {
        kind: crate::IoFaultKind,
        os_code: Option<NonZeroI32>,
    },
    StorageIo {
        operation: crate::StorageIoOperation,
        kind: crate::IoFaultKind,
        os_code: Option<NonZeroI32>,
    },
    Runtime(crate::RuntimeFailure),
    RuntimeContext {
        code: crate::RuntimeFailure,
        cause: Box<Error>,
    },
    ResearchSlot {
        index: usize,
        cause: Box<Error>,
    },
    Research(crate::ResearchFailure),
    ModelDigestMismatch(Box<ModelDigestMismatch>),
    External(Box<ExternalFailure>),
    ResearchMismatch {
        code: crate::ResearchFailure,
        expected: u64,
        actual: u64,
    },
    ResearchIndex {
        code: crate::ResearchFailure,
        index: usize,
    },
    ResearchJob {
        code: crate::ResearchFailure,
        job: u64,
    },
    ResearchContext {
        code: crate::ResearchFailure,
        cause: Box<Error>,
    },
    CompositionReplay {
        work: usize,
        maximum: usize,
    },
    Worker(crate::WorkerFailure),
    ResearchCombined {
        primary: Box<Error>,
        cleanup: Box<Error>,
    },
    StorageCombined {
        primary: Box<Error>,
        cleanup: Box<Error>,
    },
    RuntimeCombined {
        primary: Box<Error>,
        cleanup: Box<Error>,
    },
    Startup {
        code: crate::StartupFailure,
        reaped: bool,
        cause: Option<Box<Error>>,
    },
    StartupCleanup {
        primary: Box<Error>,
        cleanup: Box<Error>,
    },
    StartupChildExit {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
}
impl Error {
    /// The same mathematical contract survives both native proof paths.
    pub fn diagnostic(&self) -> Option<&naome_checker::diagnostics::ProofDiagnostic> {
        match self {
            Self::Proof(diagnostic) => Some(diagnostic),
            Self::Stored(error) => error.diagnostic(),
            _ => None,
        }
    }
    pub fn code(&self) -> u32 {
        let code = match self {
            Self::MemoryOverload { .. } => OperationCode::MemoryOverload,
            Self::DiskOverload { .. } => OperationCode::DiskOverload,
            Self::ExecutionLimit => OperationCode::ExecutionLimit,
            Self::InputLimit(limit) => return (*limit).into(),
            Self::InputFault(fault) => return (*fault).into(),
            Self::QuestionLimit(_) => OperationCode::QuestionLimit,
            Self::StaleAuthority => OperationCode::StaleAuthority,
            Self::Deadline => OperationCode::Deadline,
            Self::InvalidInput(_) => OperationCode::InvalidInput,
            Self::MissingQuestionDefinition(_) => OperationCode::MissingQuestionDefinition,
            Self::MissingRequiredTheorem(_) => OperationCode::MissingRequiredTheorem,
            Self::Proof(_) => OperationCode::ProofCheck,
            Self::DiagnosticInspection(_) => OperationCode::DiagnosticInspection,
            Self::CertificateFormat(_) => OperationCode::CertificateFormat,
            Self::CertificateConstruction(_) => OperationCode::CertificateConstruction,
            Self::DefinedFormula(_) => OperationCode::DefinedFormula,
            Self::DefinitionExpansion(_) => OperationCode::DefinitionExpansion,
            Self::Schema { .. } => OperationCode::Schema,
            Self::Stored(_) => OperationCode::InvalidStoredRecord,
            Self::CorruptStorage(_) => OperationCode::CorruptStorage,
            Self::CheckedContext(_) => OperationCode::CheckedContext,
            Self::UncertainDurability(failure) => return failure.code.into(),
            Self::LearningEvidence(failure) => return failure.code().into(),
            Self::LearningGraph(failure) => return (*failure).into(),
            Self::ProgramCodec(_) => OperationCode::ProgramCodec,
            Self::ProgramProjection(_) => OperationCode::ProgramProjection,
            Self::Compression(_) => OperationCode::Compression,
            Self::ProgramInput(_) => OperationCode::ProgramInput,
            Self::Formula(_) => OperationCode::Formula,
            Self::QuestionInput(_) => OperationCode::QuestionInput,
            Self::QuestionRegistration(_) => OperationCode::QuestionRegistration,
            Self::DefinitionCheck(_) => OperationCode::DefinitionCheck,
            Self::CheckpointDecode { .. } => OperationCode::CheckpointDecode,
            Self::ConfigDecode { .. } => OperationCode::ConfigDecode,
            Self::RecordDecode { .. } => OperationCode::RecordDecode,
            Self::ProofCommandInput { .. } => OperationCode::ProofCommandInput,
            Self::ObservationUnavailable(_) => OperationCode::ObservationUnavailable,
            Self::ResourceProfileDecode { .. } => OperationCode::ResourceProfileDecode,
            Self::ResourceValidation { .. } => OperationCode::ResourceValidation,
            Self::CheckpointSql { .. } => OperationCode::CheckpointSql,
            Self::ProgramSql { .. } => OperationCode::ProgramSql,
            Self::CatalogSql { .. } => OperationCode::CatalogSql,
            Self::BacklogSql { .. } => OperationCode::BacklogSql,
            Self::CheckedIndexCloseSql { .. } => OperationCode::CheckedIndexCloseSql,
            Self::CheckedIndexSql { .. } => OperationCode::CheckedIndexSql,
            Self::StorageContext { code, .. } => return (*code).into(),
            Self::StorageIo { .. } => OperationCode::StorageIo,
            Self::Io { .. } => OperationCode::Io,
            Self::Runtime(failure) => return (*failure).into(),
            Self::RuntimeContext { code, .. } => return (*code).into(),
            Self::ResearchSlot { .. } => return crate::RuntimeFailure::ResearchSlot.into(),
            Self::Research(failure) => return (*failure).into(),
            Self::External(failure) => return failure.code.into(),
            Self::ModelDigestMismatch(_) => {
                return crate::ResearchFailure::ModelDigestMismatch.into();
            }
            Self::ResearchMismatch { code, .. }
            | Self::ResearchIndex { code, .. }
            | Self::ResearchJob { code, .. }
            | Self::ResearchContext { code, .. } => {
                return (*code).into();
            }
            Self::CompositionReplay { .. } => {
                return crate::ResearchFailure::CompositionReplayMismatch.into();
            }
            Self::Worker(failure) => return (*failure).into(),
            Self::ResearchCombined { .. } => {
                return crate::ResearchFailure::MultipleFailures.into();
            }
            Self::StorageCombined { .. } => OperationCode::StorageCombined,
            Self::RuntimeCombined { .. } => return crate::RuntimeFailure::Cleanup.into(),
            Self::Startup { code, .. } => return (*code).into(),
            Self::StartupCleanup { .. } => return crate::RuntimeFailure::Cleanup.into(),
            Self::StartupChildExit { .. } => OperationCode::StartupChildExit,
        };
        code.into()
    }
    pub fn retryable(&self) -> bool {
        if matches!(self, Self::Stored(_)) {
            return false;
        }
        self.diagnostic()
            .is_some_and(|d| matches!(d.failure, naome_checker::diagnostics::Failure::ContextLimit))
            || matches!(
                self,
                Self::ObservationUnavailable(_)
                    | Self::MemoryOverload { .. }
                    | Self::DiskOverload { .. }
                    | Self::ExecutionLimit
                    | Self::StaleAuthority
                    | Self::Deadline
            )
    }
    pub(crate) fn fatal_storage(self) -> Self {
        if self.fatal() {
            self
        } else {
            Self::Stored(Box::new(self))
        }
    }
    pub(crate) fn storage(self) -> Self {
        match self {
            Self::InvalidInput(message) => Self::CorruptStorage(message),
            error @ (Self::InputFault(_)
            | Self::MissingRequiredTheorem(_)
            | Self::QuestionLimit(_)
            | Self::QuestionInput(_)
            | Self::QuestionRegistration(_)
            | Self::DefinitionCheck(_)
            | Self::CheckpointDecode { .. }
            | Self::ConfigDecode { .. }
            | Self::RecordDecode { .. }
            | Self::ResourceProfileDecode { .. }
            | Self::ResourceValidation { .. }
            | Self::CheckpointSql { .. }
            | Self::StorageIo { .. }
            | Self::Io { .. }
            | Self::ProgramInput(_)
            | Self::Formula(_)
            | Self::DefinedFormula(_)
            | Self::DefinitionExpansion(_)
            | Self::Schema { .. }) => Self::Stored(Box::new(error)),
            error @ (Self::Proof(_)
            | Self::CertificateFormat(_)
            | Self::CertificateConstruction(_)
            | Self::ProgramCodec(_)
            | Self::ProgramProjection(_)
            | Self::Compression(_))
                if !error.retryable() =>
            {
                Self::Stored(Box::new(error))
            }
            other => other,
        }
    }
    pub(crate) fn fatal(&self) -> bool {
        self.diagnostic()
            .is_some_and(|d| d.outcome == naome_checker::diagnostics::Outcome::ContextFailure)
            || matches!(
                self,
                Self::Stored(_)
                    | Self::CorruptStorage(_)
                    | Self::ProgramSql { .. }
                    | Self::CatalogSql { .. }
                    | Self::BacklogSql { .. }
                    | Self::CheckedIndexCloseSql { .. }
                    | Self::CheckedIndexSql { .. }
                    | Self::StorageContext { .. }
                    | Self::CheckedContext(_)
                    | Self::UncertainDurability(_)
                    | Self::Runtime(_)
                    | Self::RuntimeContext { .. }
                    | Self::ResearchSlot { .. }
                    | Self::ResearchCombined { .. }
                    | Self::StorageCombined { .. }
                    | Self::RuntimeCombined { .. }
                    | Self::Startup { .. }
                    | Self::StartupCleanup { .. }
            )
            || matches!(
                self,
                Self::Research(
                    crate::ResearchFailure::ClockBeforeEpoch
                        | crate::ResearchFailure::ClockOverflow
                        | crate::ResearchFailure::ClockRollback
                        | crate::ResearchFailure::ElapsedOverflow
                        | crate::ResearchFailure::AccountingRecordMissing
                        | crate::ResearchFailure::MultipleFailures
                        | crate::ResearchFailure::EffectsUnconfirmed
                        | crate::ResearchFailure::DriverPanic
                        | crate::ResearchFailure::StopReceiptUnavailable
                        | crate::ResearchFailure::OwnerThreadPanic
                        | crate::ResearchFailure::OwnerRuntimeUnavailable
                )
            )
    }
    fn format_error(&self) -> Option<(naome_checker::diagnostics::Digest, &FormatFailure)> {
        match self {
            Self::CertificateFormat(error) => Some((error.input_digest, &error.reason)),
            Self::Stored(error) => error.format_error(),
            _ => None,
        }
    }
    #[cfg(test)]
    pub(crate) fn contains(&self, pattern: &str) -> bool {
        self.to_string().contains(pattern)
    }
    #[cfg(test)]
    pub(crate) fn starts_with(&self, pattern: &str) -> bool {
        self.to_string().starts_with(pattern)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryOverload {
                requested,
                charged,
                budget,
            } => write!(
                f,
                "memory overload: requested {requested}, charged {charged}, budget {budget}"
            ),
            Self::DiskOverload {
                available,
                required,
            } => write!(
                f,
                "disk overload: available {available}, required reserve and work {required}"
            ),
            Self::ExecutionLimit => f.write_str("operation execution resources exhausted"),
            Self::InputLimit(limit) => f.write_str(limit.label()),
            Self::InputFault(fault) => f.write_str(match fault {
                InputFault::DescriptionAddressMismatch => "description proof address differs",
                InputFault::ArtifactCompatibilityMismatch => "compatibility mismatch",
                InputFault::CheckedIdentityMismatch => "checked identity mismatch",
                InputFault::MalformedJson => "invalid JSON",
                InputFault::CommandFrameLimit => "command frame limit",
                InputFault::CommandFrameIncomplete => "command frame incomplete",
                InputFault::CommandRead => "command input read failed",
                InputFault::IdentityWidth => "identity width",
                InputFault::HexWidth => "hex width",
                InputFault::HexNoncanonical => "noncanonical hex",
                InputFault::PrerequisiteDuplicate => "duplicate prerequisite",
                InputFault::PrerequisiteProgramInvalid => "invalid prerequisite program",
                InputFault::PrerequisiteOfferedProofMissing => {
                    "offered theorem absent from captured inputs"
                }
                InputFault::PrerequisiteNotClosed => "prerequisite is not closed",
                InputFault::PrerequisiteObligationMissing => {
                    "prerequisite definition obligation missing"
                }
                InputFault::RegularFileRequired => "regular file required",
                InputFault::RelayListenAddress => "invalid relay listen address",
                InputFault::RelayExternalAddress => "invalid relay external address",
                InputFault::FormalGoalRequiresNative => {
                    "formal goal requires native proof learning"
                }
                InputFault::QuestionRegistryPopulated => "question registry is already populated",
                InputFault::CheckpointRecordKey => "checkpoint record key or kind is invalid",
                InputFault::CheckpointRecordReadLimit => "checkpoint record exceeds its read limit",
                InputFault::CheckpointRecordDigest => "checkpoint record digest differs",
                InputFault::CheckpointPageBudget => "checkpoint page budget must be positive",
                InputFault::CheckpointPageByteWidth => "checkpoint page byte width",
                InputFault::CheckpointPageRecordWidth => "checkpoint page record width",
                InputFault::CheckpointPageMemoryOverflow => "checkpoint page memory overflow",
                InputFault::CheckpointPageMemoryLimit => {
                    "checkpoint record exceeds page memory budget"
                }
                InputFault::CheckpointFileReplaced => "transactional checkpoint file was replaced",
                InputFault::CheckpointOutsideOwner => {
                    "transactional checkpoint changed outside its owner"
                }
                InputFault::CheckpointEncoding => "checkpoint encoding failed",
                InputFault::CheckpointNoncanonical => "noncanonical checkpoint record",
                InputFault::CheckpointHeaderCardinality => "checkpoint header cardinality differs",
                InputFault::CheckpointHeaderDomain => "checkpoint header domain differs",
                InputFault::CheckpointHeaderCapacity => "checkpoint header exceeds its capacity",
                InputFault::CheckpointHeaderDigest => "checkpoint header digest differs",
                InputFault::CheckpointHeaderCount => "checkpoint header count width",
                InputFault::CheckpointIdentity => "unsupported transactional checkpoint",
                InputFault::CheckpointSchema => "transactional checkpoint schema differs",
                InputFault::CheckpointIntegrity => "transactional checkpoint integrity failure",
                InputFault::CheckpointRowCount => "transactional checkpoint row count differs",
                InputFault::CheckpointCountWidth => "checkpoint count width",
                InputFault::CheckpointReadWidth => "checkpoint read width",
                InputFault::CheckpointUnexpectedKind => "unexpected checkpoint record kind",
                InputFault::CheckpointParentMissing => "checkpoint parent missing",
                InputFault::CheckpointFilenameMissing => "checkpoint filename missing",
                InputFault::CheckpointTargetExists => {
                    "checkpoint publication target already exists"
                }
                InputFault::OwnedFileType => "local store must be a regular file",
                InputFault::OwnedFileLinks => "local store has invalid link count",
                InputFault::OwnedFileOwner => "local store is not owned by this process",
                InputFault::OwnedInputLimitWidth => "local input read limit",
                InputFault::OwnedInputCapacity => "local input byte capacity",
                InputFault::MarkerCorrupt => "research initialization marker corruption",
                InputFault::MarkerParentMissing => "research marker parent absent",
                InputFault::ResourceCustomInvalid => "custom resource limits are inconsistent",
                InputFault::ResourceCustomProfileMismatch => {
                    "custom settings require the custom profile"
                }
                InputFault::ResourceEffectiveEncoding => "effective resource profile is not UTF-8",
                InputFault::ResourceEffectiveCapacity => "effective resource profile capacity",
                InputFault::ResourceEffectiveIdentity => "unsupported effective resource profile",
                InputFault::ResourceImmutable => {
                    "resource profile is immutable after initialization"
                }
                InputFault::ResourceInitializationRace => {
                    "concurrent resource profile initialization"
                }
                InputFault::ResearchCompatibility => "research compatibility differs",
                InputFault::CooperativeRole => "cooperative binding requires a solving job",
                InputFault::EmptyTrainingEpoch => "empty native learning epoch",
                InputFault::PeerIdentitySyntax => "peer identity syntax",
                InputFault::PeerIdentityEncoding => "peer identity encoding",
                InputFault::RequiredTheorems => "required theorem role or capacity",
                InputFault::PrerequisiteRoots => "temporary prerequisites lack required roots",
                InputFault::ProgramReplyRoot => "program reply root mismatch",
                InputFault::ProgramReplyId => "program reply identity mismatch",
                InputFault::ProgramReplyStart => "program reply start mismatch",
                InputFault::ProgramReplyEmpty => "program reply is empty",
                InputFault::ProgramReplyLimit => "program reply exceeds requested limit",
                InputFault::ProgramDescriptionRoot => "program description root mismatch",
                InputFault::ProgramDescriptionId => "program description identity mismatch",
                InputFault::StoredQuestionProofHeaderMissing => "checked proof header missing",
                InputFault::StoredQuestionBinding => "stored exchange question does not bind the checked proof",
                InputFault::CheckedStorageHaltPoisoned => "checked storage halt lock poisoned",
                InputFault::CatalogReplayCursorWidth => "catalog replay cursor width",
                InputFault::CatalogReplayCursorBeyondCount => "catalog replay cursor exceeds corpus count",
                InputFault::CatalogReplayPageWidth => "catalog page width",
                InputFault::CatalogReplayOrdinalOverflow => "catalog replay ordinal overflow",
                InputFault::CatalogReplayOrderIncomplete => "catalog replay ordering is incomplete",
                InputFault::CatalogReplayPageCount => "catalog replay page count differs",
                InputFault::CatalogReplayProofMissing => "catalog replay proof disappeared",
                InputFault::CatalogReplayProofOrder => "catalog replay proof order differs",
                InputFault::CatalogProofIdOrdering => "catalog proof ID page ordering differs",
                InputFault::CatalogChangedDuringReplay => "catalog changed during mathematical replay",
                InputFault::CatalogReplayRoot => "replayed corpus root differs from catalog",
                InputFault::CatalogQuestionMemberMissing => "catalog question has no member",
                InputFault::CatalogExternalChange => "proof catalog changed outside its owned connection",
                InputFault::CatalogNotValidated => "proof catalog has not been validated",
                InputFault::CatalogSchemaUnsupported => "unsupported or uninitialized proof catalog",
                InputFault::CatalogSchemaObject => "unexpected catalog schema object",
                InputFault::CatalogSchemaMismatch => "catalog schema differs from the current contract",
                InputFault::CatalogSchemaIncomplete => "incomplete catalog schema",
                InputFault::CatalogMetadataCardinality => "catalog metadata row count differs",
                InputFault::CatalogDatabaseIdentity => "catalog database identity differs from lineage receipt",
                InputFault::CatalogActivationState => "catalog activation state differs",
                InputFault::CatalogActivationRoot => "catalog activation root missing or premature",
                InputFault::CatalogInitialData => "initializing catalog contains accepted data",
                InputFault::CatalogValidationProofMissing => "missing catalog proof during validation",
                InputFault::CatalogPayloadCount => "catalog payload count differs",
                InputFault::CatalogNotActive => "canonical catalog is not active",
                InputFault::CatalogSummaryMismatch => "canonical catalog differs from the committed graph summary",
                InputFault::CatalogPayloadLength => "catalog payload length differs",
                InputFault::CatalogPayloadDigest => "catalog payload length or digest differs",
                InputFault::CatalogProofIdentity => "catalog canonical proof identity differs",
                InputFault::CatalogOriginMembership => "catalog proof originating membership differs",
                InputFault::CatalogOriginCommitMissing => "catalog proof originating commit missing",
                InputFault::CatalogDependencyOrder => "catalog dependency replay order differs",
                InputFault::CatalogCorpusSummary => "catalog corpus root, count or byte total differs",
                InputFault::CatalogRelationCount => "catalog relation count differs",
                InputFault::CatalogMembershipIncomplete => "incomplete catalog commit membership",
                InputFault::CatalogDependencyMissing => "catalog has missing proof dependencies",
                InputFault::CatalogCommitRootMissing => "catalog commit root missing from members",
                InputFault::CatalogProofCollision => "immutable catalog proof collision or corruption",
                InputFault::CatalogCommitDigest => "catalog commit digest differs",
                InputFault::CatalogFileType => "proof catalog must be a regular file",
                InputFault::CatalogStageFileType => "catalog initialization stage is not a regular file",
                InputFault::CatalogStageNotEmpty => "catalog initialization stage is not empty",
                InputFault::CatalogPeerCursorWidth => "peer learning cursor width",
                InputFault::CatalogPeerOrdinalWidth => "peer learning ordinal",
                InputFault::CatalogPeerOriginSyntax => "peer learning origin syntax",
                InputFault::CatalogPeerOrdinalMismatch => "peer learning ordinal differs",
                InputFault::CatalogPageCountWidth => "catalog page count width",
                InputFault::CatalogBatchCount => "catalog batch object count limit",
                InputFault::CatalogBatchByteOverflow => "catalog batch byte overflow",
                InputFault::CatalogBatchByteCapacity => "catalog batch byte capacity",
                InputFault::CatalogBatchDuplicateProof => "duplicate catalog batch proof ID",
                InputFault::CatalogBatchEmpty => "empty catalog batch",
                InputFault::CatalogFilenameMissing => "proof catalog filename missing",
                InputFault::CatalogJournalMode => "catalog journal mode differs",
                InputFault::CatalogBusyTimeoutWidth => "catalog busy timeout width",
                InputFault::CatalogFullSync => "catalog fullfsync differs",
                InputFault::CatalogCountWidth => "catalog count width",
                InputFault::CatalogByteWidth => "catalog byte width",
                InputFault::CatalogReplayCountOverflow => "catalog replay count overflow",
                InputFault::CatalogReplayCountWidth => "catalog replay count width",
                InputFault::CatalogPayloadLengthWidth => "catalog payload length width",
                InputFault::CatalogProofMemoryOverflow => "proof memory overflow",
                InputFault::CatalogPayloadWidth => "catalog payload width differs",
                InputFault::CatalogCountOverflow => "catalog count overflow",
                InputFault::CatalogByteOverflow => "catalog byte overflow",
                InputFault::CatalogSuccessorFingerprintMissing => "checked successor fingerprint missing",
                InputFault::CatalogMetadataUpdateCount => "catalog metadata update count differs",
                InputFault::CatalogProofAlreadyOwned => "concrete proof already belongs to another commit",
                InputFault::CatalogCommitPeerOrigin => "catalog commit peer origin differs",
                InputFault::CatalogCommitMembership => "existing catalog commit membership differs",
                InputFault::CatalogCommitProofMissing => "catalog commit proof missing",
                InputFault::CatalogDependencyOrdering => "catalog dependency ordering or width differs",
                InputFault::CatalogMembershipOrdering => "catalog membership ordering differs",
                InputFault::CatalogMembershipCountOverflow => "catalog membership count overflow",
                InputFault::CatalogCommitCountWidth => "catalog commit count width",
                InputFault::CatalogValidationCommitProofMissing => "missing catalog commit proof",
                InputFault::CatalogProofOwnerMismatch => "catalog proof belongs to a different originating commit",
                InputFault::CatalogRelationCountWidth => "catalog relation count width",
                InputFault::CatalogIdentityWidth => "catalog identity width",
                InputFault::CatalogOrdinalWidth => "catalog replay ordinal width",
                InputFault::CatalogOrdinalZero => "catalog replay ordinal must be positive",
                InputFault::CatalogIntegerWidth => "catalog integer width",
                InputFault::CatalogActivatedMissing => "activated proof catalog missing",
                InputFault::CatalogReceiptMissing => "active proof catalog format receipt missing",
                InputFault::CatalogStageAcceptedData => "unexpected accepted data in catalog initialization stage",
                InputFault::CatalogGenerationPoisoned => "proof catalog generation poisoned",
                InputFault::CatalogLockPoisoned => "proof catalog lock poisoned",
                InputFault::CorpusLeafType => "proof corpus leaf must be a regular unaliased file",
                InputFault::CorpusLeafLinks => "proof corpus leaf has linked aliases",
                InputFault::CorpusReceiptInvalid => "unsupported or corrupt proof corpus format receipt",
                InputFault::CorpusReceiptWidth => "proof corpus format identity width",
                InputFault::CorpusReceiptConflict => "conflicting proof corpus format recovery receipt",
                InputFault::CorpusReceiptType => "proof corpus receipt must be a regular unaliased file",
                InputFault::CorpusReceiptLinks => "proof corpus receipt has linked aliases",
                InputFault::CorpusReceiptChanged => "proof corpus receipt identity changed",
                InputFault::CatalogClock => "catalog clock precedes its epoch",
                InputFault::CatalogDirectoryOwned => "knowledge directory already owned",
                InputFault::CatalogProgramAddressExhausted => "physical program address exhausted",
                InputFault::CatalogProgramAddressNegative => "negative program address",
                InputFault::CatalogProgramStagingMissing => "program staging missing",
                InputFault::CatalogProgramManifestChanged => "program manifest changed",
                InputFault::CatalogProgramPrefixExceeds => "program prefix exceeds manifest",
                InputFault::CatalogProgramAddressMismatch => "program address differs",
                InputFault::CatalogProgramCursorBeyondPrefix => "program cursor exceeds received prefix",
                InputFault::CatalogProgramIdentityMismatch => "staged program identity differs",
                InputFault::CatalogProgramInputOrdering => "staged program input order or width differs",
                InputFault::CatalogProgramInputHash => "staged program input hash differs",
                InputFault::CatalogProgramStreamSuffix => "staged program stream suffix differs",
                InputFault::CatalogProgramStreamRoot => "staged program stream root differs",
                InputFault::CheckedIndexLockPoisoned => "checked index lock poisoned",
                InputFault::CheckedCacheLockPoisoned => "checked cache lock poisoned",
                InputFault::CheckedWritePhaseActive => "checked index write phase already active",
                InputFault::CheckedWritePhaseMissing => "checked index write phase missing",
                InputFault::CheckedWriteBufferActive => "startup buffer must finish before COMMIT",
                InputFault::CheckedSourceBegin => "checked admission source BEGIN",
                InputFault::CheckedMirrorBegin => "checked admission mirror BEGIN",
                InputFault::CheckedSourceCommit => "checked admission source COMMIT",
                InputFault::CheckedMirrorCommit => "checked admission mirror COMMIT",
                InputFault::CheckedWriteGatePoisoned => "checked write gate poisoned",
                InputFault::CheckedHaltLockPoisoned => "checked halt lock poisoned",
                InputFault::CheckedCopyMirrorAttached => "checked copy mirror already attached or cyclic",
                InputFault::CheckedCopyTargetMirrors => "checked copy target already mirrors another generation",
                InputFault::CheckedCopyEpochOverflow => "checked copy epoch overflow",
                InputFault::CheckedCopyRouteChanged => "checked copy source epoch or target changed",
                InputFault::CheckedAdmissionOwned => "checked admission phase already owned",
                InputFault::CheckedAdmissionEpochMissing => "checked admission has no source epoch",
                InputFault::CheckedAdmissionOwnerChanged => "checked admission generation, epoch or phase owner changed",
                InputFault::CheckedSourceGate => "checked admission source gate",
                InputFault::CheckedMirrorGate => "checked admission mirror gate",
                InputFault::CheckedStartupPageUnavailable => "startup page already buffered or closed",
                InputFault::CheckedSuccessorBuffered => "startup buffer has no published successor",
                InputFault::CheckedGenerationOverflow => "checked generation number overflow",
                InputFault::CheckedStartupVacuumMode => "startup checked storage requires incremental vacuum",
                InputFault::CheckedIndexSizeOverflow => "checked index size overflow",
                InputFault::CheckedIndexSizeWidth => "checked index size width",
                InputFault::CheckedPruneUnfinishedPage => "startup prune requires a finished replay page",
                InputFault::CheckedPruneVacuumMode => "startup prune requires incremental vacuum",
                InputFault::CheckedPruneReclaimIncomplete => "startup checked storage reclaim is incomplete",
                InputFault::CheckedIndexFileType => "checked index is not a regular file",
                InputFault::CheckedIndexFileLinks => "checked index has linked aliases",
                InputFault::DescriptionStatementMismatch => "description statement does not match a question target",
                InputFault::StatementIdentityWidth => "statement identity width",
                InputFault::CheckedConclusionMissing => "checked proof conclusion missing",
                InputFault::DiscoveryProtocolInvalid => "invalid discovery protocol",
                InputFault::NetworkRelayPolicy => "relay-only mode requires relays and disables mDNS",
                InputFault::NetworkRelayId => "invalid relay identity",
                InputFault::NetworkRelayAddress => "invalid relay address",
                InputFault::NetworkBootstrapId => "invalid bootstrap identity",
                InputFault::NetworkBootstrapAddress => "invalid bootstrap address",
                InputFault::NetworkPeerId => "invalid configured peer identity",
                InputFault::NetworkPeerAddress => "invalid configured peer address",
                InputFault::NetworkDuplicatePeer => "duplicate configured peer",
                InputFault::NetworkListenAddress => "invalid TCP listen address",
                InputFault::NetworkExternalAddress => "invalid external address",
                InputFault::NetworkDirectAdvertisement => "relay-only mode cannot advertise a direct endpoint",
                InputFault::RouteTargetRequired => "routing requires a target peer ID",
                InputFault::ContactStaticPolicy => "static peer policy",
                InputFault::RouteAddressBytes => "routing address byte limit",
                InputFault::RouteEndpointInvalid => "invalid routable TCP endpoint",
                InputFault::RouteTargetInvalid => "invalid routing target or unconfigured relay",
                InputFault::ContactAllocationOverflow => "contact allocation overflow",
                InputFault::ContactRetired => "retired contact backoff",
                InputFault::ContactSelf => "self contact",
                InputFault::ContactCapacity => "contact capacity",
                InputFault::ContactDisabled => "contact disabled",
                InputFault::ContactPrivateAddress => "untrusted private routing address",
                InputFault::ContactDirectDisabled => "direct proof address disabled",
                InputFault::ContactAddressCapacity => "contact address capacity",
                InputFault::ContactPinnedCapacity => "pinned contact capacity",
                InputFault::ContactInboundDirectDisabled => "direct proof connection disabled",
                InputFault::ContactInboundSender => "invalid inbound circuit sender",
                InputFault::ContactLocalAddress => "LAN discovery requires a safe literal endpoint",
                InputFault::NodeDirectoryUnset => "node directory environment is unset",
                InputFault::NodeDirectoryEmpty => "node directory is empty",
                InputFault::LifecycleLockTimeout => "lifecycle operation lock timed out",
                InputFault::StartupHandoffExisting => "startup handoff requires a new daemon",
                InputFault::StartupLifelineMissing => "startup parent lifeline missing",
                InputFault::ResourceSnapshotEncoding => "effective resource snapshot encoding failed",
                InputFault::ReplayClockNegative => "negative replay clock",
                InputFault::ReplayClockOverflow => "replay clock overflow",
                InputFault::ReplayRssNegative => "negative replay RSS",
                InputFault::ReplayRssOverflow => "replay RSS overflow",
                InputFault::ReplayRssUnavailable => "own replay RSS unavailable",
                InputFault::ReplayDescriptor => "invalid status replay descriptor",
                InputFault::ReplayNonce => "invalid status replay nonce",
                InputFault::ReplayCutoff => "invalid replay cutoff",
                InputFault::ReplayWindow => "status replay cutoff is expired or exceeds its configured allowance",
                InputFault::ReplayFrameLimit => "status replay frame limit",
                InputFault::ReplayFrameEncoding => "invalid replay frame",
                InputFault::ReplayGrantIdentity => "status replay grant identity differs",
                InputFault::ReplaySequence => "invalid replay sequence",
                InputFault::ReplaySampleClock => "invalid replay sample clock",
                InputFault::ReplayGrantOrder => "status replay sequence, freshness or cutoff differs",
                InputFault::ReplayGrantExpired => "status replay grant expired",
                InputFault::ReplayDeadline => "original status replay deadline reached",
                InputFault::ReplayMemory => "status replay own RSS exceeds its configured budget or is unavailable",
                InputFault::ReplaySetting => "invalid status replay setting",
                InputFault::ReplayCommand => "status replay guard requires the status command",
                InputFault::ReplaySession => "status replay guard requires its own detached group",
                InputFault::ReplayInitialGrant => "status replay initial grant unavailable",
                InputFault::ReplayLifelineClosed => "status replay parent lifeline closed",
                InputFault::ReplayCallerGone => "status replay caller gone",
                InputFault::ReplayFinalGrant => "status replay final grant expired",
                InputFault::ReplayWatcherPanicked => "status replay watcher panicked",
                InputFault::CliArgumentsInvalid => "invalid command arguments",
                InputFault::CliHandoffCommand => "startup handoff requires start",
                InputFault::StatusEncoding => "status encoding failed",
                InputFault::TransportTaskCancelled => "transport task cancelled",
                InputFault::TransportTaskFailed => "transport task failed",
                InputFault::StartupAbortReport => "startup abort report failed",
                InputFault::StartupDeadline => "node startup deadline",
                InputFault::StartupAcknowledgementDeadline => "node startup acknowledgement deadline",
                InputFault::StartupPidInvalid => "invalid owned startup process identity",
                InputFault::StartupReapUnconfirmed => "owned startup exit and reap remain unconfirmed",
                InputFault::ControlNonceMissing => "internal launch nonce missing",
                InputFault::ControlNonceInvalid => "invalid internal launch nonce",
                InputFault::ControlSocketPath => "local control path is not a socket",
                InputFault::ControlEndpointEncode => "control endpoint encoding failed",
                InputFault::ControlTaskCancelled => "control task cancelled",
                InputFault::ControlTaskFailed => "control task failed",
                InputFault::IdentityKeyMissing => "existing node identity is missing",
                InputFault::IdentityKeyEncode => "node identity encoding failed",
                InputFault::IdentityKeyDecode => "node identity decoding failed",
                InputFault::IdentityReceiptVersion => "unsupported node identity receipt version",
                InputFault::IdentityReceiptMismatch => "node identity receipt mismatch",
                InputFault::IdentityReceiptMissing => "node identity receipt missing",
                InputFault::IdentityReceiptEncode => "node identity receipt encoding failed",
                InputFault::RuntimeConfigEncode => "runtime configuration encoding failed",
                InputFault::RuntimeIntervalsWidth => "runtime intervals must be representable",
                InputFault::RuntimeConfigObject => "node configuration must be an object",
                InputFault::RuntimeConfigDirectory => "configuration directory must be a path",
                InputFault::RuntimeConfigOwner => "configuration belongs to another node directory",
                InputFault::RuntimeConfigProducer => "producer artifacts require a developer operation",
                InputFault::LogRecordEncoding => "runtime event encoding failed",
                InputFault::LogRecordCapacity => "runtime event exceeds log capacity",
                InputFault::LogFileInvalid => "runtime log must be one owned regular file",
                InputFault::LogPathInvalid => "runtime log path must be a regular file",
                InputFault::CorpusCountWidth => "corpus count width",
                InputFault::AcceptedCountOverflow => "accepted count overflow",
                InputFault::NodeDirectoryInvalid => "node state must be one owned directory",
                InputFault::CalibrationDescriptorReserve => "available descriptors cannot preserve reserves",
                InputFault::CalibrationMemoryReserve => "available hardware cannot preserve checker and replay reserves",
                InputFault::CalibrationCpuWidth => "CPU capacity width",
                InputFault::ObservationNumeric => "hardware observation numeric value invalid",
                InputFault::ObservationCapacity => "hardware observation capacity",
                InputFault::ObservationProcessFormat => "process observation format invalid",
                InputFault::ObservationProcessOverflow => "process observation overflow",
                InputFault::ObservationProcessDuplicate => "duplicate process observation",
                InputFault::ObservationProcessMissing => "node process observation absent",
                InputFault::ObservationProcessCycle => "cyclic process observation",
                InputFault::ObservationPlatformField => "platform observation field missing or invalid",
                InputFault::ObservationCgroupMembership => "invalid cgroup membership",
                InputFault::ObservationCgroupPath => "invalid cgroup path",
                InputFault::ObservationCgroupQuota => "invalid cgroup CPU quota",
                InputFault::ObservationIncomplete => "hardware observation incomplete",
                InputFault::ObservationClock => "hardware observation clock before epoch",
                InputFault::ObservationClockWidth => "hardware observation clock width",
                InputFault::ProbeCustodyPoisoned => "hardware probe custody unavailable",
                InputFault::ProbeCustodyUnconfirmed => "hardware probe custody unconfirmed",
                InputFault::ProbeCleanupPending => "previous hardware probe cleanup pending",
                InputFault::ProbeDeadline => "hardware observation deadline",
                InputFault::ProbeOutputMissing => "hardware observation output absent",
                InputFault::ProbeCapacity => "hardware observation capacity",
                InputFault::ProbeExitFailure => "hardware observation failed",
                InputFault::ProbeOutputEncoding => "hardware observation output encoding",
                InputFault::ProofWorkChanged => "proof work changed outside its owner",
                InputFault::ProofWorkFilename => "proof work filename missing",
                InputFault::ProofBudgetEncoding => "proof budget encoding failed",
                InputFault::ProofCacheBudget => "invalid effective cache budget",
                InputFault::ProofWorkBudget => "invalid effective proof budget",
                InputFault::CandidateDirectoryInvalid => "candidate cache directory must be owned",
                InputFault::CandidateChanged => "candidate changed during retirement",
                InputFault::CandidateFormat => "candidate cache format differs",
                InputFault::CandidateLockChanged => "candidate lock changed before orphan retirement",
                InputFault::ControlEndpointInvalid => "invalid local control endpoint",
                InputFault::ControlFrameIncomplete => "local control frame incomplete",
                InputFault::ControlFrameLimit => "local control frame limit",
                InputFault::ControlReadTimeout => "local control read timeout",
                InputFault::ControlWriteTimeout => "local control write timeout",
                InputFault::ControlConnectTimeout => "local control connect timeout",
                InputFault::ControlResponseMismatch => "local control response instance mismatch",
                InputFault::ControlJsonIo => "local control JSON I/O",
                InputFault::ControlJsonSyntax => "local control JSON syntax",
                InputFault::ControlJsonData => "local control JSON data",
                InputFault::ControlJsonEof => "local control JSON incomplete",
                InputFault::StopProcessGroupUnconfirmed => "daemon process group exit unconfirmed",
                InputFault::StopProcessIdentity => "invalid daemon process identity",
                InputFault::ResearchDirectoryInvalid => "research path must be one owned directory",
                InputFault::DisposableIndexOwned => "disposable index already owned",
                InputFault::DisposableIndexSequence => "disposable index sequence exhausted",
                InputFault::DisposableIndexClock => "disposable index clock before epoch",
                InputFault::DisposableIndexParent => "disposable index parent missing",
                InputFault::DisposableIndexConnectionPoisoned => "disposable index connection poisoned",
                InputFault::DisposableIndexMirrorPoisoned => "disposable index mirror poisoned",
                InputFault::DisposableIndexMirrorActive => "disposable index mirror already active",
                InputFault::DisposableIndexClosed => "disposable index connection closed",
                InputFault::DisposableIndexSize => "disposable index size overflow",
                InputFault::DisposableIndexChanged => "disposable index changed during inspection",
                InputFault::RegistryCompactionSize => "registry compaction size overflow",
                InputFault::RegistryCompactionWidth => "registry compaction disk width",
                InputFault::CheckedCacheSizeWidth => "checked index cache size width",
                InputFault::CheckedIndexClosed => "checked index connection closed",
                InputFault::CatalogProgramPrefixSummary => "staged program prefix summary differs",
                InputFault::CatalogFileChanged => "proof catalog file changed outside its owned connection",
                InputFault::CatalogPageLimit => "catalog page limit outside supported bounds",
                InputFault::CatalogForeignKeyMismatch => "catalog foreign-key relation differs",
                InputFault::CheckedInventoryMismatch => "canonical inventory differs from checked set",
                InputFault::ResourceObservationDirectory => {
                    "resource observation directory is unavailable"
                }
            }),
            Self::QuestionLimit(limit) => naome_proof::QuestionError::Limit(*limit).fmt(f),
            Self::InvalidInput(message) => f.write_str(message),
            Self::MissingRequiredTheorem(id) => write!(f, "required theorem unavailable: {id:?}"),
            Self::MissingQuestionDefinition(id) => {
                write!(f, "question definition unavailable: {id:?}")
            }
            Self::Proof(diagnostic) => write!(
                f,
                "proof step {} violates {}",
                diagnostic.location.step,
                diagnostic.code()
            ),
            Self::DiagnosticInspection(error) => error.fmt(f),
            Self::CertificateFormat(error) => {
                write!(f, "malformed certificate: {:?}", error.reason)
            }
            Self::DefinedFormula(reason) => write!(f, "defined formula: {reason:?}"),
            Self::DefinitionExpansion(reason) => write!(f, "definition expansion: {reason:?}"),
            Self::Schema { reason, variable } => {
                write!(f, "schema {} variable {variable}", u32::from(*reason))
            }
            Self::CertificateConstruction(reason) => {
                write!(f, "certificate construction: {reason:?}")
            }
            Self::Stored(error) => write!(f, "storage halted: {error}"),
            Self::CorruptStorage(message) => write!(f, "storage halted: {message}"),
            Self::CheckedContext(error) => write!(f, "storage halted: {error}"),
            Self::LearningEvidence(error) => error.fmt(f),
            Self::LearningGraph(error) => error.fmt(f),
            Self::ProgramCodec(error) => error.fmt(f),
            Self::ProgramProjection(error) => error.fmt(f),
            Self::Compression(error) => error.fmt(f),
            Self::ProgramInput(error) => error.fmt(f),
            Self::Formula(error) => error.fmt(f),
            Self::QuestionInput(error) => error.fmt(f),
            Self::QuestionRegistration(reason) => write!(f, "question registration: {reason:?}"),
            Self::DefinitionCheck(reason) => write!(f, "definition check: {reason}"),
            Self::Io { kind, os_code } => {
                write!(f, "IO failure {} ({os_code:?})", u32::from(*kind))
            }
            Self::StorageIo {
                operation,
                kind,
                os_code,
            } => write!(
                f,
                "storage IO failure {}:{} ({os_code:?})",
                u32::from(*operation),
                u32::from(*kind)
            ),
            Self::ProgramSql {
                reason,
                sqlite_code,
            } => write!(
                f,
                "program SQLite failure {} ({sqlite_code:?})",
                u32::from(*reason)
            ),
            Self::CatalogSql { reason, sqlite_code } => write!(
                f,
                "catalog SQLite failure {} ({sqlite_code:?})",
                u32::from(*reason)
            ),
            Self::BacklogSql { reason, sqlite_code } => write!(
                f,
                "backlog SQLite failure {} ({sqlite_code:?})",
                u32::from(*reason)
            ),
            Self::CheckedIndexSql { reason, sqlite_code } => write!(f, "checked index SQLite failure {} ({sqlite_code:?})", u32::from(*reason)),
            Self::StorageContext { code, cause } => write!(f, "storage phase {}: {cause}", u32::from(*code)),
            Self::CheckedIndexCloseSql { reason, sqlite_code } => write!(
                f, "checked index close failure {} ({sqlite_code:?})", u32::from(*reason)
            ),
            Self::CheckpointSql {
                reason,
                sqlite_code,
            } => write!(
                f,
                "checkpoint SQLite failure {} ({sqlite_code:?})",
                u32::from(*reason)
            ),
            Self::ResourceValidation {
                reason,
                field,
                actual,
                minimum,
                maximum,
            } => write!(
                f,
                "resource validation {} ({field:?}, {actual:?}, {minimum:?}, {maximum:?})",
                u32::from(*reason)
            ),
            Self::ResourceProfileDecode {
                reason,
                line,
                column,
            } => write!(
                f,
                "resource profile decode failure {} at {line}:{column}",
                u32::from(*reason)
            ),
            Self::ObservationUnavailable(cause) => write!(f, "hardware observation unavailable: {cause}"),
            Self::ProofCommandInput { reason, appended } => write!(f, "proof command failure {} after {appended} appended records", u32::from(*reason)),
            Self::RecordDecode { reason, line, column } => write!(f, "record decode failure {} at {line}:{column}", u32::from(*reason)),
            Self::ConfigDecode { reason, line, column } => write!(f, "configuration decode failure {} at {line}:{column}", u32::from(*reason)),
            Self::CheckpointDecode {
                reason,
                line,
                column,
            } => write!(
                f,
                "checkpoint decoding failure {} at {line}:{column}",
                u32::from(*reason)
            ),
            Self::Runtime(failure) => write!(f, "runtime failure {}", u32::from(*failure)),
            Self::RuntimeContext { code, cause } => {
                write!(f, "runtime failure {}: {cause}", u32::from(*code))
            }
            Self::Worker(failure) => write!(f, "worker failure {}", u32::from(*failure)),
            Self::Research(failure) => f.write_str(match failure {
                crate::ResearchFailure::EvidenceIdentity => "research evidence identity differs",
                crate::ResearchFailure::EvidenceHelperCapacity => "research helper plan capacity",
                crate::ResearchFailure::EvidenceHelperSource => {
                    "research helper plan source differs"
                }
                crate::ResearchFailure::EvidenceOutcome => {
                    "research evidence outcome or cost differs"
                }
                crate::ResearchFailure::EvidenceInitialization => {
                    "Finder initialization would replace actual experience"
                }
                crate::ResearchFailure::EvidenceDrawOverflow => "research draw overflow",
                crate::ResearchFailure::EvidenceObservationOverflow => {
                    "finder observation overflow"
                }
                crate::ResearchFailure::EvidenceCompletedReceipt => {
                    "finder experience substituted a completed receipt"
                }
                crate::ResearchFailure::EvidenceAttemptOverflow => "research attempt overflow",
                crate::ResearchFailure::EvidenceWorkOverflow => "research work overflow",
                crate::ResearchFailure::EvidenceTimeOverflow => "research time overflow",
                crate::ResearchFailure::EvidencePlanBinding => {
                    "research recursive plan binding or capacity"
                }
                crate::ResearchFailure::EvidencePlanCycle => "research recursive plan cycle",
                crate::ResearchFailure::EvidencePreparedJob => "research prepared job differs",
                crate::ResearchFailure::EvidenceCandidateRequired => {
                    "only a candidate job can supply checked evidence"
                }
                crate::ResearchFailure::EvidenceProofSourceMissing => {
                    "finder proof index source is missing"
                }
                crate::ResearchFailure::EvidenceProofIdentity => {
                    "finder proof index identity differs"
                }
                crate::ResearchFailure::EvidenceSupportReceipt => {
                    "finder support receipt identity differs"
                }
                crate::ResearchFailure::EvidenceSupportOverflow => "finder support count overflow",
                crate::ResearchFailure::FrontierFormulaCapacity => "open branch formula capacity",
                crate::ResearchFailure::FrontierFormulaEncoding => "open branch formula encoding",
                crate::ResearchFailure::FrontierObservationCapacity => {
                    "open branch observation capacity"
                }
                crate::ResearchFailure::FrontierTargetBinding => {
                    "open branch target binding differs"
                }
                crate::ResearchFailure::FrontierStateCapacity => "open branch state capacity",
                crate::ResearchFailure::FrontierAssumptionBinding => {
                    "open branch assumptions or variable binding differs"
                }
                crate::ResearchFailure::TraceFormulaEncoding => {
                    "search observation formula encoding"
                }
                crate::ResearchFailure::TraceCapacity => {
                    "search observation capacity or coverage differs"
                }
                crate::ResearchFailure::TraceRootMissing => {
                    "search events lack their original context"
                }
                crate::ResearchFailure::TraceTargetMismatch => "search observation target differs",
                crate::ResearchFailure::TraceTheoremCapacity => {
                    "search observation theorem capacity differs"
                }
                crate::ResearchFailure::TraceExpansionOrder => {
                    "search observation expansion order differs"
                }
                crate::ResearchFailure::TraceParentOrder => {
                    "search observation parent is not an earlier action"
                }
                crate::ResearchFailure::TraceBranchAncestry => {
                    "search observation branch ancestry differs"
                }
                crate::ResearchFailure::TraceBranchNotOffered => {
                    "search observation branch is not offered"
                }
                crate::ResearchFailure::TraceStateBinding => {
                    "search observation state or action binding differs"
                }
                crate::ResearchFailure::TraceRankingShape => {
                    "search observation ranking shape differs"
                }
                crate::ResearchFailure::TraceRankingOrder => {
                    "search observation differs from its attempted ranking order"
                }
                crate::ResearchFailure::TraceBranchCount => {
                    "search observation executed branch count differs"
                }
                crate::ResearchFailure::TraceRepairAttemptMissing => {
                    "repair has no recorded attempt"
                }
                crate::ResearchFailure::TraceRepairDecision => {
                    "repair decision differs from its failed attempt"
                }
                crate::ResearchFailure::TraceRepairRootMissing => "repair has no search root",
                crate::ResearchFailure::TraceRepairSnapshotMissing => {
                    "repair lacks its original theorem snapshot"
                }
                crate::ResearchFailure::TraceRepairAlternative => {
                    "checked repair does not use the alternative at its recorded state"
                }
                crate::ResearchFailure::TraceRepairConclusion => {
                    "checked repair conclusion differs"
                }
                crate::ResearchFailure::TraceQuestionBinding => {
                    "search observation belongs to a different question"
                }
                crate::ResearchFailure::TraceSnapshotMissing => {
                    "search observation lacks its exact theorem snapshot"
                }
                crate::ResearchFailure::TraceTheoremIdentity => {
                    "search observation theorem identity differs"
                }
                crate::ResearchFailure::TraceClosedDepth => "observed closed branch depth differs",
                crate::ResearchFailure::TraceMultipleTerminals => {
                    "observed branch has multiple terminal completions"
                }
                crate::ResearchFailure::TraceSkippedAttempt => {
                    "search observation skipped an attempted action"
                }
                crate::ResearchFailure::SearchTheoremIndex => "theorem candidate index",
                crate::ResearchFailure::SearchDoubleAction => "double action mismatch",
                crate::ResearchFailure::SearchNegatedImplication => {
                    "not implication action mismatch"
                }
                crate::ResearchFailure::SearchModusPonens => "MP action mismatch",
                crate::ResearchFailure::SearchPremise => "MP premise mismatch",
                crate::ResearchFailure::SearchBranchAction => "beta action mismatch",
                crate::ResearchFailure::SearchUniversalAction => "universal action mismatch",
                crate::ResearchFailure::SearchInstantiationShape => {
                    "instantiated implication expected"
                }
                crate::ResearchFailure::SearchInstantiationPremise => {
                    "instantiated premise differs"
                }
                crate::ResearchFailure::SearchWitnessFreshness => "witness variable is not fresh",
                crate::ResearchFailure::SearchWitnessNegation => "witness negation",
                crate::ResearchFailure::SearchWitnessUniversal => "witness universal",
                crate::ResearchFailure::SearchEqualityAction => "equality action mismatch",
                crate::ResearchFailure::ReplayDepth => "native replay depth",
                crate::ResearchFailure::ReplayState => "replay formula state mismatch",
                crate::ResearchFailure::ReplayPositiveIndex => "closing positive index",
                crate::ResearchFailure::ReplayNegativeIndex => "closing negative index",
                crate::ResearchFailure::ReplayClosure => "forged tableau closure",
                crate::ResearchFailure::ReplayNestedAxiom => "unsupported nested axiom trace",
                crate::ResearchFailure::ReplayAction => "replay action not offered",
                crate::ResearchFailure::ReplayArity => "replay branch arity mismatch",
                crate::ResearchFailure::ReplayTheoremIndex => "replay theorem index",
                crate::ResearchFailure::ReplayWitness => "replay witness",
                crate::ResearchFailure::ReplayWitnessBody => "replay witness body",
                crate::ResearchFailure::ReplayWitnessDischarge => {
                    "witness discharge changed the universal"
                }
                crate::ResearchFailure::ReplayEquality => "replay equality",
                crate::ResearchFailure::ReplayBranch => "replay beta",
                crate::ResearchFailure::ReplayScopedTarget => "scope trace target binding differs",
                crate::ResearchFailure::ReplayTheoremTarget => {
                    "theorem trace target binding differs"
                }
                crate::ResearchFailure::ReplayDefinitionAvailability => {
                    "definition availability differs"
                }
                crate::ResearchFailure::ReplayDefinitionIndex => "definition selection index",
                crate::ResearchFailure::ReplayDefinitionUnused => {
                    "selected definition is not used by the checked proof"
                }
                crate::ResearchFailure::ReplayOwnedSnapshot => {
                    "peer replay requires its owned journal snapshot"
                }
                crate::ResearchFailure::ReplayAxiomIndex => "unknown native axiom",
                crate::ResearchFailure::ReplayAxiomTarget => "axiom target differs",
                crate::ResearchFailure::ReplayAssumptionWrapper => "assumption wrapper",
                crate::ResearchFailure::ReplayCompiledTarget => "compiled native target mismatch",
                crate::ResearchFailure::ScopeTraceTarget => "scope trace target differs",
                crate::ResearchFailure::ScopeTraceCapacity => "scope trace action capacity",
                crate::ResearchFailure::ScopeReplayOperand => "scope replay operand differs",
                crate::ResearchFailure::ScopeConclusion => "scope trace conclusion differs",
                crate::ResearchFailure::ScopeCitationMissing => "scope replay citation missing",
                crate::ResearchFailure::ScopeCitationFormulaMissing => {
                    "scope replay citation formula missing"
                }
                crate::ResearchFailure::ScopeProgramTarget => "scope program target differs",
                crate::ResearchFailure::ScopeProgramOperands => "scope program operands differ",
                crate::ResearchFailure::ScopeOperandOrder => "scope operand is not an earlier fact",
                crate::ResearchFailure::ScopeResultOrder => "scope result is not an earlier fact",
                crate::ResearchFailure::PeerReplayCapacity => "peer certificate replay capacity",
                crate::ResearchFailure::PeerClosureCapacity => "native DAG replay closure capacity",
                crate::ResearchFailure::PeerConclusion => "peer certificate conclusion differs",
                crate::ResearchFailure::PeerWorkCapacity => "native DAG replay work capacity",
                crate::ResearchFailure::PeerReconstructionIdentity => {
                    "peer DAG reconstruction identity differs"
                }
                crate::ResearchFailure::PeerStepCapacity => "peer DAG replay step capacity",
                crate::ResearchFailure::PeerImplicationIndex => "peer implication index",
                crate::ResearchFailure::PeerImplicationShape => "peer MP implication",
                crate::ResearchFailure::PeerPremiseIndex => "peer premise index",
                crate::ResearchFailure::PeerPremiseMismatch => "peer MP premise differs",
                crate::ResearchFailure::PeerGraphOverflow => "peer graph work overflow",
                crate::ResearchFailure::PeerGraphCapacity => "peer graph work capacity",
                crate::ResearchFailure::PeerGeneralizationIndex => "peer generalization index",
                crate::ResearchFailure::PeerCitationMissing => "peer cited proof missing",
                crate::ResearchFailure::PeerCitationFormulaMissing => {
                    "peer cited statement missing"
                }
                crate::ResearchFailure::PeerProgramArtifact => {
                    "peer program artifact identity differs"
                }
                crate::ResearchFailure::PeerProgramInference => {
                    "peer program has no supported ambiguous inference"
                }
                crate::ResearchFailure::PeerProgramBinding => {
                    "peer replay source differs from checked program"
                }
                crate::ResearchFailure::PeerDagBinding => {
                    "peer replay source differs from checked native DAG"
                }
                crate::ResearchFailure::PeerDagInference => {
                    "peer DAG has no supported ambiguous inference"
                }
                crate::ResearchFailure::PeerArtifactIdentity => "peer artifact identity differs",
                crate::ResearchFailure::EvidenceCheckerCapacity => {
                    "construction checker work capacity"
                }
                crate::ResearchFailure::EvidenceCanonicalBinding => {
                    "construction evidence canonical binding"
                }
                crate::ResearchFailure::EvidenceTargetBinding => {
                    "construction evidence target differs"
                }
                crate::ResearchFailure::KnowledgeTraceMissing => "theorem trace missing",
                crate::ResearchFailure::NativeDagTargetMismatch => "native DAG conclusion differs",
                crate::ResearchFailure::NativeTermTargetMismatch => {
                    "search term differs from the requested target"
                }
                crate::ResearchFailure::NativeCheckedTargetMismatch => {
                    "checked certificate proves a different target"
                }
                crate::ResearchFailure::ProofApplicationShape => {
                    "application requires an implication"
                }
                crate::ResearchFailure::ProofApplicationAntecedent => {
                    "application antecedent differs"
                }
                crate::ResearchFailure::ProofCombinatorShape => {
                    "combinator application requires an implication"
                }
                crate::ResearchFailure::ProofCombinatorAntecedent => {
                    "combinator application antecedent differs"
                }
                crate::ResearchFailure::ProofGeneralizationCapture => {
                    "generalization eigenvariable occurs in an assumption"
                }
                crate::ResearchFailure::ProofUnboundVariable => {
                    "unbound variable during bracket abstraction"
                }
                crate::ResearchFailure::ProofLemmaTarget => "construction lemma target differs",
                crate::ResearchFailure::ProofSealedTarget => {
                    "sealed native recipe conclusion differs"
                }
                crate::ResearchFailure::ProofUndischargedAssumption => {
                    "certificate still has an assumption"
                }
                crate::ResearchFailure::ProofIndexWidth => "proof index width",
                crate::ResearchFailure::LogicOpenLemma => "open construction lemma",
                crate::ResearchFailure::LogicLemmaInstantiation => {
                    "construction lemma instantiation"
                }
                crate::ResearchFailure::LogicProjectionShape => "conjunction projection",
                crate::ResearchFailure::LogicProjectionResult => "projection result",
                crate::ResearchFailure::LogicExistentialGoal => "existential goal",
                crate::ResearchFailure::LogicExistentialPremise => "existential premise",
                crate::ResearchFailure::LogicEigenvariableEscape => {
                    "existential eigenvariable escapes"
                }
                crate::ResearchFailure::LogicExistentialElimination => "existential elimination",
                crate::ResearchFailure::LogicExistentialOpening => "existential opening",
                crate::ResearchFailure::LogicContradiction => "contradiction operands differ",
                crate::ResearchFailure::LogicDoubleNegation => "double negation expected",
                crate::ResearchFailure::LogicNegatedImplication => "negated implication expected",
                crate::ResearchFailure::LogicFreshVariable => "fresh variable space",
                crate::ResearchFailure::LogicUniversalPremise => "universal premise expected",
                crate::ResearchFailure::ProofReferenceReplacement => {
                    "exact native references cannot be replaced during proof encoding"
                }
                crate::ResearchFailure::ProofRepresentationMismatch => {
                    "typed representation changed the checked conclusion"
                }
                crate::ResearchFailure::DefinitionBinderSpace => {
                    "definition binder space exhausted"
                }
                crate::ResearchFailure::DefinitionBinder => "definition binder cannot be opened",
                crate::ResearchFailure::DefinitionProposalBinder => {
                    "definition proposal binder space exhausted"
                }
                crate::ResearchFailure::DefinitionProposalUniversal => {
                    "definition proposal universal cannot be opened"
                }
                crate::ResearchFailure::DefinitionScores => "definition reference scores differ",
                crate::ResearchFailure::DefinitionChoicesEmpty => "definition choices empty",
                crate::ResearchFailure::KernelUnsupported => "unsupported kernel constant",
                crate::ResearchFailure::FragmentFormulaEncoding => {
                    "contextual proof formula encoding differs"
                }
                crate::ResearchFailure::FragmentObservedJob => {
                    "contextual proof lacks its observed job"
                }
                crate::ResearchFailure::FragmentCapacity => {
                    "contextual proof capacity or scope differs"
                }
                crate::ResearchFailure::FragmentVariableScope => {
                    "contextual proof free-variable scope differs"
                }
                crate::ResearchFailure::FragmentClosedTarget => {
                    "contextual proof closed target differs"
                }
                crate::ResearchFailure::FragmentIdentity => {
                    "contextual proof conclusion or identity differs"
                }
                crate::ResearchFailure::FragmentSourceLineage => {
                    "contextual proof source lineage differs"
                }
                crate::ResearchFailure::FragmentBranchSource => {
                    "contextual proof branch leaves its checked source"
                }
                crate::ResearchFailure::FragmentChild => "contextual proof child differs",
                crate::ResearchFailure::FragmentTransition => "contextual proof transition differs",
                crate::ResearchFailure::FragmentBranchBinding => {
                    "contextual proof assumptions or branch binding differs"
                }
                crate::ResearchFailure::FragmentObservedParent => {
                    "contextual proof does not cite an observed parent"
                }
                crate::ResearchFailure::FragmentObservedReceipt => {
                    "contextual proof observed receipt differs"
                }
                crate::ResearchFailure::FragmentExecutionMissing => {
                    "contextual proof original execution absent"
                }
                crate::ResearchFailure::FragmentClosedBranchMissing => {
                    "contextual proof closed branch is missing or truncated"
                }
                crate::ResearchFailure::FragmentObservedSubtree => {
                    "contextual proof observed subtree differs"
                }
                crate::ResearchFailure::FragmentRecordedScope => {
                    "contextual proof differs from its recorded scope"
                }
                crate::ResearchFailure::FragmentNegatedGoal => {
                    "contextual proof lacks the original negated goal"
                }
                crate::ResearchFailure::FragmentNegationBinding => {
                    "contextual proof negation binding"
                }
                crate::ResearchFailure::FragmentOpenScope => {
                    "contextual proof left an open assumption or variable"
                }
                crate::ResearchFailure::DerivationDepth => "checked sequence depth differs",
                crate::ResearchFailure::DerivationNestedEvidence => {
                    "checked sequence contains unsupported nested evidence"
                }
                crate::ResearchFailure::DerivationAction => {
                    "checked sequence action is not offered"
                }
                crate::ResearchFailure::DerivationArity => "checked sequence branch arity differs",
                crate::ResearchFailure::DerivationCitationIndex => "checked citation index",
                crate::ResearchFailure::DerivationSourceIdentity => {
                    "checked sequence source identity differs"
                }
                crate::ResearchFailure::SearchFreshVariableExhausted => {
                    "fresh variable space exhausted"
                }
                crate::ResearchFailure::TraceSerialization => "search trace serialization failed",
                crate::ResearchFailure::FrontierSerialization => "open branch serialization failed",
                crate::ResearchFailure::ExperienceTerminalCandidate => {
                    "terminal evidence differs from the checked candidate"
                }
                crate::ResearchFailure::ExperienceNativeContext => {
                    "experience native context differs from its retained snapshot"
                }
                crate::ResearchFailure::ExperienceResultMissing => {
                    "complete native experience lacks its result"
                }
                crate::ResearchFailure::ExperienceCheckpointMissing => {
                    "complete native experience lacks its checkpoint"
                }
                crate::ResearchFailure::ExperienceExecutionMismatch => {
                    "native terminal evidence differs from its retained execution"
                }
                crate::ResearchFailure::ExperiencePeerSyntax => "experience peer identity syntax",
                crate::ResearchFailure::ExperiencePeerEncoding => {
                    "experience peer identity encoding"
                }
                crate::ResearchFailure::ExperienceReceiptIdentity => {
                    "experience receipt identity differs"
                }
                crate::ResearchFailure::ExperienceTraceMismatch => {
                    "experience terminal, trace or measured work differs"
                }
                crate::ResearchFailure::ExperienceLineage => {
                    "history observation is outside the eligible training lineage"
                }
                crate::ResearchFailure::ExperienceObservationBinding => {
                    "history observation question or frontier binding differs"
                }
                crate::ResearchFailure::ExperienceJobBinding => {
                    "finder experience differs from its completed job"
                }
                crate::ResearchFailure::ExperienceNativeBinding => {
                    "finder experience differs from its native result"
                }
                crate::ResearchFailure::ExperienceTerminalState => {
                    "finder experience lacks its terminal job state"
                }
                crate::ResearchFailure::ExperienceOutcome => {
                    "finder outcome differs from its native experience"
                }
                crate::ResearchFailure::ExperienceStoredBinding => {
                    "stored finder experience differs from its observation"
                }
                crate::ResearchFailure::EvidenceMissing => {
                    "established research evidence is missing"
                }
                crate::ResearchFailure::EvidenceRandomState => "invalid research random state",
                crate::ResearchFailure::EvidenceObservationSequence => {
                    "finder observation sequence differs"
                }
                crate::ResearchFailure::RecoveryFifoIdentity => {
                    "research FIFO history identity differs"
                }
                crate::ResearchFailure::RecoveryRecordMissing => {
                    "research history record is missing"
                }
                crate::ResearchFailure::RecoveryRecordIdentity => {
                    "research history record identity differs"
                }
                crate::ResearchFailure::RecoveryBytesOverflow => "research recovery bytes overflow",
                crate::ResearchFailure::CandidatePrefixMismatch => {
                    "candidate retained prefix differs"
                }
                crate::ResearchFailure::CandidateCheckpointInsideGroup => {
                    "candidate checkpoint ends inside a provider group"
                }
                crate::ResearchFailure::CandidateInputMismatch => {
                    "candidate input differs from its retained program"
                }
                crate::ResearchFailure::CandidateUnitOverflow => "provider unit address exhausted",
                crate::ResearchFailure::CandidateStreamMismatch => {
                    "candidate retained stream differs"
                }
                crate::ResearchFailure::CandidateSealMissing => {
                    "candidate has no completely checked seal"
                }
                crate::ResearchFailure::CandidateCheckedMissing => "checked candidate absent",
                crate::ResearchFailure::ProgramGroupMissing => "provider program group missing",
                crate::ResearchFailure::CommandQueueFull => "research command queue is full",
                crate::ResearchFailure::ServiceStopped => "research service stopped",
                crate::ResearchFailure::PeerCursorBeyondGraph => {
                    "peer learning cursor exceeds checked graph"
                }
                crate::ResearchFailure::ConflictingProviders => {
                    "native and mock providers are mutually exclusive"
                }
                crate::ResearchFailure::InvalidRoleLimits => "invalid research role limits",
                crate::ResearchFailure::DeveloperWorkloadUnavailable => {
                    "controlled workloads require developer tools"
                }
                crate::ResearchFailure::ClockBeforeEpoch => "wall clock is before research epoch",
                crate::ResearchFailure::ClockOverflow => "research clock overflow",
                crate::ResearchFailure::ClockRollback => "research clock rollback",
                crate::ResearchFailure::ElapsedOverflow => "research elapsed overflow",
                crate::ResearchFailure::AccountingRecordMissing => {
                    "research accounting record absent"
                }
                crate::ResearchFailure::MultipleFailures => "multiple research failures",
                crate::ResearchFailure::EffectsUnconfirmed => {
                    "provider cleanup or effects require reconciliation"
                }
                crate::ResearchFailure::DriverPanic => {
                    "research driver panicked; pending effects require reconciliation"
                }
                crate::ResearchFailure::StopReceiptUnavailable => {
                    "research stop receipt unavailable"
                }
                crate::ResearchFailure::OwnerThreadPanic => "research owner thread panicked",
                crate::ResearchFailure::OwnerRuntimeUnavailable => {
                    "research owner runtime unavailable"
                }
                crate::ResearchFailure::OwnerCancelled => "research job cancelled or expired",
                crate::ResearchFailure::WorkBudgetExhausted => "research work budget exhausted",
                crate::ResearchFailure::DuplicateProgram => "duplicate outstanding program group",
                crate::ResearchFailure::ReservationMissing => "research reservation record absent",
                crate::ResearchFailure::ReservationSequence => {
                    "research reservation lifecycle differs"
                }
                crate::ResearchFailure::ProgressMissing => "unknown provider progress",
                crate::ResearchFailure::ProgressNotRunning => "research checkpoint cancelled",
                crate::ResearchFailure::ProgressSequence => {
                    "provider checkpoint differs from its durable reservation"
                }
                crate::ResearchFailure::LearningCheckpointMissing => "unknown learning checkpoint",
                crate::ResearchFailure::LearningReservation => {
                    "learning checkpoint lacks original reservation"
                }
                crate::ResearchFailure::LearningSnapshotMissing => {
                    "learning checkpoint lacks snapshot"
                }
                crate::ResearchFailure::ProgramJobMissing => "unknown program job",
                crate::ResearchFailure::ProgramReservation => {
                    "program group lacks its original reservation"
                }
                crate::ResearchFailure::ExperienceJournalRecordIdentityDiffers => {
                    "experience journal record identity differs"
                }
                crate::ResearchFailure::ExperiencePageIoOverflow => "experience page IO overflow",
                crate::ResearchFailure::ExperienceRecordExceedsTheWorkingPageCapacity => {
                    "experience record exceeds the working page capacity"
                }
                crate::ResearchFailure::HistoricalAdmittedSourceRecordMissing => {
                    "historical admitted source record missing"
                }
                crate::ResearchFailure::HistoricalOwnAdmissionIdentityDiffers => {
                    "historical own admission identity differs"
                }
                crate::ResearchFailure::HistoricalOwnAdmissionReceiptMissing => {
                    "historical own admission receipt missing"
                }
                crate::ResearchFailure::HistoricalPageImmutableChunkDiffers => {
                    "historical page immutable chunk differs"
                }
                crate::ResearchFailure::HistoricalPeerProvenanceDiffers => {
                    "historical peer provenance differs"
                }
                crate::ResearchFailure::HistoricalPeerReceiptMissing => {
                    "historical peer receipt missing"
                }
                crate::ResearchFailure::HistoricalSourceExceedsWorkingPageCapacity => {
                    "historical source exceeds working page capacity"
                }
                crate::ResearchFailure::HistoricalSourceIdentityDiffers => {
                    "historical source identity differs"
                }
                crate::ResearchFailure::HistoricalSourceRoleDiffers => {
                    "historical source role differs"
                }
                crate::ResearchFailure::HistoricalSourceSolutionMissing => {
                    "historical source solution missing"
                }
                crate::ResearchFailure::HistoryIoOperationOverflow => {
                    "history IO operation overflow"
                }
                crate::ResearchFailure::HistoryIoOverflow => "history IO overflow",
                crate::ResearchFailure::HistoryJobMissing => "history job missing",
                crate::ResearchFailure::HistoryLifetimeIoOverflow => "history lifetime IO overflow",
                crate::ResearchFailure::HistoryNativeOwnerMissing => "history native owner missing",
                crate::ResearchFailure::HistoryOriginalJobMissing => "history original job missing",
                crate::ResearchFailure::HistoryReadLacksItsOriginalTrainingReservation => {
                    "history read lacks its original training reservation"
                }
                crate::ResearchFailure::HistorySourceHasNoJob => "history source has no job",
                crate::ResearchFailure::NativeCheckpointWritesRequireTheReservedTrainingRole => {
                    "native checkpoint writes require the reserved training role"
                }
                crate::ResearchFailure::NativeModelIoLacksOriginalReservation => {
                    "native model IO lacks original reservation"
                }
                crate::ResearchFailure::NativeModelIoOperationsOverflow => {
                    "native model IO operations overflow"
                }
                crate::ResearchFailure::NativeModelIoOverflow => "native model IO overflow",
                crate::ResearchFailure::NativeModelArtifactCountExhausted => {
                    "native model artifact count exhausted"
                }
                crate::ResearchFailure::NativeModelChunkLengthDiffers => {
                    "native model chunk length differs"
                }
                crate::ResearchFailure::HistoryOriginEvidence => {
                    "historical origin lacks its exact admission evidence"
                }
                crate::ResearchFailure::HistoryTrajectoryMissing => {
                    "history source lacks its complete trajectory"
                }
                crate::ResearchFailure::HistoryPageIdentity => {
                    "history page identity or sequence differs"
                }
                crate::ResearchFailure::HistoryPageCursor => "history page source cursor differs",
                crate::ResearchFailure::HistoryPageContinuation => {
                    "history continuation lacks its last examined source"
                }
                crate::ResearchFailure::HistoryRecordPageMismatch => {
                    "history record page omitted or substituted a scanned job"
                }
                crate::ResearchFailure::HistoryObservationHorizon => {
                    "history observation differs from its original job horizon"
                }
                crate::ResearchFailure::HistorySourcePageLane => {
                    "admitted source page contains a different journal view"
                }
                crate::ResearchFailure::HistorySourcePageMismatch => {
                    "historical page omitted or substituted an owned source"
                }
                crate::ResearchFailure::HistoryPreparedCapacity => {
                    "prepared replay exceeds existing working source capacity"
                }
                crate::ResearchFailure::HistoryPreparedIdentity => {
                    "prepared replay differs from its immutable job"
                }
                crate::ResearchFailure::HistoryPreparedChanged => {
                    "prepared replay changed across continuation"
                }
                crate::ResearchFailure::DefinitionSnapshotCapacity => {
                    "definition reference snapshot capacity"
                }
                crate::ResearchFailure::DefinitionSelectionIndex => "definition selection index",
                crate::ResearchFailure::DefinitionAvailability => "definition availability differs",
                crate::ResearchFailure::DefinitionTraceSnapshotMissing => {
                    "source context requires its owned trace snapshot"
                }
                crate::ResearchFailure::ExpectedProofArtifact => {
                    "expected a canonical proof artifact"
                }
                crate::ResearchFailure::NativeProgramBinding => {
                    "native program source or conclusion differs"
                }
                crate::ResearchFailure::NativeCertificateConclusion => {
                    "native certificate conclusion differs"
                }
                crate::ResearchFailure::NativeDefinitionHelpers => {
                    "definition helper source binding differs"
                }
                crate::ResearchFailure::NativeSourceIdentity => "native source identity differs",
                crate::ResearchFailure::NativeModelHashMismatch => {
                    "native model checkpoint hash differs"
                }
                crate::ResearchFailure::NativeModelChunkMissing => "native model chunk missing",
                crate::ResearchFailure::NativeModelImmutableChunkDiffers => {
                    "native model immutable chunk differs"
                }
                crate::ResearchFailure::NativeModelLifetimeIoAllowanceExhausted => {
                    "native model lifetime IO allowance exhausted"
                }
                crate::ResearchFailure::NativeModelOriginalJobMissing => {
                    "native model original job missing"
                }
                crate::ResearchFailure::NativeModelOriginalSnapshotMissing => {
                    "native model original snapshot missing"
                }
                crate::ResearchFailure::NativeModelReadOutsideImmutableOwnedSnapshots => {
                    "native model read outside immutable owned snapshots"
                }
                crate::ResearchFailure::NativeModelRetainedChunkLengthDiffers => {
                    "native model retained chunk length differs"
                }
                crate::ResearchFailure::ProviderProgramOriginalJobMissing => {
                    "provider program original job missing"
                }
                crate::ResearchFailure::ProviderProgramOriginalReservationMissing => {
                    "provider program original reservation missing"
                }
                crate::ResearchFailure::ResumedProviderProgramGroupDiffers => {
                    "resumed provider program group differs"
                }
                crate::ResearchFailure::ModelBlobCapacity => "native model blob capacity",
                crate::ResearchFailure::ModelChunkIndex => "native model chunk index",
                crate::ResearchFailure::ModelChunkRange => "native model chunk range",
                crate::ResearchFailure::HistoryRecordKeySyntax => "history record key syntax",
                crate::ResearchFailure::HistoryRecordKeyEncoding => "history record key encoding",
                crate::ResearchFailure::HistoryRequestJobMissing => {
                    "history request lacks its original job"
                }
                crate::ResearchFailure::HistoryPageRequestMismatch => {
                    "history page differs from its bounded request"
                }
                crate::ResearchFailure::HistoryCursorNotAdvanced => {
                    "history cursor did not advance"
                }
                crate::ResearchFailure::StatelessRankerMemory => "stateless ranker received memory",
                crate::ResearchFailure::MemoryActionIndex => "native memory action index differs",
                crate::ResearchFailure::MemoryTensorDecode => {
                    "native memory tensor decoding failed"
                }
                crate::ResearchFailure::MemorySuccessor => "native memory successor differs",
                crate::ResearchFailure::MemoryCheckpointMissing => {
                    "native memory checkpoint missing"
                }
                crate::ResearchFailure::MemoryShapeOrValue => {
                    "native memory shape or value differs"
                }
                crate::ResearchFailure::MemoryContext => {
                    "native memory context or checkpoint differs"
                }
                crate::ResearchFailure::MemoryPrediction => "native memory prediction differs",
                crate::ResearchFailure::StatelessExplorationMemory => {
                    "stateless exploration received memory"
                }
                crate::ResearchFailure::InvalidActionScores => "invalid native action scores",
                crate::ResearchFailure::LearningUnitSequence => {
                    "learning checkpoint sequence differs"
                }
                crate::ResearchFailure::TrainingPlanMissing => "training plan absent",
                crate::ResearchFailure::SampledSequenceOverflow => {
                    "native sampled sequence count overflow"
                }
                crate::ResearchFailure::MetaTrialPlanMissing => "meta trial plan absent",
                crate::ResearchFailure::FormulaCacheBatchCapacity => "formula cache batch capacity",
                crate::ResearchFailure::FormulaCacheTensorDecode => {
                    "formula cache tensor decoding failed"
                }
                crate::ResearchFailure::ScopeInvalidScores => {
                    "scope ranker scores differ from offered actions"
                }
                crate::ResearchFailure::ScopeLemmaNotClosed => "scoped lemma is not closed",
                crate::ResearchFailure::ScopeBinderCapacity => "scope binder capacity",
                crate::ResearchFailure::OfferedProofMissing => "offered theorem missing",
                crate::ResearchFailure::OfferedProofBinding => {
                    "offered theorem failed context binding"
                }
                crate::ResearchFailure::CompositionTraceCapacity => "composition trace capacity",
                crate::ResearchFailure::CompositionInputBinding => {
                    "composition input binding differs"
                }
                crate::ResearchFailure::CompositionCheckedInputMissing => {
                    "composition checked input missing"
                }
                crate::ResearchFailure::CompositionReplayMismatch => "composition replay differs",
                crate::ResearchFailure::CompositionDeductionSourceMissing => {
                    "temporary deduction original source missing"
                }
                crate::ResearchFailure::CandidateStatementWidth => "native program statement width",
                crate::ResearchFailure::CandidateCertificateWidth => {
                    "native program certificate width"
                }
                crate::ResearchFailure::CandidateCertificateIdentity => {
                    "native program candidate certificate identity differs"
                }
                crate::ResearchFailure::CandidateScopeTarget => {
                    "scope program target binding differs"
                }
                crate::ResearchFailure::CandidateDefinitionIndex => "definition selection index",
                crate::ResearchFailure::PeerProgramFrameWidth => "peer program frame width",
                crate::ResearchFailure::PeerProgramFrameTruncated => "peer program frame truncated",
                crate::ResearchFailure::PeerProgramWorkOverflow => {
                    "peer program checker work overflow"
                }
                crate::ResearchFailure::PeerProgramWorkCapacity => {
                    "peer program checker work capacity"
                }
                crate::ResearchFailure::PeerProgramContextCapacity => {
                    "peer program context capacity"
                }
                crate::ResearchFailure::PeerProgramDependencyTrailing => {
                    "peer program dependency trailing bytes"
                }
                crate::ResearchFailure::PeerProgramStepOverflow => {
                    "peer program context step overflow"
                }
                crate::ResearchFailure::PeerProgramStepCapacity => {
                    "peer program context step capacity"
                }
                crate::ResearchFailure::PeerProgramFrameOutputWidth => {
                    "peer program output frame width"
                }
                crate::ResearchFailure::PeerProgramPacketCapacity => {
                    "native program replay packet capacity"
                }
                crate::ResearchFailure::PeerProgramContextBytesOverflow => {
                    "peer program context byte overflow"
                }
                crate::ResearchFailure::PeerProgramContextBytesCapacity => {
                    "peer program context byte capacity"
                }
                crate::ResearchFailure::PeerPrerequisiteProofBinding => {
                    "temporary prerequisite checked binding differs"
                }
                crate::ResearchFailure::PeerPrerequisiteStatement => {
                    "temporary prerequisite checked statement differs"
                }
                crate::ResearchFailure::PeerPrerequisiteDefinitionBinding => {
                    "temporary definition checked binding differs"
                }
                crate::ResearchFailure::PeerPrerequisiteObligationMissing => {
                    "temporary definition checked obligation is missing"
                }
                crate::ResearchFailure::PeerPrerequisiteObligationBinding => {
                    "temporary definition checked obligation differs"
                }
                crate::ResearchFailure::PeerProgramConclusionCapacity => {
                    "peer replay formula capacity"
                }
                crate::ResearchFailure::PreservationRootBranch => {
                    "preservation prefix root branch differs"
                }
                crate::ResearchFailure::PreservationPredecessor => {
                    "preservation prefix predecessor differs"
                }
                crate::ResearchFailure::PreservationBranchBinding => {
                    "preservation prefix crosses a checked branch"
                }
                crate::ResearchFailure::PreservationActionLabel => {
                    "preservation prefix action lacks a checked label"
                }
                crate::ResearchFailure::ReplaySourceJobMissing => "peer replay source job absent",
                crate::ResearchFailure::ReplaySourceSolutionMissing => {
                    "checked replay source solution missing"
                }
                crate::ResearchFailure::ReplaySampleMismatch => {
                    "native replay sample source differs"
                }
                crate::ResearchFailure::ReplayResultMissing => "native replay source result absent",
                crate::ResearchFailure::ReplayIdentityMismatch => {
                    "native replay source identity differs"
                }
                crate::ResearchFailure::ReplayOwnReceiptMissing => {
                    "native replay lacks admitted own receipt"
                }
                crate::ResearchFailure::ReplayPeerReceiptMissing => {
                    "native peer replay receipt absent"
                }
                crate::ResearchFailure::ReplayPeerReceiptMismatch => {
                    "native peer replay receipt differs"
                }
                crate::ResearchFailure::ReplayProvenanceMismatch => {
                    "native replay source provenance differs"
                }
                crate::ResearchFailure::PeerQueueOrdinalMismatch => {
                    "peer learning queue ordinal differs"
                }
                crate::ResearchFailure::PeerOrdinalZero => "peer learning ordinal is zero",
                crate::ResearchFailure::PeerSyntax => "peer learning source syntax",
                crate::ResearchFailure::PeerEncoding => "peer learning source encoding",
                crate::ResearchFailure::PeerOwnerDisabled => "peer learning owner is disabled",
                crate::ResearchFailure::PeerArtifactMismatch => {
                    "theorem observation artifact differs"
                }
                crate::ResearchFailure::PeerConversionJobMissing => "peer conversion job missing",
                crate::ResearchFailure::PeerConversionReceiptMissing => {
                    "peer conversion admission receipt missing"
                }
                crate::ResearchFailure::PeerConversionOriginMismatch => {
                    "peer conversion origin differs"
                }
                crate::ResearchFailure::PeerLearningStateMissing => "peer learning state missing",
                crate::ResearchFailure::TheoremCapacity => "theorem snapshot capacity",
                crate::ResearchFailure::TheoremNotClosed => "theorem is not closed",
                crate::ResearchFailure::JournalNativeModelOwnerEncoding => "native model owner encoding",
                crate::ResearchFailure::JournalMetaTrialExperienceDiffersFromItsOriginalOwnedJob => "meta trial experience differs from its original owned job",
                crate::ResearchFailure::JournalNativeLearningSingletonDiffers => "native learning singleton differs",
                crate::ResearchFailure::JournalNativeReplaySnapshotResultMissing => "native replay snapshot result missing",
                crate::ResearchFailure::JournalNativeReplaySnapshotSourceDiffers => "native replay snapshot source differs",
                crate::ResearchFailure::JournalNativeSnapshotLacksAdmittedLocalReceipt => "native snapshot lacks admitted local receipt",
                crate::ResearchFailure::JournalNativeReplaySnapshotOriginRoleDiffers => "native replay snapshot origin role differs",
                crate::ResearchFailure::JournalNativeRecordModelOwnerIndexDiffers => "native record model owner index differs",
                crate::ResearchFailure::JournalNativeGlobalModelOwnerIndexDiffers => "native global model owner index differs",
                crate::ResearchFailure::JournalNativeModelOwnerIndexDiffers => "native model owner index differs",
                crate::ResearchFailure::JournalNativeModelUseIndexMissing => "native model use index missing",
                crate::ResearchFailure::JournalNativeModelUseOwnerDiffers => "native model use owner differs",
                crate::ResearchFailure::JournalNativeModelReclamationKeyDiffers => "native model reclamation key differs",
                crate::ResearchFailure::JournalNativeModelChunkIdentityOrLengthDiffers => "native model chunk identity or length differs",
                crate::ResearchFailure::JournalSeenProofSourceDiffers => "seen proof source differs",
                crate::ResearchFailure::JournalNativeSampleProvenanceCountersDiffer => "native sample provenance counters differ",
                crate::ResearchFailure::JournalNativeSamplesLackLearningState => "native samples lack learning state",
                crate::ResearchFailure::JournalPeerPendingSourceDiffers => "peer pending source differs",
                crate::ResearchFailure::JournalOwnLearningAdmissionReceiptDiffers => "own learning admission receipt differs",
                crate::ResearchFailure::JournalPeerAdmissionSourceDiffers => "peer admission source differs",
                crate::ResearchFailure::JournalPeerAdmissionPendingIndexDiffers => "peer admission pending index differs",
                crate::ResearchFailure::JournalFinishedPeerAdmissionRemainsQueued => "finished peer admission remains queued",
                crate::ResearchFailure::JournalPeerConversionJobSourceDiffers => "peer conversion job source differs",
                crate::ResearchFailure::JournalPeerConversionProofReceiptDiffers => "peer conversion proof receipt differs",
                crate::ResearchFailure::JournalNativeSampleSourceRoleDiffers => "native sample source role differs",
                crate::ResearchFailure::JournalNativeSampleSourceIdentityDiffers => "native sample source identity differs",
                crate::ResearchFailure::JournalNativeSampleOwnAdmissionAbsent => "native sample own admission absent",
                crate::ResearchFailure::JournalNativeSamplePeerConversionDiffers => "native sample peer conversion differs",
                crate::ResearchFailure::JournalNativeSourceJobMissing => "native source job missing",
                crate::ResearchFailure::JournalNativeModelOwnerSyntax => "native model owner syntax",
                crate::ResearchFailure::JournalMetaTrialSourceUpdateAbsent => "meta trial source update absent",
                crate::ResearchFailure::JournalNativeModelUseKey => "native model use key",
                crate::ResearchFailure::JournalNativeModelChunkKey => "native model chunk key",
                crate::ResearchFailure::JournalNativeModelChunkHasNoOwnerOrReclamationReceipt => "native model chunk has no owner or reclamation receipt",
                crate::ResearchFailure::JournalPeerPendingReceiptMissing => "peer pending receipt missing",
                crate::ResearchFailure::JournalNativeSamplePeerAdmissionAbsent => "native sample peer admission absent",
                crate::ResearchFailure::JournalNativeModelOwnerIdentity => "native model owner identity",
                crate::ResearchFailure::JournalNativeModelChunkIndex => "native model chunk index",
                crate::ResearchFailure::JournalOwnLearningReceiptIdentity => "own learning receipt identity",
                crate::ResearchFailure::JournalPeerAdmissionSyntax => "peer admission syntax",
                crate::ResearchFailure::ModelInitializationPoisoned => "native model initialization poisoned",
                crate::ResearchFailure::ModelParameterCountMismatch => "native graph policy parameter count differs",
                crate::ResearchFailure::ModelOptimizerRestorationMismatch => "native optimizer did not restore exactly",
                crate::ResearchFailure::ModelUpdatesOverflow => "native model updates overflow",
                crate::ResearchFailure::BackendPackHeader => "model container header invalid",
                crate::ResearchFailure::BackendPackMagic => "model container magic invalid",
                crate::ResearchFailure::BackendPackVersion => "model container version invalid",
                crate::ResearchFailure::BackendPackMetadataWrite => "model container metadata write failed",
                crate::ResearchFailure::BackendPackMetadataRead => "model container metadata read failed",
                crate::ResearchFailure::BackendPackIo => "model container I/O failed",
                crate::ResearchFailure::BackendPackTensorMissing => "model container tensor missing",
                crate::ResearchFailure::BackendPackTensorSize => "model container tensor size mismatch",
                crate::ResearchFailure::BackendPackValidation => "model container validation failed",
                crate::ResearchFailure::BackendPackExists => "model container destination exists",
                crate::ResearchFailure::BackendRecordIo => "model record I/O failed",
                crate::ResearchFailure::BackendRecordValidation => "model record validation failed",
                crate::ResearchFailure::PreservationStepsMissing => "missing preservation step count",
                crate::ResearchFailure::PreservationStepsInvalid => "preservation step count is not an unsigned integer",
                crate::ResearchFailure::PreservationStepsExceeded => "preservation count exceeds actual updates",
                crate::ResearchFailure::PreservationUnknownField => "unknown optimizer memory field",
                crate::ResearchFailure::PreservationParameterMismatch => "EMA parameter path, type, shape or identity differs",
                crate::ResearchFailure::PreservationValueInvalid => "non-finite or unbounded preservation memory",
                crate::ResearchFailure::PreservationIncomplete => "incomplete preservation memory",
                crate::ResearchFailure::TensorStorageAccess => "tensor storage access failed",
                crate::ResearchFailure::TensorInvalidRepresentation => "tensor data representation invalid",
                crate::ResearchFailure::TensorDtypeMismatch => "tensor data type differs",
                crate::ResearchFailure::TensorUnsupportedConversion => "tensor data conversion unsupported",
                crate::ResearchFailure::TensorElementCountMismatch => "tensor element count differs",
                crate::ResearchFailure::TensorByteLengthInvalid => "tensor byte length invalid",
                crate::ResearchFailure::TrainingLossCount => "training loss requires exactly one value",
                crate::ResearchFailure::TrainingLossNonFinite => "training loss is non-finite",
                crate::ResearchFailure::TrainingPoolEmpty => "training requires own accepted proof decisions",
                crate::ResearchFailure::SequenceEmpty => "native sequence is empty",
                crate::ResearchFailure::SequenceShape => "native sequence batch shape differs",
                crate::ResearchFailure::SequenceCapacity => "native sequence batch capacity exceeded",
                crate::ResearchFailure::SequencePredecessor => "native sequence predecessor differs",
                crate::ResearchFailure::SequenceDepth => "native sequence depth exceeds limit",
                crate::ResearchFailure::SequenceSelectedAction => "native sequence selected action differs",
                crate::ResearchFailure::SequenceMemoryMissing => "native sequence memory predecessor missing",
                crate::ResearchFailure::SequenceOutputMissing => "native sequence output missing",
                crate::ResearchFailure::PreservationStepsOverflow => "preservation steps overflow",
                crate::ResearchFailure::PreservationIdentityMismatch => "preservation parameter identity differs",
                crate::ResearchFailure::ModelReclamationIdentity => "native model reclamation identity differs",
                crate::ResearchFailure::LearningReceiptMismatch => "owned learning receipt differs",
                crate::ResearchFailure::LearningResultMissing => "owned learning result missing",
                crate::ResearchFailure::LearningResultIncomplete => "learning result is not complete",
                crate::ResearchFailure::LearningSourceRole => "learning source role differs",
                crate::ResearchFailure::LearningProgramIdentity => "accepted native program identity differs",
                crate::ResearchFailure::LearningOwnerMissing => "native learning owner state absent",
                crate::ResearchFailure::TheoremIdentityMismatch => "accepted theorem identity differs",
                crate::ResearchFailure::AcknowledgementUnknown => "unknown research acknowledgement",
                crate::ResearchFailure::AcknowledgementNotTerminal => "acknowledged research job is still running or held",
                crate::ResearchFailure::JournalHoldAccountMissing => "uncertain job original account missing",
                crate::ResearchFailure::JournalActiveBytesOverflow => "active journal byte overflow",
                crate::ResearchFailure::JobInputEncoding => "research job input encoding failed",
                crate::ResearchFailure::JobReservationOverflow => "research byte reservation overflow",
                crate::ResearchFailure::JobResultReservationOverflow => "research result reservation overflow",
                crate::ResearchFailure::JobHorizonOverflow => "research horizon overflow",
                crate::ResearchFailure::QueuedJobMissing => "queued research job absent",
                crate::ResearchFailure::CompletionJobMissing => "completion research identity absent",
                crate::ResearchFailure::SlotLaneInvalid => "research slot lane differs",
                crate::ResearchFailure::SlotParentMissing => "research slot parent absent",
                crate::ResearchFailure::SlotIdentityMismatch => "research physical slot identity differs",
                crate::ResearchFailure::SlotWorkersActive => "provider slot reconfiguration requires every previous physical worker to drain",
                crate::ResearchFailure::IndexedRequestMissing => "indexed research request is missing",
                crate::ResearchFailure::IndexedRequestMismatch => "research request identity index differs",
                crate::ResearchFailure::RecoveryProgramKey => "invalid provider program key",
                crate::ResearchFailure::RecoveryProgramJobSyntax => "invalid provider program job",
                crate::ResearchFailure::RecoveryProgramUnitSyntax => "invalid provider program unit",
                crate::ResearchFailure::RecoveryProgramKeyCanonical => "noncanonical provider program key",
                crate::ResearchFailure::RecoveryProgramJobMissing => "provider program job missing",
                crate::ResearchFailure::RecoveryProgramReservation => "provider program reservation missing",
                crate::ResearchFailure::RecoveryHeaderInvalid => "unsupported research journal configuration or header",
                crate::ResearchFailure::RecoveryResidentIndex => "research resident record index differs",
                crate::ResearchFailure::RecoverySlotAllocation => "research physical slot allocation differs",
                crate::ResearchFailure::RecoveryLearningMissing => "local learning state missing",
                crate::ResearchFailure::RecoveryRecordRowIdentity => "research record row identity differs",
                crate::ResearchFailure::RecoveryRequestCountOverflow => "research request count overflow",
                crate::ResearchFailure::RecoveryRequestBinding => "research unacknowledged request index differs",
                crate::ResearchFailure::RecoveryResidentBytesOverflow => "research resident memory overflow",
                crate::ResearchFailure::RecoveryHistoryCardinality => "research history index cardinality differs",
                crate::ResearchFailure::RecoveryRequestCardinality => "research request index cardinality differs",
                crate::ResearchFailure::RecoveryResidentMissing => "research resident record is missing",
                crate::ResearchFailure::RecoveryResidentDisappeared => "research resident record disappeared",
                crate::ResearchFailure::RecoveryRetiredCountOverflow => "research retired count overflow",
                crate::ResearchFailure::RecoveryArchiveUnitsOverflow => "research archive unit overflow",
                crate::ResearchFailure::RecoveryArchiveTimeOverflow => "research archive time overflow",
                crate::ResearchFailure::RecoveryHeldJobMissing => "held research job is missing",
                crate::ResearchFailure::RecoveryHeldAccountMismatch => "held research account identity differs",
                crate::ResearchFailure::RecoveryArchiveAllowance => "research archived allowance differs",
                crate::ResearchFailure::TheoremOrdinalZero => "theorem learning ordinal is zero",
                crate::ResearchFailure::DefinitionOrdinalZero => "definition learning ordinal is zero",
                crate::ResearchFailure::PendingLearningReceiptMismatch => "pending owned learning receipt differs",
                crate::ResearchFailure::DuplicateHistoryRead => "duplicate pending history read",
                crate::ResearchFailure::DuplicateModelIo => "duplicate pending native model IO",
                crate::ResearchFailure::DuplicateLearningCheckpoint => "duplicate pending local checkpoint",
                crate::ResearchFailure::ResidentJobMissing => "nonterminal research job is absent from its resident working set",
                crate::ResearchFailure::JournalActiveCapacity => "active journal byte capacity",
                crate::ResearchFailure::JournalReservedCapacity => "research reserved result byte capacity",
                crate::ResearchFailure::DiskReservationWidth => "job disk reservation width",
                crate::ResearchFailure::ProviderInvocationRequired => "internal provider invocation required",
                crate::ResearchFailure::ProviderPipeCapacity => "provider pipe capacity",
                crate::ResearchFailure::ProviderStartDecoding => "provider start decoding failed",
                crate::ResearchFailure::ProviderStartInvalid => "provider start version or horizon differs",
                crate::ResearchFailure::ProviderWorkerInputMissing => "provider worker lifeline absent",
                crate::ResearchFailure::ProviderWorkerOutputMissing => "provider worker output absent",
                crate::ResearchFailure::ProviderStopped => "provider stopped or failed",
                crate::ResearchFailure::DescendantSignalEnded => "descendant signal stream ended",
                crate::ResearchFailure::DescendantOwnerPanic => "descendant signal owner panicked",
                crate::ResearchFailure::ProviderRoleMismatch => "structural finder role differs",
                crate::ResearchFailure::ProviderUnknown => "unknown research provider",
                crate::ResearchFailure::MockProgramUnit => "invalid mock program unit",
                crate::ResearchFailure::ProviderPidOverflow => "provider PID overflow",
                crate::ResearchFailure::ProviderTermSignal => "provider TERM group signal failed",
                crate::ResearchFailure::ProviderKillSignal => "provider KILL group signal failed",
                crate::ResearchFailure::ProviderChildKill => "provider child kill failed",
                crate::ResearchFailure::ProviderWaitFailed => "provider child wait failed",
                crate::ResearchFailure::ProviderReapDeadline => "provider child reaping deadline",
                crate::ResearchFailure::ProviderGroupProbe => "provider group observation failed",
                crate::ResearchFailure::ProviderGroupUnconfirmed => "provider group termination is unconfirmed",
                crate::ResearchFailure::TheoremDuplicate => "duplicate theorem snapshot",
                crate::ResearchFailure::RequiredTheoremCapacity => "required theorem capacity",
                crate::ResearchFailure::TheoremStepOverflow => "theorem step count overflow",
                crate::ResearchFailure::TheoremAvailabilityMismatch => "theorem availability differs from owner snapshot",
                crate::ResearchFailure::ConstructionAvailabilityMismatch => "construction availability differs from owner snapshot",
                crate::ResearchFailure::DefinitionSnapshotMismatch => "definition availability differs from owner snapshot",
                crate::ResearchFailure::ConstructionScoreCount => "construction plan score count differs",
                crate::ResearchFailure::ConstructionScoreNonFinite => "construction plan score is non-finite",
                crate::ResearchFailure::ConstructionSourceNotClosed => "construction plan source is not closed",
                crate::ResearchFailure::ConstructionSelectionIndex => "construction plan index invalid",
                crate::ResearchFailure::ConstructionMeaningMismatch => "construction meaning rewrite changed the claim",
                crate::ResearchFailure::ConstructionRootMissing => "missing construction root",
                crate::ResearchFailure::ConstructionHelperForward => "native helper forward operand",
                crate::ResearchFailure::ConstructionHelperWidth => "native helper operand width",
                crate::ResearchFailure::ConstructionRecipeEmpty => "empty native helper recipe",
                crate::ResearchFailure::ConstructionRecipeRootMismatch => "native helper root differs",
                crate::ResearchFailure::RepairDeadline => "construction repair deadline",
                crate::ResearchFailure::RepairWorkAllowance => "construction repair work allowance",
                crate::ResearchFailure::RepairProtectedProof => "construction repair would replace a supplied proof",
                crate::ResearchFailure::RepairHelperConclusion => "construction repair changed a helper conclusion",
                crate::ResearchFailure::RepairProtectedHelper => "construction repair would replace a supplied helper",
                crate::ResearchFailure::RepairRootConclusion => "construction repair changed the root conclusion",
                crate::ResearchFailure::RepairClosureCapacity => "repaired construction source closure exceeds capacity",
                crate::ResearchFailure::PartitionFreshVariable => "fresh instantiation name",
                crate::ResearchFailure::PartitionBinderMissing => "closed cut binder missing",
                crate::ResearchFailure::PartitionReferenceMismatch => "cut changed a native local step reference",
                crate::ResearchFailure::PartitionConclusionMissing => "missing checked open conclusion",
                crate::ResearchFailure::PartitionVariableInventory => "bounded complete native free-variable inventory required",
                crate::ResearchFailure::PartitionOriginMissing => "normalized free variable has no source origin",
                crate::ResearchFailure::PartitionTargetMismatch => "partition target or native size differs",
                crate::ResearchFailure::PartitionArtifactCapacity => "partition artifact exceeds capacity",
                crate::ResearchFailure::PartitionReplayMismatch => "partition source replay differs",
                crate::ResearchFailure::PartitionCutMissing => "no portable construction partition cut",
                crate::ResearchFailure::FinderDescriptorShape => "finder descriptor bounds differ",
                crate::ResearchFailure::FinderDescriptorBinding => "finder descriptor binding differs",
                crate::ResearchFailure::FinderPredictorWidth => "finder predictor weight count differs",
                crate::ResearchFailure::FinderUtilityWidth => "finder utility weight count differs",
                crate::ResearchFailure::FinderPredictorWeight => "finder predictor weight invalid",
                crate::ResearchFailure::FinderUtilityWeight => "finder utility weight invalid",
                crate::ResearchFailure::FinderObservationCounts => "finder predictor observation counts differ",
                crate::ResearchFailure::FinderUtilityLabel => "finder utility label differs",
                crate::ResearchFailure::FinderUtilityOverflow => "finder utility count overflow",
                crate::ResearchFailure::FinderReplayUtility => "finder replay utility differs",
                crate::ResearchFailure::FinderRehearsalOverflow => "finder rehearsal count overflow",
                crate::ResearchFailure::FinderUpdateOverflow => "finder update overflow",
                crate::ResearchFailure::FinderSuccessOverflow => "finder success overflow",
                crate::ResearchFailure::FinderAttemptOverflow => "finder attempt overflow",
                crate::ResearchFailure::FinderSupportOverflow => "finder support overflow",
                crate::ResearchFailure::FinderRecipeInvalid => "finder construction recipe differs",
                crate::ResearchFailure::FinderCurriculumCapacity => "finder curriculum capacity differs",
                crate::ResearchFailure::FinderCurriculumCounts => "finder curriculum counters differ",
                crate::ResearchFailure::FinderRehearsalInvalid => "finder rehearsal identity or labels differ",
                crate::ResearchFailure::PeerSealMissing => "peer program seal missing",
                crate::ResearchFailure::PeerOperandWidth => "peer program operand width",
                crate::ResearchFailure::PeerOperandOrder => "peer program operand order differs",
                crate::ResearchFailure::FinderCursorOverflow => "finder replay cursor overflow",
                crate::ResearchFailure::ModelChunkMissing => {
                    "native model checkpoint chunk missing"
                }
                crate::ResearchFailure::ModelChunkLength => {
                    "native model checkpoint length differs"
                }
                crate::ResearchFailure::ModelDigestMismatch => {
                    "native model checkpoint content differs"
                }
                crate::ResearchFailure::ModelReceiptMissing => {
                    "native model checkpoint lacks an owned artifact receipt"
                }
                crate::ResearchFailure::MetaUpdateExperienceMissing => {
                    "meta update lacks real trial experience"
                }
                crate::ResearchFailure::MetaOptimizationNonFinite => "non-finite meta optimization",
                crate::ResearchFailure::MetaOptimizerCounterOverflow => {
                    "meta optimizer counter overflow"
                }
                crate::ResearchFailure::MetaWeightWidth => "meta weight width differs",
                crate::ResearchFailure::MetaOptimizerWidth => "meta optimizer width differs",
                crate::ResearchFailure::MetaOptimizerCounter => "meta optimizer counter differs",
                crate::ResearchFailure::MetaWeightValue => "invalid meta weight value",
                crate::ResearchFailure::MetaOptimizerValue => "invalid meta optimizer value",
                crate::ResearchFailure::MetaSecondMoment => "negative meta optimizer second moment",
                crate::ResearchFailure::MetaExperienceBinding => {
                    "meta optimization experience differs from its original model or selected plan"
                }
                crate::ResearchFailure::UtilityGradientInvalid => {
                    "non-finite native utility gradient"
                }
                crate::ResearchFailure::UtilityReferenceCapacity => {
                    "native utility reference capacity"
                }
                crate::ResearchFailure::AbilityProfileCapacity => {
                    "ability observations exceed their bounded contract"
                }
                crate::ResearchFailure::AbilityUtilityBinding => {
                    "finder utility checkpoint differs"
                }
                crate::ResearchFailure::AbilityCheckpointBinding => {
                    "ability checkpoint binding differs"
                }
                crate::ResearchFailure::FinderUtilityCapacity => {
                    "native finder utility capacity differs"
                }
                crate::ResearchFailure::FinderUtilityIdentity => {
                    "native finder utility identity differs"
                }
                crate::ResearchFailure::FinderExampleEligibility => {
                    "finder utility requires eligible local training proofs"
                }
                crate::ResearchFailure::FinderProofIdentity => {
                    "finder utility proof identity differs"
                }
                crate::ResearchFailure::ModelCheckpointBinding => {
                    "native model specification or paired optimizer differs"
                }
                crate::ResearchFailure::MetaCheckpointBinding => {
                    "meta paired input/optimizer binding differs"
                }
                crate::ResearchFailure::MetaCheckpointShape => "meta checkpoint shape differs",
                crate::ResearchFailure::MetaTransferIncomplete => {
                    "meta transfer outcome is not a complete owned trial"
                }
                crate::ResearchFailure::MetaPromotionBinding => {
                    "meta retained model lacks protected family transfer gain"
                }
                crate::ResearchFailure::MetaTrialDimensions => "meta trial dimensions differ",
                crate::ResearchFailure::MetaMemoryCapacity => "meta experience memory capacity",
                crate::ResearchFailure::MetaTrialDuplicate => "duplicate meta source trial",
                crate::ResearchFailure::MetaSelectionValues => "meta selection values differ",
                crate::ResearchFailure::MetaPlanObjective => "meta plan objective bound",
                crate::ResearchFailure::MetaMemoryPhase => "meta memory phase encoding differs",
                crate::ResearchFailure::TransferCoverageInvalid => {
                    "noncanonical transfer outcome coverage"
                }
                crate::ResearchFailure::TransferSequence => "transfer evaluation sequence differs",
                crate::ResearchFailure::PoolPredictionInvalid => {
                    "preparation prediction shape or value differs"
                }
                crate::ResearchFailure::PoolHindsightSourceCapacity => {
                    "native hindsight source capacity"
                }
                crate::ResearchFailure::PoolMaskWorkOverflow => "native target mask work overflow",
                crate::ResearchFailure::PoolMaskWorkCapacity => "native target mask work capacity",
                crate::ResearchFailure::PoolHindsightWorkOverflow => {
                    "native hindsight work overflow"
                }
                crate::ResearchFailure::PoolHindsightWorkCapacity => {
                    "native hindsight work capacity"
                }
                crate::ResearchFailure::PoolObservationLineage => {
                    "observed training lineage differs"
                }
                crate::ResearchFailure::PoolSequenceWorkOverflow => "native sequence work overflow",
                crate::ResearchFailure::PoolSequenceWorkCapacity => "native sequence work capacity",
                crate::ResearchFailure::PoolSequenceBinding => {
                    "checked sequence differs from its admitted replay"
                }
                crate::ResearchFailure::PoolWitnessWorkOverflow => {
                    "native witness pool work overflow"
                }
                crate::ResearchFailure::PoolDerivedWorkOverflow => {
                    "native derived pool work overflow"
                }
                crate::ResearchFailure::PoolDerivedWorkCapacity => {
                    "native derived pool work capacity"
                }
                crate::ResearchFailure::PoolGraphWorkOverflow => "native pool work overflow",
                crate::ResearchFailure::PoolGraphWorkCapacity => "native pool work capacity",
                crate::ResearchFailure::CoverageFilterInvalid => {
                    "replay coverage filter capacity or occupancy"
                }
                crate::ResearchFailure::CoverageProgramIdentity => {
                    "replay coverage program identity differs"
                }
                crate::ResearchFailure::CoverageProofIdentity => {
                    "replay coverage proof identity differs"
                }
                crate::ResearchFailure::CoverageDependencyOrder => {
                    "coverage dependency order differs"
                }
                crate::ResearchFailure::CoverageActionMissing => "coverage action missing",
                crate::ResearchFailure::CoverageGraphReference => {
                    "coverage graph reference missing"
                }
                crate::ResearchFailure::ReplaySnapshotMissing => "owned replay snapshot missing",
                crate::ResearchFailure::ReplaySnapshotBinding => {
                    "owned replay snapshot binding differs"
                }
                crate::ResearchFailure::ReplayCoverageBinding => {
                    "owned replay coverage binding differs"
                }
                crate::ResearchFailure::ReplayTrainingSplit => "training split differs",
                crate::ResearchFailure::ReplayProgramBinding => {
                    "peer replay snapshot program differs"
                }
                crate::ResearchFailure::ReplayProofBinding => "peer replay snapshot proof differs",
                crate::ResearchFailure::RoleHistoryFormat => {
                    "research historical role value exceeds its format"
                }
                crate::ResearchFailure::OutputFrontierRole => "open branches outside solve",
                crate::ResearchFailure::OutputFrontierResolved => {
                    "resolved output contains open branches"
                }
                crate::ResearchFailure::OutputTypeCapacity => {
                    "provider result type or capacity differs"
                }
                crate::ResearchFailure::JournalConfiguration => {
                    "research journal compatibility, configuration or capacity differs"
                }
                crate::ResearchFailure::JournalSequence => {
                    "research monotonic sequence or retired accounting differs"
                }
                crate::ResearchFailure::JournalUnitsOverflow => "research aggregate units overflow",
                crate::ResearchFailure::JournalTimeOverflow => "research aggregate time overflow",
                crate::ResearchFailure::JournalAllowance => {
                    "research aggregate original allowance differs"
                }
                crate::ResearchFailure::JournalTrainingRole => "native training role differs",
                crate::ResearchFailure::JournalLearningEpoch => "native learning epoch differs",
                crate::ResearchFailure::JournalFrontierRole => {
                    "open branch checkpoint role differs"
                }
                crate::ResearchFailure::JournalResolvedFrontier => {
                    "resolved checkpoint has open branches"
                }
                crate::ResearchFailure::JournalHistoryJob => "history request original job differs",
                crate::ResearchFailure::JournalMetaJob => {
                    "meta experience source job identity differs"
                }
                crate::ResearchFailure::JournalProviderRole => {
                    "native provider snapshot role differs"
                }
                crate::ResearchFailure::JournalProviderMissing => "native provider snapshot absent",
                crate::ResearchFailure::JournalHorizonOverflow => "job horizon overflow",
                crate::ResearchFailure::JournalRecordBinding => {
                    "research record identity, lifecycle, checkpoint or budget differs"
                }
                crate::ResearchFailure::JournalProgramCheckpoint => {
                    "retained program differs from original checkpoints"
                }
                crate::ResearchFailure::JournalAccountMissing => {
                    "missing original obligation budget"
                }
                crate::ResearchFailure::JournalAccountBinding => {
                    "research original obligation budget differs"
                }
                crate::ResearchFailure::JournalFinderCursor => {
                    "research finding cursor binding differs"
                }
                crate::ResearchFailure::JournalAccountCorrupt => {
                    "research obligation allowance corruption"
                }
                crate::ResearchFailure::ProgressMetaJobBinding => {
                    "meta experience source job differs"
                }
                crate::ResearchFailure::ProgressRepeatedMismatch => {
                    "repeated learning checkpoint differs"
                }
                crate::ResearchFailure::ProgressContinuationMismatch => {
                    "learning plan or measured continuation differs"
                }
                crate::ResearchFailure::ProgressMetaTrialBinding => {
                    "meta outcome differs from its retained trial"
                }
                crate::ResearchFailure::ProgressFirstUnit => {
                    "learning checkpoint lacks its first unit"
                }
                crate::ResearchFailure::ProgressTransferLoss => {
                    "learning checkpoint loses an incumbent transfer success"
                }
                crate::ResearchFailure::LearningFixedSnapshotCapacity => {
                    "fixed learning snapshot exceeds working byte capacity"
                }
                crate::ResearchFailure::LearningMetaHeadroom => {
                    "meta context exceeds the frozen matched headroom"
                }
                crate::ResearchFailure::LearningMetaBatchCapacity => {
                    "matched meta context cannot retain a learning batch"
                }
                crate::ResearchFailure::LearningLocalCountOverflow => {
                    "local learning count overflow"
                }
                crate::ResearchFailure::LearningPeerCountOverflow => "peer learning count overflow",
                crate::ResearchFailure::LearningSequenceOverflow => "learning sequence overflow",
                crate::ResearchFailure::LearningRevisionOverflow => "learning revision overflow",
                crate::ResearchFailure::LearningExampleOwner => {
                    "learning example lacks an owned job"
                }
                crate::ResearchFailure::LearningExampleEligibility => {
                    "learning example outside eligible dependency split"
                }
                crate::ResearchFailure::LearningReplayPointer => "peer replay pointer differs",
                crate::ResearchFailure::LearningProgramProvenance => {
                    "learning program provenance differs"
                }
                crate::ResearchFailure::LearningProofProvenance => {
                    "learning proof provenance differs"
                }
                crate::ResearchFailure::LearningProgramTarget => "checked program target differs",
                crate::ResearchFailure::LearningDefinitionUtility => {
                    "definition utility lacks a checked meaning"
                }
                crate::ResearchFailure::LearningStateCapacity => {
                    "local learning state capacity or sequence"
                }
                crate::ResearchFailure::LearningReplayStrategyCapacity => {
                    "question replay strategy capacity"
                }
                crate::ResearchFailure::LearningFeedbackModel => "learning feedback model differs",
                crate::ResearchFailure::JobPrerequisiteRole => {
                    "temporary prerequisites lack a solving role"
                }
                crate::ResearchFailure::JobParentSnapshot => "learning parent snapshot differs",
                crate::ResearchFailure::JobHistoryRequestBinding => {
                    "history request differs from its training parent"
                }
                crate::ResearchFailure::JobHistoryRequestMissing => {
                    "history receipt lacks its original request"
                }
                crate::ResearchFailure::JobReplaySnapshotBinding => {
                    "peer replay snapshot binding differs"
                }
                crate::ResearchFailure::JobArtifactLifetimeCapacity => {
                    "native artifact lifetime allowance"
                }
                crate::ResearchFailure::JobArtifactReservation => {
                    "native artifact reservation differs"
                }
                crate::ResearchFailure::JobReplayReceiptBinding => {
                    "prepared replay lacks its original history receipt"
                }
                crate::ResearchFailure::JobReplayPreparationMissing => {
                    "training progress lacks its frozen replay preparation"
                }
                crate::ResearchFailure::JobObservationWorkOverflow => {
                    "search observation work overflow"
                }
                crate::ResearchFailure::JobObservationBinding => {
                    "search observations exceed the actual bounded execution"
                }
                crate::ResearchFailure::JobMetaPlanContext => {
                    "meta plan context differs from its parent"
                }
                crate::ResearchFailure::JobMetaPlanMissing => {
                    "native meta trial lacks its selected plan"
                }
                crate::ResearchFailure::JobMetaCost => "meta cost exceeds actual job cost",
                crate::ResearchFailure::JobMetaUpdatePlanMissing => {
                    "meta update without selected plan"
                }
                crate::ResearchFailure::JobMetaUpdateBinding => {
                    "meta experience or optimizer is not bound to the actual completed trial"
                }
                crate::ResearchFailure::JobMetaUpdateMissing => {
                    "completed meta trial lacks its real update"
                }
                crate::ResearchFailure::JobCheckpointCapacity => {
                    "local checkpoints exceed original provider stream capacity"
                }
                crate::ResearchFailure::JobPromotionBinding => {
                    "retained promotion lacks complete protected transfer gain"
                }
                crate::ResearchFailure::JobTransferCoverage => {
                    "transfer coverage differs from the retained unit"
                }
                crate::ResearchFailure::JobDevelopmentBinding => {
                    "development observations differ from their incumbent"
                }
                crate::ResearchFailure::JobCompositionBinding => {
                    "composition differs from requested prerequisites"
                }
                crate::ResearchFailure::JobModelQualification => {
                    "native model changed before successful qualification"
                }
                crate::ResearchFailure::JobSamplingContinuation => {
                    "native sampling continuation differs"
                }
                crate::ResearchFailure::JobQualificationSequence => {
                    "native qualification sequence differs"
                }
                crate::ResearchFailure::JobFinderBinding => {
                    "native finder diagnostic source differs"
                }
                crate::ResearchFailure::JobCheckpointUnit => "learning checkpoint unit differs",
                crate::ResearchFailure::GeneratedTraceMissing => {
                    "local discovery lacks its generated decision trace"
                }
                crate::ResearchFailure::PeerPrerequisiteFormulaMissing => {
                    "checked temporary prerequisite formula is missing"
                }
                crate::ResearchFailure::PeerProgramConclusionMismatch => {
                    "peer program conclusion differs"
                }
                crate::ResearchFailure::PeerProgramObjectCapacity => {
                    "peer program context object capacity"
                }
                crate::ResearchFailure::PeerProgramCommandCapacity => {
                    "peer program replay command capacity"
                }
                crate::ResearchFailure::CompositionDeductionIdentity => {
                    "temporary deduction identity differs"
                }
                crate::ResearchFailure::OfferedProofFormulaMissing => {
                    "offered theorem formula missing"
                }
            }),
            Self::ResearchSlot { index, cause } => write!(f, "research slot {index}: {cause}"),
            Self::ModelDigestMismatch(_) => f.write_str("native model checkpoint content differs"),
            Self::External(failure) => write!(f, "external research failure {}", u32::from(failure.code)),
            Self::ResearchMismatch {
                code,
                expected,
                actual,
            } => write!(
                f,
                "research failure {}: {actual} != {expected}",
                u32::from(*code)
            ),
            Self::ResearchIndex { code, index } => {
                write!(f, "research failure {} at {index}", u32::from(*code))
            }
            Self::ResearchJob { code, job } => write!(f, "research failure {} for job {job}", u32::from(*code)),
            Self::ResearchContext { code, cause } => write!(f, "research failure {}: {cause}", u32::from(*code)),
            Self::CompositionReplay { work, maximum } => {
                write!(f, "composition replay differs at work {work}/{maximum}")
            }
            Self::ResearchCombined { primary, cleanup } | Self::StorageCombined { primary, cleanup } | Self::RuntimeCombined { primary, cleanup } => {
                write!(f, "cleanup failed: {cleanup}; primary failure: {primary}")
            }
            Self::Startup { code, .. } => write!(f, "startup failure {}", u32::from(*code)),
            Self::StartupCleanup { primary, cleanup } => write!(f, "startup failed: {primary}; cleanup failed: {cleanup}"),
            Self::StartupChildExit { exit_code, signal } => write!(f, "startup child exited ({exit_code:?}, {signal:?})"),
            Self::UncertainDurability(failure) => {
                write!(f, "storage halted: {}", u32::from(failure.code))
            }
            Self::StaleAuthority => {
                f.write_str("publication authority changed before durable commit")
            }
            Self::Deadline => f.write_str("catalog commit deadline expired before durable commit"),
        }
    }
}
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Stored(error) | Self::ObservationUnavailable(error) => Some(error),
            Self::Startup {
                cause: Some(error), ..
            } => Some(error),
            Self::StartupCleanup { primary, .. } => Some(primary),
            Self::RuntimeContext { cause, .. } => Some(cause),
            Self::ResearchContext { cause, .. } | Self::StorageContext { cause, .. } => Some(cause),
            Self::ResearchSlot { cause, .. } => Some(cause),
            Self::ResearchCombined { primary, .. }
            | Self::StorageCombined { primary, .. }
            | Self::RuntimeCombined { primary, .. } => Some(primary),
            Self::DiagnosticInspection(error) => Some(error),
            _ => None,
        }
    }
}
impl From<naome_proof::program::CodecFailure> for Error {
    fn from(error: naome_proof::program::CodecFailure) -> Self {
        Self::ProgramCodec(error)
    }
}

impl From<crate::StartupFailure> for Error {
    fn from(code: crate::StartupFailure) -> Self {
        Self::Startup {
            code,
            reaped: false,
            cause: None,
        }
    }
}

impl From<InputLimit> for Error {
    fn from(limit: InputLimit) -> Self {
        Self::InputLimit(limit)
    }
}
impl From<InputFault> for Error {
    fn from(error: InputFault) -> Self {
        Self::InputFault(error)
    }
}

impl From<crate::WorkerFailure> for Error {
    fn from(error: crate::WorkerFailure) -> Self {
        Self::Worker(error)
    }
}

impl From<crate::ResearchFailure> for Error {
    fn from(error: crate::ResearchFailure) -> Self {
        Self::Research(error)
    }
}

impl From<crate::RuntimeFailure> for Error {
    fn from(error: crate::RuntimeFailure) -> Self {
        Self::Runtime(error)
    }
}

impl From<crate::LearningGraphFailure> for Error {
    fn from(error: crate::LearningGraphFailure) -> Self {
        Self::LearningGraph(error)
    }
}

impl From<EvidenceFailure> for Error {
    fn from(error: EvidenceFailure) -> Self {
        Self::LearningEvidence(error)
    }
}

pub(crate) fn record_decode(error: serde_json::Error) -> Error {
    Error::RecordDecode {
        reason: json_fault(&error),
        line: error.line(),
        column: error.column(),
    }
}

pub(crate) fn config_decode(error: serde_json::Error) -> Error {
    Error::ConfigDecode {
        reason: json_fault(&error),
        line: error.line(),
        column: error.column(),
    }
}

pub(crate) fn json_fault(error: &serde_json::Error) -> crate::JsonFault {
    match error.classify() {
        serde_json::error::Category::Io => crate::JsonFault::Io,
        serde_json::error::Category::Syntax => crate::JsonFault::Syntax,
        serde_json::error::Category::Data => crate::JsonFault::Data,
        serde_json::error::Category::Eof => crate::JsonFault::Eof,
    }
}

pub(crate) fn sqlite_fault(error: &rusqlite::Error) -> (crate::SqlFault, Option<NonZeroI32>) {
    let reason = match error {
        rusqlite::Error::SqliteFailure(..) => crate::SqlFault::Engine,
        rusqlite::Error::QueryReturnedNoRows => crate::SqlFault::MissingRow,
        rusqlite::Error::InvalidColumnType(..) => crate::SqlFault::ColumnType,
        _ => crate::SqlFault::Other,
    };
    (reason, naome_storage::sqlite_code(error))
}

pub(crate) fn storage_io_error(
    operation: crate::StorageIoOperation,
    error: std::io::Error,
) -> Error {
    Error::StorageIo {
        operation,
        kind: crate::outcome::io_fault_kind(&error),
        os_code: error.raw_os_error().and_then(NonZeroI32::new),
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        use std::io::ErrorKind;
        if matches!(
            error.kind(),
            ErrorKind::WouldBlock
                | ErrorKind::Interrupted
                | ErrorKind::OutOfMemory
                | ErrorKind::StorageFull
                | ErrorKind::QuotaExceeded
        ) {
            Self::ExecutionLimit
        } else {
            Self::Io {
                kind: crate::outcome::io_fault_kind(&error),
                os_code: error.raw_os_error().and_then(NonZeroI32::new),
            }
        }
    }
}
impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::InvalidInput(message)
    }
}
impl From<naome_checker::program::Error> for Error {
    fn from(error: naome_checker::program::Error) -> Self {
        if error.resource_shortage() {
            return Self::ExecutionLimit;
        }
        match error {
            naome_checker::program::Error::Check(diagnostic) => Self::Proof(diagnostic.into()),
            naome_checker::program::Error::Inspection(error) => Self::DiagnosticInspection(error),
            naome_checker::program::Error::Invalid(reason) => Self::ProgramInput(reason),
            naome_checker::program::Error::Formula(error) => Self::Formula(error),
            naome_checker::program::Error::Codec(error) => error.into(),
            naome_checker::program::Error::Storage(error) => {
                let (reason, sqlite_code) = sqlite_fault(&error);
                Self::ProgramSql {
                    reason,
                    sqlite_code,
                }
            }
            naome_checker::program::Error::Context(error) => error.into(),
        }
    }
}
impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self::InvalidInput(message.to_owned())
    }
}
impl From<Error> for String {
    fn from(error: Error) -> Self {
        error.to_string()
    }
}
impl From<naome_checker::ContextError> for Error {
    fn from(error: naome_checker::ContextError) -> Self {
        match error {
            naome_checker::ContextError::Limit => Self::ExecutionLimit,
            other => Self::CheckedContext(other),
        }
    }
}
impl serde::Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        if let Self::LearningEvidence(failure) = self {
            return failure.serialize(serializer);
        }
        if let Self::UncertainDurability(failure) = self {
            let mut value = serializer.serialize_struct(
                "DurabilityError",
                3 + usize::from(failure.sqlite_code.is_some()),
            )?;
            value.serialize_field("code", &failure.code)?;
            if let Some(sqlite_code) = failure.sqlite_code {
                value.serialize_field("sqlite_code", &sqlite_code)?;
            }
            value.serialize_field("retryable", &false)?;
            value.serialize_field("fatal", &true)?;
            return value.end();
        }
        use serde::ser::SerializeMap;
        let mut value = serializer.serialize_map(None)?;
        value.serialize_entry("code", &self.code())?;
        value.serialize_entry("retryable", &self.retryable())?;
        value.serialize_entry("fatal", &self.fatal())?;
        if let Self::Startup {
            cause: Some(cause), ..
        } = self
        {
            value.serialize_entry("cause", cause)?;
        }
        if let Self::StartupCleanup { primary, cleanup } = self {
            value.serialize_entry("primary", primary)?;
            value.serialize_entry("cleanup", cleanup)?;
        }
        if let Self::StartupChildExit { exit_code, signal } = self {
            if let Some(code) = exit_code {
                value.serialize_entry("exit_code", code)?;
            }
            if let Some(signal) = signal {
                value.serialize_entry("signal", signal)?;
            }
        }
        if let Self::ObservationUnavailable(cause) = self {
            value.serialize_entry("cause", cause)?;
        }
        if let Self::RuntimeContext { cause, .. } = self {
            value.serialize_entry("cause", cause)?;
        }
        if let Self::ResearchContext { cause, .. } | Self::StorageContext { cause, .. } = self {
            value.serialize_entry("cause", cause)?;
        }
        if let Self::ResearchSlot { index, cause } = self {
            value.serialize_entry("index", index)?;
            value.serialize_entry("cause", cause)?;
        }
        if let Self::ResearchCombined { primary, cleanup }
        | Self::StorageCombined { primary, cleanup }
        | Self::RuntimeCombined { primary, cleanup } = self
        {
            value.serialize_entry("primary", primary)?;
            value.serialize_entry("cleanup", cleanup)?;
        }
        if let Some(diagnostic) = self.diagnostic() {
            value.serialize_entry("diagnostic", diagnostic)?;
        }
        if let Self::DiagnosticInspection(error) = self {
            value.serialize_entry("inspection_error", error)?;
        }
        if let Some((input_digest, reason)) = self.format_error() {
            #[derive(serde::Serialize)]
            struct Format<'a> {
                input_digest: naome_checker::diagnostics::Digest,
                reason: &'a FormatFailure,
            }
            value.serialize_entry(
                "format_error",
                &Format {
                    input_digest,
                    reason,
                },
            )?;
        }
        let cause = match self {
            Self::Stored(cause) => {
                value.serialize_entry("cause_code", &cause.code())?;
                cause
            }
            _ => self,
        };
        if let Self::External(details) = cause
            && let Some(digest) = details.detail_digest
        {
            value.serialize_entry("detail_digest", &digest)?;
        }
        if let Self::External(details) = cause {
            if let Some(expected) = details.expected_type {
                value.serialize_entry("expected_type", &expected)?;
            }
            if let Some(actual) = details.actual_type {
                value.serialize_entry("actual_type", &actual)?;
            }
        }
        if let Self::ModelDigestMismatch(details) = cause {
            value.serialize_entry("expected_digest", &details.expected)?;
            value.serialize_entry("actual_digest", &details.actual)?;
        }
        if let Self::ResearchMismatch {
            expected, actual, ..
        } = cause
        {
            value.serialize_entry("expected", expected)?;
            value.serialize_entry("actual", actual)?;
        }
        if let Self::ResearchIndex { index, .. } = cause {
            value.serialize_entry("index", index)?;
        }
        if let Self::ResearchJob { job, .. } = cause {
            value.serialize_entry("job", job)?;
        }
        if let Self::CompositionReplay { work, maximum } = cause {
            value.serialize_entry("work", work)?;
            value.serialize_entry("maximum", maximum)?;
        }
        if let Self::CertificateConstruction(reason) = cause {
            value.serialize_entry("format_reason", reason)?;
        }
        if let Self::CheckedContext(context) = cause {
            match context {
                naome_checker::ContextError::Storage(reason) => {
                    value.serialize_entry("reason", &reason.code())?;
                    if let Some(code) = reason.native_code() {
                        value.serialize_entry("native_code", &code)?;
                    }
                }
                naome_checker::ContextError::Corrupt => value.serialize_entry("reason", &13u8)?,
                naome_checker::ContextError::Limit => value.serialize_entry("reason", &14u8)?,
            }
        }
        if let Self::ProgramCodec(reason) = cause {
            value.serialize_entry("reason", &(*reason as u8))?;
        }
        if let Self::Compression(reason) = cause {
            value.serialize_entry("compression", reason)?;
        }
        if let Self::ProgramProjection(reason) = cause {
            value.serialize_entry("reason", &(*reason as u8))?;
        }
        if let Self::ProgramInput(reason) = cause {
            value.serialize_entry("reason", &(*reason as u8))?;
        }
        if let Self::DefinitionExpansion(reason) = cause {
            value.serialize_entry("expansion", reason)?;
        }
        if let Self::Schema { reason, variable } = cause {
            value.serialize_entry("reason", reason)?;
            value.serialize_entry("variable", variable)?;
        }
        if let Self::DefinedFormula(reason) = cause {
            value.serialize_entry("formula", reason)?;
        }
        if let Self::Formula(reason) = cause {
            value.serialize_entry(
                "formula",
                &naome_checker::diagnostics::FormulaFailure::from(reason),
            )?;
        }
        if let Self::QuestionRegistration(reason) = cause {
            value.serialize_entry("reason", &reason.code())?;
        }
        if let Self::Io { kind, os_code } = cause {
            value.serialize_entry("kind", kind)?;
            if let Some(code) = os_code {
                value.serialize_entry("os_code", code)?;
            }
        }
        if let Self::StorageIo {
            operation,
            kind,
            os_code,
        } = cause
        {
            value.serialize_entry("operation", operation)?;
            value.serialize_entry("kind", kind)?;
            if let Some(code) = os_code {
                value.serialize_entry("os_code", code)?;
            }
        }
        if let Self::CheckpointSql {
            reason,
            sqlite_code,
        }
        | Self::ProgramSql {
            reason,
            sqlite_code,
        }
        | Self::CatalogSql {
            reason,
            sqlite_code,
        }
        | Self::BacklogSql {
            reason,
            sqlite_code,
        }
        | Self::CheckedIndexCloseSql {
            reason,
            sqlite_code,
        }
        | Self::CheckedIndexSql {
            reason,
            sqlite_code,
        } = cause
        {
            value.serialize_entry("reason", reason)?;
            if let Some(code) = sqlite_code {
                value.serialize_entry("sqlite_code", code)?;
            }
        }
        if let Self::ResourceValidation {
            reason,
            field,
            actual,
            minimum,
            maximum,
        } = cause
        {
            value.serialize_entry("reason", reason)?;
            if let Some(field) = field {
                value.serialize_entry("field", field)?;
            }
            if let Some(actual) = actual {
                value.serialize_entry("actual", actual)?;
            }
            if let Some(minimum) = minimum {
                value.serialize_entry("minimum", minimum)?;
            }
            if let Some(maximum) = maximum {
                value.serialize_entry("maximum", maximum)?;
            }
        }
        if let Self::ProofCommandInput { reason, appended } = cause {
            value.serialize_entry("reason", reason)?;
            value.serialize_entry("appended", appended)?;
        }
        if let Self::ResourceProfileDecode {
            reason,
            line,
            column,
        } = cause
        {
            value.serialize_entry("reason", reason)?;
            value.serialize_entry("line", line)?;
            value.serialize_entry("column", column)?;
        }
        if let Self::CheckpointDecode {
            reason,
            line,
            column,
        }
        | Self::ConfigDecode {
            reason,
            line,
            column,
        }
        | Self::RecordDecode {
            reason,
            line,
            column,
        } = cause
        {
            value.serialize_entry("reason", reason)?;
            value.serialize_entry("line", line)?;
            value.serialize_entry("column", column)?;
        }
        if let Self::DefinitionCheck(reason) = cause {
            use crate::outcome::DefinitionCheckReason as Code;
            use naome_checker::DefinitionCheckError as E;
            use naome_checker::diagnostics::{ExpansionFailure, FormulaFailure};
            let code = match reason.as_ref() {
                E::Expansion(error) => {
                    value.serialize_entry("expansion", &ExpansionFailure::from(error))?;
                    Code::Expansion
                }
                E::CanonicalBody(error) => {
                    value.serialize_entry("formula", &FormulaFailure::from(error))?;
                    Code::CanonicalBody
                }
                E::Certificate(error) => {
                    value.serialize_entry("format", &FormatFailure::from(error))?;
                    Code::Certificate
                }
                E::UnknownObligationStatement { statement_id } => {
                    value.serialize_entry("statement", statement_id.as_bytes())?;
                    Code::UnknownObligation
                }
                E::ObligationConclusionMismatch { statement_id } => {
                    value.serialize_entry("statement", statement_id.as_bytes())?;
                    Code::ObligationMismatch
                }
                E::ObligationFormula(error) => {
                    value.serialize_entry("formula", &FormulaFailure::from(error))?;
                    Code::ObligationFormula
                }
                _ => Code::Unsupported,
            };
            value.serialize_entry("reason", &code)?;
        }
        if let Self::QuestionInput(reason) = cause {
            use naome_checker::diagnostics::{ExpansionFailure, FormulaFailure};
            use naome_proof::QuestionError;
            match reason.as_ref() {
                QuestionError::Invalid(fault) => {
                    value.serialize_entry("reason", &(*fault as u8))?
                }
                QuestionError::Formula(error) => {
                    value.serialize_entry("formula", &FormulaFailure::from(error))?
                }
                QuestionError::DefinedFormula(error) => {
                    value.serialize_entry("formula", &FormulaFailure::from(error))?
                }
                QuestionError::Expansion(error) => {
                    value.serialize_entry("expansion", &ExpansionFailure::from(error))?
                }
                _ => {}
            }
        }
        if let Self::MemoryOverload {
            requested,
            charged,
            budget,
        } = cause
        {
            value.serialize_entry("requested", requested)?;
            value.serialize_entry("charged", charged)?;
            value.serialize_entry("budget", budget)?;
        }
        if let Self::DiskOverload {
            available,
            required,
        } = cause
        {
            // JSON consumers can preserve the full integer using two u64 limbs.
            let limbs = |value: u128| [(value >> 64) as u64, value as u64];
            value.serialize_entry("available", &limbs(*available))?;
            value.serialize_entry("required", &limbs(*required))?;
        }
        if let Self::Startup { reaped, .. } = self {
            value.serialize_entry("reaped", reaped)?;
        }
        if let Self::QuestionLimit(limit) = self {
            value.serialize_entry("limit", &(*limit as u8))?;
        }
        if let Self::MissingRequiredTheorem(id) = cause {
            value.serialize_entry("proof_id", id.as_bytes())?;
        }
        if let Self::MissingQuestionDefinition(id) = self {
            value.serialize_entry("definition", id.as_bytes())?;
        }
        value.end()
    }
}

impl From<naome_checker::CheckError> for Error {
    fn from(error: naome_checker::CheckError) -> Self {
        Self::Proof(error.into_diagnostic())
    }
}

impl From<naome_checker::DefinitionCheckError> for Error {
    fn from(error: naome_checker::DefinitionCheckError) -> Self {
        match error {
            naome_checker::DefinitionCheckError::ContextAccess(source) => source.into(),
            naome_checker::DefinitionCheckError::Expansion(
                naome_proof::DefinitionExpansionError::Access(source),
            ) => naome_checker::ContextError::from(source).into(),
            other => Self::DefinitionCheck(Box::new(other)),
        }
    }
}

impl From<naome_checker::question::ResolutionError> for Error {
    fn from(error: naome_checker::question::ResolutionError) -> Self {
        match error {
            naome_checker::question::ResolutionError::Target(diagnostic) => {
                Self::Proof(diagnostic.into())
            }
            naome_checker::question::ResolutionError::Program(error) => error.into(),
        }
    }
}

impl From<naome_proof::DefinitionExpansionError> for Error {
    fn from(error: naome_proof::DefinitionExpansionError) -> Self {
        match error {
            naome_proof::DefinitionExpansionError::Access(source) => {
                naome_checker::ContextError::from(source).into()
            }
            other => Self::DefinitionExpansion((&other).into()),
        }
    }
}
impl From<naome_foundation::SchemaError> for Error {
    fn from(error: naome_foundation::SchemaError) -> Self {
        use naome_foundation::SchemaError as S;
        let (reason, variable) = match error {
            S::RoleVariableCollision(v) => (crate::SchemaFailure::RoleCollision, v),
            S::ParameterCollidesWithRole(v) => (crate::SchemaFailure::ParameterRoleCollision, v),
            S::DuplicateParameter(v) => (crate::SchemaFailure::DuplicateParameter, v),
            S::ForbiddenPredicateVariable(v) => {
                (crate::SchemaFailure::ForbiddenPredicateVariable, v)
            }
            S::UndeclaredPredicateVariable(v) => {
                (crate::SchemaFailure::UndeclaredPredicateVariable, v)
            }
        };
        Self::Schema {
            reason,
            variable: variable.identifier(),
        }
    }
}
impl From<naome_proof::DefinedFormulaCodecError> for Error {
    fn from(error: naome_proof::DefinedFormulaCodecError) -> Self {
        Self::DefinedFormula((&error).into())
    }
}
impl From<naome_foundation::FormulaCodecError> for Error {
    fn from(error: naome_foundation::FormulaCodecError) -> Self {
        Self::Formula(error)
    }
}
impl From<naome_checker::question::RejectionReason> for Error {
    fn from(reason: naome_checker::question::RejectionReason) -> Self {
        Self::QuestionRegistration(reason)
    }
}
impl From<naome_proof::QuestionError> for Error {
    fn from(error: naome_proof::QuestionError) -> Self {
        match error {
            naome_proof::QuestionError::MissingDefinition(id) => {
                Self::MissingQuestionDefinition(id)
            }
            naome_proof::QuestionError::Limit(limit) => Self::QuestionLimit(limit),
            error => Self::QuestionInput(Box::new(error)),
        }
    }
}
impl From<naome_checker::ArtifactStateError> for Error {
    fn from(error: naome_checker::ArtifactStateError) -> Self {
        match error {
            naome_checker::ArtifactStateError::Context(error) => error.into(),
            other => Self::InvalidInput(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests;

impl From<naome_proof::program::ProjectionFailure> for Error {
    fn from(error: naome_proof::program::ProjectionFailure) -> Self {
        Self::ProgramProjection(error)
    }
}
