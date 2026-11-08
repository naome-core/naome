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
            Self::EmptyCertificate | Self::UnexpectedEnd | Self::Unsupported => {}
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
    Proof(std::sync::Arc<naome_checker::diagnostics::ProofDiagnostic>),
    DiagnosticInspection(naome_checker::diagnostics::InspectionError),
    CertificateFormat(Box<CertificateFormatError>),
    /// Invalid data read from owned storage remains fatal while retaining the
    /// original structured diagnostic. It is never a candidate repair request.
    Stored(Box<Error>),
    CorruptStorage(String),
    CheckedContext(naome_checker::ContextError),
    UncertainDurability(DurabilityFailure),
    LearningEvidence(EvidenceFailure),
    LearningGraph(crate::LearningGraphFailure),
    ProgramCodec(naome_proof::program::CodecFailure),
    ProgramInput(naome_checker::program::ProgramFault),
    Formula(naome_foundation::FormulaCodecError),
    QuestionInput(Box<naome_proof::QuestionError>),
    QuestionRegistration(naome_checker::question::RejectionReason),
    Runtime(crate::RuntimeFailure),
    Research(crate::ResearchFailure),
    ResearchCombined {
        primary: Box<Error>,
        cleanup: Box<Error>,
    },
    Startup {
        code: crate::StartupFailure,
        reaped: bool,
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
            Self::Proof(_) => OperationCode::ProofCheck,
            Self::DiagnosticInspection(_) => OperationCode::DiagnosticInspection,
            Self::CertificateFormat(_) => OperationCode::CertificateFormat,
            Self::Stored(_) => OperationCode::InvalidStoredRecord,
            Self::CorruptStorage(_) => OperationCode::CorruptStorage,
            Self::CheckedContext(_) => OperationCode::CheckedContext,
            Self::UncertainDurability(failure) => return failure.code.into(),
            Self::LearningEvidence(failure) => return failure.code().into(),
            Self::LearningGraph(failure) => return (*failure).into(),
            Self::ProgramCodec(_) => OperationCode::ProgramCodec,
            Self::ProgramInput(_) => OperationCode::ProgramInput,
            Self::Formula(_) => OperationCode::Formula,
            Self::QuestionInput(_) => OperationCode::QuestionInput,
            Self::QuestionRegistration(_) => OperationCode::QuestionRegistration,
            Self::Runtime(failure) => return (*failure).into(),
            Self::Research(failure) => return (*failure).into(),
            Self::ResearchCombined { .. } => {
                return crate::ResearchFailure::MultipleFailures.into();
            }
            Self::Startup { code, .. } => return (*code).into(),
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
                Self::MemoryOverload { .. }
                    | Self::DiskOverload { .. }
                    | Self::ExecutionLimit
                    | Self::StaleAuthority
                    | Self::Deadline
            )
    }
    pub(crate) fn storage(self) -> Self {
        match self {
            Self::InvalidInput(message) => Self::CorruptStorage(message),
            error @ (Self::InputFault(_)
            | Self::QuestionLimit(_)
            | Self::QuestionInput(_)
            | Self::QuestionRegistration(_)
            | Self::ProgramInput(_)
            | Self::Formula(_)) => Self::Stored(Box::new(error)),
            error @ (Self::Proof(_) | Self::CertificateFormat(_) | Self::ProgramCodec(_))
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
                    | Self::CheckedContext(_)
                    | Self::UncertainDurability(_)
                    | Self::Runtime(_)
                    | Self::ResearchCombined { .. }
                    | Self::Startup { .. }
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
            }),
            Self::QuestionLimit(limit) => naome_proof::QuestionError::Limit(*limit).fmt(f),
            Self::InvalidInput(message) => f.write_str(message),
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
            Self::Stored(error) => write!(f, "storage halted: {error}"),
            Self::CorruptStorage(message) => write!(f, "storage halted: {message}"),
            Self::CheckedContext(error) => write!(f, "storage halted: {error}"),
            Self::LearningEvidence(error) => error.fmt(f),
            Self::LearningGraph(error) => error.fmt(f),
            Self::ProgramCodec(error) => error.fmt(f),
            Self::ProgramInput(error) => error.fmt(f),
            Self::Formula(error) => error.fmt(f),
            Self::QuestionInput(error) => error.fmt(f),
            Self::QuestionRegistration(reason) => write!(f, "question registration: {reason:?}"),
            Self::Runtime(failure) => write!(f, "runtime failure {}", u32::from(*failure)),
            Self::Research(failure) => f.write_str(match failure {
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
                crate::ResearchFailure::OfferedProofFormulaMissing => {
                    "offered theorem formula missing"
                }
            }),
            Self::ResearchCombined { primary, cleanup } => {
                write!(f, "cleanup failed: {cleanup}; primary failure: {primary}")
            }
            Self::Startup { code, .. } => write!(f, "startup failure {}", u32::from(*code)),
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
            Self::Stored(error) => Some(error),
            Self::ResearchCombined { primary, .. } => Some(primary),
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
            Self::InvalidInput(error.to_string())
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
                Self::CorruptStorage(error.to_string())
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
        if let Self::ResearchCombined { primary, cleanup } = self {
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
        if let Self::ProgramInput(reason) = cause {
            value.serialize_entry("reason", &(*reason as u8))?;
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
        } = self
        {
            value.serialize_entry("requested", requested)?;
            value.serialize_entry("charged", charged)?;
            value.serialize_entry("budget", budget)?;
        }
        if let Self::DiskOverload {
            available,
            required,
        } = self
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
            other => Self::InvalidInput(other.to_string()),
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
