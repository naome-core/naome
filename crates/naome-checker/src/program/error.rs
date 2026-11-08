use std::fmt;

/// Stable machine reasons for proof engine input, custody and replay failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProgramFault {
    PhysicalAddress = 1,
    IncompleteExport = 2,
    CursorOutOfRange = 3,
    PrefixHashWidth = 4,
    InputHashWidth = 5,
    SuffixWidth = 6,
    UncheckedProgram = 7,
    StoredCommandCapacity = 8,
    ProgramByteWidth = 9,
    IncompleteConclusionExport = 10,
    StatementAddressWidth = 11,
    IncompleteExportIndex = 12,
    FactOutsidePrefix = 13,
    UnprovedResult = 14,
    FactOwnerMismatch = 15,
    UniversalRequired = 16,
    ForeignMutation = 17,
    UncommittedInstruction = 18,
    Sealed = 19,
    CorruptProgramHash = 20,
    ProgramAddress = 21,
    BudgetSnapshotCapacity = 22,
    CacheBudget = 23,
    InputHashMismatch = 24,
    EmptyRecipe = 25,
    ReplayResultMismatch = 26,
    ProofAddress = 27,
    PrematureSeal = 28,
    ImplicationRequired = 29,
    AntecedentMismatch = 30,
    ScopedUniversalRequired = 31,
    BinderAddress = 32,
    TransformOrder = 33,
    ReplayTransformMismatch = 34,
    GraphVariable = 35,
    GraphCycle = 36,
    GraphTag = 37,
    GraphDigest = 38,
    UnauthenticatedChild = 39,
    GraphPropertyOverflow = 40,
    GraphAuthentication = 41,
    AuthenticatedDigest = 42,
    FormulaMutation = 43,
    GraphIdentity = 44,
    DanglingBinder = 45,
    TreeVariableWidth = 46,
    IncompleteProjection = 47,
    UncheckedConclusion = 48,
    UnauthenticatedConclusion = 49,
    DependencyPageCapacity = 50,
    DependencyWidth = 51,
    ReferenceNodeWidth = 52,
    ReferenceStackAddress = 53,
    UnknownDatabase = 54,
    WorkFormat = 55,
    UnexpectedSchemaObject = 56,
    WorkSchema = 57,
    IncompleteSchema = 58,
    DeductionAssumption = 59,
    FactOutsideScope = 60,
    InsertedRowAddress = 61,
}
impl fmt::Display for ProgramFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PhysicalAddress => "physical storage address exhausted",
            Self::IncompleteExport => "program export incomplete",
            Self::CursorOutOfRange => "program cursor exceeds input",
            Self::PrefixHashWidth => "program prefix hash width",
            Self::InputHashWidth => "program input hash width",
            Self::SuffixWidth => "program stream suffix width",
            Self::UncheckedProgram => "program has not been completely checked",
            Self::StoredCommandCapacity => "stored command capacity",
            Self::ProgramByteWidth => "program byte width",
            Self::IncompleteConclusionExport => "program conclusion export is incomplete",
            Self::StatementAddressWidth => "statement address width",
            Self::IncompleteExportIndex => "program export index is incomplete",
            Self::FactOutsidePrefix => "fact is outside the checked program prefix",
            Self::UnprovedResult => "program result is not a proved fact",
            Self::FactOwnerMismatch => "fact handle belongs to a different proof evaluator",
            Self::UniversalRequired => "instantiation requires a universal fact",
            Self::ForeignMutation => "proof work changed outside its owner",
            Self::UncommittedInstruction => "cannot append during an uncommitted instruction",
            Self::Sealed => "proof program is sealed",
            Self::CorruptProgramHash => "program hash corruption",
            Self::ProgramAddress => "program address exhausted",
            Self::BudgetSnapshotCapacity => "budget snapshot capacity",
            Self::CacheBudget => "invalid effective cache budget",
            Self::InputHashMismatch => "program input hash mismatch",
            Self::EmptyRecipe => "empty proof recipe",
            Self::ReplayResultMismatch => "saved proof result differs from mathematical replay",
            Self::ProofAddress => "proof address exhausted",
            Self::PrematureSeal => "seal is not the complete program",
            Self::ImplicationRequired => "composed application requires an implication",
            Self::AntecedentMismatch => "composed modus ponens antecedent mismatch",
            Self::ScopedUniversalRequired => "scoped instantiation requires a universal fact",
            Self::BinderAddress => "physical binder address exhausted",
            Self::TransformOrder => "saved transformation is not dependency ordered",
            Self::ReplayTransformMismatch => "saved formula transformation failed replay",
            Self::GraphVariable => "invalid graph variable",
            Self::GraphCycle => "formula graph is not acyclic",
            Self::GraphTag => "invalid formula graph tag",
            Self::GraphDigest => "formula graph digest corruption",
            Self::UnauthenticatedChild => {
                "formula child has not passed current-owner authentication"
            }
            Self::GraphPropertyOverflow => "formula graph property overflow",
            Self::GraphAuthentication => "formula graph content authentication failed",
            Self::AuthenticatedDigest => "authenticated formula digest corruption",
            Self::FormulaMutation => "authenticated formula changed within its owner",
            Self::GraphIdentity => "formula graph identity collision or corruption",
            Self::DanglingBinder => "program formula has dangling bound variables",
            Self::TreeVariableWidth => "tree variable width",
            Self::IncompleteProjection => "formula projection is incomplete",
            Self::UncheckedConclusion => "program has no checked conclusion",
            Self::UnauthenticatedConclusion => "conclusion is not authenticated",
            Self::DependencyPageCapacity => "program dependency page capacity",
            Self::DependencyWidth => "checked dependency width",
            Self::ReferenceNodeWidth => "reference node width",
            Self::ReferenceStackAddress => "reference stack address exhausted",
            Self::UnknownDatabase => "unknown proof work database",
            Self::WorkFormat => "proof work format mismatch",
            Self::UnexpectedSchemaObject => "unexpected proof work schema object",
            Self::WorkSchema => "proof work schema differs from the current contract",
            Self::IncompleteSchema => "incomplete proof work schema",
            Self::DeductionAssumption => "deduction assumption is not in the checked prefix",
            Self::FactOutsideScope => "fact is outside the earlier deduction scope",
            Self::InsertedRowAddress => "invalid inserted row address",
        })
    }
}

#[derive(Debug)]
pub enum Error {
    Check(Box<crate::diagnostics::ProofDiagnostic>),
    Inspection(crate::diagnostics::InspectionError),
    Invalid(ProgramFault),
    Formula(naome_foundation::FormulaCodecError),
    Codec(naome_proof::program::CodecFailure),
    Storage(rusqlite::Error),
    Context(crate::ContextError),
}
impl Error {
    pub fn diagnostic(&self) -> Option<&crate::diagnostics::ProofDiagnostic> {
        match self {
            Self::Check(diagnostic) => Some(diagnostic),
            _ => None,
        }
    }
    pub fn resource_shortage(&self) -> bool {
        matches!(self, Self::Context(crate::ContextError::Limit))
            || matches!(self,Self::Storage(rusqlite::Error::SqliteFailure(error,_)) if matches!(error.code,
            rusqlite::ErrorCode::DatabaseBusy|rusqlite::ErrorCode::DatabaseLocked|rusqlite::ErrorCode::DiskFull|rusqlite::ErrorCode::OutOfMemory))
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Check(diagnostic) => write!(
                f,
                "proof command {} violates {}",
                diagnostic.location.step,
                diagnostic.code()
            ),
            Self::Inspection(error) => error.fmt(f),
            Self::Invalid(reason) => reason.fmt(f),
            Self::Formula(error) => error.fmt(f),
            Self::Codec(error) => error.fmt(f),
            Self::Storage(error) => write!(f, "{error}"),
            Self::Context(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Context(e) => Some(e),
            Self::Inspection(e) => Some(e),
            _ => None,
        }
    }
}
impl serde::Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut value = serializer.serialize_map(None)?;
        let code = match self {
            Self::Check(_) => "proof_check",
            Self::Inspection(_) => "diagnostic_inspection",
            Self::Invalid(_) => "program_input",
            Self::Formula(_) => "program_formula",
            Self::Codec(_) => "program_codec",
            Self::Storage(_) => "program_storage",
            Self::Context(_) => "checked_context",
        };
        value.serialize_entry("code", code)?;
        match self {
            Self::Check(diagnostic) => value.serialize_entry("diagnostic", diagnostic)?,
            Self::Inspection(error) => value.serialize_entry("inspection_error", error)?,
            Self::Invalid(reason) => value.serialize_entry("reason", &(*reason as u8))?,
            Self::Formula(error) => value
                .serialize_entry("formula", &crate::diagnostics::FormulaFailure::from(error))?,
            Self::Codec(reason) => value.serialize_entry("reason", &(*reason as u8))?,
            Self::Storage(rusqlite::Error::SqliteFailure(error, _)) => {
                value.serialize_entry("sqlite_code", &error.extended_code)?
            }
            Self::Context(error) => {
                use crate::{ContextError, diagnostics::Failure};
                let reason = match error {
                    ContextError::Corrupt => Failure::ContextCorrupt,
                    ContextError::Limit => Failure::ContextLimit,
                    ContextError::Storage(_) => Failure::ContextStorage,
                };
                value.serialize_entry("reason", &reason.code())?
            }
            Self::Storage(_) => {}
        }
        value.end()
    }
}
impl From<naome_proof::program::CodecFailure> for Error {
    fn from(error: naome_proof::program::CodecFailure) -> Self {
        Self::Codec(error)
    }
}
impl From<ProgramFault> for Error {
    fn from(value: ProgramFault) -> Self {
        Self::Invalid(value)
    }
}
impl From<naome_foundation::FormulaCodecError> for Error {
    fn from(value: naome_foundation::FormulaCodecError) -> Self {
        Self::Formula(value)
    }
}
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}
impl From<crate::ContextError> for Error {
    fn from(error: crate::ContextError) -> Self {
        Self::Context(error)
    }
}
impl From<Error> for String {
    fn from(value: Error) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_storage_failure_keeps_the_extended_code_without_sqlite_text() {
        let error = Error::Storage(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE),
            Some("private SQL detail".into()),
        ));
        let value = serde_json::to_value(&error).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "code": "program_storage",
                "sqlite_code": rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE,
            })
        );
    }
}
