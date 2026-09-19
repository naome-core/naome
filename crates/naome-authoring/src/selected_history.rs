//! Authoring against healthy, fully replayed canonical finalized history.

use super::*;
use naome_storage::state::{ResearchStorageError, SelectedResearchHistory};

/// Compiles one proof using the selected full state's checked proof library.
/// History health is checked before source parsing. Proposed records, downloaded
/// packages, and caller-built snapshots cannot implement the sealed history
/// interface. Compilation performs no I/O or mutation and grants no publication;
/// subsequent ledger admission rechecks the result against its actual parent.
pub fn compile_against_selected_history(
    source: &str,
    selected: &(impl SelectedResearchHistory + ?Sized),
) -> Result<CompiledProof, SelectedHistoryCompileError> {
    match compile_artifact_against_selected_history(source, selected)? {
        CompiledArtifact::Proof(proof) => Ok(proof),
        CompiledArtifact::Definition(_) => Err(SelectedHistoryCompileError::Compilation {
            source: CompileError::ExpectedProof { offset: 0 },
        }),
    }
}

/// Compiles a mathematical artifact against the finalized proof library.
/// This does not extend the ledger's accepted operation kinds: standalone
/// definitions remain offline authoring artifacts under the trusted MVP rules.
pub fn compile_artifact_against_selected_history(
    source: &str,
    selected: &(impl SelectedResearchHistory + ?Sized),
) -> Result<CompiledArtifact, SelectedHistoryCompileError> {
    let context = || {
        if selected.is_halted()? {
            return Err(ResearchStorageError::Invalid("selected history halted"));
        }
        Ok(selected
            .selected_branch()?
            .state()
            .library()
            .artifact_dag()
            .artifact_state())
    };
    let context = context().map_err(|source| SelectedHistoryCompileError::SelectedState {
        source: Box::new(source),
    })?;
    compile_with_artifact_state(source, context)
        .map_err(|source| SelectedHistoryCompileError::Compilation { source })
}

/// Failure to obtain healthy finalized state or to compile source against it.
#[derive(Debug)]
#[non_exhaustive]
pub enum SelectedHistoryCompileError {
    SelectedState { source: Box<ResearchStorageError> },
    Compilation { source: CompileError },
}

impl fmt::Display for SelectedHistoryCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectedState { source } => {
                write!(formatter, "selected history unavailable: {source}")
            }
            Self::Compilation { source } => {
                write!(formatter, "artifact compilation failed: {source}")
            }
        }
    }
}

impl Error for SelectedHistoryCompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::Compilation { source } => Some(source),
        }
    }
}
