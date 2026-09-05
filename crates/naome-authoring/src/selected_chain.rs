//! Compilation against healthy replay-verified selected journal state.

use super::*;

/// Compiles one `.nao` proof source against a selected artifact-chain journal.
///
/// Journal health is checked before source compilation. Root-reachable
/// references resolve only from artifacts strictly applied or replayed into
/// `selected`; block candidates, archived payloads, and arbitrary caller-built
/// resolver states are not inputs. Compilation performs no journal I/O or mutation.
/// Its output is still an unselected authoring artifact, and later admission
/// fully rechecks it against the then-current target state. The selected journal
/// does not by itself establish network provenance, consensus, or finality.
pub fn compile_against_selected_chain(
    source: &str,
    selected: &ArtifactChainJournal,
) -> Result<CompiledProof, SelectedChainCompileError> {
    match compile_artifact_against_selected_chain(source, selected)? {
        CompiledArtifact::Proof(proof) => Ok(proof),
        CompiledArtifact::Definition(_) => Err(SelectedChainCompileError::Compilation {
            source: CompileError::ExpectedProof { offset: 0 },
        }),
    }
}

/// Compiles one proof or definition using only the journal's healthy selected state.
pub fn compile_artifact_against_selected_chain(
    source: &str,
    selected: &ArtifactChainJournal,
) -> Result<CompiledArtifact, SelectedChainCompileError> {
    let artifact_state =
        selected
            .artifact_state()
            .map_err(|source| SelectedChainCompileError::SelectedState {
                source: Box::new(source),
            })?;
    compile_with_artifact_state(source, artifact_state)
        .map_err(|source| SelectedChainCompileError::Compilation { source })
}

/// Failure to obtain selected state or compile against it.
#[derive(Debug)]
#[non_exhaustive]
pub enum SelectedChainCompileError {
    /// The selected journal cannot expose healthy applied-or-replayed state.
    SelectedState {
        source: Box<ArtifactChainJournalError>,
    },
    /// Source parsing, proof checking, or exact reference resolution failed.
    Compilation { source: CompileError },
}

impl fmt::Display for SelectedChainCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectedState { source } => {
                write!(
                    formatter,
                    "selected artifact-chain state is unavailable: {source}"
                )
            }
            Self::Compilation { source } => {
                write!(formatter, "artifact compilation failed: {source}")
            }
        }
    }
}

impl Error for SelectedChainCompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::Compilation { source } => Some(source),
        }
    }
}
