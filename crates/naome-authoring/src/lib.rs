//! Bounded `.nao` compilation of checked proofs, definitions, and formal questions.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Write as _};

use naome_checker::{
    ArtifactState, CheckError, DefinitionCheckError, check_normal_form_with_state,
    normalize_and_check_definition_with_state,
};
use naome_foundation::{
    FORMULA_MAX_DEPTH, FORMULA_MAX_NODES, FormulaCodecError, FreeVariable, ZfcAxiom,
};
use naome_proof::{
    ArtifactId, ArtifactPayload, CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_FORMULA_NODES,
    CERTIFICATE_MAX_STEPS, DEFINITION_MAX_GRAPH_ARITY, DefinedFormula, DefinedFormulaCodecError,
    DefinitionCertificateError, DefinitionExpansionError, DefinitionId, DefinitionKind,
    DerivationId, ProofCertificate, ProofCertificateError, ProofFormula, ProofId, ProofReplacement,
    ProofSeparation, ProofStep, StatementId,
};

/// Maximum UTF-8 bytes accepted in one `.nao` source value.
pub const AUTHORING_SOURCE_MAX_BYTES: usize = CERTIFICATE_MAX_BYTES;

const DIAGNOSTIC_NAME_MAX_SCALARS: usize = 64;
const FORMULA_BINDING_MAX_NODES: usize = FORMULA_MAX_NODES;

/// Compiles one complete, dependency-free `.nao` proof source.
///
/// Reachable dependencies fail because this entry point uses an empty checked
/// artifact context. Use [`compile_against_proof_context`] for explicitly
/// checker-validated dependencies.
pub fn compile(source: &str) -> Result<CompiledProof, CompileError> {
    match compile_artifact(source)? {
        CompiledArtifact::Proof(proof) => Ok(proof),
        CompiledArtifact::Definition(_) => Err(CompileError::ExpectedProof { offset: 0 }),
    }
}

/// Compiles one complete `.nao` proof or definition against an empty context.
///
/// The empty state can compile dependency-free relation definitions and proofs,
/// but it cannot authorize citations, definition aliases, or function obligations.
pub fn compile_artifact(source: &str) -> Result<CompiledArtifact, CompileError> {
    compile_with_artifact_state(source, &ArtifactState::new())
}

/// Compiles a proof against an explicitly supplied, checker-validated context.
/// This supports offline state packages and downloaded helper certificates.
/// Compilation establishes mathematical validity only; it does not establish
/// publication, scientific usefulness, or reward eligibility.
pub fn compile_against_proof_context(
    source: &str,
    context: &ArtifactState,
) -> Result<CompiledProof, CompileError> {
    match compile_with_artifact_state(source, context)? {
        CompiledArtifact::Proof(proof) => Ok(proof),
        CompiledArtifact::Definition(_) => Err(CompileError::ExpectedProof { offset: 0 }),
    }
}

/// Compiles a proof or conservative definition against a checked offline context.
/// The context grants mathematical dependency resolution only. It grants no
/// publication, scientific usefulness, or reward eligibility.
pub fn compile_artifact_against_proof_context(
    source: &str,
    context: &ArtifactState,
) -> Result<CompiledArtifact, CompileError> {
    compile_with_artifact_state(source, context)
}

fn compile_with_artifact_state(
    source: &str,
    artifact_state: &ArtifactState,
) -> Result<CompiledArtifact, CompileError> {
    if source.len() > AUTHORING_SOURCE_MAX_BYTES {
        return Err(CompileError::SourceTooLong {
            actual: source.len(),
            maximum: AUTHORING_SOURCE_MAX_BYTES,
        });
    }

    Parser::new(source).compile(artifact_state)
}

mod diagnostics;
mod output;
mod parser;
mod question;
mod syntax;

pub use diagnostics::{
    CompileDiagnostic, CompileError, DiagnosticCode, SourcePosition, SourceSpan,
};
pub use output::{CompiledArtifact, CompiledDefinition, CompiledProof};
use parser::Parser;
pub use question::{
    CompiledQuestion, QUESTION_SOURCE_MAX_BYTES, QUESTION_TARGET_MAX_DEPTH,
    QUESTION_TARGET_MAX_NODES, QuestionCompileError, QuestionError, QuestionOutcome,
};
