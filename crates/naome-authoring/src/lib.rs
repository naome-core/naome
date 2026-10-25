//! Bounded `.nao` compilation of checked proofs, definitions, and formal questions.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Write as _};

use naome_checker::{
    ArtifactState, CheckError, ContextView, DefinitionCheckError, check_normal_form_with_state,
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
        CompiledArtifact::Definition(_) => Err(CompileError::at_source(
            CompileErrorKind::ExpectedProof { offset: 0 },
            source,
        )),
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
    context: &dyn ContextView,
) -> Result<CompiledProof, CompileError> {
    match compile_with_artifact_state(source, context)? {
        CompiledArtifact::Proof(proof) => Ok(proof),
        CompiledArtifact::Definition(_) => Err(CompileError::at_source(
            CompileErrorKind::ExpectedProof { offset: 0 },
            source,
        )),
    }
}

/// Compiles a proof or conservative definition against a checked offline context.
/// The context grants mathematical dependency resolution only. It grants no
/// publication, scientific usefulness, or reward eligibility.
pub fn compile_artifact_against_proof_context(
    source: &str,
    context: &dyn ContextView,
) -> Result<CompiledArtifact, CompileError> {
    compile_with_artifact_state(source, context)
}

/// Rechecks the original source against its frozen context, then returns only
/// the requested bounded structural fragment. A changed source/context or a
/// changed failure rejects reuse; no report is accepted as a proof or patch.
pub fn inspect_source(
    source: &str,
    context: &dyn ContextView,
    diagnostic: &naome_checker::diagnostics::ProofDiagnostic,
    query: &naome_checker::diagnostics::FormulaQuery,
) -> Result<naome_checker::diagnostics::FormulaFragment, naome_checker::diagnostics::InspectionError>
{
    use naome_checker::diagnostics::{Digest, InspectionError};
    diagnostic.validate_schema()?;
    query.validate()?;
    if source.len() > AUTHORING_SOURCE_MAX_BYTES
        || diagnostic.input.source_digest != Some(Digest::of(source.as_bytes()))
    {
        return Err(InspectionError::InputChanged);
    }
    if diagnostic.context_snapshot != Digest(context.snapshot_id())
        || !diagnostic.context_consistent
    {
        return Err(InspectionError::ContextChanged);
    }
    if !diagnostic.matches_query(query) {
        return Err(InspectionError::UnknownFormula);
    }
    let error = Parser::new(source)
        .with_query(query)
        .compile(context)
        .err()
        .ok_or(InspectionError::InputChanged)?;
    let report = match &error {
        CompileErrorKind::Check { source, .. } => source.diagnostic(),
        CompileErrorKind::StatementMismatch { diagnostic, .. } => diagnostic,
        _ => return Err(InspectionError::InputChanged),
    };
    if report.input != diagnostic.input
        || report.location.step != diagnostic.location.step
        || report.failure != diagnostic.failure
    {
        return Err(InspectionError::InputChanged);
    }
    report
        .inspection
        .clone()
        .ok_or(InspectionError::InvalidPath)
}

fn compile_with_artifact_state(
    source: &str,
    artifact_state: &dyn ContextView,
) -> Result<CompiledArtifact, CompileError> {
    if source.len() > AUTHORING_SOURCE_MAX_BYTES {
        return Err(CompileError::at_source(
            CompileErrorKind::SourceTooLong {
                actual: source.len(),
                maximum: AUTHORING_SOURCE_MAX_BYTES,
            },
            source,
        ));
    }

    Parser::new(source)
        .compile(artifact_state)
        .map_err(|kind| CompileError::at_source(kind, source))
}

mod diagnostics;
mod output;
mod parser;
mod question;
mod syntax;

pub use diagnostics::{
    CompileDetails, CompileDiagnostic, CompileError, CompileErrorKind, DefinitionFailure,
    DiagnosticCode, FormatFailure, SourcePosition, SourceSpan,
};
pub use output::{CompiledArtifact, CompiledDefinition, CompiledProof};
use parser::Parser;
pub use question::{
    CompiledQuestion, QUESTION_SOURCE_MAX_BYTES, QUESTION_TARGET_MAX_DEPTH,
    QUESTION_TARGET_MAX_NODES, QuestionCompileError, QuestionError, QuestionOutcome,
    ResolutionError,
};
