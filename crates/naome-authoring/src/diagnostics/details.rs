use super::*;
use naome_checker::diagnostics::{ExpansionFailure, FormulaFailure};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CompileDetails {
    Syntax {
        expected: &'static str,
    },
    Name {
        name_preview: String,
        name_digest: Digest,
    },
    Limit {
        resource: &'static str,
        actual: Option<usize>,
        maximum: usize,
    },
    ReturnNotFinal,
    ExpectedProof,
    Formula {
        reason: FormulaFailure,
    },
    Format {
        reason: FormatFailure,
    },
    DefinitionNotSelected {
        definition_id: Digest,
    },
    DefinitionArity {
        name_preview: String,
        expected: u32,
        actual: usize,
    },
    DefinitionExpansion {
        reason: ExpansionFailure,
    },
    DefinitionCheck {
        reason: DefinitionFailure,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FormatFailure {
    EmptyCertificate,
    Limit {
        resource: &'static str,
        actual: Option<u64>,
        maximum: u64,
    },
    ReferenceNotEarlier {
        step: u32,
        reference: u32,
    },
    UnexpectedEnd,
    UnknownTag {
        domain: &'static str,
        tag: u8,
    },
    Formula {
        reason: FormulaFailure,
    },
    TrailingBytes {
        remaining: usize,
    },
    ZeroArity {
        definition_kind: &'static str,
    },
    DefinitionReference {
        definition_id: Digest,
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
impl From<&ProofCertificateError> for FormatFailure {
    fn from(error: &ProofCertificateError) -> Self {
        match *error {
            ProofCertificateError::EmptyCertificate => Self::EmptyCertificate,
            ProofCertificateError::TooManySteps { actual, maximum } => Self::Limit {
                resource: "steps",
                actual: Some(actual as u64),
                maximum: maximum as u64,
            },
            ProofCertificateError::InputTooLong { actual, maximum } => Self::Limit {
                resource: "bytes",
                actual: Some(actual as u64),
                maximum: maximum as u64,
            },
            ProofCertificateError::FormulaNodeLimitExceeded { maximum } => Self::Limit {
                resource: "nodes",
                actual: None,
                maximum: maximum as u64,
            },
            ProofCertificateError::ReferenceNotEarlier { step, reference } => {
                Self::ReferenceNotEarlier { step, reference }
            }
            ProofCertificateError::UnexpectedEnd => Self::UnexpectedEnd,
            ProofCertificateError::UnknownStepTag(tag) => Self::UnknownTag {
                domain: "proof_step",
                tag,
            },
            ProofCertificateError::UnknownZfcAxiomTag(tag) => Self::UnknownTag {
                domain: "zfc_axiom",
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
impl From<&DefinitionCertificateError> for FormatFailure {
    fn from(error: &DefinitionCertificateError) -> Self {
        match *error {
            DefinitionCertificateError::InputTooLong { actual, maximum } => Self::Limit {
                resource: "bytes",
                actual: Some(actual as u64),
                maximum: maximum as u64,
            },
            DefinitionCertificateError::UnexpectedEnd => Self::UnexpectedEnd,
            DefinitionCertificateError::UnknownKindTag(tag) => Self::UnknownTag {
                domain: "definition_kind",
                tag,
            },
            DefinitionCertificateError::ZeroRelationArity => Self::ZeroArity {
                definition_kind: "relation",
            },
            DefinitionCertificateError::ZeroFunctionArity => Self::ZeroArity {
                definition_kind: "function",
            },
            DefinitionCertificateError::ArityTooLarge { actual, maximum } => Self::Limit {
                resource: "arity",
                actual: Some(actual),
                maximum: u64::from(maximum),
            },
            DefinitionCertificateError::DefinitionReference { definition_id } => {
                Self::DefinitionReference {
                    definition_id: Digest(*definition_id.as_bytes()),
                }
            }
            DefinitionCertificateError::UndeclaredFormalVariable { identifier, arity } => {
                Self::UndeclaredFormalVariable { identifier, arity }
            }
            DefinitionCertificateError::MissingFormalVariable { identifier, arity } => {
                Self::MissingFormalVariable { identifier, arity }
            }
            DefinitionCertificateError::Formula(ref reason) => Self::Formula {
                reason: reason.into(),
            },
            DefinitionCertificateError::TrailingBytes { remaining } => {
                Self::TrailingBytes { remaining }
            }
            _ => Self::Unsupported,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DefinitionFailure {
    ContextLimit,
    ContextCorrupt,
    ContextStorage,
    Expansion { reason: ExpansionFailure },
    Formula { reason: FormulaFailure },
    Certificate { reason: FormatFailure },
    MissingObligation { statement_id: Digest },
    ObligationMismatch { statement_id: Digest },
    Unsupported,
}
impl From<&DefinitionCheckError> for DefinitionFailure {
    fn from(error: &DefinitionCheckError) -> Self {
        match error {
            DefinitionCheckError::ContextAccess(error) => match error {
                naome_checker::ContextError::Limit => Self::ContextLimit,
                naome_checker::ContextError::Corrupt => Self::ContextCorrupt,
                naome_checker::ContextError::Storage(_) => Self::ContextStorage,
            },
            DefinitionCheckError::Expansion(reason) => Self::Expansion {
                reason: reason.into(),
            },
            DefinitionCheckError::CanonicalBody(reason) => Self::Formula {
                reason: reason.into(),
            },
            DefinitionCheckError::Certificate(reason) => Self::Certificate {
                reason: reason.into(),
            },
            DefinitionCheckError::UnknownObligationStatement { statement_id } => {
                Self::MissingObligation {
                    statement_id: Digest(*statement_id.as_bytes()),
                }
            }
            DefinitionCheckError::ObligationConclusionMismatch { statement_id } => {
                Self::ObligationMismatch {
                    statement_id: Digest(*statement_id.as_bytes()),
                }
            }
            DefinitionCheckError::ObligationFormula(reason) => Self::Formula {
                reason: reason.into(),
            },
            _ => Self::Unsupported,
        }
    }
}

pub(super) fn from_error(error: &CompileErrorKind) -> Option<CompileDetails> {
    use CompileDetails as D;
    Some(match error {
        CompileErrorKind::SourceTooLong { actual, maximum } => D::Limit {
            resource: "source_bytes",
            actual: Some(*actual),
            maximum: *maximum,
        },
        CompileErrorKind::Syntax { expected, .. } => D::Syntax { expected },
        CompileErrorKind::DuplicateStep { name, .. }
        | CompileErrorKind::UnknownStep { name, .. }
        | CompileErrorKind::DuplicateFormulaBinding { name, .. }
        | CompileErrorKind::UnknownFormulaBinding { name, .. }
        | CompileErrorKind::DuplicateDefinitionAlias { name, .. }
        | CompileErrorKind::UnknownDefinitionAlias { name, .. }
        | CompileErrorKind::DuplicateProofReference { name, .. }
        | CompileErrorKind::UnknownProofReference { name, .. } => D::Name {
            name_preview: diagnostic_name(name).to_string(),
            name_digest: Digest::of(name.as_bytes()),
        },
        CompileErrorKind::ReturnNotFinal { .. } => D::ReturnNotFinal,
        CompileErrorKind::ExpectedProof { .. } => D::ExpectedProof,
        CompileErrorKind::FormulaDepthLimitExceeded { maximum, .. } => D::Limit {
            resource: "formula_depth",
            actual: None,
            maximum: *maximum as usize,
        },
        CompileErrorKind::FormulaBindingNodeLimitExceeded { maximum, .. } => D::Limit {
            resource: "formula_binding_nodes",
            actual: None,
            maximum: *maximum,
        },
        CompileErrorKind::Statement { source, .. } => D::Formula {
            reason: source.into(),
        },
        CompileErrorKind::Certificate { source, .. } => D::Format {
            reason: source.into(),
        },
        CompileErrorKind::Definition { source, .. } => D::Format {
            reason: source.into(),
        },
        CompileErrorKind::DefinitionNotSelected { definition_id, .. } => D::DefinitionNotSelected {
            definition_id: Digest(*definition_id.as_bytes()),
        },
        CompileErrorKind::DefinitionArityMismatch {
            name,
            expected,
            actual,
            ..
        } => D::DefinitionArity {
            name_preview: diagnostic_name(name).to_string(),
            expected: *expected,
            actual: *actual,
        },
        CompileErrorKind::DefinitionFormula { source, .. } => D::Formula {
            reason: source.into(),
        },
        CompileErrorKind::DefinitionExpansion { source, .. } => D::DefinitionExpansion {
            reason: source.into(),
        },
        CompileErrorKind::DefinitionCheck { source, .. } => D::DefinitionCheck {
            reason: source.as_ref().into(),
        },
        CompileErrorKind::Check { .. } | CompileErrorKind::StatementMismatch { .. } => return None,
    })
}
