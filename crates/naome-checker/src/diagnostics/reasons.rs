use super::{Digest, OperandRole, Outcome};
use naome_foundation::FormulaCodecError;
use naome_proof::{DefinedFormulaCodecError, DefinitionExpansionError};
use serde::Serialize;

/// The failed condition, with typed witnesses instead of prose interpretation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "code")]
pub enum Failure {
    #[serde(rename = "mp.expected_implication")]
    ExpectedImplication { operand: OperandRole },
    #[serde(rename = "mp.antecedent_mismatch")]
    AntecedentMismatch,
    #[serde(rename = "inference.input_not_proved")]
    InputNotProved {
        operand: OperandRole,
        reference: u64,
    },
    #[serde(rename = "reference.not_earlier")]
    ReferenceNotEarlier {
        operand: OperandRole,
        reference: u64,
    },
    #[serde(rename = "schema.role_collision")]
    RoleCollision {
        variable: u32,
        roles: Vec<OperandRole>,
    },
    #[serde(rename = "schema.parameter_role_collision")]
    ParameterRoleCollision {
        variable: u32,
        role: OperandRole,
        parameter: u32,
    },
    #[serde(rename = "schema.duplicate_parameter")]
    DuplicateParameter {
        variable: u32,
        first: u32,
        second: u32,
    },
    #[serde(rename = "schema.forbidden_predicate_variable")]
    ForbiddenPredicateVariable { variable: u32, role: OperandRole },
    #[serde(rename = "schema.undeclared_predicate_variable")]
    UndeclaredPredicateVariable { variable: u32 },
    #[serde(rename = "conclusion.open")]
    OpenConclusion,
    #[serde(rename = "reference.missing_proof")]
    MissingProof { proof_id: Digest },
    #[serde(rename = "definition.expansion")]
    Expansion { reason: ExpansionFailure },
    #[serde(rename = "formula.invalid")]
    Formula { reason: FormulaFailure },
    #[serde(rename = "checker.formula_work_limit")]
    FormulaWorkLimit { actual: usize, maximum: usize },
    #[serde(rename = "context.limit")]
    ContextLimit,
    #[serde(rename = "context.corrupt")]
    ContextCorrupt,
    #[serde(rename = "context.storage")]
    ContextStorage,
    #[serde(rename = "target.mismatch")]
    TargetMismatch,
    #[serde(rename = "program.manifest_mismatch")]
    ManifestMismatch {
        field: ClaimField,
        expected: ClaimValue,
        actual: ClaimValue,
    },
}
impl Failure {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ExpectedImplication { .. } => "mp.expected_implication",
            Self::AntecedentMismatch => "mp.antecedent_mismatch",
            Self::InputNotProved { .. } => "inference.input_not_proved",
            Self::ReferenceNotEarlier { .. } => "reference.not_earlier",
            Self::RoleCollision { .. } => "schema.role_collision",
            Self::ParameterRoleCollision { .. } => "schema.parameter_role_collision",
            Self::DuplicateParameter { .. } => "schema.duplicate_parameter",
            Self::ForbiddenPredicateVariable { .. } => "schema.forbidden_predicate_variable",
            Self::UndeclaredPredicateVariable { .. } => "schema.undeclared_predicate_variable",
            Self::OpenConclusion => "conclusion.open",
            Self::MissingProof { .. } => "reference.missing_proof",
            Self::Expansion { .. } => "definition.expansion",
            Self::Formula { .. } => "formula.invalid",
            Self::FormulaWorkLimit { .. } => "checker.formula_work_limit",
            Self::ContextLimit => "context.limit",
            Self::ContextCorrupt => "context.corrupt",
            Self::ContextStorage => "context.storage",
            Self::TargetMismatch => "target.mismatch",
            Self::ManifestMismatch { .. } => "program.manifest_mismatch",
        }
    }
    pub fn outcome(&self) -> Outcome {
        match self {
            Self::MissingProof { .. }
            | Self::Expansion {
                reason: ExpansionFailure::UnknownDefinition { .. },
            } => Outcome::MissingDependency,
            Self::ContextLimit | Self::FormulaWorkLimit { .. } => Outcome::LimitExceeded,
            Self::ContextCorrupt | Self::ContextStorage => Outcome::ContextFailure,
            Self::Formula { reason } if reason.is_limit() => Outcome::LimitExceeded,
            Self::Expansion { reason } if reason.is_limit() => Outcome::LimitExceeded,
            _ => Outcome::Invalid,
        }
    }
    pub fn operand(&self) -> Option<OperandRole> {
        match self {
            Self::ExpectedImplication { operand }
            | Self::InputNotProved { operand, .. }
            | Self::ReferenceNotEarlier { operand, .. } => Some(*operand),
            Self::ForbiddenPredicateVariable { .. } | Self::UndeclaredPredicateVariable { .. } => {
                Some(OperandRole::Predicate)
            }
            Self::DuplicateParameter { .. } | Self::ParameterRoleCollision { .. } => {
                Some(OperandRole::Parameter)
            }
            Self::OpenConclusion => Some(OperandRole::Conclusion),
            Self::MissingProof { .. } => Some(OperandRole::Proof),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimField {
    Commands,
    InputBytes,
    ProgramHash,
    StreamRoot,
    Statement,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ClaimValue {
    Count(u64),
    Digest(Digest),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FormulaFailure {
    ByteLimit { actual: usize, maximum: usize },
    NodeLimit { maximum: usize },
    DepthLimit { maximum: u32 },
    UnexpectedEnd,
    UnknownFormulaTag { tag: u8 },
    UnknownVariableTag { tag: u8 },
    DanglingBoundVariable { index: u32, binder_depth: u32 },
    TrailingBytes { remaining: usize },
    DefinitionArgumentLimit { actual: usize },
    UnexpandedDefinition { definition_id: Digest },
    Unsupported,
}
impl FormulaFailure {
    pub fn is_limit(&self) -> bool {
        matches!(
            self,
            Self::ByteLimit { .. }
                | Self::NodeLimit { .. }
                | Self::DepthLimit { .. }
                | Self::DefinitionArgumentLimit { .. }
        )
    }
}
impl From<&FormulaCodecError> for FormulaFailure {
    fn from(error: &FormulaCodecError) -> Self {
        match *error {
            FormulaCodecError::InputTooLong { actual, maximum } => {
                Self::ByteLimit { actual, maximum }
            }
            FormulaCodecError::NodeLimitExceeded { maximum } => Self::NodeLimit { maximum },
            FormulaCodecError::DepthLimitExceeded { maximum } => Self::DepthLimit { maximum },
            FormulaCodecError::UnexpectedEnd => Self::UnexpectedEnd,
            FormulaCodecError::UnknownFormulaTag(tag) => Self::UnknownFormulaTag { tag },
            FormulaCodecError::UnknownVariableTag(tag) => Self::UnknownVariableTag { tag },
            FormulaCodecError::DanglingBoundVariable {
                index,
                binder_depth,
            } => Self::DanglingBoundVariable {
                index,
                binder_depth,
            },
            FormulaCodecError::TrailingBytes { remaining } => Self::TrailingBytes { remaining },
            _ => Self::Unsupported,
        }
    }
}
impl From<&DefinedFormulaCodecError> for FormulaFailure {
    fn from(error: &DefinedFormulaCodecError) -> Self {
        match *error {
            DefinedFormulaCodecError::InputTooLong { actual, maximum } => {
                Self::ByteLimit { actual, maximum }
            }
            DefinedFormulaCodecError::NodeLimitExceeded { maximum } => Self::NodeLimit { maximum },
            DefinedFormulaCodecError::DepthLimitExceeded { maximum } => {
                Self::DepthLimit { maximum }
            }
            DefinedFormulaCodecError::TooManyDefinitionArguments { actual } => {
                Self::DefinitionArgumentLimit { actual }
            }
            DefinedFormulaCodecError::UnexpandedDefinition { definition_id } => {
                Self::UnexpandedDefinition {
                    definition_id: Digest(*definition_id.as_bytes()),
                }
            }
            DefinedFormulaCodecError::UnexpectedEnd => Self::UnexpectedEnd,
            DefinedFormulaCodecError::UnknownFormulaTag(tag) => Self::UnknownFormulaTag { tag },
            DefinedFormulaCodecError::UnknownVariableTag(tag) => Self::UnknownVariableTag { tag },
            DefinedFormulaCodecError::DanglingBoundVariable {
                index,
                binder_depth,
            } => Self::DanglingBoundVariable {
                index,
                binder_depth,
            },
            DefinedFormulaCodecError::TrailingBytes { remaining } => {
                Self::TrailingBytes { remaining }
            }
            DefinedFormulaCodecError::Primitive(ref error) => Self::from(error),
            _ => Self::Unsupported,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExpansionFailure {
    UnknownDefinition {
        definition_id: Digest,
    },
    ArityMismatch {
        definition_id: Digest,
        expected: usize,
        actual: usize,
    },
    CyclicDefinition {
        definition_id: Digest,
    },
    UndeclaredFormalVariable {
        identifier: u32,
    },
    NodeLimit {
        maximum: usize,
    },
    DepthLimit {
        maximum: u32,
    },
    Formula {
        reason: FormulaFailure,
    },
    Unsupported,
}
impl ExpansionFailure {
    pub fn is_limit(&self) -> bool {
        match self {
            Self::NodeLimit { .. } | Self::DepthLimit { .. } => true,
            Self::Formula { reason } => reason.is_limit(),
            _ => false,
        }
    }
}
impl From<&DefinitionExpansionError> for ExpansionFailure {
    fn from(error: &DefinitionExpansionError) -> Self {
        match *error {
            DefinitionExpansionError::UnknownDefinition { definition_id } => {
                Self::UnknownDefinition {
                    definition_id: Digest(*definition_id.as_bytes()),
                }
            }
            DefinitionExpansionError::ArityMismatch {
                definition_id,
                expected,
                actual,
            } => Self::ArityMismatch {
                definition_id: Digest(*definition_id.as_bytes()),
                expected,
                actual,
            },
            DefinitionExpansionError::CyclicDefinition { definition_id } => {
                Self::CyclicDefinition {
                    definition_id: Digest(*definition_id.as_bytes()),
                }
            }
            DefinitionExpansionError::UndeclaredFormalVariable { identifier } => {
                Self::UndeclaredFormalVariable { identifier }
            }
            DefinitionExpansionError::NodeLimitExceeded { maximum } => Self::NodeLimit { maximum },
            DefinitionExpansionError::DepthLimitExceeded { maximum } => {
                Self::DepthLimit { maximum }
            }
            DefinitionExpansionError::Formula(ref reason) => Self::Formula {
                reason: reason.into(),
            },
            _ => Self::Unsupported,
        }
    }
}
