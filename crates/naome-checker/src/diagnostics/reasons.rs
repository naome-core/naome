use super::{Digest, OperandRole, Outcome};
use naome_foundation::FormulaCodecError;
use naome_proof::{DefinedFormulaCodecError, DefinitionExpansionError};
use serde::Serialize;

diagnostic_codes! {
    /// The failed condition, with typed witnesses instead of prose interpretation.
    Failure, DIAGNOSTIC_FAILURE_CODES, "ProofFailure",
    structured {
        ExpectedImplication = 0x0025_0001 { operand: OperandRole },
        ExpectedUniversal = 0x0025_0002 { operand: OperandRole },
        InputNotProved = 0x0025_0004 { operand: OperandRole, reference: u64 },
        ReferenceNotEarlier = 0x0025_0005 { operand: OperandRole, reference: u64 },
        RoleCollision = 0x0025_0006 { variable: u32, roles: Vec<OperandRole> },
        ParameterRoleCollision = 0x0025_0007 { variable: u32, role: OperandRole, parameter: u32 },
        DuplicateParameter = 0x0025_0008 { variable: u32, first: u32, second: u32 },
        ForbiddenPredicateVariable = 0x0025_0009 { variable: u32, role: OperandRole },
        UndeclaredPredicateVariable = 0x0025_000a { variable: u32 },
        MissingProof = 0x0025_000c { proof_id: Digest },
        Expansion = 0x0025_000d { reason: ExpansionFailure },
        Formula = 0x0025_000e { reason: FormulaFailure },
        FormulaWorkLimit = 0x0025_000f { actual: usize, maximum: usize },
        ManifestMismatch = 0x0025_0014 { field: ClaimField, expected: ClaimValue, actual: ClaimValue },
    }
    units {
        AntecedentMismatch = 0x0025_0003,
        OpenConclusion = 0x0025_000b,
        ContextLimit = 0x0025_0010,
        ContextCorrupt = 0x0025_0011,
        ContextStorage = 0x0025_0012,
        TargetMismatch = 0x0025_0013,
    }
}

impl Failure {
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
            | Self::ExpectedUniversal { operand }
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

diagnostic_units! {
    ClaimField, CLAIM_FIELD_CODES, "ClaimField", 49 {
        Commands = 1,
        InputBytes = 2,
        ProgramHash = 3,
        StreamRoot = 4,
        Statement = 5,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimValue {
    Count(u64),
    Digest(Digest),
}
impl Serialize for ClaimValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct("ClaimValue", 2)?;
        match self {
            Self::Count(count) => {
                value.serialize_field("code", &0x0032_0001_u32)?;
                value.serialize_field("value", count)?;
            }
            Self::Digest(digest) => {
                value.serialize_field("code", &0x0032_0002_u32)?;
                value.serialize_field("value", digest)?;
            }
        }
        value.end()
    }
}
/// Assigned claim value classes for the machine catalog.
pub const CLAIM_VALUE_CODES: &[(&str, &str, u32)] = &[
    ("ClaimValue", "Count", 0x0032_0001),
    ("ClaimValue", "Digest", 0x0032_0002),
];

diagnostic_codes! {
    FormulaFailure, FORMULA_FAILURE_CODES, "FormulaFailure",
    structured {
        ByteLimit = 0x0028_0001 { actual: usize, maximum: usize },
        NodeLimit = 0x0028_0002 { maximum: usize },
        DepthLimit = 0x0028_0003 { maximum: u32 },
        UnknownFormulaTag = 0x0028_0005 { tag: u8 },
        UnknownVariableTag = 0x0028_0006 { tag: u8 },
        DanglingBoundVariable = 0x0028_0007 { index: u32, binder_depth: u32 },
        TrailingBytes = 0x0028_0008 { remaining: usize },
        DefinitionArgumentLimit = 0x0028_0009 { actual: usize },
        UnexpandedDefinition = 0x0028_000a { definition_id: Digest },
        GraphDanglingBinder = 0x0028_000c { index: u64, binder_depth: u32 },
    }
    units {
        UnexpectedEnd = 0x0028_0004,
        Unsupported = 0x0028_000b,
    }
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
            DefinedFormulaCodecError::Graph(ref error) => match *error {
                naome_foundation::graph::MaterializationError::DepthLimit { maximum } => {
                    Self::DepthLimit { maximum }
                }
                naome_foundation::graph::MaterializationError::NodeLimit { maximum } => {
                    Self::NodeLimit { maximum }
                }
                naome_foundation::graph::MaterializationError::DanglingBinder {
                    index,
                    binder_depth,
                } => Self::GraphDanglingBinder {
                    index,
                    binder_depth,
                },
                naome_foundation::graph::MaterializationError::Read(never) => match never {},
            },
            _ => Self::Unsupported,
        }
    }
}

diagnostic_codes! {
    ExpansionFailure, EXPANSION_FAILURE_CODES, "ExpansionFailure",
    structured {
        UnknownDefinition = 0x0029_0001 { definition_id: Digest },
        ArityMismatch = 0x0029_0002 { definition_id: Digest, expected: usize, actual: usize },
        CyclicDefinition = 0x0029_0003 { definition_id: Digest },
        UndeclaredFormalVariable = 0x0029_0004 { identifier: u32 },
        NodeLimit = 0x0029_0005 { maximum: usize },
        DepthLimit = 0x0029_0006 { maximum: u32 },
        Formula = 0x0029_0007 { reason: FormulaFailure },
    }
    units { Unsupported = 0x0029_0008 }
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
