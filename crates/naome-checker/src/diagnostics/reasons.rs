use super::{Digest, OperandRole, Outcome};
use naome_foundation::FormulaCodecError;
use naome_proof::{DefinedFormulaCodecError, DefinitionExpansionError};
use serde::Serialize;

// One table owns each diagnosis code, its typed fields and the offline catalog.
macro_rules! diagnostic_failures {
    (
        structured { $( $name:ident = $code:literal { $( $field:ident: $ty:ty ),+ $(,)? } ),+ $(,)? }
        units { $( $unit:ident = $unit_code:literal ),+ $(,)? }
    ) => {
        /// The failed condition, with typed witnesses instead of prose interpretation.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum Failure {
            $( $name { $( $field: $ty ),+ }, )+
            $( $unit, )+
        }
        impl Failure {
            /// Stable machine code of this condition.
            pub fn code(&self) -> u32 {
                match self {
                    $( Self::$name { .. } => $code, )+
                    $( Self::$unit => $unit_code, )+
                }
            }
        }
        impl serde::Serialize for Failure {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeStruct;
                match self {
                    $( Self::$name { $( $field ),+ } => {
                        let mut value = serializer.serialize_struct("Failure", 1 $(+ { let _ = stringify!($field); 1 })+)?;
                        value.serialize_field("code", &$code)?;
                        $( value.serialize_field(stringify!($field), $field)?; )+
                        value.end()
                    }, )+
                    $( Self::$unit => {
                        let mut value = serializer.serialize_struct("Failure", 1)?;
                        value.serialize_field("code", &$unit_code)?;
                        value.end()
                    }, )+
                }
            }
        }
        /// Assigned checker diagnostic failures for the machine catalog.
        pub const DIAGNOSTIC_FAILURE_CODES: &[(&str, &str, u32)] = &[
            $( ("ProofFailure", stringify!($name), $code), )+
            $( ("ProofFailure", stringify!($unit), $unit_code), )+
        ];
    };
}

diagnostic_failures! {
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
