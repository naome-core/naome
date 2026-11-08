//! Machine-readable failures of canonical proof program input and streaming.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CodecFailure {
    Truncated = 1,
    IntegerOverflow = 2,
    NoncanonicalInteger = 3,
    TermWidth = 4,
    FreeTermWidth = 5,
    DefinitionArguments = 6,
    ScopedOperands = 7,
    AxiomTag = 8,
    MissingAssumption = 9,
    ScopedOpcode = 10,
    BinderWidth = 11,
    Opcode = 12,
    CommandBytes = 13,
    TrailingCommandBytes = 14,
    InvalidManifest = 15,
    ManifestBytes = 16,
    TrailingManifestBytes = 17,
    ChunkRecords = 18,
    ChunkBytes = 19,
    AddressOverflow = 20,
    ByteWidth = 21,
    ChunkRequest = 22,
    RecordExtent = 23,
    ChunkBudget = 24,
    InputHash = 25,
    MissingPrefix = 26,
    ManifestBinding = 27,
    ChunkWidth = 28,
    ChunkBinding = 29,
    ChunkCursor = 30,
    ChunkEnd = 31,
    EarlySeal = 32,
    PrefixLimit = 33,
    GraphDomain = 34,
    GraphNodeWidth = 35,
    GraphChildWidth = 36,
    GraphVariableWidth = 37,
    GraphVariableTag = 38,
    GraphNodeTag = 39,
    GraphPropertyFlag = 40,
    GraphNoncanonical = 41,
    GraphPropertyWidth = 42,
}

impl std::fmt::Display for CodecFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "truncated program input",
            Self::IntegerOverflow => "program integer overflow",
            Self::NoncanonicalInteger => "noncanonical program integer",
            Self::TermWidth => "program term width",
            Self::FreeTermWidth => "free term width",
            Self::DefinitionArguments => "program definition argument capacity",
            Self::ScopedOperands => "scoped program operand capacity",
            Self::AxiomTag => "program axiom tag",
            Self::MissingAssumption => "deduction requires an assumption",
            Self::ScopedOpcode => "unknown scoped program opcode",
            Self::BinderWidth => "program binder width",
            Self::Opcode => "unknown program opcode",
            Self::CommandBytes => "program command byte capacity",
            Self::TrailingCommandBytes => "trailing program command bytes",
            Self::InvalidManifest => "invalid program manifest",
            Self::ManifestBytes => "program manifest byte capacity",
            Self::TrailingManifestBytes => "trailing program manifest bytes",
            Self::ChunkRecords => "program chunk record capacity",
            Self::ChunkBytes => "program chunk byte capacity",
            Self::AddressOverflow => "program address exhausted",
            Self::ByteWidth => "program byte width",
            Self::ChunkRequest => "program chunk request capacity",
            Self::RecordExtent => "program record order or width differs",
            Self::ChunkBudget => "program record exceeds chunk budget",
            Self::InputHash => "program input hash mismatch",
            Self::MissingPrefix => "program input prefix missing",
            Self::ManifestBinding => "program input is incomplete or differs from manifest",
            Self::ChunkWidth => "program chunk width",
            Self::ChunkBinding => "program chunk authentication or prefix mismatch",
            Self::ChunkCursor => "program chunk cursor width",
            Self::ChunkEnd => "program chunk end mismatch",
            Self::EarlySeal => "program seal precedes declared end",
            Self::PrefixLimit => "program prefix exceeds manifest",
            Self::GraphDomain => "formula node domain",
            Self::GraphNodeWidth => "formula node width",
            Self::GraphChildWidth => "formula child width",
            Self::GraphVariableWidth => "formula variable width",
            Self::GraphVariableTag => "formula variable tag",
            Self::GraphNodeTag => "formula node tag",
            Self::GraphPropertyFlag => "formula property flag",
            Self::GraphNoncanonical => "noncanonical formula node",
            Self::GraphPropertyWidth => "formula property width",
        })
    }
}

impl std::error::Error for CodecFailure {}

impl From<CodecFailure> for String {
    fn from(error: CodecFailure) -> Self {
        error.to_string()
    }
}
