use sha2::{Digest, Sha256};

macro_rules! identity {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);
        impl $name {
            /// Constructs an address only, without asserting validity.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// Returns the raw digest in canonical byte order.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

identity!(GenesisId, "Identity of one immutable research test run.");
identity!(ProfileId, "Identity of all immutable research parameters.");
identity!(
    AccountId,
    "Role-separated address of a registered research account key."
);
identity!(
    ValidatorId,
    "Role-separated address of a fixed validator consensus key."
);
identity!(
    ResolutionId,
    "Foundation and canonical core identity, independent of orientation."
);
identity!(
    QuestionId,
    "Identity of the exact opened question and approved context."
);
identity!(
    SolutionRoundId,
    "Identity of one approved commitment and reveal attempt."
);
identity!(
    RecordId,
    "Identity of complete research record content, excluding finality signatures."
);
identity!(
    StateCommitment,
    "Commitment to the entire canonical research state."
);
identity!(OperationId, "Identity of one authenticated user operation.");
identity!(
    CommitmentId,
    "Identity of an original package commitment and its secret."
);
identity!(
    PackageHash,
    "Commitment to exact original proof-package bytes."
);

/// Hashes a role domain and unambiguous u64-length-prefixed fields.
pub(crate) fn hash(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

impl AccountId {
    /// Derives the research-account address; registration is checked separately.
    pub fn for_key(key: &[u8; 32]) -> Self {
        Self(hash(b"naome:state:account:v1\0", &[key]))
    }
}

impl ValidatorId {
    /// Derives the validator address; membership is checked separately.
    pub fn for_key(key: &[u8; 32]) -> Self {
        Self(hash(b"naome:state:validator:v1\0", &[key]))
    }
}
