/// The SHA-256 identity of one canonical closed Foundation statement.
///
/// This value is an address, not evidence that the statement has an admitted
/// proof. [`Self::from_bytes`] therefore does not establish validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct StatementId([u8; 32]);

impl StatementId {
    /// Exact width of one statement identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an identity from its raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The SHA-256 identity of one reference-transparent Foundation derivation.
///
/// This identity describes the checked inference DAG rather than its
/// certificate packaging. Inlining a checked dependency or citing that same
/// derivation therefore retains one identity. [`Self::from_bytes`] creates an
/// address only and does not establish that the derivation exists or is valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct DerivationId([u8; 32]);

impl DerivationId {
    /// Exact width of one derivation identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an identity from its raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The SHA-256 identity of one concrete checked Foundation proof artifact.
///
/// Unlike [`DerivationId`], this identity retains the canonical certificate's
/// citation boundaries and selected proof references. This value is an address,
/// not evidence that the referenced proof exists or was admitted.
/// [`Self::from_bytes`] therefore does not establish validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ProofId([u8; 32]);

impl ProofId {
    /// Exact width of one proof identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an identity from its raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The SHA-256 identity of one canonical conservative definition artifact.
///
/// This value is an address, not evidence that the definition exists or has
/// passed semantic checking against selected state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct DefinitionId([u8; 32]);

impl DefinitionId {
    /// Exact width of one definition identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an identity from its raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The SHA-256 address of one typed canonical proof or definition artifact.
///
/// Artifact identities deliberately hide the typed identity behind one
/// domain-separated address suitable for authenticated sets and blocks. The
/// canonical payload still carries the type needed for strict admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ArtifactId([u8; 32]);

impl ArtifactId {
    /// Exact width of one artifact identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an address from its raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives the artifact address for one exact checked proof identity.
    pub fn from_proof_id(proof_id: ProofId) -> Self {
        Self::from_typed_id(b"naome:artifact:proof:v0\0", proof_id.as_bytes())
    }

    /// Derives the artifact address for one exact checked definition identity.
    pub fn from_definition_id(definition_id: DefinitionId) -> Self {
        Self::from_typed_id(b"naome:artifact:definition:v1\0", definition_id.as_bytes())
    }

    fn from_typed_id(domain: &[u8], identity: &[u8; 32]) -> Self {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(identity);
        Self(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests;
