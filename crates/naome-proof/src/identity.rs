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

#[cfg(test)]
mod tests;
