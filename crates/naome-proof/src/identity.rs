/// The SHA-256 identity of one canonical closed Foundation V0 statement.
///
/// This value is an address, not evidence that the statement has an admitted
/// proof. [`Self::from_bytes`] therefore does not establish validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct StatementId([u8; 32]);

impl StatementId {
    /// Constructs an identity from its raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The SHA-256 identity of one checked Foundation V0 statement and proof normal form.
///
/// This value is an address, not evidence that the referenced proof exists or
/// was admitted. [`Self::from_bytes`] therefore does not establish validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ProofId([u8; 32]);

impl ProofId {
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
mod tests {
    use super::{ProofId, StatementId};

    #[test]
    fn identity_bytes_round_trip_without_claiming_validity() {
        let statement_bytes = [0x11; 32];
        let proof_bytes = [0x22; 32];

        assert_eq!(
            StatementId::from_bytes(statement_bytes).as_bytes(),
            &statement_bytes
        );
        assert_eq!(ProofId::from_bytes(proof_bytes).as_bytes(), &proof_bytes);
    }
}
