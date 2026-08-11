use std::error::Error;
use std::fmt;

use naome_ledger::PROOF_BATCH_MAX_CANDIDATES;
use naome_proof::ProofId;
use sha2::{Digest, Sha256};

use crate::ProofSetRoot;

const PROOF_TRANSITION_DOMAIN: &[u8] = b"naome:proof-transition\0";
const ROOT_BYTES: usize = 32;
const COUNT_BYTES: usize = 1;
const PROOF_ID_BYTES: usize = 32;
const PREFIX_BYTES: usize = ROOT_BYTES + ROOT_BYTES + COUNT_BYTES;

/// Maximum length of one canonical proof-state transition commitment.
pub const PROOF_TRANSITION_MAX_BYTES: usize =
    PREFIX_BYTES + PROOF_BATCH_MAX_CANDIDATES * PROOF_ID_BYTES;

/// The SHA-256 identity of one canonical proof-state transition commitment.
///
/// This value addresses only the transition bytes. It establishes neither
/// proof validity nor successful application to a selected state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ProofTransitionId([u8; 32]);

impl ProofTransitionId {
    /// Constructs a transition address from raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A canonical commitment to one bounded proof-set state transition.
///
/// Proof identities remain in exact dependency-first, root-last application
/// order. Construction and decoding validate only this bounded canonical
/// structure. Successful application performs state binding, proof checking,
/// root closure, and atomic registration.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ProofTransition {
    previous_proof_set_root: ProofSetRoot,
    resulting_proof_set_root: ProofSetRoot,
    proof_ids: Box<[ProofId]>,
}

impl ProofTransition {
    /// Constructs one structurally valid transition commitment.
    ///
    /// The supplied order is identity-bearing and is never sorted or
    /// normalized. Use [`crate::ProofDag::prepare_proof_transition`] to derive
    /// the resulting root from a local selected state.
    pub fn new(
        previous_proof_set_root: ProofSetRoot,
        resulting_proof_set_root: ProofSetRoot,
        proof_ids: Vec<ProofId>,
    ) -> Result<Self, ProofTransitionError> {
        validate_proof_ids(&proof_ids)?;
        Ok(Self::from_validated_parts(
            previous_proof_set_root,
            resulting_proof_set_root,
            proof_ids.into_boxed_slice(),
        ))
    }

    /// Decodes one complete canonical transition commitment.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProofTransitionError> {
        if bytes.len() > PROOF_TRANSITION_MAX_BYTES {
            return Err(ProofTransitionError::InputTooLong {
                actual: bytes.len(),
                maximum: PROOF_TRANSITION_MAX_BYTES,
            });
        }
        if bytes.len() < PREFIX_BYTES {
            return Err(ProofTransitionError::UnexpectedEnd);
        }

        let count = usize::from(bytes[ROOT_BYTES + ROOT_BYTES]);
        validate_count(count)?;
        let expected_length = PREFIX_BYTES + count * PROOF_ID_BYTES;
        if bytes.len() < expected_length {
            return Err(ProofTransitionError::UnexpectedEnd);
        }
        if bytes.len() > expected_length {
            return Err(ProofTransitionError::TrailingBytes {
                remaining: bytes.len() - expected_length,
            });
        }

        let previous_proof_set_root = ProofSetRoot::from_bytes(
            bytes[..ROOT_BYTES]
                .try_into()
                .expect("the checked previous-root slice has exactly 32 bytes"),
        );
        let resulting_proof_set_root = ProofSetRoot::from_bytes(
            bytes[ROOT_BYTES..ROOT_BYTES + ROOT_BYTES]
                .try_into()
                .expect("the checked resulting-root slice has exactly 32 bytes"),
        );
        let proof_ids = bytes[PREFIX_BYTES..]
            .chunks_exact(PROOF_ID_BYTES)
            .map(|bytes| {
                ProofId::from_bytes(
                    bytes
                        .try_into()
                        .expect("a canonical transition proof id has exactly 32 bytes"),
                )
            })
            .collect::<Vec<_>>();
        validate_proof_ids(&proof_ids)?;

        Ok(Self::from_validated_parts(
            previous_proof_set_root,
            resulting_proof_set_root,
            proof_ids.into_boxed_slice(),
        ))
    }

    /// Encodes this commitment in its sole canonical representation.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PREFIX_BYTES + self.proof_ids.len() * PROOF_ID_BYTES);
        bytes.extend_from_slice(self.previous_proof_set_root.as_bytes());
        bytes.extend_from_slice(self.resulting_proof_set_root.as_bytes());
        bytes.push(self.proof_ids.len() as u8);
        for proof_id in &self.proof_ids {
            bytes.extend_from_slice(proof_id.as_bytes());
        }
        bytes
    }

    /// Returns this transition's canonical content address.
    pub fn id(&self) -> ProofTransitionId {
        let mut hasher = Sha256::new();
        hasher.update(PROOF_TRANSITION_DOMAIN);
        hasher.update(self.previous_proof_set_root.as_bytes());
        hasher.update(self.resulting_proof_set_root.as_bytes());
        hasher.update([self.proof_ids.len() as u8]);
        for proof_id in &self.proof_ids {
            hasher.update(proof_id.as_bytes());
        }
        ProofTransitionId(hasher.finalize().into())
    }

    /// Returns the selected-state root required before application.
    pub const fn previous_proof_set_root(&self) -> ProofSetRoot {
        self.previous_proof_set_root
    }

    /// Returns the selected-state root committed after application.
    pub const fn resulting_proof_set_root(&self) -> ProofSetRoot {
        self.resulting_proof_set_root
    }

    /// Returns the exact dependency-first, root-last proof identities.
    pub fn proof_ids(&self) -> &[ProofId] {
        &self.proof_ids
    }

    /// Returns the final proof identity whose dependency closure is selected.
    pub fn root_proof_id(&self) -> ProofId {
        *self
            .proof_ids
            .last()
            .expect("validated proof transitions are nonempty")
    }

    pub(crate) fn from_validated_parts(
        previous_proof_set_root: ProofSetRoot,
        resulting_proof_set_root: ProofSetRoot,
        proof_ids: Box<[ProofId]>,
    ) -> Self {
        debug_assert!(validate_proof_ids(&proof_ids).is_ok());
        Self {
            previous_proof_set_root,
            resulting_proof_set_root,
            proof_ids,
        }
    }

    pub(crate) fn with_resulting_root(mut self, resulting_proof_set_root: ProofSetRoot) -> Self {
        self.resulting_proof_set_root = resulting_proof_set_root;
        self
    }
}

/// A malformed proof-state transition commitment or local preparation input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofTransitionError {
    /// The encoded commitment exceeds its deterministic byte limit.
    InputTooLong { actual: usize, maximum: usize },
    /// The encoded commitment ends before a required field is complete.
    UnexpectedEnd,
    /// A transition must select at least one proof.
    Empty,
    /// A transition selects more proofs than one atomic rooted batch permits.
    TooManyProofs { actual: usize, maximum: usize },
    /// A complete commitment is followed by additional bytes.
    TrailingBytes { remaining: usize },
    /// One exact proof identity occurs more than once.
    DuplicateProofId {
        first_index: usize,
        duplicate_index: usize,
        proof_id: ProofId,
    },
    /// A locally prepared transition includes an already-selected proof.
    AlreadySelectedProofId { index: usize, proof_id: ProofId },
}

impl fmt::Display for ProofTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "canonical proof transition has {actual} bytes; the limit is {maximum}"
            ),
            Self::UnexpectedEnd => {
                formatter.write_str("canonical proof transition ended unexpectedly")
            }
            Self::Empty => formatter.write_str("proof transition contains no proofs"),
            Self::TooManyProofs { actual, maximum } => write!(
                formatter,
                "proof transition contains {actual} proofs; the limit is {maximum}"
            ),
            Self::TrailingBytes { remaining } => write!(
                formatter,
                "canonical proof transition has {remaining} trailing bytes"
            ),
            Self::DuplicateProofId {
                first_index,
                duplicate_index,
                proof_id,
            } => write!(
                formatter,
                "proof transition id {proof_id:?} at index {duplicate_index} duplicates index {first_index}"
            ),
            Self::AlreadySelectedProofId { index, proof_id } => write!(
                formatter,
                "proof transition id {proof_id:?} at index {index} is already selected"
            ),
        }
    }
}

impl Error for ProofTransitionError {}

fn validate_count(count: usize) -> Result<(), ProofTransitionError> {
    if count == 0 {
        return Err(ProofTransitionError::Empty);
    }
    if count > PROOF_BATCH_MAX_CANDIDATES {
        return Err(ProofTransitionError::TooManyProofs {
            actual: count,
            maximum: PROOF_BATCH_MAX_CANDIDATES,
        });
    }
    Ok(())
}

fn validate_proof_ids(proof_ids: &[ProofId]) -> Result<(), ProofTransitionError> {
    validate_count(proof_ids.len())?;
    for (duplicate_index, proof_id) in proof_ids.iter().copied().enumerate() {
        if let Some(first_index) = proof_ids[..duplicate_index]
            .iter()
            .position(|candidate| *candidate == proof_id)
        {
            return Err(ProofTransitionError::DuplicateProofId {
                first_index,
                duplicate_index,
                proof_id,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
