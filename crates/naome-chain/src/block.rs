use std::error::Error;
use std::fmt;

use naome_ledger::{AcceptedProofRecord, AddressedProofCandidate};
use naome_proof::ProofId;
use sha2::{Digest, Sha256};

use crate::{
    PROOF_TRANSITION_MAX_BYTES, ProofDag, ProofTransition, ProofTransitionApplyError,
    ProofTransitionError,
};

const PROOF_CHAIN_GENESIS_DOMAIN: &[u8] = b"naome:proof-chain-genesis\0";
const PROOF_BLOCK_DOMAIN: &[u8] = b"naome:proof-block\0";
const BLOCK_ID_BYTES: usize = 32;

/// Maximum length of one canonical linear proof block.
pub const PROOF_BLOCK_MAX_BYTES: usize = BLOCK_ID_BYTES + PROOF_TRANSITION_MAX_BYTES;

/// An externally configured identifier for one linear proof-chain context.
///
/// The identifier derives the virtual genesis parent. It is context, not an
/// address of canonical content, an authorization token, or consensus proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ProofChainId([u8; 32]);

impl ProofChainId {
    /// Constructs a chain-context identifier from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw chain-context bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn genesis_parent_block_id(self) -> ProofBlockId {
        let mut hasher = Sha256::new();
        hasher.update(PROOF_CHAIN_GENESIS_DOMAIN);
        hasher.update(self.as_bytes());
        ProofBlockId(hasher.finalize().into())
    }
}

/// A 32-byte address in one canonical linear proof-block ancestry.
///
/// [`ProofBlock::id`] addresses canonical block bytes. A chain state's initial
/// value instead addresses its separately domain-separated virtual genesis
/// parent. Neither form establishes proof validity, consensus selection,
/// finality, or data availability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ProofBlockId([u8; 32]);

impl ProofBlockId {
    /// Constructs a block address from raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One canonical parent-linked proof-state transition.
///
/// The parent is always present. The first block points to the virtual genesis
/// parent derived from the chain context; later blocks point to the exact
/// preceding [`ProofBlockId`]. Proof payloads remain separately supplied,
/// content-addressed candidates and are not duplicated in this commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ProofBlock {
    parent_block_id: ProofBlockId,
    transition: ProofTransition,
}

impl ProofBlock {
    /// Constructs one block from an exact parent and canonical transition.
    pub const fn new(parent_block_id: ProofBlockId, transition: ProofTransition) -> Self {
        Self {
            parent_block_id,
            transition,
        }
    }

    /// Decodes one complete canonical proof block.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProofBlockDecodeError> {
        if bytes.len() > PROOF_BLOCK_MAX_BYTES {
            return Err(ProofBlockDecodeError::InputTooLong {
                actual: bytes.len(),
                maximum: PROOF_BLOCK_MAX_BYTES,
            });
        }
        if bytes.len() < BLOCK_ID_BYTES {
            return Err(ProofBlockDecodeError::UnexpectedEnd);
        }

        let parent_block_id = ProofBlockId::from_bytes(
            bytes[..BLOCK_ID_BYTES]
                .try_into()
                .expect("the checked parent block-id slice has exactly 32 bytes"),
        );
        let transition = ProofTransition::from_canonical_bytes(&bytes[BLOCK_ID_BYTES..])
            .map_err(|source| ProofBlockDecodeError::Transition { source })?;

        Ok(Self::new(parent_block_id, transition))
    }

    /// Encodes this block in its sole canonical representation.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BLOCK_ID_BYTES + self.transition.canonical_byte_len());
        bytes.extend_from_slice(self.parent_block_id.as_bytes());
        self.transition.append_canonical_bytes(&mut bytes);
        bytes
    }

    /// Returns this block's canonical content address.
    pub fn id(&self) -> ProofBlockId {
        let mut hasher = Sha256::new();
        hasher.update(PROOF_BLOCK_DOMAIN);
        hasher.update(self.parent_block_id.as_bytes());
        self.transition.update_canonical_hasher(&mut hasher);
        ProofBlockId(hasher.finalize().into())
    }

    /// Returns the exact parent block or virtual genesis address.
    pub const fn parent_block_id(&self) -> ProofBlockId {
        self.parent_block_id
    }

    /// Returns the committed proof-state transition.
    pub const fn transition(&self) -> &ProofTransition {
        &self.transition
    }
}

/// A malformed canonical linear proof block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofBlockDecodeError {
    /// The encoded block exceeds its deterministic byte limit.
    InputTooLong { actual: usize, maximum: usize },
    /// The encoded block ends before its complete parent address.
    UnexpectedEnd,
    /// The embedded canonical transition is malformed.
    Transition { source: ProofTransitionError },
}

impl fmt::Display for ProofBlockDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "canonical proof block has {actual} bytes; the limit is {maximum}"
            ),
            Self::UnexpectedEnd => formatter.write_str("canonical proof block ended unexpectedly"),
            Self::Transition { source } => {
                write!(
                    formatter,
                    "canonical proof block transition is invalid: {source}"
                )
            }
        }
    }
}

impl Error for ProofBlockDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transition { source } => Some(source),
            _ => None,
        }
    }
}

/// An in-memory exact-tip execution chain for canonical proof blocks.
///
/// The selected [`ProofDag`] is privately owned so its authenticated state and
/// the linear block head cannot diverge. The initial head is a virtual genesis
/// parent derived from [`ProofChainId`], not an admitted block.
#[must_use]
pub struct ProofChainState {
    head_block_id: ProofBlockId,
    proof_dag: ProofDag,
}

impl ProofChainState {
    /// Constructs an empty chain at its domain-separated virtual genesis head.
    pub fn new(chain_id: ProofChainId) -> Self {
        Self {
            head_block_id: chain_id.genesis_parent_block_id(),
            proof_dag: ProofDag::new(),
        }
    }

    /// Returns the exact head expected as the next block's parent.
    ///
    /// Before the first block, this is the virtual genesis parent and does not
    /// address an admitted block.
    pub const fn head_block_id(&self) -> ProofBlockId {
        self.head_block_id
    }

    /// Returns read-only access to the selected proof DAG.
    pub const fn proof_dag(&self) -> &ProofDag {
        &self.proof_dag
    }

    /// Prepares one block against the exact current head and proof state.
    ///
    /// Preparation is read-only. Proof identities remain in the exact
    /// dependency-first, root-last order supplied to transition preparation.
    pub fn prepare_block(
        &self,
        proof_ids: Vec<ProofId>,
    ) -> Result<ProofBlock, ProofTransitionError> {
        let transition = self.proof_dag.prepare_proof_transition(proof_ids)?;
        Ok(ProofBlock::new(self.head_block_id, transition))
    }

    /// Atomically applies one exact-head canonical proof block.
    ///
    /// Parent binding precedes all transition and proof work. After the
    /// existing atomic transition commits, only an infallible head assignment
    /// remains. Every error therefore preserves both linear and selected state.
    pub fn apply_block(
        &mut self,
        block: &ProofBlock,
        candidates: Vec<AddressedProofCandidate>,
    ) -> Result<&AcceptedProofRecord, ProofBlockApplyError> {
        if block.parent_block_id() != self.head_block_id {
            return Err(ProofBlockApplyError::ParentBlockIdMismatch {
                expected: self.head_block_id,
                actual: block.parent_block_id(),
            });
        }

        let next_head = block.id();
        let record = self
            .proof_dag
            .apply_proof_transition(block.transition(), candidates)
            .map_err(|source| ProofBlockApplyError::Transition { source })?;
        self.head_block_id = next_head;
        Ok(record)
    }
}

/// A fail-closed linear proof-block application error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofBlockApplyError {
    /// The block does not extend the chain's exact current head.
    ParentBlockIdMismatch {
        expected: ProofBlockId,
        actual: ProofBlockId,
    },
    /// The embedded transition failed before the linear head changed.
    Transition { source: ProofTransitionApplyError },
}

impl fmt::Display for ProofBlockApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParentBlockIdMismatch { expected, actual } => write!(
                formatter,
                "proof block parent mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::Transition { source } => {
                write!(formatter, "proof block transition failed: {source}")
            }
        }
    }
}

impl Error for ProofBlockApplyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transition { source } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
