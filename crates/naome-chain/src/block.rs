use std::error::Error;
use std::fmt;

use naome_foundation::FOUNDATION_ID;
use naome_ledger::{AcceptedProofRecord, AddressedProofCandidate, ProofState};
use naome_proof::ProofId;
use sha2::{Digest, Sha256};

use crate::{
    PROOF_TRANSITION_MAX_BYTES, ProofDag, ProofSetRoot, ProofTransition, ProofTransitionApplyError,
    ProofTransitionError,
};

const PROOF_CHAIN_GENESIS_DOMAIN: &[u8] = b"naome:proof-chain-genesis\0";
const PROOF_CHAIN_DEFINITION_DOMAIN: &[u8] = b"naome:proof-chain-definition\0";
const PROOF_BLOCK_DOMAIN: &[u8] = b"naome:proof-block\0";
const BLOCK_ID_BYTES: usize = ProofBlockId::BYTE_LENGTH;
const DEPLOYMENT_DISCRIMINATOR_BYTES: usize = 32;
const FOUNDATION_ID_BYTES: usize = FOUNDATION_ID.len();
const GENESIS_PROOF_SET_ROOT_BYTES: usize = ProofSetRoot::BYTE_LENGTH;

/// Maximum length of one canonical linear proof block.
pub const PROOF_BLOCK_MAX_BYTES: usize = BLOCK_ID_BYTES + PROOF_TRANSITION_MAX_BYTES;

/// The canonical executable context from which one proof chain is derived.
///
/// The caller supplies only a deployment discriminator. Canonical bytes also
/// bind the exact compiled Foundation identity and empty authenticated proof-
/// set root, so unsupported genesis semantics cannot be injected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ProofChainDefinition {
    deployment_discriminator: [u8; DEPLOYMENT_DISCRIMINATOR_BYTES],
}

impl ProofChainDefinition {
    /// Exact byte length of one canonical proof-chain definition.
    pub const BYTE_LENGTH: usize =
        DEPLOYMENT_DISCRIMINATOR_BYTES + FOUNDATION_ID_BYTES + GENESIS_PROOF_SET_ROOT_BYTES;

    /// Constructs the current executable definition for one deployment.
    pub const fn new(deployment_discriminator: [u8; DEPLOYMENT_DISCRIMINATOR_BYTES]) -> Self {
        Self {
            deployment_discriminator,
        }
    }

    /// Returns the caller-selected deployment discriminator.
    pub const fn deployment_discriminator(&self) -> &[u8; DEPLOYMENT_DISCRIMINATOR_BYTES] {
        &self.deployment_discriminator
    }

    /// Decodes one complete canonical proof-chain definition.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProofChainDefinitionDecodeError> {
        let bytes = <&[u8; Self::BYTE_LENGTH]>::try_from(bytes).map_err(|_| {
            ProofChainDefinitionDecodeError::InvalidLength {
                actual: bytes.len(),
                expected: Self::BYTE_LENGTH,
            }
        })?;
        let foundation_start = DEPLOYMENT_DISCRIMINATOR_BYTES;
        let genesis_root_start = foundation_start + FOUNDATION_ID_BYTES;
        if bytes[foundation_start..genesis_root_start] != *FOUNDATION_ID.as_bytes() {
            return Err(ProofChainDefinitionDecodeError::FoundationIdMismatch);
        }
        let actual_root = ProofSetRoot::from_bytes(
            bytes[genesis_root_start..]
                .try_into()
                .expect("the fixed definition suffix is one proof-set root"),
        );
        let expected_root = ProofSetRoot::empty();
        if actual_root != expected_root {
            return Err(
                ProofChainDefinitionDecodeError::GenesisProofSetRootMismatch {
                    expected: expected_root,
                    actual: actual_root,
                },
            );
        }
        Ok(Self::new(
            bytes[..DEPLOYMENT_DISCRIMINATOR_BYTES]
                .try_into()
                .expect("the fixed definition prefix is one deployment discriminator"),
        ))
    }

    /// Encodes this definition in its sole canonical representation.
    #[must_use]
    pub fn to_canonical_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        let mut bytes = [0_u8; Self::BYTE_LENGTH];
        let foundation_start = DEPLOYMENT_DISCRIMINATOR_BYTES;
        let genesis_root_start = foundation_start + FOUNDATION_ID_BYTES;
        bytes[..foundation_start].copy_from_slice(&self.deployment_discriminator);
        bytes[foundation_start..genesis_root_start].copy_from_slice(FOUNDATION_ID.as_bytes());
        bytes[genesis_root_start..].copy_from_slice(ProofSetRoot::empty().as_bytes());
        bytes
    }

    /// Returns the content-derived identity of this complete definition.
    pub fn id(self) -> ProofChainId {
        let mut hasher = Sha256::new();
        hasher.update(PROOF_CHAIN_DEFINITION_DOMAIN);
        hasher.update(self.to_canonical_bytes());
        ProofChainId(hasher.finalize().into())
    }
}

/// A malformed or unsupported canonical proof-chain definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofChainDefinitionDecodeError {
    /// The input is not exactly one complete canonical definition.
    InvalidLength { actual: usize, expected: usize },
    /// The definition names a Foundation other than the executable contract.
    FoundationIdMismatch,
    /// The definition does not start from the executable empty proof set.
    GenesisProofSetRootMismatch {
        expected: ProofSetRoot,
        actual: ProofSetRoot,
    },
}

impl fmt::Display for ProofChainDefinitionDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => write!(
                formatter,
                "canonical proof-chain definition length {actual} does not equal {expected} bytes"
            ),
            Self::FoundationIdMismatch => {
                formatter.write_str("proof-chain definition Foundation identity is unsupported")
            }
            Self::GenesisProofSetRootMismatch { expected, actual } => write!(
                formatter,
                "proof-chain definition genesis proof-set root mismatch: expected {expected:?}, actual {actual:?}"
            ),
        }
    }
}

impl Error for ProofChainDefinitionDecodeError {}

/// The content-derived address of one canonical [`ProofChainDefinition`].
///
/// [`Self::from_bytes`] constructs an observed or persisted address only. It
/// does not establish that the bytes came from a supported definition, and
/// trusted chain state cannot be constructed from this value alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ProofChainId([u8; 32]);

impl ProofChainId {
    /// Exact width of one proof-chain identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an unvalidated chain-definition address from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw chain-context bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives the virtual genesis parent for this observed chain identity.
    ///
    /// This calculation does not establish that the identity came from a
    /// supported [`ProofChainDefinition`]. Trusted state construction accepts
    /// the definition itself.
    pub fn virtual_genesis_block_id(self) -> ProofBlockId {
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
    /// Exact width of one proof-block identity.
    pub const BYTE_LENGTH: usize = 32;

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
/// parent derived from [`ProofChainDefinition`], not an admitted block.
#[must_use]
pub struct ProofChainState {
    chain_id: ProofChainId,
    head_block_id: ProofBlockId,
    proof_dag: ProofDag,
}

impl ProofChainState {
    /// Constructs an empty chain at its domain-separated virtual genesis head.
    pub fn new(definition: ProofChainDefinition) -> Self {
        let chain_id = definition.id();
        Self {
            chain_id,
            head_block_id: chain_id.virtual_genesis_block_id(),
            proof_dag: ProofDag::new(),
        }
    }

    /// Returns the definition-derived chain identity.
    pub const fn chain_id(&self) -> ProofChainId {
        self.chain_id
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

    /// Returns immutable access to the selected checked-proof resolver state.
    pub const fn proof_state(&self) -> &ProofState {
        self.proof_dag.proof_state()
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
        self.ensure_parent(block)?;

        let next_head = block.id();
        let record = self
            .proof_dag
            .apply_proof_transition(block.transition(), candidates)
            .map_err(|source| ProofBlockApplyError::Transition { source })?;
        self.head_block_id = next_head;
        Ok(record)
    }

    /// Validates one exact-head block without changing selected state.
    ///
    /// Success is relative only to the current head and proof state: it does
    /// not reserve, select, or authorize the block. A later application fully
    /// revalidates it and may reject it after state changes.
    pub fn validate_block(
        &self,
        block: &ProofBlock,
        candidates: Vec<AddressedProofCandidate>,
    ) -> Result<(), ProofBlockApplyError> {
        self.ensure_parent(block)?;
        self.proof_dag
            .validate_proof_transition(block.transition(), candidates)
            .map_err(|source| ProofBlockApplyError::Transition { source })
    }

    fn ensure_parent(&self, block: &ProofBlock) -> Result<(), ProofBlockApplyError> {
        let actual = block.parent_block_id();
        if actual != self.head_block_id {
            return Err(ProofBlockApplyError::ParentBlockIdMismatch {
                expected: self.head_block_id,
                actual,
            });
        }
        Ok(())
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
