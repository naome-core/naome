use std::error::Error;
use std::fmt;

use naome_foundation::FOUNDATION_ID;
use naome_ledger::{AcceptedProofRecord, ProofState};
use naome_proof::ProofId;
use sha2::{Digest, Sha256};

use crate::{ProofDag, ProofSetRoot};

const PROOF_CHAIN_GENESIS_DOMAIN: &[u8] = b"naome:proof-chain-genesis\0";
const PROOF_CHAIN_DEFINITION_DOMAIN: &[u8] = b"naome:proof-chain-definition:single-proof-v0\0";
const PROOF_BLOCK_DOMAIN: &[u8] = b"naome:proof-block\0";
const BLOCK_ID_BYTES: usize = ProofBlockId::BYTE_LENGTH;
const PROOF_SET_ROOT_BYTES: usize = ProofSetRoot::BYTE_LENGTH;
const PROOF_ID_BYTES: usize = ProofId::BYTE_LENGTH;
const DEPLOYMENT_DISCRIMINATOR_BYTES: usize = 32;
const FOUNDATION_ID_BYTES: usize = FOUNDATION_ID.len();
const GENESIS_PROOF_SET_ROOT_BYTES: usize = ProofSetRoot::BYTE_LENGTH;

/// Exact length of one canonical linear single-proof block.
pub const PROOF_BLOCK_BYTES: usize = BLOCK_ID_BYTES + PROOF_SET_ROOT_BYTES * 2 + PROOF_ID_BYTES;

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

/// One canonical parent-linked single-proof state transition.
///
/// The parent is always present. The first block points to the virtual genesis
/// parent derived from the chain context; later blocks point to the exact
/// preceding [`ProofBlockId`]. The block commits exactly one proof identity and
/// the proof-set root before and after admitting it. Proof bytes remain one
/// separately supplied canonical payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct ProofBlock {
    parent_block_id: ProofBlockId,
    previous_proof_set_root: ProofSetRoot,
    resulting_proof_set_root: ProofSetRoot,
    proof_id: ProofId,
}

impl ProofBlock {
    /// Constructs one block from its four fixed-width commitment fields.
    pub const fn new(
        parent_block_id: ProofBlockId,
        previous_proof_set_root: ProofSetRoot,
        resulting_proof_set_root: ProofSetRoot,
        proof_id: ProofId,
    ) -> Self {
        Self {
            parent_block_id,
            previous_proof_set_root,
            resulting_proof_set_root,
            proof_id,
        }
    }

    /// Decodes one complete canonical proof block.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProofBlockDecodeError> {
        let bytes = <&[u8; PROOF_BLOCK_BYTES]>::try_from(bytes).map_err(|_| {
            ProofBlockDecodeError::InvalidLength {
                actual: bytes.len(),
                expected: PROOF_BLOCK_BYTES,
            }
        })?;

        let parent_block_id = ProofBlockId::from_bytes(
            bytes[..BLOCK_ID_BYTES]
                .try_into()
                .expect("the fixed block prefix is one parent identity"),
        );
        let previous_root_start = BLOCK_ID_BYTES;
        let resulting_root_start = previous_root_start + PROOF_SET_ROOT_BYTES;
        let proof_id_start = resulting_root_start + PROOF_SET_ROOT_BYTES;
        let previous_proof_set_root = ProofSetRoot::from_bytes(
            bytes[previous_root_start..resulting_root_start]
                .try_into()
                .expect("the fixed second block field is one proof-set root"),
        );
        let resulting_proof_set_root = ProofSetRoot::from_bytes(
            bytes[resulting_root_start..proof_id_start]
                .try_into()
                .expect("the fixed third block field is one proof-set root"),
        );
        let proof_id = ProofId::from_bytes(
            bytes[proof_id_start..]
                .try_into()
                .expect("the fixed block suffix is one proof identity"),
        );

        Ok(Self::new(
            parent_block_id,
            previous_proof_set_root,
            resulting_proof_set_root,
            proof_id,
        ))
    }

    /// Encodes this block in its sole canonical representation.
    #[must_use]
    pub fn to_canonical_bytes(self) -> [u8; PROOF_BLOCK_BYTES] {
        let mut bytes = [0_u8; PROOF_BLOCK_BYTES];
        let previous_root_start = BLOCK_ID_BYTES;
        let resulting_root_start = previous_root_start + PROOF_SET_ROOT_BYTES;
        let proof_id_start = resulting_root_start + PROOF_SET_ROOT_BYTES;
        bytes[..previous_root_start].copy_from_slice(self.parent_block_id.as_bytes());
        bytes[previous_root_start..resulting_root_start]
            .copy_from_slice(self.previous_proof_set_root.as_bytes());
        bytes[resulting_root_start..proof_id_start]
            .copy_from_slice(self.resulting_proof_set_root.as_bytes());
        bytes[proof_id_start..].copy_from_slice(self.proof_id.as_bytes());
        bytes
    }

    /// Returns this block's canonical content address.
    pub fn id(&self) -> ProofBlockId {
        let mut hasher = Sha256::new();
        hasher.update(PROOF_BLOCK_DOMAIN);
        hasher.update(self.parent_block_id.as_bytes());
        hasher.update(self.previous_proof_set_root.as_bytes());
        hasher.update(self.resulting_proof_set_root.as_bytes());
        hasher.update(self.proof_id.as_bytes());
        ProofBlockId(hasher.finalize().into())
    }

    /// Returns the exact parent block or virtual genesis address.
    pub const fn parent_block_id(&self) -> ProofBlockId {
        self.parent_block_id
    }

    /// Returns the selected proof-set root required before application.
    pub const fn previous_proof_set_root(&self) -> ProofSetRoot {
        self.previous_proof_set_root
    }

    /// Returns the selected proof-set root committed after application.
    pub const fn resulting_proof_set_root(&self) -> ProofSetRoot {
        self.resulting_proof_set_root
    }

    /// Returns the sole proof identity committed by this block.
    pub const fn proof_id(&self) -> ProofId {
        self.proof_id
    }
}

/// A malformed canonical linear proof block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofBlockDecodeError {
    /// The input is not exactly one complete fixed-width block.
    InvalidLength { actual: usize, expected: usize },
}

impl fmt::Display for ProofBlockDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => write!(
                formatter,
                "canonical proof block length {actual} does not equal {expected} bytes"
            ),
        }
    }
}

impl Error for ProofBlockDecodeError {}

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
    /// Preparation is read-only and rejects a proof already selected in this
    /// chain. It does not inspect, retrieve, or check proof bytes.
    pub fn prepare_block(&self, proof_id: ProofId) -> Result<ProofBlock, ProofBlockPrepareError> {
        let previous_root = self.proof_dag.proof_set_root();
        let (resulting_root, already_selected) = self.proof_dag.projected_proof_set_root(proof_id);
        if already_selected {
            return Err(ProofBlockPrepareError::AlreadySelectedProofId { proof_id });
        }
        Ok(ProofBlock::new(
            self.head_block_id,
            previous_root,
            resulting_root,
            proof_id,
        ))
    }

    /// Atomically applies one exact-head canonical proof block.
    ///
    /// Parent, current-root, already-selected, and projected-root checks precede
    /// proof work. After the one-proof admission commits, only an
    /// infallible head assignment remains. Every error therefore preserves both
    /// linear and selected state.
    pub fn apply_block(
        &mut self,
        block: &ProofBlock,
        canonical_proof_bytes: Vec<u8>,
    ) -> Result<&AcceptedProofRecord, ProofBlockApplyError> {
        self.preflight_block(block)?;

        let next_head = block.id();
        let record = self
            .proof_dag
            .apply_canonical_proof_bytes_with_expected_id(canonical_proof_bytes, block.proof_id())
            .map_err(|source| ProofBlockApplyError::Admission { source })?;
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
        canonical_proof_bytes: Vec<u8>,
    ) -> Result<(), ProofBlockApplyError> {
        self.preflight_block(block)?;
        self.proof_dag
            .validate_canonical_proof_bytes_with_expected_id(
                canonical_proof_bytes,
                block.proof_id(),
            )
            .map_err(|source| ProofBlockApplyError::Admission { source })
    }

    fn preflight_block(&self, block: &ProofBlock) -> Result<(), ProofBlockApplyError> {
        let actual = block.parent_block_id();
        if actual != self.head_block_id {
            return Err(ProofBlockApplyError::ParentBlockIdMismatch {
                expected: self.head_block_id,
                actual,
            });
        }

        let expected = self.proof_dag.proof_set_root();
        let actual = block.previous_proof_set_root();
        if actual != expected {
            return Err(ProofBlockApplyError::PreviousProofSetRootMismatch { expected, actual });
        }

        let (actual, already_selected) = self.proof_dag.projected_proof_set_root(block.proof_id());
        if already_selected {
            return Err(ProofBlockApplyError::AlreadySelectedProofId {
                proof_id: block.proof_id(),
            });
        }
        if actual != block.resulting_proof_set_root() {
            return Err(ProofBlockApplyError::ResultingProofSetRootMismatch {
                expected: block.resulting_proof_set_root(),
                actual,
            });
        }
        Ok(())
    }
}

/// A rejected read-only single-proof block preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofBlockPrepareError {
    /// The proposed proof already belongs to the selected proof set.
    AlreadySelectedProofId { proof_id: ProofId },
}

impl fmt::Display for ProofBlockPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadySelectedProofId { proof_id } => {
                write!(formatter, "proof id {proof_id:?} is already selected")
            }
        }
    }
}

impl Error for ProofBlockPrepareError {}

/// A fail-closed linear proof-block application error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofBlockApplyError {
    /// The block does not extend the chain's exact current head.
    ParentBlockIdMismatch {
        expected: ProofBlockId,
        actual: ProofBlockId,
    },
    /// The block is bound to a different selected proof set.
    PreviousProofSetRootMismatch {
        expected: ProofSetRoot,
        actual: ProofSetRoot,
    },
    /// The block attempts to admit a proof already in the selected proof set.
    AlreadySelectedProofId { proof_id: ProofId },
    /// Read-only insertion projection did not reproduce the committed root.
    ResultingProofSetRootMismatch {
        expected: ProofSetRoot,
        actual: ProofSetRoot,
    },
    /// Strict single-proof admission rejected the supplied payload.
    Admission { source: naome_ledger::LedgerError },
}

impl fmt::Display for ProofBlockApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParentBlockIdMismatch { expected, actual } => write!(
                formatter,
                "proof block parent mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::PreviousProofSetRootMismatch { expected, actual } => write!(
                formatter,
                "proof block previous root mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::AlreadySelectedProofId { proof_id } => {
                write!(
                    formatter,
                    "proof block proof id {proof_id:?} is already selected"
                )
            }
            Self::ResultingProofSetRootMismatch { expected, actual } => write!(
                formatter,
                "proof block resulting root mismatch: expected {expected:?}, projected {actual:?}"
            ),
            Self::Admission { source } => {
                write!(formatter, "proof block admission failed: {source}")
            }
        }
    }
}

impl Error for ProofBlockApplyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission { source } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
