use std::error::Error;
use std::fmt;

use naome_foundation::FOUNDATION_ID;
use naome_ledger::{AcceptedArtifactRecord, ArtifactState};
use naome_proof::ArtifactId;
use sha2::{Digest, Sha256};

use crate::{ArtifactDag, ArtifactSetRoot};

const ARTIFACT_CHAIN_GENESIS_DOMAIN: &[u8] = b"naome:artifact-chain-genesis:v0\0";
const ARTIFACT_CHAIN_DEFINITION_DOMAIN: &[u8] =
    b"naome:artifact-chain-definition:canonical-definition-v1\0";
const ARTIFACT_BLOCK_DOMAIN: &[u8] = b"naome:artifact-block:v0\0";
const BLOCK_ID_BYTES: usize = ArtifactBlockId::BYTE_LENGTH;
const ARTIFACT_SET_ROOT_BYTES: usize = ArtifactSetRoot::BYTE_LENGTH;
const ARTIFACT_ID_BYTES: usize = ArtifactId::BYTE_LENGTH;
const DEPLOYMENT_DISCRIMINATOR_BYTES: usize = 32;
const FOUNDATION_ID_BYTES: usize = FOUNDATION_ID.len();
const GENESIS_ARTIFACT_SET_ROOT_BYTES: usize = ArtifactSetRoot::BYTE_LENGTH;

/// Exact length of one canonical linear single-artifact block.
pub const ARTIFACT_BLOCK_BYTES: usize =
    BLOCK_ID_BYTES + ARTIFACT_SET_ROOT_BYTES * 2 + ARTIFACT_ID_BYTES;

/// The canonical executable context from which one artifact chain is derived.
///
/// The caller supplies only a deployment discriminator. Canonical bytes also
/// bind the exact compiled Foundation identity and empty authenticated artifact-
/// set root, so unsupported genesis semantics cannot be injected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ArtifactChainDefinition {
    deployment_discriminator: [u8; DEPLOYMENT_DISCRIMINATOR_BYTES],
}

impl ArtifactChainDefinition {
    /// Exact byte length of one canonical artifact-chain definition.
    pub const BYTE_LENGTH: usize =
        DEPLOYMENT_DISCRIMINATOR_BYTES + FOUNDATION_ID_BYTES + GENESIS_ARTIFACT_SET_ROOT_BYTES;

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

    /// Decodes one complete canonical artifact-chain definition.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ArtifactChainDefinitionDecodeError> {
        let bytes = <&[u8; Self::BYTE_LENGTH]>::try_from(bytes).map_err(|_| {
            ArtifactChainDefinitionDecodeError::InvalidLength {
                actual: bytes.len(),
                expected: Self::BYTE_LENGTH,
            }
        })?;
        let foundation_start = DEPLOYMENT_DISCRIMINATOR_BYTES;
        let genesis_root_start = foundation_start + FOUNDATION_ID_BYTES;
        if bytes[foundation_start..genesis_root_start] != *FOUNDATION_ID.as_bytes() {
            return Err(ArtifactChainDefinitionDecodeError::FoundationIdMismatch);
        }
        let actual_root = ArtifactSetRoot::from_bytes(
            bytes[genesis_root_start..]
                .try_into()
                .expect("the fixed definition suffix is one artifact-set root"),
        );
        let expected_root = ArtifactSetRoot::empty();
        if actual_root != expected_root {
            return Err(
                ArtifactChainDefinitionDecodeError::GenesisArtifactSetRootMismatch {
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
        bytes[genesis_root_start..].copy_from_slice(ArtifactSetRoot::empty().as_bytes());
        bytes
    }

    /// Returns the content-derived identity of this complete definition.
    pub fn id(self) -> ArtifactChainId {
        let mut hasher = Sha256::new();
        hasher.update(ARTIFACT_CHAIN_DEFINITION_DOMAIN);
        hasher.update(self.to_canonical_bytes());
        ArtifactChainId(hasher.finalize().into())
    }
}

/// A malformed or unsupported canonical artifact-chain definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactChainDefinitionDecodeError {
    /// The input is not exactly one complete canonical definition.
    InvalidLength { actual: usize, expected: usize },
    /// The definition names a Foundation other than the executable contract.
    FoundationIdMismatch,
    /// The definition does not start from the executable empty artifact set.
    GenesisArtifactSetRootMismatch {
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
}

impl fmt::Display for ArtifactChainDefinitionDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => write!(
                formatter,
                "canonical artifact-chain definition length {actual} does not equal {expected} bytes"
            ),
            Self::FoundationIdMismatch => {
                formatter.write_str("artifact-chain definition Foundation identity is unsupported")
            }
            Self::GenesisArtifactSetRootMismatch { expected, actual } => write!(
                formatter,
                "artifact-chain definition genesis artifact-set root mismatch: expected {expected:?}, actual {actual:?}"
            ),
        }
    }
}

impl Error for ArtifactChainDefinitionDecodeError {}

/// The content-derived address of one canonical [`ArtifactChainDefinition`].
///
/// [`Self::from_bytes`] constructs an observed or persisted address only. It
/// does not establish that the bytes came from a supported definition, and
/// trusted chain state cannot be constructed from this value alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ArtifactChainId([u8; 32]);

impl ArtifactChainId {
    /// Exact width of one artifact-chain identity.
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
    /// supported [`ArtifactChainDefinition`]. Trusted state construction accepts
    /// the definition itself.
    pub fn virtual_genesis_block_id(self) -> ArtifactBlockId {
        let mut hasher = Sha256::new();
        hasher.update(ARTIFACT_CHAIN_GENESIS_DOMAIN);
        hasher.update(self.as_bytes());
        ArtifactBlockId(hasher.finalize().into())
    }
}

/// A 32-byte address in one canonical linear artifact-block ancestry.
///
/// [`ArtifactBlock::id`] addresses canonical block bytes. A chain state's initial
/// value instead addresses its separately domain-separated virtual genesis
/// parent. Neither form establishes artifact validity, consensus selection,
/// finality, or data availability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ArtifactBlockId([u8; 32]);

impl ArtifactBlockId {
    /// Exact width of one artifact-block identity.
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

/// One canonical parent-linked single-artifact state transition.
///
/// The parent is always present. The first block points to the virtual genesis
/// parent derived from the chain context; later blocks point to the exact
/// preceding [`ArtifactBlockId`]. The block commits exactly one artifact identity
/// and the artifact-set root before and after admitting it. The canonical tagged
/// artifact payload remains separately supplied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct ArtifactBlock {
    parent_block_id: ArtifactBlockId,
    previous_artifact_set_root: ArtifactSetRoot,
    resulting_artifact_set_root: ArtifactSetRoot,
    artifact_id: ArtifactId,
}

impl ArtifactBlock {
    /// Constructs one block from its four fixed-width commitment fields.
    pub const fn new(
        parent_block_id: ArtifactBlockId,
        previous_artifact_set_root: ArtifactSetRoot,
        resulting_artifact_set_root: ArtifactSetRoot,
        artifact_id: ArtifactId,
    ) -> Self {
        Self {
            parent_block_id,
            previous_artifact_set_root,
            resulting_artifact_set_root,
            artifact_id,
        }
    }

    /// Decodes one complete canonical artifact block.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ArtifactBlockDecodeError> {
        let bytes = <&[u8; ARTIFACT_BLOCK_BYTES]>::try_from(bytes).map_err(|_| {
            ArtifactBlockDecodeError::InvalidLength {
                actual: bytes.len(),
                expected: ARTIFACT_BLOCK_BYTES,
            }
        })?;

        let parent_block_id = ArtifactBlockId::from_bytes(
            bytes[..BLOCK_ID_BYTES]
                .try_into()
                .expect("the fixed block prefix is one parent identity"),
        );
        let previous_root_start = BLOCK_ID_BYTES;
        let resulting_root_start = previous_root_start + ARTIFACT_SET_ROOT_BYTES;
        let artifact_id_start = resulting_root_start + ARTIFACT_SET_ROOT_BYTES;
        let previous_artifact_set_root = ArtifactSetRoot::from_bytes(
            bytes[previous_root_start..resulting_root_start]
                .try_into()
                .expect("the fixed second block field is one artifact-set root"),
        );
        let resulting_artifact_set_root = ArtifactSetRoot::from_bytes(
            bytes[resulting_root_start..artifact_id_start]
                .try_into()
                .expect("the fixed third block field is one artifact-set root"),
        );
        let artifact_id = ArtifactId::from_bytes(
            bytes[artifact_id_start..]
                .try_into()
                .expect("the fixed block suffix is one artifact identity"),
        );

        Ok(Self::new(
            parent_block_id,
            previous_artifact_set_root,
            resulting_artifact_set_root,
            artifact_id,
        ))
    }

    /// Encodes this block in its sole canonical representation.
    #[must_use]
    pub fn to_canonical_bytes(self) -> [u8; ARTIFACT_BLOCK_BYTES] {
        let mut bytes = [0_u8; ARTIFACT_BLOCK_BYTES];
        let previous_root_start = BLOCK_ID_BYTES;
        let resulting_root_start = previous_root_start + ARTIFACT_SET_ROOT_BYTES;
        let artifact_id_start = resulting_root_start + ARTIFACT_SET_ROOT_BYTES;
        bytes[..previous_root_start].copy_from_slice(self.parent_block_id.as_bytes());
        bytes[previous_root_start..resulting_root_start]
            .copy_from_slice(self.previous_artifact_set_root.as_bytes());
        bytes[resulting_root_start..artifact_id_start]
            .copy_from_slice(self.resulting_artifact_set_root.as_bytes());
        bytes[artifact_id_start..].copy_from_slice(self.artifact_id.as_bytes());
        bytes
    }

    /// Returns this block's canonical content address.
    pub fn id(&self) -> ArtifactBlockId {
        let mut hasher = Sha256::new();
        hasher.update(ARTIFACT_BLOCK_DOMAIN);
        hasher.update(self.parent_block_id.as_bytes());
        hasher.update(self.previous_artifact_set_root.as_bytes());
        hasher.update(self.resulting_artifact_set_root.as_bytes());
        hasher.update(self.artifact_id.as_bytes());
        ArtifactBlockId(hasher.finalize().into())
    }

    /// Returns the exact parent block or virtual genesis address.
    pub const fn parent_block_id(&self) -> ArtifactBlockId {
        self.parent_block_id
    }

    /// Returns the selected artifact-set root required before application.
    pub const fn previous_artifact_set_root(&self) -> ArtifactSetRoot {
        self.previous_artifact_set_root
    }

    /// Returns the selected artifact-set root committed after application.
    pub const fn resulting_artifact_set_root(&self) -> ArtifactSetRoot {
        self.resulting_artifact_set_root
    }

    /// Returns the sole artifact identity committed by this block.
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact_id
    }
}

/// A malformed canonical linear artifact block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactBlockDecodeError {
    /// The input is not exactly one complete fixed-width block.
    InvalidLength { actual: usize, expected: usize },
}

impl fmt::Display for ArtifactBlockDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => write!(
                formatter,
                "canonical artifact block length {actual} does not equal {expected} bytes"
            ),
        }
    }
}

impl Error for ArtifactBlockDecodeError {}

/// An in-memory exact-tip execution chain for canonical artifact blocks.
///
/// The selected [`ArtifactDag`] is privately owned so its authenticated state and
/// the linear block head cannot diverge. The initial head is a virtual genesis
/// parent derived from [`ArtifactChainDefinition`], not an admitted block.
#[derive(Clone)]
#[must_use]
pub struct ArtifactChainState {
    chain_id: ArtifactChainId,
    head_block_id: ArtifactBlockId,
    artifact_dag: ArtifactDag,
}

impl ArtifactChainState {
    /// Constructs an empty chain at its domain-separated virtual genesis head.
    pub fn new(definition: ArtifactChainDefinition) -> Self {
        let chain_id = definition.id();
        Self {
            chain_id,
            head_block_id: chain_id.virtual_genesis_block_id(),
            artifact_dag: ArtifactDag::new(),
        }
    }

    /// Returns the definition-derived chain identity.
    pub const fn chain_id(&self) -> ArtifactChainId {
        self.chain_id
    }

    /// Returns the exact head expected as the next block's parent.
    ///
    /// Before the first block, this is the virtual genesis parent and does not
    /// address an admitted block.
    pub const fn head_block_id(&self) -> ArtifactBlockId {
        self.head_block_id
    }

    /// Returns read-only access to the selected artifact DAG.
    pub const fn artifact_dag(&self) -> &ArtifactDag {
        &self.artifact_dag
    }

    /// Returns immutable access to the selected checked-artifact resolver state.
    pub const fn artifact_state(&self) -> &ArtifactState {
        self.artifact_dag.artifact_state()
    }

    /// Captures this exact strictly constructed chain state as an immutable branch snapshot.
    ///
    /// The snapshot structurally shares immutable state with this chain. Later
    /// selected-chain changes cannot alter it, and validating a child returns a
    /// separate snapshot without mutating either input.
    pub fn branch_snapshot(&self) -> ArtifactChainBranchSnapshot {
        ArtifactChainBranchSnapshot {
            state: self.clone(),
        }
    }

    /// Prepares one block against the exact current head and artifact state.
    ///
    /// Preparation is read-only and rejects an artifact already selected in this
    /// chain. It does not inspect, retrieve, or check payload bytes.
    pub fn prepare_block(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactBlock, ArtifactBlockPrepareError> {
        let previous_root = self.artifact_dag.artifact_set_root();
        let (resulting_root, already_selected) =
            self.artifact_dag.projected_artifact_set_root(artifact_id);
        if already_selected {
            return Err(ArtifactBlockPrepareError::AlreadySelectedArtifactId { artifact_id });
        }
        Ok(ArtifactBlock::new(
            self.head_block_id,
            previous_root,
            resulting_root,
            artifact_id,
        ))
    }

    /// Atomically applies one exact-head canonical artifact block.
    ///
    /// Parent, current-root, already-selected, and projected-root checks precede
    /// artifact work. After the one-artifact admission commits, only an
    /// infallible head assignment remains. Every error therefore preserves both
    /// linear and selected state.
    pub fn apply_block(
        &mut self,
        block: &ArtifactBlock,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<&AcceptedArtifactRecord, ArtifactBlockApplyError> {
        self.preflight_block(block)?;

        let next_head = block.id();
        let record = self
            .artifact_dag
            .apply_canonical_artifact_bytes_with_expected_id(
                canonical_artifact_bytes,
                block.artifact_id(),
            )
            .map_err(|source| ArtifactBlockApplyError::Admission { source })?;
        self.head_block_id = next_head;
        Ok(record)
    }

    /// Validates one exact-head block without changing selected state.
    ///
    /// Success is relative only to the current head and artifact state: it does
    /// not reserve, select, or authorize the block. A later application fully
    /// revalidates it and may reject it after state changes.
    pub fn validate_block(
        &self,
        block: &ArtifactBlock,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<(), ArtifactBlockApplyError> {
        self.preflight_block(block)?;
        self.artifact_dag
            .validate_canonical_artifact_bytes_with_expected_id(
                canonical_artifact_bytes,
                block.artifact_id(),
            )
            .map_err(|source| ArtifactBlockApplyError::Admission { source })
    }

    fn preflight_block(&self, block: &ArtifactBlock) -> Result<(), ArtifactBlockApplyError> {
        let actual = block.parent_block_id();
        if actual != self.head_block_id {
            return Err(ArtifactBlockApplyError::ParentBlockIdMismatch {
                expected: self.head_block_id,
                actual,
            });
        }

        let expected = self.artifact_dag.artifact_set_root();
        let actual = block.previous_artifact_set_root();
        if actual != expected {
            return Err(ArtifactBlockApplyError::PreviousArtifactSetRootMismatch {
                expected,
                actual,
            });
        }

        let (actual, already_selected) = self
            .artifact_dag
            .projected_artifact_set_root(block.artifact_id());
        if already_selected {
            return Err(ArtifactBlockApplyError::AlreadySelectedArtifactId {
                artifact_id: block.artifact_id(),
            });
        }
        if actual != block.resulting_artifact_set_root() {
            return Err(ArtifactBlockApplyError::ResultingArtifactSetRootMismatch {
                expected: block.resulting_artifact_set_root(),
                actual,
            });
        }
        Ok(())
    }
}

/// An immutable exact-head artifact-chain state for candidate evaluation.
///
/// Snapshots have no public constructor. They are derived from one strictly constructed
/// [`ArtifactChainState`] or from a successfully validated child, and bind the
/// chain identity, exact block head, authenticated artifact-set root, and the
/// complete checked dependency resolver state. A snapshot establishes no
/// selection, fork choice, consensus inclusion, finality, or persistence.
#[derive(Clone)]
#[must_use]
pub struct ArtifactChainBranchSnapshot {
    state: ArtifactChainState,
}

impl ArtifactChainBranchSnapshot {
    /// Returns the chain identity captured by this snapshot.
    pub const fn chain_id(&self) -> ArtifactChainId {
        self.state.chain_id()
    }

    /// Returns the exact parent required by the next candidate child.
    pub const fn head_block_id(&self) -> ArtifactBlockId {
        self.state.head_block_id()
    }

    /// Returns the authenticated artifact-set root captured by this snapshot.
    pub fn artifact_set_root(&self) -> ArtifactSetRoot {
        self.state.artifact_dag().artifact_set_root()
    }

    /// Returns whether this is the exact empty virtual-genesis snapshot.
    ///
    /// Only [`ArtifactChainState::new`] can create this state. A successfully
    /// validated child has a non-genesis head and a non-empty checked artifact
    /// DAG. This query does not install or authenticate a consensus genesis.
    pub fn is_virtual_genesis(&self) -> bool {
        self.state.head_block_id() == self.state.chain_id().virtual_genesis_block_id()
            && self.state.artifact_dag().is_empty()
    }

    /// Strictly validates one direct child and returns its immutable state.
    ///
    /// Validation preserves the same parent, root, duplicate, projected-root,
    /// and strict artifact-admission precedence as selected-chain application.
    /// Every error leaves this snapshot unchanged.
    pub fn validate_child(
        &self,
        block: &ArtifactBlock,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<Self, ArtifactBlockApplyError> {
        let mut state = self.state.clone();
        state.apply_block(block, canonical_artifact_bytes)?;
        Ok(Self { state })
    }
}

/// A rejected read-only single-artifact block preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactBlockPrepareError {
    /// The proposed artifact already belongs to the selected artifact set.
    AlreadySelectedArtifactId { artifact_id: ArtifactId },
}

impl fmt::Display for ArtifactBlockPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadySelectedArtifactId { artifact_id } => {
                write!(formatter, "artifact id {artifact_id:?} is already selected")
            }
        }
    }
}

impl Error for ArtifactBlockPrepareError {}

/// A fail-closed linear artifact-block application error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactBlockApplyError {
    /// The block does not extend the chain's exact current head.
    ParentBlockIdMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// The block is bound to a different selected artifact set.
    PreviousArtifactSetRootMismatch {
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// The block attempts to admit an artifact already in the selected artifact set.
    AlreadySelectedArtifactId { artifact_id: ArtifactId },
    /// Read-only insertion projection did not reproduce the committed root.
    ResultingArtifactSetRootMismatch {
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// Strict single-artifact admission rejected the supplied payload.
    Admission { source: naome_ledger::LedgerError },
}

impl fmt::Display for ArtifactBlockApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParentBlockIdMismatch { expected, actual } => write!(
                formatter,
                "artifact block parent mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::PreviousArtifactSetRootMismatch { expected, actual } => write!(
                formatter,
                "artifact block previous root mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::AlreadySelectedArtifactId { artifact_id } => {
                write!(
                    formatter,
                    "artifact block commits already-selected artifact id {artifact_id:?}"
                )
            }
            Self::ResultingArtifactSetRootMismatch { expected, actual } => write!(
                formatter,
                "artifact block resulting root mismatch: expected {expected:?}, projected {actual:?}"
            ),
            Self::Admission { source } => {
                write!(formatter, "artifact block admission failed: {source}")
            }
        }
    }
}

impl Error for ArtifactBlockApplyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission { source } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
