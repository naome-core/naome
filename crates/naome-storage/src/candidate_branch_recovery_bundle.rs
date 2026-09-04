use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::ops::Range;

use naome_chain::{
    ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockApplyError, ArtifactBlockId,
    ArtifactChainBranchSnapshot, ArtifactChainId, ArtifactSetRoot,
};
use naome_proof::{ARTIFACT_PAYLOAD_MAX_BYTES, ArtifactId};
use sha2::{Digest, Sha256};

use crate::candidate_branch_reconstruction::{
    CandidateBranchPathAnchor, CandidateBranchPathError, collect_candidate_branch_path,
};
use crate::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError, ArtifactChainJournal,
    ArtifactChainJournalError, CanonicalArtifactPayloadStore, CanonicalArtifactPayloadStoreError,
    JournalCore, SelectedArtifactHistory, SelectedArtifactHistoryError, StoreIo,
};

const BUNDLE_HEADER: &[u8] = b"naome:candidate-branch-recovery-bundle:v0\0";
const BUNDLE_DIGEST_DOMAIN: &[u8] = b"naome:candidate-branch-recovery-bundle-digest:v0\0";
const DIGEST_BYTES: usize = 32;
const COUNT_BYTES: usize = 4;
const PAYLOAD_LENGTH_BYTES: usize = 4;
const TOTAL_PAYLOAD_BYTES: usize = 8;
const FIXED_METADATA_BYTES: usize = BUNDLE_HEADER.len()
    + ArtifactChainId::BYTE_LENGTH
    + ArtifactBlockId::BYTE_LENGTH
    + ArtifactSetRoot::BYTE_LENGTH
    + ArtifactBlockId::BYTE_LENGTH
    + COUNT_BYTES
    + TOTAL_PAYLOAD_BYTES;
const MIN_BUNDLE_BYTES: usize = FIXED_METADATA_BYTES + DIGEST_BYTES;

/// Caller-local bounds for one portable candidate-branch recovery bundle.
///
/// These limits are not persisted policy, branch-retention policy, or consensus
/// resource limits. Every bound is applied independently by export, decode,
/// selected import, and unselected staging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateBranchRecoveryBundleLimits {
    max_blocks: usize,
    max_payload_bytes: u64,
    max_bundle_bytes: u64,
}

impl CandidateBranchRecoveryBundleLimits {
    /// Constructs positive block, logical-payload, and complete-byte bounds.
    pub const fn new(
        max_blocks: usize,
        max_payload_bytes: u64,
        max_bundle_bytes: u64,
    ) -> Result<Self, CandidateBranchRecoveryBundleLimitsError> {
        if max_blocks == 0 {
            return Err(CandidateBranchRecoveryBundleLimitsError::ZeroMaxBlocks);
        }
        if max_payload_bytes == 0 {
            return Err(CandidateBranchRecoveryBundleLimitsError::ZeroMaxPayloadBytes);
        }
        if max_bundle_bytes == 0 {
            return Err(CandidateBranchRecoveryBundleLimitsError::ZeroMaxBundleBytes);
        }
        Ok(Self {
            max_blocks,
            max_payload_bytes,
            max_bundle_bytes,
        })
    }

    /// Returns the maximum number of blocks in one bundle.
    pub const fn max_blocks(&self) -> usize {
        self.max_blocks
    }

    /// Returns the maximum sum of exact tagged payload bytes.
    pub const fn max_payload_bytes(&self) -> u64 {
        self.max_payload_bytes
    }

    /// Returns the maximum complete canonical bundle length.
    pub const fn max_bundle_bytes(&self) -> u64 {
        self.max_bundle_bytes
    }
}

/// A rejected recovery-bundle limit configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidateBranchRecoveryBundleLimitsError {
    /// At least one block must be permitted.
    ZeroMaxBlocks,
    /// At least one payload byte must be permitted.
    ZeroMaxPayloadBytes,
    /// At least one complete bundle byte must be permitted.
    ZeroMaxBundleBytes,
}

impl fmt::Display for CandidateBranchRecoveryBundleLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroMaxBlocks => "candidate recovery bundle block limit must be positive",
            Self::ZeroMaxPayloadBytes => {
                "candidate recovery bundle payload-byte limit must be positive"
            }
            Self::ZeroMaxBundleBytes => {
                "candidate recovery bundle complete-byte limit must be positive"
            }
        })
    }
}

impl Error for CandidateBranchRecoveryBundleLimitsError {}

/// One deterministic, versioned, integrity-digested local recovery bundle.
///
/// The digest detects corruption or changes without a recomputed digest, but
/// authenticates no producer. Payload bytes stay private to the canonical byte
/// image and are deliberately omitted from `Debug`.
#[must_use]
pub struct CandidateBranchRecoveryBundleV0 {
    canonical_bytes: Vec<u8>,
    chain_id: ArtifactChainId,
    anchor_block_id: ArtifactBlockId,
    anchor_artifact_set_root: ArtifactSetRoot,
    target_block_id: ArtifactBlockId,
    block_count: usize,
    total_payload_bytes: u64,
}

impl CandidateBranchRecoveryBundleV0 {
    /// Strictly decodes and owns one complete canonical bundle byte string.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        limits: CandidateBranchRecoveryBundleLimits,
    ) -> Result<Self, CandidateBranchRecoveryBundleDecodeError> {
        let decoded = decode_bundle(bytes, limits)?;
        let mut canonical_bytes = Vec::new();
        canonical_bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| CandidateBranchRecoveryBundleDecodeError::Allocation {
                bytes: bytes.len(),
            })?;
        canonical_bytes.extend_from_slice(bytes);
        Ok(Self {
            canonical_bytes,
            chain_id: decoded.chain_id,
            anchor_block_id: decoded.anchor_block_id,
            anchor_artifact_set_root: decoded.anchor_artifact_set_root,
            target_block_id: decoded.target_block_id,
            block_count: decoded.entries.len(),
            total_payload_bytes: decoded.total_payload_bytes,
        })
    }

    /// Borrows the sole canonical byte representation.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Consumes the bundle and returns its sole canonical byte representation.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }

    /// Returns the exact artifact-chain context committed by the bundle.
    pub const fn chain_id(&self) -> ArtifactChainId {
        self.chain_id
    }

    /// Returns the exact selected anchor committed by the bundle.
    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.anchor_block_id
    }

    /// Returns the exact selected anchor's artifact-set root.
    pub const fn anchor_artifact_set_root(&self) -> ArtifactSetRoot {
        self.anchor_artifact_set_root
    }

    /// Returns the exact caller-selected candidate target.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the number of forward branch entries.
    pub const fn block_count(&self) -> usize {
        self.block_count
    }

    /// Returns the sum of exact tagged payload bytes.
    pub const fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes
    }

    /// Returns the complete canonical bundle length.
    pub fn encoded_bytes(&self) -> usize {
        self.canonical_bytes.len()
    }
}

impl fmt::Debug for CandidateBranchRecoveryBundleV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateBranchRecoveryBundleV0")
            .field("chain_id", &self.chain_id)
            .field("anchor_block_id", &self.anchor_block_id)
            .field("anchor_artifact_set_root", &self.anchor_artifact_set_root)
            .field("target_block_id", &self.target_block_id)
            .field("block_count", &self.block_count)
            .field("total_payload_bytes", &self.total_payload_bytes)
            .field("encoded_bytes", &self.canonical_bytes.len())
            .finish_non_exhaustive()
    }
}

pub(super) struct DecodedBundleEntry {
    pub(super) block: ArtifactBlock,
    pub(super) payload_range: Range<usize>,
}

pub(super) struct DecodedBundle {
    pub(super) chain_id: ArtifactChainId,
    pub(super) anchor_block_id: ArtifactBlockId,
    pub(super) anchor_artifact_set_root: ArtifactSetRoot,
    pub(super) target_block_id: ArtifactBlockId,
    pub(super) total_payload_bytes: u64,
    pub(super) entries: Vec<DecodedBundleEntry>,
}

pub(super) fn decode_bundle(
    bytes: &[u8],
    limits: CandidateBranchRecoveryBundleLimits,
) -> Result<DecodedBundle, CandidateBranchRecoveryBundleDecodeError> {
    let actual_bytes = u64::try_from(bytes.len())
        .map_err(|_| CandidateBranchRecoveryBundleDecodeError::BundleByteCountOverflow)?;
    if actual_bytes > limits.max_bundle_bytes {
        return Err(
            CandidateBranchRecoveryBundleDecodeError::BundleByteLimitExceeded {
                actual: actual_bytes,
                maximum: limits.max_bundle_bytes,
            },
        );
    }
    if bytes.len() < MIN_BUNDLE_BYTES {
        return Err(CandidateBranchRecoveryBundleDecodeError::Truncated);
    }
    if !bytes.starts_with(BUNDLE_HEADER) {
        return Err(CandidateBranchRecoveryBundleDecodeError::InvalidHeader);
    }

    let body_end = bytes.len() - DIGEST_BYTES;
    let expected_digest = bundle_digest(&bytes[..body_end]);
    if bytes[body_end..] != expected_digest {
        return Err(CandidateBranchRecoveryBundleDecodeError::DigestMismatch);
    }

    let mut cursor = BUNDLE_HEADER.len();
    let chain_id = ArtifactChainId::from_bytes(take_array(bytes, &mut cursor)?);
    let anchor_block_id = ArtifactBlockId::from_bytes(take_array(bytes, &mut cursor)?);
    let anchor_artifact_set_root = ArtifactSetRoot::from_bytes(take_array(bytes, &mut cursor)?);
    let target_block_id = ArtifactBlockId::from_bytes(take_array(bytes, &mut cursor)?);
    let declared_block_count = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
    if declared_block_count == 0 {
        return Err(CandidateBranchRecoveryBundleDecodeError::EmptyBranch);
    }
    let block_count = declared_block_count as usize;
    if block_count > limits.max_blocks {
        return Err(
            CandidateBranchRecoveryBundleDecodeError::BlockLimitExceeded {
                actual: block_count,
                maximum: limits.max_blocks,
            },
        );
    }
    let declared_payload_bytes = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
    if declared_payload_bytes > limits.max_payload_bytes {
        return Err(
            CandidateBranchRecoveryBundleDecodeError::PayloadByteLimitExceeded {
                actual: declared_payload_bytes,
                maximum: limits.max_payload_bytes,
            },
        );
    }

    let minimum_entries = block_count
        .checked_mul(ARTIFACT_BLOCK_BYTES + PAYLOAD_LENGTH_BYTES + 1)
        .and_then(|bytes| cursor.checked_add(bytes))
        .ok_or(CandidateBranchRecoveryBundleDecodeError::BundleByteCountOverflow)?;
    if minimum_entries > body_end {
        return Err(CandidateBranchRecoveryBundleDecodeError::Truncated);
    }

    let mut entries = Vec::new();
    entries.try_reserve_exact(block_count).map_err(|_| {
        CandidateBranchRecoveryBundleDecodeError::EntryAllocation {
            entries: block_count,
        }
    })?;
    let mut seen = HashSet::new();
    seen.try_reserve(block_count.saturating_add(1))
        .map_err(
            |_| CandidateBranchRecoveryBundleDecodeError::EntryAllocation {
                entries: block_count,
            },
        )?;
    seen.insert(anchor_block_id);
    let mut total_payload_bytes = 0_u64;
    let mut previous: Option<ArtifactBlock> = None;
    for entry in 0..block_count {
        if cursor
            .checked_add(ARTIFACT_BLOCK_BYTES + PAYLOAD_LENGTH_BYTES)
            .is_none_or(|end| end > body_end)
        {
            return Err(CandidateBranchRecoveryBundleDecodeError::Truncated);
        }
        let block_start = cursor;
        cursor += ARTIFACT_BLOCK_BYTES;
        let block =
            ArtifactBlock::from_canonical_bytes(&bytes[block_start..cursor]).map_err(|source| {
                CandidateBranchRecoveryBundleDecodeError::BlockDecode { entry, source }
            })?;
        if block.to_canonical_bytes() != bytes[block_start..cursor] {
            return Err(CandidateBranchRecoveryBundleDecodeError::NonCanonicalBlock { entry });
        }
        let block_id = block.id();
        if !seen.insert(block_id) {
            return Err(CandidateBranchRecoveryBundleDecodeError::RepeatedBlockId { block_id });
        }

        let payload_len = u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize;
        if payload_len == 0 || payload_len > ARTIFACT_PAYLOAD_MAX_BYTES {
            return Err(
                CandidateBranchRecoveryBundleDecodeError::InvalidPayloadLength {
                    entry,
                    actual: payload_len,
                    maximum: ARTIFACT_PAYLOAD_MAX_BYTES,
                },
            );
        }
        let additional = u64::try_from(payload_len)
            .map_err(|_| CandidateBranchRecoveryBundleDecodeError::PayloadByteCountOverflow)?;
        total_payload_bytes = total_payload_bytes
            .checked_add(additional)
            .ok_or(CandidateBranchRecoveryBundleDecodeError::PayloadByteCountOverflow)?;
        if total_payload_bytes > limits.max_payload_bytes {
            return Err(
                CandidateBranchRecoveryBundleDecodeError::PayloadByteLimitExceeded {
                    actual: total_payload_bytes,
                    maximum: limits.max_payload_bytes,
                },
            );
        }
        if total_payload_bytes > declared_payload_bytes {
            return Err(
                CandidateBranchRecoveryBundleDecodeError::PayloadByteTotalMismatch {
                    declared: declared_payload_bytes,
                    actual: total_payload_bytes,
                },
            );
        }
        let payload_end = cursor
            .checked_add(payload_len)
            .ok_or(CandidateBranchRecoveryBundleDecodeError::BundleByteCountOverflow)?;
        if payload_end > body_end {
            return Err(CandidateBranchRecoveryBundleDecodeError::Truncated);
        }

        let (expected_parent, expected_root) = match previous {
            Some(parent) => (parent.id(), parent.resulting_artifact_set_root()),
            None => (anchor_block_id, anchor_artifact_set_root),
        };
        if block.parent_block_id() != expected_parent {
            return Err(
                CandidateBranchRecoveryBundleDecodeError::ParentBlockIdMismatch {
                    entry,
                    expected: expected_parent,
                    actual: block.parent_block_id(),
                },
            );
        }
        if block.previous_artifact_set_root() != expected_root {
            return Err(
                CandidateBranchRecoveryBundleDecodeError::PreviousArtifactSetRootMismatch {
                    entry,
                    expected: expected_root,
                    actual: block.previous_artifact_set_root(),
                },
            );
        }
        entries.push(DecodedBundleEntry {
            block,
            payload_range: cursor..payload_end,
        });
        cursor = payload_end;
        previous = Some(block);
    }

    if cursor != body_end {
        return Err(CandidateBranchRecoveryBundleDecodeError::TrailingBytes {
            bytes: body_end - cursor,
        });
    }
    if total_payload_bytes != declared_payload_bytes {
        return Err(
            CandidateBranchRecoveryBundleDecodeError::PayloadByteTotalMismatch {
                declared: declared_payload_bytes,
                actual: total_payload_bytes,
            },
        );
    }
    let actual_target = previous
        .expect("a nonempty decoded bundle retains a last block")
        .id();
    if actual_target != target_block_id {
        return Err(
            CandidateBranchRecoveryBundleDecodeError::TargetBlockIdMismatch {
                expected: target_block_id,
                actual: actual_target,
            },
        );
    }

    Ok(DecodedBundle {
        chain_id,
        anchor_block_id,
        anchor_artifact_set_root,
        target_block_id,
        total_payload_bytes,
        entries,
    })
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], CandidateBranchRecoveryBundleDecodeError> {
    let end = cursor
        .checked_add(N)
        .ok_or(CandidateBranchRecoveryBundleDecodeError::BundleByteCountOverflow)?;
    let field = bytes
        .get(*cursor..end)
        .ok_or(CandidateBranchRecoveryBundleDecodeError::Truncated)?;
    *cursor = end;
    Ok(field
        .try_into()
        .expect("an exactly bounded bundle field has its declared width"))
}

fn bundle_digest(body: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(BUNDLE_DIGEST_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

/// A malformed, noncanonical, corrupt, or over-limit bundle.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateBranchRecoveryBundleDecodeError {
    /// Complete or field byte arithmetic overflowed.
    BundleByteCountOverflow,
    /// The complete input exceeds the caller-local byte bound.
    BundleByteLimitExceeded { actual: u64, maximum: u64 },
    /// The byte string ends before its declared canonical framing does.
    Truncated,
    /// The format domain/version header is unsupported.
    InvalidHeader,
    /// The final whole-bundle integrity digest does not match.
    DigestMismatch,
    /// V0 recovery bundles must carry at least one candidate block.
    EmptyBranch,
    /// The declared entry count exceeds the caller-local block bound.
    BlockLimitExceeded { actual: usize, maximum: usize },
    /// The declared or accumulated payload bytes exceed the caller-local bound.
    PayloadByteLimitExceeded { actual: u64, maximum: u64 },
    /// Reserving bounded entry metadata failed.
    EntryAllocation { entries: usize },
    /// Owning the complete canonical byte image failed.
    Allocation { bytes: usize },
    /// One fixed-width block failed its strict canonical decoder.
    BlockDecode {
        entry: usize,
        source: naome_chain::ArtifactBlockDecodeError,
    },
    /// One decoded block differs from its canonical re-encoding.
    NonCanonicalBlock { entry: usize },
    /// The anchor or an earlier entry identity repeats in the forward path.
    RepeatedBlockId { block_id: ArtifactBlockId },
    /// One payload length is zero or exceeds the protocol payload maximum.
    InvalidPayloadLength {
        entry: usize,
        actual: usize,
        maximum: usize,
    },
    /// Accumulating declared payload bytes overflowed.
    PayloadByteCountOverflow,
    /// Entry lengths do not sum to the declared logical payload total.
    PayloadByteTotalMismatch { declared: u64, actual: u64 },
    /// One entry is not the exact child of its preceding anchor or block.
    ParentBlockIdMismatch {
        entry: usize,
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// One entry does not start at its predecessor's resulting artifact root.
    PreviousArtifactSetRootMismatch {
        entry: usize,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// Unframed bytes remain between the declared entries and final digest.
    TrailingBytes { bytes: usize },
    /// The final decoded entry does not have the header's target identity.
    TargetBlockIdMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
}

impl fmt::Display for CandidateBranchRecoveryBundleDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BundleByteCountOverflow => {
                formatter.write_str("candidate recovery bundle byte count overflowed")
            }
            Self::BundleByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "candidate recovery bundle has {actual} bytes, exceeding limit {maximum}"
            ),
            Self::Truncated => formatter.write_str("candidate recovery bundle is truncated"),
            Self::InvalidHeader => {
                formatter.write_str("candidate recovery bundle header is unsupported")
            }
            Self::DigestMismatch => {
                formatter.write_str("candidate recovery bundle integrity digest does not match")
            }
            Self::EmptyBranch => {
                formatter.write_str("candidate recovery bundle branch must not be empty")
            }
            Self::BlockLimitExceeded { actual, maximum } => write!(
                formatter,
                "candidate recovery bundle has {actual} blocks, exceeding limit {maximum}"
            ),
            Self::PayloadByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "candidate recovery bundle declares or contains {actual} payload bytes, exceeding limit {maximum}"
            ),
            Self::EntryAllocation { entries } => write!(
                formatter,
                "candidate recovery bundle could not reserve metadata for {entries} entries"
            ),
            Self::Allocation { bytes } => write!(
                formatter,
                "candidate recovery bundle could not allocate its {bytes} canonical bytes"
            ),
            Self::BlockDecode { entry, source } => write!(
                formatter,
                "candidate recovery bundle entry {entry} block failed to decode: {source}"
            ),
            Self::NonCanonicalBlock { entry } => write!(
                formatter,
                "candidate recovery bundle entry {entry} block is not canonically encoded"
            ),
            Self::RepeatedBlockId { block_id } => write!(
                formatter,
                "candidate recovery bundle repeats block address {block_id:?}"
            ),
            Self::InvalidPayloadLength {
                entry,
                actual,
                maximum,
            } => write!(
                formatter,
                "candidate recovery bundle entry {entry} payload length {actual} is outside 1..={maximum}"
            ),
            Self::PayloadByteCountOverflow => {
                formatter.write_str("candidate recovery bundle payload byte count overflowed")
            }
            Self::PayloadByteTotalMismatch { declared, actual } => write!(
                formatter,
                "candidate recovery bundle declares {declared} payload bytes but contains {actual}"
            ),
            Self::ParentBlockIdMismatch {
                entry,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate recovery bundle entry {entry} parent is {actual:?}, expected {expected:?}"
            ),
            Self::PreviousArtifactSetRootMismatch {
                entry,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate recovery bundle entry {entry} previous artifact-set root is {actual:?}, expected {expected:?}"
            ),
            Self::TrailingBytes { bytes } => write!(
                formatter,
                "candidate recovery bundle has {bytes} trailing bytes before its digest"
            ),
            Self::TargetBlockIdMismatch { expected, actual } => write!(
                formatter,
                "candidate recovery bundle ends at {actual:?}, expected target {expected:?}"
            ),
        }
    }
}

impl Error for CandidateBranchRecoveryBundleDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BlockDecode { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Exports one exact current-head candidate extension from sealed selected history.
///
/// The immutable chain context is checked before selected-state health. A healthy,
/// non-halted artifact or finality journal supplies the exact current anchor; all
/// candidate blocks and archived payloads are bounded, integrity-read, and fully
/// validated before canonical bytes are returned. This read-only operation grants
/// no selection or finality authority and chooses no target or transport.
pub fn export_candidate_branch_recovery_bundle_v0(
    selected: &dyn SelectedArtifactHistory,
    target_block_id: ArtifactBlockId,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    limits: CandidateBranchRecoveryBundleLimits,
) -> Result<CandidateBranchRecoveryBundleV0, CandidateBranchRecoveryBundleExportError> {
    let selected_chain_id = selected.selected_chain_id();
    if selected_chain_id != candidates.chain_id() {
        return Err(CandidateBranchRecoveryBundleExportError::ChainIdMismatch {
            selected: selected_chain_id,
            candidates: candidates.chain_id(),
        });
    }

    let anchor_block_id = selected
        .selected_head_block_id()
        .map_err(CandidateBranchRecoveryBundleExportError::selected_history_state)?;
    let anchor_snapshot = selected
        .selected_branch_snapshot_at(anchor_block_id)
        .map_err(CandidateBranchRecoveryBundleExportError::selected_history_state)?
        .expect("a healthy current selected head retains its exact snapshot");

    let path = collect_candidate_branch_path(
        target_block_id,
        candidates,
        limits.max_blocks,
        CandidateBranchPathAnchor::ExactSelected {
            block_id: anchor_block_id,
            snapshot: anchor_snapshot,
        },
        |block_id| selected.selected_branch_snapshot_at(block_id),
    )
    .map_err(|error| {
        CandidateBranchRecoveryBundleExportError::from_path(
            error,
            CandidateBranchRecoveryBundleExportError::selected_history_state,
        )
    })?;
    debug_assert_eq!(path.anchor_block_id, anchor_block_id);
    let block_count = path.blocks.len();
    let mut entries = Vec::new();
    entries.try_reserve_exact(block_count).map_err(|_| {
        CandidateBranchRecoveryBundleExportError::EntryAllocation {
            entries: block_count,
        }
    })?;
    entries.extend(path.blocks.into_iter().map(|block| BundleExportEntry {
        block,
        payload: BundleExportPayload::Archive,
        payload_len: 0,
    }));

    encode_recovery_bundle(
        BundleExportContext {
            chain_id: selected_chain_id,
            target_block_id,
            snapshot: path.snapshot,
        },
        entries,
        payloads,
        limits,
    )
}

impl ArtifactChainJournal {
    fn recovery_bundle_chain_id(
        &self,
        candidates: &ArtifactBlockCandidateStore,
    ) -> Result<ArtifactChainId, CandidateBranchRecoveryBundleExportError> {
        let selected = self.chain_id();
        let candidate_chain = candidates.chain_id();
        if selected != candidate_chain {
            return Err(CandidateBranchRecoveryBundleExportError::ChainIdMismatch {
                selected,
                candidates: candidate_chain,
            });
        }
        Ok(selected)
    }

    /// Exports one exact current-head candidate extension as a portable V0 bundle.
    ///
    /// The caller chooses the target. Every block and exact archived payload is
    /// bounded, integrity-read, and strictly validated against the captured
    /// current selected head before the canonical bundle is published.
    pub fn export_candidate_branch_recovery_bundle_v0(
        &self,
        target_block_id: ArtifactBlockId,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        limits: CandidateBranchRecoveryBundleLimits,
    ) -> Result<CandidateBranchRecoveryBundleV0, CandidateBranchRecoveryBundleExportError> {
        export_candidate_branch_recovery_bundle_v0(
            self,
            target_block_id,
            candidates,
            payloads,
            limits,
        )
    }

    /// Exports one exact candidate branch from virtual genesis as a portable V0 bundle.
    ///
    /// The caller chooses an unselected target. Export discovers that candidate's
    /// nearest retained selected ancestor, walks the replay-verified selected
    /// prefix backward to virtual genesis, then strictly validates the combined
    /// selected-prefix and candidate-suffix payloads forward from genesis before
    /// publishing canonical bytes. Selected-prefix payloads come from the
    /// journal's accepted records; only candidate-suffix payloads use `payloads`.
    ///
    /// This operation neither exports later selected history after the candidate's
    /// anchor nor changes any source store. The bundle carries no source-selection,
    /// consensus, finality, or peer-trust authority.
    pub fn export_genesis_anchored_candidate_branch_recovery_bundle_v0(
        &self,
        target_block_id: ArtifactBlockId,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        limits: CandidateBranchRecoveryBundleLimits,
    ) -> Result<CandidateBranchRecoveryBundleV0, CandidateBranchRecoveryBundleExportError> {
        let selected_chain_id = self.recovery_bundle_chain_id(candidates)?;
        let path = collect_candidate_branch_path(
            target_block_id,
            candidates,
            limits.max_blocks,
            CandidateBranchPathAnchor::NearestSelected,
            |block_id| self.branch_snapshot_at(block_id),
        )
        .map_err(|error| {
            CandidateBranchRecoveryBundleExportError::from_path(
                error,
                CandidateBranchRecoveryBundleExportError::selected_state,
            )
        })?;
        let candidate_block_count = path.blocks.len();
        let max_selected_block_count = limits.max_blocks - candidate_block_count;
        let mut next_selected_block_id = path.anchor_block_id;
        let mut entries = Vec::new();

        let genesis_snapshot = loop {
            let selected_block = self
                .block(next_selected_block_id)
                .map_err(CandidateBranchRecoveryBundleExportError::selected_state)?;
            let Some(selected_block) = selected_block else {
                let snapshot = self
                    .branch_snapshot_at(next_selected_block_id)
                    .map_err(CandidateBranchRecoveryBundleExportError::selected_state)?
                    .ok_or(
                        CandidateBranchRecoveryBundleExportError::SelectedPrefixBlockMissing {
                            block_id: next_selected_block_id,
                        },
                    )?;
                if next_selected_block_id != selected_chain_id.virtual_genesis_block_id() {
                    return Err(
                        CandidateBranchRecoveryBundleExportError::SelectedPrefixBlockMissing {
                            block_id: next_selected_block_id,
                        },
                    );
                }
                break snapshot;
            };

            if entries.len() == max_selected_block_count {
                return Err(
                    CandidateBranchRecoveryBundleExportError::BlockLimitExceeded {
                        maximum: limits.max_blocks,
                        next_block_id: next_selected_block_id,
                    },
                );
            }
            let retained_blocks = candidate_block_count + entries.len();
            entries.try_reserve(1).map_err(|_| {
                CandidateBranchRecoveryBundleExportError::SelectedPrefixBufferAllocation {
                    next_block_id: next_selected_block_id,
                    retained_blocks,
                }
            })?;

            let selected_block = *selected_block;
            let artifact_id = selected_block.artifact_id();
            let payload = self
                .artifact(artifact_id)
                .map_err(CandidateBranchRecoveryBundleExportError::selected_state)?
                .ok_or(
                    CandidateBranchRecoveryBundleExportError::SelectedPrefixArtifactMissing {
                        block_id: next_selected_block_id,
                        artifact_id,
                    },
                )?
                .canonical_artifact_bytes();
            entries.push(BundleExportEntry {
                block: selected_block,
                payload: BundleExportPayload::Selected(payload),
                payload_len: 0,
            });
            next_selected_block_id = selected_block.parent_block_id();
        };

        entries.reverse();
        let block_count = entries.len() + candidate_block_count;
        entries
            .try_reserve_exact(candidate_block_count)
            .map_err(
                |_| CandidateBranchRecoveryBundleExportError::EntryAllocation {
                    entries: block_count,
                },
            )?;
        entries.extend(path.blocks.into_iter().map(|block| BundleExportEntry {
            block,
            payload: BundleExportPayload::Archive,
            payload_len: 0,
        }));
        debug_assert_eq!(entries.len(), block_count);

        encode_recovery_bundle(
            BundleExportContext {
                chain_id: selected_chain_id,
                target_block_id,
                snapshot: genesis_snapshot,
            },
            entries,
            payloads,
            limits,
        )
    }

    /// Imports or resumes one exact portable V0 bundle at its captured head.
    ///
    /// The bundle is decoded again under `limits`. The journal must still be at
    /// the original anchor or at an exact already-selected bundle prefix. The
    /// complete branch is strictly validated before the unselected suffix is
    /// applied through ordinary sequential journal commits.
    pub fn import_candidate_branch_recovery_bundle_v0(
        &mut self,
        bundle: &CandidateBranchRecoveryBundleV0,
        limits: CandidateBranchRecoveryBundleLimits,
    ) -> Result<CandidateBranchRecoveryBundleImportOutcome, CandidateBranchRecoveryBundleImportError>
    {
        self.core
            .import_candidate_branch_recovery_bundle_v0(bundle, limits)
    }
}

enum BundleExportPayload<'journal> {
    Selected(&'journal [u8]),
    Archive,
}

struct BundleExportEntry<'journal> {
    block: ArtifactBlock,
    payload: BundleExportPayload<'journal>,
    payload_len: u32,
}

struct BundleExportContext {
    chain_id: ArtifactChainId,
    target_block_id: ArtifactBlockId,
    snapshot: ArtifactChainBranchSnapshot,
}

fn encode_recovery_bundle(
    context: BundleExportContext,
    entries: Vec<BundleExportEntry<'_>>,
    payloads: &mut CanonicalArtifactPayloadStore,
    limits: CandidateBranchRecoveryBundleLimits,
) -> Result<CandidateBranchRecoveryBundleV0, CandidateBranchRecoveryBundleExportError> {
    let BundleExportContext {
        chain_id,
        target_block_id,
        mut snapshot,
    } = context;
    let anchor_block_id = snapshot.head_block_id();
    let anchor_artifact_set_root = snapshot.artifact_set_root();
    let block_count = entries.len();
    let block_count_u32 = u32::try_from(block_count).map_err(|_| {
        CandidateBranchRecoveryBundleExportError::BlockCountOverflow { block_count }
    })?;

    let mut total_payload_bytes = 0_u64;
    let mut entries = entries;
    for entry in &mut entries {
        let block_id = entry.block.id();
        let artifact_id = entry.block.artifact_id();
        let payload_len = match &entry.payload {
            BundleExportPayload::Selected(bytes) => u32::try_from(bytes.len())
                .expect("a replay-accepted artifact payload length fits V0 framing"),
            BundleExportPayload::Archive => payloads
                .indexed_payload_len(artifact_id)
                .map_err(
                    |source| CandidateBranchRecoveryBundleExportError::PayloadStoreRead {
                        block_id,
                        artifact_id,
                        source: Box::new(source),
                    },
                )?
                .ok_or(
                    CandidateBranchRecoveryBundleExportError::PayloadNotRetained {
                        block_id,
                        artifact_id,
                    },
                )?,
        };
        let attempted = total_payload_bytes
            .checked_add(u64::from(payload_len))
            .ok_or(CandidateBranchRecoveryBundleExportError::PayloadByteCountOverflow)?;
        if attempted > limits.max_payload_bytes {
            return Err(
                CandidateBranchRecoveryBundleExportError::PayloadByteLimitExceeded {
                    actual: attempted,
                    maximum: limits.max_payload_bytes,
                    block_id,
                    artifact_id,
                },
            );
        }
        total_payload_bytes = attempted;
        entry.payload_len = payload_len;
    }

    let fixed = u64::try_from(FIXED_METADATA_BYTES + DIGEST_BYTES)
        .expect("fixed recovery bundle framing fits u64");
    let per_entry = u64::try_from(ARTIFACT_BLOCK_BYTES + PAYLOAD_LENGTH_BYTES)
        .expect("fixed recovery bundle entry framing fits u64");
    let encoded_bytes = u64::try_from(block_count)
        .ok()
        .and_then(|count| count.checked_mul(per_entry))
        .and_then(|entry_bytes| fixed.checked_add(entry_bytes))
        .and_then(|bytes| bytes.checked_add(total_payload_bytes))
        .ok_or(CandidateBranchRecoveryBundleExportError::BundleByteCountOverflow)?;
    if encoded_bytes > limits.max_bundle_bytes {
        return Err(
            CandidateBranchRecoveryBundleExportError::BundleByteLimitExceeded {
                actual: encoded_bytes,
                maximum: limits.max_bundle_bytes,
            },
        );
    }
    let encoded_bytes_usize = usize::try_from(encoded_bytes).map_err(|_| {
        CandidateBranchRecoveryBundleExportError::UnsupportedBundleLength {
            bytes: encoded_bytes,
        }
    })?;
    let mut canonical_bytes = Vec::new();
    canonical_bytes
        .try_reserve_exact(encoded_bytes_usize)
        .map_err(
            |_| CandidateBranchRecoveryBundleExportError::BundleAllocation {
                bytes: encoded_bytes_usize,
            },
        )?;
    canonical_bytes.extend_from_slice(BUNDLE_HEADER);
    canonical_bytes.extend_from_slice(chain_id.as_bytes());
    canonical_bytes.extend_from_slice(anchor_block_id.as_bytes());
    canonical_bytes.extend_from_slice(anchor_artifact_set_root.as_bytes());
    canonical_bytes.extend_from_slice(target_block_id.as_bytes());
    canonical_bytes.extend_from_slice(&block_count_u32.to_be_bytes());
    canonical_bytes.extend_from_slice(&total_payload_bytes.to_be_bytes());

    for entry in entries {
        let block = entry.block;
        let block_id = block.id();
        let artifact_id = block.artifact_id();
        let expected_payload_len = entry.payload_len;
        canonical_bytes.extend_from_slice(&block.to_canonical_bytes());
        canonical_bytes.extend_from_slice(&expected_payload_len.to_be_bytes());
        let validation_payload = match entry.payload {
            BundleExportPayload::Selected(payload) => {
                canonical_bytes.extend_from_slice(payload);
                copy_payload(payload).map_err(|bytes| {
                    CandidateBranchRecoveryBundleExportError::PayloadAllocation {
                        block_id,
                        artifact_id,
                        bytes,
                    }
                })?
            }
            BundleExportPayload::Archive => {
                let payload = payloads
                    .get(artifact_id)
                    .map_err(
                        |source| CandidateBranchRecoveryBundleExportError::PayloadStoreRead {
                            block_id,
                            artifact_id,
                            source: Box::new(source),
                        },
                    )?
                    .ok_or(
                        CandidateBranchRecoveryBundleExportError::PayloadNotRetained {
                            block_id,
                            artifact_id,
                        },
                    )?;
                let payload = payload.into_canonical_artifact_bytes().into_vec();
                debug_assert_eq!(payload.len(), expected_payload_len as usize);
                canonical_bytes.extend_from_slice(&payload);
                payload
            }
        };
        debug_assert_eq!(validation_payload.len(), expected_payload_len as usize);
        snapshot = snapshot
            .validate_child(&block, validation_payload)
            .map_err(
                |source| CandidateBranchRecoveryBundleExportError::BlockValidation {
                    block_id,
                    source: Box::new(source),
                },
            )?;
    }
    debug_assert_eq!(snapshot.head_block_id(), target_block_id);

    let digest = bundle_digest(&canonical_bytes);
    canonical_bytes.extend_from_slice(&digest);
    debug_assert_eq!(canonical_bytes.len(), encoded_bytes_usize);

    Ok(CandidateBranchRecoveryBundleV0 {
        canonical_bytes,
        chain_id,
        anchor_block_id,
        anchor_artifact_set_root,
        target_block_id,
        block_count,
        total_payload_bytes,
    })
}

fn copy_payload(bytes: &[u8]) -> Result<Vec<u8>, usize> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| bytes.len())?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

/// A bounded bundle export failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateBranchRecoveryBundleExportError {
    /// The selected journal and candidate store have different chain contexts.
    ChainIdMismatch {
        selected: ArtifactChainId,
        candidates: ArtifactChainId,
    },
    /// The selected journal failed a required health or position read.
    SelectedState {
        source: Box<ArtifactChainJournalError>,
    },
    /// A finality-backed selected history denied a required read.
    SelectedHistoryState {
        source: Box<SelectedArtifactHistoryError>,
    },
    /// The exact caller target is already selected.
    TargetAlreadySelected { block_id: ArtifactBlockId },
    /// Reserving bounded candidate-suffix metadata failed.
    CandidateBufferAllocation {
        next_block_id: ArtifactBlockId,
        retained_blocks: usize,
    },
    /// Reserving bounded selected-prefix metadata failed.
    SelectedPrefixBufferAllocation {
        next_block_id: ArtifactBlockId,
        retained_blocks: usize,
    },
    /// A required selected-prefix block is absent from the selected index.
    SelectedPrefixBlockMissing { block_id: ArtifactBlockId },
    /// A selected block's replay-accepted artifact record is absent.
    SelectedPrefixArtifactMissing {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
    },
    /// An exact candidate-store integrity read failed.
    CandidateStoreRead {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockCandidateStoreError>,
    },
    /// One exact candidate address is absent locally.
    CandidateNotRetained { block_id: ArtifactBlockId },
    /// Adjacent candidate or anchor artifact roots do not join.
    ArtifactSetRootMismatch {
        preceding_block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// A block identity repeats in the retained path.
    RepeatedBlockId { block_id: ArtifactBlockId },
    /// The path reaches selected history other than the required selected anchor.
    DivergentAncestry {
        expected_anchor: ArtifactBlockId,
        encountered: ArtifactBlockId,
    },
    /// The complete retained path does not reach its required anchor within the block bound.
    BlockLimitExceeded {
        maximum: usize,
        next_block_id: ArtifactBlockId,
    },
    /// The retained entry count cannot be encoded in V0's u32 field.
    BlockCountOverflow { block_count: usize },
    /// Reserving bounded bundle-entry metadata failed.
    EntryAllocation { entries: usize },
    /// One exact payload-store integrity read failed.
    PayloadStoreRead {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        source: Box<CanonicalArtifactPayloadStoreError>,
    },
    /// One candidate suffix's exact payload is absent locally.
    PayloadNotRetained {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
    },
    /// Accumulating exact payload lengths overflowed.
    PayloadByteCountOverflow,
    /// Another exact payload would exceed the caller-local payload bound.
    PayloadByteLimitExceeded {
        actual: u64,
        maximum: u64,
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
    },
    /// Computing the complete encoded length overflowed.
    BundleByteCountOverflow,
    /// The complete canonical encoding exceeds the caller-local byte bound.
    BundleByteLimitExceeded { actual: u64, maximum: u64 },
    /// The bounded encoded length cannot be represented on this platform.
    UnsupportedBundleLength { bytes: u64 },
    /// Allocating the complete canonical bundle buffer failed.
    BundleAllocation { bytes: usize },
    /// Copying one selected-prefix payload for immutable validation failed.
    PayloadAllocation {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        bytes: usize,
    },
    /// One block or payload failed complete anchor-relative validation.
    BlockValidation {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockApplyError>,
    },
}

impl CandidateBranchRecoveryBundleExportError {
    fn selected_state(source: ArtifactChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }

    fn selected_history_state(source: SelectedArtifactHistoryError) -> Self {
        match source {
            SelectedArtifactHistoryError::ArtifactChainJournal { source } => {
                Self::SelectedState { source }
            }
            source => Self::SelectedHistoryState {
                source: Box::new(source),
            },
        }
    }

    fn from_path<E>(error: CandidateBranchPathError<E>, selected_error: fn(E) -> Self) -> Self {
        match error {
            CandidateBranchPathError::SelectedState { source } => selected_error(*source),
            CandidateBranchPathError::TargetAlreadySelected { block_id } => {
                Self::TargetAlreadySelected { block_id }
            }
            CandidateBranchPathError::CandidateBufferAllocation {
                next_block_id,
                retained_blocks,
            } => Self::CandidateBufferAllocation {
                next_block_id,
                retained_blocks,
            },
            CandidateBranchPathError::CandidateStoreRead { block_id, source } => {
                Self::CandidateStoreRead { block_id, source }
            }
            CandidateBranchPathError::CandidateNotRetained { block_id } => {
                Self::CandidateNotRetained { block_id }
            }
            CandidateBranchPathError::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            } => Self::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            },
            CandidateBranchPathError::RepeatedBlockId { block_id } => {
                Self::RepeatedBlockId { block_id }
            }
            CandidateBranchPathError::DivergentAncestry {
                expected_anchor,
                encountered,
            } => Self::DivergentAncestry {
                expected_anchor,
                encountered,
            },
            CandidateBranchPathError::BlockLimitExceeded {
                maximum,
                next_block_id,
            } => Self::BlockLimitExceeded {
                maximum,
                next_block_id,
            },
        }
    }
}

impl fmt::Display for CandidateBranchRecoveryBundleExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainIdMismatch {
                selected,
                candidates,
            } => write!(
                formatter,
                "candidate recovery bundle candidate-store chain {candidates:?} does not match selected chain {selected:?}"
            ),
            Self::SelectedState { source } => write!(
                formatter,
                "candidate recovery bundle cannot use selected state: {source}"
            ),
            Self::SelectedHistoryState { source } => write!(
                formatter,
                "candidate recovery bundle cannot use selected history: {source}"
            ),
            Self::TargetAlreadySelected { block_id } => write!(
                formatter,
                "candidate recovery bundle target {block_id:?} is already selected"
            ),
            Self::CandidateBufferAllocation {
                next_block_id,
                retained_blocks,
            } => write!(
                formatter,
                "candidate recovery bundle path after {retained_blocks} blocks could not reserve storage for {next_block_id:?}"
            ),
            Self::SelectedPrefixBufferAllocation {
                next_block_id,
                retained_blocks,
            } => write!(
                formatter,
                "candidate recovery bundle combined path after {retained_blocks} blocks could not reserve selected-prefix storage for {next_block_id:?}"
            ),
            Self::SelectedPrefixBlockMissing { block_id } => write!(
                formatter,
                "candidate recovery bundle selected-prefix block {block_id:?} is absent from selected history"
            ),
            Self::SelectedPrefixArtifactMissing {
                block_id,
                artifact_id,
            } => write!(
                formatter,
                "candidate recovery bundle selected-prefix block {block_id:?} has no replay-accepted artifact record {artifact_id:?}"
            ),
            Self::CandidateStoreRead { block_id, source } => write!(
                formatter,
                "candidate recovery bundle block {block_id:?} could not be read: {source}"
            ),
            Self::CandidateNotRetained { block_id } => write!(
                formatter,
                "candidate recovery bundle block {block_id:?} is not retained"
            ),
            Self::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate recovery bundle after {preceding_block_id:?} expected artifact-set root {expected:?}, actual {actual:?}"
            ),
            Self::RepeatedBlockId { block_id } => write!(
                formatter,
                "candidate recovery bundle path repeats block address {block_id:?}"
            ),
            Self::DivergentAncestry {
                expected_anchor,
                encountered,
            } => write!(
                formatter,
                "candidate recovery bundle expected selected anchor {expected_anchor:?} but encountered selected position {encountered:?}"
            ),
            Self::BlockLimitExceeded {
                maximum,
                next_block_id,
            } => write!(
                formatter,
                "candidate recovery bundle did not reach its required anchor within {maximum} blocks; next block is {next_block_id:?}"
            ),
            Self::BlockCountOverflow { block_count } => write!(
                formatter,
                "candidate recovery bundle block count {block_count} does not fit V0 framing"
            ),
            Self::EntryAllocation { entries } => write!(
                formatter,
                "candidate recovery bundle could not reserve metadata for {entries} entries"
            ),
            Self::PayloadStoreRead {
                block_id,
                artifact_id,
                source,
            } => write!(
                formatter,
                "candidate recovery bundle block {block_id:?} payload {artifact_id:?} could not be read: {source}"
            ),
            Self::PayloadNotRetained {
                block_id,
                artifact_id,
            } => write!(
                formatter,
                "candidate recovery bundle block {block_id:?} payload {artifact_id:?} is not retained"
            ),
            Self::PayloadByteCountOverflow => {
                formatter.write_str("candidate recovery bundle payload byte count overflowed")
            }
            Self::PayloadByteLimitExceeded {
                actual,
                maximum,
                block_id,
                artifact_id,
            } => write!(
                formatter,
                "candidate recovery bundle would retain {actual} payload bytes at block {block_id:?} payload {artifact_id:?}, exceeding limit {maximum}"
            ),
            Self::BundleByteCountOverflow => {
                formatter.write_str("candidate recovery bundle complete byte count overflowed")
            }
            Self::BundleByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "candidate recovery bundle would encode {actual} bytes, exceeding limit {maximum}"
            ),
            Self::UnsupportedBundleLength { bytes } => write!(
                formatter,
                "candidate recovery bundle length {bytes} cannot be represented on this platform"
            ),
            Self::BundleAllocation { bytes } => write!(
                formatter,
                "candidate recovery bundle could not allocate {bytes} canonical bytes"
            ),
            Self::PayloadAllocation {
                block_id,
                artifact_id,
                bytes,
            } => write!(
                formatter,
                "candidate recovery bundle could not allocate {bytes} validation bytes for block {block_id:?} payload {artifact_id:?}"
            ),
            Self::BlockValidation { block_id, source } => write!(
                formatter,
                "candidate recovery bundle block {block_id:?} failed strict export validation: {source}"
            ),
        }
    }
}

impl Error for CandidateBranchRecoveryBundleExportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::SelectedHistoryState { source } => Some(source.as_ref()),
            Self::CandidateStoreRead { source, .. } => Some(source.as_ref()),
            Self::PayloadStoreRead { source, .. } => Some(source.as_ref()),
            Self::BlockValidation { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

struct PreparedBundleEntry {
    block: ArtifactBlock,
    payload: Vec<u8>,
}

impl<F: StoreIo> JournalCore<F> {
    pub(crate) fn import_candidate_branch_recovery_bundle_v0(
        &mut self,
        bundle: &CandidateBranchRecoveryBundleV0,
        limits: CandidateBranchRecoveryBundleLimits,
    ) -> Result<CandidateBranchRecoveryBundleImportOutcome, CandidateBranchRecoveryBundleImportError>
    {
        let decoded = decode_bundle(bundle.canonical_bytes(), limits)
            .map_err(CandidateBranchRecoveryBundleImportError::decode)?;
        let selected_chain_id = self.chain.chain_id();
        if selected_chain_id != decoded.chain_id {
            return Err(CandidateBranchRecoveryBundleImportError::ChainIdMismatch {
                selected: selected_chain_id,
                bundle: decoded.chain_id,
            });
        }
        self.ensure_healthy()
            .map_err(CandidateBranchRecoveryBundleImportError::selected_state)?;

        let current_head = self.chain.head_block_id();
        let current_root = self.chain.artifact_dag().artifact_set_root();
        let anchor_snapshot = self.blocks.snapshot(decoded.anchor_block_id).ok_or(
            CandidateBranchRecoveryBundleImportError::AnchorNotSelected {
                anchor_block_id: decoded.anchor_block_id,
            },
        )?;
        let actual_anchor_root = anchor_snapshot.artifact_set_root();
        if actual_anchor_root != decoded.anchor_artifact_set_root {
            return Err(
                CandidateBranchRecoveryBundleImportError::AnchorArtifactSetRootMismatch {
                    anchor_block_id: decoded.anchor_block_id,
                    expected: decoded.anchor_artifact_set_root,
                    actual: actual_anchor_root,
                },
            );
        }

        let already_selected_block_count = if current_head == decoded.anchor_block_id {
            if current_root != decoded.anchor_artifact_set_root {
                return Err(
                    CandidateBranchRecoveryBundleImportError::SelectedPrefixArtifactSetRootMismatch {
                        block_id: current_head,
                        expected: decoded.anchor_artifact_set_root,
                        actual: current_root,
                    },
                );
            }
            0
        } else {
            let Some(position) = decoded
                .entries
                .iter()
                .position(|entry| entry.block.id() == current_head)
            else {
                return Err(
                    CandidateBranchRecoveryBundleImportError::CurrentHeadNotBundlePrefix {
                        anchor_block_id: decoded.anchor_block_id,
                        target_block_id: decoded.target_block_id,
                        actual: current_head,
                    },
                );
            };
            position + 1
        };

        for entry in &decoded.entries[..already_selected_block_count] {
            let block_id = entry.block.id();
            let selected_block = self.blocks.get(&block_id).ok_or(
                CandidateBranchRecoveryBundleImportError::SelectedPrefixBlockMissing { block_id },
            )?;
            if selected_block != &entry.block {
                return Err(
                    CandidateBranchRecoveryBundleImportError::SelectedPrefixBlockMismatch {
                        block_id,
                    },
                );
            }
            let actual_root = self.blocks.artifact_set_root(block_id).ok_or(
                CandidateBranchRecoveryBundleImportError::SelectedPrefixBlockMissing { block_id },
            )?;
            let expected_root = entry.block.resulting_artifact_set_root();
            if actual_root != expected_root {
                return Err(
                    CandidateBranchRecoveryBundleImportError::SelectedPrefixArtifactSetRootMismatch {
                        block_id,
                        expected: expected_root,
                        actual: actual_root,
                    },
                );
            }
        }
        let expected_current_root = if already_selected_block_count == 0 {
            decoded.anchor_artifact_set_root
        } else {
            decoded.entries[already_selected_block_count - 1]
                .block
                .resulting_artifact_set_root()
        };
        if current_root != expected_current_root {
            return Err(
                CandidateBranchRecoveryBundleImportError::SelectedPrefixArtifactSetRootMismatch {
                    block_id: current_head,
                    expected: expected_current_root,
                    actual: current_root,
                },
            );
        }

        let suffix_count = decoded.entries.len() - already_selected_block_count;
        let mut prepared = Vec::new();
        prepared.try_reserve_exact(suffix_count).map_err(|_| {
            CandidateBranchRecoveryBundleImportError::ImportPlanAllocation {
                entries: suffix_count,
            }
        })?;
        let mut snapshot = anchor_snapshot;
        for (entry_index, entry) in decoded.entries.iter().enumerate() {
            let block_id = entry.block.id();
            let artifact_id = entry.block.artifact_id();
            let payload_bytes = &bundle.canonical_bytes()[entry.payload_range.clone()];
            let validation_payload = copy_payload(payload_bytes).map_err(|bytes| {
                CandidateBranchRecoveryBundleImportError::PayloadAllocation {
                    block_id,
                    artifact_id,
                    bytes,
                }
            })?;
            if entry_index >= already_selected_block_count {
                let commit_payload = copy_payload(payload_bytes).map_err(|bytes| {
                    CandidateBranchRecoveryBundleImportError::PayloadAllocation {
                        block_id,
                        artifact_id,
                        bytes,
                    }
                })?;
                prepared.push(PreparedBundleEntry {
                    block: entry.block,
                    payload: commit_payload,
                });
            }
            snapshot = snapshot
                .validate_child(&entry.block, validation_payload)
                .map_err(
                    |source| CandidateBranchRecoveryBundleImportError::BlockValidation {
                        block_id,
                        source: Box::new(source),
                    },
                )?;
        }
        debug_assert_eq!(snapshot.head_block_id(), decoded.target_block_id);

        self.blocks
            .reserve_entries(suffix_count)
            .map_err(
                |source| CandidateBranchRecoveryBundleImportError::JournalPreparation {
                    source: Box::new(source),
                },
            )?;
        drop(snapshot);

        let resumed_from_block_id = current_head;
        let mut committed_block_count = 0_usize;
        let mut last_acknowledged_head_block_id = current_head;
        for PreparedBundleEntry { block, payload } in prepared {
            let block_id = block.id();
            if let Err(source) = self.apply_block(&block, payload) {
                return Err(CandidateBranchRecoveryBundleImportError::Commit {
                    source: CandidateBranchRecoveryBundleCommitError {
                        target_block_id: decoded.target_block_id,
                        failed_block_id: block_id,
                        committed_block_count,
                        last_acknowledged_head_block_id,
                        source: Box::new(source),
                    },
                });
            }
            committed_block_count += 1;
            last_acknowledged_head_block_id = block_id;
        }
        debug_assert_eq!(last_acknowledged_head_block_id, decoded.target_block_id);

        Ok(CandidateBranchRecoveryBundleImportOutcome {
            anchor_block_id: decoded.anchor_block_id,
            resumed_from_block_id,
            target_block_id: decoded.target_block_id,
            already_selected_block_count,
            committed_block_count,
            total_payload_bytes: decoded.total_payload_bytes,
        })
    }
}

/// A fully validated and acknowledged recovery-bundle import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct CandidateBranchRecoveryBundleImportOutcome {
    anchor_block_id: ArtifactBlockId,
    resumed_from_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    already_selected_block_count: usize,
    committed_block_count: usize,
    total_payload_bytes: u64,
}

impl CandidateBranchRecoveryBundleImportOutcome {
    /// Returns the original exact selected anchor committed by the bundle.
    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.anchor_block_id
    }

    /// Returns the selected head from which this invocation resumed.
    pub const fn resumed_from_block_id(&self) -> ArtifactBlockId {
        self.resumed_from_block_id
    }

    /// Returns the exact caller-selected target now acknowledged.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the number of exact bundle-prefix blocks already selected at start.
    pub const fn already_selected_block_count(&self) -> usize {
        self.already_selected_block_count
    }

    /// Returns the number of new commits acknowledged by this invocation.
    pub const fn committed_block_count(&self) -> usize {
        self.committed_block_count
    }

    /// Returns the complete bundle's logical tagged-payload byte count.
    pub const fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes
    }
}

/// A fail-closed recovery-bundle import failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateBranchRecoveryBundleImportError {
    /// Destination-limit or strict bundle decoding failed.
    Decode {
        source: CandidateBranchRecoveryBundleDecodeError,
    },
    /// The bundle belongs to another artifact-chain context.
    ChainIdMismatch {
        selected: ArtifactChainId,
        bundle: ArtifactChainId,
    },
    /// The selected journal failed its required health check.
    SelectedState {
        source: Box<ArtifactChainJournalError>,
    },
    /// The bundle's original anchor is not retained selected history.
    AnchorNotSelected { anchor_block_id: ArtifactBlockId },
    /// The retained anchor snapshot does not have the bundle's exact root.
    AnchorArtifactSetRootMismatch {
        anchor_block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// The current head is neither the original anchor nor a bundle prefix.
    CurrentHeadNotBundlePrefix {
        anchor_block_id: ArtifactBlockId,
        target_block_id: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// A claimed selected prefix block is absent from the journal index.
    SelectedPrefixBlockMissing { block_id: ArtifactBlockId },
    /// A claimed selected prefix block differs from the bundle block.
    SelectedPrefixBlockMismatch { block_id: ArtifactBlockId },
    /// A selected prefix snapshot has a different authenticated artifact root.
    SelectedPrefixArtifactSetRootMismatch {
        block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// Reserving the complete unselected suffix plan failed.
    ImportPlanAllocation { entries: usize },
    /// Copying one bounded payload for preflight or later commit failed.
    PayloadAllocation {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        bytes: usize,
    },
    /// One block or payload failed complete validation from the original anchor.
    BlockValidation {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockApplyError>,
    },
    /// The selected journal could not reserve its complete suffix index growth.
    JournalPreparation {
        source: Box<ArtifactChainJournalError>,
    },
    /// Sequential application failed after the reported acknowledged suffix.
    Commit {
        source: CandidateBranchRecoveryBundleCommitError,
    },
}

impl CandidateBranchRecoveryBundleImportError {
    fn decode(source: CandidateBranchRecoveryBundleDecodeError) -> Self {
        Self::Decode { source }
    }

    fn selected_state(source: ArtifactChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for CandidateBranchRecoveryBundleImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { source } => {
                write!(
                    formatter,
                    "candidate recovery bundle decode failed: {source}"
                )
            }
            Self::ChainIdMismatch { selected, bundle } => write!(
                formatter,
                "candidate recovery bundle chain {bundle:?} does not match selected chain {selected:?}"
            ),
            Self::SelectedState { source } => write!(
                formatter,
                "candidate recovery bundle cannot use selected state: {source}"
            ),
            Self::AnchorNotSelected { anchor_block_id } => write!(
                formatter,
                "candidate recovery bundle anchor {anchor_block_id:?} is not retained selected history"
            ),
            Self::AnchorArtifactSetRootMismatch {
                anchor_block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate recovery bundle anchor {anchor_block_id:?} commits artifact-set root {expected:?}, selected snapshot has {actual:?}"
            ),
            Self::CurrentHeadNotBundlePrefix {
                anchor_block_id,
                target_block_id,
                actual,
            } => write!(
                formatter,
                "selected head {actual:?} is neither candidate recovery bundle anchor {anchor_block_id:?} nor an exact prefix through target {target_block_id:?}"
            ),
            Self::SelectedPrefixBlockMissing { block_id } => write!(
                formatter,
                "candidate recovery bundle prefix block {block_id:?} is absent from selected history"
            ),
            Self::SelectedPrefixBlockMismatch { block_id } => write!(
                formatter,
                "candidate recovery bundle prefix block {block_id:?} differs from selected history"
            ),
            Self::SelectedPrefixArtifactSetRootMismatch {
                block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate recovery bundle selected prefix at {block_id:?} expected artifact-set root {expected:?}, actual {actual:?}"
            ),
            Self::ImportPlanAllocation { entries } => write!(
                formatter,
                "candidate recovery bundle could not reserve an import plan for {entries} entries"
            ),
            Self::PayloadAllocation {
                block_id,
                artifact_id,
                bytes,
            } => write!(
                formatter,
                "candidate recovery bundle could not allocate {bytes} bytes for block {block_id:?} payload {artifact_id:?} preflight"
            ),
            Self::BlockValidation { block_id, source } => write!(
                formatter,
                "candidate recovery bundle block {block_id:?} failed strict import preflight: {source}"
            ),
            Self::JournalPreparation { source } => write!(
                formatter,
                "candidate recovery bundle could not reserve selected journal capacity: {source}"
            ),
            Self::Commit { source } => write!(formatter, "{source}"),
        }
    }
}

impl Error for CandidateBranchRecoveryBundleImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode { source } => Some(source),
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::BlockValidation { source, .. } => Some(source.as_ref()),
            Self::JournalPreparation { source } => Some(source.as_ref()),
            Self::Commit { source } => Some(source),
            _ => None,
        }
    }
}

/// A sequential journal failure with the exact newly acknowledged suffix.
#[derive(Debug)]
pub struct CandidateBranchRecoveryBundleCommitError {
    target_block_id: ArtifactBlockId,
    failed_block_id: ArtifactBlockId,
    committed_block_count: usize,
    last_acknowledged_head_block_id: ArtifactBlockId,
    source: Box<ArtifactChainJournalError>,
}

impl CandidateBranchRecoveryBundleCommitError {
    /// Returns the exact bundle target.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the block whose commit this invocation did not observe succeeding.
    pub const fn failed_block_id(&self) -> ArtifactBlockId {
        self.failed_block_id
    }

    /// Returns the number of new commits this invocation observed succeeding.
    pub const fn committed_block_count(&self) -> usize {
        self.committed_block_count
    }

    /// Returns the last selected head this invocation observed being acknowledged.
    pub const fn last_acknowledged_head_block_id(&self) -> ArtifactBlockId {
        self.last_acknowledged_head_block_id
    }

    /// Returns the underlying selected-journal failure.
    pub fn journal_error(&self) -> &ArtifactChainJournalError {
        &self.source
    }
}

impl fmt::Display for CandidateBranchRecoveryBundleCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate branch recovery bundle commit failed at {:?} after {} acknowledged commits ending at {:?}: {}",
            self.failed_block_id,
            self.committed_block_count,
            self.last_acknowledged_head_block_id,
            self.source
        )
    }
}

impl Error for CandidateBranchRecoveryBundleCommitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}
