use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, SeekFrom, Write};
use std::path::Path;

use naome_chain::{
    PROOF_BLOCK_MAX_BYTES, ProofBlock, ProofBlockDecodeError, ProofBlockId, ProofChainDefinition,
    ProofChainId,
};

use crate::{AppendPhase, ExclusiveLockError, PROOF_BLOCK_MIN_BYTES, StoreIo, open_exclusive_lock};

const LOCK_FILE_NAME: &str = "proof-block-candidate-store.lock";
const STORE_FILE_NAME: &str = "proof-block-candidate-store.log";
const STORE_HEADER: &[u8] = b"naome:proof-block-candidate-store\0";
const CHAIN_ID_BYTES: u64 = ProofChainId::BYTE_LENGTH as u64;
const BLOCK_LENGTH_BYTES: u64 = 2;
const BLOCK_ID_BYTES: u64 = ProofBlockId::BYTE_LENGTH as u64;
const ENTRY_FIXED_BYTES: u64 = BLOCK_LENGTH_BYTES + BLOCK_ID_BYTES;
const STORE_PREFIX_BYTES: u64 = STORE_HEADER.len() as u64 + CHAIN_ID_BYTES;

/// Local resource limits for one proof-block candidate store handle.
///
/// Limits are caller policy rather than persisted identity. Reopening the same
/// store with different positive limits is allowed if its complete committed
/// contents fit those limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofBlockCandidateStoreLimits {
    max_entries: usize,
    max_total_block_bytes: u64,
}

impl ProofBlockCandidateStoreLimits {
    /// Constructs positive entry-count and aggregate canonical-block limits.
    pub const fn new(
        max_entries: usize,
        max_total_block_bytes: u64,
    ) -> Result<Self, ProofBlockCandidateStoreLimitsError> {
        if max_entries == 0 {
            return Err(ProofBlockCandidateStoreLimitsError::ZeroMaxEntries);
        }
        if max_total_block_bytes == 0 {
            return Err(ProofBlockCandidateStoreLimitsError::ZeroMaxTotalBlockBytes);
        }
        Ok(Self {
            max_entries,
            max_total_block_bytes,
        })
    }

    /// Returns the maximum number of retained candidates.
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Returns the maximum aggregate canonical block bytes.
    pub const fn max_total_block_bytes(&self) -> u64 {
        self.max_total_block_bytes
    }
}

/// A rejected proof-block candidate store limit configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofBlockCandidateStoreLimitsError {
    /// At least one retained entry must be permitted.
    ZeroMaxEntries,
    /// At least one canonical block byte must be permitted.
    ZeroMaxTotalBlockBytes,
}

impl fmt::Display for ProofBlockCandidateStoreLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxEntries => {
                formatter.write_str("proof-block candidate store entry limit must be positive")
            }
            Self::ZeroMaxTotalBlockBytes => formatter.write_str(
                "proof-block candidate store aggregate block-byte limit must be positive",
            ),
        }
    }
}

impl Error for ProofBlockCandidateStoreLimitsError {}

/// The result of inserting one structural proof-block candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum ProofBlockCandidateInsertOutcome {
    /// A new immutable candidate was durably appended.
    Inserted,
    /// The same block identity and exact canonical bytes were already retained.
    AlreadyPresent,
}

/// An exclusively opened append-only store of structural proof-block candidates.
///
/// The store is bound to one exact [`ProofChainDefinition`] and accepts typed
/// canonical [`ProofBlock`] values. It deliberately performs no parent lookup,
/// proof execution, chain selection, fork choice, networking, or consensus.
///
/// A commit I/O error poisons the handle because the durable outcome is then
/// ambiguous. A post-open read or integrity failure also poisons it because the
/// retained offset index can no longer be trusted. Dropping and reopening is
/// the only recovery path.
#[must_use]
pub struct ProofBlockCandidateStore {
    _lock: File,
    core: ProofBlockCandidateStoreCore<File>,
}

impl ProofBlockCandidateStore {
    /// Creates and exclusively opens a new empty store for `definition`.
    ///
    /// Creation never replaces an existing store. The chain-scoped prefix is
    /// synchronized before this function succeeds. Portable parent-directory
    /// entry durability remains the caller's provisioning responsibility.
    pub fn create(
        directory: impl AsRef<Path>,
        definition: ProofChainDefinition,
        limits: ProofBlockCandidateStoreLimits,
    ) -> Result<Self, ProofBlockCandidateStoreError> {
        let directory = directory.as_ref();
        let lock = open_and_lock(directory)?;
        let store_path = directory.join(STORE_FILE_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(store_path)
            .map_err(|source| ProofBlockCandidateStoreError::Create { source })?;
        let chain_id = definition.id();

        file.write_all(STORE_HEADER)
            .and_then(|()| file.write_all(chain_id.as_bytes()))
            .and_then(|()| file.sync_all())
            .map_err(|source| ProofBlockCandidateStoreError::Create { source })?;

        Ok(Self {
            _lock: lock,
            core: ProofBlockCandidateStoreCore::empty(file, chain_id, limits),
        })
    }

    /// Exclusively opens, verifies, and recovers an existing candidate store.
    ///
    /// Replay retains only a block-address/offset index. One framing-incomplete
    /// final entry is truncated to the preceding committed boundary. Complete
    /// malformed, corrupt, or duplicate entries fail closed.
    pub fn open(
        directory: impl AsRef<Path>,
        expected_definition: ProofChainDefinition,
        limits: ProofBlockCandidateStoreLimits,
    ) -> Result<Self, ProofBlockCandidateStoreError> {
        let directory = directory.as_ref();
        let lock = open_and_lock(directory)?;
        let store_path = directory.join(STORE_FILE_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(store_path)
            .map_err(|source| ProofBlockCandidateStoreError::Open { source })?;
        let core = ProofBlockCandidateStoreCore::replay(file, expected_definition.id(), limits)?;
        Ok(Self { _lock: lock, core })
    }

    /// Durably retains one typed canonical block as a structural candidate.
    ///
    /// Repeating the exact block is idempotent even at configured capacity.
    /// Its parent and transition are not evaluated against any chain state.
    pub fn insert(
        &mut self,
        block: &ProofBlock,
    ) -> Result<ProofBlockCandidateInsertOutcome, ProofBlockCandidateStoreError> {
        self.core.insert(block)
    }

    /// Loads one owned, structurally checked canonical block candidate.
    ///
    /// Storage does not establish that its parent exists, its transition is
    /// executable, or that the block is selected, preferred, or finalized.
    pub fn get(
        &mut self,
        block_id: ProofBlockId,
    ) -> Result<Option<ProofBlock>, ProofBlockCandidateStoreError> {
        self.core.get(block_id)
    }

    /// Returns whether an exact block address is indexed.
    pub fn contains(&self, block_id: ProofBlockId) -> Result<bool, ProofBlockCandidateStoreError> {
        self.core.ensure_healthy()?;
        Ok(self.core.index.contains_key(&block_id))
    }

    /// Returns the number of uniquely retained block candidates.
    pub fn len(&self) -> Result<usize, ProofBlockCandidateStoreError> {
        self.core.ensure_healthy()?;
        Ok(self.core.index.len())
    }

    /// Returns whether no block candidates are retained.
    pub fn is_empty(&self) -> Result<bool, ProofBlockCandidateStoreError> {
        self.core.ensure_healthy()?;
        Ok(self.core.index.is_empty())
    }

    /// Returns the aggregate canonical bytes of uniquely retained blocks.
    pub fn total_block_bytes(&self) -> Result<u64, ProofBlockCandidateStoreError> {
        self.core.ensure_healthy()?;
        Ok(self.core.total_block_bytes)
    }

    /// Returns the exact chain context bound into this store.
    pub const fn chain_id(&self) -> ProofChainId {
        self.core.chain_id
    }

    /// Returns the local resource policy used by this handle.
    pub const fn limits(&self) -> ProofBlockCandidateStoreLimits {
        self.core.limits
    }
}

fn open_and_lock(directory: &Path) -> Result<File, ProofBlockCandidateStoreError> {
    open_exclusive_lock(directory, LOCK_FILE_NAME).map_err(|error| match error {
        ExclusiveLockError::LockFile(source) => ProofBlockCandidateStoreError::LockFile { source },
        ExclusiveLockError::Locked => ProofBlockCandidateStoreError::Locked,
        ExclusiveLockError::Lock(source) => ProofBlockCandidateStoreError::Lock { source },
    })
}

struct ProofBlockCandidateStoreCore<F> {
    file: F,
    chain_id: ProofChainId,
    index: HashMap<ProofBlockId, u64>,
    total_block_bytes: u64,
    committed_end: u64,
    limits: ProofBlockCandidateStoreLimits,
    poisoned: bool,
}

impl<F: StoreIo> ProofBlockCandidateStoreCore<F> {
    fn empty(file: F, chain_id: ProofChainId, limits: ProofBlockCandidateStoreLimits) -> Self {
        Self {
            file,
            chain_id,
            index: HashMap::new(),
            total_block_bytes: 0,
            committed_end: STORE_PREFIX_BYTES,
            limits,
            poisoned: false,
        }
    }

    fn replay(
        mut file: F,
        expected_chain_id: ProofChainId,
        limits: ProofBlockCandidateStoreLimits,
    ) -> Result<Self, ProofBlockCandidateStoreError> {
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|source| ProofBlockCandidateStoreError::Read { offset: 0, source })?;
        if file_len < STORE_PREFIX_BYTES {
            return Err(ProofBlockCandidateStoreError::InvalidHeader);
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|source| ProofBlockCandidateStoreError::Read { offset: 0, source })?;
        let mut header = [0_u8; STORE_HEADER.len()];
        read_field(&mut file, &mut header, 0)?;
        if header != STORE_HEADER {
            return Err(ProofBlockCandidateStoreError::InvalidHeader);
        }
        let mut chain_id_bytes = [0_u8; ProofChainId::BYTE_LENGTH];
        read_field(&mut file, &mut chain_id_bytes, STORE_HEADER.len() as u64)?;
        let actual_chain_id = ProofChainId::from_bytes(chain_id_bytes);
        if actual_chain_id != expected_chain_id {
            return Err(ProofBlockCandidateStoreError::ChainIdMismatch {
                expected: expected_chain_id,
                actual: actual_chain_id,
            });
        }

        let mut index = HashMap::new();
        let mut total_block_bytes = 0_u64;
        let mut entry_start = STORE_PREFIX_BYTES;
        let mut entry = 0_u64;
        let mut block_buffer = [0_u8; PROOF_BLOCK_MAX_BYTES];

        while entry_start < file_len {
            let remaining = file_len - entry_start;
            if remaining < BLOCK_LENGTH_BYTES {
                return Self::finish_replay(
                    file,
                    actual_chain_id,
                    index,
                    total_block_bytes,
                    entry_start,
                    limits,
                    Some(entry_start),
                );
            }

            let mut block_length_bytes = [0_u8; BLOCK_LENGTH_BYTES as usize];
            read_field(&mut file, &mut block_length_bytes, entry_start)?;
            let block_len = u16::from_be_bytes(block_length_bytes);
            if (block_len as usize) < PROOF_BLOCK_MIN_BYTES
                || (block_len as usize) > PROOF_BLOCK_MAX_BYTES
            {
                return Err(ProofBlockCandidateStoreError::InvalidBlockLength {
                    entry,
                    offset: entry_start,
                    actual: block_len,
                    minimum: PROOF_BLOCK_MIN_BYTES as u16,
                    maximum: PROOF_BLOCK_MAX_BYTES as u16,
                });
            }

            let entry_len = ENTRY_FIXED_BYTES + u64::from(block_len);
            let entry_end = entry_start.checked_add(entry_len).ok_or(
                ProofBlockCandidateStoreError::EntryOffsetOverflow {
                    entry,
                    offset: entry_start,
                },
            )?;
            if file_len < entry_end {
                return Self::finish_replay(
                    file,
                    actual_chain_id,
                    index,
                    total_block_bytes,
                    entry_start,
                    limits,
                    Some(entry_start),
                );
            }

            let block_offset = entry_start + BLOCK_LENGTH_BYTES;
            let block_bytes = &mut block_buffer[..block_len as usize];
            read_field(&mut file, block_bytes, block_offset)?;
            let block = ProofBlock::from_canonical_bytes(block_bytes).map_err(|source| {
                ProofBlockCandidateStoreError::InvalidBlock {
                    entry,
                    offset: block_offset,
                    source,
                }
            })?;
            let actual_block_id = block.id();

            let footer_offset = block_offset + u64::from(block_len);
            let mut stored_id_bytes = [0_u8; ProofBlockId::BYTE_LENGTH];
            read_field(&mut file, &mut stored_id_bytes, footer_offset)?;
            let stored_block_id = ProofBlockId::from_bytes(stored_id_bytes);
            if stored_block_id != actual_block_id {
                return Err(ProofBlockCandidateStoreError::BlockIdMismatch {
                    entry,
                    offset: entry_start,
                    stored: stored_block_id,
                    actual: actual_block_id,
                });
            }
            if index.contains_key(&actual_block_id) {
                return Err(ProofBlockCandidateStoreError::DuplicateBlockId {
                    entry,
                    offset: entry_start,
                    block_id: actual_block_id,
                });
            }

            let actual_entries = index
                .len()
                .checked_add(1)
                .ok_or(ProofBlockCandidateStoreError::EntryCountOverflow)?;
            if actual_entries > limits.max_entries {
                return Err(ProofBlockCandidateStoreError::EntryLimitExceeded {
                    actual: actual_entries,
                    maximum: limits.max_entries,
                });
            }
            let actual_block_bytes = total_block_bytes
                .checked_add(u64::from(block_len))
                .ok_or(ProofBlockCandidateStoreError::BlockByteCountOverflow)?;
            if actual_block_bytes > limits.max_total_block_bytes {
                return Err(ProofBlockCandidateStoreError::BlockByteLimitExceeded {
                    actual: actual_block_bytes,
                    maximum: limits.max_total_block_bytes,
                });
            }

            reserve_index_entry(&mut index, entry)?;
            let replaced = index.insert(actual_block_id, entry_start);
            debug_assert!(replaced.is_none());
            total_block_bytes = actual_block_bytes;
            entry_start = entry_end;
            entry += 1;
        }

        Self::finish_replay(
            file,
            actual_chain_id,
            index,
            total_block_bytes,
            entry_start,
            limits,
            None,
        )
    }

    fn finish_replay(
        mut file: F,
        chain_id: ProofChainId,
        index: HashMap<ProofBlockId, u64>,
        total_block_bytes: u64,
        committed_end: u64,
        limits: ProofBlockCandidateStoreLimits,
        recovery_offset: Option<u64>,
    ) -> Result<Self, ProofBlockCandidateStoreError> {
        if let Some(offset) = recovery_offset {
            recover_tail(&mut file, offset)?;
        } else {
            file.sync_all()
                .map_err(|source| ProofBlockCandidateStoreError::Stabilize { source })?;
        }
        Ok(Self {
            file,
            chain_id,
            index,
            total_block_bytes,
            committed_end,
            limits,
            poisoned: false,
        })
    }

    fn insert(
        &mut self,
        block: &ProofBlock,
    ) -> Result<ProofBlockCandidateInsertOutcome, ProofBlockCandidateStoreError> {
        self.ensure_healthy()?;
        let block_id = block.id();

        if let Some(entry_offset) = self.index.get(&block_id).copied() {
            let stored = match read_stored_block(&mut self.file, entry_offset, block_id) {
                Ok(stored) => stored,
                Err(error) => return Err(self.poison_stored_read(block_id, error)),
            };
            return if stored == *block {
                Ok(ProofBlockCandidateInsertOutcome::AlreadyPresent)
            } else {
                Err(ProofBlockCandidateStoreError::BlockConflict { block_id })
            };
        }

        let actual_entries = self
            .index
            .len()
            .checked_add(1)
            .ok_or(ProofBlockCandidateStoreError::EntryCountOverflow)?;
        if actual_entries > self.limits.max_entries {
            return Err(ProofBlockCandidateStoreError::EntryLimitExceeded {
                actual: actual_entries,
                maximum: self.limits.max_entries,
            });
        }

        let block_bytes = block.to_canonical_bytes();
        let block_len =
            u16::try_from(block_bytes.len()).expect("a canonical proof block length fits u16");
        let actual_block_bytes = self
            .total_block_bytes
            .checked_add(u64::from(block_len))
            .ok_or(ProofBlockCandidateStoreError::BlockByteCountOverflow)?;
        if actual_block_bytes > self.limits.max_total_block_bytes {
            return Err(ProofBlockCandidateStoreError::BlockByteLimitExceeded {
                actual: actual_block_bytes,
                maximum: self.limits.max_total_block_bytes,
            });
        }

        let entry = u64::try_from(self.index.len()).expect("candidate index length fits u64");
        reserve_index_entry(&mut self.index, entry)?;
        let entry_offset = self.committed_end;
        let entry_end = entry_offset
            .checked_add(ENTRY_FIXED_BYTES + u64::from(block_len))
            .ok_or(ProofBlockCandidateStoreError::EntryOffsetOverflow {
                entry,
                offset: entry_offset,
            })?;
        let block_length_bytes = block_len.to_be_bytes();

        let actual_end = match self.file.seek(SeekFrom::End(0)) {
            Ok(actual_end) => actual_end,
            Err(source) => {
                self.poisoned = true;
                return Err(ProofBlockCandidateStoreError::Commit {
                    block_id,
                    block_bytes: block_bytes.len(),
                    source,
                });
            }
        };
        if actual_end != entry_offset {
            self.poisoned = true;
            return Err(ProofBlockCandidateStoreError::StoreLengthChanged {
                expected: entry_offset,
                actual: actual_end,
            });
        }

        let commit_result = (|| -> io::Result<()> {
            self.file
                .append_write_all(AppendPhase::Body, &block_length_bytes)?;
            self.file
                .append_write_all(AppendPhase::Body, &block_bytes)?;
            self.file.append_sync_all(AppendPhase::Body)?;
            self.file
                .append_write_all(AppendPhase::Commit, block_id.as_bytes())?;
            self.file.append_sync_all(AppendPhase::Commit)?;
            Ok(())
        })();

        if let Err(source) = commit_result {
            self.poisoned = true;
            return Err(ProofBlockCandidateStoreError::Commit {
                block_id,
                block_bytes: block_bytes.len(),
                source,
            });
        }

        let replaced = self.index.insert(block_id, entry_offset);
        debug_assert!(replaced.is_none());
        self.total_block_bytes = actual_block_bytes;
        self.committed_end = entry_end;
        Ok(ProofBlockCandidateInsertOutcome::Inserted)
    }

    fn get(
        &mut self,
        block_id: ProofBlockId,
    ) -> Result<Option<ProofBlock>, ProofBlockCandidateStoreError> {
        self.ensure_healthy()?;
        let Some(entry_offset) = self.index.get(&block_id).copied() else {
            return Ok(None);
        };
        let block = match read_stored_block(&mut self.file, entry_offset, block_id) {
            Ok(block) => block,
            Err(error) => return Err(self.poison_stored_read(block_id, error)),
        };
        Ok(Some(block))
    }

    fn poison_stored_read(
        &mut self,
        block_id: ProofBlockId,
        error: StoredReadError,
    ) -> ProofBlockCandidateStoreError {
        self.poisoned = true;
        match error {
            StoredReadError::Io { offset, source } => {
                ProofBlockCandidateStoreError::Read { offset, source }
            }
            StoredReadError::Changed => {
                ProofBlockCandidateStoreError::StoredEntryChanged { block_id }
            }
        }
    }

    fn ensure_healthy(&self) -> Result<(), ProofBlockCandidateStoreError> {
        if self.poisoned {
            Err(ProofBlockCandidateStoreError::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn reserve_index_entry(
    index: &mut HashMap<ProofBlockId, u64>,
    entry: u64,
) -> Result<(), ProofBlockCandidateStoreError> {
    index
        .try_reserve(1)
        .map_err(|_| ProofBlockCandidateStoreError::IndexAllocation { entry })
}

fn recover_tail<F: StoreIo>(
    file: &mut F,
    offset: u64,
) -> Result<(), ProofBlockCandidateStoreError> {
    file.set_len(offset)
        .and_then(|()| file.sync_all())
        .map_err(|source| ProofBlockCandidateStoreError::Recovery { offset, source })
}

fn read_field<F: StoreIo>(
    file: &mut F,
    bytes: &mut [u8],
    offset: u64,
) -> Result<(), ProofBlockCandidateStoreError> {
    file.read_exact(bytes)
        .map_err(|source| ProofBlockCandidateStoreError::Read { offset, source })
}

#[derive(Debug)]
enum StoredReadError {
    Io { offset: u64, source: io::Error },
    Changed,
}

fn read_stored_block<F: StoreIo>(
    file: &mut F,
    entry_offset: u64,
    expected_block_id: ProofBlockId,
) -> Result<ProofBlock, StoredReadError> {
    file.seek(SeekFrom::Start(entry_offset))
        .map_err(|source| StoredReadError::Io {
            offset: entry_offset,
            source,
        })?;
    let mut block_length_bytes = [0_u8; BLOCK_LENGTH_BYTES as usize];
    file.read_exact(&mut block_length_bytes)
        .map_err(|source| StoredReadError::Io {
            offset: entry_offset,
            source,
        })?;
    let block_len = u16::from_be_bytes(block_length_bytes) as usize;
    if !(PROOF_BLOCK_MIN_BYTES..=PROOF_BLOCK_MAX_BYTES).contains(&block_len) {
        return Err(StoredReadError::Changed);
    }

    let mut block_buffer = [0_u8; PROOF_BLOCK_MAX_BYTES];
    let block_bytes = &mut block_buffer[..block_len];
    let block_offset = entry_offset + BLOCK_LENGTH_BYTES;
    file.read_exact(block_bytes)
        .map_err(|source| StoredReadError::Io {
            offset: block_offset,
            source,
        })?;
    let block =
        ProofBlock::from_canonical_bytes(block_bytes).map_err(|_| StoredReadError::Changed)?;
    if block.id() != expected_block_id {
        return Err(StoredReadError::Changed);
    }

    let footer_offset = block_offset + block_len as u64;
    let mut stored_id_bytes = [0_u8; ProofBlockId::BYTE_LENGTH];
    file.read_exact(&mut stored_id_bytes)
        .map_err(|source| StoredReadError::Io {
            offset: footer_offset,
            source,
        })?;
    if ProofBlockId::from_bytes(stored_id_bytes) != expected_block_id {
        return Err(StoredReadError::Changed);
    }
    Ok(block)
}

/// A fail-closed proof-block candidate store error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProofBlockCandidateStoreError {
    /// The sidecar lock file could not be opened.
    LockFile { source: io::Error },
    /// Another process or handle already owns the candidate-store lock.
    Locked,
    /// The operating-system file lock could not be acquired.
    Lock { source: io::Error },
    /// A new candidate-store file could not be created or initialized.
    Create { source: io::Error },
    /// An existing candidate-store file could not be opened.
    Open { source: io::Error },
    /// Existing candidate-store bytes could not be read.
    Read { offset: u64, source: io::Error },
    /// The store header is incomplete or unsupported.
    InvalidHeader,
    /// The store belongs to a different exact proof-chain definition.
    ChainIdMismatch {
        expected: ProofChainId,
        actual: ProofChainId,
    },
    /// A complete entry declares an impossible canonical block length.
    InvalidBlockLength {
        entry: u64,
        offset: u64,
        actual: u16,
        minimum: u16,
        maximum: u16,
    },
    /// An entry boundary cannot be represented safely.
    EntryOffsetOverflow { entry: u64, offset: u64 },
    /// A complete entry contains a malformed canonical block.
    InvalidBlock {
        entry: u64,
        offset: u64,
        source: ProofBlockDecodeError,
    },
    /// A complete entry footer does not match its canonical block address.
    BlockIdMismatch {
        entry: u64,
        offset: u64,
        stored: ProofBlockId,
        actual: ProofBlockId,
    },
    /// A committed log contains the same immutable block address twice.
    DuplicateBlockId {
        entry: u64,
        offset: u64,
        block_id: ProofBlockId,
    },
    /// Counting one more indexed entry overflowed the platform range.
    EntryCountOverflow,
    /// The complete committed store exceeds the local entry-count policy.
    EntryLimitExceeded { actual: usize, maximum: usize },
    /// Summing complete committed block lengths overflowed `u64`.
    BlockByteCountOverflow,
    /// The complete committed store exceeds the local aggregate-byte policy.
    BlockByteLimitExceeded { actual: u64, maximum: u64 },
    /// Reserving one bounded index slot failed.
    IndexAllocation { entry: u64 },
    /// One address is already durably associated with different exact bytes.
    BlockConflict { block_id: ProofBlockId },
    /// The visible log length changed after this handle established its index.
    StoreLengthChanged { expected: u64, actual: u64 },
    /// A previously indexed entry changed or failed its structural check.
    StoredEntryChanged { block_id: ProofBlockId },
    /// An incomplete final entry could not be removed durably.
    Recovery { offset: u64, source: io::Error },
    /// A fully replayed visible store image could not be stabilized.
    Stabilize { source: io::Error },
    /// Commit durability is unknown and the handle is now poisoned.
    Commit {
        block_id: ProofBlockId,
        block_bytes: usize,
        source: io::Error,
    },
    /// Memory may disagree with durable storage after an ambiguous operation.
    Poisoned,
}

impl fmt::Display for ProofBlockCandidateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockFile { source } => {
                write!(formatter, "block candidate store lock failed: {source}")
            }
            Self::Locked => {
                formatter.write_str("proof-block candidate store is already exclusively open")
            }
            Self::Lock { source } => {
                write!(formatter, "block candidate store locking failed: {source}")
            }
            Self::Create { source } => {
                write!(formatter, "block candidate store creation failed: {source}")
            }
            Self::Open { source } => {
                write!(formatter, "block candidate store opening failed: {source}")
            }
            Self::Read { offset, source } => write!(
                formatter,
                "block candidate store read failed at byte {offset}: {source}"
            ),
            Self::InvalidHeader => formatter.write_str("invalid proof-block candidate store header"),
            Self::ChainIdMismatch { expected, actual } => write!(
                formatter,
                "proof-block candidate store chain mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::InvalidBlockLength {
                entry,
                offset,
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "block candidate store entry {entry} at byte {offset} has block length {actual}, expected {minimum}..={maximum}"
            ),
            Self::EntryOffsetOverflow { entry, offset } => write!(
                formatter,
                "block candidate store entry {entry} at byte {offset} exceeds the offset range"
            ),
            Self::InvalidBlock {
                entry,
                offset,
                source,
            } => write!(
                formatter,
                "block candidate store entry {entry} at byte {offset} is invalid: {source}"
            ),
            Self::BlockIdMismatch {
                entry,
                offset,
                stored,
                actual,
            } => write!(
                formatter,
                "block candidate store entry {entry} at byte {offset} has footer {stored:?}, expected {actual:?}"
            ),
            Self::DuplicateBlockId {
                entry,
                offset,
                block_id,
            } => write!(
                formatter,
                "block candidate store entry {entry} at byte {offset} duplicates block {block_id:?}"
            ),
            Self::EntryCountOverflow => {
                formatter.write_str("proof-block candidate store entry count overflowed")
            }
            Self::EntryLimitExceeded { actual, maximum } => write!(
                formatter,
                "proof-block candidate store has {actual} entries, exceeding limit {maximum}"
            ),
            Self::BlockByteCountOverflow => {
                formatter.write_str("proof-block candidate store byte count overflowed")
            }
            Self::BlockByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "proof-block candidate store has {actual} canonical block bytes, exceeding limit {maximum}"
            ),
            Self::IndexAllocation { entry } => write!(
                formatter,
                "block candidate store entry {entry} could not reserve its index slot"
            ),
            Self::BlockConflict { block_id } => write!(
                formatter,
                "proof block {block_id:?} is already associated with different bytes"
            ),
            Self::StoreLengthChanged { expected, actual } => write!(
                formatter,
                "proof-block candidate store length changed after open: expected {expected} bytes, actual {actual} bytes"
            ),
            Self::StoredEntryChanged { block_id } => write!(
                formatter,
                "indexed proof block {block_id:?} changed after candidate store open"
            ),
            Self::Recovery { offset, source } => write!(
                formatter,
                "incomplete block candidate store tail at byte {offset} could not be recovered: {source}"
            ),
            Self::Stabilize { source } => {
                write!(formatter, "block candidate store stabilization failed: {source}")
            }
            Self::Commit {
                block_id,
                block_bytes,
                source,
            } => write!(
                formatter,
                "block candidate store commit of {block_id:?} with {block_bytes} bytes has unknown durability: {source}"
            ),
            Self::Poisoned => formatter.write_str(
                "block candidate store is poisoned after an ambiguous operation; drop and reopen it",
            ),
        }
    }
}

impl Error for ProofBlockCandidateStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LockFile { source }
            | Self::Lock { source }
            | Self::Create { source }
            | Self::Open { source }
            | Self::Read { source, .. }
            | Self::Recovery { source, .. }
            | Self::Stabilize { source }
            | Self::Commit { source, .. } => Some(source),
            Self::InvalidBlock { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
