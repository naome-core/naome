//! Crash-consistent local persistence for NAOME proof-chain state and payloads.
//!
//! [`ProofChainJournal`] stores canonical [`ProofBlock`] values together with
//! the exact canonical proof payloads committed by each block. Opening a
//! journal reconstructs the block head and complete selected proof DAG through
//! strict [`ProofChainState`] replay; persisted bytes never bypass block or
//! proof validation. One exact-parent block may also be validated read-only;
//! durable application always revalidates before selection and commit.
//!
//! [`CanonicalProofPayloadStore`] separately archives exact payload bytes from
//! accepted proof records without making them selected or reusable as checked
//! records. Consumers must validate loaded bytes again in their target proof
//! context.
//!
//! [`ProofBlockCandidateStore`] retains chain-scoped structural blocks,
//! including siblings and blocks with unavailable parents, without validating
//! or selecting a candidate history. These stores define no reorganization,
//! fork choice, consensus, finality, networking, or economic state.

mod block_candidate_store;
#[cfg(test)]
mod fault_io;
mod payload_store;

pub use block_candidate_store::{
    ProofBlockCandidateInsertOutcome, ProofBlockCandidateStore, ProofBlockCandidateStoreError,
    ProofBlockCandidateStoreLimits, ProofBlockCandidateStoreLimitsError,
};

pub use payload_store::{
    CanonicalProofPayload, CanonicalProofPayloadStore, CanonicalProofPayloadStoreError,
    ProofPayloadInsertOutcome, ProofPayloadStoreLimits, ProofPayloadStoreLimitsError,
};

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use naome_chain::{
    PROOF_BLOCK_BYTES, ProofBlock, ProofBlockApplyError, ProofBlockId, ProofBlockPrepareError,
    ProofChainDefinition, ProofChainId, ProofChainState, ProofSetProof, ProofSetRoot,
};
use naome_ledger::{AcceptedProofRecord, ProofState};
use naome_proof::{CERTIFICATE_MAX_BYTES, ProofId};

const LOCK_FILE_NAME: &str = "proof-chain.lock";
const JOURNAL_FILE_NAME: &str = "proof-chain.journal";
const JOURNAL_HEADER: &[u8] = b"naome:proof-chain-journal\0";
const CHAIN_ID_BYTES: usize = ProofChainId::BYTE_LENGTH;
const BLOCK_ID_BYTES: u64 = ProofBlockId::BYTE_LENGTH as u64;
const ENTRY_FIXED_BYTES: u64 = 4 + BLOCK_ID_BYTES;
const JOURNAL_PREFIX_BYTES: usize = JOURNAL_HEADER.len() + CHAIN_ID_BYTES;
const ENTRY_MIN_BODY_BYTES: u32 = (PROOF_BLOCK_BYTES + 1) as u32;
const ENTRY_MAX_BODY_BYTES: u32 = (PROOF_BLOCK_BYTES + CERTIFICATE_MAX_BYTES) as u32;

/// An exclusively opened, crash-consistent journal for one selected proof chain.
///
/// The handle privately owns both the exact block head and selected proof DAG.
/// A commit I/O error makes the handle unusable because memory may then be ahead
/// of durable storage. Dropping and reopening is the only recovery path.
#[must_use]
pub struct ProofChainJournal {
    _lock: File,
    core: JournalCore<File>,
}

impl ProofChainJournal {
    /// Creates and exclusively opens a new empty journal for `definition`.
    ///
    /// Creation never replaces an existing journal. The prefix containing the
    /// exact chain context is synchronized before this function succeeds.
    /// Portable parent-directory-entry durability remains the caller's
    /// provisioning responsibility.
    pub fn create(
        directory: impl AsRef<Path>,
        definition: ProofChainDefinition,
    ) -> Result<Self, ProofChainJournalError> {
        let directory = directory.as_ref();
        let lock = open_and_lock(directory)?;
        let journal_path = directory.join(JOURNAL_FILE_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(journal_path)
            .map_err(|source| ProofChainJournalError::Create { source })?;

        let chain = ProofChainState::new(definition);
        file.write_all(JOURNAL_HEADER)
            .and_then(|()| file.write_all(chain.chain_id().as_bytes()))
            .and_then(|()| file.sync_all())
            .map_err(|source| ProofChainJournalError::Create { source })?;

        Ok(Self {
            _lock: lock,
            core: JournalCore::empty(file, chain),
        })
    }

    /// Exclusively opens and strictly replays an existing journal.
    ///
    /// One incomplete final entry is recovered to the preceding committed
    /// boundary. A complete corrupt or invalid entry fails closed.
    pub fn open_recovering_unverified(
        directory: impl AsRef<Path>,
        expected_definition: ProofChainDefinition,
    ) -> Result<Self, ProofChainJournalError> {
        Self::open_inner(directory.as_ref(), expected_definition, None)
    }

    /// Opens, strictly replays, and verifies the complete block ancestry.
    ///
    /// `expected_head` must come from a separately trusted source. If an
    /// incomplete tail is visible, it is truncated only after the replayed
    /// committed prefix matches this expected head.
    pub fn open_verified(
        directory: impl AsRef<Path>,
        expected_definition: ProofChainDefinition,
        expected_head: ProofBlockId,
    ) -> Result<Self, ProofChainJournalError> {
        Self::open_inner(directory.as_ref(), expected_definition, Some(expected_head))
    }

    fn open_inner(
        directory: &Path,
        expected_definition: ProofChainDefinition,
        expected_head: Option<ProofBlockId>,
    ) -> Result<Self, ProofChainJournalError> {
        let lock = open_and_lock(directory)?;
        let journal_path = directory.join(JOURNAL_FILE_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal_path)
            .map_err(|source| ProofChainJournalError::Open { source })?;
        let core = JournalCore::replay(file, expected_definition, expected_head)?;
        Ok(Self { _lock: lock, core })
    }

    /// Returns the immutable chain context synchronized at creation or
    /// verified from the persisted prefix during open.
    pub const fn chain_id(&self) -> ProofChainId {
        self.core.chain.chain_id()
    }

    /// Prepares one exact-parent block without changing memory or disk.
    pub fn prepare_block(&self, proof_id: ProofId) -> Result<ProofBlock, ProofChainJournalError> {
        self.core.ensure_healthy()?;
        self.core
            .chain
            .prepare_block(proof_id)
            .map_err(|source| ProofChainJournalError::Preparation { source })
    }

    /// Atomically validates, selects, and durably commits one exact-parent block.
    ///
    /// Ordinary validation errors perform no file I/O and leave the handle
    /// healthy. An ambiguous I/O failure after in-memory admission poisons it.
    pub fn apply_block(
        &mut self,
        block: &ProofBlock,
        canonical_proof_bytes: Vec<u8>,
    ) -> Result<&AcceptedProofRecord, ProofChainJournalError> {
        self.core.apply_block(block, canonical_proof_bytes)
    }

    /// Validates one exact-parent block without changing memory or disk.
    ///
    /// Success is relative only to the journal's current selected state. It
    /// reserves no block, confers no selection authority, and every later
    /// application fully revalidates against the then-current state.
    pub fn validate_block(
        &self,
        block: &ProofBlock,
        canonical_proof_bytes: Vec<u8>,
    ) -> Result<(), ProofChainJournalError> {
        self.core.ensure_healthy()?;
        self.core
            .chain
            .validate_block(block, canonical_proof_bytes)
            .map_err(|source| ProofChainJournalError::BlockAdmission { source })
    }

    /// Returns the exact committed head, or the virtual genesis anchor if empty.
    pub fn head_block_id(&self) -> Result<ProofBlockId, ProofChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.head_block_id())
    }

    /// Returns one committed and replay-checked block by its exact identity.
    pub fn block(
        &self,
        block_id: ProofBlockId,
    ) -> Result<Option<&ProofBlock>, ProofChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.blocks.get(&block_id))
    }

    /// Returns one committed and replay-checked proof record.
    pub fn proof(
        &self,
        proof_id: ProofId,
    ) -> Result<Option<&AcceptedProofRecord>, ProofChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.proof_dag().proof(proof_id))
    }

    /// Returns immutable access to the committed checked-proof resolver state.
    ///
    /// The borrow contains only proofs selected through strict block application
    /// or replay. A poisoned handle fails closed.
    pub fn proof_state(&self) -> Result<&ProofState, ProofChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.proof_state())
    }

    /// Returns the number of committed proof records.
    pub fn len(&self) -> Result<usize, ProofChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.proof_dag().len())
    }

    /// Returns whether no proof records have been committed.
    pub fn is_empty(&self) -> Result<bool, ProofChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.proof_dag().is_empty())
    }

    /// Returns the authenticated root of the committed proof set.
    pub fn proof_set_root(&self) -> Result<ProofSetRoot, ProofChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.proof_dag().proof_set_root())
    }

    /// Returns one proof-set membership or non-membership witness.
    pub fn proof_set_proof(
        &self,
        proof_id: ProofId,
    ) -> Result<ProofSetProof, ProofChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.proof_dag().proof_set_proof(proof_id))
    }
}

fn open_and_lock(directory: &Path) -> Result<File, ProofChainJournalError> {
    open_exclusive_lock(directory, LOCK_FILE_NAME).map_err(|error| match error {
        ExclusiveLockError::LockFile(source) => ProofChainJournalError::LockFile { source },
        ExclusiveLockError::Locked => ProofChainJournalError::Locked,
        ExclusiveLockError::Lock(source) => ProofChainJournalError::Lock { source },
    })
}

enum ExclusiveLockError {
    LockFile(io::Error),
    Locked,
    Lock(io::Error),
}

fn open_exclusive_lock(directory: &Path, file_name: &str) -> Result<File, ExclusiveLockError> {
    let lock_path = directory.join(file_name);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(ExclusiveLockError::LockFile)?;

    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(ExclusiveLockError::Locked),
        Err(TryLockError::Error(source)) => Err(ExclusiveLockError::Lock(source)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppendPhase {
    Body,
    Commit,
}

trait StoreIo: Read + Write + Seek {
    fn set_len(&mut self, size: u64) -> io::Result<()>;
    fn sync_all(&mut self) -> io::Result<()>;

    fn append_write_all(&mut self, _phase: AppendPhase, bytes: &[u8]) -> io::Result<()> {
        self.write_all(bytes)
    }

    fn append_sync_all(&mut self, _phase: AppendPhase) -> io::Result<()> {
        self.sync_all()
    }
}

impl StoreIo for File {
    fn set_len(&mut self, size: u64) -> io::Result<()> {
        File::set_len(self, size)
    }

    fn sync_all(&mut self) -> io::Result<()> {
        File::sync_all(self)
    }
}

struct JournalCore<F> {
    file: F,
    chain: ProofChainState,
    blocks: HashMap<ProofBlockId, ProofBlock>,
    committed_end: u64,
    poisoned: bool,
}

impl<F: StoreIo> JournalCore<F> {
    fn empty(file: F, chain: ProofChainState) -> Self {
        Self {
            file,
            chain,
            blocks: HashMap::new(),
            committed_end: JOURNAL_PREFIX_BYTES as u64,
            poisoned: false,
        }
    }

    fn replay(
        mut file: F,
        expected_definition: ProofChainDefinition,
        expected_head: Option<ProofBlockId>,
    ) -> Result<Self, ProofChainJournalError> {
        let chain = ProofChainState::new(expected_definition);
        let expected_chain_id = chain.chain_id();
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|source| ProofChainJournalError::Read { offset: 0, source })?;
        if file_len < JOURNAL_PREFIX_BYTES as u64 {
            return Err(ProofChainJournalError::InvalidHeader);
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|source| ProofChainJournalError::Read { offset: 0, source })?;
        let mut header = [0_u8; JOURNAL_HEADER.len()];
        file.read_exact(&mut header)
            .map_err(|source| ProofChainJournalError::Read { offset: 0, source })?;
        if header != JOURNAL_HEADER {
            return Err(ProofChainJournalError::InvalidHeader);
        }

        let mut stored_chain_id = [0_u8; CHAIN_ID_BYTES];
        file.read_exact(&mut stored_chain_id)
            .map_err(|source| ProofChainJournalError::Read {
                offset: JOURNAL_HEADER.len() as u64,
                source,
            })?;
        let actual_chain_id = ProofChainId::from_bytes(stored_chain_id);
        if actual_chain_id != expected_chain_id {
            return Err(ProofChainJournalError::ChainIdMismatch {
                expected: expected_chain_id,
                actual: actual_chain_id,
            });
        }

        let mut chain = chain;
        let mut blocks = HashMap::new();
        let mut entry_start = JOURNAL_PREFIX_BYTES as u64;
        let mut entry = 0_u64;

        while entry_start < file_len {
            let remaining = file_len - entry_start;
            if remaining < 4 {
                return Self::finish_replay(
                    file,
                    chain,
                    blocks,
                    entry_start,
                    expected_head,
                    Some(entry_start),
                );
            }

            let mut body_length_bytes = [0_u8; 4];
            file.read_exact(&mut body_length_bytes).map_err(|source| {
                ProofChainJournalError::Read {
                    offset: entry_start,
                    source,
                }
            })?;
            let body_length = u32::from_be_bytes(body_length_bytes);
            if !(ENTRY_MIN_BODY_BYTES..=ENTRY_MAX_BODY_BYTES).contains(&body_length) {
                return Err(ProofChainJournalError::InvalidEntryLength {
                    entry,
                    offset: entry_start,
                    actual: body_length,
                    minimum: ENTRY_MIN_BODY_BYTES,
                    maximum: ENTRY_MAX_BODY_BYTES,
                });
            }

            let entry_length = ENTRY_FIXED_BYTES + u64::from(body_length);
            let entry_end = entry_start.checked_add(entry_length).ok_or(
                ProofChainJournalError::EntryOffsetOverflow {
                    entry,
                    offset: entry_start,
                },
            )?;
            if file_len < entry_end {
                return Self::finish_replay(
                    file,
                    chain,
                    blocks,
                    entry_start,
                    expected_head,
                    Some(entry_start),
                );
            }

            let block_offset = entry_start + 4;
            let mut block_bytes = [0_u8; PROOF_BLOCK_BYTES];
            read_field(&mut file, &mut block_bytes, block_offset)?;
            let block = ProofBlock::from_canonical_bytes(&block_bytes)
                .expect("every fixed-length proof block byte string is structurally valid");
            let proof_offset = block_offset + PROOF_BLOCK_BYTES as u64;
            let proof_length = body_length as usize - PROOF_BLOCK_BYTES;
            debug_assert!((1..=CERTIFICATE_MAX_BYTES).contains(&proof_length));
            let mut payload = Vec::new();
            payload.try_reserve_exact(proof_length).map_err(|_| {
                ProofChainJournalError::Allocation {
                    entry,
                    bytes: proof_length,
                }
            })?;
            payload.resize(proof_length, 0);
            read_field(&mut file, &mut payload, proof_offset)?;
            let mut stored_block_id = [0_u8; 32];
            file.read_exact(&mut stored_block_id).map_err(|source| {
                ProofChainJournalError::Read {
                    offset: entry_end - BLOCK_ID_BYTES,
                    source,
                }
            })?;
            let expected_block_id = block.id();
            let actual_block_id = ProofBlockId::from_bytes(stored_block_id);
            if actual_block_id != expected_block_id {
                return Err(ProofChainJournalError::BlockIdMismatch {
                    entry,
                    offset: entry_start,
                    expected: expected_block_id,
                    actual: actual_block_id,
                });
            }

            chain.apply_block(&block, payload).map_err(|source| {
                ProofChainJournalError::Replay {
                    entry,
                    offset: entry_start,
                    source: Box::new(source),
                }
            })?;
            reserve_block_index_entry(&mut blocks, entry)?;
            let replaced = blocks.insert(expected_block_id, block);
            debug_assert!(replaced.is_none());

            entry_start = entry_end;
            entry += 1;
        }

        Self::finish_replay(file, chain, blocks, entry_start, expected_head, None)
    }

    fn finish_replay(
        mut file: F,
        chain: ProofChainState,
        blocks: HashMap<ProofBlockId, ProofBlock>,
        committed_end: u64,
        expected_head: Option<ProofBlockId>,
        recovery_offset: Option<u64>,
    ) -> Result<Self, ProofChainJournalError> {
        if let Some(expected) = expected_head {
            let actual = chain.head_block_id();
            if actual != expected {
                return Err(ProofChainJournalError::HeadBlockIdMismatch { expected, actual });
            }
        }

        if let Some(offset) = recovery_offset {
            recover_tail(&mut file, offset)?;
        } else {
            file.sync_all()
                .map_err(|source| ProofChainJournalError::Stabilize { source })?;
        }

        Ok(Self {
            file,
            chain,
            blocks,
            committed_end,
            poisoned: false,
        })
    }

    fn apply_block(
        &mut self,
        block: &ProofBlock,
        canonical_proof_bytes: Vec<u8>,
    ) -> Result<&AcceptedProofRecord, ProofChainJournalError> {
        self.ensure_healthy()?;
        let expected_parent = self.chain.head_block_id();
        let actual_parent = block.parent_block_id();
        if actual_parent != expected_parent {
            return Err(ProofChainJournalError::BlockAdmission {
                source: ProofBlockApplyError::ParentBlockIdMismatch {
                    expected: expected_parent,
                    actual: actual_parent,
                },
            });
        }
        let block_bytes = block.to_canonical_bytes();
        let indexed_block = *block;
        let entry = u64::try_from(self.blocks.len()).expect("block index length fits u64");
        reserve_block_index_entry(&mut self.blocks, entry)?;
        self.chain
            .apply_block(block, canonical_proof_bytes)
            .map_err(|source| ProofChainJournalError::BlockAdmission { source })?;
        let block_id = self.chain.head_block_id();
        self.commit_entry(block_id, &block_bytes, block.proof_id())?;
        let replaced = self.blocks.insert(block_id, indexed_block);
        debug_assert!(replaced.is_none());
        Ok(self
            .chain
            .proof_dag()
            .proof(block.proof_id())
            .expect("the committed block proof remains retained"))
    }

    fn commit_entry(
        &mut self,
        block_id: ProofBlockId,
        block_bytes: &[u8; PROOF_BLOCK_BYTES],
        proof_id: ProofId,
    ) -> Result<(), ProofChainJournalError> {
        let payload = self
            .chain
            .proof_dag()
            .proof(proof_id)
            .expect("the committed block proof is retained")
            .canonical_proof_bytes();
        let body_length = block_bytes
            .len()
            .checked_add(payload.len())
            .expect("bounded proof-chain entry length fits usize");
        let body_length = u32::try_from(body_length)
            .expect("bounded proof-chain entry length fits the u32 framing");
        debug_assert!((ENTRY_MIN_BODY_BYTES..=ENTRY_MAX_BODY_BYTES).contains(&body_length));
        let body_length_bytes = body_length.to_be_bytes();
        let commit_result = (|| -> io::Result<()> {
            self.file.seek(SeekFrom::Start(self.committed_end))?;
            self.file
                .append_write_all(AppendPhase::Body, &body_length_bytes)?;
            self.file.append_write_all(AppendPhase::Body, block_bytes)?;
            self.file.append_write_all(AppendPhase::Body, payload)?;
            self.file.append_sync_all(AppendPhase::Body)?;
            self.file
                .append_write_all(AppendPhase::Commit, block_id.as_bytes())?;
            self.file.append_sync_all(AppendPhase::Commit)?;
            Ok(())
        })();

        match commit_result {
            Ok(()) => {}
            Err(source) => {
                self.poisoned = true;
                return Err(ProofChainJournalError::Commit { block_id, source });
            }
        }

        self.committed_end = self
            .committed_end
            .checked_add(ENTRY_FIXED_BYTES + u64::from(body_length))
            .expect("proof-chain journal offsets fit u64");
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), ProofChainJournalError> {
        if self.poisoned {
            Err(ProofChainJournalError::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn reserve_block_index_entry(
    blocks: &mut HashMap<ProofBlockId, ProofBlock>,
    entry: u64,
) -> Result<(), ProofChainJournalError> {
    blocks
        .try_reserve(1)
        .map_err(|_| ProofChainJournalError::BlockIndexAllocation { entry })
}

fn recover_tail<F: StoreIo>(file: &mut F, offset: u64) -> Result<(), ProofChainJournalError> {
    file.set_len(offset)
        .and_then(|()| file.sync_all())
        .map_err(|source| ProofChainJournalError::Recovery { offset, source })
}

fn read_field<F: StoreIo>(
    file: &mut F,
    bytes: &mut [u8],
    offset: u64,
) -> Result<(), ProofChainJournalError> {
    file.read_exact(bytes)
        .map_err(|source| ProofChainJournalError::Read { offset, source })?;
    Ok(())
}

/// A fail-closed proof-chain journal error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProofChainJournalError {
    /// The sidecar lock file could not be opened.
    LockFile { source: io::Error },
    /// Another process or handle already owns the journal lock.
    Locked,
    /// The operating-system file lock could not be acquired.
    Lock { source: io::Error },
    /// A new journal file could not be created or initialized.
    Create { source: io::Error },
    /// An existing journal file could not be opened.
    Open { source: io::Error },
    /// Existing journal bytes could not be read.
    Read { offset: u64, source: io::Error },
    /// The journal header or chain identifier is incomplete or unsupported.
    InvalidHeader,
    /// The file is bound to a different proof-chain context.
    ChainIdMismatch {
        expected: ProofChainId,
        actual: ProofChainId,
    },
    /// A complete entry declares an impossible body length.
    InvalidEntryLength {
        entry: u64,
        offset: u64,
        actual: u32,
        minimum: u32,
        maximum: u32,
    },
    /// An entry boundary cannot be represented safely.
    EntryOffsetOverflow { entry: u64, offset: u64 },
    /// Allocating one bounded proof payload failed.
    Allocation { entry: u64, bytes: usize },
    /// Reserving the selected-block index for one journal entry failed.
    BlockIndexAllocation { entry: u64 },
    /// The commit footer does not repeat the decoded canonical block identity.
    BlockIdMismatch {
        entry: u64,
        offset: u64,
        expected: ProofBlockId,
        actual: ProofBlockId,
    },
    /// Strict block replay rejected one complete committed entry.
    Replay {
        entry: u64,
        offset: u64,
        source: Box<ProofBlockApplyError>,
    },
    /// An incomplete final entry could not be removed durably.
    Recovery { offset: u64, source: io::Error },
    /// A fully replayed visible journal image could not be stabilized.
    Stabilize { source: io::Error },
    /// Strict replay produced a different block ancestry than expected.
    HeadBlockIdMismatch {
        expected: ProofBlockId,
        actual: ProofBlockId,
    },
    /// Read-only block preparation rejected its proof identity.
    Preparation { source: ProofBlockPrepareError },
    /// The supplied block failed before journal I/O.
    BlockAdmission { source: ProofBlockApplyError },
    /// Commit durability is unknown and the handle is now poisoned.
    Commit {
        block_id: ProofBlockId,
        source: io::Error,
    },
    /// Memory may be ahead of durable storage after an ambiguous commit.
    Poisoned,
}

impl fmt::Display for ProofChainJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockFile { source } => write!(formatter, "journal lock file failed: {source}"),
            Self::Locked => formatter.write_str("proof chain journal is already exclusively open"),
            Self::Lock { source } => write!(formatter, "journal locking failed: {source}"),
            Self::Create { source } => write!(formatter, "journal creation failed: {source}"),
            Self::Open { source } => write!(formatter, "journal opening failed: {source}"),
            Self::Read { offset, source } => {
                write!(formatter, "journal read failed at byte {offset}: {source}")
            }
            Self::InvalidHeader => formatter.write_str("invalid proof chain journal header"),
            Self::ChainIdMismatch { expected, actual } => write!(
                formatter,
                "proof chain identifier mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::InvalidEntryLength {
                entry,
                offset,
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "journal entry {entry} at byte {offset} has body length {actual}, expected {minimum}..={maximum}"
            ),
            Self::EntryOffsetOverflow { entry, offset } => write!(
                formatter,
                "journal entry {entry} at byte {offset} exceeds the offset range"
            ),
            Self::Allocation { entry, bytes } => write!(
                formatter,
                "journal entry {entry} proof payload could not allocate {bytes} bytes"
            ),
            Self::BlockIndexAllocation { entry } => {
                write!(
                    formatter,
                    "journal entry {entry} could not reserve its block index slot"
                )
            }
            Self::BlockIdMismatch {
                entry,
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "journal entry {entry} at byte {offset} commits block {actual:?}, expected decoded block {expected:?}"
            ),
            Self::Replay {
                entry,
                offset,
                source,
            } => write!(
                formatter,
                "journal entry {entry} at byte {offset} failed strict block replay: {source}"
            ),
            Self::Recovery { offset, source } => write!(
                formatter,
                "incomplete journal tail at byte {offset} could not be recovered: {source}"
            ),
            Self::Stabilize { source } => {
                write!(formatter, "replayed journal stabilization failed: {source}")
            }
            Self::HeadBlockIdMismatch { expected, actual } => write!(
                formatter,
                "proof-chain head mismatch: expected {expected:?}, replayed {actual:?}"
            ),
            Self::Preparation { source } => write!(formatter, "block preparation failed: {source}"),
            Self::BlockAdmission { source } => {
                write!(formatter, "block admission failed: {source}")
            }
            Self::Commit { block_id, source } => write!(
                formatter,
                "journal commit of block {block_id:?} has unknown durability: {source}"
            ),
            Self::Poisoned => formatter
                .write_str("journal is poisoned after an ambiguous commit; drop and reopen it"),
        }
    }
}

impl Error for ProofChainJournalError {
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
            Self::Replay { source, .. } => Some(source.as_ref()),
            Self::Preparation { source } => Some(source),
            Self::BlockAdmission { source } => Some(source),
            Self::Locked
            | Self::InvalidHeader
            | Self::ChainIdMismatch { .. }
            | Self::InvalidEntryLength { .. }
            | Self::EntryOffsetOverflow { .. }
            | Self::Allocation { .. }
            | Self::BlockIndexAllocation { .. }
            | Self::BlockIdMismatch { .. }
            | Self::HeadBlockIdMismatch { .. }
            | Self::Poisoned => None,
        }
    }
}

#[cfg(test)]
mod tests;
