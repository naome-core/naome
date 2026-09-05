//! Artifact-only selected state, strict replay, and durable journal ownership.

use super::*;

mod errors;
pub use errors::ArtifactChainJournalError;
mod recovery_bundle_import;
pub use recovery_bundle_import::{
    CandidateBranchRecoveryBundleCommitError, CandidateBranchRecoveryBundleImportError,
    CandidateBranchRecoveryBundleImportOutcome,
};

const JOURNAL_HEADER: &[u8] = b"naome:artifact-chain-journal:v1\0";
const CHAIN_ID_BYTES: usize = ArtifactChainId::BYTE_LENGTH;
const BLOCK_ID_BYTES: u64 = ArtifactBlockId::BYTE_LENGTH as u64;
const ENTRY_FIXED_BYTES: u64 = 4 + BLOCK_ID_BYTES;
const JOURNAL_PREFIX_BYTES: usize = JOURNAL_HEADER.len() + CHAIN_ID_BYTES;
const ENTRY_MIN_BODY_BYTES: u32 = (ARTIFACT_BLOCK_BYTES + 1) as u32;
const ENTRY_MAX_BODY_BYTES: u32 = (ARTIFACT_BLOCK_BYTES + ARTIFACT_PAYLOAD_MAX_BYTES) as u32;

/// An exclusively opened, crash-consistent journal for one selected artifact chain.
///
/// The handle privately owns both the exact block head and selected artifact DAG.
/// A commit I/O error makes the handle unusable because memory may then be ahead
/// of durable storage. Dropping and reopening is the only recovery path.
#[must_use]
pub struct ArtifactChainJournal {
    _lock: File,
    core: JournalCore<File>,
}

impl ArtifactChainJournal {
    /// Creates and exclusively opens a new empty journal for `definition`.
    ///
    /// Creation never replaces an existing journal. The prefix containing the
    /// exact chain context is synchronized before this function succeeds.
    /// Portable parent-directory-entry durability remains the caller's
    /// provisioning responsibility.
    pub fn create(
        directory: impl AsRef<Path>,
        definition: ArtifactChainDefinition,
    ) -> Result<Self, ArtifactChainJournalError> {
        let directory = directory.as_ref();
        let lock = open_and_lock(directory)?;
        let journal_path = directory.join(JOURNAL_FILE_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(journal_path)
            .map_err(|source| ArtifactChainJournalError::Create { source })?;

        let chain = ArtifactChainState::new(definition);
        file.write_all(JOURNAL_HEADER)
            .and_then(|()| file.write_all(chain.chain_id().as_bytes()))
            .and_then(|()| file.sync_all())
            .map_err(|source| ArtifactChainJournalError::Create { source })?;

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
        expected_definition: ArtifactChainDefinition,
    ) -> Result<Self, ArtifactChainJournalError> {
        Self::open_inner(directory.as_ref(), expected_definition, None)
    }

    /// Opens, strictly replays, and verifies the complete block ancestry.
    ///
    /// `expected_head` must come from a separately trusted source. If an
    /// incomplete tail is visible, it is truncated only after the replayed
    /// committed prefix matches this expected head.
    pub fn open_verified(
        directory: impl AsRef<Path>,
        expected_definition: ArtifactChainDefinition,
        expected_head: ArtifactBlockId,
    ) -> Result<Self, ArtifactChainJournalError> {
        Self::open_inner(directory.as_ref(), expected_definition, Some(expected_head))
    }

    fn open_inner(
        directory: &Path,
        expected_definition: ArtifactChainDefinition,
        expected_head: Option<ArtifactBlockId>,
    ) -> Result<Self, ArtifactChainJournalError> {
        let lock = open_and_lock(directory)?;
        let journal_path = directory.join(JOURNAL_FILE_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal_path)
            .map_err(|source| ArtifactChainJournalError::Open { source })?;
        let core = JournalCore::replay(file, expected_definition, expected_head)?;
        Ok(Self { _lock: lock, core })
    }

    /// Returns the immutable chain context synchronized at creation or
    /// verified from the persisted prefix during open.
    pub const fn chain_id(&self) -> ArtifactChainId {
        self.core.chain.chain_id()
    }

    /// Prepares one exact-parent block without changing memory or disk.
    pub fn prepare_block(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactBlock, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        self.core
            .chain
            .prepare_block(artifact_id)
            .map_err(|source| ArtifactChainJournalError::Preparation { source })
    }

    /// Atomically validates, selects, and durably commits one exact-parent block.
    ///
    /// Ordinary validation errors perform no file I/O and leave the handle
    /// healthy. An ambiguous I/O failure after in-memory admission poisons it.
    pub fn apply_block(
        &mut self,
        block: &ArtifactBlock,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<&AcceptedArtifactRecord, ArtifactChainJournalError> {
        self.core.apply_block(block, canonical_artifact_bytes)
    }

    /// Validates one exact-parent block without changing memory or disk.
    ///
    /// Success is relative only to the journal's current selected state. It
    /// reserves no block, confers no selection authority, and every later
    /// application fully revalidates against the then-current state.
    pub fn validate_block(
        &self,
        block: &ArtifactBlock,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<(), ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        self.core
            .chain
            .validate_block(block, canonical_artifact_bytes)
            .map_err(|source| ArtifactChainJournalError::BlockAdmission { source })
    }

    /// Returns the exact committed head, or the virtual genesis anchor if empty.
    pub fn head_block_id(&self) -> Result<ArtifactBlockId, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.head_block_id())
    }

    /// Returns one committed and replay-checked block by its exact identity.
    pub fn block(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<&ArtifactBlock>, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.blocks.get(&block_id))
    }

    /// Returns an owned immutable branch snapshot at one selected artifact fork point.
    ///
    /// The virtual genesis anchor and every strictly selected block are available.
    /// An unknown or non-selected address returns `None`. Journal health is checked
    /// before the address lookup. Candidate snapshots derived from the result are
    /// memory-only and are never added to this selected snapshot index.
    pub fn branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.blocks.snapshot(block_id))
    }

    /// Returns one committed and replay-checked artifact record.
    pub fn artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<&AcceptedArtifactRecord>, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.artifact_dag().artifact(artifact_id))
    }

    /// Returns immutable access to the committed checked-artifact resolver state.
    ///
    /// The borrow contains only artifacts selected through strict block
    /// application or replay. A poisoned handle fails closed.
    pub fn artifact_state(&self) -> Result<&ArtifactState, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.artifact_state())
    }

    /// Returns the number of committed artifact records.
    pub fn len(&self) -> Result<usize, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.artifact_dag().len())
    }

    /// Returns whether no artifact records have been committed.
    pub fn is_empty(&self) -> Result<bool, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.artifact_dag().is_empty())
    }

    /// Returns the authenticated root of the committed artifact set.
    pub fn artifact_set_root(&self) -> Result<ArtifactSetRoot, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.artifact_dag().artifact_set_root())
    }

    /// Returns one artifact-set membership or non-membership witness.
    pub fn artifact_set_proof(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactSetProof, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self
            .core
            .chain
            .artifact_dag()
            .artifact_set_proof(artifact_id))
    }

    pub(crate) fn reserve_selected_block_entries(
        &mut self,
        additional: usize,
    ) -> Result<(), ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        self.core.blocks.reserve_entries(additional)
    }
}

impl selected_artifact_history_sealed::Sealed for ArtifactChainJournal {}

impl SelectedArtifactHistory for ArtifactChainJournal {
    fn selected_chain_id(&self) -> ArtifactChainId {
        self.chain_id()
    }

    fn selected_head_block_id(&self) -> Result<ArtifactBlockId, SelectedArtifactHistoryError> {
        self.head_block_id()
            .map_err(SelectedArtifactHistoryError::artifact_chain)
    }

    fn selected_artifact_set_root(&self) -> Result<ArtifactSetRoot, SelectedArtifactHistoryError> {
        self.artifact_set_root()
            .map_err(SelectedArtifactHistoryError::artifact_chain)
    }

    fn selected_branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, SelectedArtifactHistoryError> {
        self.branch_snapshot_at(block_id)
            .map_err(SelectedArtifactHistoryError::artifact_chain)
    }
}

fn open_and_lock(directory: &Path) -> Result<File, ArtifactChainJournalError> {
    open_exclusive_lock(directory, LOCK_FILE_NAME).map_err(|error| match error {
        ExclusiveLockError::LockFile(source) => ArtifactChainJournalError::LockFile { source },
        ExclusiveLockError::Locked => ArtifactChainJournalError::Locked,
        ExclusiveLockError::Lock(source) => ArtifactChainJournalError::Lock { source },
    })
}

struct JournalCore<F> {
    file: F,
    chain: ArtifactChainState,
    blocks: SelectedBlockIndex,
    committed_end: u64,
    poisoned: bool,
}

struct SelectedBlockEntry {
    block: ArtifactBlock,
    snapshot: ArtifactChainBranchSnapshot,
}

struct SelectedBlockIndex {
    genesis: ArtifactChainBranchSnapshot,
    blocks: HashMap<ArtifactBlockId, SelectedBlockEntry>,
}

impl SelectedBlockIndex {
    fn new(chain: &ArtifactChainState) -> Self {
        Self {
            genesis: chain.branch_snapshot(),
            blocks: HashMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.blocks.len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn get(&self, block_id: &ArtifactBlockId) -> Option<&ArtifactBlock> {
        self.blocks.get(block_id).map(|entry| &entry.block)
    }

    fn snapshot(&self, block_id: ArtifactBlockId) -> Option<ArtifactChainBranchSnapshot> {
        if block_id == self.genesis.head_block_id() {
            Some(self.genesis.clone())
        } else {
            self.blocks
                .get(&block_id)
                .map(|entry| entry.snapshot.clone())
        }
    }

    fn artifact_set_root(&self, block_id: ArtifactBlockId) -> Option<ArtifactSetRoot> {
        if block_id == self.genesis.head_block_id() {
            Some(self.genesis.artifact_set_root())
        } else {
            self.blocks
                .get(&block_id)
                .map(|entry| entry.snapshot.artifact_set_root())
        }
    }

    fn reserve_entry(&mut self, entry: u64) -> Result<(), ArtifactChainJournalError> {
        self.blocks
            .try_reserve(1)
            .map_err(|_| ArtifactChainJournalError::BlockIndexAllocation { entry })
    }

    fn reserve_entries(&mut self, additional: usize) -> Result<(), ArtifactChainJournalError> {
        let entry = u64::try_from(self.blocks.len()).expect("block index length fits u64");
        self.blocks
            .try_reserve(additional)
            .map_err(|_| ArtifactChainJournalError::BlockIndexAllocation { entry })
    }

    fn insert(
        &mut self,
        block_id: ArtifactBlockId,
        block: ArtifactBlock,
        snapshot: ArtifactChainBranchSnapshot,
    ) {
        let replaced = self
            .blocks
            .insert(block_id, SelectedBlockEntry { block, snapshot });
        debug_assert!(replaced.is_none());
    }
}

impl<F: StoreIo> JournalCore<F> {
    fn empty(file: F, chain: ArtifactChainState) -> Self {
        let blocks = SelectedBlockIndex::new(&chain);
        Self {
            file,
            chain,
            blocks,
            committed_end: JOURNAL_PREFIX_BYTES as u64,
            poisoned: false,
        }
    }

    fn replay(
        mut file: F,
        expected_definition: ArtifactChainDefinition,
        expected_head: Option<ArtifactBlockId>,
    ) -> Result<Self, ArtifactChainJournalError> {
        let chain = ArtifactChainState::new(expected_definition);
        let expected_chain_id = chain.chain_id();
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|source| ArtifactChainJournalError::Read { offset: 0, source })?;
        if file_len < JOURNAL_PREFIX_BYTES as u64 {
            return Err(ArtifactChainJournalError::InvalidHeader);
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|source| ArtifactChainJournalError::Read { offset: 0, source })?;
        let mut header = [0_u8; JOURNAL_HEADER.len()];
        file.read_exact(&mut header)
            .map_err(|source| ArtifactChainJournalError::Read { offset: 0, source })?;
        if header != JOURNAL_HEADER {
            return Err(ArtifactChainJournalError::InvalidHeader);
        }

        let mut stored_chain_id = [0_u8; CHAIN_ID_BYTES];
        file.read_exact(&mut stored_chain_id).map_err(|source| {
            ArtifactChainJournalError::Read {
                offset: JOURNAL_HEADER.len() as u64,
                source,
            }
        })?;
        let actual_chain_id = ArtifactChainId::from_bytes(stored_chain_id);
        if actual_chain_id != expected_chain_id {
            return Err(ArtifactChainJournalError::ChainIdMismatch {
                expected: expected_chain_id,
                actual: actual_chain_id,
            });
        }

        let mut blocks = SelectedBlockIndex::new(&chain);
        let mut chain = chain;
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
                ArtifactChainJournalError::Read {
                    offset: entry_start,
                    source,
                }
            })?;
            let body_length = u32::from_be_bytes(body_length_bytes);
            if !(ENTRY_MIN_BODY_BYTES..=ENTRY_MAX_BODY_BYTES).contains(&body_length) {
                return Err(ArtifactChainJournalError::InvalidEntryLength {
                    entry,
                    offset: entry_start,
                    actual: body_length,
                    minimum: ENTRY_MIN_BODY_BYTES,
                    maximum: ENTRY_MAX_BODY_BYTES,
                });
            }

            let entry_length = ENTRY_FIXED_BYTES + u64::from(body_length);
            let entry_end = entry_start.checked_add(entry_length).ok_or(
                ArtifactChainJournalError::EntryOffsetOverflow {
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
            let mut block_bytes = [0_u8; ARTIFACT_BLOCK_BYTES];
            read_field(&mut file, &mut block_bytes, block_offset)?;
            let block = ArtifactBlock::from_canonical_bytes(&block_bytes)
                .expect("every fixed-length artifact block byte string is structurally valid");
            let payload_offset = block_offset + ARTIFACT_BLOCK_BYTES as u64;
            let payload_length = body_length as usize - ARTIFACT_BLOCK_BYTES;
            debug_assert!((1..=ARTIFACT_PAYLOAD_MAX_BYTES).contains(&payload_length));
            let mut payload = Vec::new();
            payload.try_reserve_exact(payload_length).map_err(|_| {
                ArtifactChainJournalError::Allocation {
                    entry,
                    bytes: payload_length,
                }
            })?;
            payload.resize(payload_length, 0);
            read_field(&mut file, &mut payload, payload_offset)?;
            let mut stored_block_id = [0_u8; ArtifactBlockId::BYTE_LENGTH];
            file.read_exact(&mut stored_block_id).map_err(|source| {
                ArtifactChainJournalError::Read {
                    offset: entry_end - BLOCK_ID_BYTES,
                    source,
                }
            })?;
            let expected_block_id = block.id();
            let actual_block_id = ArtifactBlockId::from_bytes(stored_block_id);
            if actual_block_id != expected_block_id {
                return Err(ArtifactChainJournalError::BlockIdMismatch {
                    entry,
                    offset: entry_start,
                    expected: expected_block_id,
                    actual: actual_block_id,
                });
            }

            chain.apply_block(&block, payload).map_err(|source| {
                ArtifactChainJournalError::Replay {
                    entry,
                    offset: entry_start,
                    source: Box::new(source),
                }
            })?;
            blocks.reserve_entry(entry)?;
            let snapshot = chain.branch_snapshot();
            blocks.insert(expected_block_id, block, snapshot);

            entry_start = entry_end;
            entry += 1;
        }

        Self::finish_replay(file, chain, blocks, entry_start, expected_head, None)
    }

    fn finish_replay(
        mut file: F,
        chain: ArtifactChainState,
        blocks: SelectedBlockIndex,
        committed_end: u64,
        expected_head: Option<ArtifactBlockId>,
        recovery_offset: Option<u64>,
    ) -> Result<Self, ArtifactChainJournalError> {
        if let Some(expected) = expected_head {
            let actual = chain.head_block_id();
            if actual != expected {
                return Err(ArtifactChainJournalError::HeadBlockIdMismatch { expected, actual });
            }
        }

        if let Some(offset) = recovery_offset {
            recover_tail(&mut file, offset)?;
        } else {
            file.sync_all()
                .map_err(|source| ArtifactChainJournalError::Stabilize { source })?;
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
        block: &ArtifactBlock,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<&AcceptedArtifactRecord, ArtifactChainJournalError> {
        self.ensure_healthy()?;
        let expected_parent = self.chain.head_block_id();
        let actual_parent = block.parent_block_id();
        if actual_parent != expected_parent {
            return Err(ArtifactChainJournalError::BlockAdmission {
                source: ArtifactBlockApplyError::ParentBlockIdMismatch {
                    expected: expected_parent,
                    actual: actual_parent,
                },
            });
        }
        let block_bytes = block.to_canonical_bytes();
        let indexed_block = *block;
        let entry = u64::try_from(self.blocks.len()).expect("block index length fits u64");
        self.blocks.reserve_entry(entry)?;
        self.chain
            .apply_block(block, canonical_artifact_bytes)
            .map_err(|source| ArtifactChainJournalError::BlockAdmission { source })?;
        let block_id = self.chain.head_block_id();
        let snapshot = self.chain.branch_snapshot();
        self.commit_entry(block_id, &block_bytes, block.artifact_id())?;
        self.blocks.insert(block_id, indexed_block, snapshot);
        Ok(self
            .chain
            .artifact_dag()
            .artifact(block.artifact_id())
            .expect("the committed block artifact remains retained"))
    }

    fn commit_entry(
        &mut self,
        block_id: ArtifactBlockId,
        block_bytes: &[u8; ARTIFACT_BLOCK_BYTES],
        artifact_id: ArtifactId,
    ) -> Result<(), ArtifactChainJournalError> {
        let payload = self
            .chain
            .artifact_dag()
            .artifact(artifact_id)
            .expect("the committed block artifact is retained")
            .canonical_artifact_bytes();
        let body_length = block_bytes
            .len()
            .checked_add(payload.len())
            .expect("bounded artifact-chain entry length fits usize");
        let body_length = u32::try_from(body_length)
            .expect("bounded artifact-chain entry length fits the u32 framing");
        debug_assert!((ENTRY_MIN_BODY_BYTES..=ENTRY_MAX_BODY_BYTES).contains(&body_length));
        let body_length_bytes = body_length.to_be_bytes();
        let commit_result = (|| -> io::Result<()> {
            self.file.seek(SeekFrom::Start(self.committed_end))?;
            crate::store_io::append_body_and_commit(
                &mut self.file,
                &[&body_length_bytes, block_bytes, payload],
                block_id.as_bytes(),
            )?;
            Ok(())
        })();

        match commit_result {
            Ok(()) => {}
            Err(source) => {
                self.poisoned = true;
                return Err(ArtifactChainJournalError::Commit { block_id, source });
            }
        }

        self.committed_end = self
            .committed_end
            .checked_add(ENTRY_FIXED_BYTES + u64::from(body_length))
            .expect("artifact-chain journal offsets fit u64");
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), ArtifactChainJournalError> {
        if self.poisoned {
            Err(ArtifactChainJournalError::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn recover_tail<F: StoreIo>(file: &mut F, offset: u64) -> Result<(), ArtifactChainJournalError> {
    file.set_len(offset)
        .and_then(|()| file.sync_all())
        .map_err(|source| ArtifactChainJournalError::Recovery { offset, source })
}

fn read_field<F: StoreIo>(
    file: &mut F,
    bytes: &mut [u8],
    offset: u64,
) -> Result<(), ArtifactChainJournalError> {
    file.read_exact(bytes)
        .map_err(|source| ArtifactChainJournalError::Read { offset, source })?;
    Ok(())
}

/// A fail-closed artifact-chain journal error.
#[cfg(test)]
mod tests;
