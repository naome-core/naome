use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, SeekFrom, Write};
use std::path::Path;

use naome_chain::ArtifactBlock;
use naome_foundation::FOUNDATION_ID;
use naome_ledger::AcceptedArtifactRecord;
use naome_proof::{ARTIFACT_PAYLOAD_MAX_BYTES, ArtifactId};
use sha2::{Digest, Sha256};

use crate::{
    AppendPhase, ArtifactChainJournal, ArtifactChainJournalError, ExclusiveLockError, StoreIo,
    open_exclusive_lock,
};

const LOCK_FILE_NAME: &str = "artifact-payload-store.lock";
const STORE_FILE_NAME: &str = "artifact-payload-store.log";
const STORE_HEADER: &[u8] = b"naome:artifact-payload-store:v1\0";
const ENTRY_DOMAIN: &[u8] = b"naome:artifact-payload-store-entry:v1\0";
const PAYLOAD_LENGTH_BYTES: u64 = 4;
const ARTIFACT_ID_BYTES: u64 = ArtifactId::BYTE_LENGTH as u64;
const DIGEST_BYTES: u64 = 32;
const ENTRY_FIXED_BYTES: u64 = PAYLOAD_LENGTH_BYTES + ARTIFACT_ID_BYTES + DIGEST_BYTES;
const STORE_PREFIX_BYTES: u64 = (STORE_HEADER.len() + FOUNDATION_ID.len()) as u64;
const REPLAY_BUFFER_BYTES: usize = 8 * 1024;

/// Local resource limits for one canonical artifact-payload store handle.
///
/// Limits are caller policy rather than persisted identity. Reopening the same
/// store with different positive limits is allowed if its complete committed
/// contents fit those limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactPayloadStoreLimits {
    max_entries: usize,
    max_total_payload_bytes: u64,
}

impl ArtifactPayloadStoreLimits {
    /// Constructs positive entry-count and aggregate-payload limits.
    pub const fn new(
        max_entries: usize,
        max_total_payload_bytes: u64,
    ) -> Result<Self, ArtifactPayloadStoreLimitsError> {
        if max_entries == 0 {
            return Err(ArtifactPayloadStoreLimitsError::ZeroMaxEntries);
        }
        if max_total_payload_bytes == 0 {
            return Err(ArtifactPayloadStoreLimitsError::ZeroMaxTotalPayloadBytes);
        }
        Ok(Self {
            max_entries,
            max_total_payload_bytes,
        })
    }

    /// Returns the maximum number of retained payloads.
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Returns the maximum aggregate bytes of retained payloads.
    pub const fn max_total_payload_bytes(&self) -> u64 {
        self.max_total_payload_bytes
    }
}

/// A rejected artifact-payload store limit configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactPayloadStoreLimitsError {
    /// At least one retained entry must be permitted.
    ZeroMaxEntries,
    /// At least one retained payload byte must be permitted.
    ZeroMaxTotalPayloadBytes,
}

impl fmt::Display for ArtifactPayloadStoreLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxEntries => {
                formatter.write_str("artifact payload store entry limit must be positive")
            }
            Self::ZeroMaxTotalPayloadBytes => formatter
                .write_str("artifact payload store aggregate payload-byte limit must be positive"),
        }
    }
}

impl Error for ArtifactPayloadStoreLimitsError {}

/// One immutable tagged canonical artifact payload loaded from local storage.
///
/// The payload entered through an [`AcceptedArtifactRecord`] or the same-call
/// direct-child validation gate, but loading does not recreate that checked
/// context. Before admission elsewhere, consumers must strictly decode, require
/// canonical bytes, resolve and check dependencies, and compare the resulting
/// artifact identity with [`Self::artifact_id`].
#[derive(PartialEq, Eq)]
#[must_use]
pub struct CanonicalArtifactPayload {
    artifact_id: ArtifactId,
    canonical_artifact_bytes: Box<[u8]>,
}

impl CanonicalArtifactPayload {
    /// Returns the address associated with the archived payload.
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact_id
    }

    /// Returns the exact archived tagged canonical artifact bytes.
    pub fn canonical_artifact_bytes(&self) -> &[u8] {
        &self.canonical_artifact_bytes
    }

    /// Consumes the payload and returns its exact owned bytes.
    pub fn into_canonical_artifact_bytes(self) -> Box<[u8]> {
        self.canonical_artifact_bytes
    }
}

impl fmt::Debug for CanonicalArtifactPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalArtifactPayload")
            .field("artifact_id", &self.artifact_id)
            .field(
                "canonical_artifact_bytes_len",
                &self.canonical_artifact_bytes.len(),
            )
            .finish()
    }
}

/// The result of inserting one strictly gated artifact payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum ArtifactPayloadInsertOutcome {
    /// A new immutable payload was durably appended.
    Inserted,
    /// The same artifact identity and exact payload were already retained.
    AlreadyPresent,
}

/// A failed direct-child candidate validation or payload archive.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidatePayloadArchiveError {
    /// The block or payload failed validation against the journal's current head.
    Validation {
        source: Box<ArtifactChainJournalError>,
    },
    /// The strictly validated payload could not be archived.
    Archive {
        source: Box<CanonicalArtifactPayloadStoreError>,
    },
}

impl CandidatePayloadArchiveError {
    fn validation(source: ArtifactChainJournalError) -> Self {
        Self::Validation {
            source: Box::new(source),
        }
    }

    fn archive(source: CanonicalArtifactPayloadStoreError) -> Self {
        Self::Archive {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for CandidatePayloadArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation { source } => {
                write!(formatter, "candidate payload validation failed: {source}")
            }
            Self::Archive { source } => {
                write!(
                    formatter,
                    "validated candidate payload archive failed: {source}"
                )
            }
        }
    }
}

impl Error for CandidatePayloadArchiveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Validation { source } => Some(source.as_ref()),
            Self::Archive { source } => Some(source.as_ref()),
        }
    }
}

/// An exclusively opened append-only archive of canonical artifact payloads.
///
/// The archive is scoped to the compiled Foundation contract rather than one
/// deployment or artifact chain. Writes accept either an already checked
/// [`AcceptedArtifactRecord`] or exact bytes validated in the same call against
/// one journal's current direct-child candidate. Persisted entries contain no
/// dependency, statement, derivation, selected-chain, or consensus metadata.
///
/// A commit I/O error poisons the handle because the durable outcome is then
/// ambiguous. A post-open read or integrity failure also poisons it because the
/// retained index can no longer be trusted. Dropping and reopening is the only
/// recovery path.
#[must_use]
pub struct CanonicalArtifactPayloadStore {
    _lock: File,
    core: ArtifactPayloadStoreCore<File>,
}

impl CanonicalArtifactPayloadStore {
    /// Creates and exclusively opens a new empty payload store.
    ///
    /// Creation never replaces an existing store. The Foundation-scoped prefix
    /// is synchronized before this function succeeds. Portable parent-directory
    /// entry durability remains the caller's provisioning responsibility.
    pub fn create(
        directory: impl AsRef<Path>,
        limits: ArtifactPayloadStoreLimits,
    ) -> Result<Self, CanonicalArtifactPayloadStoreError> {
        let directory = directory.as_ref();
        let lock = open_and_lock(directory)?;
        let store_path = directory.join(STORE_FILE_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(store_path)
            .map_err(|source| CanonicalArtifactPayloadStoreError::Create { source })?;

        file.write_all(STORE_HEADER)
            .and_then(|()| file.write_all(FOUNDATION_ID.as_bytes()))
            .and_then(|()| file.sync_all())
            .map_err(|source| CanonicalArtifactPayloadStoreError::Create { source })?;

        Ok(Self {
            _lock: lock,
            core: ArtifactPayloadStoreCore::empty(file, limits),
        })
    }

    /// Exclusively opens, verifies, and recovers an existing payload store.
    ///
    /// Replay streams entry integrity checks and retains only an address/offset
    /// index. One in-bounds framing-incomplete final entry is truncated to the
    /// preceding committed boundary. Complete invalid entries fail closed.
    pub fn open(
        directory: impl AsRef<Path>,
        limits: ArtifactPayloadStoreLimits,
    ) -> Result<Self, CanonicalArtifactPayloadStoreError> {
        let directory = directory.as_ref();
        let lock = open_and_lock(directory)?;
        let store_path = directory.join(STORE_FILE_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(store_path)
            .map_err(|source| CanonicalArtifactPayloadStoreError::Open { source })?;
        let core = ArtifactPayloadStoreCore::replay(file, limits)?;
        Ok(Self { _lock: lock, core })
    }

    /// Durably archives the exact canonical payload from one accepted record.
    ///
    /// Repeating the exact identity and bytes is idempotent even at configured
    /// capacity. The same identity with different bytes is rejected without
    /// replacement or file mutation.
    pub fn insert(
        &mut self,
        record: &AcceptedArtifactRecord,
    ) -> Result<ArtifactPayloadInsertOutcome, CanonicalArtifactPayloadStoreError> {
        self.core.insert(record)
    }

    /// Strictly validates and durably archives one direct-child candidate payload.
    ///
    /// Archive health is checked before candidate work. Validation then uses the
    /// journal's current exact head and selected artifact state without mutating
    /// either. Only bytes that pass the complete existing block and artifact
    /// validation are passed to the private archive write gate. Success does not
    /// reserve, select, or authorize the block, and every later use of archived
    /// bytes must validate them again in its target state.
    pub fn validate_and_insert_candidate_payload(
        &mut self,
        selected: &ArtifactChainJournal,
        block: &ArtifactBlock,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<ArtifactPayloadInsertOutcome, CandidatePayloadArchiveError> {
        self.core
            .ensure_healthy()
            .map_err(CandidatePayloadArchiveError::archive)?;
        if canonical_artifact_bytes.len() > ARTIFACT_PAYLOAD_MAX_BYTES {
            return match selected.validate_block(block, canonical_artifact_bytes) {
                Err(source) => Err(CandidatePayloadArchiveError::validation(source)),
                Ok(()) => unreachable!(
                    "journal validation cannot accept an artifact payload above the canonical byte limit"
                ),
            };
        }
        let archive_bytes = canonical_artifact_bytes.clone();
        selected
            .validate_block(block, canonical_artifact_bytes)
            .map_err(CandidatePayloadArchiveError::validation)?;
        self.core
            .insert_payload(block.artifact_id(), &archive_bytes)
            .map_err(CandidatePayloadArchiveError::archive)
    }

    /// Loads one exact owned payload candidate and rechecks its entry integrity.
    ///
    /// The result is not a reusable checked record. A target ledger or branch
    /// must perform complete context-specific artifact admission again.
    pub fn get(
        &mut self,
        artifact_id: ArtifactId,
    ) -> Result<Option<CanonicalArtifactPayload>, CanonicalArtifactPayloadStoreError> {
        self.core.get(artifact_id)
    }

    /// Returns whether an exact artifact address is indexed.
    pub fn contains(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<bool, CanonicalArtifactPayloadStoreError> {
        self.core.ensure_healthy()?;
        Ok(self.core.index.contains_key(&artifact_id))
    }

    /// Returns the number of uniquely archived artifact payloads.
    pub fn len(&self) -> Result<usize, CanonicalArtifactPayloadStoreError> {
        self.core.ensure_healthy()?;
        Ok(self.core.index.len())
    }

    /// Returns whether no artifact payloads are archived.
    pub fn is_empty(&self) -> Result<bool, CanonicalArtifactPayloadStoreError> {
        self.core.ensure_healthy()?;
        Ok(self.core.index.is_empty())
    }

    /// Returns the aggregate bytes of uniquely archived payloads.
    pub fn total_payload_bytes(&self) -> Result<u64, CanonicalArtifactPayloadStoreError> {
        self.core.ensure_healthy()?;
        Ok(self.core.total_payload_bytes)
    }

    /// Returns the local resource policy used by this handle.
    pub const fn limits(&self) -> ArtifactPayloadStoreLimits {
        self.core.limits
    }
}

fn open_and_lock(directory: &Path) -> Result<File, CanonicalArtifactPayloadStoreError> {
    open_exclusive_lock(directory, LOCK_FILE_NAME).map_err(|error| match error {
        ExclusiveLockError::LockFile(source) => {
            CanonicalArtifactPayloadStoreError::LockFile { source }
        }
        ExclusiveLockError::Locked => CanonicalArtifactPayloadStoreError::Locked,
        ExclusiveLockError::Lock(source) => CanonicalArtifactPayloadStoreError::Lock { source },
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PayloadLocation {
    entry_offset: u64,
    payload_len: u32,
}

struct ArtifactPayloadStoreCore<F> {
    file: F,
    index: HashMap<ArtifactId, PayloadLocation>,
    total_payload_bytes: u64,
    committed_end: u64,
    limits: ArtifactPayloadStoreLimits,
    poisoned: bool,
}

impl<F: StoreIo> ArtifactPayloadStoreCore<F> {
    fn empty(file: F, limits: ArtifactPayloadStoreLimits) -> Self {
        Self {
            file,
            index: HashMap::new(),
            total_payload_bytes: 0,
            committed_end: STORE_PREFIX_BYTES,
            limits,
            poisoned: false,
        }
    }

    fn replay(
        mut file: F,
        limits: ArtifactPayloadStoreLimits,
    ) -> Result<Self, CanonicalArtifactPayloadStoreError> {
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|source| CanonicalArtifactPayloadStoreError::Read { offset: 0, source })?;
        if file_len < STORE_PREFIX_BYTES {
            return Err(CanonicalArtifactPayloadStoreError::InvalidHeader);
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|source| CanonicalArtifactPayloadStoreError::Read { offset: 0, source })?;
        let mut header = [0_u8; STORE_HEADER.len()];
        read_field(&mut file, &mut header, 0)?;
        if header != STORE_HEADER {
            return Err(CanonicalArtifactPayloadStoreError::InvalidHeader);
        }
        let mut foundation = [0_u8; FOUNDATION_ID.len()];
        read_field(&mut file, &mut foundation, STORE_HEADER.len() as u64)?;
        if foundation != FOUNDATION_ID.as_bytes() {
            return Err(CanonicalArtifactPayloadStoreError::FoundationIdMismatch);
        }

        let mut index = HashMap::new();
        let mut total_payload_bytes = 0_u64;
        let mut entry_start = STORE_PREFIX_BYTES;
        let mut entry = 0_u64;
        let mut buffer = [0_u8; REPLAY_BUFFER_BYTES];

        while entry_start < file_len {
            let remaining = file_len - entry_start;
            if remaining < PAYLOAD_LENGTH_BYTES {
                return Self::finish_replay(
                    file,
                    index,
                    total_payload_bytes,
                    entry_start,
                    limits,
                    Some(entry_start),
                );
            }

            let mut payload_length_bytes = [0_u8; PAYLOAD_LENGTH_BYTES as usize];
            read_field(&mut file, &mut payload_length_bytes, entry_start)?;
            let payload_len = u32::from_be_bytes(payload_length_bytes);
            if payload_len == 0 || payload_len as usize > ARTIFACT_PAYLOAD_MAX_BYTES {
                return Err(CanonicalArtifactPayloadStoreError::InvalidPayloadLength {
                    entry,
                    offset: entry_start,
                    actual: payload_len,
                    maximum: ARTIFACT_PAYLOAD_MAX_BYTES as u32,
                });
            }

            let entry_len = ENTRY_FIXED_BYTES + u64::from(payload_len);
            let entry_end = entry_start.checked_add(entry_len).ok_or(
                CanonicalArtifactPayloadStoreError::EntryOffsetOverflow {
                    entry,
                    offset: entry_start,
                },
            )?;
            if file_len < entry_end {
                return Self::finish_replay(
                    file,
                    index,
                    total_payload_bytes,
                    entry_start,
                    limits,
                    Some(entry_start),
                );
            }

            let artifact_id_offset = entry_start + PAYLOAD_LENGTH_BYTES;
            let mut artifact_id_bytes = [0_u8; ArtifactId::BYTE_LENGTH];
            read_field(&mut file, &mut artifact_id_bytes, artifact_id_offset)?;
            let artifact_id = ArtifactId::from_bytes(artifact_id_bytes);

            let mut hasher = entry_hasher(payload_length_bytes, artifact_id);
            let payload_offset = artifact_id_offset + ARTIFACT_ID_BYTES;
            let mut payload_remaining = payload_len as usize;
            let mut read_offset = payload_offset;
            while payload_remaining > 0 {
                let chunk_len = payload_remaining.min(buffer.len());
                let chunk = &mut buffer[..chunk_len];
                read_field(&mut file, chunk, read_offset)?;
                hasher.update(&*chunk);
                payload_remaining -= chunk_len;
                read_offset += chunk_len as u64;
            }

            let mut stored_digest = [0_u8; DIGEST_BYTES as usize];
            read_field(&mut file, &mut stored_digest, entry_end - DIGEST_BYTES)?;
            let expected_digest: [u8; DIGEST_BYTES as usize] = hasher.finalize().into();
            if stored_digest != expected_digest {
                return Err(CanonicalArtifactPayloadStoreError::EntryDigestMismatch {
                    entry,
                    offset: entry_start,
                    artifact_id,
                });
            }
            if index.contains_key(&artifact_id) {
                return Err(CanonicalArtifactPayloadStoreError::DuplicateArtifactId {
                    entry,
                    offset: entry_start,
                    artifact_id,
                });
            }

            let actual_entries = index
                .len()
                .checked_add(1)
                .ok_or(CanonicalArtifactPayloadStoreError::EntryCountOverflow)?;
            if actual_entries > limits.max_entries {
                return Err(CanonicalArtifactPayloadStoreError::EntryLimitExceeded {
                    actual: actual_entries,
                    maximum: limits.max_entries,
                });
            }
            let actual_payload_bytes = total_payload_bytes
                .checked_add(u64::from(payload_len))
                .ok_or(CanonicalArtifactPayloadStoreError::PayloadByteCountOverflow)?;
            if actual_payload_bytes > limits.max_total_payload_bytes {
                return Err(
                    CanonicalArtifactPayloadStoreError::PayloadByteLimitExceeded {
                        actual: actual_payload_bytes,
                        maximum: limits.max_total_payload_bytes,
                    },
                );
            }

            reserve_index_entry(&mut index, entry)?;
            let replaced = index.insert(
                artifact_id,
                PayloadLocation {
                    entry_offset: entry_start,
                    payload_len,
                },
            );
            debug_assert!(replaced.is_none());
            total_payload_bytes = actual_payload_bytes;
            entry_start = entry_end;
            entry += 1;
        }

        Self::finish_replay(file, index, total_payload_bytes, entry_start, limits, None)
    }

    fn finish_replay(
        mut file: F,
        index: HashMap<ArtifactId, PayloadLocation>,
        total_payload_bytes: u64,
        committed_end: u64,
        limits: ArtifactPayloadStoreLimits,
        recovery_offset: Option<u64>,
    ) -> Result<Self, CanonicalArtifactPayloadStoreError> {
        if let Some(offset) = recovery_offset {
            recover_tail(&mut file, offset)?;
        } else {
            file.sync_all()
                .map_err(|source| CanonicalArtifactPayloadStoreError::Stabilize { source })?;
        }
        Ok(Self {
            file,
            index,
            total_payload_bytes,
            committed_end,
            limits,
            poisoned: false,
        })
    }

    fn insert(
        &mut self,
        record: &AcceptedArtifactRecord,
    ) -> Result<ArtifactPayloadInsertOutcome, CanonicalArtifactPayloadStoreError> {
        self.insert_payload(record.artifact_id(), record.canonical_artifact_bytes())
    }

    fn insert_payload(
        &mut self,
        artifact_id: ArtifactId,
        payload: &[u8],
    ) -> Result<ArtifactPayloadInsertOutcome, CanonicalArtifactPayloadStoreError> {
        self.ensure_healthy()?;
        debug_assert!(!payload.is_empty());
        debug_assert!(payload.len() <= ARTIFACT_PAYLOAD_MAX_BYTES);

        if let Some(location) = self.index.get(&artifact_id).copied() {
            let matches =
                match stored_payload_matches(&mut self.file, location, artifact_id, payload) {
                    Ok(matches) => matches,
                    Err(error) => return Err(self.poison_stored_read(artifact_id, error)),
                };
            return if matches {
                Ok(ArtifactPayloadInsertOutcome::AlreadyPresent)
            } else {
                Err(CanonicalArtifactPayloadStoreError::PayloadConflict { artifact_id })
            };
        }

        let actual_entries = self
            .index
            .len()
            .checked_add(1)
            .ok_or(CanonicalArtifactPayloadStoreError::EntryCountOverflow)?;
        if actual_entries > self.limits.max_entries {
            return Err(CanonicalArtifactPayloadStoreError::EntryLimitExceeded {
                actual: actual_entries,
                maximum: self.limits.max_entries,
            });
        }
        let payload_len = u32::try_from(payload.len())
            .expect("an accepted canonical artifact payload length fits u32");
        let actual_payload_bytes = self
            .total_payload_bytes
            .checked_add(u64::from(payload_len))
            .ok_or(CanonicalArtifactPayloadStoreError::PayloadByteCountOverflow)?;
        if actual_payload_bytes > self.limits.max_total_payload_bytes {
            return Err(
                CanonicalArtifactPayloadStoreError::PayloadByteLimitExceeded {
                    actual: actual_payload_bytes,
                    maximum: self.limits.max_total_payload_bytes,
                },
            );
        }

        let entry = u64::try_from(self.index.len()).expect("payload index length fits u64");
        reserve_index_entry(&mut self.index, entry)?;
        let payload_length_bytes = payload_len.to_be_bytes();
        let digest = entry_digest(payload_length_bytes, artifact_id, payload);
        let entry_offset = self.committed_end;
        let entry_end = entry_offset
            .checked_add(ENTRY_FIXED_BYTES + u64::from(payload_len))
            .ok_or(CanonicalArtifactPayloadStoreError::EntryOffsetOverflow {
                entry,
                offset: entry_offset,
            })?;

        let commit_result = (|| -> io::Result<()> {
            self.file.seek(SeekFrom::Start(entry_offset))?;
            self.file
                .append_write_all(AppendPhase::Body, &payload_length_bytes)?;
            self.file
                .append_write_all(AppendPhase::Body, artifact_id.as_bytes())?;
            self.file.append_write_all(AppendPhase::Body, payload)?;
            self.file.append_sync_all(AppendPhase::Body)?;
            self.file.append_write_all(AppendPhase::Commit, &digest)?;
            self.file.append_sync_all(AppendPhase::Commit)?;
            Ok(())
        })();

        if let Err(source) = commit_result {
            self.poisoned = true;
            return Err(CanonicalArtifactPayloadStoreError::Commit {
                artifact_id,
                payload_bytes: payload.len(),
                source,
            });
        }

        let replaced = self.index.insert(
            artifact_id,
            PayloadLocation {
                entry_offset,
                payload_len,
            },
        );
        debug_assert!(replaced.is_none());
        self.total_payload_bytes = actual_payload_bytes;
        self.committed_end = entry_end;
        Ok(ArtifactPayloadInsertOutcome::Inserted)
    }

    fn get(
        &mut self,
        artifact_id: ArtifactId,
    ) -> Result<Option<CanonicalArtifactPayload>, CanonicalArtifactPayloadStoreError> {
        self.ensure_healthy()?;
        let Some(location) = self.index.get(&artifact_id).copied() else {
            return Ok(None);
        };

        let payload_len = location.payload_len as usize;
        let mut payload = Vec::new();
        payload.try_reserve_exact(payload_len).map_err(|_| {
            CanonicalArtifactPayloadStoreError::PayloadAllocation {
                artifact_id,
                bytes: payload_len,
            }
        })?;
        payload.resize(payload_len, 0);
        if let Err(error) = read_stored_payload(&mut self.file, location, artifact_id, &mut payload)
        {
            return Err(self.poison_stored_read(artifact_id, error));
        }
        Ok(Some(CanonicalArtifactPayload {
            artifact_id,
            canonical_artifact_bytes: payload.into_boxed_slice(),
        }))
    }

    fn poison_stored_read(
        &mut self,
        artifact_id: ArtifactId,
        error: StoredReadError,
    ) -> CanonicalArtifactPayloadStoreError {
        self.poisoned = true;
        match error {
            StoredReadError::Io { offset, source } => {
                CanonicalArtifactPayloadStoreError::Read { offset, source }
            }
            StoredReadError::Changed => {
                CanonicalArtifactPayloadStoreError::StoredEntryChanged { artifact_id }
            }
        }
    }

    fn ensure_healthy(&self) -> Result<(), CanonicalArtifactPayloadStoreError> {
        if self.poisoned {
            Err(CanonicalArtifactPayloadStoreError::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn entry_hasher(payload_length_bytes: [u8; 4], artifact_id: ArtifactId) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(ENTRY_DOMAIN);
    hasher.update(
        u32::try_from(FOUNDATION_ID.len())
            .expect("Foundation identifier length fits u32")
            .to_be_bytes(),
    );
    hasher.update(FOUNDATION_ID.as_bytes());
    hasher.update(payload_length_bytes);
    hasher.update(artifact_id.as_bytes());
    hasher
}

fn entry_digest(
    payload_length_bytes: [u8; 4],
    artifact_id: ArtifactId,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = entry_hasher(payload_length_bytes, artifact_id);
    hasher.update(payload);
    hasher.finalize().into()
}

fn reserve_index_entry(
    index: &mut HashMap<ArtifactId, PayloadLocation>,
    entry: u64,
) -> Result<(), CanonicalArtifactPayloadStoreError> {
    index
        .try_reserve(1)
        .map_err(|_| CanonicalArtifactPayloadStoreError::IndexAllocation { entry })
}

fn recover_tail<F: StoreIo>(
    file: &mut F,
    offset: u64,
) -> Result<(), CanonicalArtifactPayloadStoreError> {
    file.set_len(offset)
        .and_then(|()| file.sync_all())
        .map_err(|source| CanonicalArtifactPayloadStoreError::Recovery { offset, source })
}

fn read_field<F: StoreIo>(
    file: &mut F,
    bytes: &mut [u8],
    offset: u64,
) -> Result<(), CanonicalArtifactPayloadStoreError> {
    file.read_exact(bytes)
        .map_err(|source| CanonicalArtifactPayloadStoreError::Read { offset, source })
}

#[derive(Debug)]
enum StoredReadError {
    Io { offset: u64, source: io::Error },
    Changed,
}

fn read_stored_header<F: StoreIo>(
    file: &mut F,
    location: PayloadLocation,
    expected_artifact_id: ArtifactId,
) -> Result<Sha256, StoredReadError> {
    file.seek(SeekFrom::Start(location.entry_offset))
        .map_err(|source| StoredReadError::Io {
            offset: location.entry_offset,
            source,
        })?;
    let mut payload_length_bytes = [0_u8; PAYLOAD_LENGTH_BYTES as usize];
    file.read_exact(&mut payload_length_bytes)
        .map_err(|source| StoredReadError::Io {
            offset: location.entry_offset,
            source,
        })?;
    if u32::from_be_bytes(payload_length_bytes) != location.payload_len {
        return Err(StoredReadError::Changed);
    }
    let artifact_id_offset = location.entry_offset + PAYLOAD_LENGTH_BYTES;
    let mut artifact_id_bytes = [0_u8; ArtifactId::BYTE_LENGTH];
    file.read_exact(&mut artifact_id_bytes)
        .map_err(|source| StoredReadError::Io {
            offset: artifact_id_offset,
            source,
        })?;
    let actual_artifact_id = ArtifactId::from_bytes(artifact_id_bytes);
    if actual_artifact_id != expected_artifact_id {
        return Err(StoredReadError::Changed);
    }
    Ok(entry_hasher(payload_length_bytes, expected_artifact_id))
}

fn verify_stored_footer<F: StoreIo>(
    file: &mut F,
    location: PayloadLocation,
    hasher: Sha256,
) -> Result<(), StoredReadError> {
    let footer_offset = location.entry_offset
        + PAYLOAD_LENGTH_BYTES
        + ARTIFACT_ID_BYTES
        + u64::from(location.payload_len);
    let mut stored_digest = [0_u8; DIGEST_BYTES as usize];
    file.read_exact(&mut stored_digest)
        .map_err(|source| StoredReadError::Io {
            offset: footer_offset,
            source,
        })?;
    let expected_digest: [u8; DIGEST_BYTES as usize] = hasher.finalize().into();
    if stored_digest != expected_digest {
        return Err(StoredReadError::Changed);
    }
    Ok(())
}

fn stored_payload_matches<F: StoreIo>(
    file: &mut F,
    location: PayloadLocation,
    expected_artifact_id: ArtifactId,
    expected_payload: &[u8],
) -> Result<bool, StoredReadError> {
    let mut hasher = read_stored_header(file, location, expected_artifact_id)?;
    let mut matches = expected_payload.len() == location.payload_len as usize;
    let mut payload_remaining = location.payload_len as usize;
    let mut expected_offset = 0_usize;
    let mut read_offset = location.entry_offset + PAYLOAD_LENGTH_BYTES + ARTIFACT_ID_BYTES;
    let mut buffer = [0_u8; REPLAY_BUFFER_BYTES];
    while payload_remaining > 0 {
        let chunk_len = payload_remaining.min(buffer.len());
        let chunk = &mut buffer[..chunk_len];
        file.read_exact(chunk)
            .map_err(|source| StoredReadError::Io {
                offset: read_offset,
                source,
            })?;
        hasher.update(&*chunk);
        if matches
            && chunk
                != &expected_payload[expected_offset..expected_offset.saturating_add(chunk_len)]
        {
            matches = false;
        }
        payload_remaining -= chunk_len;
        expected_offset += chunk_len;
        read_offset += chunk_len as u64;
    }
    verify_stored_footer(file, location, hasher)?;
    Ok(matches)
}

fn read_stored_payload<F: StoreIo>(
    file: &mut F,
    location: PayloadLocation,
    expected_artifact_id: ArtifactId,
    payload: &mut [u8],
) -> Result<(), StoredReadError> {
    debug_assert_eq!(payload.len(), location.payload_len as usize);
    let mut hasher = read_stored_header(file, location, expected_artifact_id)?;
    let payload_offset = location.entry_offset + PAYLOAD_LENGTH_BYTES + ARTIFACT_ID_BYTES;
    file.read_exact(payload)
        .map_err(|source| StoredReadError::Io {
            offset: payload_offset,
            source,
        })?;
    hasher.update(&*payload);
    verify_stored_footer(file, location, hasher)
}

/// A fail-closed canonical artifact-payload store error.
#[derive(Debug)]
#[non_exhaustive]
pub enum CanonicalArtifactPayloadStoreError {
    /// The sidecar lock file could not be opened.
    LockFile { source: io::Error },
    /// Another process or handle already owns the payload-store lock.
    Locked,
    /// The operating-system file lock could not be acquired.
    Lock { source: io::Error },
    /// A new payload-store file could not be created or initialized.
    Create { source: io::Error },
    /// An existing payload-store file could not be opened.
    Open { source: io::Error },
    /// Existing payload-store bytes could not be read.
    Read { offset: u64, source: io::Error },
    /// The store header is incomplete or unsupported.
    InvalidHeader,
    /// The store was written for a different Foundation contract.
    FoundationIdMismatch,
    /// A complete entry declares an impossible payload length.
    InvalidPayloadLength {
        entry: u64,
        offset: u64,
        actual: u32,
        maximum: u32,
    },
    /// An entry boundary cannot be represented safely.
    EntryOffsetOverflow { entry: u64, offset: u64 },
    /// A complete entry fails its accidental-corruption integrity digest.
    EntryDigestMismatch {
        entry: u64,
        offset: u64,
        artifact_id: ArtifactId,
    },
    /// A committed log contains the same immutable artifact address twice.
    DuplicateArtifactId {
        entry: u64,
        offset: u64,
        artifact_id: ArtifactId,
    },
    /// Counting one more indexed entry overflowed the platform range.
    EntryCountOverflow,
    /// The complete committed store exceeds the local entry-count policy.
    EntryLimitExceeded { actual: usize, maximum: usize },
    /// Summing complete committed payload lengths overflowed `u64`.
    PayloadByteCountOverflow,
    /// The complete committed store exceeds the local aggregate-byte policy.
    PayloadByteLimitExceeded { actual: u64, maximum: u64 },
    /// Reserving one bounded index slot failed.
    IndexAllocation { entry: u64 },
    /// Allocating one exact bounded payload result failed.
    PayloadAllocation {
        artifact_id: ArtifactId,
        bytes: usize,
    },
    /// One address is already durably associated with different exact bytes.
    PayloadConflict { artifact_id: ArtifactId },
    /// A previously indexed entry changed or failed its integrity check.
    StoredEntryChanged { artifact_id: ArtifactId },
    /// An incomplete final entry could not be removed durably.
    Recovery { offset: u64, source: io::Error },
    /// A fully replayed visible store image could not be stabilized.
    Stabilize { source: io::Error },
    /// Commit durability is unknown and the handle is now poisoned.
    Commit {
        artifact_id: ArtifactId,
        payload_bytes: usize,
        source: io::Error,
    },
    /// Memory may disagree with durable storage after an ambiguous operation.
    Poisoned,
}

impl fmt::Display for CanonicalArtifactPayloadStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockFile { source } => write!(formatter, "payload store lock failed: {source}"),
            Self::Locked => {
                formatter.write_str("artifact payload store is already exclusively open")
            }
            Self::Lock { source } => write!(formatter, "payload store locking failed: {source}"),
            Self::Create { source } => write!(formatter, "payload store creation failed: {source}"),
            Self::Open { source } => write!(formatter, "payload store opening failed: {source}"),
            Self::Read { offset, source } => {
                write!(
                    formatter,
                    "payload store read failed at byte {offset}: {source}"
                )
            }
            Self::InvalidHeader => formatter.write_str("invalid artifact payload store header"),
            Self::FoundationIdMismatch => {
                formatter.write_str("artifact payload store Foundation identifier mismatch")
            }
            Self::InvalidPayloadLength {
                entry,
                offset,
                actual,
                maximum,
            } => write!(
                formatter,
                "payload store entry {entry} at byte {offset} has payload length {actual}, expected 1..={maximum}"
            ),
            Self::EntryOffsetOverflow { entry, offset } => write!(
                formatter,
                "payload store entry {entry} at byte {offset} exceeds the offset range"
            ),
            Self::EntryDigestMismatch {
                entry,
                offset,
                artifact_id,
            } => write!(
                formatter,
                "payload store entry {entry} at byte {offset} for {artifact_id:?} has an invalid digest"
            ),
            Self::DuplicateArtifactId {
                entry,
                offset,
                artifact_id,
            } => write!(
                formatter,
                "payload store entry {entry} at byte {offset} duplicates artifact {artifact_id:?}"
            ),
            Self::EntryCountOverflow => {
                formatter.write_str("artifact payload store entry count overflowed")
            }
            Self::EntryLimitExceeded { actual, maximum } => write!(
                formatter,
                "artifact payload store has {actual} entries, exceeding limit {maximum}"
            ),
            Self::PayloadByteCountOverflow => {
                formatter.write_str("artifact payload store byte count overflowed")
            }
            Self::PayloadByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "artifact payload store has {actual} payload bytes, exceeding limit {maximum}"
            ),
            Self::IndexAllocation { entry } => write!(
                formatter,
                "payload store entry {entry} could not reserve its index slot"
            ),
            Self::PayloadAllocation { artifact_id, bytes } => write!(
                formatter,
                "artifact payload {artifact_id:?} could not allocate {bytes} bytes"
            ),
            Self::PayloadConflict { artifact_id } => write!(
                formatter,
                "artifact payload {artifact_id:?} is already associated with different bytes"
            ),
            Self::StoredEntryChanged { artifact_id } => write!(
                formatter,
                "indexed artifact payload {artifact_id:?} changed after store open"
            ),
            Self::Recovery { offset, source } => write!(
                formatter,
                "incomplete payload store tail at byte {offset} could not be recovered: {source}"
            ),
            Self::Stabilize { source } => {
                write!(formatter, "payload store stabilization failed: {source}")
            }
            Self::Commit {
                artifact_id,
                payload_bytes,
                source,
            } => write!(
                formatter,
                "payload store commit of {artifact_id:?} with {payload_bytes} bytes has unknown durability: {source}"
            ),
            Self::Poisoned => formatter.write_str(
                "payload store is poisoned after an ambiguous operation; drop and reopen it",
            ),
        }
    }
}

impl Error for CanonicalArtifactPayloadStoreError {
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
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
