//! Crash-consistent local persistence for the selected NAOME proof DAG.
//!
//! [`ProofDagJournal`] stores only canonical proof-certificate payloads in
//! dependency-first admission order. Opening a journal reconstructs every
//! identity, dependency edge, and checked conclusion through strict
//! [`ProofDag`] replay; persisted bytes never bypass proof validation.
//!
//! The journal is a local recovery mechanism. Its physical order is neither a
//! consensus order nor proof-finality evidence, and it defines no networking,
//! snapshots, compaction, pruning, or economic state.

use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use naome_chain::{ProofDag, ProofSetProof, ProofSetRoot};
use naome_ledger::{AcceptedProofRecord, LedgerError};
use naome_proof::{CERTIFICATE_MAX_BYTES, ProofId};
use sha2::{Digest, Sha256};

const LOCK_FILE_NAME: &str = "proof-dag.lock";
const JOURNAL_FILE_NAME: &str = "proof-dag.journal";
const JOURNAL_HEADER: &[u8; 24] = b"naome:proof-dag-journal\0";
const GENESIS_DOMAIN: &[u8; 32] = b"naome:proof-dag-journal-genesis\0";
const ENTRY_DOMAIN: &[u8; 30] = b"naome:proof-dag-journal-entry\0";
const DIGEST_BYTES: u64 = 32;
const FRAME_FIXED_BYTES: u64 = 4 + DIGEST_BYTES;

/// An exclusively opened, crash-consistent journal for one selected proof DAG.
///
/// The handle is neither cloneable nor shareable through an inner mutable
/// state. A commit I/O error makes it unusable because the in-memory DAG may
/// then be ahead of durable storage. Dropping and reopening the journal is the
/// only recovery path.
#[must_use]
pub struct ProofDagJournal {
    _lock: File,
    core: JournalCore<File>,
}

impl ProofDagJournal {
    /// Creates and exclusively opens a new journal in an existing directory.
    ///
    /// Creation never replaces or reinitializes an existing journal. The new
    /// file and its header are synchronized before this function succeeds.
    /// Portable parent-directory-entry durability remains the caller's
    /// provisioning responsibility.
    pub fn create(directory: impl AsRef<Path>) -> Result<Self, JournalError> {
        let directory = directory.as_ref();
        let lock = open_and_lock(directory)?;
        let journal_path = directory.join(JOURNAL_FILE_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(journal_path)
            .map_err(|source| JournalError::Create { source })?;

        file.write_all(JOURNAL_HEADER)
            .and_then(|()| file.sync_all())
            .map_err(|source| JournalError::Create { source })?;

        Ok(Self {
            _lock: lock,
            core: JournalCore::empty(file),
        })
    }

    /// Exclusively opens and strictly replays an existing journal.
    ///
    /// One incomplete final frame is treated as an uncommitted append,
    /// truncated, and synchronized before success. A complete corrupt or
    /// proof-invalid frame fails closed and is never skipped or repaired.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, JournalError> {
        let directory = directory.as_ref();
        let lock = open_and_lock(directory)?;
        let journal_path = directory.join(JOURNAL_FILE_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal_path)
            .map_err(|source| JournalError::Open { source })?;
        let core = JournalCore::replay(file)?;

        Ok(Self { _lock: lock, core })
    }

    /// Opens, strictly replays, and verifies the complete selected proof set.
    ///
    /// The expected root must come from a separately trusted source. Every
    /// lock, file-format, digest, recovery, and strict replay check completes
    /// before the final root comparison. This verifies the exact current
    /// journal state, not an arbitrary historical prefix or subset.
    pub fn open_verified(
        directory: impl AsRef<Path>,
        expected_root: ProofSetRoot,
    ) -> Result<Self, JournalError> {
        let journal = Self::open(directory)?;
        let actual = journal.core.dag.proof_set_root();
        if actual != expected_root {
            return Err(JournalError::ProofSetRootMismatch {
                expected: expected_root,
                actual,
            });
        }
        Ok(journal)
    }

    /// Strictly admits and durably commits one canonical proof payload.
    ///
    /// Admission errors write nothing and leave the handle healthy. After
    /// in-memory admission, the frame body and its commit footer are each
    /// synchronized in order. Any ambiguous commit I/O error poisons the
    /// handle and requires drop plus reopen. This entry point is not bound to
    /// an externally requested address; content-addressed retrieval must use
    /// [`Self::apply_canonical_proof_bytes_with_expected_id`].
    pub fn apply_canonical_proof_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<&AcceptedProofRecord, JournalError> {
        self.core.apply_canonical_proof_bytes(bytes)
    }

    /// Strictly admits and commits canonical proof bytes at an expected address.
    ///
    /// A checked identity mismatch is an ordinary admission error: it performs
    /// no file I/O, leaves the journal healthy, and does not change the retained
    /// proof DAG.
    pub fn apply_canonical_proof_bytes_with_expected_id(
        &mut self,
        bytes: Vec<u8>,
        expected_proof_id: ProofId,
    ) -> Result<&AcceptedProofRecord, JournalError> {
        self.core
            .apply_canonical_proof_bytes_with_expected_id(bytes, expected_proof_id)
    }

    /// Returns one locally committed and replay-checked proof record.
    pub fn proof(&self, proof_id: ProofId) -> Result<Option<&AcceptedProofRecord>, JournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.dag.proof(proof_id))
    }

    /// Returns the number of locally committed proof records.
    pub fn len(&self) -> Result<usize, JournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.dag.len())
    }

    /// Returns whether the locally committed proof DAG is empty.
    pub fn is_empty(&self) -> Result<bool, JournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.dag.is_empty())
    }

    /// Returns the authenticated root of the locally committed proof set.
    pub fn proof_set_root(&self) -> Result<ProofSetRoot, JournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.dag.proof_set_root())
    }

    /// Returns a compact proof-set witness from the locally committed state.
    pub fn proof_set_proof(&self, proof_id: ProofId) -> Result<ProofSetProof, JournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.dag.proof_set_proof(proof_id))
    }
}

fn open_and_lock(directory: &Path) -> Result<File, JournalError> {
    let lock_path = directory.join(LOCK_FILE_NAME);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|source| JournalError::LockFile { source })?;

    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(JournalError::Locked),
        Err(TryLockError::Error(source)) => Err(JournalError::Lock { source }),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppendPhase {
    Body,
    Commit,
}

trait JournalIo: Read + Write + Seek {
    fn set_len(&mut self, size: u64) -> io::Result<()>;
    fn sync_all(&mut self) -> io::Result<()>;

    fn append_write_all(&mut self, _phase: AppendPhase, bytes: &[u8]) -> io::Result<()> {
        self.write_all(bytes)
    }

    fn append_sync_all(&mut self, _phase: AppendPhase) -> io::Result<()> {
        self.sync_all()
    }
}

impl JournalIo for File {
    fn set_len(&mut self, size: u64) -> io::Result<()> {
        File::set_len(self, size)
    }

    fn sync_all(&mut self) -> io::Result<()> {
        File::sync_all(self)
    }
}

struct JournalCore<F> {
    file: F,
    dag: ProofDag,
    committed_end: u64,
    chain_digest: [u8; 32],
    poisoned: bool,
}

impl<F: JournalIo> JournalCore<F> {
    fn empty(file: F) -> Self {
        Self {
            file,
            dag: ProofDag::new(),
            committed_end: JOURNAL_HEADER.len() as u64,
            chain_digest: genesis_digest(),
            poisoned: false,
        }
    }

    fn replay(mut file: F) -> Result<Self, JournalError> {
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|source| JournalError::Read { offset: 0, source })?;
        if file_len < JOURNAL_HEADER.len() as u64 {
            return Err(JournalError::InvalidHeader);
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|source| JournalError::Read { offset: 0, source })?;
        let mut header = [0_u8; JOURNAL_HEADER.len()];
        file.read_exact(&mut header)
            .map_err(|source| JournalError::Read { offset: 0, source })?;
        if &header != JOURNAL_HEADER {
            return Err(JournalError::InvalidHeader);
        }

        let mut dag = ProofDag::new();
        let mut chain_digest = genesis_digest();
        let mut frame_start = JOURNAL_HEADER.len() as u64;
        let mut entry = 0_u64;

        while frame_start < file_len {
            let remaining = file_len - frame_start;
            if remaining < 4 {
                recover_tail(&mut file, frame_start)?;
                return Ok(Self {
                    file,
                    dag,
                    committed_end: frame_start,
                    chain_digest,
                    poisoned: false,
                });
            }

            let mut length_bytes = [0_u8; 4];
            file.read_exact(&mut length_bytes)
                .map_err(|source| JournalError::Read {
                    offset: frame_start,
                    source,
                })?;
            let payload_len = u32::from_be_bytes(length_bytes);
            if payload_len == 0 || payload_len as usize > CERTIFICATE_MAX_BYTES {
                return Err(JournalError::InvalidFrameLength {
                    entry,
                    offset: frame_start,
                    actual: payload_len,
                    maximum: CERTIFICATE_MAX_BYTES as u32,
                });
            }

            let frame_len = FRAME_FIXED_BYTES + u64::from(payload_len);
            let frame_end =
                frame_start
                    .checked_add(frame_len)
                    .ok_or(JournalError::FrameOffsetOverflow {
                        entry,
                        offset: frame_start,
                    })?;
            if file_len < frame_end {
                recover_tail(&mut file, frame_start)?;
                return Ok(Self {
                    file,
                    dag,
                    committed_end: frame_start,
                    chain_digest,
                    poisoned: false,
                });
            }

            let mut payload = vec![0_u8; payload_len as usize];
            file.read_exact(&mut payload)
                .map_err(|source| JournalError::Read {
                    offset: frame_start + 4,
                    source,
                })?;
            let mut stored_digest = [0_u8; 32];
            file.read_exact(&mut stored_digest)
                .map_err(|source| JournalError::Read {
                    offset: frame_end - 32,
                    source,
                })?;
            let actual_digest = entry_digest(chain_digest, length_bytes, &payload);
            if stored_digest != actual_digest {
                return Err(JournalError::EntryDigestMismatch {
                    entry,
                    offset: frame_start,
                });
            }

            dag.apply_canonical_proof_bytes(payload)
                .map_err(|source| JournalError::Replay {
                    entry,
                    offset: frame_start,
                    source,
                })?;
            chain_digest = actual_digest;
            frame_start = frame_end;
            entry += 1;
        }

        file.sync_all()
            .map_err(|source| JournalError::Stabilize { source })?;
        Ok(Self {
            file,
            dag,
            committed_end: frame_start,
            chain_digest,
            poisoned: false,
        })
    }

    fn apply_canonical_proof_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<&AcceptedProofRecord, JournalError> {
        self.apply_canonical_proof_bytes_inner(bytes, None)
    }

    fn apply_canonical_proof_bytes_with_expected_id(
        &mut self,
        bytes: Vec<u8>,
        expected_proof_id: ProofId,
    ) -> Result<&AcceptedProofRecord, JournalError> {
        self.apply_canonical_proof_bytes_inner(bytes, Some(expected_proof_id))
    }

    fn apply_canonical_proof_bytes_inner(
        &mut self,
        bytes: Vec<u8>,
        expected_proof_id: Option<ProofId>,
    ) -> Result<&AcceptedProofRecord, JournalError> {
        self.ensure_healthy()?;
        let record = match expected_proof_id {
            Some(expected) => self
                .dag
                .apply_canonical_proof_bytes_with_expected_id(bytes, expected),
            None => self.dag.apply_canonical_proof_bytes(bytes),
        }
        .map_err(|source| JournalError::Admission { source })?;
        let proof_id = record.proof_id();
        let payload = record.canonical_proof_bytes();
        let payload_len = u32::try_from(payload.len()).expect("accepted payload length fits u32");
        let length_bytes = payload_len.to_be_bytes();
        let digest = entry_digest(self.chain_digest, length_bytes, payload);
        let commit_result = self
            .file
            .seek(SeekFrom::Start(self.committed_end))
            .and_then(|_| self.file.append_write_all(AppendPhase::Body, &length_bytes))
            .and_then(|()| self.file.append_write_all(AppendPhase::Body, payload))
            .and_then(|()| self.file.append_sync_all(AppendPhase::Body))
            .and_then(|()| self.file.append_write_all(AppendPhase::Commit, &digest))
            .and_then(|()| self.file.append_sync_all(AppendPhase::Commit));

        if let Err(source) = commit_result {
            self.poisoned = true;
            return Err(JournalError::Commit { proof_id, source });
        }

        self.committed_end = self
            .committed_end
            .checked_add(FRAME_FIXED_BYTES + u64::from(payload_len))
            .expect("journal offsets fit u64");
        self.chain_digest = digest;
        Ok(record)
    }

    fn ensure_healthy(&self) -> Result<(), JournalError> {
        if self.poisoned {
            Err(JournalError::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn recover_tail<F: JournalIo>(file: &mut F, offset: u64) -> Result<(), JournalError> {
    file.set_len(offset)
        .and_then(|()| file.sync_all())
        .map_err(|source| JournalError::Recovery { offset, source })
}

fn genesis_digest() -> [u8; 32] {
    Sha256::digest(GENESIS_DOMAIN).into()
}

fn entry_digest(previous_digest: [u8; 32], payload_len: [u8; 4], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ENTRY_DOMAIN);
    hasher.update(previous_digest);
    hasher.update(payload_len);
    hasher.update(payload);
    hasher.finalize().into()
}

/// A fail-closed local proof-DAG journal error.
#[derive(Debug)]
#[non_exhaustive]
pub enum JournalError {
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
    /// The journal header is absent, incomplete, or unsupported.
    InvalidHeader,
    /// A complete frame declares an impossible proof payload length.
    InvalidFrameLength {
        entry: u64,
        offset: u64,
        actual: u32,
        maximum: u32,
    },
    /// A frame offset cannot be represented safely.
    FrameOffsetOverflow { entry: u64, offset: u64 },
    /// A complete frame does not match its chained payload digest.
    EntryDigestMismatch { entry: u64, offset: u64 },
    /// Strict proof replay rejected one complete committed frame.
    Replay {
        entry: u64,
        offset: u64,
        source: LedgerError,
    },
    /// An incomplete final frame could not be removed durably.
    Recovery { offset: u64, source: io::Error },
    /// A fully replayed visible journal image could not be stabilized.
    Stabilize { source: io::Error },
    /// Strict replay produced a different selected proof set than expected.
    ProofSetRootMismatch {
        expected: ProofSetRoot,
        actual: ProofSetRoot,
    },
    /// The candidate proof was rejected before journal mutation.
    Admission { source: LedgerError },
    /// Commit durability is unknown and the handle is now poisoned.
    Commit {
        proof_id: ProofId,
        source: io::Error,
    },
    /// The handle may expose in-memory state ahead of durable storage.
    Poisoned,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockFile { source } => write!(formatter, "journal lock file failed: {source}"),
            Self::Locked => formatter.write_str("proof DAG journal is already exclusively open"),
            Self::Lock { source } => write!(formatter, "journal locking failed: {source}"),
            Self::Create { source } => write!(formatter, "journal creation failed: {source}"),
            Self::Open { source } => write!(formatter, "journal opening failed: {source}"),
            Self::Read { offset, source } => {
                write!(formatter, "journal read failed at byte {offset}: {source}")
            }
            Self::InvalidHeader => formatter.write_str("invalid proof DAG journal header"),
            Self::InvalidFrameLength {
                entry,
                offset,
                actual,
                maximum,
            } => write!(
                formatter,
                "journal entry {entry} at byte {offset} has payload length {actual}, maximum {maximum}"
            ),
            Self::FrameOffsetOverflow { entry, offset } => write!(
                formatter,
                "journal entry {entry} at byte {offset} exceeds the offset range"
            ),
            Self::EntryDigestMismatch { entry, offset } => write!(
                formatter,
                "journal entry {entry} at byte {offset} failed its chained digest"
            ),
            Self::Replay {
                entry,
                offset,
                source,
            } => write!(
                formatter,
                "journal entry {entry} at byte {offset} failed strict replay: {source}"
            ),
            Self::Recovery { offset, source } => write!(
                formatter,
                "incomplete journal tail at byte {offset} could not be recovered: {source}"
            ),
            Self::Stabilize { source } => {
                write!(formatter, "replayed journal stabilization failed: {source}")
            }
            Self::ProofSetRootMismatch { expected, actual } => write!(
                formatter,
                "proof-set root mismatch: expected {expected:?}, replayed {actual:?}"
            ),
            Self::Admission { source } => write!(formatter, "proof admission failed: {source}"),
            Self::Commit { proof_id, source } => write!(
                formatter,
                "journal commit for {proof_id:?} has unknown durability: {source}"
            ),
            Self::Poisoned => formatter
                .write_str("journal is poisoned after an ambiguous commit; drop and reopen it"),
        }
    }
}

impl Error for JournalError {
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
            Self::Replay { source, .. } | Self::Admission { source } => Some(source),
            Self::Locked
            | Self::InvalidHeader
            | Self::InvalidFrameLength { .. }
            | Self::FrameOffsetOverflow { .. }
            | Self::EntryDigestMismatch { .. }
            | Self::ProofSetRootMismatch { .. }
            | Self::Poisoned => None,
        }
    }
}

#[cfg(test)]
mod tests;
