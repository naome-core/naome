//! Crash-consistent local persistence for the selected NAOME proof DAG.
//!
//! [`ProofDagJournal`] stores bounded transactions of canonical proof-
//! certificate payloads in dependency-first order. Opening a journal
//! reconstructs every identity, dependency edge, and checked conclusion
//! through strict rooted [`ProofDag`] replay; persisted bytes never bypass
//! proof validation.
//!
//! The journal is a local recovery mechanism. Its physical order is neither a
//! consensus order nor proof-finality evidence, and it defines no networking,
//! snapshots, compaction, pruning, or economic state.

use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use naome_chain::{
    AddressedProofCandidate, PROOF_BATCH_MAX_CANDIDATES, ProofBatchError, ProofDag, ProofSetProof,
    ProofSetRoot,
};
use naome_ledger::{AcceptedProofRecord, LedgerError};
use naome_proof::{CERTIFICATE_MAX_BYTES, ProofId};
use sha2::{Digest, Sha256};

const LOCK_FILE_NAME: &str = "proof-dag.lock";
const JOURNAL_FILE_NAME: &str = "proof-dag.journal";
const JOURNAL_HEADER: &[u8; 36] = b"naome:proof-dag-transaction-journal\0";
const GENESIS_DOMAIN: &[u8; 44] = b"naome:proof-dag-transaction-journal-genesis\0";
const TRANSACTION_DOMAIN: &[u8; 28] = b"naome:proof-dag-transaction\0";
const DIGEST_BYTES: u64 = 32;
const TRANSACTION_FIXED_BYTES: u64 = 4 + DIGEST_BYTES;
const TRANSACTION_MIN_BODY_BYTES: u32 = 1 + 4 + 1;
const TRANSACTION_MAX_BODY_BYTES: u32 =
    (1 + PROOF_BATCH_MAX_CANDIDATES * (4 + CERTIFICATE_MAX_BYTES)) as u32;

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
    /// One incomplete final transaction is treated as an uncommitted append,
    /// truncated, and synchronized before success. A complete corrupt or
    /// proof-invalid transaction fails closed and is never skipped or repaired.
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
    /// in-memory admission, the transaction body and its commit footer are each
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

    /// Atomically admits and durably commits one addressed dependency closure.
    ///
    /// The final candidate must be `requested_root`; every earlier candidate
    /// must be transitively reachable from it. Admission failures write
    /// nothing. A successful closure is persisted behind one commit footer, so
    /// recovery exposes either the previous state or the complete closure.
    pub fn apply_rooted_canonical_proof_batch(
        &mut self,
        requested_root: ProofId,
        candidates: Vec<AddressedProofCandidate>,
    ) -> Result<&AcceptedProofRecord, JournalError> {
        self.core
            .apply_rooted_canonical_proof_batch(requested_root, candidates)
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
        let mut transaction_start = JOURNAL_HEADER.len() as u64;
        let mut transaction = 0_u64;

        while transaction_start < file_len {
            let remaining = file_len - transaction_start;
            if remaining < 4 {
                recover_tail(&mut file, transaction_start)?;
                return Ok(Self {
                    file,
                    dag,
                    committed_end: transaction_start,
                    chain_digest,
                    poisoned: false,
                });
            }

            let mut body_length_bytes = [0_u8; 4];
            file.read_exact(&mut body_length_bytes)
                .map_err(|source| JournalError::Read {
                    offset: transaction_start,
                    source,
                })?;
            let body_length = u32::from_be_bytes(body_length_bytes);
            if !(TRANSACTION_MIN_BODY_BYTES..=TRANSACTION_MAX_BODY_BYTES).contains(&body_length) {
                return Err(JournalError::InvalidTransactionLength {
                    transaction,
                    offset: transaction_start,
                    actual: body_length,
                    minimum: TRANSACTION_MIN_BODY_BYTES,
                    maximum: TRANSACTION_MAX_BODY_BYTES,
                });
            }

            let transaction_length = TRANSACTION_FIXED_BYTES + u64::from(body_length);
            let transaction_end = transaction_start.checked_add(transaction_length).ok_or(
                JournalError::TransactionOffsetOverflow {
                    transaction,
                    offset: transaction_start,
                },
            )?;
            if file_len < transaction_end {
                recover_tail(&mut file, transaction_start)?;
                return Ok(Self {
                    file,
                    dag,
                    committed_end: transaction_start,
                    chain_digest,
                    poisoned: false,
                });
            }

            let mut hasher = transaction_hasher(chain_digest, body_length_bytes);
            let mut body_offset = transaction_start + 4;
            let mut proof_count_bytes = [0_u8; 1];
            read_and_hash(&mut file, &mut proof_count_bytes, body_offset, &mut hasher)?;
            body_offset += 1;
            let proof_count = proof_count_bytes[0] as usize;
            if !(1..=PROOF_BATCH_MAX_CANDIDATES).contains(&proof_count) {
                return Err(JournalError::InvalidTransactionProofCount {
                    transaction,
                    offset: transaction_start + 4,
                    actual: proof_count_bytes[0],
                    maximum: PROOF_BATCH_MAX_CANDIDATES as u8,
                });
            }

            let mut body_remaining = u64::from(body_length) - 1;
            let mut candidates = Vec::with_capacity(proof_count);
            for proof in 0..proof_count {
                if body_remaining < 4 {
                    return Err(JournalError::InvalidTransactionBody {
                        transaction,
                        offset: transaction_start,
                    });
                }
                let proof_length_offset = body_offset;
                let mut proof_length_bytes = [0_u8; 4];
                read_and_hash(
                    &mut file,
                    &mut proof_length_bytes,
                    proof_length_offset,
                    &mut hasher,
                )?;
                body_offset += 4;
                body_remaining -= 4;
                let proof_length = u32::from_be_bytes(proof_length_bytes);
                if proof_length == 0 || proof_length as usize > CERTIFICATE_MAX_BYTES {
                    return Err(JournalError::InvalidTransactionProofLength {
                        transaction,
                        proof,
                        offset: proof_length_offset,
                        actual: proof_length,
                        maximum: CERTIFICATE_MAX_BYTES as u32,
                    });
                }
                if u64::from(proof_length) > body_remaining {
                    return Err(JournalError::InvalidTransactionBody {
                        transaction,
                        offset: transaction_start,
                    });
                }
                let mut candidate = Vec::new();
                candidate
                    .try_reserve_exact(proof_length as usize)
                    .map_err(|_| JournalError::Allocation {
                        transaction,
                        proof,
                        bytes: proof_length,
                    })?;
                candidate.resize(proof_length as usize, 0);
                read_and_hash(&mut file, &mut candidate, body_offset, &mut hasher)?;
                body_offset += u64::from(proof_length);
                body_remaining -= u64::from(proof_length);
                candidates.push(candidate);
            }
            if body_remaining != 0 {
                return Err(JournalError::InvalidTransactionBody {
                    transaction,
                    offset: transaction_start,
                });
            }

            let mut stored_digest = [0_u8; 32];
            file.read_exact(&mut stored_digest)
                .map_err(|source| JournalError::Read {
                    offset: transaction_end - 32,
                    source,
                })?;
            let actual_digest: [u8; 32] = hasher.finalize().into();
            if stored_digest != actual_digest {
                return Err(JournalError::TransactionDigestMismatch {
                    transaction,
                    offset: transaction_start,
                });
            }

            dag.apply_canonical_proof_batch(candidates)
                .map_err(|source| JournalError::Replay {
                    transaction,
                    offset: transaction_start,
                    source: Box::new(source),
                })?;
            chain_digest = actual_digest;
            transaction_start = transaction_end;
            transaction += 1;
        }

        file.sync_all()
            .map_err(|source| JournalError::Stabilize { source })?;
        Ok(Self {
            file,
            dag,
            committed_end: transaction_start,
            chain_digest,
            poisoned: false,
        })
    }

    fn apply_canonical_proof_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<&AcceptedProofRecord, JournalError> {
        self.ensure_healthy()?;
        let proof_id = self
            .dag
            .apply_canonical_proof_bytes(bytes)
            .map_err(|source| JournalError::Admission { source })?
            .proof_id();
        self.commit_transaction(&[proof_id])?;
        Ok(self
            .dag
            .proof(proof_id)
            .expect("the committed proof remains retained"))
    }

    fn apply_canonical_proof_bytes_with_expected_id(
        &mut self,
        bytes: Vec<u8>,
        expected_proof_id: ProofId,
    ) -> Result<&AcceptedProofRecord, JournalError> {
        self.ensure_healthy()?;
        let proof_id = self
            .dag
            .apply_canonical_proof_bytes_with_expected_id(bytes, expected_proof_id)
            .map_err(|source| JournalError::Admission { source })?
            .proof_id();
        self.commit_transaction(&[proof_id])?;
        Ok(self
            .dag
            .proof(proof_id)
            .expect("the committed proof remains retained"))
    }

    fn apply_rooted_canonical_proof_batch(
        &mut self,
        requested_root: ProofId,
        candidates: Vec<AddressedProofCandidate>,
    ) -> Result<&AcceptedProofRecord, JournalError> {
        self.ensure_healthy()?;
        if candidates.len() > PROOF_BATCH_MAX_CANDIDATES {
            return Err(JournalError::BatchAdmission {
                source: Box::new(ProofBatchError::TooManyCandidates {
                    actual: candidates.len(),
                    maximum: PROOF_BATCH_MAX_CANDIDATES,
                }),
            });
        }
        let proof_ids = candidates
            .iter()
            .map(AddressedProofCandidate::expected_proof_id)
            .collect::<Vec<_>>();
        self.dag
            .apply_rooted_canonical_proof_batch(requested_root, candidates)
            .map_err(|source| JournalError::BatchAdmission {
                source: Box::new(source),
            })?;
        self.commit_transaction(&proof_ids)?;
        Ok(self
            .dag
            .proof(requested_root)
            .expect("the committed rooted proof remains retained"))
    }

    fn commit_transaction(&mut self, proof_ids: &[ProofId]) -> Result<(), JournalError> {
        let root_proof_id = *proof_ids
            .last()
            .expect("only successful nonempty admissions reach persistence");
        let mut body_length = 1_u32;
        for proof_id in proof_ids {
            let proof_length = self
                .dag
                .proof(*proof_id)
                .expect("every committed transaction proof is retained")
                .canonical_proof_bytes()
                .len();
            body_length = body_length
                .checked_add(4)
                .and_then(|length| length.checked_add(proof_length as u32))
                .expect("bounded transaction body length fits u32");
        }
        let body_length_bytes = body_length.to_be_bytes();
        let proof_count = [proof_ids.len() as u8];
        let mut hasher = transaction_hasher(self.chain_digest, body_length_bytes);

        let commit_result = (|| -> io::Result<[u8; 32]> {
            self.file.seek(SeekFrom::Start(self.committed_end))?;
            self.file
                .append_write_all(AppendPhase::Body, &body_length_bytes)?;
            write_and_hash(&mut self.file, &proof_count, &mut hasher)?;
            for proof_id in proof_ids {
                let payload = self
                    .dag
                    .proof(*proof_id)
                    .expect("every committed transaction proof is retained")
                    .canonical_proof_bytes();
                let proof_length = (payload.len() as u32).to_be_bytes();
                write_and_hash(&mut self.file, &proof_length, &mut hasher)?;
                write_and_hash(&mut self.file, payload, &mut hasher)?;
            }
            self.file.append_sync_all(AppendPhase::Body)?;
            let digest: [u8; 32] = hasher.finalize().into();
            self.file.append_write_all(AppendPhase::Commit, &digest)?;
            self.file.append_sync_all(AppendPhase::Commit)?;
            Ok(digest)
        })();

        let digest = match commit_result {
            Ok(digest) => digest,
            Err(source) => {
                self.poisoned = true;
                return Err(JournalError::Commit {
                    root_proof_id,
                    proof_count: proof_ids.len(),
                    source,
                });
            }
        };

        self.committed_end = self
            .committed_end
            .checked_add(TRANSACTION_FIXED_BYTES + u64::from(body_length))
            .expect("journal offsets fit u64");
        self.chain_digest = digest;
        Ok(())
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

fn transaction_hasher(previous_digest: [u8; 32], body_length: [u8; 4]) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(TRANSACTION_DOMAIN);
    hasher.update(previous_digest);
    hasher.update(body_length);
    hasher
}

fn read_and_hash<F: JournalIo>(
    file: &mut F,
    bytes: &mut [u8],
    offset: u64,
    hasher: &mut Sha256,
) -> Result<(), JournalError> {
    file.read_exact(bytes)
        .map_err(|source| JournalError::Read { offset, source })?;
    hasher.update(bytes);
    Ok(())
}

fn write_and_hash<F: JournalIo>(file: &mut F, bytes: &[u8], hasher: &mut Sha256) -> io::Result<()> {
    file.append_write_all(AppendPhase::Body, bytes)?;
    hasher.update(bytes);
    Ok(())
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
    /// A complete transaction declares an impossible body length.
    InvalidTransactionLength {
        transaction: u64,
        offset: u64,
        actual: u32,
        minimum: u32,
        maximum: u32,
    },
    /// A transaction offset cannot be represented safely.
    TransactionOffsetOverflow { transaction: u64, offset: u64 },
    /// A transaction declares an impossible proof count.
    InvalidTransactionProofCount {
        transaction: u64,
        offset: u64,
        actual: u8,
        maximum: u8,
    },
    /// One proof inside a transaction declares an impossible length.
    InvalidTransactionProofLength {
        transaction: u64,
        proof: usize,
        offset: u64,
        actual: u32,
        maximum: u32,
    },
    /// The inner proof lengths do not consume the complete transaction body.
    InvalidTransactionBody { transaction: u64, offset: u64 },
    /// Allocating one bounded transaction proof failed.
    Allocation {
        transaction: u64,
        proof: usize,
        bytes: u32,
    },
    /// A complete transaction does not match its chained digest.
    TransactionDigestMismatch { transaction: u64, offset: u64 },
    /// Strict rooted replay rejected one complete committed transaction.
    Replay {
        transaction: u64,
        offset: u64,
        source: Box<ProofBatchError>,
    },
    /// An incomplete final transaction could not be removed durably.
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
    /// The rooted candidate closure was rejected before journal mutation.
    BatchAdmission { source: Box<ProofBatchError> },
    /// Commit durability is unknown and the handle is now poisoned.
    Commit {
        root_proof_id: ProofId,
        proof_count: usize,
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
            Self::InvalidTransactionLength {
                transaction,
                offset,
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "journal transaction {transaction} at byte {offset} has body length {actual}, expected {minimum}..={maximum}"
            ),
            Self::TransactionOffsetOverflow {
                transaction,
                offset,
            } => write!(
                formatter,
                "journal transaction {transaction} at byte {offset} exceeds the offset range"
            ),
            Self::InvalidTransactionProofCount {
                transaction,
                offset,
                actual,
                maximum,
            } => write!(
                formatter,
                "journal transaction {transaction} at byte {offset} has proof count {actual}, expected 1..={maximum}"
            ),
            Self::InvalidTransactionProofLength {
                transaction,
                proof,
                offset,
                actual,
                maximum,
            } => write!(
                formatter,
                "journal transaction {transaction} proof {proof} at byte {offset} has length {actual}, expected 1..={maximum}"
            ),
            Self::InvalidTransactionBody {
                transaction,
                offset,
            } => write!(
                formatter,
                "journal transaction {transaction} at byte {offset} has inconsistent inner lengths"
            ),
            Self::Allocation {
                transaction,
                proof,
                bytes,
            } => write!(
                formatter,
                "journal transaction {transaction} proof {proof} could not allocate {bytes} bytes"
            ),
            Self::TransactionDigestMismatch {
                transaction,
                offset,
            } => write!(
                formatter,
                "journal transaction {transaction} at byte {offset} failed its chained digest"
            ),
            Self::Replay {
                transaction,
                offset,
                source,
            } => write!(
                formatter,
                "journal transaction {transaction} at byte {offset} failed strict replay: {source}"
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
            Self::BatchAdmission { source } => {
                write!(formatter, "rooted proof-batch admission failed: {source}")
            }
            Self::Commit {
                root_proof_id,
                proof_count,
                source,
            } => write!(
                formatter,
                "journal commit of {proof_count} proofs rooted at {root_proof_id:?} has unknown durability: {source}"
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
            Self::Replay { source, .. } | Self::BatchAdmission { source } => Some(source.as_ref()),
            Self::Admission { source } => Some(source),
            Self::Locked
            | Self::InvalidHeader
            | Self::InvalidTransactionLength { .. }
            | Self::TransactionOffsetOverflow { .. }
            | Self::InvalidTransactionProofCount { .. }
            | Self::InvalidTransactionProofLength { .. }
            | Self::InvalidTransactionBody { .. }
            | Self::Allocation { .. }
            | Self::TransactionDigestMismatch { .. }
            | Self::ProofSetRootMismatch { .. }
            | Self::Poisoned => None,
        }
    }
}

#[cfg(test)]
mod tests;
