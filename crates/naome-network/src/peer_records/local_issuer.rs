use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use libp2p::{
    Multiaddr, PeerId,
    identity::{Keypair, SigningError},
};
use sha2::{Digest, Sha256};

use crate::address_store::{
    MAX_ADDRESSES_PER_PEER_RECORD, MAX_PEER_ID_BYTES, SignedPeerRecord,
    SignedPeerRecordConstructionError, SignedPeerRecordError, encode_peer_id,
};
use crate::snapshot_io::{
    BoundedReadError, ExclusiveLockError, open_exclusive, read_bounded, replace_synced,
};

const SNAPSHOT_HEADER: &[u8] = b"naome:local-peer-record-issuer\0";
const SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"naome:local-peer-record-issuer-checksum\0";
const SNAPSHOT_FILE_NAME: &str = "local-peer-record-issuer.bin";
const LOCK_FILE_NAME: &str = "local-peer-record-issuer.lock";
const TEMP_FILE_NAME: &str = "local-peer-record-issuer.tmp";
const CHECKSUM_BYTES: usize = 32;
const SEQUENCE_BYTES: usize = 8;
const MIN_SNAPSHOT_BYTES: usize = SNAPSHOT_HEADER.len() + 1 + 1 + SEQUENCE_BYTES + CHECKSUM_BYTES;
const MAX_SNAPSHOT_BYTES: usize =
    SNAPSHOT_HEADER.len() + 1 + MAX_PEER_ID_BYTES + SEQUENCE_BYTES + CHECKSUM_BYTES;

/// Exclusive durable issuer of monotonic standard peer records for one identity.
///
/// The issuer persists only the public peer identity and its committed sequence
/// watermark. The signing key remains caller-owned and must match the persisted
/// identity on every issuance. During issuance, a commit I/O failure makes the
/// in-memory sequence ambiguous, so the handle fails closed until it is
/// dropped and the checksum-protected snapshot is reopened. Creation returns
/// no handle when its initial commit fails.
pub struct LocalPeerRecordIssuer {
    directory: PathBuf,
    _lock: File,
    peer_id: PeerId,
    last_issued_sequence: u64,
    poisoned: bool,
    #[cfg(test)]
    commit_fault: Option<TestCommitFault>,
}

impl LocalPeerRecordIssuer {
    /// Creates one new issuer with an explicit already-issued sequence floor.
    ///
    /// The floor is committed before the handle is returned. The issuer never
    /// derives a sequence from wall-clock time and never persists the key. A
    /// commit error may occur after the snapshot is installed; strict
    /// [`Self::open`] is the recovery probe when creation returns `Commit`.
    pub fn create(
        directory: impl AsRef<Path>,
        identity: &Keypair,
        last_issued_sequence: u64,
    ) -> Result<Self, LocalPeerRecordIssuerError> {
        let peer_id = bounded_peer_id(identity)?;
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory).map_err(LocalPeerRecordIssuerError::CreateDirectory)?;
        let lock = open_lock(&directory)?;
        let snapshot_path = directory.join(SNAPSHOT_FILE_NAME);
        if snapshot_path
            .try_exists()
            .map_err(LocalPeerRecordIssuerError::ReadSnapshot)?
        {
            return Err(LocalPeerRecordIssuerError::AlreadyExists(snapshot_path));
        }
        let bytes = encode_snapshot(peer_id, last_issued_sequence)?;
        commit_snapshot(&directory, &bytes)
            .map_err(|source| LocalPeerRecordIssuerError::Commit { source })?;
        Ok(Self {
            directory,
            _lock: lock,
            peer_id,
            last_issued_sequence,
            poisoned: false,
            #[cfg(test)]
            commit_fault: None,
        })
    }

    /// Opens and strictly verifies one existing issuer snapshot.
    pub fn open(
        directory: impl AsRef<Path>,
        identity: &Keypair,
    ) -> Result<Self, LocalPeerRecordIssuerError> {
        let expected_peer_id = bounded_peer_id(identity)?;
        let directory = directory.as_ref().to_path_buf();
        let lock = open_lock(&directory)?;
        let snapshot_path = directory.join(SNAPSHOT_FILE_NAME);
        let bytes =
            read_bounded(&snapshot_path, MAX_SNAPSHOT_BYTES).map_err(|source| match source {
                BoundedReadError::Open(source) => {
                    LocalPeerRecordIssuerError::OpenSnapshot { source }
                }
                BoundedReadError::Read(source) => LocalPeerRecordIssuerError::ReadSnapshot(source),
                BoundedReadError::TooLong { actual, maximum } => {
                    LocalPeerRecordIssuerError::SnapshotTooLong { actual, maximum }
                }
                BoundedReadError::Allocation(source) => {
                    LocalPeerRecordIssuerError::Allocation(source)
                }
            })?;
        let last_issued_sequence = decode_snapshot(&bytes, expected_peer_id)?;
        Ok(Self {
            directory,
            _lock: lock,
            peer_id: expected_peer_id,
            last_issued_sequence,
            poisoned: false,
            #[cfg(test)]
            commit_fault: None,
        })
    }

    /// Returns the public identity whose records this issuer may sign.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the last durably acknowledged sequence.
    ///
    /// A poisoned handle hides this value because the failed commit may have
    /// installed either the old or the next snapshot.
    pub fn last_issued_sequence(&self) -> Result<u64, LocalPeerRecordIssuerError> {
        self.ensure_healthy()?;
        Ok(self.last_issued_sequence)
    }

    /// Signs and durably commits the next monotonic peer record.
    ///
    /// At most five address items are consumed: the first item beyond the
    /// fixed four-address maximum proves that the input is oversized. The next
    /// sequence is committed before the signed record is returned.
    pub fn issue(
        &mut self,
        identity: &Keypair,
        addresses: impl IntoIterator<Item = Multiaddr>,
    ) -> Result<SignedPeerRecord, LocalPeerRecordIssuerError> {
        self.ensure_healthy()?;
        let actual_peer_id = identity.public().to_peer_id();
        if actual_peer_id != self.peer_id {
            return Err(LocalPeerRecordIssuerError::IdentityMismatch {
                expected: Box::new(self.peer_id),
                actual: Box::new(actual_peer_id),
            });
        }
        let next_sequence = self
            .last_issued_sequence
            .checked_add(1)
            .ok_or(LocalPeerRecordIssuerError::SequenceExhausted)?;

        let addresses = addresses.into_iter();
        let initial_capacity = addresses.size_hint().0.min(MAX_ADDRESSES_PER_PEER_RECORD);
        let mut bounded_addresses = Vec::new();
        bounded_addresses
            .try_reserve_exact(initial_capacity)
            .map_err(LocalPeerRecordIssuerError::Allocation)?;
        for address in addresses {
            if bounded_addresses.len() == MAX_ADDRESSES_PER_PEER_RECORD {
                return Err(LocalPeerRecordIssuerError::InvalidRecord(Box::new(
                    SignedPeerRecordError::AddressCount {
                        actual: MAX_ADDRESSES_PER_PEER_RECORD + 1,
                        maximum: MAX_ADDRESSES_PER_PEER_RECORD,
                    },
                )));
            }
            if bounded_addresses.len() == bounded_addresses.capacity() {
                bounded_addresses
                    .try_reserve(1)
                    .map_err(LocalPeerRecordIssuerError::Allocation)?;
            }
            bounded_addresses.push(address);
        }
        let record =
            SignedPeerRecord::sign_with_sequence(identity, next_sequence, bounded_addresses)
                .map_err(|source| match source {
                    SignedPeerRecordConstructionError::InvalidRecord(source) => {
                        LocalPeerRecordIssuerError::InvalidRecord(Box::new(source))
                    }
                    SignedPeerRecordConstructionError::Signing(source) => {
                        LocalPeerRecordIssuerError::Signing(Box::new(source))
                    }
                    SignedPeerRecordConstructionError::Allocation(source) => {
                        LocalPeerRecordIssuerError::Allocation(source)
                    }
                })?;
        let snapshot = encode_snapshot(self.peer_id, next_sequence)?;
        if let Err(source) = self.commit_snapshot(&snapshot) {
            self.poisoned = true;
            return Err(LocalPeerRecordIssuerError::Commit { source });
        }
        self.last_issued_sequence = next_sequence;
        Ok(record)
    }

    fn ensure_healthy(&self) -> Result<(), LocalPeerRecordIssuerError> {
        if self.poisoned {
            Err(LocalPeerRecordIssuerError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn commit_snapshot(&mut self, bytes: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        if let Some(fault) = self.commit_fault {
            return match fault {
                TestCommitFault::BeforeCommit => {
                    Err(io::Error::other("injected failure before issuer commit"))
                }
                TestCommitFault::AfterCommit => {
                    commit_snapshot(&self.directory, bytes)?;
                    Err(io::Error::other("injected failure after issuer commit"))
                }
            };
        }
        commit_snapshot(&self.directory, bytes)
    }
}

fn bounded_peer_id(identity: &Keypair) -> Result<PeerId, LocalPeerRecordIssuerError> {
    let peer_id = identity.public().to_peer_id();
    let length = peer_id.as_ref().encoded_len();
    if length > MAX_PEER_ID_BYTES {
        return Err(LocalPeerRecordIssuerError::PeerIdTooLong {
            actual: length,
            maximum: MAX_PEER_ID_BYTES,
        });
    }
    Ok(peer_id)
}

fn encode_snapshot(
    peer_id: PeerId,
    last_issued_sequence: u64,
) -> Result<Vec<u8>, LocalPeerRecordIssuerError> {
    let (peer_id_bytes, peer_id_length) = encode_peer_id(peer_id);
    let encoded_length =
        SNAPSHOT_HEADER.len() + 1 + peer_id_length + SEQUENCE_BYTES + CHECKSUM_BYTES;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(encoded_length)
        .map_err(LocalPeerRecordIssuerError::Allocation)?;
    bytes.extend_from_slice(SNAPSHOT_HEADER);
    bytes.push(u8::try_from(peer_id_length).expect("the peer-id cap fits in u8"));
    bytes.extend_from_slice(&peer_id_bytes[..peer_id_length]);
    bytes.extend_from_slice(&last_issued_sequence.to_be_bytes());
    let checksum = snapshot_checksum(&bytes);
    bytes.extend_from_slice(&checksum);
    debug_assert_eq!(bytes.len(), encoded_length);
    Ok(bytes)
}

fn decode_snapshot(
    bytes: &[u8],
    expected_peer_id: PeerId,
) -> Result<u64, LocalPeerRecordIssuerError> {
    if bytes.len() < MIN_SNAPSHOT_BYTES {
        return Err(LocalPeerRecordIssuerError::InvalidHeader);
    }
    let body_length = bytes.len() - CHECKSUM_BYTES;
    let (body, expected_checksum) = bytes.split_at(body_length);
    if snapshot_checksum(body).as_slice() != expected_checksum {
        return Err(LocalPeerRecordIssuerError::ChecksumMismatch);
    }
    let Some(remainder) = body.strip_prefix(SNAPSHOT_HEADER) else {
        return Err(LocalPeerRecordIssuerError::InvalidHeader);
    };
    let Some((&peer_id_length, remainder)) = remainder.split_first() else {
        return Err(LocalPeerRecordIssuerError::InvalidSnapshot(
            "missing peer identity length",
        ));
    };
    let peer_id_length = usize::from(peer_id_length);
    if peer_id_length > MAX_PEER_ID_BYTES {
        return Err(LocalPeerRecordIssuerError::PeerIdTooLong {
            actual: peer_id_length,
            maximum: MAX_PEER_ID_BYTES,
        });
    }
    let Some((peer_id_bytes, remainder)) = remainder.split_at_checked(peer_id_length) else {
        return Err(LocalPeerRecordIssuerError::InvalidSnapshot(
            "truncated peer identity",
        ));
    };
    let peer_id =
        PeerId::from_bytes(peer_id_bytes).map_err(|_| LocalPeerRecordIssuerError::InvalidPeerId)?;
    if peer_id != expected_peer_id {
        return Err(LocalPeerRecordIssuerError::IdentityMismatch {
            expected: Box::new(expected_peer_id),
            actual: Box::new(peer_id),
        });
    }
    let Some((sequence, trailing)) = remainder.split_at_checked(SEQUENCE_BYTES) else {
        return Err(LocalPeerRecordIssuerError::InvalidSnapshot(
            "truncated sequence",
        ));
    };
    if !trailing.is_empty() {
        return Err(LocalPeerRecordIssuerError::InvalidSnapshot(
            "trailing bytes",
        ));
    }
    Ok(u64::from_be_bytes(
        sequence.try_into().expect("the sequence slice is exact"),
    ))
}

fn snapshot_checksum(bytes: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_CHECKSUM_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn open_lock(directory: &Path) -> Result<File, LocalPeerRecordIssuerError> {
    match open_exclusive(directory, LOCK_FILE_NAME) {
        Ok(lock) => Ok(lock),
        Err(ExclusiveLockError::Locked) => Err(LocalPeerRecordIssuerError::Locked),
        Err(ExclusiveLockError::Io(source)) => Err(LocalPeerRecordIssuerError::OpenLock(source)),
    }
}

fn commit_snapshot(directory: &Path, bytes: &[u8]) -> io::Result<()> {
    replace_synced(directory, TEMP_FILE_NAME, SNAPSHOT_FILE_NAME, bytes)
}

/// Error creating, opening, or advancing a local peer-record issuer.
#[non_exhaustive]
#[derive(Debug)]
pub enum LocalPeerRecordIssuerError {
    /// Issuer directory creation failed.
    CreateDirectory(io::Error),
    /// Issuer lock creation or acquisition failed.
    OpenLock(io::Error),
    /// Another issuer handle owns the directory.
    Locked,
    /// The issuer snapshot already exists.
    AlreadyExists(PathBuf),
    /// Opening the issuer snapshot failed.
    OpenSnapshot { source: io::Error },
    /// Reading the issuer snapshot failed.
    ReadSnapshot(io::Error),
    /// The snapshot exceeded its exact fixed byte cap.
    SnapshotTooLong { actual: usize, maximum: usize },
    /// Reserving a bounded issuer buffer failed.
    Allocation(TryReserveError),
    /// The snapshot header was wrong or incomplete.
    InvalidHeader,
    /// The snapshot checksum did not match.
    ChecksumMismatch,
    /// The snapshot was truncated or had trailing bytes.
    InvalidSnapshot(&'static str),
    /// The snapshot contained an invalid peer identity.
    InvalidPeerId,
    /// A public peer identity exceeded the persisted byte cap.
    PeerIdTooLong { actual: usize, maximum: usize },
    /// The supplied signing key did not match the authoritative identity.
    IdentityMismatch {
        expected: Box<PeerId>,
        actual: Box<PeerId>,
    },
    /// The proposed standard signed peer record was invalid.
    InvalidRecord(Box<SignedPeerRecordError>),
    /// The supplied local identity could not sign the standard envelope.
    Signing(Box<SigningError>),
    /// No strictly greater sequence can be represented.
    SequenceExhausted,
    /// Atomic snapshot replacement failed; issuance poisons an existing handle.
    Commit { source: io::Error },
    /// A prior commit I/O failure made the in-memory sequence ambiguous.
    Poisoned,
}

impl fmt::Display for LocalPeerRecordIssuerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDirectory(source) => {
                write!(
                    formatter,
                    "cannot create peer-record issuer directory: {source}"
                )
            }
            Self::OpenLock(source) => {
                write!(formatter, "cannot open peer-record issuer lock: {source}")
            }
            Self::Locked => formatter.write_str("peer-record issuer is already locked"),
            Self::AlreadyExists(path) => write!(
                formatter,
                "peer-record issuer already exists at {}",
                path.display()
            ),
            Self::OpenSnapshot { source } => {
                write!(
                    formatter,
                    "cannot open peer-record issuer snapshot: {source}"
                )
            }
            Self::ReadSnapshot(source) => {
                write!(
                    formatter,
                    "cannot read peer-record issuer snapshot: {source}"
                )
            }
            Self::SnapshotTooLong { actual, maximum } => write!(
                formatter,
                "peer-record issuer snapshot has {actual} bytes; maximum is {maximum}"
            ),
            Self::Allocation(source) => {
                write!(
                    formatter,
                    "cannot reserve peer-record issuer buffer: {source}"
                )
            }
            Self::InvalidHeader => {
                formatter.write_str("peer-record issuer snapshot header is invalid")
            }
            Self::ChecksumMismatch => {
                formatter.write_str("peer-record issuer snapshot checksum is invalid")
            }
            Self::InvalidSnapshot(reason) => {
                write!(
                    formatter,
                    "peer-record issuer snapshot is invalid: {reason}"
                )
            }
            Self::InvalidPeerId => {
                formatter.write_str("peer-record issuer snapshot contains an invalid peer id")
            }
            Self::PeerIdTooLong { actual, maximum } => write!(
                formatter,
                "peer-record issuer identity has {actual} bytes; maximum is {maximum}"
            ),
            Self::IdentityMismatch { expected, actual } => write!(
                formatter,
                "peer-record issuer identity mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidRecord(source) => {
                write!(formatter, "invalid local signed peer record: {source}")
            }
            Self::Signing(source) => {
                write!(formatter, "cannot sign local peer record: {source}")
            }
            Self::SequenceExhausted => {
                formatter.write_str("peer-record issuer sequence is exhausted")
            }
            Self::Commit { source } => {
                write!(
                    formatter,
                    "cannot commit peer-record issuer snapshot: {source}"
                )
            }
            Self::Poisoned => formatter.write_str("peer-record issuer handle is poisoned"),
        }
    }
}

impl Error for LocalPeerRecordIssuerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CreateDirectory(source) | Self::OpenLock(source) | Self::ReadSnapshot(source) => {
                Some(source)
            }
            Self::OpenSnapshot { source } | Self::Commit { source } => Some(source),
            Self::Allocation(source) => Some(source),
            Self::InvalidRecord(source) => Some(source.as_ref()),
            Self::Signing(source) => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestCommitFault {
    BeforeCommit,
    AfterCommit,
}

#[cfg(test)]
mod tests;
