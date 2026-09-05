mod admission;
use admission::*;
mod routing;
#[cfg(test)]
use routing::*;
mod snapshot;
#[cfg(test)]
use snapshot::*;
mod endpoint_policy;
use endpoint_policy::*;

mod peer_record;

pub(crate) use peer_record::SignedPeerRecordConstructionError;
pub use peer_record::{
    MAX_ADDRESSES_PER_PEER_RECORD, MAX_PEER_ADDRESS_BYTES, MAX_SIGNED_PEER_RECORD_BYTES,
    SignedPeerRecord, SignedPeerRecordError,
};

use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::core::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use sha2::{Digest, Sha256};

use crate::record_exchange::{
    MAX_PEER_RECORDS_PER_BATCH, PeerRecordBatch, PeerRecordExchangeWireError,
};
use crate::snapshot_io::{
    BoundedReadError, ExclusiveLockError, open_exclusive, read_bounded, replace_synced,
};

const STORE_HEADER: &[u8] = b"naome:peer-address-store\0";
const STORE_CHECKSUM_DOMAIN: &[u8] = b"naome:peer-address-store-checksum\0";
const BOOTSTRAP_DIGEST_DOMAIN: &[u8] = b"naome:peer-address-bootstrap-config\0";
const CANDIDATE_ORDER_DOMAIN: &[u8] = b"naome:peer-address-rank\0";
const STORE_FILE_NAME: &str = "peer-address-store.bin";
const LOCK_FILE_NAME: &str = "peer-address-store.lock";
const TEMP_FILE_NAME: &str = "peer-address-store.tmp";
const CHECKSUM_BYTES: usize = 32;
const SALT_BYTES: usize = 32;
pub(crate) const MAX_PEER_ID_BYTES: usize = 44;
const MIN_STORED_RECORD_BYTES: usize = 1 + 1 + 8 + 2 + 1;
const SECONDS_PER_DAY: u64 = 86_400;

/// Maximum number of operator-configured bootstrap peers.
pub const MAX_BOOTSTRAP_PEERS: usize = 8;
/// Maximum number of retained signed peer records.
pub const MAX_PEER_ADDRESS_RECORDS: usize = 256;
/// Maximum records first learned from one configured bootstrap peer.
pub const MAX_RECORDS_PER_BOOTSTRAP: usize = 32;
/// Maximum stored records that cover one IPv4 /16 or IPv6 /32 group.
pub const MAX_RECORDS_PER_NETWORK_GROUP: usize = 8;
/// Maximum candidates returned by one selection.
pub const MAX_DIAL_CANDIDATES: usize = MAX_BOOTSTRAP_PEERS;
/// Maximum selected candidates first learned from one bootstrap peer.
pub const MAX_DIAL_CANDIDATES_PER_BOOTSTRAP: usize = 2;
/// Local freshness lifetime of one signed peer record.
pub const PEER_RECORD_TTL: Duration = Duration::from_secs(7 * SECONDS_PER_DAY);

// Header + local peer + bootstrap digest + salt + count + maximum entries + checksum.
const MAX_STORE_BYTES: usize = STORE_HEADER.len()
    + 1
    + MAX_PEER_ID_BYTES
    + CHECKSUM_BYTES
    + SALT_BYTES
    + 2
    + MAX_PEER_ADDRESS_RECORDS * (1 + MAX_PEER_ID_BYTES + 8 + 2 + MAX_SIGNED_PEER_RECORD_BYTES)
    + CHECKSUM_BYTES;

/// One operator-selected first-contact endpoint.
///
/// A bootstrap peer is routing configuration. It is not a artifact-authorized
/// [`crate::StaticPeer`] and cannot be converted into one implicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct BootstrapPeer {
    peer_id: PeerId,
    address: Multiaddr,
}

impl BootstrapPeer {
    /// Creates one exact IP/TCP bootstrap endpoint.
    ///
    /// Operator bootstrap addresses may be private or loopback so the same
    /// contract remains usable for private deployments and local tests.
    pub fn new(peer_id: PeerId, address: Multiaddr) -> Result<Self, BootstrapPeerError> {
        validate_endpoint(&address, false).map_err(|reason| BootstrapPeerError {
            address: Box::new(address.clone()),
            reason,
        })?;
        Ok(Self { peer_id, address })
    }

    /// Returns the expected authenticated bootstrap identity.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the operator-configured first-contact address.
    pub const fn address(&self) -> &Multiaddr {
        &self.address
    }
}

/// Error constructing one bootstrap endpoint.
#[derive(Debug)]
pub struct BootstrapPeerError {
    address: Box<Multiaddr>,
    reason: AddressReason,
}

impl fmt::Display for BootstrapPeerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid bootstrap address {}: {}",
            self.address, self.reason
        )
    }
}

impl Error for BootstrapPeerError {}

/// One untrusted, locally diversified future dial input.
///
/// This type deliberately has no conversion into [`crate::StaticPeer`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct DialCandidate {
    peer_id: PeerId,
    address: Multiaddr,
    source_peer_id: PeerId,
}

impl DialCandidate {
    /// Returns the self-certified peer identity.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the selected self-certified address.
    pub const fn address(&self) -> &Multiaddr {
        &self.address
    }

    /// Returns the configured-bootstrap provenance that first introduced this
    /// subject.
    pub const fn source_peer_id(&self) -> PeerId {
        self.source_peer_id
    }

    #[cfg(test)]
    pub(crate) const fn for_test(
        peer_id: PeerId,
        address: Multiaddr,
        source_peer_id: PeerId,
    ) -> Self {
        Self {
            peer_id,
            address,
            source_peer_id,
        }
    }
}

#[derive(Clone)]
struct StoredRecord {
    source_peer_id: PeerId,
    received_at: u64,
    record: SignedPeerRecord,
}

/// Outcome of admitting one valid signed record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum PeerRecordAdmission {
    /// A previously unknown subject was stored.
    Inserted,
    /// A strictly newer record replaced the subject's prior signed claim.
    Replaced,
    /// An exact replay or older sequence was ignored without refreshing TTL.
    IgnoredStale,
}

/// Summary of one atomic signed peer-record batch admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct PeerRecordBatchAdmission {
    inserted: u8,
    replaced: u8,
    ignored_stale: u8,
}

impl PeerRecordBatchAdmission {
    /// Returns the number of previously unknown subjects inserted.
    pub const fn inserted(&self) -> usize {
        self.inserted as usize
    }

    /// Returns the number of strictly newer subject records installed.
    pub const fn replaced(&self) -> usize {
        self.replaced as usize
    }

    /// Returns the number of older or byte-identical replay records ignored.
    pub const fn ignored_stale(&self) -> usize {
        self.ignored_stale as usize
    }

    /// Returns the number of input records classified by this admission.
    pub const fn total(&self) -> usize {
        self.inserted as usize + self.replaced as usize + self.ignored_stale as usize
    }
}

/// Exclusive bounded local store for self-signed peer-address candidates.
pub struct PeerAddressStore {
    directory: PathBuf,
    _lock: File,
    local_peer_id: PeerId,
    bootstraps: Vec<BootstrapPeer>,
    bootstrap_digest: [u8; CHECKSUM_BYTES],
    ordering_salt: [u8; SALT_BYTES],
    records: Vec<StoredRecord>,
    poisoned: bool,
    #[cfg(test)]
    commit_attempts: usize,
}

impl PeerAddressStore {
    /// Returns the immutable operator bootstrap configuration.
    pub fn bootstrap_peers(&self) -> Result<&[BootstrapPeer], PeerAddressStoreError> {
        self.ensure_healthy()?;
        Ok(&self.bootstraps)
    }
    /// Returns the number of retained sequence watermarks.
    pub fn len(&self) -> Result<usize, PeerAddressStoreError> {
        self.ensure_healthy()?;
        Ok(self.records.len())
    }
    /// Returns whether the store contains no retained record.
    pub fn is_empty(&self) -> Result<bool, PeerAddressStoreError> {
        self.ensure_healthy()?;
        Ok(self.records.is_empty())
    }
    fn ensure_healthy(&self) -> Result<(), PeerAddressStoreError> {
        if self.poisoned {
            Err(PeerAddressStoreError::Poisoned)
        } else {
            Ok(())
        }
    }
}

/// Error deriving one caller-selected peer-record publication from a store.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeerRecordPublicationError {
    /// A prior commit failure poisoned the store handle.
    Poisoned,
    /// The caller selected more subjects than one canonical batch can contain.
    TooManySubjects { actual: usize, maximum: usize },
    /// The caller selected one subject more than once.
    DuplicateSubject(Box<PeerId>),
    /// The caller selected a subject that the store does not retain.
    UnknownSubject(Box<PeerId>),
    /// The supplied local evaluation time preceded the Unix epoch.
    TimeBeforeUnixEpoch,
    /// A selected retained subject was not locally fresh at the supplied time.
    SubjectNotFresh(Box<PeerId>),
    /// Reserving the owned canonical batch failed.
    Allocation(TryReserveError),
}

impl fmt::Display for PeerRecordPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned => formatter
                .write_str("cannot derive peer-record publication from a poisoned address store"),
            Self::TooManySubjects { actual, maximum } => write!(
                formatter,
                "peer-record publication selects {actual} subjects; maximum is {maximum}"
            ),
            Self::DuplicateSubject(peer_id) => write!(
                formatter,
                "peer-record publication selects subject {peer_id} more than once"
            ),
            Self::UnknownSubject(peer_id) => write!(
                formatter,
                "peer-record publication subject {peer_id} is not retained"
            ),
            Self::TimeBeforeUnixEpoch => {
                formatter.write_str("peer-record publication time precedes Unix epoch")
            }
            Self::SubjectNotFresh(peer_id) => write!(
                formatter,
                "peer-record publication subject {peer_id} is not fresh at the supplied time"
            ),
            Self::Allocation(source) => {
                write!(
                    formatter,
                    "cannot reserve peer-record publication batch: {source}"
                )
            }
        }
    }
}

impl Error for PeerRecordPublicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Allocation(source) => Some(source),
            _ => None,
        }
    }
}

/// Error validating operator bootstrap configuration.
#[derive(Debug)]
pub enum BootstrapConfigError {
    /// The local or bootstrap identity exceeded the persisted identity cap.
    PeerIdTooLong {
        role: &'static str,
        actual: usize,
        maximum: usize,
    },
    /// The local identity was configured as a bootstrap.
    LocalPeer(Box<PeerId>),
    /// One bootstrap identity was configured more than once.
    DuplicatePeer(Box<PeerId>),
    /// The configuration exceeded the fixed cap.
    TooManyPeers { actual: usize, maximum: usize },
}

impl fmt::Display for BootstrapConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerIdTooLong {
                role,
                actual,
                maximum,
            } => write!(
                formatter,
                "{role} peer identity has {actual} bytes; maximum is {maximum}"
            ),
            Self::LocalPeer(peer_id) => {
                write!(formatter, "local peer {peer_id} cannot bootstrap itself")
            }
            Self::DuplicatePeer(peer_id) => {
                write!(formatter, "bootstrap peer {peer_id} is duplicated")
            }
            Self::TooManyPeers { actual, maximum } => write!(
                formatter,
                "bootstrap configuration has {actual} peers; maximum is {maximum}"
            ),
        }
    }
}

impl Error for BootstrapConfigError {}

/// Error creating, opening, or mutating a peer-address store.
#[derive(Debug)]
pub enum PeerAddressStoreError {
    /// Bootstrap configuration was invalid.
    BootstrapConfig(BootstrapConfigError),
    /// Store directory creation failed.
    CreateDirectory(io::Error),
    /// Store lock creation failed.
    OpenLock(io::Error),
    /// Another store handle owns the directory.
    Locked,
    /// The store snapshot already exists.
    AlreadyExists(PathBuf),
    /// Opening the store snapshot failed.
    OpenSnapshot { source: io::Error },
    /// Reading the snapshot failed.
    ReadSnapshot(io::Error),
    /// The snapshot exceeded the fixed byte cap.
    SnapshotTooLong { actual: usize, maximum: usize },
    /// Random salt generation failed.
    Random(getrandom::Error),
    /// Reserving a bounded in-memory store buffer failed.
    Allocation(TryReserveError),
    /// The snapshot header was wrong or incomplete.
    InvalidHeader,
    /// The snapshot checksum did not match.
    ChecksumMismatch,
    /// The snapshot was truncated or had trailing bytes.
    InvalidSnapshot(&'static str),
    /// The snapshot belongs to another local peer.
    LocalPeerMismatch,
    /// The operator bootstrap configuration does not match the snapshot.
    BootstrapConfigurationMismatch,
    /// A persisted peer identity was invalid.
    InvalidPeerId,
    /// One persisted signed record was invalid.
    InvalidRecord {
        index: usize,
        source: Box<SignedPeerRecordError>,
    },
    /// The supplying configured-bootstrap provenance is not configured.
    UnknownSource(Box<PeerId>),
    /// The learned dial-candidate subject is not retained by this store.
    UnknownDialCandidate(Box<PeerId>),
    /// The retained dial-candidate subject no longer matches the selected tuple
    /// or is no longer fresh at the supplied receipt time.
    StaleDialCandidate(Box<PeerId>),
    /// A record tried to add the local identity.
    LocalRecord(Box<PeerId>),
    /// The same subject signed different bytes at one sequence.
    SequenceConflict { peer_id: Box<PeerId>, sequence: u64 },
    /// The fixed retained-record capacity was exhausted.
    RecordCapacity { maximum: usize },
    /// One bootstrap source reached its retained-record quota.
    SourceCapacity { source: Box<PeerId>, maximum: usize },
    /// One target network group reached its retained-record quota.
    NetworkGroupCapacity { maximum: usize },
    /// A supplied local time preceded the Unix epoch.
    TimeBeforeUnixEpoch,
    /// A supplied receipt time cannot represent the complete fixed TTL.
    ReceiptTimeOverflow,
    /// Atomic snapshot replacement failed and poisoned the handle.
    Commit { source: io::Error },
    /// A prior commit I/O failure poisoned the handle.
    Poisoned,
}

impl fmt::Display for PeerAddressStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BootstrapConfig(source) => {
                write!(formatter, "invalid bootstrap configuration: {source}")
            }
            Self::CreateDirectory(source) => {
                write!(formatter, "cannot create address-store directory: {source}")
            }
            Self::OpenLock(source) => write!(formatter, "cannot open address-store lock: {source}"),
            Self::Locked => formatter.write_str("peer-address store is already locked"),
            Self::AlreadyExists(path) => write!(
                formatter,
                "peer-address store already exists at {}",
                path.display()
            ),
            Self::OpenSnapshot { source } => {
                write!(formatter, "cannot open peer-address snapshot: {source}")
            }
            Self::ReadSnapshot(source) => {
                write!(formatter, "cannot read peer-address snapshot: {source}")
            }
            Self::SnapshotTooLong { actual, maximum } => write!(
                formatter,
                "peer-address snapshot has {actual} bytes; maximum is {maximum}"
            ),
            Self::Random(source) => write!(
                formatter,
                "cannot generate address-selection salt: {source}"
            ),
            Self::Allocation(source) => {
                write!(
                    formatter,
                    "cannot reserve peer-address store buffer: {source}"
                )
            }
            Self::InvalidHeader => formatter.write_str("peer-address snapshot header is invalid"),
            Self::ChecksumMismatch => {
                formatter.write_str("peer-address snapshot checksum is invalid")
            }
            Self::InvalidSnapshot(reason) => {
                write!(formatter, "peer-address snapshot is invalid: {reason}")
            }
            Self::LocalPeerMismatch => {
                formatter.write_str("peer-address snapshot belongs to another local peer")
            }
            Self::BootstrapConfigurationMismatch => {
                formatter.write_str("peer-address snapshot bootstrap configuration differs")
            }
            Self::InvalidPeerId => {
                formatter.write_str("peer-address snapshot contains an invalid peer id")
            }
            Self::InvalidRecord { index, source } => write!(
                formatter,
                "peer-address snapshot record {index} is invalid: {source}"
            ),
            Self::UnknownSource(peer_id) => write!(
                formatter,
                "peer-address record source {peer_id} is not configured"
            ),
            Self::UnknownDialCandidate(peer_id) => write!(
                formatter,
                "learned dial candidate {peer_id} is not retained by this store"
            ),
            Self::StaleDialCandidate(peer_id) => write!(
                formatter,
                "learned dial candidate {peer_id} no longer matches the retained fresh tuple"
            ),
            Self::LocalRecord(peer_id) => write!(
                formatter,
                "peer-address record cannot describe local peer {peer_id}"
            ),
            Self::SequenceConflict { peer_id, sequence } => write!(
                formatter,
                "peer {peer_id} signed conflicting records at sequence {sequence}"
            ),
            Self::RecordCapacity { maximum } => write!(
                formatter,
                "peer-address record capacity {maximum} is exhausted"
            ),
            Self::SourceCapacity { source, maximum } => write!(
                formatter,
                "bootstrap source {source} reached record capacity {maximum}"
            ),
            Self::NetworkGroupCapacity { maximum } => write!(
                formatter,
                "target network group reached record capacity {maximum}"
            ),
            Self::TimeBeforeUnixEpoch => {
                formatter.write_str("peer-address receipt time precedes Unix epoch")
            }
            Self::ReceiptTimeOverflow => formatter
                .write_str("peer-address receipt time cannot represent the complete record TTL"),
            Self::Commit { source } => {
                write!(formatter, "peer-address snapshot commit failed: {source}")
            }
            Self::Poisoned => {
                formatter.write_str("peer-address store is poisoned; drop and reopen it")
            }
        }
    }
}

impl Error for PeerAddressStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BootstrapConfig(source) => Some(source),
            Self::CreateDirectory(source)
            | Self::OpenLock(source)
            | Self::ReadSnapshot(source)
            | Self::Commit { source }
            | Self::OpenSnapshot { source } => Some(source),
            Self::Random(source) => Some(source),
            Self::Allocation(source) => Some(source),
            Self::InvalidRecord { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<BootstrapConfigError> for PeerAddressStoreError {
    fn from(source: BootstrapConfigError) -> Self {
        Self::BootstrapConfig(source)
    }
}

pub(crate) fn validate_bootstraps(
    local_peer_id: PeerId,
    bootstraps: impl IntoIterator<Item = BootstrapPeer>,
) -> Result<Vec<BootstrapPeer>, BootstrapConfigError> {
    validate_configured_peer_id("local", local_peer_id)?;
    let bootstraps = bootstraps.into_iter();
    let initial_capacity = bootstraps.size_hint().0.min(MAX_BOOTSTRAP_PEERS);
    let mut result = Vec::with_capacity(initial_capacity);
    for bootstrap in bootstraps {
        validate_configured_peer_id("bootstrap", bootstrap.peer_id)?;
        if bootstrap.peer_id == local_peer_id {
            return Err(BootstrapConfigError::LocalPeer(Box::new(local_peer_id)));
        }
        if result
            .iter()
            .any(|existing: &BootstrapPeer| existing.peer_id == bootstrap.peer_id)
        {
            return Err(BootstrapConfigError::DuplicatePeer(Box::new(
                bootstrap.peer_id,
            )));
        }
        if result.len() == MAX_BOOTSTRAP_PEERS {
            return Err(BootstrapConfigError::TooManyPeers {
                actual: result.len() + 1,
                maximum: MAX_BOOTSTRAP_PEERS,
            });
        }
        result.push(bootstrap);
    }
    result.sort_unstable_by(|left, right| compare_peer_id_bytes(&left.peer_id, &right.peer_id));
    Ok(result)
}

fn validate_configured_peer_id(
    role: &'static str,
    peer_id: PeerId,
) -> Result<(), BootstrapConfigError> {
    let actual = peer_id.as_ref().encoded_len();
    if actual > MAX_PEER_ID_BYTES {
        return Err(BootstrapConfigError::PeerIdTooLong {
            role,
            actual,
            maximum: MAX_PEER_ID_BYTES,
        });
    }
    Ok(())
}

fn unix_seconds(time: SystemTime) -> Result<u64, PeerAddressStoreError> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| PeerAddressStoreError::TimeBeforeUnixEpoch)
}

fn validate_receipt_time(received_at: u64) -> Result<(), PeerAddressStoreError> {
    received_at
        .checked_add(PEER_RECORD_TTL.as_secs())
        .map(|_| ())
        .ok_or(PeerAddressStoreError::ReceiptTimeOverflow)
}

fn is_fresh(received_at: u64, now: u64) -> bool {
    received_at <= now
        && received_at
            .checked_add(PEER_RECORD_TTL.as_secs())
            .is_some_and(|expires_at| now < expires_at)
}

pub(crate) fn encode_peer_id(peer_id: PeerId) -> ([u8; MAX_PEER_ID_BYTES], usize) {
    let length = peer_id.as_ref().encoded_len();
    assert!(
        length <= MAX_PEER_ID_BYTES,
        "validated peer identities fit the snapshot cap"
    );
    let mut bytes = [0_u8; MAX_PEER_ID_BYTES];
    let written = peer_id
        .as_ref()
        .write(&mut bytes[..])
        .expect("the fixed peer-id buffer has validated capacity");
    debug_assert_eq!(written, length);
    (bytes, written)
}

pub(crate) fn compare_peer_id_bytes(left: &PeerId, right: &PeerId) -> std::cmp::Ordering {
    let left_hash = left.as_ref();
    let right_hash = right.as_ref();
    if left_hash.code() < 0x80 && right_hash.code() < 0x80 {
        return left_hash
            .code()
            .cmp(&right_hash.code())
            .then_with(|| left_hash.size().cmp(&right_hash.size()))
            .then_with(|| left_hash.digest().cmp(right_hash.digest()));
    }

    let (left, left_length) = encode_peer_id(*left);
    let (right, right_length) = encode_peer_id(*right);
    left[..left_length].cmp(&right[..right_length])
}

#[cfg(test)]
mod tests;
