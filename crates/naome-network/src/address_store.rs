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
    /// Creates one new empty store in `directory`.
    pub fn create(
        directory: impl AsRef<Path>,
        local_peer_id: PeerId,
        bootstraps: impl IntoIterator<Item = BootstrapPeer>,
    ) -> Result<Self, PeerAddressStoreError> {
        let directory = directory.as_ref().to_path_buf();
        let bootstraps = validate_bootstraps(local_peer_id, bootstraps)?;
        fs::create_dir_all(&directory).map_err(PeerAddressStoreError::CreateDirectory)?;
        let lock = open_lock(&directory)?;
        let snapshot_path = directory.join(STORE_FILE_NAME);
        if snapshot_path
            .try_exists()
            .map_err(PeerAddressStoreError::ReadSnapshot)?
        {
            return Err(PeerAddressStoreError::AlreadyExists(snapshot_path));
        }

        let bootstrap_digest = bootstrap_digest(&bootstraps);
        let mut ordering_salt = [0_u8; SALT_BYTES];
        getrandom::fill(&mut ordering_salt).map_err(PeerAddressStoreError::Random)?;
        let mut store = Self {
            directory,
            _lock: lock,
            local_peer_id,
            bootstraps,
            bootstrap_digest,
            ordering_salt,
            records: Vec::new(),
            poisoned: false,
            #[cfg(test)]
            commit_attempts: 0,
        };
        let bytes = store.encode_snapshot(&[])?;
        store.commit_snapshot(&bytes)?;
        Ok(store)
    }

    /// Opens and strictly verifies one existing store.
    pub fn open(
        directory: impl AsRef<Path>,
        local_peer_id: PeerId,
        bootstraps: impl IntoIterator<Item = BootstrapPeer>,
    ) -> Result<Self, PeerAddressStoreError> {
        let directory = directory.as_ref().to_path_buf();
        let bootstraps = validate_bootstraps(local_peer_id, bootstraps)?;
        let lock = open_lock(&directory)?;
        let bootstrap_digest = bootstrap_digest(&bootstraps);
        let snapshot_path = directory.join(STORE_FILE_NAME);
        let bytes =
            read_bounded(&snapshot_path, MAX_STORE_BYTES).map_err(|source| match source {
                BoundedReadError::Open(source) => PeerAddressStoreError::OpenSnapshot { source },
                BoundedReadError::Read(source) => PeerAddressStoreError::ReadSnapshot(source),
                BoundedReadError::TooLong { actual, maximum } => {
                    PeerAddressStoreError::SnapshotTooLong { actual, maximum }
                }
                BoundedReadError::Allocation(source) => PeerAddressStoreError::Allocation(source),
            })?;
        let (ordering_salt, records) =
            decode_snapshot(&bytes, local_peer_id, &bootstraps, bootstrap_digest)?;
        Ok(Self {
            directory,
            _lock: lock,
            local_peer_id,
            bootstraps,
            bootstrap_digest,
            ordering_salt,
            records,
            poisoned: false,
            #[cfg(test)]
            commit_attempts: 0,
        })
    }

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

    /// Derives one owned canonical publication from exact caller-selected subjects.
    ///
    /// Selection rejects a poisoned handle, excess count, the lowest duplicate
    /// subject, the lowest unretained subject, an evaluation time before the
    /// Unix epoch, then the lowest subject that is not locally fresh. The
    /// method neither mutates the store nor refreshes local receipt times, and
    /// the returned batch contains no receipt-time or provenance metadata.
    pub fn peer_record_publication(
        &self,
        now: SystemTime,
        subjects: &[PeerId],
    ) -> Result<PeerRecordBatch, PeerRecordPublicationError> {
        if self.poisoned {
            return Err(PeerRecordPublicationError::Poisoned);
        }
        if subjects.len() > MAX_PEER_RECORDS_PER_BATCH {
            return Err(PeerRecordPublicationError::TooManySubjects {
                actual: subjects.len(),
                maximum: MAX_PEER_RECORDS_PER_BATCH,
            });
        }
        if let Some(duplicate) = subjects
            .iter()
            .enumerate()
            .filter_map(|(index, subject)| {
                subjects[index + 1..].contains(subject).then_some(subject)
            })
            .min_by(|left, right| compare_peer_id_bytes(left, right))
        {
            return Err(PeerRecordPublicationError::DuplicateSubject(Box::new(
                *duplicate,
            )));
        }
        let mut selected_indices = [0_usize; MAX_PEER_RECORDS_PER_BATCH];
        let mut lowest_unknown = None;
        for (subject, selected_index) in subjects.iter().zip(&mut selected_indices) {
            match self
                .records
                .binary_search_by(|stored| compare_peer_id_bytes(&stored.record.peer_id, subject))
            {
                Ok(index) => *selected_index = index,
                Err(_) => {
                    if lowest_unknown
                        .is_none_or(|lowest| compare_peer_id_bytes(subject, lowest).is_lt())
                    {
                        lowest_unknown = Some(subject);
                    }
                }
            }
        }
        if let Some(unknown) = lowest_unknown {
            return Err(PeerRecordPublicationError::UnknownSubject(Box::new(
                *unknown,
            )));
        }
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PeerRecordPublicationError::TimeBeforeUnixEpoch)?
            .as_secs();
        if let Some(not_fresh) = subjects
            .iter()
            .zip(&selected_indices)
            .filter_map(|(subject, &index)| {
                (!is_fresh(self.records[index].received_at, now)).then_some(subject)
            })
            .min_by(|left, right| compare_peer_id_bytes(left, right))
        {
            return Err(PeerRecordPublicationError::SubjectNotFresh(Box::new(
                *not_fresh,
            )));
        }

        match PeerRecordBatch::new(
            selected_indices[..subjects.len()]
                .iter()
                .map(|&index| self.records[index].record.clone()),
        ) {
            Ok(batch) => Ok(batch),
            Err(PeerRecordExchangeWireError::Allocation(source)) => {
                Err(PeerRecordPublicationError::Allocation(source))
            }
            Err(source) => unreachable!(
                "validated peer-record publication violated batch invariants: {source}"
            ),
        }
    }

    /// Admits one already-verified record from a configured bootstrap source.
    pub fn admit_record(
        &mut self,
        source_peer_id: PeerId,
        record: SignedPeerRecord,
        received_at: SystemTime,
    ) -> Result<PeerRecordAdmission, PeerAddressStoreError> {
        self.ensure_healthy()?;
        if !self
            .bootstraps
            .iter()
            .any(|bootstrap| bootstrap.peer_id == source_peer_id)
        {
            return Err(PeerAddressStoreError::UnknownSource(Box::new(
                source_peer_id,
            )));
        }
        if record.peer_id == self.local_peer_id {
            return Err(PeerAddressStoreError::LocalRecord(Box::new(record.peer_id)));
        }
        let received_at = unix_seconds(received_at)?;
        validate_receipt_time(received_at)?;
        let search = self.records.binary_search_by(|stored| {
            compare_peer_id_bytes(&stored.record.peer_id, &record.peer_id)
        });
        let (index, existing, admission) = match search {
            Ok(index) => {
                let existing = &self.records[index];
                if record.sequence < existing.record.sequence
                    || (record.sequence == existing.record.sequence
                        && record.envelope_bytes == existing.record.envelope_bytes)
                {
                    return Ok(PeerRecordAdmission::IgnoredStale);
                }
                if record.sequence == existing.record.sequence {
                    return Err(PeerAddressStoreError::SequenceConflict {
                        peer_id: Box::new(record.peer_id),
                        sequence: record.sequence,
                    });
                }
                (index, Some(index), PeerRecordAdmission::Replaced)
            }
            Err(index) => (index, None, PeerRecordAdmission::Inserted),
        };

        let source_peer_id = existing
            .map(|existing| self.records[existing].source_peer_id)
            .unwrap_or(source_peer_id);
        validate_record_capacity(&self.records, &record, source_peer_id, existing)?;
        let next = StoredRecord {
            source_peer_id,
            received_at,
            record,
        };
        let mutation = BatchMutation {
            replace: existing.is_some(),
            record: next,
        };
        if existing.is_none() {
            self.records
                .try_reserve(1)
                .map_err(PeerAddressStoreError::Allocation)?;
        }
        let bytes = self.encode_snapshot(std::slice::from_ref(&mutation))?;
        self.commit_snapshot(&bytes)?;
        let next = mutation.record;
        if existing.is_some() {
            self.records[index] = next;
        } else {
            self.records.insert(index, next);
        }
        Ok(admission)
    }

    /// Atomically admits one canonical batch from one authenticated bootstrap.
    ///
    /// Every record is classified and the complete proposed final state is
    /// validated before one snapshot replacement. Older and exact replay
    /// records do not refresh their local receipt time. Any error rejects the
    /// whole batch without installing a prefix.
    pub fn admit_record_batch(
        &mut self,
        source_peer_id: PeerId,
        batch: PeerRecordBatch,
        received_at: SystemTime,
    ) -> Result<PeerRecordBatchAdmission, PeerAddressStoreError> {
        self.ensure_healthy()?;
        if !self
            .bootstraps
            .iter()
            .any(|bootstrap| bootstrap.peer_id == source_peer_id)
        {
            return Err(PeerAddressStoreError::UnknownSource(Box::new(
                source_peer_id,
            )));
        }
        let received_at = unix_seconds(received_at)?;
        validate_receipt_time(received_at)?;

        self.admit_record_batch_from_validated_source(source_peer_id, batch, received_at)
    }

    /// Admits one batch obtained from an exact retained learned candidate.
    ///
    /// The candidate's subject, signed address, configured-bootstrap
    /// provenance, and freshness at the caller-supplied receipt time are
    /// revalidated before any batch record is classified. Candidate ranking is
    /// deliberately not recomputed. New
    /// subjects inherit the candidate's original configured-bootstrap
    /// provenance; replacements keep their existing first-introducer
    /// provenance.
    pub(crate) fn admit_learned_record_batch(
        &mut self,
        candidate: &DialCandidate,
        batch: PeerRecordBatch,
        received_at: SystemTime,
    ) -> Result<PeerRecordBatchAdmission, PeerAddressStoreError> {
        self.ensure_healthy()?;
        let Ok(index) = self.records.binary_search_by(|stored| {
            compare_peer_id_bytes(&stored.record.peer_id, &candidate.peer_id)
        }) else {
            return Err(PeerAddressStoreError::UnknownDialCandidate(Box::new(
                candidate.peer_id,
            )));
        };
        let stored = &self.records[index];
        if stored.source_peer_id != candidate.source_peer_id
            || !stored.record.addresses.contains(&candidate.address)
        {
            return Err(PeerAddressStoreError::StaleDialCandidate(Box::new(
                candidate.peer_id,
            )));
        }
        let source_received_at = stored.received_at;
        let received_at = unix_seconds(received_at)?;
        validate_receipt_time(received_at)?;
        if !is_fresh(source_received_at, received_at) {
            return Err(PeerAddressStoreError::StaleDialCandidate(Box::new(
                candidate.peer_id,
            )));
        }

        self.admit_record_batch_from_validated_source(candidate.source_peer_id, batch, received_at)
    }

    fn admit_record_batch_from_validated_source(
        &mut self,
        source_peer_id: PeerId,
        batch: PeerRecordBatch,
        received_at: u64,
    ) -> Result<PeerRecordBatchAdmission, PeerAddressStoreError> {
        let records = batch.into_records();
        if let Some(record) = records
            .iter()
            .find(|record| record.peer_id == self.local_peer_id)
        {
            return Err(PeerAddressStoreError::LocalRecord(Box::new(record.peer_id)));
        }
        let record_count = records.len();
        let mut mutations = Vec::<BatchMutation>::new();
        let mut admission = PeerRecordBatchAdmission {
            inserted: 0,
            replaced: 0,
            ignored_stale: 0,
        };
        for (batch_index, record) in records.into_iter().enumerate() {
            match self.records.binary_search_by(|stored| {
                compare_peer_id_bytes(&stored.record.peer_id, &record.peer_id)
            }) {
                Ok(index) => {
                    let existing = &self.records[index];
                    if record.sequence < existing.record.sequence
                        || (record.sequence == existing.record.sequence
                            && record.envelope_bytes == existing.record.envelope_bytes)
                    {
                        admission.ignored_stale += 1;
                        continue;
                    }
                    if record.sequence == existing.record.sequence {
                        return Err(PeerAddressStoreError::SequenceConflict {
                            peer_id: Box::new(record.peer_id),
                            sequence: record.sequence,
                        });
                    }
                    push_batch_mutation(
                        &mut mutations,
                        record_count - batch_index,
                        BatchMutation {
                            replace: true,
                            record: StoredRecord {
                                source_peer_id: existing.source_peer_id,
                                received_at,
                                record,
                            },
                        },
                    )?;
                    admission.replaced += 1;
                }
                Err(_) => {
                    push_batch_mutation(
                        &mut mutations,
                        record_count - batch_index,
                        BatchMutation {
                            replace: false,
                            record: StoredRecord {
                                source_peer_id,
                                received_at,
                                record,
                            },
                        },
                    )?;
                    admission.inserted += 1;
                }
            }
        }

        if mutations.is_empty() {
            return Ok(admission);
        }
        validate_projected_capacity(&self.records, &mutations)?;
        let insertions = mutations
            .iter()
            .filter(|mutation| !mutation.replace)
            .count();
        self.records
            .try_reserve(insertions)
            .map_err(PeerAddressStoreError::Allocation)?;
        let bytes = self.encode_snapshot(&mutations)?;
        self.commit_snapshot(&bytes)?;
        for mutation in mutations {
            let peer_id = mutation.record.record.peer_id;
            match self
                .records
                .binary_search_by(|stored| compare_peer_id_bytes(&stored.record.peer_id, &peer_id))
            {
                Ok(index) => {
                    debug_assert!(mutation.replace);
                    self.records[index] = mutation.record;
                }
                Err(index) => {
                    debug_assert!(!mutation.replace);
                    self.records.insert(index, mutation.record);
                }
            }
        }
        Ok(admission)
    }

    /// Selects a deterministic, prefix- and source-diversified candidate set.
    pub fn dial_candidates(
        &self,
        now: SystemTime,
    ) -> Result<Vec<DialCandidate>, PeerAddressStoreError> {
        self.ensure_healthy()?;
        let now = unix_seconds(now)?;
        let epoch = now / SECONDS_PER_DAY;
        let ranked_capacity = self
            .records
            .iter()
            .filter(|stored| is_fresh(stored.received_at, now))
            .map(|stored| stored.record.addresses.len())
            .sum();
        let mut ranked = Vec::new();
        ranked
            .try_reserve_exact(ranked_capacity)
            .map_err(PeerAddressStoreError::Allocation)?;
        for stored in &self.records {
            if !is_fresh(stored.received_at, now) {
                continue;
            }
            for address in &stored.record.addresses {
                ranked.push(RankedCandidate {
                    score: candidate_score(
                        &self.ordering_salt,
                        epoch,
                        stored.record.peer_id,
                        address,
                        stored.source_peer_id,
                    ),
                    peer_id: stored.record.peer_id,
                    address,
                    source_peer_id: stored.source_peer_id,
                    group: network_group(address).expect("stored addresses are validated"),
                });
            }
        }
        ranked.sort_unstable_by(|left, right| {
            left.score
                .cmp(&right.score)
                .then_with(|| compare_peer_id_bytes(&left.peer_id, &right.peer_id))
                .then_with(|| left.address.as_ref().cmp(right.address.as_ref()))
                .then_with(|| compare_peer_id_bytes(&left.source_peer_id, &right.source_peer_id))
        });

        let mut selected = Vec::<DialCandidate>::new();
        selected
            .try_reserve_exact(MAX_DIAL_CANDIDATES)
            .map_err(PeerAddressStoreError::Allocation)?;
        let mut groups = [NetworkGroup::Ipv4([0; 2]); MAX_DIAL_CANDIDATES];
        for candidate in ranked {
            if selected.len() == MAX_DIAL_CANDIDATES {
                break;
            }
            if selected
                .iter()
                .any(|selected| selected.peer_id == candidate.peer_id)
                || groups[..selected.len()].contains(&candidate.group)
            {
                continue;
            }
            let source_count = selected
                .iter()
                .filter(|selected| selected.source_peer_id == candidate.source_peer_id)
                .count();
            if source_count == MAX_DIAL_CANDIDATES_PER_BOOTSTRAP {
                continue;
            }
            groups[selected.len()] = candidate.group;
            selected.push(DialCandidate {
                peer_id: candidate.peer_id,
                address: candidate.address.clone(),
                source_peer_id: candidate.source_peer_id,
            });
        }
        Ok(selected)
    }

    fn ensure_healthy(&self) -> Result<(), PeerAddressStoreError> {
        if self.poisoned {
            Err(PeerAddressStoreError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn encode_snapshot(
        &self,
        mutations: &[BatchMutation],
    ) -> Result<Vec<u8>, PeerAddressStoreError> {
        let count = self.records.len()
            + mutations
                .iter()
                .filter(|mutation| !mutation.replace)
                .count();
        let count = u16::try_from(count).expect("the record cap fits u16");
        let records = ProjectedRecords::new(&self.records, mutations);
        let fixed_length = STORE_HEADER.len()
            + 1
            + self.local_peer_id.as_ref().encoded_len()
            + CHECKSUM_BYTES
            + SALT_BYTES
            + 2
            + CHECKSUM_BYTES;
        let encoded_length = records.clone().try_fold(fixed_length, |length, record| {
            length
                .checked_add(stored_record_encoded_length(record))
                .ok_or(PeerAddressStoreError::SnapshotTooLong {
                    actual: usize::MAX,
                    maximum: MAX_STORE_BYTES,
                })
        })?;
        if encoded_length > MAX_STORE_BYTES {
            return Err(PeerAddressStoreError::SnapshotTooLong {
                actual: encoded_length,
                maximum: MAX_STORE_BYTES,
            });
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(encoded_length)
            .map_err(PeerAddressStoreError::Allocation)?;
        bytes.extend_from_slice(STORE_HEADER);
        write_peer_id(&mut bytes, self.local_peer_id);
        bytes.extend_from_slice(&self.bootstrap_digest);
        bytes.extend_from_slice(&self.ordering_salt);
        bytes.extend_from_slice(&count.to_be_bytes());

        for record in records {
            write_stored_record(&mut bytes, record);
        }
        let checksum = checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        debug_assert_eq!(bytes.len(), encoded_length);
        Ok(bytes)
    }

    fn commit_snapshot(&mut self, bytes: &[u8]) -> Result<(), PeerAddressStoreError> {
        #[cfg(test)]
        {
            self.commit_attempts += 1;
        }
        let result = commit_snapshot(&self.directory, bytes);
        if let Err(source) = result {
            self.poisoned = true;
            return Err(PeerAddressStoreError::Commit { source });
        }
        Ok(())
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

struct BatchMutation {
    replace: bool,
    record: StoredRecord,
}

fn push_batch_mutation(
    mutations: &mut Vec<BatchMutation>,
    maximum_remaining: usize,
    mutation: BatchMutation,
) -> Result<(), PeerAddressStoreError> {
    if mutations.is_empty() {
        mutations
            .try_reserve_exact(maximum_remaining)
            .map_err(PeerAddressStoreError::Allocation)?;
    }
    mutations.push(mutation);
    Ok(())
}

#[derive(Clone)]
struct ProjectedRecords<'a> {
    existing: &'a [StoredRecord],
    mutations: &'a [BatchMutation],
    existing_index: usize,
    mutation_index: usize,
}

impl<'a> ProjectedRecords<'a> {
    const fn new(existing: &'a [StoredRecord], mutations: &'a [BatchMutation]) -> Self {
        Self {
            existing,
            mutations,
            existing_index: 0,
            mutation_index: 0,
        }
    }
}

impl<'a> Iterator for ProjectedRecords<'a> {
    type Item = &'a StoredRecord;

    fn next(&mut self) -> Option<Self::Item> {
        let existing = self.existing.get(self.existing_index);
        let mutation = self.mutations.get(self.mutation_index);
        match (existing, mutation) {
            (Some(existing), Some(mutation)) => {
                match compare_peer_id_bytes(
                    &existing.record.peer_id,
                    &mutation.record.record.peer_id,
                ) {
                    std::cmp::Ordering::Less => {
                        self.existing_index += 1;
                        Some(existing)
                    }
                    std::cmp::Ordering::Equal => {
                        debug_assert!(mutation.replace);
                        self.existing_index += 1;
                        self.mutation_index += 1;
                        Some(&mutation.record)
                    }
                    std::cmp::Ordering::Greater => {
                        debug_assert!(!mutation.replace);
                        self.mutation_index += 1;
                        Some(&mutation.record)
                    }
                }
            }
            (Some(existing), None) => {
                self.existing_index += 1;
                Some(existing)
            }
            (None, Some(mutation)) => {
                debug_assert!(!mutation.replace);
                self.mutation_index += 1;
                Some(&mutation.record)
            }
            (None, None) => None,
        }
    }
}

struct RankedCandidate<'a> {
    score: [u8; CHECKSUM_BYTES],
    peer_id: PeerId,
    address: &'a Multiaddr,
    source_peer_id: PeerId,
    group: NetworkGroup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum NetworkGroup {
    Ipv4([u8; 2]),
    Ipv6([u8; 4]),
}

#[derive(Clone, Copy, Debug)]
enum AddressReason {
    TooLong,
    WrongShape,
    ZeroPort,
    NotGloballyRoutable,
}

impl fmt::Display for AddressReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => formatter.write_str("binary multi-address is too long"),
            Self::WrongShape => formatter.write_str("expected exactly /ip4|ip6/.../tcp/..."),
            Self::ZeroPort => formatter.write_str("TCP port zero is not dialable"),
            Self::NotGloballyRoutable => formatter.write_str("IP address is not globally routable"),
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

fn validate_record_capacity(
    records: &[StoredRecord],
    record: &SignedPeerRecord,
    source_peer_id: PeerId,
    replacing: Option<usize>,
) -> Result<(), PeerAddressStoreError> {
    if replacing.is_none() && records.len() == MAX_PEER_ADDRESS_RECORDS {
        return Err(PeerAddressStoreError::RecordCapacity {
            maximum: MAX_PEER_ADDRESS_RECORDS,
        });
    }
    let source_count = records
        .iter()
        .enumerate()
        .filter(|(index, stored)| {
            Some(*index) != replacing && stored.source_peer_id == source_peer_id
        })
        .count();
    if source_count == MAX_RECORDS_PER_BOOTSTRAP {
        return Err(PeerAddressStoreError::SourceCapacity {
            source: Box::new(source_peer_id),
            maximum: MAX_RECORDS_PER_BOOTSTRAP,
        });
    }

    for (address_index, address) in record.addresses.iter().enumerate() {
        let group = network_group(address).expect("validated records have network groups");
        if record.addresses[..address_index].iter().any(|prior| {
            network_group(prior).expect("validated records have network groups") == group
        }) {
            continue;
        }
        let count = records
            .iter()
            .enumerate()
            .filter(|(index, stored)| {
                Some(*index) != replacing
                    && stored.record.addresses.iter().any(|address| {
                        network_group(address).expect("stored records are validated") == group
                    })
            })
            .count();
        if count == MAX_RECORDS_PER_NETWORK_GROUP {
            return Err(PeerAddressStoreError::NetworkGroupCapacity {
                maximum: MAX_RECORDS_PER_NETWORK_GROUP,
            });
        }
    }
    Ok(())
}

fn validate_projected_capacity(
    records: &[StoredRecord],
    mutations: &[BatchMutation],
) -> Result<(), PeerAddressStoreError> {
    let insertions = mutations
        .iter()
        .filter(|mutation| !mutation.replace)
        .count();
    let projected_count =
        records
            .len()
            .checked_add(insertions)
            .ok_or(PeerAddressStoreError::RecordCapacity {
                maximum: MAX_PEER_ADDRESS_RECORDS,
            })?;
    if projected_count > MAX_PEER_ADDRESS_RECORDS {
        return Err(PeerAddressStoreError::RecordCapacity {
            maximum: MAX_PEER_ADDRESS_RECORDS,
        });
    }

    for (index, mutation) in mutations.iter().enumerate() {
        let source_peer_id = mutation.record.source_peer_id;
        if mutations[..index]
            .iter()
            .any(|prior| prior.record.source_peer_id == source_peer_id)
        {
            continue;
        }
        let source_count = ProjectedRecords::new(records, mutations)
            .filter(|stored| stored.source_peer_id == source_peer_id)
            .count();
        if source_count > MAX_RECORDS_PER_BOOTSTRAP {
            return Err(PeerAddressStoreError::SourceCapacity {
                source: Box::new(source_peer_id),
                maximum: MAX_RECORDS_PER_BOOTSTRAP,
            });
        }
    }

    let mut groups =
        [NetworkGroup::Ipv4([0; 2]); MAX_PEER_RECORDS_PER_BATCH * MAX_ADDRESSES_PER_PEER_RECORD];
    let mut group_count = 0_usize;
    for mutation in mutations {
        for address in &mutation.record.record.addresses {
            let group = network_group(address).expect("validated records have network groups");
            if groups[..group_count].contains(&group) {
                continue;
            }
            groups[group_count] = group;
            group_count += 1;
        }
    }

    let mut counts = [0_u8; MAX_PEER_RECORDS_PER_BATCH * MAX_ADDRESSES_PER_PEER_RECORD];
    for stored in ProjectedRecords::new(records, mutations) {
        let mut record_groups = [NetworkGroup::Ipv4([0; 2]); MAX_ADDRESSES_PER_PEER_RECORD];
        let mut record_group_count = 0_usize;
        for address in &stored.record.addresses {
            let group = network_group(address).expect("stored records are validated");
            if record_groups[..record_group_count].contains(&group) {
                continue;
            }
            record_groups[record_group_count] = group;
            record_group_count += 1;
            let Some(index) = groups[..group_count]
                .iter()
                .position(|candidate| *candidate == group)
            else {
                continue;
            };
            counts[index] += 1;
            if usize::from(counts[index]) > MAX_RECORDS_PER_NETWORK_GROUP {
                return Err(PeerAddressStoreError::NetworkGroupCapacity {
                    maximum: MAX_RECORDS_PER_NETWORK_GROUP,
                });
            }
        }
    }
    Ok(())
}

fn validate_endpoint(
    address: &Multiaddr,
    require_global: bool,
) -> Result<NetworkGroup, AddressReason> {
    if address.len() > MAX_PEER_ADDRESS_BYTES {
        return Err(AddressReason::TooLong);
    }
    endpoint_group(address, require_global)
}

fn endpoint_group(
    address: &Multiaddr,
    require_global: bool,
) -> Result<NetworkGroup, AddressReason> {
    let mut protocols = address.iter();
    let first = protocols.next();
    let second = protocols.next();
    if protocols.next().is_some() {
        return Err(AddressReason::WrongShape);
    }
    let port = match second {
        Some(Protocol::Tcp(port)) if port != 0 => port,
        Some(Protocol::Tcp(_)) => return Err(AddressReason::ZeroPort),
        _ => return Err(AddressReason::WrongShape),
    };
    let _ = port;
    match first {
        Some(Protocol::Ip4(address)) => {
            if require_global && !is_global_ipv4(address) {
                return Err(AddressReason::NotGloballyRoutable);
            }
            Ok(NetworkGroup::Ipv4([
                address.octets()[0],
                address.octets()[1],
            ]))
        }
        Some(Protocol::Ip6(address)) => {
            if require_global && !is_global_ipv6(address) {
                return Err(AddressReason::NotGloballyRoutable);
            }
            let octets = address.octets();
            Ok(NetworkGroup::Ipv6([
                octets[0], octets[1], octets[2], octets[3],
            ]))
        }
        _ => Err(AddressReason::WrongShape),
    }
}

fn network_group(address: &Multiaddr) -> Option<NetworkGroup> {
    endpoint_group(address, false).ok()
}

fn is_global_ipv4(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    !in_ipv4(value, [0, 0, 0, 0], 8)
        && !in_ipv4(value, [10, 0, 0, 0], 8)
        && !in_ipv4(value, [100, 64, 0, 0], 10)
        && !in_ipv4(value, [127, 0, 0, 0], 8)
        && !in_ipv4(value, [169, 254, 0, 0], 16)
        && !in_ipv4(value, [172, 16, 0, 0], 12)
        && !in_ipv4(value, [192, 0, 0, 0], 24)
        && !in_ipv4(value, [192, 0, 2, 0], 24)
        && !in_ipv4(value, [192, 168, 0, 0], 16)
        && !in_ipv4(value, [198, 18, 0, 0], 15)
        && !in_ipv4(value, [198, 51, 100, 0], 24)
        && !in_ipv4(value, [203, 0, 113, 0], 24)
        && !in_ipv4(value, [224, 0, 0, 0], 4)
        && !in_ipv4(value, [240, 0, 0, 0], 4)
}

fn in_ipv4(value: u32, base: [u8; 4], prefix: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    value & mask == u32::from(Ipv4Addr::from(base)) & mask
}

fn is_global_ipv6(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    let global_unicast = octets[0] & 0xe0 == 0x20;
    global_unicast
        && !in_ipv6(address, Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0), 48)
        && !in_ipv6(address, Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 0), 28)
        && !in_ipv6(address, Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28)
        && !in_ipv6(address, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
}

fn in_ipv6(value: Ipv6Addr, base: Ipv6Addr, prefix: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
    u128::from(value) & mask == u128::from(base) & mask
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

fn candidate_score(
    salt: &[u8; SALT_BYTES],
    epoch: u64,
    peer_id: PeerId,
    address: &Multiaddr,
    source_peer_id: PeerId,
) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(CANDIDATE_ORDER_DOMAIN);
    hasher.update(salt);
    hasher.update(epoch.to_be_bytes());
    let (peer_id, peer_id_length) = encode_peer_id(peer_id);
    hasher.update([u8::try_from(peer_id_length).expect("peer id fits u8")]);
    hasher.update(&peer_id[..peer_id_length]);
    let address = address.as_ref();
    hasher.update(
        u16::try_from(address.len())
            .expect("validated address fits u16")
            .to_be_bytes(),
    );
    hasher.update(address);
    let (source_peer_id, source_peer_id_length) = encode_peer_id(source_peer_id);
    hasher.update([u8::try_from(source_peer_id_length).expect("peer id fits u8")]);
    hasher.update(&source_peer_id[..source_peer_id_length]);
    hasher.finalize().into()
}

fn bootstrap_digest(bootstraps: &[BootstrapPeer]) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(BOOTSTRAP_DIGEST_DOMAIN);
    hasher.update([u8::try_from(bootstraps.len()).expect("bootstrap cap fits u8")]);
    for bootstrap in bootstraps {
        let (peer_id, peer_id_length) = encode_peer_id(bootstrap.peer_id);
        hasher.update([u8::try_from(peer_id_length).expect("peer id fits u8")]);
        hasher.update(&peer_id[..peer_id_length]);
        let address = bootstrap.address.as_ref();
        hasher.update(
            u16::try_from(address.len())
                .expect("bootstrap address fits u16")
                .to_be_bytes(),
        );
        hasher.update(address);
    }
    hasher.finalize().into()
}

fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(STORE_CHECKSUM_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn write_peer_id(bytes: &mut Vec<u8>, peer_id: PeerId) {
    let (peer_id, peer_id_length) = encode_peer_id(peer_id);
    bytes.push(u8::try_from(peer_id_length).expect("libp2p peer id fits u8"));
    bytes.extend_from_slice(&peer_id[..peer_id_length]);
}

fn write_stored_record(bytes: &mut Vec<u8>, record: &StoredRecord) {
    write_peer_id(bytes, record.source_peer_id);
    bytes.extend_from_slice(&record.received_at.to_be_bytes());
    bytes.extend_from_slice(
        &u16::try_from(record.record.envelope_bytes.len())
            .expect("envelope cap fits u16")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&record.record.envelope_bytes);
}

fn stored_record_encoded_length(record: &StoredRecord) -> usize {
    1 + record.source_peer_id.as_ref().encoded_len() + 8 + 2 + record.record.envelope_bytes.len()
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

fn open_lock(directory: &Path) -> Result<File, PeerAddressStoreError> {
    match open_exclusive(directory, LOCK_FILE_NAME) {
        Ok(lock) => Ok(lock),
        Err(ExclusiveLockError::Locked) => Err(PeerAddressStoreError::Locked),
        Err(ExclusiveLockError::Io(source)) => Err(PeerAddressStoreError::OpenLock(source)),
    }
}

fn commit_snapshot(directory: &Path, bytes: &[u8]) -> io::Result<()> {
    replace_synced(directory, TEMP_FILE_NAME, STORE_FILE_NAME, bytes)
}

fn decode_snapshot(
    bytes: &[u8],
    local_peer_id: PeerId,
    bootstraps: &[BootstrapPeer],
    expected_bootstrap_digest: [u8; CHECKSUM_BYTES],
) -> Result<([u8; SALT_BYTES], Vec<StoredRecord>), PeerAddressStoreError> {
    let minimum = STORE_HEADER.len() + 1 + 1 + CHECKSUM_BYTES + SALT_BYTES + 2 + CHECKSUM_BYTES;
    if bytes.len() < minimum {
        return Err(PeerAddressStoreError::InvalidHeader);
    }
    let body_length = bytes.len() - CHECKSUM_BYTES;
    let (body, expected_checksum) = bytes.split_at(body_length);
    if checksum(body).as_slice() != expected_checksum {
        return Err(PeerAddressStoreError::ChecksumMismatch);
    }
    let Some(remainder) = body.strip_prefix(STORE_HEADER) else {
        return Err(PeerAddressStoreError::InvalidHeader);
    };
    let mut cursor = Cursor::new(remainder);
    if cursor.read_peer_id()? != local_peer_id {
        return Err(PeerAddressStoreError::LocalPeerMismatch);
    }
    if cursor.read_array::<CHECKSUM_BYTES>()? != expected_bootstrap_digest {
        return Err(PeerAddressStoreError::BootstrapConfigurationMismatch);
    }
    let ordering_salt = cursor.read_array::<SALT_BYTES>()?;
    let count = usize::from(cursor.read_u16()?);
    if count > MAX_PEER_ADDRESS_RECORDS {
        return Err(PeerAddressStoreError::RecordCapacity {
            maximum: MAX_PEER_ADDRESS_RECORDS,
        });
    }
    let minimum_entries_length = count.checked_mul(MIN_STORED_RECORD_BYTES).ok_or(
        PeerAddressStoreError::InvalidSnapshot("record count length overflow"),
    )?;
    if cursor.remaining() < minimum_entries_length {
        return Err(PeerAddressStoreError::InvalidSnapshot(
            "record count exceeds remaining bytes",
        ));
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(PeerAddressStoreError::Allocation)?;
    for index in 0..count {
        let source_peer_id = cursor.read_peer_id()?;
        if !bootstraps
            .iter()
            .any(|bootstrap| bootstrap.peer_id == source_peer_id)
        {
            return Err(PeerAddressStoreError::UnknownSource(Box::new(
                source_peer_id,
            )));
        }
        let received_at = cursor.read_u64()?;
        validate_receipt_time(received_at)?;
        let envelope_length = usize::from(cursor.read_u16()?);
        if envelope_length == 0 || envelope_length > MAX_SIGNED_PEER_RECORD_BYTES {
            return Err(PeerAddressStoreError::InvalidSnapshot(
                "envelope length is outside bounds",
            ));
        }
        let envelope = cursor.read_exact(envelope_length)?;
        let record = SignedPeerRecord::from_envelope_slice(envelope).map_err(|source| {
            PeerAddressStoreError::InvalidRecord {
                index,
                source: Box::new(source),
            }
        })?;
        if record.envelope_bytes.as_slice() != envelope {
            return Err(PeerAddressStoreError::InvalidSnapshot(
                "signed envelope is not normalized",
            ));
        }
        if record.peer_id == local_peer_id {
            return Err(PeerAddressStoreError::LocalRecord(Box::new(record.peer_id)));
        }
        if records.last().is_some_and(|prior: &StoredRecord| {
            compare_peer_id_bytes(&prior.record.peer_id, &record.peer_id)
                != std::cmp::Ordering::Less
        }) {
            return Err(PeerAddressStoreError::InvalidSnapshot(
                "record subjects are not strictly ordered",
            ));
        }
        validate_record_capacity(&records, &record, source_peer_id, None)?;
        records.push(StoredRecord {
            source_peer_id,
            received_at,
            record,
        });
    }
    if !cursor.is_empty() {
        return Err(PeerAddressStoreError::InvalidSnapshot("trailing bytes"));
    }
    Ok((ordering_salt, records))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PeerAddressStoreError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(PeerAddressStoreError::InvalidSnapshot("length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(PeerAddressStoreError::InvalidSnapshot("truncated field"))?;
        self.position = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, PeerAddressStoreError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, PeerAddressStoreError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], PeerAddressStoreError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| PeerAddressStoreError::InvalidSnapshot("invalid fixed field"))
    }

    fn read_peer_id(&mut self) -> Result<PeerId, PeerAddressStoreError> {
        let length = usize::from(*self.read_exact(1)?.first().expect("one byte was read"));
        if length == 0 || length > MAX_PEER_ID_BYTES {
            return Err(PeerAddressStoreError::InvalidPeerId);
        }
        PeerId::from_bytes(self.read_exact(length)?)
            .map_err(|_| PeerAddressStoreError::InvalidPeerId)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
}

#[cfg(test)]
mod tests;
