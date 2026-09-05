use super::*;

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
    pub(super) fn encode_snapshot(
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
    pub(super) fn commit_snapshot(&mut self, bytes: &[u8]) -> Result<(), PeerAddressStoreError> {
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

pub(super) fn bootstrap_digest(bootstraps: &[BootstrapPeer]) -> [u8; CHECKSUM_BYTES] {
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

pub(super) fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(STORE_CHECKSUM_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(super) fn write_peer_id(bytes: &mut Vec<u8>, peer_id: PeerId) {
    let (peer_id, peer_id_length) = encode_peer_id(peer_id);
    bytes.push(u8::try_from(peer_id_length).expect("libp2p peer id fits u8"));
    bytes.extend_from_slice(&peer_id[..peer_id_length]);
}

pub(super) fn write_stored_record(bytes: &mut Vec<u8>, record: &StoredRecord) {
    write_peer_id(bytes, record.source_peer_id);
    bytes.extend_from_slice(&record.received_at.to_be_bytes());
    bytes.extend_from_slice(
        &u16::try_from(record.record.envelope_bytes.len())
            .expect("envelope cap fits u16")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&record.record.envelope_bytes);
}

pub(super) fn stored_record_encoded_length(record: &StoredRecord) -> usize {
    1 + record.source_peer_id.as_ref().encoded_len() + 8 + 2 + record.record.envelope_bytes.len()
}
pub(super) fn open_lock(directory: &Path) -> Result<File, PeerAddressStoreError> {
    match open_exclusive(directory, LOCK_FILE_NAME) {
        Ok(lock) => Ok(lock),
        Err(ExclusiveLockError::Locked) => Err(PeerAddressStoreError::Locked),
        Err(ExclusiveLockError::Io(source)) => Err(PeerAddressStoreError::OpenLock(source)),
    }
}

pub(super) fn commit_snapshot(directory: &Path, bytes: &[u8]) -> io::Result<()> {
    replace_synced(directory, TEMP_FILE_NAME, STORE_FILE_NAME, bytes)
}

pub(super) fn decode_snapshot(
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

pub(super) struct Cursor<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) position: usize,
}

impl<'a> Cursor<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(super) fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PeerAddressStoreError> {
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

    pub(super) fn read_u16(&mut self) -> Result<u16, PeerAddressStoreError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    pub(super) fn read_u64(&mut self) -> Result<u64, PeerAddressStoreError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    pub(super) fn read_array<const N: usize>(&mut self) -> Result<[u8; N], PeerAddressStoreError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| PeerAddressStoreError::InvalidSnapshot("invalid fixed field"))
    }

    pub(super) fn read_peer_id(&mut self) -> Result<PeerId, PeerAddressStoreError> {
        let length = usize::from(*self.read_exact(1)?.first().expect("one byte was read"));
        if length == 0 || length > MAX_PEER_ID_BYTES {
            return Err(PeerAddressStoreError::InvalidPeerId);
        }
        PeerId::from_bytes(self.read_exact(length)?)
            .map_err(|_| PeerAddressStoreError::InvalidPeerId)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    pub(super) fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
}
