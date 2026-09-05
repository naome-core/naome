use super::*;

impl PeerAddressStore {
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
    pub(super) fn admit_record_batch_from_validated_source(
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
}

pub(super) struct BatchMutation {
    pub(super) replace: bool,
    pub(super) record: StoredRecord,
}

pub(super) fn push_batch_mutation(
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
pub(super) struct ProjectedRecords<'a> {
    pub(super) existing: &'a [StoredRecord],
    pub(super) mutations: &'a [BatchMutation],
    pub(super) existing_index: usize,
    pub(super) mutation_index: usize,
}

impl<'a> ProjectedRecords<'a> {
    pub(super) const fn new(existing: &'a [StoredRecord], mutations: &'a [BatchMutation]) -> Self {
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
pub(super) fn validate_record_capacity(
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

pub(super) fn validate_projected_capacity(
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

impl PeerAddressStore {
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
}
