use super::*;

impl PeerAddressStore {
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
}

pub(super) struct RankedCandidate<'a> {
    pub(super) score: [u8; CHECKSUM_BYTES],
    pub(super) peer_id: PeerId,
    pub(super) address: &'a Multiaddr,
    pub(super) source_peer_id: PeerId,
    pub(super) group: NetworkGroup,
}
pub(super) fn candidate_score(
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
