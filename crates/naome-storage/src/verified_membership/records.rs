use super::*;

pub(super) fn event_body(
    event: &MembershipMachineEvent,
    finalized: Option<&MembershipFinalityProof>,
) -> Vec<u8> {
    let event = event.to_bytes();
    let proof = finalized.map_or_else(Vec::new, MembershipFinalityProof::to_bytes);
    let mut bytes = vec![0];
    put(&mut bytes, &event);
    put(&mut bytes, &proof);
    bytes
}

pub(super) fn completion_body(publications: &[MembershipPublication]) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&(publications.len() as u16).to_be_bytes());
    for publication in publications {
        put(&mut bytes, &publication.to_bytes());
    }
    bytes
}

fn put(bytes: &mut Vec<u8>, part: &[u8]) {
    bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
    bytes.extend_from_slice(part);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], MembershipJournalError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(MembershipJournalError::Encoding)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(MembershipJournalError::Encoding)?;
        self.position = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, MembershipJournalError> {
        Ok(self.take(1)?[0])
    }
    fn part(&mut self, maximum: usize) -> Result<&'a [u8], MembershipJournalError> {
        let length = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| MembershipJournalError::Encoding)?,
        ) as usize;
        if length > maximum {
            return Err(MembershipJournalError::Limit);
        }
        self.take(length)
    }
    fn finish(self) -> Result<(), MembershipJournalError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(MembershipJournalError::Encoding)
        }
    }
}

impl MembershipJournal {
    pub(super) fn apply_body(
        &mut self,
        body: &[u8],
        body_offset: u64,
    ) -> Result<(), MembershipJournalError> {
        let mut reader = Cursor {
            bytes: body,
            position: 0,
        };
        if self.halted {
            return Err(MembershipJournalError::ConflictingFinality);
        }
        match reader.byte()? {
            0 => {
                if !self.pending.is_empty() {
                    return Err(MembershipJournalError::PendingSignature);
                }
                let event = MembershipMachineEvent::from_bytes(
                    reader.part(MembershipMachineEvent::MAX_BYTES)?,
                )?;
                let transition = self.machine.prepare(event)?;
                let proof = reader.part(MembershipFinalityProof::MAX_BYTES)?;
                let proof_offset = body_offset + (reader.position - proof.len()) as u64;
                if proof
                    != transition
                        .finalized()
                        .map_or_else(Vec::new, MembershipFinalityProof::to_bytes)
                {
                    return Err(MembershipJournalError::Integrity);
                }
                reader.finish()?;
                if let Some(finalized) = transition.finalized() {
                    let height = finalized.proposal.value.height();
                    let snapshot = self.machine.branch().next_snapshot()?;
                    if self
                        .snapshots
                        .last_key_value()
                        .is_none_or(|(_, previous)| previous.id() != snapshot.id())
                    {
                        self.snapshots.insert(height, snapshot.clone());
                    }
                    if self
                        .proofs
                        .insert(
                            height,
                            (
                                proof_offset,
                                proof.len(),
                                hash(b"naome/verified-membership/v0/proof-record\0", &[proof]),
                            ),
                        )
                        .is_some()
                    {
                        return Err(MembershipJournalError::Integrity);
                    }
                }
                self.pending = transition.intents().to_vec();
                let publications = transition.publications().to_vec();
                self.machine = transition.into_machine();
                self.prune_publications();
                for publication in publications {
                    self.retain_publication(publication)?;
                }
            }
            1 => {
                let count = u16::from_be_bytes(
                    reader
                        .take(2)?
                        .try_into()
                        .map_err(|_| MembershipJournalError::Encoding)?,
                ) as usize;
                if count == 0 || count > 4 || count != self.pending.len() {
                    return Err(MembershipJournalError::PendingSignature);
                }
                let mut publications = Vec::with_capacity(count);
                for intent in &self.pending {
                    let publication = MembershipPublication::from_bytes(
                        reader.part(MembershipMachineEvent::MAX_BYTES)?,
                    )?;
                    intent.verify_completion(&publication)?;
                    publications.push(publication);
                }
                reader.finish()?;
                self.pending.clear();
                for publication in publications {
                    self.retain_publication(publication)?;
                }
            }
            2 => {
                let proof = MembershipFinalityProof::from_bytes(&body[1..])?;
                if !self.verify_historical_conflict(&proof)? {
                    return Err(MembershipJournalError::Integrity);
                }
                self.halted = true;
                // Preserve the prepared intent in history, but never complete it
                // after authenticated conflicting finality has stopped signing.
                self.pending.clear();
            }
            _ => return Err(MembershipJournalError::Encoding),
        }
        Ok(())
    }

    fn prune_publications(&mut self) {
        let selected_height = self.machine.branch().height();
        let floor = self.machine.round().saturating_sub(7);
        self.outbox.retain(|_, publication| match publication {
            MembershipPublication::Finality(proof) => {
                proof.proposal.value.height() == selected_height
            }
            MembershipPublication::Proposal { proposal, .. } => {
                proposal.value.height() > selected_height && proposal.round >= floor
            }
            MembershipPublication::Vote(vote) => {
                vote.coordinate.height > selected_height && vote.coordinate.round >= floor
            }
            MembershipPublication::Certificate(certificate) => {
                certificate.coordinate().height > selected_height
                    && certificate.coordinate().round >= floor
            }
        });
    }

    fn retain_publication(
        &mut self,
        publication: MembershipPublication,
    ) -> Result<(), MembershipJournalError> {
        let id = publication.id();
        if !self.outbox.contains_key(&id) && self.outbox.len() >= MAX_OUTBOX_ITEMS {
            return Err(MembershipJournalError::Limit);
        }
        self.outbox.insert(id, publication);
        self.prune_publications();
        Ok(())
    }
}
