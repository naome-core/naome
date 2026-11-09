//! An immutable bounded page from the existing admitted-source journal.
use super::*;
use crate::learning::history::{Lane, PAGE_BYTES, Page, Receipt, Request, SOURCES, Source};

// The prepared snapshot also contains the replay (at most 32 KiB) and the
// job's existing evidence. Of its remaining 8 KiB, reserve half for the
// receipt and envelope. The full page is an upper bound on its observations.
fn records_page_bytes(evidence_bytes: usize) -> usize {
    (PAGE_BYTES + 4096)
        .saturating_sub(evidence_bytes)
        .min(PAGE_BYTES)
}

impl Disk {
    pub(in crate::jobs) fn history_page(
        &mut self,
        journal: &mut Journal,
        id: u64,
        unit: u32,
        request: &Request,
    ) -> Result<Receipt, crate::Error> {
        let record = journal
            .records
            .get(&id)
            .ok_or(crate::ResearchFailure::HistoryOriginalJobMissing)?;
        let native = record
            .native
            .as_ref()
            .ok_or(crate::ResearchFailure::HistoryNativeOwnerMissing)?;
        if record.state != State::Running
            || unit != 1
            || record.checkpoint != 0
            || record.reserved_units < unit
            || record.provider != crate::learning::PROVIDER
            || !native.training
            || native.units() <= 1
            || request.horizon != id
            || native.history_request.as_ref() != Some(request)
        {
            return Err(
                crate::ResearchFailure::HistoryReadLacksItsOriginalTrainingReservation.into(),
            );
        }
        request.validate()?;
        if let Some(receipt) = &native.history {
            receipt.validate(request)?;
            return Ok(receipt.clone());
        }
        let started = crate::learning::meta::cpu_micros()?;
        if request.lane == Lane::Records {
            let bytes = records_page_bytes(crate::checkpoint::encode(&native.evidence)?.len());
            return self.experience_page(journal, id, request, started, bytes);
        }
        let mut read_bytes = 0usize;
        let mut read_operations = 1usize;
        let rows = self.checkpoint.page(
            "replay_seen",
            request.after.as_deref(),
            SOURCES,
            crate::resources::limits().closure_bytes,
        )?;
        read_bytes += rows
            .iter()
            .map(|(key, bytes)| key.len() + bytes.len())
            .sum::<usize>();
        let at_end = rows.len() < SOURCES;
        let mut page = Page {
            request: request.clone(),
            next: None,
            examined: Vec::new(),
            sources: Vec::new(),
            records: Vec::new(),
        };
        for (key, payload) in rows {
            crate::object::id_bytes(&key)?;
            let source_id: u64 = crate::checkpoint::decode(&payload)?;
            if source_id == 0 {
                return Err(crate::ResearchFailure::HistorySourceHasNoJob.into());
            }
            if source_id < id {
                let bytes = self
                    .checkpoint
                    .get_bytes(
                        "record",
                        &source_id.to_string(),
                        crate::resources::limits()
                            .native_model_blob_bytes
                            .saturating_sub(read_bytes),
                    )?
                    .ok_or(crate::ResearchFailure::HistoricalAdmittedSourceRecordMissing)?;
                read_bytes = read_bytes
                    .checked_add(bytes.len())
                    .ok_or(crate::ResearchFailure::HistoryIoOverflow)?;
                read_operations += 1;
                let source: Record = crate::checkpoint::decode(&bytes)?;
                let Some(Output::Native {
                    solution: Some(solution),
                    ..
                }) = &source.result
                else {
                    return Err(crate::ResearchFailure::HistoricalSourceSolutionMissing.into());
                };
                if source.id != source_id
                    || source.state != State::Complete
                    || !source.acknowledged
                    || solution.proof_id != key
                {
                    return Err(crate::ResearchFailure::HistoricalSourceIdentityDiffers.into());
                }
                let (question, origin, peer_evidence) = match &source.input {
                    Input::Solve { question } => {
                        let bytes = self
                            .checkpoint
                            .get_bytes(
                                "learned",
                                &source_id.to_string(),
                                256.min(
                                    crate::resources::limits()
                                        .native_model_blob_bytes
                                        .saturating_sub(read_bytes),
                                ),
                            )?
                            .ok_or(crate::ResearchFailure::HistoricalOwnAdmissionReceiptMissing)?;
                        read_bytes += bytes.len();
                        read_operations += 1;
                        let root: String = crate::checkpoint::decode(&bytes)?;
                        let expected =
                            crate::learning::program::Candidate::artifact(solution, question)?;
                        if root != crate::hex(expected.as_bytes()) {
                            return Err(
                                crate::ResearchFailure::HistoricalOwnAdmissionIdentityDiffers
                                    .into(),
                            );
                        }
                        (question.clone(), crate::learning::Origin::Local, None)
                    }
                    Input::Peer {
                        question,
                        artifact,
                        peer,
                        evidence,
                    } => {
                        let bytes = self
                            .checkpoint
                            .get_bytes(
                                "peer_receipt",
                                artifact,
                                crate::resources::limits().closure_bytes.min(
                                    crate::resources::limits()
                                        .native_model_blob_bytes
                                        .saturating_sub(read_bytes),
                                ),
                            )?
                            .ok_or(crate::ResearchFailure::HistoricalPeerReceiptMissing)?;
                        read_bytes += bytes.len();
                        read_operations += 1;
                        let receipt: PeerReceipt = crate::checkpoint::decode(&bytes)?;
                        // replay_seen owns checked conversions, including ones
                        // declined by the bounded working selector. A terminal
                        // disposition is not proof authority: the worker still
                        // reconstructs this exact admitted native evidence.
                        let terminal = match &receipt.status {
                            PeerStatus::Learned {
                                conversion_job,
                                trace_proof,
                            } => *conversion_job == source_id && *trace_proof == key,
                            PeerStatus::Unsupported { .. } => true,
                            _ => false,
                        };
                        if receipt.admission.artifact != *artifact
                            || receipt.admission.peer != *peer
                            || receipt.admission.question.as_ref() != Some(question)
                            || receipt.admission.evidence.as_ref() != Some(evidence)
                            || !terminal
                        {
                            return Err(
                                crate::ResearchFailure::HistoricalPeerProvenanceDiffers.into()
                            );
                        }
                        (
                            question.clone(),
                            crate::learning::Origin::Peer {
                                artifact: artifact.clone(),
                                peer: peer.clone(),
                            },
                            Some(evidence.clone()),
                        )
                    }
                    _ => return Err(crate::ResearchFailure::HistoricalSourceRoleDiffers.into()),
                };
                page.sources.push(Source {
                    job: source_id,
                    origin,
                    question,
                    solution: solution.clone(),
                    peer_evidence,
                });
            }
            page.examined.push((key.clone(), source_id));
            page.next = Some(key);
            if crate::checkpoint::encode(&page)?.len() > PAGE_BYTES {
                page.examined.pop();
                if source_id < id {
                    page.sources.pop();
                }
                page.next = page.examined.last().map(|(key, _)| key.clone());
                if page.examined.is_empty() {
                    return Err(
                        crate::ResearchFailure::HistoricalSourceExceedsWorkingPageCapacity.into(),
                    );
                }
                return self.retain_history(
                    journal,
                    id,
                    page,
                    read_bytes,
                    read_operations,
                    started,
                );
            }
        }
        if at_end {
            page.next = None;
        }
        self.retain_history(journal, id, page, read_bytes, read_operations, started)
    }

    fn experience_page(
        &mut self,
        journal: &mut Journal,
        id: u64,
        request: &Request,
        started: u64,
        page_bytes: usize,
    ) -> Result<Receipt, crate::Error> {
        let mut page = Page {
            request: request.clone(),
            next: request.after.clone(),
            examined: Vec::new(),
            sources: Vec::new(),
            records: Vec::new(),
        };
        let mut read_bytes = 0usize;
        let mut read_operations = 0usize;
        for _ in 0..SOURCES {
            let remaining = crate::resources::limits()
                .native_model_blob_bytes
                .saturating_sub(read_bytes);
            if remaining == 0 {
                break;
            }
            // Read one owned row at a time. Large historical jobs do not make
            // the resident page or its lifetime IO allowance unbounded.
            let mut rows = self
                .checkpoint
                .page("record", page.next.as_deref(), 1, remaining)?;
            read_operations += 1;
            let Some((key, bytes)) = rows.pop() else {
                page.next = None;
                break;
            };
            read_bytes = read_bytes
                .checked_add(key.len())
                .and_then(|n| n.checked_add(bytes.len()))
                .ok_or(crate::ResearchFailure::ExperiencePageIoOverflow)?;
            let record: crate::jobs::Record = crate::checkpoint::decode(&bytes)?;
            if record.id == 0 || record.id.to_string() != key {
                return Err(crate::ResearchFailure::ExperienceJournalRecordIdentityDiffers.into());
            }
            let observation = if record.id < id {
                crate::learning::experience::Observation::from_record(&record)?
            } else {
                None
            };
            page.records.push(crate::learning::history::Record {
                job: record.id,
                observation,
            });
            page.examined.push((key.clone(), record.id));
            if crate::checkpoint::encode(&page)?.len() > page_bytes {
                page.records.pop();
                page.examined.pop();
                if page.examined.is_empty() {
                    return Err(
                        crate::ResearchFailure::ExperienceRecordExceedsTheWorkingPageCapacity
                            .into(),
                    );
                }
                break;
            }
            page.next = Some(key);
        }
        self.retain_history(journal, id, page, read_bytes, read_operations, started)
    }

    fn retain_history(
        &mut self,
        journal: &mut Journal,
        id: u64,
        page: Page,
        read_bytes: usize,
        read_operations: usize,
        started: u64,
    ) -> Result<Receipt, crate::Error> {
        let bytes = crate::checkpoint::encode(&page)?;
        let blob = crate::learning::Blob::of(&bytes);
        let receipt = Receipt {
            request: page.request.clone(),
            blob: blob.clone(),
            next: page.next,
            read_bytes,
            read_operations,
            read_cpu_micros: crate::learning::meta::cpu_micros()?.saturating_sub(started),
        };
        receipt.validate(&page.request)?;
        let mut updates = Vec::new();
        for (index, part) in bytes
            .chunks(crate::resources::limits().native_model_chunk_bytes)
            .enumerate()
        {
            if let Some(previous) = self.checkpoint.get_bytes(
                "model",
                &blob.key(index),
                crate::resources::limits().native_model_chunk_bytes,
            )? {
                if previous != part {
                    return Err(crate::ResearchFailure::HistoricalPageImmutableChunkDiffers.into());
                }
            } else {
                updates.push(crate::checkpoint::Update::Put {
                    kind: "model",
                    key: blob.key(index),
                    payload: part.to_vec(),
                });
            }
        }
        let record = journal
            .records
            .get_mut(&id)
            .ok_or(crate::ResearchFailure::HistoryJobMissing)?;
        let previous = record.native.clone();
        let native = record
            .native
            .as_mut()
            .ok_or(crate::ResearchFailure::HistoryNativeOwnerMissing)?;
        native.io_bytes = native
            .io_bytes
            .checked_add(read_bytes)
            .and_then(|n| n.checked_add(bytes.len()))
            .ok_or(crate::ResearchFailure::HistoryLifetimeIoOverflow)?;
        native.io_operations = native
            .io_operations
            .checked_add(read_operations)
            .and_then(|n| n.checked_add(blob.chunks()))
            .ok_or(crate::ResearchFailure::HistoryIoOperationOverflow)?;
        native.written.push((1, blob));
        native.history = Some(receipt.clone());
        if let Err(error) = native
            .validate()
            .and_then(|()| self.save_with(journal, updates))
        {
            journal
                .records
                .get_mut(&id)
                .expect("history original owner")
                .native = previous;
            return Err(error);
        }
        Ok(receipt)
    }
}
