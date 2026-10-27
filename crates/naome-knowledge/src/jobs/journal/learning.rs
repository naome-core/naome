//! Native learning rows share the canonical job checkpoint and transactions.
use super::*;
mod validation;
pub(super) use validation::validate_rows;
impl Disk {
    pub(in crate::jobs) fn replay_evidence(
        &self,
        state: &crate::learning::State,
    ) -> Result<Vec<crate::learning::Evidence>, String> {
        let mut result = std::collections::BTreeMap::new();
        for example in state
            .training_sources()
            .filter(|e| e.evidence_job().is_some())
        {
            let source: Record = self
                .checkpoint
                .get(
                    "record",
                    &example.job.to_string(),
                    crate::checkpoint::MAX_ROW,
                )?
                .ok_or("peer replay source job absent")?;
            let Some(Output::Native {
                solution: Some(solution),
                ..
            }) = &source.result
            else {
                return Err("replay source solution missing".into());
            };
            if source.state != State::Complete || !example.matches_solution(solution) {
                return Err("replay source snapshot differs".into());
            }
            let trace = match &source.input {
                Input::Peer {
                    question,
                    artifact,
                    certificate,
                    ..
                } => {
                    if !crate::learning::peer::matches_artifact(
                        &example.proof_id,
                        artifact,
                        certificate,
                    )? {
                        return Err("peer snapshot artifact differs".into());
                    }
                    crate::learning::peer::validate_solution(
                        question,
                        artifact,
                        certificate,
                        solution,
                    )?;
                    solution.tree.clone()
                }
                Input::Solve { .. } => {
                    if self
                        .checkpoint
                        .get::<String>("learned", &source.id.to_string(), 256)?
                        .as_deref()
                        != Some(
                            crate::hex(crate::object::proof_address(&example.proof_id)?.as_bytes())
                                .as_str(),
                        )
                    {
                        return Err("local replay snapshot lacks admission receipt".into());
                    }
                    solution.tree.clone()
                }
                _ => return Err("replay source role differs".into()),
            };
            result.insert(
                example.job,
                crate::learning::Evidence {
                    job: example.job,
                    proof_id: example.proof_id.clone(),
                    trace,
                },
            );
        }
        Ok(result.into_values().collect())
    }
    pub(in crate::jobs) fn enqueue_peer(
        &mut self,
        journal: &mut Journal,
        admission: PeerAdmission,
    ) -> Result<(), String> {
        if admission.ordinal == 0 {
            return Err("peer learning ordinal is zero".into());
        }
        crate::object::id_bytes(&admission.artifact)?;
        admission.binding.validate()?;
        let peer: libp2p::PeerId = admission
            .peer
            .parse()
            .map_err(|_| "peer learning source syntax")?;
        if peer.to_string() != admission.peer {
            return Err("peer learning source encoding".into());
        }
        if admission
            .certificate
            .as_ref()
            .is_some_and(|b| b.len() > 8 * 1024)
        {
            return Err("peer compressed admission capacity".into());
        }
        if let Some(question) = &admission.question {
            naome_authoring::CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
        }
        let learning = journal
            .learning
            .as_mut()
            .ok_or("peer learning owner is disabled")?;
        if let Some(packet) = admission.certificate.as_ref().filter(|_| {
            admission
                .question
                .as_deref()
                .is_some_and(crate::learning::State::eligible)
        }) {
            let entry = crate::learning::knowledge::Entry {
                packet: packet.clone(),
            };
            let verified = entry.verified()?;
            if !crate::learning::peer::matches_artifact(
                &crate::hex(verified.native_id.as_bytes()),
                &admission.artifact,
                packet,
            )? {
                return Err("theorem observation artifact differs".into());
            }
            learning.remember_theorem(entry)?;
        }
        let mut updates = Vec::new();
        if self
            .checkpoint
            .get::<PeerReceipt>(
                "peer_receipt",
                &admission.artifact,
                crate::resources::limits().closure_bytes,
            )?
            .is_none()
        {
            let receipt = PeerReceipt {
                admission: admission.clone(),
                status: PeerStatus::Queued,
            };
            updates.push(crate::checkpoint::Update::put(
                "peer_pending",
                format!("{:020}", admission.ordinal),
                &admission,
            )?);
            updates.push(crate::checkpoint::Update::put(
                "peer_receipt",
                &admission.artifact,
                &receipt,
            )?);
        }
        learning.peer_cursor = learning.peer_cursor.max(admission.ordinal);
        self.save_with(journal, updates).map_err(String::from)
    }
    pub(in crate::jobs) fn pending_peer(&self) -> Result<Option<PeerAdmission>, String> {
        let mut rows = self.checkpoint.page(
            "peer_pending",
            None,
            1,
            crate::resources::limits().closure_bytes,
        )?;
        let Some((key, payload)) = rows.pop() else {
            return Ok(None);
        };
        let admission: PeerAdmission = crate::checkpoint::decode(&payload)?;
        if key != format!("{:020}", admission.ordinal) {
            return Err("peer learning queue ordinal differs".into());
        }
        Ok(Some(admission))
    }
    pub(in crate::jobs) fn peer_status(
        &mut self,
        journal: &mut Journal,
        admission: &PeerAdmission,
        status: PeerStatus,
    ) -> Result<(), String> {
        let receipt = PeerReceipt {
            admission: admission.clone(),
            status,
        };
        self.save_with(
            journal,
            vec![
                crate::checkpoint::Update::put("peer_receipt", &admission.artifact, &receipt)?,
                crate::checkpoint::Update::Remove {
                    kind: "peer_pending",
                    key: format!("{:020}", admission.ordinal),
                },
            ],
        )
        .map_err(String::from)
    }
    pub(in crate::jobs) fn finish_peer(
        &self,
        journal: &mut Journal,
        id: u64,
    ) -> Result<Vec<crate::checkpoint::Update>, String> {
        let record = journal
            .records
            .get(&id)
            .ok_or("peer conversion job missing")?;
        let Input::Peer {
            question,
            artifact,
            peer,
            certificate,
        } = &record.input
        else {
            return Ok(Vec::new());
        };
        let mut receipt = self
            .checkpoint
            .get::<PeerReceipt>(
                "peer_receipt",
                artifact,
                crate::resources::limits().closure_bytes,
            )?
            .ok_or("peer conversion admission receipt missing")?;
        if matches!(
            receipt.status,
            PeerStatus::Learned { .. } | PeerStatus::Unsupported { .. }
        ) {
            return Ok(Vec::new());
        }
        if receipt.admission.peer != *peer || receipt.admission.question.as_ref() != Some(question)
        {
            return Err("peer conversion origin differs".into());
        }
        let mut sample = None;
        let mut seen = None;
        let mut status = PeerStatus::Unsupported {
            reason: record
                .failure
                .clone()
                .unwrap_or_else(|| "native reconstruction unavailable".into()),
        };
        if let Some(Output::Native {
            solution,
            diagnostic,
        }) = &record.result
        {
            status = PeerStatus::Unsupported {
                reason: diagnostic.clone(),
            };
            if let Some(solution) = solution
                && !solution.refuted
            {
                let checked = solution.checked()?;
                if crate::hex(checked.proof_id().as_bytes()) != solution.proof_id
                    || !crate::learning::peer::matches_artifact(
                        &solution.proof_id,
                        artifact,
                        certificate,
                    )?
                {
                    return Err("peer reconstructed proof checker identity differs".into());
                }
                let extracted = crate::learning::peer::extract(question, artifact, certificate)?;
                if crate::learning::digest(&extracted.tree)
                    != crate::learning::digest(&solution.tree)
                {
                    return Err("peer replay did not extract the admitted native DAG".into());
                }
                let example = crate::learning::Example {
                    origin: crate::learning::Origin::Peer {
                        artifact: artifact.clone(),
                        peer: peer.clone(),
                    },
                    job: id,
                    question: question.clone(),
                    proof_id: solution.proof_id.clone(),
                    refuted: false,
                    tree: solution.tree.clone(),
                };
                let learning = journal
                    .learning
                    .as_mut()
                    .ok_or("peer learning state missing")?;
                let q = naome_authoring::CompiledQuestion::compile(question)
                    .map_err(|e| e.to_string())?;
                let key = crate::hex(q.resolution_id());
                let unique = self.checkpoint.get::<u64>("sample", &key, 64)?.is_none();
                let unseen = self
                    .checkpoint
                    .get::<u64>("replay_seen", &solution.proof_id, 64)?
                    .is_none();
                if unseen {
                    seen = Some(crate::checkpoint::Update::put(
                        "replay_seen",
                        &solution.proof_id,
                        &id,
                    )?);
                }
                if unseen && learning.consider(example, unique)? {
                    if unique {
                        sample = Some(crate::checkpoint::Update::put("sample", key, &id)?);
                    }
                    status = PeerStatus::Learned {
                        conversion_job: id,
                        trace_proof: solution.proof_id.clone(),
                    };
                } else {
                    status = PeerStatus::Unsupported {
                        reason: "duplicate or no supported ambiguous decisions".into(),
                    };
                }
            }
        }
        crate::network::emit(
            serde_json::json!({"event":"native_peer_replay","artifact":artifact,"peer":peer,"conversion_job":id,"status":status}),
        );
        receipt.status = status;
        let mut updates = vec![
            crate::checkpoint::Update::put("peer_receipt", artifact, &receipt)?,
            crate::checkpoint::Update::Remove {
                kind: "peer_pending",
                key: format!("{:020}", receipt.admission.ordinal),
            },
        ];
        updates.extend(sample);
        updates.extend(seen);
        Ok(updates)
    }
    pub(in crate::jobs) fn model_io(
        &mut self,
        journal: &mut Journal,
        id: u64,
        unit: u32,
        blob: &crate::learning::Blob,
        range: std::ops::Range<usize>,
        bytes: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, crate::Error> {
        let length = blob.range_len(&range)?;
        let record = journal
            .records
            .get_mut(&id)
            .ok_or("native model original job missing")?;
        if record.state != State::Running
            || unit != record.checkpoint + 1
            || unit > record.reserved_units
            || record.provider != crate::learning::PROVIDER
        {
            return Err("native model IO lacks original reservation".into());
        }
        let previous_native = record.native.clone();
        let native = record
            .native
            .as_mut()
            .ok_or("native model original snapshot missing")?;
        let reading = bytes.is_none();
        if !reading && !native.training {
            return Err("native checkpoint writes require the reserved training role".into());
        }
        if reading && !native.allows_read(blob) {
            return Err("native model read outside immutable owned snapshots".into());
        }
        let count = native
            .io_bytes
            .checked_add(length)
            .ok_or("native model IO overflow")?;
        let operations = native
            .io_operations
            .checked_add(range.len())
            .ok_or("native model IO operations overflow")?;
        if count > crate::resources::limits().native_model_io_bytes
            || operations
                > crate::resources::limits().native_model_io_bytes
                    / crate::resources::limits().native_model_chunk_bytes
                    * 2
        {
            return Err("native model lifetime IO allowance exhausted".into());
        }
        let mut updates = Vec::new();
        let output = if let Some(bytes) = bytes {
            if bytes.len() != length {
                return Err("native model chunk length differs".into());
            }
            let new = !native
                .written
                .iter()
                .any(|(owner, known)| *owner == unit && known == blob);
            if new && native.written.len() >= 2 * (crate::learning::TRAINING_UNITS as usize + 2) {
                return Err("native model artifact count exhausted".into());
            }
            for (index, part) in
                range.zip(bytes.chunks(crate::resources::limits().native_model_chunk_bytes))
            {
                let key = blob.key(index);
                if let Some(previous) = self.checkpoint.get_bytes(
                    "model",
                    &key,
                    crate::resources::limits().native_model_chunk_bytes,
                )? {
                    if previous != part {
                        return Err("native model immutable chunk differs".into());
                    }
                } else {
                    updates.push(crate::checkpoint::Update::Put {
                        kind: "model",
                        key,
                        payload: part.to_vec(),
                    });
                }
            }
            if new {
                native.written.push((unit, blob.clone()));
            }
            Vec::new()
        } else {
            let mut bytes = Vec::with_capacity(length);
            for index in range {
                let part = self
                    .checkpoint
                    .get_bytes(
                        "model",
                        &blob.key(index),
                        crate::resources::limits().native_model_chunk_bytes,
                    )?
                    .ok_or("native model chunk missing")?;
                if part.len() != blob.chunk_len(index)? {
                    return Err("native model retained chunk length differs".into());
                }
                bytes.extend_from_slice(&part);
            }
            bytes
        };
        if reading && output.len() != length {
            return Err("native model retained chunk length differs".into());
        }
        native.io_bytes = count;
        native.io_operations = operations;
        if let Err(error) = self.save_with(journal, updates) {
            if error.retryable() {
                journal
                    .records
                    .get_mut(&id)
                    .expect("owned model IO job")
                    .native = previous_native;
            }
            return Err(error);
        }
        Ok(output)
    }
    pub(super) fn verify_blob(&mut self, blob: &crate::learning::Blob) -> Result<(), String> {
        blob.validate()?;
        if self.verified_models.contains(&blob.sha256) {
            return Ok(());
        }
        let mut digest = Sha256::new();
        for index in 0..blob.chunks() {
            let bytes = self
                .checkpoint
                .get_bytes(
                    "model",
                    &blob.key(index),
                    crate::resources::limits().native_model_chunk_bytes,
                )?
                .ok_or("native model checkpoint chunk missing")?;
            if bytes.len() != blob.chunk_len(index)? {
                return Err("native model checkpoint length differs".into());
            }
            digest.update(&bytes);
        }
        if crate::hex(&digest.finalize()) != blob.sha256 {
            return Err("native model checkpoint content differs".into());
        }
        if self.verified_models.len() >= 64 {
            self.verified_models.pop_first();
        }
        self.verified_models.insert(blob.sha256.clone());
        Ok(())
    }
    pub(in crate::jobs) fn verify_models(
        &mut self,
        native: &crate::learning::Job,
    ) -> Result<(), String> {
        for blob in native.blobs() {
            let inherited = native.base.blobs().any(|known| known == blob);
            if !inherited
                && !native.written.iter().any(|(unit, known)| {
                    *unit <= native.progress.as_ref().map_or(0, |p| p.unit) && known == blob
                })
            {
                return Err("native model checkpoint lacks an owned artifact receipt".into());
            }
            self.verify_blob(blob)?;
        }
        Ok(())
    }
    pub(super) fn record_model_refs(record: &Record) -> Vec<crate::learning::Blob> {
        if record.acknowledged {
            return Vec::new();
        }
        let Some(native) = &record.native else {
            return Vec::new();
        };
        let mut refs: Vec<_> = native.blobs().into_iter().cloned().collect();
        if !record.state.terminal() {
            for (unit, blob) in &native.written {
                if *unit > record.checkpoint {
                    refs.push(blob.clone());
                }
            }
        }
        refs.sort();
        refs.dedup();
        refs
    }
    pub(super) fn update_model_refs(
        &self,
        updates: &mut Vec<crate::checkpoint::Update>,
        owner: &str,
        mut refs: Vec<crate::learning::Blob>,
    ) -> Result<(), String> {
        refs.sort();
        refs.dedup();
        let old = self
            .checkpoint
            .get::<Vec<crate::learning::Blob>>(
                "model_owner",
                owner,
                crate::resources::limits().closure_bytes,
            )?
            .unwrap_or_default();
        if old == refs {
            return Ok(());
        }
        for blob in &old {
            if !refs.contains(blob) {
                updates.push(crate::checkpoint::Update::Remove {
                    kind: "model_use",
                    key: format!("{}:{owner}", blob.sha256),
                });
                updates.push(crate::checkpoint::Update::put(
                    "model_gc",
                    &blob.sha256,
                    blob,
                )?);
            }
        }
        for blob in &refs {
            if !old.contains(blob) {
                blob.validate()?;
                updates.push(crate::checkpoint::Update::put(
                    "model_use",
                    format!("{}:{owner}", blob.sha256),
                    blob,
                )?);
            }
        }
        if refs.is_empty() {
            updates.push(crate::checkpoint::Update::Remove {
                kind: "model_owner",
                key: owner.to_owned(),
            });
        } else {
            updates.push(crate::checkpoint::Update::put("model_owner", owner, &refs)?);
        }
        Ok(())
    }
    pub(in crate::jobs) fn collect_models(
        &mut self,
        journal: &mut Journal,
    ) -> Result<(), crate::Error> {
        let rows = self.checkpoint.page("model_gc", None, 1, 4096)?;
        let Some((hash, payload)) = rows.into_iter().next() else {
            return Ok(());
        };
        let blob: crate::learning::Blob = crate::checkpoint::decode(&payload)?;
        blob.validate()?;
        if blob.sha256 != hash {
            return Err("native model reclamation identity differs".into());
        }
        let uses = self
            .checkpoint
            .page("model_use", Some(&format!("{hash}:")), 1, 4096)?;
        let live = uses
            .first()
            .is_some_and(|(key, _)| key.starts_with(&format!("{hash}:")));
        let mut updates = vec![crate::checkpoint::Update::Remove {
            kind: "model_gc",
            key: hash.clone(),
        }];
        if !live {
            for index in 0..blob.chunks() {
                updates.push(crate::checkpoint::Update::Remove {
                    kind: "model",
                    key: blob.key(index),
                });
            }
            self.verified_models.remove(&hash);
        }
        self.save_with(journal, updates)
    }
    pub(in crate::jobs) fn accept_learning(
        &mut self,
        journal: &mut Journal,
        id: u64,
        root: &str,
    ) -> Result<(), String> {
        crate::object::id_bytes(root)?;
        if let Some(previous) = self
            .checkpoint
            .get::<String>("learned", &id.to_string(), 256)?
        {
            return if previous == root {
                Ok(())
            } else {
                Err("owned learning receipt differs".into())
            };
        }
        let mut record = journal
            .records
            .get(&id)
            .cloned()
            .or(self
                .checkpoint
                .get("record", &id.to_string(), crate::checkpoint::MAX_ROW)?)
            .ok_or("owned learning result missing")?;
        if record.state != State::Complete {
            return Err("learning result is not complete".into());
        }
        let Some(Output::Native {
            solution: Some(solution),
            ..
        }) = &record.result
        else {
            self.acknowledge(journal, id)?;
            return Ok(());
        };
        if crate::hex(crate::object::proof_address(&solution.proof_id)?.as_bytes()) != root {
            return Err("accepted native proof identity differs".into());
        }
        let Input::Solve { question } = &record.input else {
            return Err("learning source role differs".into());
        };
        let compiled = solution.checked()?;
        if crate::hex(compiled.artifact_id().as_bytes()) != root {
            return Err("accepted source checker identity differs".into());
        }
        let example = crate::learning::Example {
            origin: crate::learning::Origin::Local,
            job: id,
            question: question.clone(),
            proof_id: solution.proof_id.clone(),
            refuted: solution.refuted,
            tree: solution.tree.clone(),
        };
        let mut learning = journal
            .learning
            .clone()
            .ok_or("native learning owner state absent")?;
        let key = crate::hex(
            naome_authoring::CompiledQuestion::compile(question)
                .map_err(|e| e.to_string())?
                .resolution_id(),
        );
        let unique = self.checkpoint.get::<u64>("sample", &key, 64)?.is_none();
        let unseen = self
            .checkpoint
            .get::<u64>("replay_seen", &solution.proof_id, 64)?
            .is_none();
        let sampled = unseen && learning.consider(example, unique)?;
        learning.compact()?;
        record.acknowledged = true;
        let request = super::request_key(&record.input, &record.binding, record.settings);
        let mut updates = vec![
            crate::checkpoint::Update::put("learning", "current", &Some(&learning))?,
            crate::checkpoint::Update::put("learned", id, &root)?,
            crate::checkpoint::Update::put("record", id, &record)?,
        ];
        if unseen {
            updates.push(crate::checkpoint::Update::put(
                "replay_seen",
                &solution.proof_id,
                &id,
            )?);
        }
        if sampled && unique {
            updates.push(crate::checkpoint::Update::put("sample", key, &id)?);
        }
        if self.checkpoint.get::<u64>("request", &request, 64)? == Some(id) {
            updates.push(crate::checkpoint::Update::Remove {
                kind: "request",
                key: request,
            });
        }
        self.update_model_refs(&mut updates, &format!("job{id}"), Vec::new())?;
        self.checkpoint
            .commit(&journal.header(), updates)
            .map_err(crate::Error::from)?;
        journal.learning = Some(learning);
        self.learning_hash = crate::learning::digest(&journal.learning);
        if let Some(current) = journal.records.get_mut(&id) {
            *current = record;
        }
        Ok(())
    }
}
