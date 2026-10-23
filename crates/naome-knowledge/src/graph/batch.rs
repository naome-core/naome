use super::*;
use naome_authoring::CompiledQuestion;

/// A complete checked delta, prepared without publishing staged knowledge.
pub(crate) struct CheckedBatch {
    context: DiskArtifactState,
    entries: Vec<(ProofId, crate::object::BinaryProof)>,
    base_snapshot: [u8; 32],
    storage: Arc<CheckedStorage>,
    copy_epoch: u64,
    context_bytes: usize,
}

impl Graph {
    /// Check returned native sources in one bounded temporary context, then
    /// require the exact root and its complete actual cited closure. No helper
    /// is published or persisted before the final checked batch commit.
    pub(crate) fn prepare_generated(
        &self,
        source: &str,
        helpers: &[String],
        question: &CompiledQuestion,
    ) -> Result<(ProofId, CheckedBatch), String> {
        self.ensure_live()?;
        // Capture before helper preparation can write immutable staged nodes.
        // The shared batch path must never refresh this token after a copy starts.
        let copy_epoch = self.cold(self.checked_storage.copy_epoch())?;
        if source.len() > crate::resources::limits().proof_bytes
            || helpers.len() >= crate::resources::limits().closure_objects
            || helpers
                .iter()
                .any(|s| s.len() > crate::resources::limits().proof_bytes)
            || source.len() + helpers.iter().map(String::len).sum::<usize>()
                > crate::resources::limits().closure_bytes
        {
            return Err("generated closure source capacity".into());
        }
        let mut context = self.context.clone();
        let mut records = BTreeMap::new();
        let mut entries = Vec::new();
        let mut steps = 0usize;
        let mut bytes = 0usize;
        let mut context_bytes = self.context_bytes;
        let mut root = None;
        // Compilation returns a sealed CheckedProof. Keep that result rather
        // than converting it to transport syntax and invoking Checker again.
        for source in helpers
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(source))
        {
            let checked = self.compile_source(source, &context)?.into_checked_proof();
            let record = crate::object::BinaryProof::from_checked(&checked)?;
            let id = record.id;
            steps = steps
                .checked_add(checked.normal_form().certificate().steps().len())
                .ok_or("generated checker work overflow")?;
            bytes = bytes
                .checked_add(record.bytes.len())
                .ok_or("generated closure byte overflow")?;
            if steps > crate::resources::limits().closure_steps
                || bytes > crate::resources::limits().closure_bytes
            {
                return Err("generated closure checker work capacity".into());
            }
            if self.contains(id)? || records.contains_key(&id) {
                return Err("duplicate generated object".into());
            }
            if !self.cold(
                context
                    .contains_statement(checked.statement_id())
                    .map_err(|e| e.to_string()),
            )? {
                context_bytes = context_bytes
                    .checked_add(
                        checked
                            .conclusion()
                            .encode_canonical()
                            .map_err(|e| e.to_string())?
                            .len(),
                    )
                    .ok_or("checked context capacity")?;
            }
            root = Some(id);
            // The final compilation is the root. All helpers must belong to
            // its actual cited closure; no unrelated checked helper is admitted.
            if entries.len() == helpers.len() {
                question
                    .classify_checked_proof(&checked)
                    .map_err(|e| e.to_string())?;
            }
            self.cold(
                context
                    .register_proof_for_replication(checked)
                    .map_err(|e| e.to_string()),
            )?;
            records.insert(id, record.dependencies.clone());
            entries.push((id, record));
        }
        let root = root.ok_or("missing generated root")?;
        let mut reachable = BTreeSet::new();
        let mut queue = vec![root];
        while let Some(id) = queue.pop() {
            if !reachable.insert(id) {
                continue;
            }
            for dependency in records.get(&id).ok_or("missing generated dependency")? {
                if !self.contains(*dependency)? {
                    queue.push(*dependency);
                }
            }
        }
        if reachable.len() != records.len() {
            return Err("unrequested staged object".into());
        }
        Ok((
            root,
            CheckedBatch {
                context,
                entries,
                base_snapshot: self.context.snapshot_id(),
                storage: self.checked_storage.clone(),
                copy_epoch,
                context_bytes,
            },
        ))
    }

    pub(crate) fn batch_current(&self, batch: &CheckedBatch) -> Result<bool, String> {
        self.ensure_live()?;
        Ok(batch.base_snapshot == self.context.snapshot_id()
            && Arc::ptr_eq(&batch.storage, &self.checked_storage)
            && batch.copy_epoch == self.cold(self.checked_storage.copy_epoch())?)
    }
    #[cfg(test)]
    pub(crate) fn test_batch_cut(&self, cut: crate::store::BatchCut) {
        self.store.set_cut(cut);
    }
    pub(crate) fn prepare_batch(
        &self,
        root: ProofId,
        candidates: BTreeMap<ProofId, Candidate>,
        question: &CompiledQuestion,
    ) -> Result<CheckedBatch, String> {
        self.ensure_live()?;
        let copy_epoch = self.cold(self.checked_storage.copy_epoch())?;
        self.prepare_batch_at_epoch(root, candidates, question, copy_epoch)
    }

    fn prepare_batch_at_epoch(
        &self,
        root: ProofId,
        mut candidates: BTreeMap<ProofId, Candidate>,
        question: &CompiledQuestion,
        copy_epoch: u64,
    ) -> Result<CheckedBatch, String> {
        self.ensure_live()?;
        if candidates.is_empty() || candidates.len() > crate::resources::limits().closure_objects {
            return Err("checked batch operation capacity".into());
        }
        if !candidates.contains_key(&root) {
            return Err("missing staged root".into());
        }
        let mut reachable = BTreeSet::new();
        let mut queue = vec![root];
        while let Some(id) = queue.pop() {
            if !reachable.insert(id) {
                continue;
            }
            let candidate = candidates.get(&id).ok_or("missing committed dependency")?;
            for dependency in &candidate.dependencies {
                if !self.contains(*dependency)? {
                    queue.push(*dependency);
                }
            }
        }
        if reachable.len() != candidates.len() {
            return Err("unrequested staged object".into());
        }
        let mut context = self.context.clone();
        let mut bytes = self.bytes;
        let mut context_bytes = self.context_bytes;
        let mut entries = Vec::new();
        while !candidates.is_empty() {
            let mut ready = Vec::new();
            for (id, candidate) in &candidates {
                let mut complete = true;
                for dependency in &candidate.dependencies {
                    if !self.cold(
                        context
                            .contains_proof(*dependency)
                            .map_err(|e| e.to_string()),
                    )? {
                        complete = false;
                        break;
                    }
                }
                if complete {
                    ready.push(*id);
                }
            }
            if ready.is_empty() {
                return Err("missing or cyclic committed dependency closure".into());
            }
            for id in ready {
                let candidate = candidates.remove(&id).expect("selected staged object");
                if self.contains(id)? {
                    return Err("stale staged object already stored".into());
                }
                bytes = bytes
                    .checked_add(candidate.bytes.len())
                    .ok_or("accepted byte overflow")?;
                let record = candidate.record();
                let checked = self.check_normal(candidate.normal, &context)?;
                if checked.proof_id() != id || checked.statement_id() != candidate.statement {
                    return Err("checked identity mismatch".into());
                }
                if id == root {
                    question
                        .classify_checked_proof(&checked)
                        .map_err(|error| error.to_string())?;
                }
                if !self.cold(
                    context
                        .contains_statement(checked.statement_id())
                        .map_err(|e| e.to_string()),
                )? {
                    context_bytes = context_bytes
                        .checked_add(
                            checked
                                .conclusion()
                                .encode_canonical()
                                .map_err(|error| error.to_string())?
                                .len(),
                        )
                        .ok_or("checked context capacity")?;
                }
                self.cold(
                    context
                        .register_proof_for_replication(checked)
                        .map_err(|error| error.to_string()),
                )?;
                entries.push((id, record));
            }
        }
        Ok(CheckedBatch {
            context,
            entries,
            base_snapshot: self.context.snapshot_id(),
            storage: self.checked_storage.clone(),
            copy_epoch,
            context_bytes,
        })
    }

    /// Commit a prepared delta against its exact checked base, then publish
    /// only infallible roots/scalars. No caller can apply an uncommitted batch.
    pub(crate) fn commit_batch(
        &mut self,
        root: ProofId,
        batch: CheckedBatch,
        deadline: Instant,
    ) -> Result<Vec<ProofId>, String> {
        self.ensure_live()?;
        self.publication_current()?;
        if batch.base_snapshot != self.context.snapshot_id() {
            return Err("stale checked batch context".into());
        }
        if !Arc::ptr_eq(&batch.storage, &self.checked_storage) {
            return Err("checked batch storage generation changed".into());
        }
        let storage = self.checked_storage.clone();
        let gate = self.cold(storage.write_gate())?;
        self.ensure_live()?;
        if batch.copy_epoch != gate.epoch() {
            return Err("checked batch storage generation changed".into());
        }
        let admitted: Vec<_> = batch.entries.iter().map(|(id, _)| *id).collect();
        let result = self.store.persist_binary_batch(
            root,
            batch.entries.iter().map(|(_, object)| object),
            self.fixed_summary(),
            Some(deadline),
            crate::corpus::root(
                self.count
                    .checked_add(batch.entries.len())
                    .ok_or("accepted count overflow")?,
                batch.context.proof_set_fingerprint(),
            )?,
            self.commit_guard.as_ref(),
        );
        let summary = match result {
            Err(error) if error == crate::store::COMMIT_DEADLINE_ERROR => return Err(error),
            other => self.cold(other)?,
        };
        self.context = batch.context;
        self.context_bytes = batch.context_bytes;
        self.bytes = summary.bytes;
        self.count = summary.count;
        self.root = summary.root;
        for id in &admitted {
            self.pending.remove(id);
        }
        drop(gate);
        Ok(admitted)
    }
}
