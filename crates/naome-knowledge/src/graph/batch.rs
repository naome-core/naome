use super::*;
use naome_authoring::CompiledQuestion;

/// A complete checked delta, prepared without publishing staged knowledge.
pub(crate) struct CheckedBatch {
    pub(super) context: DiskArtifactState,
    pub(super) entries: Vec<(ProofId, crate::object::BinaryProof)>,
    pub(super) base_snapshot: [u8; 32],
    pub(super) storage: Arc<CheckedStorage>,
    pub(super) copy_epoch: u64,
    pub(super) context_bytes: usize,
    pub(super) _disk: crate::resources::DiskLease,
}

impl CheckedBatch {
    pub(super) fn from_program(
        graph: &Graph,
        context: DiskArtifactState,
        record: crate::object::BinaryProof,
        copy_epoch: u64,
        growth: usize,
        prefix: Option<CheckedBatch>,
    ) -> Result<Self, crate::Error> {
        let prior_bytes = prefix.as_ref().map_or(0, |prefix| {
            prefix
                .entries
                .iter()
                .map(|(_, entry)| entry.bytes.len())
                .sum::<usize>()
        });
        let count = prefix.as_ref().map_or(1, |prefix| prefix.entries.len() + 1);
        let disk = graph.reserve_publication(record.bytes.len() + prior_bytes, count)?;
        let context_bytes = prefix
            .as_ref()
            .map_or(graph.context_bytes, |prefix| prefix.context_bytes)
            .checked_add(growth)
            .ok_or("checked program context width")?;
        let mut entries = prefix.map_or_else(Vec::new, |prefix| prefix.entries);
        if entries.iter().any(|(id, _)| *id == record.id) {
            return Err("duplicate staged program".into());
        }
        entries.push((record.id, record));
        Ok(Self {
            context,
            entries,
            base_snapshot: graph.context.snapshot_id(),
            storage: graph.checked_storage.clone(),
            copy_epoch,
            context_bytes,
            _disk: disk,
        })
    }
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
    ) -> Result<(ProofId, CheckedBatch), crate::Error> {
        self.ensure_live()?;
        crate::resources::require_work_admission()?;
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
        let disk = self.reserve_publication(
            source.len() + helpers.iter().map(String::len).sum::<usize>(),
            helpers.len() + 1,
        )?;
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
                    .map_err(crate::Error::from),
            )? {
                context_bytes = context_bytes
                    .checked_add(
                        checked
                            .conclusion()
                            .encode_canonical()
                            .map_err(crate::Error::from)?
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
                    .map_err(crate::Error::from)?;
            }
            self.cold(
                context
                    .register_proof_for_replication(checked)
                    .map_err(crate::Error::from),
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
                _disk: disk,
            },
        ))
    }

    pub(crate) fn batch_current(&self, batch: &CheckedBatch) -> Result<bool, crate::Error> {
        self.ensure_live()?;
        Ok(batch.base_snapshot == self.context.snapshot_id()
            && Arc::ptr_eq(&batch.storage, &self.checked_storage)
            && batch.copy_epoch == self.cold(self.checked_storage.copy_epoch())?)
    }
    #[cfg(test)]
    pub(crate) fn test_batch_cut(&self, cut: crate::store::BatchCut) {
        self.store.set_cut(cut);
    }
    #[cfg(test)]
    pub(crate) fn prepare_batch(
        &self,
        root: ProofId,
        candidates: BTreeMap<ProofId, Candidate>,
        question: &CompiledQuestion,
    ) -> Result<CheckedBatch, crate::Error> {
        self.ensure_live()?;
        crate::resources::require_work_admission()?;
        let copy_epoch = self.cold(self.checked_storage.copy_epoch())?;
        self.prepare_batch_at_epoch(root, candidates, question, copy_epoch, None)
    }

    pub(crate) fn prepare_batch_after(
        &self,
        root: ProofId,
        candidates: BTreeMap<ProofId, Candidate>,
        question: &CompiledQuestion,
        prefix: Option<CheckedBatch>,
    ) -> Result<CheckedBatch, crate::Error> {
        if let Some(prefix) = &prefix
            && !self.batch_current(prefix)?
        {
            return Err(STALE_COMMIT);
        }
        let epoch = self.cold(self.checked_storage.copy_epoch())?;
        self.prepare_batch_at_epoch(root, candidates, question, epoch, prefix)
    }

    fn prepare_batch_at_epoch(
        &self,
        root: ProofId,
        mut candidates: BTreeMap<ProofId, Candidate>,
        question: &CompiledQuestion,
        copy_epoch: u64,
        prefix: Option<CheckedBatch>,
    ) -> Result<CheckedBatch, crate::Error> {
        self.ensure_live()?;
        if candidates.is_empty() || candidates.len() > crate::resources::limits().closure_objects {
            return Err("checked batch operation capacity".into());
        }
        if !candidates.contains_key(&root) {
            return Err("missing staged root".into());
        }
        let prefix_records = prefix
            .as_ref()
            .map(|prefix| {
                prefix
                    .entries
                    .iter()
                    .map(|(id, record)| (*id, record))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let mut reachable = BTreeSet::new();
        let mut queue = vec![root];
        while let Some(id) = queue.pop() {
            if !reachable.insert(id) {
                continue;
            }
            let dependencies = if let Some(candidate) = candidates.get(&id) {
                &candidate.dependencies
            } else {
                &prefix_records
                    .get(&id)
                    .ok_or("missing committed dependency")?
                    .dependencies
            };
            for dependency in dependencies {
                if !self.contains(*dependency)? {
                    queue.push(*dependency);
                }
            }
        }
        if reachable.len() != candidates.len() + prefix_records.len() {
            return Err("unrequested staged object".into());
        }
        let prefix_count = prefix.as_ref().map_or(0, |prefix| prefix.entries.len());
        if candidates.len() + prefix_count > crate::resources::limits().closure_objects {
            return Err("checked closure operation capacity".into());
        }
        let prefix_bytes = prefix.as_ref().map_or(0, |prefix| {
            prefix
                .entries
                .iter()
                .map(|(_, entry)| entry.bytes.len())
                .sum::<usize>()
        });
        let disk = self.reserve_publication(
            candidates.values().map(|c| c.bytes.len()).sum::<usize>() + prefix_bytes,
            candidates.len() + prefix_count,
        )?;
        let (mut context, mut context_bytes, mut entries) = prefix.map_or_else(
            || (self.context.clone(), self.context_bytes, Vec::new()),
            |prefix| (prefix.context, prefix.context_bytes, prefix.entries),
        );
        let mut bytes = self.bytes;
        while !candidates.is_empty() {
            let mut ready = Vec::new();
            for (id, candidate) in &candidates {
                let mut complete = true;
                for dependency in &candidate.dependencies {
                    if !self.cold(
                        context
                            .contains_proof(*dependency)
                            .map_err(crate::Error::from),
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
                        .map_err(crate::Error::from)?;
                }
                if !self.cold(
                    context
                        .contains_statement(checked.statement_id())
                        .map_err(crate::Error::from),
                )? {
                    context_bytes = context_bytes
                        .checked_add(
                            checked
                                .conclusion()
                                .encode_canonical()
                                .map_err(crate::Error::from)?
                                .len(),
                        )
                        .ok_or("checked context capacity")?;
                }
                self.cold(
                    context
                        .register_proof_for_replication(checked)
                        .map_err(crate::Error::from),
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
            _disk: disk,
        })
    }

    /// Commit a prepared delta against its exact checked base, then publish
    /// only infallible roots/scalars. No caller can apply an uncommitted batch.
    #[cfg(test)]
    pub(crate) fn commit_batch(
        &mut self,
        root: ProofId,
        batch: CheckedBatch,
        deadline: Instant,
    ) -> Result<Vec<ProofId>, crate::Error> {
        self.commit_batch_granted(root, batch, deadline, None)
    }

    pub(crate) fn commit_batch_granted(
        &mut self,
        root: ProofId,
        batch: CheckedBatch,
        deadline: Instant,
        peer: Option<PeerGrant>,
    ) -> Result<Vec<ProofId>, crate::Error> {
        self.ensure_live()?;
        self.publication_current()?;
        let guard = peer
            .map(|peer| {
                self.commit_guard
                    .clone()
                    .unwrap_or_else(|| {
                        CommitGuard::new(
                            Arc::new(std::sync::atomic::AtomicU64::new(0)),
                            0,
                            None,
                            None,
                        )
                    })
                    .with_peer(peer)
            })
            .or_else(|| self.commit_guard.clone());
        if let Some(guard) = &guard {
            guard.check()?;
        }
        batch._disk.recheck(self.store.directory())?;
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
            guard.as_ref(),
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
        for id in &admitted {
            let wake = self.backlog()?.accepted(*id);
            self.cold(wake)?;
        }
        Ok(admitted)
    }
}
