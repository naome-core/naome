use super::*;
use naome_authoring::CompiledQuestion;

/// A complete checked delta, prepared without publishing staged knowledge.
pub(crate) struct CheckedBatch {
    context: DiskArtifactState,
    entries: Vec<(ProofId, Envelope)>,
    base_snapshot: [u8; 32],
    storage: Arc<CheckedStorage>,
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
        if source.len() > crate::MAX_PROOF_BYTES
            || helpers.len() >= crate::intake::MAX_CLOSURE_OBJECTS
            || helpers.iter().any(|s| s.len() > crate::MAX_PROOF_BYTES)
            || source.len() + helpers.iter().map(String::len).sum::<usize>()
                > crate::intake::MAX_CLOSURE_BYTES
        {
            return Err("generated closure source capacity".into());
        }
        let mut context = self.context.clone();
        let mut candidates = BTreeMap::new();
        // Providers return helpers in dependency order. Reject one incomplete
        // source rather than repeatedly reparsing an unresolved batch.
        let mut steps = 0usize;
        let mut bytes = 0usize;
        for source in helpers {
            let compiled = self.compile_source(source, &context)?;
            let candidate = Envelope::from_compiled(compiled).prepare()?;
            steps = steps
                .checked_add(candidate.normal.certificate().steps().len())
                .ok_or("generated checker work overflow")?;
            bytes = bytes
                .checked_add(candidate.envelope.proof.len() / 2)
                .ok_or("generated closure byte overflow")?;
            if steps > crate::intake::MAX_CLOSURE_STEPS || bytes > crate::intake::MAX_CLOSURE_BYTES
            {
                return Err("generated closure checker work capacity".into());
            }
            let checked =
                self.check_normal(candidate.envelope.clone().prepare()?.normal, &context)?;
            context
                .register_proof_for_replication(checked)
                .map_err(|e| e.to_string())?;
            if self.contains(candidate.id)? || candidates.insert(candidate.id, candidate).is_some()
            {
                return Err("duplicate generated helper".into());
            }
        }
        let root = Envelope::from_compiled(self.compile_source(source, &context)?).prepare()?;
        let id = root.id;
        if self.contains(id)? || candidates.insert(id, root).is_some() {
            return Err("duplicate generated root".into());
        }
        drop(context);
        let steps = candidates
            .values()
            .map(|c| c.normal.certificate().steps().len())
            .sum::<usize>();
        let bytes = candidates
            .values()
            .map(|c| c.envelope.proof.len() / 2)
            .sum::<usize>();
        if steps > crate::intake::MAX_CLOSURE_STEPS || bytes > crate::intake::MAX_CLOSURE_BYTES {
            return Err("generated closure checker work capacity".into());
        }
        self.prepare_batch(id, candidates, question)
            .map(|batch| (id, batch))
    }
    #[cfg(test)]
    pub(crate) fn test_batch_cut(&self, cut: crate::store::BatchCut) {
        self.store.set_cut(cut);
    }
    pub(crate) fn prepare_batch(
        &self,
        root: ProofId,
        mut candidates: BTreeMap<ProofId, Candidate>,
        question: &CompiledQuestion,
    ) -> Result<CheckedBatch, String> {
        self.ensure_live()?;
        if candidates.is_empty() || candidates.len() > crate::intake::MAX_CLOSURE_OBJECTS {
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
                let mut depth = 0usize;
                for dependency in &candidate.dependencies {
                    depth = depth.max(
                        self.cold(
                            context
                                .proof_dependency_depth(*dependency)
                                .map_err(|e| e.to_string()),
                        )?
                        .ok_or("missing checked dependency")?,
                    );
                }
                let depth = depth.checked_add(1).ok_or("dependency depth overflow")?;
                if depth > MAX_DEPTH {
                    return Err("dependency depth limit".into());
                }
                bytes = bytes
                    .checked_add(candidate.envelope.proof.len() / 2)
                    .ok_or("accepted byte overflow")?;
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
                entries.push((id, candidate.envelope));
            }
        }
        Ok(CheckedBatch {
            context,
            entries,
            base_snapshot: self.context.snapshot_id(),
            storage: self.checked_storage.clone(),
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
        if batch.base_snapshot != self.context.snapshot_id() {
            return Err("stale checked batch context".into());
        }
        if !Arc::ptr_eq(&batch.storage, &self.checked_storage) {
            return Err("checked batch storage generation changed".into());
        }
        let admitted: Vec<_> = batch.entries.iter().map(|(id, _)| *id).collect();
        let result = self.store.persist_batch_checked(
            root,
            batch.entries.iter().map(|(_, object)| object),
            self.fixed_summary(),
            Some(deadline),
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
        Ok(admitted)
    }
}
