use super::*;
use naome_authoring::CompiledQuestion;
#[cfg(test)]
thread_local! { static DEPENDENCY_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(super) fn dependency_visits() -> usize {
    DEPENDENCY_VISITS.with(std::cell::Cell::get)
}

/// A complete checked delta, prepared without publishing staged knowledge.
pub(crate) struct CheckedBatch {
    pub(super) context: DiskArtifactState,
    pub(super) entries: Vec<(ArtifactId, crate::object::BinaryArtifact)>,
    // Bounded unpublished closure edges. Program references remain canonical
    // commands rather than duplicated persistent catalog relations.
    pub(super) edges: BTreeMap<ArtifactId, BTreeSet<ArtifactId>>,
    pub(super) stamp: Stamp,
    pub(super) context_bytes: usize,
    pub(super) _disk: crate::resources::DiskLease,
}

impl CheckedBatch {
    pub(crate) fn context(&self) -> &DiskArtifactState {
        &self.context
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
    ) -> Result<(ArtifactId, CheckedBatch), crate::Error> {
        self.ensure_live()?;
        crate::resources::require_work_admission()?;
        // Capture before helper preparation can write immutable staged nodes.
        // The shared batch path must never refresh this token after a copy starts.
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
        let mut preparation = Preparation::new(
            self,
            None,
            source.len() + helpers.iter().map(String::len).sum::<usize>(),
            helpers.len() + 1,
        )?;
        let mut steps = 0usize;
        let mut bytes = 0usize;
        let mut root = None;
        // Compilation returns a sealed CheckedProof. Keep that result rather
        // than converting it to transport syntax and invoking Checker again.
        for (position, source) in helpers
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(source))
            .enumerate()
        {
            let checked =
                CheckedArtifact::from_compiled(self.compile_source(source, preparation.context())?);
            let record = checked.record(preparation.context())?;
            let id = record.id;
            steps = steps
                .checked_add(match &checked {
                    CheckedArtifact::Proof(proof) => {
                        proof.normal_form().certificate().steps().len()
                    }
                    CheckedArtifact::Definition(_) => 1,
                })
                .ok_or("generated checker work overflow")?;
            bytes = bytes
                .checked_add(record.bytes.len())
                .ok_or("generated closure byte overflow")?;
            if steps > crate::resources::limits().closure_steps
                || bytes > crate::resources::limits().closure_bytes
            {
                return Err("generated closure checker work capacity".into());
            }
            root = Some(id);
            // The final compilation is the root. All helpers must belong to
            // its actual cited closure; no unrelated checked helper is admitted.
            if position == helpers.len() {
                question
                    .classify_checked_proof(checked.proof()?)
                    .map_err(crate::Error::from)?;
            }
            preparation.append_artifact(self, checked, record)?;
        }
        let root = root.ok_or("missing generated root")?;
        Ok((root, preparation.finish(self, root)?))
    }

    pub(crate) fn batch_current(&self, batch: &CheckedBatch) -> Result<bool, crate::Error> {
        batch.stamp.current(self)
    }
    #[cfg(test)]
    pub(crate) fn test_batch_cut(&self, cut: crate::store::BatchCut) {
        self.store.set_cut(cut);
    }
    #[cfg(test)]
    pub(crate) fn prepare_batch(
        &self,
        root: ArtifactId,
        candidates: BTreeMap<ArtifactId, Candidate>,
        question: &CompiledQuestion,
    ) -> Result<CheckedBatch, crate::Error> {
        self.ensure_live()?;
        crate::resources::require_work_admission()?;
        self.prepare_batch_after(root, candidates, question, None)
    }

    pub(crate) fn prepare_batch_after(
        &self,
        root: ArtifactId,
        mut candidates: BTreeMap<ArtifactId, Candidate>,
        question: &CompiledQuestion,
        prefix: Option<CheckedBatch>,
    ) -> Result<CheckedBatch, crate::Error> {
        self.ensure_live()?;
        if candidates.is_empty() || candidates.len() > crate::resources::limits().closure_objects {
            return Err("checked batch operation capacity".into());
        }
        if !candidates.contains_key(&root) {
            return Err("missing staged root".into());
        }
        let prefix_count = prefix.as_ref().map_or(0, |prefix| prefix.entries.len());
        if candidates.len() + prefix_count > crate::resources::limits().closure_objects {
            return Err("checked closure operation capacity".into());
        }
        preparation::require_closure(
            self,
            root,
            candidates
                .iter()
                .map(|(id, candidate)| (*id, &candidate.dependencies))
                .chain(prefix.iter().flat_map(|prefix| {
                    prefix
                        .edges
                        .iter()
                        .map(|(id, dependencies)| (*id, dependencies))
                })),
        )?;
        let mut preparation = Preparation::new(
            self,
            prefix,
            candidates
                .values()
                .map(|candidate| candidate.bytes.len())
                .sum(),
            candidates.len(),
        )?;
        // Resolve internal edges once. Only dependencies outside this batch
        // need an authenticated lookup in the fixed predecessor context.
        let mut waiting = BTreeMap::new();
        let mut dependents: BTreeMap<ArtifactId, Vec<ArtifactId>> = BTreeMap::new();
        let mut external = BTreeSet::new();
        let mut ready = BTreeSet::new();
        for (id, candidate) in &candidates {
            let mut count = 0usize;
            for dependency in &candidate.dependencies {
                #[cfg(test)]
                DEPENDENCY_VISITS.with(|count| count.set(count.get() + 1));
                if candidates.contains_key(dependency) {
                    count += 1;
                    dependents.entry(*dependency).or_default().push(*id);
                } else if external.insert(*dependency)
                    && !self.cold(
                        preparation
                            .context()
                            .contains_artifact(*dependency)
                            .map_err(crate::Error::from),
                    )?
                {
                    return Err("missing or cyclic committed dependency closure".into());
                }
            }
            waiting.insert(*id, count);
            if count == 0 {
                ready.insert(*id);
            }
        }
        while let Some(id) = ready.pop_first() {
            let candidate = candidates.remove(&id).expect("selected staged object");
            let record = candidate.record();
            let checked = self.check_artifact(candidate, preparation.context())?;
            if id == root {
                question
                    .classify_checked_proof(checked.proof()?)
                    .map_err(crate::Error::from)?;
            }
            preparation.append_artifact(self, checked, record)?;
            for dependent in dependents.remove(&id).unwrap_or_default() {
                let remaining = waiting.get_mut(&dependent).expect("batch dependency");
                *remaining -= 1;
                if *remaining == 0 {
                    ready.insert(dependent);
                }
            }
        }
        if !candidates.is_empty() {
            return Err("missing or cyclic committed dependency closure".into());
        }
        preparation.finish(self, root)
    }

    /// Check a necessary certificate helper in the canonical private builder.
    /// Its checked result cannot publish knowledge without the complete root.
    pub(crate) fn prepare_helper_after(
        &self,
        candidate: Candidate,
        prefix: Option<CheckedBatch>,
    ) -> Result<CheckedBatch, crate::Error> {
        let record = candidate.record();
        let mut preparation = Preparation::new(self, prefix, record.bytes.len(), 1)?;
        let checked = self.check_artifact(candidate, preparation.context())?;
        preparation.append_artifact(self, checked, record)?;
        Ok(preparation.into_prefix())
    }

    /// Commit a prepared delta against its exact checked base, then publish
    /// only infallible roots/scalars. No caller can apply an uncommitted batch.
    #[cfg(test)]
    pub(crate) fn commit_batch(
        &mut self,
        root: ArtifactId,
        batch: CheckedBatch,
        deadline: Instant,
    ) -> Result<Vec<ArtifactId>, crate::Error> {
        self.commit_batch_granted(root, batch, deadline, None)
    }

    pub(crate) fn commit_batch_granted(
        &mut self,
        root: ArtifactId,
        batch: CheckedBatch,
        deadline: Instant,
        peer: Option<PeerGrant>,
    ) -> Result<Vec<ArtifactId>, crate::Error> {
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
        batch.require_closure(self, root)?;
        let storage = self.checked_storage.clone();
        let gate = self.cold(storage.write_gate())?;
        batch.stamp.check_at_gate(self, gate.epoch())?;
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
                batch.context.artifact_set_fingerprint(),
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
