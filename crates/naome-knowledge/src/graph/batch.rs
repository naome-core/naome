use super::*;
use naome_authoring::CompiledQuestion;

/// A complete checked delta, prepared without publishing staged knowledge.
pub(crate) struct CheckedBatch {
    context: ArtifactState,
    entries: Vec<(ProofId, Envelope, usize)>,
    bytes: usize,
    context_bytes: usize,
}

impl Graph {
    #[cfg(test)]
    pub(crate) fn test_batch_cut(&self, cut: crate::store::BatchCut) {
        self.store
            .as_ref()
            .expect("durable test graph")
            .set_cut(cut);
    }
    pub(crate) fn prepare_batch(
        &self,
        root: ProofId,
        mut candidates: BTreeMap<ProofId, Candidate>,
        question: &CompiledQuestion,
    ) -> Result<CheckedBatch, String> {
        if self.storage_error.is_some() {
            return Err("storage halted".into());
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
                if !self.contains(*dependency) {
                    queue.push(*dependency);
                }
            }
        }
        if reachable.len() != candidates.len() {
            return Err("unrequested staged object".into());
        }
        let mut context = self.context.clone();
        let mut depths = self.depths.clone();
        let mut bytes = self.bytes;
        let mut context_bytes = self.context_bytes;
        let mut entries = Vec::new();
        while !candidates.is_empty() {
            let ready: Vec<_> = candidates
                .iter()
                .filter_map(|(id, candidate)| {
                    candidate
                        .dependencies
                        .iter()
                        .all(|dependency| depths.contains_key(dependency))
                        .then_some(*id)
                })
                .collect();
            if ready.is_empty() {
                return Err("missing or cyclic committed dependency closure".into());
            }
            for id in ready {
                let candidate = candidates.remove(&id).expect("selected staged object");
                if self.contains(id) {
                    return Err("stale staged object already stored".into());
                }
                let depth = candidate
                    .dependencies
                    .iter()
                    .map(|id| depths[id])
                    .max()
                    .unwrap_or(0)
                    + 1;
                if depth > MAX_DEPTH {
                    return Err("dependency depth limit".into());
                }
                bytes = bytes
                    .checked_add(candidate.envelope.proof.len() / 2)
                    .ok_or("accepted capacity")?;
                if self.objects.len() + entries.len() >= MAX_OBJECTS || bytes > MAX_ACCEPTED_BYTES {
                    return Err("accepted capacity".into());
                }
                let checked = check_normal_form_with_state(candidate.normal, &context)
                    .map_err(|error| format!("mathematically invalid: {error}"))?;
                if checked.proof_id() != id || checked.statement_id() != candidate.statement {
                    return Err("checked identity mismatch".into());
                }
                if id == root {
                    question
                        .classify_checked_proof(&checked)
                        .map_err(|error| error.to_string())?;
                }
                if !context.contains_statement(checked.statement_id()) {
                    context_bytes = context_bytes
                        .checked_add(
                            checked
                                .conclusion()
                                .encode_canonical()
                                .map_err(|error| error.to_string())?
                                .len(),
                        )
                        .ok_or("checked context capacity")?;
                    if context_bytes > MAX_CONTEXT_BYTES {
                        return Err("checked context capacity".into());
                    }
                }
                context
                    .register_proof_for_replication(checked)
                    .map_err(|error| error.to_string())?;
                depths.insert(id, depth);
                entries.push((id, candidate.envelope, depth));
            }
        }
        Ok(CheckedBatch {
            context,
            entries,
            bytes,
            context_bytes,
        })
    }

    /// All mathematical and registry preparation must precede this call.
    pub(crate) fn persist_batch(
        &mut self,
        root: ProofId,
        batch: &CheckedBatch,
    ) -> Result<(), String> {
        if let Some(store) = &self.store
            && let Err(error) =
                store.persist_batch(root, batch.entries.iter().map(|(_, object, _)| object))
        {
            self.storage_error = Some(error.clone());
            return Err(format!("storage halted: {error}"));
        }
        Ok(())
    }

    pub(crate) fn apply_batch(&mut self, batch: CheckedBatch) -> Vec<ProofId> {
        self.context = batch.context;
        self.bytes = batch.bytes;
        self.context_bytes = batch.context_bytes;
        let mut admitted = Vec::with_capacity(batch.entries.len());
        for (id, object, depth) in batch.entries {
            self.pending.remove(&id);
            self.depths.insert(id, depth);
            self.objects.insert(id, object);
            admitted.push(id);
        }
        admitted
    }
}
