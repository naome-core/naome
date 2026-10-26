//! One owner for unpublished checked deltas and their exact predecessor.
//! Input adapters decide how to obtain checked results. This module owns
//! registration, growth accounting and complete staged dependency closure.
use super::*;

#[derive(Clone)]
pub(super) struct Stamp {
    snapshot: [u8; 32],
    pub(super) storage: Arc<CheckedStorage>,
    epoch: u64,
}
impl Stamp {
    pub(super) fn capture(graph: &Graph) -> Result<Self, crate::Error> {
        graph.ensure_live()?;
        Ok(Self {
            snapshot: graph.context.snapshot_id(),
            storage: graph.checked_storage.clone(),
            epoch: graph.cold(graph.checked_storage.copy_epoch())?,
        })
    }
    pub(super) fn current(&self, graph: &Graph) -> Result<bool, crate::Error> {
        graph.ensure_live()?;
        Ok(self.matches(graph, graph.cold(graph.checked_storage.copy_epoch())?))
    }
    fn matches(&self, graph: &Graph, epoch: u64) -> bool {
        self.snapshot == graph.context.snapshot_id()
            && Arc::ptr_eq(&self.storage, &graph.checked_storage)
            && self.epoch == epoch
    }
    pub(super) fn check(&self, graph: &Graph) -> Result<(), crate::Error> {
        if self.current(graph)? {
            Ok(())
        } else {
            Err(STALE_COMMIT)
        }
    }
    pub(super) fn check_at_gate(&self, graph: &Graph, epoch: u64) -> Result<(), crate::Error> {
        graph.ensure_live()?;
        if self.matches(graph, epoch) {
            Ok(())
        } else {
            Err(STALE_COMMIT)
        }
    }
}

pub(super) struct Preparation {
    batch: CheckedBatch,
    ids: BTreeSet<ArtifactId>,
}
pub(super) struct ArtifactRegistration {
    checked: CheckedArtifact,
    record: crate::object::BinaryArtifact,
    context_bytes: usize,
}
impl Preparation {
    pub(super) fn new(
        graph: &Graph,
        prefix: Option<CheckedBatch>,
        bytes: usize,
        count: usize,
    ) -> Result<Self, crate::Error> {
        graph.ensure_live()?;
        crate::resources::require_work_admission()?;
        let stamp = Stamp::capture(graph)?;
        if let Some(prefix) = &prefix {
            prefix.stamp.check(graph)?;
        }
        let prior_bytes = prefix.as_ref().map_or(0, |prefix| {
            prefix
                .entries
                .iter()
                .map(|(_, record)| record.bytes.len())
                .sum::<usize>()
        });
        let count = count
            .checked_add(prefix.as_ref().map_or(0, |prefix| prefix.entries.len()))
            .ok_or("checked batch count overflow")?;
        if count > crate::resources::limits().closure_objects {
            return Err(crate::Error::InputLimit(
                "checked closure operation capacity",
            ));
        }
        let disk = graph.reserve_publication(
            bytes
                .checked_add(prior_bytes)
                .ok_or("checked batch byte overflow")?,
            count,
        )?;
        Ok(Self::reserved(graph, prefix, stamp, disk))
    }
    pub(super) fn reserved(
        graph: &Graph,
        prefix: Option<CheckedBatch>,
        stamp: Stamp,
        disk: crate::resources::DiskLease,
    ) -> Self {
        let (context, context_bytes, entries, edges) = prefix.map_or_else(
            || {
                (
                    graph.context.clone(),
                    graph.context_bytes,
                    Vec::new(),
                    BTreeMap::new(),
                )
            },
            |prefix| {
                (
                    prefix.context,
                    prefix.context_bytes,
                    prefix.entries,
                    prefix.edges,
                )
            },
        );
        let ids = entries.iter().map(|(id, _)| *id).collect();
        Self {
            ids,
            batch: CheckedBatch {
                context,
                entries,
                edges,
                stamp,
                context_bytes,
                _disk: disk,
            },
        }
    }
    pub(super) fn context(&self) -> &DiskArtifactState {
        &self.batch.context
    }
    pub(super) fn ids(&self) -> impl Iterator<Item = ArtifactId> + '_ {
        self.ids.iter().copied()
    }
    pub(super) fn stamp(&self) -> &Stamp {
        &self.batch.stamp
    }
    fn require_absent(&self, graph: &Graph, id: ArtifactId) -> Result<(), crate::Error> {
        if graph.contains(id)? || self.ids.contains(&id) {
            return Err("duplicate staged object".into());
        }
        Ok(())
    }
    pub(super) fn append_artifact(
        &mut self,
        graph: &Graph,
        checked: CheckedArtifact,
        record: crate::object::BinaryArtifact,
    ) -> Result<(), crate::Error> {
        let registration = self.check_registration(graph, checked, record)?;
        self.register_artifact(graph, registration)
    }
    /// Reject input and reserve growth before opening a disposable write phase.
    pub(super) fn check_registration(
        &self,
        graph: &Graph,
        checked: CheckedArtifact,
        record: crate::object::BinaryArtifact,
    ) -> Result<ArtifactRegistration, crate::Error> {
        self.require_absent(graph, record.id)?;
        if checked.id() != record.id || checked.statement() != record.statement {
            return Err("checked identity mismatch".into());
        }
        let growth = graph.registration_growth(&self.batch.context, &checked)?;
        let context_bytes = self
            .batch
            .context_bytes
            .checked_add(growth)
            .ok_or("checked context capacity")?;
        Ok(ArtifactRegistration {
            checked,
            record,
            context_bytes,
        })
    }
    pub(super) fn register_artifact(
        &mut self,
        graph: &Graph,
        registration: ArtifactRegistration,
    ) -> Result<(), crate::Error> {
        let ArtifactRegistration {
            checked,
            record,
            context_bytes,
        } = registration;
        graph.cold(checked.register(&mut self.batch.context))?;
        self.batch.context_bytes = context_bytes;
        self.ids.insert(record.id);
        self.batch
            .edges
            .insert(record.id, record.dependencies.clone());
        self.batch.entries.push((record.id, record));
        Ok(())
    }
    pub(super) fn append_program(
        &mut self,
        graph: &Graph,
        context: DiskArtifactState,
        record: crate::object::BinaryArtifact,
        dependencies: BTreeSet<ArtifactId>,
        growth: usize,
    ) -> Result<(), crate::Error> {
        self.batch.stamp.check(graph)?;
        self.require_absent(graph, record.id)?;
        self.batch.context_bytes = self
            .batch
            .context_bytes
            .checked_add(growth)
            .ok_or("checked program context width")?;
        self.batch.context = context;
        self.batch.edges.insert(record.id, dependencies);
        self.ids.insert(record.id);
        self.batch.entries.push((record.id, record));
        Ok(())
    }
    /// A checked prefix may still contain helpers whose parent is not prepared.
    /// Complete reachability is required before a final batch can be published.
    pub(super) fn into_prefix(self) -> CheckedBatch {
        self.batch
    }
    pub(super) fn finish(
        self,
        graph: &Graph,
        root: ArtifactId,
    ) -> Result<CheckedBatch, crate::Error> {
        self.batch.require_closure(graph, root)?;
        Ok(self.batch)
    }
}

impl CheckedBatch {
    pub(super) fn require_closure(
        &self,
        graph: &Graph,
        root: ArtifactId,
    ) -> Result<(), crate::Error> {
        require_closure(
            graph,
            root,
            self.edges
                .iter()
                .map(|(id, dependencies)| (*id, dependencies)),
        )
    }
}

pub(super) fn require_closure<'a>(
    graph: &Graph,
    root: ArtifactId,
    entries: impl IntoIterator<Item = (ArtifactId, &'a BTreeSet<ArtifactId>)>,
) -> Result<(), crate::Error> {
    let mut records = BTreeMap::new();
    for (id, dependencies) in entries {
        if records.insert(id, dependencies).is_some() {
            return Err("duplicate staged object".into());
        }
    }
    if !records.contains_key(&root) {
        return Err("missing staged root".into());
    }
    let mut reachable = BTreeSet::new();
    let mut queue = vec![root];
    while let Some(id) = queue.pop() {
        if !reachable.insert(id) {
            continue;
        }
        for dependency in *records.get(&id).ok_or("missing staged dependency")? {
            if !graph.contains(*dependency)? {
                queue.push(*dependency);
            }
        }
    }
    if reachable.len() != records.len() {
        return Err("unrequested staged object".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
