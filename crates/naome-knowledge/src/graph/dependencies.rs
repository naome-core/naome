//! Disposable readiness derived from canonical dependencies; never admission authority.
use naome_proof::ArtifactId;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(crate) struct Dependencies {
    pending: BTreeMap<ArtifactId, Option<usize>>,
    dependents: BTreeMap<ArtifactId, Vec<ArtifactId>>,
    ready: BTreeSet<ArtifactId>,
    complete: BTreeSet<ArtifactId>,
    undefined: usize,
    #[cfg(test)]
    visits: usize,
}
impl Dependencies {
    pub(crate) fn declare(&mut self, id: ArtifactId) {
        if !self.complete.contains(&id) && !self.pending.contains_key(&id) {
            self.pending.insert(id, None);
            self.undefined += 1;
        }
    }
    pub(crate) fn known(&self, id: ArtifactId) -> bool {
        self.pending.contains_key(&id)
            || self.complete.contains(&id)
            || self.dependents.contains_key(&id)
    }
    pub(crate) fn is_complete(&self, id: ArtifactId) -> bool {
        self.complete.contains(&id)
    }
    pub(crate) fn add(
        &mut self,
        id: ArtifactId,
        dependencies: &BTreeSet<ArtifactId>,
    ) -> Result<(), crate::Error> {
        self.declare(id);
        let count = self
            .pending
            .get_mut(&id)
            .ok_or("already completed dependency member")?;
        if count.is_some() {
            return Err("duplicate dependency member".into());
        }
        let mut missing = 0;
        for dependency in dependencies {
            #[cfg(test)]
            {
                self.visits += 1;
            }
            if !self.complete.contains(dependency) {
                missing += 1;
                self.dependents.entry(*dependency).or_default().push(id);
            }
        }
        *count = Some(missing);
        self.undefined -= 1;
        if missing == 0 {
            self.ready.insert(id);
        }
        Ok(())
    }
    pub(crate) fn finish(&mut self, id: ArtifactId) {
        if !self.complete.insert(id) {
            return;
        }
        if matches!(self.pending.remove(&id), Some(None)) {
            self.undefined -= 1;
        }
        self.ready.remove(&id);
        for dependent in self.dependents.remove(&id).unwrap_or_default() {
            #[cfg(test)]
            {
                self.visits += 1;
            }
            if let Some(Some(count)) = self.pending.get_mut(&dependent) {
                *count -= 1;
                if *count == 0 {
                    self.ready.insert(dependent);
                }
            }
        }
    }
    pub(crate) fn next(&self, except: Option<ArtifactId>) -> Option<ArtifactId> {
        self.ready.iter().find(|id| Some(**id) != except).copied()
    }
    pub(crate) fn only_pending(&self, except: ArtifactId) -> bool {
        self.pending.len() == usize::from(self.pending.contains_key(&except))
    }
    pub(crate) fn complete(&self) -> bool {
        self.pending.is_empty()
    }
    pub(crate) fn defined(&self) -> bool {
        self.undefined == 0
    }
    #[cfg(test)]
    pub(crate) fn visits(&self) -> usize {
        self.visits
    }
}

#[cfg(test)]
mod tests;
