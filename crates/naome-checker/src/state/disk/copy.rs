use super::{
    DiskArtifactState, StatementId, decode_root, decode_statement_record, formula_address, maps,
    statement_id,
};
use crate::context::{ContextError, ContextStorage};
use crate::state::disk_map::{DiskMap, MAX_NODE_BYTES, Walk};
use std::sync::Arc;

/// Limits actual authenticated record visits and raw bytes read in one step.
/// A node visit reserves its fixed maximum before reading; formulas reserve
/// their authenticated length. A formula is one atomic record, at most the
/// existing CHECKER_MAX_FORMULA_WORK_BYTES. The budget must accommodate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskCopyBudget {
    pub records: usize,
    pub bytes: usize,
}

/// Work performed by this step, including branch-only and repeated index
/// visits. Formula records contribute to records/bytes, but not node_visits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiskCopyProgress {
    pub records: usize,
    pub node_visits: usize,
    pub bytes: usize,
    pub complete: bool,
}

impl DiskCopyProgress {
    pub(crate) fn fits(&self, budget: DiskCopyBudget, bytes: usize) -> bool {
        self.records < budget.records && bytes <= budget.bytes.saturating_sub(self.bytes)
    }

    pub(crate) fn node(&mut self, bytes: usize) {
        self.records += 1;
        self.node_visits += 1;
        self.bytes += bytes;
    }
}

/// A live checked context's authenticated, resumable copy. The cursor holds
/// two depth-bounded DFS stacks at most, and one pending formula descriptor.
/// No persisted root or caller-supplied address set can complete this cursor.
#[must_use]
pub struct DiskArtifactCopy {
    source: DiskArtifactState,
    target: Arc<dyn ContextStorage>,
    phase: usize,
    walk: Option<Walk>,
    nested: Option<Walk>,
    formula: Option<(StatementId, [u8; 32], usize)>,
    failed: bool,
}

impl DiskArtifactState {
    /// Start copying the exact live roots. Callers that later finish against
    /// newer roots must mirror every subsequent successful immutable write to
    /// the target and exclude deltas prepared before that mirror was attached.
    /// Byte storage still grants no mathematical validity.
    pub fn begin_copy(&self, target: Arc<dyn ContextStorage>) -> DiskArtifactCopy {
        DiskArtifactCopy {
            source: self.clone(),
            target,
            phase: 0,
            walk: None,
            nested: None,
            formula: None,
            failed: false,
        }
    }
}

impl DiskArtifactCopy {
    pub fn complete(&self) -> bool {
        !self.failed && self.phase == 13 && self.nested.is_none() && self.formula.is_none()
    }

    /// Yield after a bounded number of actual reads, including all nine maps,
    /// statement formulas and all three nested bucket families. A too-small
    /// fresh budget fails rather than silently skipping an oversized record.
    pub fn advance(&mut self, budget: DiskCopyBudget) -> Result<DiskCopyProgress, ContextError> {
        let result = self.advance_inner(budget);
        if result.is_err() {
            self.failed = true;
        }
        self.source.report(result)
    }

    fn advance_inner(&mut self, budget: DiskCopyBudget) -> Result<DiskCopyProgress, ContextError> {
        if self.failed {
            return Err(ContextError::Corrupt);
        }
        if budget.records == 0 || budget.bytes < MAX_NODE_BYTES {
            return Err(ContextError::Limit);
        }
        let mut work = DiskCopyProgress::default();
        loop {
            if let Some((id, address, length)) = self.formula {
                if length > budget.bytes {
                    return Err(ContextError::Limit);
                }
                if !work.fits(budget, length) {
                    break;
                }
                let bytes = self.source.statements.storage().read(address, length)?;
                if bytes.len() != length
                    || formula_address(&bytes) != address
                    || statement_id(&bytes) != id
                {
                    return Err(ContextError::Corrupt);
                }
                self.target.write(address, &bytes)?;
                work.records += 1;
                work.bytes += bytes.len();
                self.formula = None;
                continue;
            }
            if let Some(nested) = &mut self.nested {
                if nested.complete() {
                    self.nested = None;
                    continue;
                }
                if !work.fits(budget, MAX_NODE_BYTES) {
                    break;
                }
                let visit = nested.step()?.ok_or(ContextError::Corrupt)?;
                self.target.write(visit.address, &visit.bytes)?;
                work.node(visit.bytes.len());
                continue;
            }
            if self.phase == 13 {
                break;
            }
            if self.walk.is_none() {
                self.walk = Some(self.phase_map().walk());
            }
            let walk = self.walk.as_mut().expect("active copy phase");
            if walk.complete() {
                self.walk = None;
                self.phase += 1;
                continue;
            }
            if !work.fits(budget, MAX_NODE_BYTES) {
                break;
            }
            let visit = walk.step()?.ok_or(ContextError::Corrupt)?;
            if self.phase < 9 {
                self.target.write(visit.address, &visit.bytes)?;
            }
            work.node(visit.bytes.len());
            if let Some((key, record)) = visit.entry {
                if self.phase == 9 {
                    let (address, length) = decode_statement_record(&record)?;
                    if length == 0 {
                        if naome_proof::program::graph_statement_id(address).as_bytes() != &key
                            || !self.source.program_nodes.contains_key(&address)?
                        {
                            return Err(ContextError::Corrupt);
                        }
                    } else {
                        self.formula = Some((StatementId::from_bytes(key), address, length));
                    }
                } else if self.phase > 9 {
                    let root = decode_root(Some(&record))?;
                    self.nested = Some(DiskMap::from_root(self.phase_map().storage(), root).walk());
                }
            }
        }
        work.complete = self.complete();
        Ok(work)
    }

    fn phase_map(&self) -> &DiskMap {
        match self.phase {
            0..=8 => maps(&self.source)[self.phase],
            9 => &self.source.statements,
            10 => &self.source.outgoing,
            11 => &self.source.deductions,
            12 => &self.source.instances,
            _ => unreachable!("completed copy has no next map"),
        }
    }

    /// Consume a fully exhausted cursor and bind only roots of an already
    /// checked, live context from the same source storage. The owner must hold
    /// its write gate through target COMMIT and publication. This constant-size
    /// rebind does not read records, reconstruct roots, or restore persisted
    /// validity. Later mirrored writes are an availability obligation of that
    /// owner, just as successful writes are for synchronous copy_to.
    pub fn finish(self, current: &DiskArtifactState) -> Result<DiskArtifactState, ContextError> {
        let result = (|| {
            if !self.complete() {
                return Err(ContextError::Storage("checked copy is incomplete".into()));
            }
            for (source, current) in maps(&self.source).into_iter().zip(maps(current)) {
                if !Arc::ptr_eq(&source.storage(), &current.storage()) {
                    return Err(ContextError::Corrupt);
                }
            }
            let [
                proofs,
                derivations,
                statements,
                artifacts,
                witnesses,
                outgoing,
                deductions,
                instances,
                program_nodes,
            ] = maps(current).map(|map| DiskMap::from_root(self.target.clone(), map.root()));
            Ok(DiskArtifactState {
                read_cache: current.read_cache,
                proofs,
                derivations,
                statements,
                artifacts,
                witnesses,
                outgoing,
                deductions,
                instances,
                program_nodes,
            })
        })();
        self.source.report(result)
    }
}

#[cfg(test)]
mod tests;
