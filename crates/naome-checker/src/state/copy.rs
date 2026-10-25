//! Bounded authenticated traversal shared by checked contexts and registries.
//! Plans own record interpretation; the cursor owns reads, writes and budgets.
use super::disk_map::{DiskMap, Lookup, MAX_NODE_BYTES, Walk};
use crate::{ContextError, ContextStorage, StatementId, statement_id};
use std::sync::Arc;

/// Limits actual authenticated record visits and raw bytes read in one step.
/// A node reserves its fixed maximum before reading. An atomic formula must
/// fit in a fresh byte budget; no partial record or hidden lookup is permitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskCopyBudget {
    pub records: usize,
    pub bytes: usize,
}

/// Actual reads in one step, including branch-only and membership visits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiskCopyProgress {
    pub records: usize,
    pub node_visits: usize,
    pub bytes: usize,
    pub complete: bool,
}
impl DiskCopyProgress {
    fn fits(&self, budget: DiskCopyBudget, bytes: usize) -> bool {
        self.records < budget.records && bytes <= budget.bytes.saturating_sub(self.bytes)
    }
    fn node(&mut self, bytes: usize) {
        self.records += 1;
        self.node_visits += 1;
        self.bytes += bytes;
    }
}

pub(crate) struct CopyMap<'a> {
    pub(crate) map: &'a DiskMap,
    pub(crate) copy_nodes: bool,
}
pub(crate) struct FormulaRecord {
    pub(crate) statement: StatementId,
    pub(crate) address: [u8; 32],
    pub(crate) length: usize,
    pub(crate) address_of: fn(&[u8]) -> [u8; 32],
}
pub(crate) enum Follow {
    None,
    Formula(FormulaRecord),
    Bucket(Walk),
    Membership(DiskMap, Lookup),
}

/// Only live authenticated owners may describe their reachable record graph.
/// Advancing a plan itself must perform no storage reads.
pub(crate) trait CopyPlan {
    fn storage(&self) -> Arc<dyn ContextStorage>;
    fn current(&self) -> Option<CopyMap<'_>>;
    fn next(&mut self);
    fn follow(&self, key: [u8; 32], value: &[u8]) -> Result<Follow, ContextError>;
}

pub(crate) struct AuthenticatedCopy<P> {
    plan: P,
    target: Arc<dyn ContextStorage>,
    walk: Option<Walk>,
    follow: Follow,
    failed: bool,
}
impl<P: CopyPlan> AuthenticatedCopy<P> {
    pub(crate) fn new(plan: P, target: Arc<dyn ContextStorage>) -> Self {
        Self {
            plan,
            target,
            walk: None,
            follow: Follow::None,
            failed: false,
        }
    }
    pub(crate) fn plan(&self) -> &P {
        &self.plan
    }
    pub(crate) fn target(&self) -> Arc<dyn ContextStorage> {
        self.target.clone()
    }
    pub(crate) fn complete(&self) -> bool {
        !self.failed
            && self.plan.current().is_none()
            && self.walk.is_none()
            && matches!(self.follow, Follow::None)
    }
    pub(crate) fn advance(
        &mut self,
        budget: DiskCopyBudget,
    ) -> Result<DiskCopyProgress, ContextError> {
        let result = self.advance_inner(budget);
        if let Err(error) = &result {
            self.failed = true;
            // A failed cursor cannot publish roots. An insufficient quantum
            // does not corrupt the still-live source or halt its other readers.
            if matches!(error, ContextError::Corrupt | ContextError::Storage(_)) {
                self.plan.storage().record_failure(error);
            }
        }
        result
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
            match &mut self.follow {
                Follow::Membership(map, lookup) => {
                    if lookup.complete() {
                        if lookup.value()?.is_none() {
                            return Err(ContextError::Corrupt);
                        }
                        self.follow = Follow::None;
                        continue;
                    }
                    if !work.fits(budget, MAX_NODE_BYTES) {
                        break;
                    }
                    work.node(map.advance_lookup(lookup)?.ok_or(ContextError::Corrupt)?);
                    continue;
                }
                Follow::Formula(record) => {
                    if record.length > budget.bytes {
                        return Err(ContextError::Limit);
                    }
                    if !work.fits(budget, record.length) {
                        break;
                    }
                    let bytes = self.plan.storage().read(record.address, record.length)?;
                    if bytes.len() != record.length
                        || (record.address_of)(&bytes) != record.address
                        || statement_id(&bytes) != record.statement
                    {
                        return Err(ContextError::Corrupt);
                    }
                    self.target.write(record.address, &bytes)?;
                    work.records += 1;
                    work.bytes += bytes.len();
                    self.follow = Follow::None;
                    continue;
                }
                Follow::Bucket(walk) => {
                    if walk.complete() {
                        self.follow = Follow::None;
                        continue;
                    }
                    if !work.fits(budget, MAX_NODE_BYTES) {
                        break;
                    }
                    let visit = walk.step()?.ok_or(ContextError::Corrupt)?;
                    self.target.write(visit.address, &visit.bytes)?;
                    work.node(visit.bytes.len());
                    continue;
                }
                Follow::None => {}
            }
            let Some(current) = self.plan.current() else {
                break;
            };
            let walk = self.walk.get_or_insert_with(|| current.map.walk());
            if walk.complete() {
                self.walk = None;
                self.plan.next();
                continue;
            }
            if !work.fits(budget, MAX_NODE_BYTES) {
                break;
            }
            let visit = walk.step()?.ok_or(ContextError::Corrupt)?;
            if current.copy_nodes {
                self.target.write(visit.address, &visit.bytes)?;
            }
            work.node(visit.bytes.len());
            if let Some((key, value)) = visit.entry {
                self.follow = self.plan.follow(key, &value)?;
            }
        }
        work.complete = self.complete();
        Ok(work)
    }
}
