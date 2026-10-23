//! Bounded copy of reachable registry nodes, formulas and statement buckets.
use super::*;
use crate::{
    DiskCopyBudget, DiskCopyProgress,
    state::disk_map::{DiskMap, MAX_NODE_BYTES, Root, Walk},
};

/// An authenticated cursor over live registry roots. The storage owner must
/// mirror subsequent immutable writes until the returned roots are published.
pub struct QuestionRegistryCopy {
    source: QuestionRegistry,
    target: Arc<dyn ContextStorage>,
    phase: usize,
    walk: Option<Walk>,
    nested: Option<Walk>,
    formula: Option<(StatementId, Identity, usize)>,
    failed: bool,
}
impl QuestionRegistry {
    pub fn begin_copy(
        &self,
        target: Arc<dyn ContextStorage>,
    ) -> Result<QuestionRegistryCopy, ContextError> {
        if self.cold.is_none() {
            return Err(ContextError::Corrupt);
        }
        Ok(QuestionRegistryCopy {
            source: self.clone(),
            target,
            phase: 0,
            walk: None,
            nested: None,
            formula: None,
            failed: false,
        })
    }
}
impl QuestionRegistryCopy {
    fn map(&self) -> &DiskMap {
        let cold = self.source.cold.as_ref().expect("disk registry copy");
        match self.phase {
            0 => &cold.records,
            1 => &cold.statements,
            _ => &cold.contents,
        }
    }
    pub fn advance(&mut self, budget: DiskCopyBudget) -> Result<DiskCopyProgress, ContextError> {
        if self.failed {
            return Err(ContextError::Corrupt);
        }
        let result = self.advance_inner(budget);
        if let Err(error) = &result {
            self.failed = true;
            self.source
                .cold
                .as_ref()
                .expect("disk registry copy")
                .records
                .storage()
                .record_failure(error);
        }
        result
    }
    fn advance_inner(&mut self, budget: DiskCopyBudget) -> Result<DiskCopyProgress, ContextError> {
        if budget.records == 0 || budget.bytes < MAX_NODE_BYTES {
            return Err(ContextError::Limit);
        }
        let mut work = DiskCopyProgress::default();
        loop {
            if let Some((statement, address, length)) = self.formula {
                if length > budget.bytes {
                    return Err(ContextError::Limit);
                }
                if !work.fits(budget, length) {
                    break;
                }
                let bytes = self.map().storage().read(address, length)?;
                if bytes.len() != length
                    || cold::formula_address(&bytes) != address
                    || statement_id(&bytes) != statement
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
            if self.phase == 3 {
                break;
            }
            if self.walk.is_none() {
                self.walk = Some(self.map().walk());
            }
            let walk = self.walk.as_mut().expect("active registry copy");
            if walk.complete() {
                self.walk = None;
                self.phase += 1;
                continue;
            }
            if !work.fits(budget, MAX_NODE_BYTES) {
                break;
            }
            let visit = walk.step()?.ok_or(ContextError::Corrupt)?;
            self.target.write(visit.address, &visit.bytes)?;
            work.node(visit.bytes.len());
            if let Some((_, value)) = visit.entry {
                if self.phase == 0 {
                    if value.len() != 72 {
                        return Err(ContextError::Corrupt);
                    }
                    let statement = StatementId::from_bytes(
                        value[..32].try_into().map_err(|_| ContextError::Corrupt)?,
                    );
                    let address = value[32..64]
                        .try_into()
                        .map_err(|_| ContextError::Corrupt)?;
                    let length = usize::try_from(u64::from_be_bytes(
                        value[64..].try_into().map_err(|_| ContextError::Corrupt)?,
                    ))
                    .map_err(|_| ContextError::Limit)?;
                    if length > naome_foundation::FORMULA_MAX_BYTES {
                        return Err(ContextError::Corrupt);
                    }
                    self.formula = Some((statement, address, length));
                } else if self.phase == 1 {
                    if value.len() != 64 {
                        return Err(ContextError::Corrupt);
                    }
                    let root = Root {
                        address: value[..32].try_into().map_err(|_| ContextError::Corrupt)?,
                        fingerprint: value[32..].try_into().map_err(|_| ContextError::Corrupt)?,
                    };
                    self.nested = Some(DiskMap::from_root(self.map().storage(), Some(root)).walk());
                } else if !value.is_empty() {
                    return Err(ContextError::Corrupt);
                }
            }
        }
        work.complete = self.phase == 3 && self.formula.is_none() && self.nested.is_none();
        Ok(work)
    }
    pub fn finish(self, current: &QuestionRegistry) -> Result<QuestionRegistry, ContextError> {
        if self.failed || self.phase != 3 || self.formula.is_some() || self.nested.is_some() {
            return Err(ContextError::Corrupt);
        }
        let source = self.source.cold.as_ref().ok_or(ContextError::Corrupt)?;
        let current_cold = current.cold.as_ref().ok_or(ContextError::Corrupt)?;
        if !Arc::ptr_eq(&source.records.storage(), &current_cold.records.storage()) {
            return Err(ContextError::Corrupt);
        }
        let mut next = current.clone();
        next.cold = Some(cold::DiskRegistry {
            records: DiskMap::from_root(self.target.clone(), current_cold.records.root()),
            statements: DiskMap::from_root(self.target.clone(), current_cold.statements.root()),
            contents: DiskMap::from_root(self.target, current_cold.contents.root()),
        });
        Ok(next)
    }
}
