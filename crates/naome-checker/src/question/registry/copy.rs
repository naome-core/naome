//! Bounded copy of reachable registry nodes, formulas and statement buckets.
use super::*;
use crate::{
    DiskCopyBudget, DiskCopyProgress,
    state::{
        copy::{AuthenticatedCopy, CopyMap, CopyPlan, Follow, FormulaRecord},
        disk_map::{DiskMap, Root},
    },
};

#[derive(Clone, Copy)]
enum Phase {
    Records,
    Statements,
    Contents,
    Complete,
}
struct RegistryCopyPlan {
    source: QuestionRegistry,
    phase: Phase,
}
impl CopyPlan for RegistryCopyPlan {
    fn storage(&self) -> Arc<dyn ContextStorage> {
        self.source
            .cold
            .as_ref()
            .expect("disk registry copy")
            .records
            .storage()
    }
    fn current(&self) -> Option<CopyMap<'_>> {
        let cold = self.source.cold.as_ref().expect("disk registry copy");
        let map = match self.phase {
            Phase::Records => &cold.records,
            Phase::Statements => &cold.statements,
            Phase::Contents => &cold.contents,
            Phase::Complete => return None,
        };
        Some(CopyMap {
            map,
            copy_nodes: true,
        })
    }
    fn next(&mut self) {
        self.phase = match self.phase {
            Phase::Records => Phase::Statements,
            Phase::Statements => Phase::Contents,
            Phase::Contents | Phase::Complete => Phase::Complete,
        };
    }
    fn follow(&self, _: [u8; 32], value: &[u8]) -> Result<Follow, ContextError> {
        match self.phase {
            Phase::Records => {
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
                Ok(Follow::Formula(FormulaRecord {
                    statement,
                    address,
                    length,
                    address_of: cold::formula_address,
                }))
            }
            Phase::Statements => {
                if value.len() != 64 {
                    return Err(ContextError::Corrupt);
                }
                let root = Root {
                    address: value[..32].try_into().map_err(|_| ContextError::Corrupt)?,
                    fingerprint: value[32..].try_into().map_err(|_| ContextError::Corrupt)?,
                };
                Ok(Follow::Bucket(
                    DiskMap::from_root(self.storage(), Some(root)).walk(),
                ))
            }
            _ if !value.is_empty() => Err(ContextError::Corrupt),
            _ => Ok(Follow::None),
        }
    }
}

/// An authenticated cursor over live registry roots. The storage owner must
/// mirror subsequent immutable writes until the returned roots are published.
pub struct QuestionRegistryCopy {
    copy: AuthenticatedCopy<RegistryCopyPlan>,
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
            copy: AuthenticatedCopy::new(
                RegistryCopyPlan {
                    source: self.clone(),
                    phase: Phase::Records,
                },
                target,
            ),
        })
    }
}
impl QuestionRegistryCopy {
    pub fn advance(&mut self, budget: DiskCopyBudget) -> Result<DiskCopyProgress, ContextError> {
        self.copy.advance(budget)
    }
    pub fn finish(self, current: &QuestionRegistry) -> Result<QuestionRegistry, ContextError> {
        if !self.copy.complete() {
            return Err(ContextError::Corrupt);
        }
        let source = self
            .copy
            .plan()
            .source
            .cold
            .as_ref()
            .ok_or(ContextError::Corrupt)?;
        let current_cold = current.cold.as_ref().ok_or(ContextError::Corrupt)?;
        if !Arc::ptr_eq(&source.records.storage(), &current_cold.records.storage()) {
            return Err(ContextError::Corrupt);
        }
        let target = self.copy.target();
        let mut next = current.clone();
        next.cold = Some(cold::DiskRegistry {
            records: DiskMap::from_root(target.clone(), current_cold.records.root()),
            statements: DiskMap::from_root(target.clone(), current_cold.statements.root()),
            contents: DiskMap::from_root(target, current_cold.contents.root()),
        });
        Ok(next)
    }
}

#[cfg(test)]
mod tests;
