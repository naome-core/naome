use super::{
    DiskArtifactState, MapKind, StatementId, decode_root, decode_statement_record, formula_address,
    maps,
};
use crate::context::{ContextError, ContextStorage};
use crate::state::{
    copy::{AuthenticatedCopy, CopyMap, CopyPlan, Follow, FormulaRecord},
    disk_map::DiskMap,
};
use std::sync::Arc;

pub use crate::state::copy::{DiskCopyBudget, DiskCopyProgress};

#[derive(Clone, Copy)]
enum Phase {
    Map(MapKind),
    Formulas,
    Bucket(crate::context::BucketKind),
    Complete,
}
impl Phase {
    fn next(self) -> Self {
        use crate::context::BucketKind;
        match self {
            Self::Map(kind) => kind.next().map_or(Self::Formulas, Self::Map),
            Self::Formulas => Self::Bucket(BucketKind::Outgoing),
            Self::Bucket(BucketKind::Outgoing) => Self::Bucket(BucketKind::Deductions),
            Self::Bucket(BucketKind::Deductions) => Self::Bucket(BucketKind::Instances),
            Self::Bucket(BucketKind::Instances) | Self::Complete => Self::Complete,
        }
    }
    fn map(self, source: &DiskArtifactState) -> &DiskMap {
        use crate::context::BucketKind;
        match self {
            Self::Map(kind) => kind.map(source),
            Self::Formulas => &source.statements,
            Self::Bucket(BucketKind::Outgoing) => &source.outgoing,
            Self::Bucket(BucketKind::Deductions) => &source.deductions,
            Self::Bucket(BucketKind::Instances) => &source.instances,
            Self::Complete => unreachable!("completed copy has no next map"),
        }
    }
}

struct ArtifactCopyPlan {
    source: DiskArtifactState,
    phase: Phase,
}
impl CopyPlan for ArtifactCopyPlan {
    fn storage(&self) -> Arc<dyn ContextStorage> {
        self.source.statements.storage()
    }
    fn current(&self) -> Option<CopyMap<'_>> {
        (!matches!(self.phase, Phase::Complete)).then(|| CopyMap {
            map: self.phase.map(&self.source),
            copy_nodes: matches!(self.phase, Phase::Map(_)),
        })
    }
    fn next(&mut self) {
        self.phase = self.phase.next();
    }
    fn follow(&self, key: [u8; 32], value: &[u8]) -> Result<Follow, ContextError> {
        match self.phase {
            Phase::Formulas => {
                let (address, length) = decode_statement_record(value)?;
                if length == 0 {
                    if naome_proof::program::graph_statement_id(address).as_bytes() != &key {
                        return Err(ContextError::Corrupt);
                    }
                    Ok(Follow::Membership(
                        self.source.program_nodes.clone(),
                        self.source.program_nodes.lookup(address),
                    ))
                } else {
                    Ok(Follow::Formula(FormulaRecord {
                        statement: StatementId::from_bytes(key),
                        address,
                        length,
                        address_of: formula_address,
                    }))
                }
            }
            Phase::Bucket(_) => Ok(Follow::Bucket(
                DiskMap::from_root(self.storage(), decode_root(Some(value))?).walk(),
            )),
            _ => Ok(Follow::None),
        }
    }
}

/// A live checked context's authenticated, resumable copy. The cursor holds
/// two depth-bounded DFS stacks at most, and one pending formula descriptor.
/// No persisted root or caller-supplied address set can complete this cursor.
#[must_use]
pub struct DiskArtifactCopy {
    copy: AuthenticatedCopy<ArtifactCopyPlan>,
}
impl DiskArtifactState {
    /// Start copying the exact live roots. Callers that later finish against
    /// newer roots must mirror every subsequent successful immutable write to
    /// the target and exclude deltas prepared before that mirror was attached.
    /// Byte storage still grants no mathematical validity.
    pub fn begin_copy(&self, target: Arc<dyn ContextStorage>) -> DiskArtifactCopy {
        DiskArtifactCopy {
            copy: AuthenticatedCopy::new(
                ArtifactCopyPlan {
                    source: self.clone(),
                    phase: Phase::Map(MapKind::Proofs),
                },
                target,
            ),
        }
    }
}
impl DiskArtifactCopy {
    pub fn complete(&self) -> bool {
        self.copy.complete()
    }
    /// Yield after bounded actual reads, including maps, formulas, nested
    /// buckets and graph-statement membership checks. An oversized record fails.
    pub fn advance(&mut self, budget: DiskCopyBudget) -> Result<DiskCopyProgress, ContextError> {
        self.copy.advance(budget)
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
            for (source, current) in maps(&self.copy.plan().source)
                .into_iter()
                .zip(maps(current))
            {
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
            ] = maps(current).map(|map| DiskMap::from_root(self.copy.target(), map.root()));
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
        self.copy.plan().source.report(result)
    }
}

#[cfg(test)]
mod tests;
