//! Enumerate a buffered storage frontier from already checked live roots.
use super::{
    DiskArtifactState, MapKind, decode_root, decode_statement_record, formula_address, statement_id,
};
use crate::{ContextError, StatementId, state::disk_map::DiskMap};

impl DiskArtifactState {
    /// Visit records still buffered by an exclusively owned storage generation.
    /// Returning false declares that this immutable record and its descendants
    /// were already materialized. Returning true visits and authenticates its
    /// contents. The callback may mark records, but never supplies checked roots.
    ///
    /// Traversal uses depth-bounded stacks, not a set proportional to history.
    /// Statement formulas and all nested bucket families are included. This
    /// operation neither establishes mathematical validity nor restores a
    /// persisted context: only this existing live checked view is traversed.
    pub fn visit_pending_records(
        &self,
        mut select: impl FnMut([u8; 32]) -> Result<bool, ContextError>,
    ) -> Result<(), ContextError> {
        self.report((|| {
            for kind in MapKind::ALL {
                let map = kind.map(self);
                let mut walk = map.walk();
                while let Some(visit) = walk.step_selected(&mut select)? {
                    let Some((key, record)) = visit.entry else {
                        continue;
                    };
                    if matches!(kind, MapKind::Statements) {
                        let (address, length) = decode_statement_record(&record)?;
                        let id = StatementId::from_bytes(key);
                        if length == 0 {
                            if naome_proof::program::graph_statement_id(address) != id
                                || !self.program_nodes.contains_key(&address)?
                            {
                                return Err(ContextError::Corrupt);
                            }
                        } else if select(address)? {
                            let bytes = map.storage().read(address, length)?;
                            if bytes.len() != length
                                || formula_address(&bytes) != address
                                || statement_id(&bytes) != id
                            {
                                return Err(ContextError::Corrupt);
                            }
                        }
                    } else if matches!(
                        kind,
                        MapKind::Outgoing | MapKind::Deductions | MapKind::Instances
                    ) {
                        let mut nested =
                            DiskMap::from_root(map.storage(), decode_root(Some(&record))?).walk();
                        while nested.step_selected(&mut select)?.is_some() {}
                    }
                }
            }
            Ok(())
        })())
    }
}

#[cfg(test)]
mod tests;
