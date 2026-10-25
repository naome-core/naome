//! Stable inventory pages over immutable admission ordinals, with no retained
//! SQL transaction or additional snapshot storage between requests.
use super::*;
use crate::corpus::{InventoryCursor, InventoryPage, InventorySnapshot};

impl Catalog {
    pub(in crate::store) fn inventory_page(
        &self,
        after: Option<InventoryCursor>,
        limit: usize,
        expected: Summary,
    ) -> Result<Option<InventoryPage>, crate::Error> {
        page_limit(limit, crate::resources::limits().inventory_page)?;
        let transaction = begin(&self.connection, TransactionBehavior::Deferred)?;
        check_expected_summary(&read_meta(&transaction, Some(self.database_id))?, expected)?;
        self.require_validated_version(&transaction)?;
        let current_count = u64::try_from(expected.count).map_err(|_| "inventory count width")?;
        let (snapshot, position) = match after {
            Some(cursor) => {
                if cursor.snapshot.lineage != self.database_id
                    || cursor.snapshot.count > current_count
                    || cursor.after > cursor.snapshot.count
                    || (cursor.snapshot.count == current_count
                        && cursor.snapshot.root != expected.root)
                {
                    return Ok(None);
                }
                (cursor.snapshot, cursor.after)
            }
            None => (
                InventorySnapshot {
                    lineage: self.database_id,
                    root: expected.root,
                    count: current_count,
                },
                0,
            ),
        };
        let mut ids = Vec::with_capacity(limit);
        {
            let mut statement = transaction
                .prepare_cached(
                    "SELECT replay_order, substr(id,1,33) FROM proofs
                 WHERE replay_order > ?1 AND replay_order <= ?2
                 ORDER BY replay_order LIMIT ?3",
                )
                .map_err(sql_error)?;
            let mut rows = statement
                .query(params![
                    position as i64,
                    snapshot.count as i64,
                    sql_width(limit)?
                ])
                .map_err(sql_error)?;
            while let Some(row) = rows.next().map_err(sql_error)? {
                let ordinal = replay_ordinal(row.get(0).map_err(sql_error)?)?;
                if ordinal != position + ids.len() as u64 + 1 {
                    return Err("catalog inventory order is incomplete".into());
                }
                ids.push(ProofId::from_bytes(key(row.get(1).map_err(sql_error)?)?));
            }
        }
        if ids.len() as u64 != (snapshot.count - position).min(limit as u64) {
            return Err("catalog inventory page count differs".into());
        }
        let end = position + ids.len() as u64;
        let next = (end < snapshot.count).then_some(InventoryCursor {
            snapshot,
            after: end,
        });
        transaction.commit().map_err(sql_error)?;
        Ok(Some(InventoryPage {
            snapshot,
            ids,
            next,
        }))
    }
}
