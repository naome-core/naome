//! Finite, restartable inventory scans over a fixed append-only horizon.
use super::*;

pub(super) fn response(
    graph: &Graph,
    known: Option<[u8; 32]>,
    after: Option<InventoryCursor>,
    limit: usize,
) -> Result<Body, crate::Error> {
    let root = graph.content_root();
    if after.is_none() && known == Some(root) {
        return Ok(Body::InventoryUnchanged { root });
    }
    if limit == 0 {
        return Err(crate::Error::InputLimit(
            "inventory page limit must be positive",
        ));
    }
    let Some(page) =
        graph.inventory_page(after, limit.min(crate::resources::limits().inventory_page))?
    else {
        return Ok(Body::InventoryRestart);
    };
    Ok(Body::InventoryResult {
        snapshot: page.snapshot,
        ids: page.ids.into_iter().map(|id| *id.as_bytes()).collect(),
        next: page.next,
    })
}

fn valid_page(
    after: Option<InventoryCursor>,
    snapshot: InventorySnapshot,
    ids: &[[u8; 32]],
    next: Option<InventoryCursor>,
) -> bool {
    let position = after.map_or(0, |cursor| cursor.after);
    if snapshot.count > i64::MAX as u64
        || after.is_some_and(|cursor| cursor.snapshot != snapshot)
        || position > snapshot.count
        || ids.len() as u64
            != (snapshot.count - position).min(crate::resources::limits().inventory_page as u64)
        || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
    {
        return false;
    }
    let end = position + ids.len() as u64;
    next == (end < snapshot.count).then_some(InventoryCursor {
        snapshot,
        after: end,
    })
}

impl Node {
    pub(super) fn inventory(&mut self, peer: PeerId, after: Option<InventoryCursor>, pages: usize) {
        let local = self.graph.content_root();
        let known = after.is_none().then(|| {
            self.inventory_summaries
                .get(&peer)
                .filter(|(_, observed_local)| *observed_local == local)
                .map_or(local, |(remote, _)| *remote)
        });
        let id = self.swarm.behaviour_mut().exchange.send_request(
            &peer,
            Frame::new(Body::Inventory {
                known,
                after,
                limit: crate::resources::limits().inventory_page,
            }),
        );
        self.flights.insert(
            id,
            Flight::Inventory {
                started: Instant::now(),
                peer,
                known,
                after,
                pages,
            },
        );
        self.next_inventory.insert(
            peer,
            Instant::now() + crate::resources::limits().reconcile_interval,
        );
    }

    pub(super) fn received_inventory(
        &mut self,
        peer: PeerId,
        after: Option<InventoryCursor>,
        pages: usize,
        snapshot: InventorySnapshot,
        ids: Vec<[u8; 32]>,
        next: Option<InventoryCursor>,
    ) -> Result<(), String> {
        if !valid_page(after, snapshot, &ids, next) {
            emit(json!({"event":"rejected","error":"invalid inventory"}));
            return Ok(());
        }
        // A full queue retries this exact page; new admissions cannot reset or
        // extend the captured horizon. No proof payload or SQL snapshot is held.
        let mut retained = true;
        for id in &ids {
            retained &= self.want(ProofId::from_bytes(*id))?;
        }
        if retained {
            if next.is_some() {
                self.inventory_progress.insert(
                    peer,
                    InventoryProgress {
                        after: next,
                        pages: pages.saturating_add(1),
                    },
                );
            } else {
                self.inventory_progress.remove(&peer);
                self.inventory_summaries
                    .insert(peer, (snapshot.root, self.graph.content_root()));
            }
        }
        emit(json!({"event":"inventory_page", "peer":peer.to_string(),
            "after":after.map(|cursor| cursor.after), "page":pages,
            "count":ids.len(), "retained":retained, "horizon":snapshot.count,
            "last":ids.last().map(|id|hex(id))}));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
