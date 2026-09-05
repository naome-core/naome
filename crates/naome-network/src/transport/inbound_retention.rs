//! Shared custody accounting for separately budgeted opaque inbound exchanges.

use super::PeerId;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

pub(super) struct InboundRetentionBudget {
    max_events: usize,
    max_bytes: usize,
    retained: Mutex<InboundRetentionState>,
}

#[derive(Default)]
struct InboundRetentionState {
    events: usize,
    bytes: usize,
    peers: HashSet<PeerId>,
}

impl InboundRetentionBudget {
    pub(super) fn new(max_events: usize, max_bytes: usize) -> Self {
        Self {
            max_events,
            max_bytes,
            retained: Mutex::default(),
        }
    }
    pub(super) fn try_acquire(budget: &Arc<Self>, bytes: usize) -> Option<InboundRetentionPermit> {
        let mut retained = budget.retained.lock().ok()?;
        let events = retained.events.checked_add(1)?;
        let aggregate_bytes = retained.bytes.checked_add(bytes)?;
        if events > budget.max_events || aggregate_bytes > budget.max_bytes {
            return None;
        }
        retained.events = events;
        retained.bytes = aggregate_bytes;
        Some(InboundRetentionPermit {
            budget: Arc::clone(budget),
            bytes,
            peer_id: None,
        })
    }
}

pub(super) struct InboundRetentionPermit {
    budget: Arc<InboundRetentionBudget>,
    bytes: usize,
    peer_id: Option<PeerId>,
}

impl InboundRetentionPermit {
    pub(super) fn bind_peer(&mut self, peer_id: PeerId) -> bool {
        if self.peer_id.is_some() {
            return false;
        }
        let Ok(mut retained) = self.budget.retained.lock() else {
            return false;
        };
        if !retained.peers.insert(peer_id) {
            return false;
        }
        self.peer_id = Some(peer_id);
        true
    }
}

impl Drop for InboundRetentionPermit {
    fn drop(&mut self) {
        let mut retained = self
            .budget
            .retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retained.events = retained.events.saturating_sub(1);
        retained.bytes = retained.bytes.saturating_sub(self.bytes);
        if let Some(peer_id) = self.peer_id {
            retained.peers.remove(&peer_id);
        }
    }
}
