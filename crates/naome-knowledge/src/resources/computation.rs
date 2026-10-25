//! Per-node computation admission, independent of network and capacity budgets.
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// Network readiness is reported separately from productive computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputationState {
    Stopped,
    Running,
    Pausing,
    Paused,
}

/// Tracks admitted work; the shared adaptive budget is the only pause authority.
#[derive(Default)]
pub(crate) struct Computation {
    active: AtomicUsize,
}

impl Computation {
    #[cfg(test)]
    pub(crate) fn state(&self) -> ComputationState {
        self.status().0
    }

    pub(crate) fn status(&self) -> (ComputationState, Option<String>) {
        super::adaptive::inspect_work(|available, reason| {
            let state = if available {
                ComputationState::Running
            } else if self.active.load(Ordering::Acquire) == 0 {
                ComputationState::Paused
            } else {
                ComputationState::Pausing
            };
            (state, reason.map(str::to_owned))
        })
    }

    /// Admission and pause share one lock, so acknowledged quiescence cannot
    /// race with a new computation. Existing bounded work may finish its step.
    pub(crate) fn try_enter(self: &Arc<Self>) -> Option<ComputationPermit> {
        super::adaptive::admit_work(|| {
            self.active
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                    active.checked_add(1)
                })
                .expect("computation count");
            ComputationPermit(self.clone())
        })
    }

    /// Providers wait at confirmed boundaries; their original deadline and
    /// cancellation remain owned by the surrounding process supervisor.
    pub(crate) async fn enter(self: &Arc<Self>) -> ComputationPermit {
        let mut changed = super::adaptive::work_changes();
        loop {
            if let Some(permit) = self.try_enter() {
                return permit;
            }
            changed.changed().await.expect("live computation owner");
        }
    }
}

pub(crate) struct ComputationPermit(Arc<Computation>);

impl ComputationPermit {
    pub(crate) fn owner(&self) -> Arc<Computation> {
        self.0.clone()
    }
}

impl Drop for ComputationPermit {
    fn drop(&mut self) {
        let previous = self.0.active.fetch_sub(1, Ordering::AcqRel);
        assert!(previous > 0, "owned computation");
    }
}

#[cfg(test)]
mod tests;
