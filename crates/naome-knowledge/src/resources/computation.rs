//! Per-node computation admission, independent of network and capacity budgets.
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::watch;

/// Network readiness is reported separately from productive computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputationState {
    Stopped,
    Running,
    Pausing,
    Paused,
}

#[derive(Clone, Copy, Default)]
struct Admission {
    paused: bool,
    active: usize,
}

/// One authority shared by the state owner, local control and provider service.
pub(crate) struct Computation {
    admission: watch::Sender<Admission>,
}

impl Default for Computation {
    fn default() -> Self {
        Self {
            admission: watch::channel(Admission::default()).0,
        }
    }
}

impl Computation {
    pub(crate) fn set_paused(&self, paused: bool) {
        self.admission.send_if_modified(|state| {
            let changed = state.paused != paused;
            state.paused = paused;
            changed
        });
    }

    pub(crate) fn state(&self) -> ComputationState {
        let state = self.admission.borrow();
        match (state.paused, state.active) {
            (false, _) => ComputationState::Running,
            (true, 0) => ComputationState::Paused,
            (true, _) => ComputationState::Pausing,
        }
    }

    /// Admission and pause share one lock, so acknowledged quiescence cannot
    /// race with a new computation. Existing bounded work may finish its step.
    pub(crate) fn try_enter(self: &Arc<Self>) -> Option<ComputationPermit> {
        let entered = self.admission.send_if_modified(|state| {
            if state.paused {
                return false;
            }
            state.active = state.active.checked_add(1).expect("computation count");
            true
        });
        entered.then(|| ComputationPermit(self.clone()))
    }

    /// Providers wait at confirmed boundaries; their original deadline and
    /// cancellation remain owned by the surrounding process supervisor.
    pub(crate) async fn enter(self: &Arc<Self>) -> ComputationPermit {
        let mut changed = self.admission.subscribe();
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
        self.0.admission.send_modify(|state| {
            state.active = state.active.checked_sub(1).expect("owned computation");
        });
    }
}

#[cfg(test)]
mod tests;
