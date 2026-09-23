//! Two independently authenticated periods during a sealed authority handoff.

use super::state_exchange::{StateContext, StateLane};
use super::{NetworkEvent, StateNetwork};
use crate::PeerId;
use naome_ledger::LedgerState;

/// Identifies the transport on which a network event arrived.
#[derive(Debug)]
pub enum StateTransportEvent {
    Active(NetworkEvent),
    Handoff(NetworkEvent),
    Recovery(NetworkEvent),
}

/// Holds the selected parent transport and, while preparing a handoff, the
/// fresh-key transport. Retiring the old period drops all of its Noise sessions.
pub struct StateTransportPair {
    active: Option<StateNetwork>,
    staged: Option<StateNetwork>,
    recovery: Option<StateNetwork>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateTransportPairError {
    Lane,
    Context,
    AlreadyStaged,
    AlreadyRecovery,
}
impl std::fmt::Display for StateTransportPairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid state transport pair: {self:?}")
    }
}
impl std::error::Error for StateTransportPairError {}

impl StateTransportPair {
    pub fn new(active: StateNetwork) -> Result<Self, StateTransportPairError> {
        if active.state_lane() != Some(StateLane::Active) {
            return Err(StateTransportPairError::Lane);
        }
        Ok(Self {
            active: Some(active),
            staged: None,
            recovery: None,
        })
    }
    /// Restores only the fresh handoff identity after old-period retirement.
    pub fn from_staged(staged: StateNetwork) -> Result<Self, StateTransportPairError> {
        if staged.state_lane() != Some(StateLane::Handoff) {
            return Err(StateTransportPairError::Lane);
        }
        Ok(Self {
            active: None,
            staged: Some(staged),
            recovery: None,
        })
    }
    pub fn from_recovery(recovery: StateNetwork) -> Result<Self, StateTransportPairError> {
        if recovery.state_lane() != Some(StateLane::Recovery) {
            return Err(StateTransportPairError::Lane);
        }
        Ok(Self {
            active: None,
            staged: None,
            recovery: Some(recovery),
        })
    }
    pub fn active(&self) -> Option<&StateNetwork> {
        self.active.as_ref()
    }
    pub fn active_mut(&mut self) -> Option<&mut StateNetwork> {
        self.active.as_mut()
    }
    pub fn staged(&self) -> Option<&StateNetwork> {
        self.staged.as_ref()
    }
    pub fn staged_mut(&mut self) -> Option<&mut StateNetwork> {
        self.staged.as_mut()
    }
    pub fn recovery(&self) -> Option<&StateNetwork> {
        self.recovery.as_ref()
    }
    pub fn recovery_mut(&mut self) -> Option<&mut StateNetwork> {
        self.recovery.as_mut()
    }
    pub fn state_context(&self) -> Option<StateContext> {
        self.active
            .as_ref()
            .or(self.staged.as_ref())
            .or(self.recovery.as_ref())
            .and_then(StateNetwork::state_context)
    }
    pub fn is_configured_peer(&self, peer: &PeerId) -> bool {
        self.active
            .as_ref()
            .is_some_and(|net| net.is_configured_peer(peer))
            || self
                .staged
                .as_ref()
                .is_some_and(|net| net.is_configured_peer(peer))
    }
    pub fn stage(&mut self, staged: StateNetwork) -> Result<(), StateTransportPairError> {
        if self.staged.is_some() {
            return Err(StateTransportPairError::AlreadyStaged);
        }
        if staged.state_lane() != Some(StateLane::Handoff) {
            return Err(StateTransportPairError::Lane);
        }
        if self.state_context() != staged.state_context() {
            return Err(StateTransportPairError::Context);
        }
        self.staged = Some(staged);
        Ok(())
    }
    /// Adds a fresh, owner-authenticated recovery lane alongside the selected
    /// or staged transport without granting it consensus authority.
    pub fn attach_recovery(
        &mut self,
        recovery: StateNetwork,
    ) -> Result<(), StateTransportPairError> {
        if self.recovery.is_some() {
            return Err(StateTransportPairError::AlreadyRecovery);
        }
        if recovery.state_lane() != Some(StateLane::Recovery) {
            return Err(StateTransportPairError::Lane);
        }
        if self
            .state_context()
            .is_some_and(|context| Some(context) != recovery.state_context())
        {
            return Err(StateTransportPairError::Context);
        }
        self.recovery = Some(recovery);
        Ok(())
    }
    /// Drops the old-period Noise identity and every connection before a saved
    /// terminal signature can be released. The fresh handoff lane remains.
    pub fn retire_old(&mut self) {
        self.active = None;
    }
    /// Reuses the prepared fresh-key sessions after the caller has verified
    /// and durably selected this exact successor. A changed roster or any
    /// outgoing courier leaves the pair untouched for a fresh rebuild.
    pub fn try_promote_selected(&mut self, selected: &LedgerState) -> bool {
        if self.active.is_some() {
            return false;
        }
        if !self
            .staged
            .as_mut()
            .is_some_and(|network| network.promote_staged_selected(selected))
        {
            return false;
        }
        self.active = self.staged.take();
        // The separately authenticated recovery lane was built against the
        // parent. Recreate it against the newly selected state if needed.
        self.recovery = None;
        true
    }
    /// Installs a new selected transport after the caller verifies sealed
    /// history. This method itself does not grant consensus signing authority.
    pub fn install_selected(
        &mut self,
        active: StateNetwork,
    ) -> Result<(), StateTransportPairError> {
        if active.state_lane() != Some(StateLane::Active) {
            return Err(StateTransportPairError::Lane);
        }
        if self
            .state_context()
            .is_some_and(|context| Some(context) != active.state_context())
        {
            return Err(StateTransportPairError::Context);
        }
        self.staged = None;
        self.recovery = None;
        self.active = Some(active);
        Ok(())
    }
    pub async fn next_event(&mut self) -> Option<StateTransportEvent> {
        match (&mut self.active, &mut self.staged, &mut self.recovery) {
            (Some(active), Some(staged), Some(recovery)) => tokio::select! {
                event = active.next_event() => Some(StateTransportEvent::Active(event)),
                event = staged.next_event() => Some(StateTransportEvent::Handoff(event)),
                event = recovery.next_event() => Some(StateTransportEvent::Recovery(event)),
            },
            (Some(active), Some(staged), None) => tokio::select! {
                event = active.next_event() => Some(StateTransportEvent::Active(event)),
                event = staged.next_event() => Some(StateTransportEvent::Handoff(event)),
            },
            (Some(active), None, Some(recovery)) => tokio::select! {
                event = active.next_event() => Some(StateTransportEvent::Active(event)),
                event = recovery.next_event() => Some(StateTransportEvent::Recovery(event)),
            },
            (None, Some(staged), Some(recovery)) => tokio::select! {
                event = staged.next_event() => Some(StateTransportEvent::Handoff(event)),
                event = recovery.next_event() => Some(StateTransportEvent::Recovery(event)),
            },
            (Some(active), None, None) => {
                Some(StateTransportEvent::Active(active.next_event().await))
            }
            (None, Some(staged), None) => {
                Some(StateTransportEvent::Handoff(staged.next_event().await))
            }
            (None, None, Some(recovery)) => {
                Some(StateTransportEvent::Recovery(recovery.next_event().await))
            }
            (None, None, None) => None,
        }
    }
}
