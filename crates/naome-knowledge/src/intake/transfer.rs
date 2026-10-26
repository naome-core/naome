//! A short metadata grant binds traffic to one peer/root and revocable epoch.
//! Research decisions and mathematical validity remain with their own owners.
use super::*;
use crate::publication::PeerGrant;

#[derive(Clone)]
pub(super) struct TransferGrant {
    peer: PeerId,
    root: ProofId,
    received: Instant,
    capability: Option<PeerGrant>,
}
impl TransferGrant {
    pub(super) fn new(peer: PeerId, root: ProofId, capability: Option<PeerGrant>) -> Self {
        Self {
            peer,
            root,
            received: Instant::now(),
            capability: capability.map(|grant| grant.with_origin(peer)),
        }
    }
    pub(super) fn peer(&self) -> PeerId {
        self.peer
    }
    pub(super) fn root(&self) -> ProofId {
        self.root
    }
    pub(super) fn deadline(&self) -> Instant {
        self.received + crate::resources::limits().root_timeout
    }
    pub(super) fn check(&self, now: Instant) -> Result<(), crate::Error> {
        if now >= self.deadline() {
            return Err(crate::Error::Deadline);
        }
        if let Some(capability) = &self.capability {
            capability.check()?;
        }
        Ok(())
    }
    pub(super) fn live(&self, now: Instant) -> bool {
        self.check(now).is_ok()
    }
    pub(super) fn authorizes(&self, peer: PeerId, root: ProofId, now: Instant) -> bool {
        self.authorize(peer, root, now).is_ok()
    }
    pub(super) fn authorize(
        &self,
        peer: PeerId,
        root: ProofId,
        now: Instant,
    ) -> Result<(), crate::Error> {
        if self.peer != peer || self.root != root {
            return Err(crate::Error::InvalidInput(
                "transfer peer or root differs".into(),
            ));
        }
        self.check(now)
    }
    pub(super) fn refresh_due(&self, now: Instant) -> bool {
        !self.live(now)
            || now.saturating_duration_since(self.received)
                >= crate::resources::limits().root_timeout / 2
    }
    pub(super) fn capability(&self) -> Option<PeerGrant> {
        self.capability.clone()
    }
}

#[cfg(test)]
mod tests;
