//! Revocable publication capabilities, independent of Runtime and Graph state.
//! Checks run again inside the canonical transaction; a cached selection never
//! substitutes for the owner's current recovery and shutdown checks.
use std::sync::Arc;

pub(crate) trait LocalAuthority: Send + Sync {
    fn check_selection(&self, expected: Option<[u8; 32]>) -> Result<(), crate::Error>;
}

pub(crate) const STALE_COMMIT: crate::Error = crate::Error::StaleAuthority;

/// A concrete peer/root authorization, independent of other peer traffic.
#[derive(Clone, Debug)]
pub(crate) struct PeerGrant(pub(crate) Arc<std::sync::atomic::AtomicBool>);
impl PeerGrant {
    pub(crate) fn new() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicBool::new(true)))
    }
    pub(crate) fn check(&self) -> Result<(), crate::Error> {
        if self.0.load(std::sync::atomic::Ordering::Acquire) {
            Ok(())
        } else {
            Err(STALE_COMMIT)
        }
    }
}

/// Revocable operation authority, checked again inside the durable transaction.
/// It contains no mathematical state and cannot grant checked membership.
#[derive(Clone)]
pub(crate) struct CommitGuard {
    epoch: Arc<std::sync::atomic::AtomicU64>,
    expected: u64,
    authority: Option<Arc<dyn LocalAuthority>>,
    selection: Option<[u8; 32]>,
    peer: Option<PeerGrant>,
}
impl CommitGuard {
    pub(crate) fn new(
        epoch: Arc<std::sync::atomic::AtomicU64>,
        expected: u64,
        authority: Option<Arc<dyn LocalAuthority>>,
        selection: Option<[u8; 32]>,
    ) -> Self {
        Self {
            epoch,
            expected,
            authority,
            selection,
            peer: None,
        }
    }
    pub(crate) fn with_peer(mut self, peer: PeerGrant) -> Self {
        self.peer = Some(peer);
        self
    }
    pub(crate) fn check(&self) -> Result<(), crate::Error> {
        use std::sync::atomic::Ordering;
        if let Some(peer) = &self.peer {
            peer.check()?;
        }
        if self.expected == u64::MAX || self.epoch.load(Ordering::Acquire) != self.expected {
            return Err(STALE_COMMIT);
        }
        if let Some(authority) = &self.authority {
            authority.check_selection(self.selection)?;
        }
        if self.epoch.load(Ordering::Acquire) != self.expected {
            return Err(STALE_COMMIT);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
