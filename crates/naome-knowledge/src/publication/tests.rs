use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

struct Selection {
    current: AtomicBool,
    transport: Arc<AtomicU64>,
    revoke_during_check: AtomicBool,
}
impl LocalAuthority for Selection {
    fn check_selection(&self, expected: Option<[u8; 32]>) -> Result<(), crate::Error> {
        if self.revoke_during_check.load(Ordering::Acquire) {
            self.transport.fetch_add(1, Ordering::AcqRel);
        }
        if self.current.load(Ordering::Acquire) && expected == Some([7; 32]) {
            Ok(())
        } else {
            Err(STALE_COMMIT)
        }
    }
}

#[test]
fn live_local_and_transport_revocation_survive_cloning_the_capability() {
    let epoch = Arc::new(AtomicU64::new(0));
    let owner = Arc::new(Selection {
        current: AtomicBool::new(true),
        transport: epoch.clone(),
        revoke_during_check: AtomicBool::new(false),
    });
    let guard = CommitGuard::new(epoch, 0, Some(owner.clone()), Some([7; 32]));
    let retained = guard.clone();
    guard.check().unwrap();
    owner.current.store(false, Ordering::Release);
    assert_eq!(retained.check(), Err(STALE_COMMIT));
    owner.current.store(true, Ordering::Release);
    owner.revoke_during_check.store(true, Ordering::Release);
    assert_eq!(guard.check(), Err(STALE_COMMIT));
}

#[test]
fn a_peer_revocation_does_not_revoke_an_unrelated_root_or_local_operation() {
    let epoch = Arc::new(AtomicU64::new(0));
    let local = CommitGuard::new(epoch, 0, None, None);
    let first = PeerGrant::new();
    let second = PeerGrant::new();
    let revoked = local.clone().with_peer(first.clone());
    let unaffected = local.clone().with_peer(second);
    first.0.store(false, Ordering::Release);
    assert_eq!(revoked.check(), Err(STALE_COMMIT));
    unaffected.check().unwrap();
    local.check().unwrap();
}
