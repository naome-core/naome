use super::*;
impl TransferGrant {
    pub(crate) fn set_received_for_test(&mut self, received: Instant) {
        self.received = received;
    }
}

#[test]
fn traffic_scope_expiry_refresh_and_revocation_are_one_contract() {
    let peer = PeerId::random();
    let root = ArtifactId::from_bytes([1; 32]);
    let capability = PeerGrant::new();
    let grant = TransferGrant::new(peer, root, Some(capability.clone()));
    let received = grant.received;
    assert!(grant.authorizes(peer, root, received));
    assert!(!grant.authorizes(PeerId::random(), root, received));
    assert!(!grant.authorizes(peer, ArtifactId::from_bytes([2; 32]), received));
    assert!(!grant.refresh_due(received));
    assert!(grant.refresh_due(received + crate::resources::limits().root_timeout / 2));
    assert!(grant.live(grant.deadline() - std::time::Duration::from_nanos(1)));
    assert!(!grant.live(grant.deadline()));
    capability
        .0
        .store(false, std::sync::atomic::Ordering::Release);
    assert!(!grant.live(received));
    assert!(grant.refresh_due(received));
    let replacement = TransferGrant::new(peer, root, Some(PeerGrant::new()));
    assert!(replacement.live(Instant::now()));
    assert!(!grant.live(received));
}
