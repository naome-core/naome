use super::*;

#[test]
fn rate_limits_reject_bursts_and_unknown_identities_until_bounded_window_expires() {
    let mut limiter = rate_limiter();
    let address = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
    let peer = || identity::Keypair::generate_ed25519().public().to_peer_id();
    let first = peer();
    let now = Instant::now();
    for _ in 0..4 {
        assert!(limiter.try_next(first, &address, now));
    }
    assert!(!limiter.try_next(first, &address, now));
    for _ in 1..crate::resources::limits().contacts {
        assert!(limiter.try_next(peer(), &address, now));
    }
    let extra = peer();
    assert!(!limiter.try_next(extra, &address, now + Duration::from_secs(1)));
    assert!(limiter.try_next(extra, &address, now + Duration::from_secs(2)));
    assert!(limiter.try_next(first, &address, now + Duration::from_secs(2)));
}
