use super::*;

fn peer() -> PeerId {
    identity::Keypair::generate_ed25519().public().to_peer_id()
}

#[test]
fn untrusted_routes_cannot_authorize_private_endpoints() {
    let mut book = Book::new(peer(), true, &Config::default());
    let remote = peer();
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "192.168.1.1",
        "100.64.0.1",
    ] {
        let address: Multiaddr = format!("/ip4/{ip}/tcp/8080").parse().unwrap();
        assert!(
            book.hint(remote, &address, Instant::now()).is_err(),
            "{address}"
        );
        assert!(!book.allows_dial(&address));
    }
    for ip in [
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "64:ff9b::a00:1",
        "2002:a00:1::1",
        "2001:db8::1",
    ] {
        let address: Multiaddr = format!("/ip6/{ip}/tcp/8080").parse().unwrap();
        assert!(
            book.hint(remote, &address, Instant::now()).is_err(),
            "{address}"
        );
        assert!(!book.allows_dial(&address));
    }
    assert!(book.contacts.is_empty());
    let public: Multiaddr = "/ip4/8.8.8.8/tcp/4001".parse().unwrap();
    book.hint(remote, &public, Instant::now()).unwrap();
    assert!(book.allows_dial(&public));
    assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
}

#[test]
fn explicit_and_lan_exceptions_do_not_authorize_other_local_services() {
    let mut book = Book::new(peer(), true, &Config::default());
    let remote = peer();
    let allowed: Multiaddr = "/ip4/192.168.1.2/tcp/4001".parse().unwrap();
    book.local_hint(remote, &allowed, Instant::now()).unwrap();
    assert!(book.allows_dial(&allowed));
    let forbidden: Multiaddr = "/ip4/192.168.1.2/tcp/22".parse().unwrap();
    assert!(!book.allows_dial(&forbidden));
    assert!(book.hint(remote, &forbidden, Instant::now()).is_err());
    let pinned = peer();
    book.pin(pinned, &forbidden, false).unwrap();
    assert!(book.allows_dial(&forbidden));
    let other: Multiaddr = "/ip4/192.168.1.3/tcp/22".parse().unwrap();
    assert!(!book.allows_dial(&other));
}
