use super::*;
use libp2p::{
    core::{Endpoint, transport::PortUse},
    futures::FutureExt,
    identity,
};

#[tokio::test]
async fn dns_resolving_to_loopback_is_rejected_before_opening_tcp() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let key = identity::Keypair::generate_ed25519();
    let book = discovery::SharedBook::new(discovery::Book::new(
        key.public().to_peer_id(),
        true,
        &discovery::Config::default(),
    ));
    let mut transport = tcp(&key, book).unwrap();
    let address = format!("/dns4/localhost/tcp/{port}").parse().unwrap();
    let dial = transport
        .dial(
            address,
            DialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::New,
            },
        )
        .unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), dial)
        .await
        .expect("private DNS answer must be rejected before a Noise handshake");
    assert!(result.is_err());
    assert!(
        listener.accept().now_or_never().is_none(),
        "untrusted DNS opened a local TCP service"
    );
}
