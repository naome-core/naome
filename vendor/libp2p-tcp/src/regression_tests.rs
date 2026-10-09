// Exercise the actual pinned transport and kernel sockets at the retry boundary.
use super::{tokio as provider, Transport};
use futures::{
    future::poll_fn,
    io::{AsyncReadExt, AsyncWriteExt},
};
use libp2p_core::{
    transport::{DialOpts, ListenerId, PortUse, TransportEvent},
    Endpoint, Multiaddr, Transport as _,
};
use std::{pin::Pin, time::Duration};

async fn next_event(
    tcp: &mut Transport<provider::Tcp>,
) -> TransportEvent<super::Ready<Result<provider::TcpStream, std::io::Error>>, std::io::Error> {
    poll_fn(|cx| Pin::new(&mut *tcp).poll(cx)).await
}

async fn address(tcp: &mut Transport<provider::Tcp>) -> Multiaddr {
    match next_event(tcp).await {
        TransportEvent::NewAddress { listen_addr, .. } => listen_addr,
        event => panic!("unexpected listener event: {event:?}"),
    }
}

async fn incoming(tcp: &mut Transport<provider::Tcp>) -> (provider::TcpStream, Multiaddr) {
    match next_event(tcp).await {
        TransportEvent::Incoming {
            upgrade,
            send_back_addr,
            ..
        } => (
            upgrade.await.expect("actual incoming stream"),
            send_back_addr,
        ),
        event => panic!("unexpected incoming event: {event:?}"),
    }
}

fn reuse() -> DialOpts {
    DialOpts {
        role: Endpoint::Dialer,
        port_use: PortUse::Reuse,
    }
}

#[::tokio::test]
async fn reverse_live_tuple_retries_with_a_new_source_port() {
    ::tokio::time::timeout(Duration::from_secs(5), async {
        let mut a = Transport::<provider::Tcp>::default();
        let mut b = Transport::<provider::Tcp>::default();
        a.listen_on(ListenerId::next(), "/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        b.listen_on(ListenerId::next(), "/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let addr_a = address(&mut a).await;
        let addr_b = address(&mut b).await;
        let mut first = a.dial(addr_b.clone(), reuse()).unwrap().await.unwrap();
        let (mut first_incoming, source_a) = incoming(&mut b).await;
        assert_eq!(source_a, addr_a, "successful reuse keeps the listener port");
        first.write_all(b"a").await.unwrap();
        let mut byte = [0];
        first_incoming.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, *b"a");

        // Keep both ends of A -> B alive while B tries the same reversed tuple.
        let mut reverse = b
            .dial(addr_a.clone(), reuse())
            .unwrap()
            .await
            .expect("a selected reuse collision must retry with a new source port");
        let (mut reverse_incoming, source_b) = incoming(&mut a).await;
        assert_ne!(source_b, addr_b, "reverse collision allocates a fresh port");
        reverse.write_all(b"b").await.unwrap();
        reverse_incoming.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, *b"b");
        println!("reuse control {addr_a} -> {addr_b}; reverse fallback {source_b} -> {addr_a}");
    })
    .await
    .expect("bounded reverse TCP tuple regression");
}
