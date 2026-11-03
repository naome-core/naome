// Copyright 2017 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use futures::{
    channel::{mpsc, oneshot},
    future::poll_fn,
};
use libp2p_core::{Endpoint, Transport as _};

use super::*;

#[test]
fn multiaddr_to_tcp_conversion() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    assert!(
        multiaddr_to_socketaddr("/ip4/127.0.0.1/udp/1234".parse::<Multiaddr>().unwrap()).is_err()
    );

    assert_eq!(
        multiaddr_to_socketaddr("/ip4/127.0.0.1/tcp/12345".parse::<Multiaddr>().unwrap()),
        Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
        ))
    );
    assert_eq!(
        multiaddr_to_socketaddr(
            "/ip4/255.255.255.255/tcp/8080"
                .parse::<Multiaddr>()
                .unwrap()
        ),
        Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            8080,
        ))
    );
    assert_eq!(
        multiaddr_to_socketaddr("/ip6/::1/tcp/12345".parse::<Multiaddr>().unwrap()),
        Ok(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            12345,
        ))
    );
    assert_eq!(
        multiaddr_to_socketaddr(
            "/ip6/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/tcp/8080"
                .parse::<Multiaddr>()
                .unwrap()
        ),
        Ok(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
            )),
            8080,
        ))
    );
}

#[test]
fn communicating_between_dialer_and_listener() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    async fn listener<T: Provider>(addr: Multiaddr, mut ready_tx: mpsc::Sender<Multiaddr>) {
        let mut tcp = Transport::<T>::default().boxed();
        tcp.listen_on(ListenerId::next(), addr).unwrap();
        loop {
            match tcp.select_next_some().await {
                TransportEvent::NewAddress { listen_addr, .. } => {
                    ready_tx.send(listen_addr).await.unwrap();
                }
                TransportEvent::Incoming { upgrade, .. } => {
                    let mut upgrade = upgrade.await.unwrap();
                    let mut buf = [0u8; 3];
                    upgrade.read_exact(&mut buf).await.unwrap();
                    assert_eq!(buf, [1, 2, 3]);
                    upgrade.write_all(&[4, 5, 6]).await.unwrap();
                    return;
                }
                e => panic!("Unexpected transport event: {e:?}"),
            }
        }
    }

    async fn dialer<T: Provider>(mut ready_rx: mpsc::Receiver<Multiaddr>) {
        let addr = ready_rx.next().await.unwrap();
        let mut tcp = Transport::<T>::default();

        // Obtain a future socket through dialing
        let mut socket = tcp
            .dial(
                addr.clone(),
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::Reuse,
                },
            )
            .unwrap()
            .await
            .unwrap();
        socket.write_all(&[0x1, 0x2, 0x3]).await.unwrap();

        let mut buf = [0u8; 3];
        socket.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [4, 5, 6]);
    }

    fn test(addr: Multiaddr) {
        let (ready_tx, ready_rx) = mpsc::channel(1);
        let listener = listener::<tokio::Tcp>(addr, ready_tx);
        let dialer = dialer::<tokio::Tcp>(ready_rx);
        let rt = ::tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let tasks = ::tokio::task::LocalSet::new();
        let listener = tasks.spawn_local(listener);
        tasks.block_on(&rt, dialer);
        tasks.block_on(&rt, listener).unwrap();
    }

    test("/ip4/127.0.0.1/tcp/0".parse().unwrap());
    test("/ip6/::1/tcp/0".parse().unwrap());
}

#[test]
fn wildcard_expansion() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    async fn listener<T: Provider>(addr: Multiaddr, mut ready_tx: mpsc::Sender<Multiaddr>) {
        let mut tcp = Transport::<T>::default().boxed();
        tcp.listen_on(ListenerId::next(), addr).unwrap();

        loop {
            match tcp.select_next_some().await {
                TransportEvent::NewAddress { listen_addr, .. } => {
                    let mut iter = listen_addr.iter();
                    match iter.next().expect("ip address") {
                        Protocol::Ip4(ip) => assert!(!ip.is_unspecified()),
                        Protocol::Ip6(ip) => assert!(!ip.is_unspecified()),
                        other => panic!("Unexpected protocol: {other}"),
                    }
                    if let Protocol::Tcp(port) = iter.next().expect("port") {
                        assert_ne!(0, port)
                    } else {
                        panic!("No TCP port in address: {listen_addr}")
                    }
                    ready_tx.send(listen_addr).await.ok();
                }
                TransportEvent::Incoming { .. } => {
                    return;
                }
                _ => {}
            }
        }
    }

    async fn dialer<T: Provider>(mut ready_rx: mpsc::Receiver<Multiaddr>) {
        let dest_addr = ready_rx.next().await.unwrap();
        let mut tcp = Transport::<T>::default();
        tcp.dial(
            dest_addr,
            DialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::New,
            },
        )
        .unwrap()
        .await
        .unwrap();
    }

    fn test(addr: Multiaddr) {
        let (ready_tx, ready_rx) = mpsc::channel(1);
        let listener = listener::<tokio::Tcp>(addr, ready_tx);
        let dialer = dialer::<tokio::Tcp>(ready_rx);
        let rt = ::tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let tasks = ::tokio::task::LocalSet::new();
        let listener = tasks.spawn_local(listener);
        tasks.block_on(&rt, dialer);
        tasks.block_on(&rt, listener).unwrap();
    }

    test("/ip4/0.0.0.0/tcp/0".parse().unwrap());
    test("/ip6/::1/tcp/0".parse().unwrap());
}

#[test]
fn port_reuse_dialing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    async fn listener<T: Provider>(
        addr: Multiaddr,
        mut ready_tx: mpsc::Sender<Multiaddr>,
        port_reuse_rx: oneshot::Receiver<Protocol<'_>>,
    ) {
        let mut tcp = Transport::<T>::new(Config::new()).boxed();
        tcp.listen_on(ListenerId::next(), addr).unwrap();
        loop {
            match tcp.select_next_some().await {
                TransportEvent::NewAddress { listen_addr, .. } => {
                    ready_tx.send(listen_addr).await.ok();
                }
                TransportEvent::Incoming {
                    upgrade,
                    mut send_back_addr,
                    ..
                } => {
                    // Receive the dialer tcp port reuse
                    let remote_port_reuse = port_reuse_rx.await.unwrap();
                    // And check it is the same as the remote port used for upgrade
                    assert_eq!(send_back_addr.pop().unwrap(), remote_port_reuse);

                    let mut upgrade = upgrade.await.unwrap();
                    let mut buf = [0u8; 3];
                    upgrade.read_exact(&mut buf).await.unwrap();
                    assert_eq!(buf, [1, 2, 3]);
                    upgrade.write_all(&[4, 5, 6]).await.unwrap();
                    return;
                }
                e => panic!("Unexpected event: {e:?}"),
            }
        }
    }

    async fn dialer<T: Provider>(
        addr: Multiaddr,
        mut ready_rx: mpsc::Receiver<Multiaddr>,
        port_reuse_tx: oneshot::Sender<Protocol<'_>>,
    ) {
        let dest_addr = ready_rx.next().await.unwrap();
        let mut tcp = Transport::<T>::new(Config::new());
        tcp.listen_on(ListenerId::next(), addr).unwrap();
        match poll_fn(|cx| Pin::new(&mut tcp).poll(cx)).await {
            TransportEvent::NewAddress { .. } => {
                // Check that tcp and listener share the same port reuse SocketAddr
                let listener = tcp.listeners.iter().next().unwrap();
                let port_reuse_tcp = tcp.port_reuse.local_dial_addr(&listener.listen_addr.ip());
                let port_reuse_listener = listener
                    .port_reuse
                    .local_dial_addr(&listener.listen_addr.ip());
                assert!(port_reuse_tcp.is_some());
                assert_eq!(port_reuse_tcp, port_reuse_listener);

                // Send the dialer tcp port reuse to the listener
                port_reuse_tx
                    .send(Protocol::Tcp(port_reuse_tcp.unwrap().port()))
                    .ok();

                // Obtain a future socket through dialing
                let mut socket = tcp
                    .dial(
                        dest_addr,
                        DialOpts {
                            role: Endpoint::Dialer,
                            port_use: PortUse::Reuse,
                        },
                    )
                    .unwrap()
                    .await
                    .unwrap();
                socket.write_all(&[0x1, 0x2, 0x3]).await.unwrap();
                // socket.flush().await;
                let mut buf = [0u8; 3];
                socket.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, [4, 5, 6]);
            }
            e => panic!("Unexpected transport event: {e:?}"),
        }
    }

    fn test(addr: Multiaddr) {
        let (ready_tx, ready_rx) = mpsc::channel(1);
        let (port_reuse_tx, port_reuse_rx) = oneshot::channel();
        let listener = listener::<tokio::Tcp>(addr.clone(), ready_tx, port_reuse_rx);
        let dialer = dialer::<tokio::Tcp>(addr, ready_rx, port_reuse_tx);
        let rt = ::tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let tasks = ::tokio::task::LocalSet::new();
        let listener = tasks.spawn_local(listener);
        tasks.block_on(&rt, dialer);
        tasks.block_on(&rt, listener).unwrap();
    }

    test("/ip4/127.0.0.1/tcp/0".parse().unwrap());
    test("/ip6/::1/tcp/0".parse().unwrap());
}

#[test]
fn port_reuse_listening() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    async fn listen_twice<T: Provider>(addr: Multiaddr) {
        let mut tcp = Transport::<T>::new(Config::new());
        tcp.listen_on(ListenerId::next(), addr).unwrap();
        match poll_fn(|cx| Pin::new(&mut tcp).poll(cx)).await {
            TransportEvent::NewAddress {
                listen_addr: addr1, ..
            } => {
                let listener1 = tcp.listeners.iter().next().unwrap();
                let port_reuse_tcp = tcp.port_reuse.local_dial_addr(&listener1.listen_addr.ip());
                let port_reuse_listener1 = listener1
                    .port_reuse
                    .local_dial_addr(&listener1.listen_addr.ip());
                assert!(port_reuse_tcp.is_some());
                assert_eq!(port_reuse_tcp, port_reuse_listener1);

                // Listen on the same address a second time.
                tcp.listen_on(ListenerId::next(), addr1.clone()).unwrap();
                match poll_fn(|cx| Pin::new(&mut tcp).poll(cx)).await {
                    TransportEvent::NewAddress {
                        listen_addr: addr2, ..
                    } => assert_eq!(addr1, addr2),
                    e => panic!("Unexpected transport event: {e:?}"),
                }
            }
            e => panic!("Unexpected transport event: {e:?}"),
        }
    }

    fn test(addr: Multiaddr) {
        let listener = listen_twice::<tokio::Tcp>(addr);
        let rt = ::tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        rt.block_on(listener);
    }

    test("/ip4/127.0.0.1/tcp/0".parse().unwrap());
}

#[test]
fn listen_port_0() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    async fn listen<T: Provider>(addr: Multiaddr) -> Multiaddr {
        let mut tcp = Transport::<T>::default().boxed();
        tcp.listen_on(ListenerId::next(), addr).unwrap();
        tcp.select_next_some()
            .await
            .into_new_address()
            .expect("listen address")
    }

    fn test(addr: Multiaddr) {
        let rt = ::tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let new_addr = rt.block_on(listen::<tokio::Tcp>(addr));
        assert!(!new_addr.to_string().contains("tcp/0"));
    }

    test("/ip6/::1/tcp/0".parse().unwrap());
    test("/ip4/127.0.0.1/tcp/0".parse().unwrap());
}

#[test]
fn listen_invalid_addr() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    fn test(addr: Multiaddr) {
        let mut tcp = tokio::Transport::default();
        assert!(tcp.listen_on(ListenerId::next(), addr).is_err());
    }

    test("/ip4/127.0.0.1/tcp/12345/tcp/12345".parse().unwrap());
}

#[test]
fn test_remove_listener() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    async fn cycle_listeners<T: Provider>() -> bool {
        let mut tcp = Transport::<T>::default().boxed();
        let listener_id = ListenerId::next();
        tcp.listen_on(listener_id, "/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        tcp.remove_listener(listener_id)
    }

    #[cfg(feature = "tokio")]
    {
        let rt = ::tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        assert!(rt.block_on(cycle_listeners::<tokio::Tcp>()));
    }
}

#[test]
fn test_listens_ipv4_ipv6_separately() {
    fn test<T: Provider>() {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut tcp = Transport::<T>::default().boxed();
        let listener_id = ListenerId::next();
        tcp.listen_on(
            listener_id,
            format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap(),
        )
        .unwrap();
        tcp.listen_on(
            ListenerId::next(),
            format!("/ip6/::/tcp/{port}").parse().unwrap(),
        )
        .unwrap();
    }
    #[cfg(feature = "tokio")]
    {
        let rt = ::tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        rt.block_on(async {
            test::<tokio::Tcp>();
        });
    }
}

#[test]
fn occupied_reused_connection_uses_a_new_port_without_closing_the_first() {
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        ::tokio::time::timeout(Duration::from_secs(5), async {
            let server = ::tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let destination: Multiaddr =
                format!("/ip4/127.0.0.1/tcp/{}", server.local_addr().unwrap().port())
                    .parse()
                    .unwrap();
            let mut transport = Transport::<tokio::Tcp>::new(Config::new());
            transport
                .listen_on(ListenerId::next(), "/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            let reused_port = loop {
                if let TransportEvent::NewAddress { listen_addr, .. } =
                    poll_fn(|cx| Pin::new(&mut transport).poll(cx)).await
                {
                    break multiaddr_to_socketaddr(listen_addr).unwrap().port();
                }
            };
            let dial = |transport: &mut Transport<tokio::Tcp>| {
                transport
                    .dial(
                        destination.clone(),
                        DialOpts {
                            role: Endpoint::Dialer,
                            port_use: PortUse::Reuse,
                        },
                    )
                    .unwrap()
            };
            let mut first = dial(&mut transport).await.unwrap();
            let (mut first_peer, first_address) = server.accept().await.unwrap();
            assert_eq!(first_address.port(), reused_port);
            // The first live socket occupies this exact local/remote tuple. Linux
            // reports EADDRNOTAVAIL and macOS reports EADDRINUSE for the next dial.
            let mut second = dial(&mut transport).await.unwrap();
            let (mut second_peer, second_address) = server.accept().await.unwrap();
            assert_ne!(second_address.port(), reused_port);
            for (client, peer, byte) in [
                (&mut first, &mut first_peer, 1),
                (&mut second, &mut second_peer, 2),
            ] {
                client.write_all(&[byte]).await.unwrap();
                let mut received = [0];
                ::tokio::io::AsyncReadExt::read_exact(peer, &mut received)
                    .await
                    .unwrap();
                assert_eq!(received, [byte]);
            }
        })
        .await
        .expect("both connections remain usable within the socket deadline");
    });
}
