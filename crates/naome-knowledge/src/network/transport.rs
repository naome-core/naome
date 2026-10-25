//! Filter the final resolved TCP endpoint before any connection is opened.
use crate::discovery;
use libp2p::{
    Multiaddr, Transport,
    core::transport::{DialOpts, ListenerId, TransportError, TransportEvent},
};
use libp2p::{
    PeerId,
    core::{muxing::StreamMuxerBox, transport::Boxed},
    futures::future::BoxFuture,
    multiaddr::Protocol,
};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::sync::Semaphore;

type Connection = (PeerId, StreamMuxerBox);

/// Use the operating system's resolver, including macOS scoped DNS and VPN
/// routing. All resolved sockets still pass through `Filtered` below.
struct SystemDns {
    inner: Arc<Mutex<Boxed<Connection>>>,
    pending: Arc<Semaphore>,
}
impl SystemDns {
    fn new(inner: Boxed<Connection>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            pending: Arc::new(Semaphore::new(
                crate::resources::limits().pending_connections as usize,
            )),
        }
    }
}
impl Transport for SystemDns {
    type Output = Connection;
    type Error = io::Error;
    type ListenerUpgrade = <Boxed<Connection> as Transport>::ListenerUpgrade;
    type Dial = BoxFuture<'static, io::Result<Connection>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<io::Error>> {
        self.inner
            .lock()
            .expect("TCP transport lock")
            .listen_on(id, address)
    }
    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner
            .lock()
            .expect("TCP transport lock")
            .remove_listener(id)
    }
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, io::Error>> {
        Pin::new(&mut *self.inner.lock().expect("TCP transport lock")).poll(cx)
    }
    fn dial(
        &mut self,
        address: Multiaddr,
        options: DialOpts,
    ) -> Result<Self::Dial, TransportError<io::Error>> {
        let (host, family) = match address.iter().next() {
            Some(Protocol::Dns(host)) => (host.into_owned(), 0),
            Some(Protocol::Dns4(host)) => (host.into_owned(), 4),
            Some(Protocol::Dns6(host)) => (host.into_owned(), 6),
            _ => {
                return self
                    .inner
                    .lock()
                    .expect("TCP transport lock")
                    .dial(address, options);
            }
        };
        let Some(Protocol::Tcp(port)) = address.iter().nth(1) else {
            return Err(TransportError::MultiaddrNotSupported(address));
        };
        if host.is_empty()
            || host.len() > 253
            || port == 0
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
        {
            return Err(TransportError::MultiaddrNotSupported(address));
        }
        let permit = self
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| TransportError::Other(io::Error::other("DNS resolution capacity")))?;
        let inner = self.inner.clone();
        Ok(Box::pin(async move {
            let _permit = permit;
            let mut endpoints = Vec::new();
            for socket in tokio::net::lookup_host((host.as_str(), port)).await? {
                let ip = socket.ip();
                if (family == 4 && !ip.is_ipv4())
                    || (family == 6 && !ip.is_ipv6())
                    || endpoints.contains(&ip)
                {
                    continue;
                }
                endpoints.push(ip);
                if endpoints.len() >= crate::resources::limits().addresses_per_contact {
                    break;
                }
            }
            let mut last_error = io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "DNS returned no usable address",
            );
            for ip in endpoints {
                let mut resolved = Multiaddr::empty().with(Protocol::from(ip));
                for part in address.iter().skip(1) {
                    resolved.push(part);
                }
                let dial = inner
                    .lock()
                    .expect("TCP transport lock")
                    .dial(resolved, options);
                match dial {
                    Ok(dial) => match dial.await {
                        Ok(connection) => return Ok(connection),
                        Err(error) => last_error = error,
                    },
                    Err(error) => last_error = io::Error::other(error),
                }
            }
            Err(last_error)
        }))
    }
}

pub(crate) struct Filtered<T> {
    pub(crate) inner: T,
    pub(crate) book: discovery::SharedBook,
}

impl<T: Transport + Unpin> Transport for Filtered<T> {
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, address)
    }
    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }
    fn dial(
        &mut self,
        address: Multiaddr,
        options: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        if !self.book.lock().allows_dial(&address) {
            return Err(TransportError::MultiaddrNotSupported(address));
        }
        self.inner.dial(address, options)
    }
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll(cx)
    }
}

pub(crate) fn tcp(
    key: &libp2p::identity::Keypair,
    book: discovery::SharedBook,
) -> Result<
    libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let transport = Filtered {
        inner: libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true)),
        book,
    }
    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
    .authenticate(libp2p::noise::Config::new(key)?)
    .multiplex(super::yamux_config())
    .map(|(peer, muxer), _| (peer, libp2p::core::muxing::StreamMuxerBox::new(muxer)))
    .boxed();
    Ok(SystemDns::new(transport).boxed())
}

#[cfg(test)]
mod tests;
