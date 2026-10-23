// Copyright 2018 Parity Technologies (UK) Ltd.
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

mod iface;
mod socket;
mod timer;

use std::{
    cmp,
    collections::{
        hash_map::{Entry, HashMap},
        VecDeque,
    },
    convert::Infallible,
    fmt,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::Instant,
};

use futures::{channel::mpsc, Stream, StreamExt};
use if_watch::IfEvent;
use libp2p_core::{transport::PortUse, Endpoint, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    behaviour::FromSwarm, dummy, ConnectionDenied, ConnectionId, ListenAddresses, NetworkBehaviour,
    THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use smallvec::SmallVec;

use self::iface::InterfaceState;
use crate::{
    behaviour::{socket::AsyncSocket, timer::Builder},
    Config,
};

/// An abstraction to allow for compatibility with various async runtimes.
pub trait Provider: 'static {
    /// The Async Socket type.
    type Socket: AsyncSocket;
    /// The Async Timer type.
    type Timer: Builder + Stream;
    /// The IfWatcher type.
    type Watcher: Stream<Item = std::io::Result<IfEvent>> + fmt::Debug + Unpin;

    type TaskHandle: Abort;

    /// Create a new instance of the `IfWatcher` type.
    fn new_watcher() -> Result<Self::Watcher, std::io::Error>;

    #[track_caller]
    fn spawn(task: impl Future<Output = ()> + Send + 'static) -> Self::TaskHandle;
}

#[allow(unreachable_pub)] // Not re-exported.
pub trait Abort {
    fn abort(self);
}

/// The type of a [`Behaviour`] using the `tokio` implementation.
#[cfg(feature = "tokio")]
pub mod tokio {
    use std::future::Future;

    use if_watch::tokio::IfWatcher;
    use tokio::task::JoinHandle;

    use super::Provider;
    use crate::behaviour::{socket::tokio::TokioUdpSocket, timer::tokio::TokioTimer, Abort};

    #[doc(hidden)]
    pub enum Tokio {}

    impl Provider for Tokio {
        type Socket = TokioUdpSocket;
        type Timer = TokioTimer;
        type Watcher = IfWatcher;
        type TaskHandle = JoinHandle<()>;

        fn new_watcher() -> Result<Self::Watcher, std::io::Error> {
            IfWatcher::new()
        }

        fn spawn(task: impl Future<Output = ()> + Send + 'static) -> Self::TaskHandle {
            tokio::spawn(task)
        }
    }

    impl Abort for JoinHandle<()> {
        fn abort(self) {
            JoinHandle::abort(&self)
        }
    }

    pub type Behaviour = super::Behaviour<Tokio>;
}

/// A `NetworkBehaviour` for mDNS. Automatically discovers peers on the local network and adds
/// them to the topology.
#[derive(Debug)]
pub struct Behaviour<P>
where
    P: Provider,
{
    /// InterfaceState config.
    config: Config,
    limits: crate::CacheLimits,

    /// Iface watcher.
    if_watch: P::Watcher,

    /// Handles to tasks running the mDNS queries.
    if_tasks: HashMap<IpAddr, P::TaskHandle>,

    query_response_receiver: mpsc::Receiver<(PeerId, Multiaddr, Instant)>,
    query_response_sender: mpsc::Sender<(PeerId, Multiaddr, Instant)>,

    /// List of nodes that we have discovered, the address, and when their TTL expires.
    ///
    /// Each combination of `PeerId` and `Multiaddr` can only appear once, but the same `PeerId`
    /// can appear multiple times.
    discovered_nodes: SmallVec<[(PeerId, Multiaddr, Instant); 8]>,

    /// Future that fires when the TTL of at least one node in `discovered_nodes` expires.
    ///
    /// `None` if `discovered_nodes` is empty.
    closest_expiration: Option<P::Timer>,

    /// The current set of listen addresses.
    ///
    /// This is shared across all interface tasks using an [`RwLock`].
    /// The [`Behaviour`] updates this upon new [`FromSwarm`]
    /// events where as [`InterfaceState`]s read from it to answer inbound mDNS queries.
    listen_addresses: Arc<RwLock<ListenAddresses>>,

    local_peer_id: PeerId,

    /// Pending behaviour events to be emitted.
    pending_events: VecDeque<ToSwarm<Event, Infallible>>,
}

impl<P> Behaviour<P>
where
    P: Provider,
{
    /// Builds a new `Mdns` behaviour.
    pub fn new(
        config: Config,
        local_peer_id: PeerId,
        limits: crate::CacheLimits,
    ) -> io::Result<Self> {
        if limits.peers == 0
            || limits.addresses_per_peer == 0
            || limits.address_bytes == 0
            || limits.responses == 0
            || limits.interfaces == 0
            || limits
                .peers
                .checked_mul(limits.addresses_per_peer)
                .is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid mDNS custody limits",
            ));
        }
        let (tx, rx) = mpsc::channel(limits.responses);

        Ok(Self {
            config,
            limits,
            if_watch: P::new_watcher()?,
            if_tasks: Default::default(),
            query_response_receiver: rx,
            query_response_sender: tx,
            discovered_nodes: Default::default(),
            closest_expiration: Default::default(),
            listen_addresses: Default::default(),
            local_peer_id,
            pending_events: Default::default(),
        })
    }

    /// Returns the list of nodes that we have discovered through mDNS and that are not expired.
    pub fn discovered_nodes(&self) -> impl ExactSizeIterator<Item = &PeerId> {
        self.discovered_nodes.iter().map(|(p, _, _)| p)
    }

    /// Revoke cached addresses immediately using the current admission owner.
    pub fn retain_nodes(&mut self, mut keep: impl FnMut(&PeerId) -> bool) {
        let mut expired = Vec::new();
        self.discovered_nodes.retain(|(peer, address, _)| {
            if keep(peer) {
                true
            } else {
                expired.push((*peer, address.clone()));
                false
            }
        });
        if !expired.is_empty() {
            self.pending_events
                .push_back(ToSwarm::GenerateEvent(Event::Expired(expired)));
        }
    }
    fn observe(&mut self, peer: PeerId, address: &Multiaddr, expiration: Instant) -> bool {
        if let Some((_, _, expires)) = self
            .discovered_nodes
            .iter_mut()
            .find(|(p, a, _)| *p == peer && a == address)
        {
            *expires = cmp::max(*expires, expiration);
            return false;
        }
        let peer_addresses = self
            .discovered_nodes
            .iter()
            .filter(|(p, _, _)| *p == peer)
            .count();
        if address.len() > self.limits.address_bytes
            || peer_addresses >= self.limits.addresses_per_peer
            || peer_addresses == 0
                && self
                    .discovered_nodes
                    .iter()
                    .map(|(p, _, _)| p)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    >= self.limits.peers
        {
            tracing::debug!(%peer,"mDNS discovery custody capacity");
            return false;
        }
        self.discovered_nodes
            .push((peer, address.clone(), expiration));
        true
    }
}

impl<P> NetworkBehaviour for Behaviour<P>
where
    P: Provider,
{
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let Some(peer_id) = maybe_peer else {
            return Ok(vec![]);
        };

        Ok(self
            .discovered_nodes
            .iter()
            .filter(|(peer, _, _)| peer == &peer_id)
            .map(|(_, addr, _)| addr.clone())
            .collect())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        ev: THandlerOutEvent<Self>,
    ) {
        libp2p_core::util::unreachable(ev)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.listen_addresses
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .on_swarm_event(&event);
    }

    #[tracing::instrument(level = "trace", name = "NetworkBehaviour::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            // Check for pending events and emit them.
            if let Some(event) = self.pending_events.pop_front() {
                return Poll::Ready(event);
            }

            // Poll ifwatch.
            while let Poll::Ready(Some(event)) = Pin::new(&mut self.if_watch).poll_next(cx) {
                match event {
                    Ok(IfEvent::Up(inet)) => {
                        if self.if_tasks.len() >= self.limits.interfaces
                            && !self.if_tasks.contains_key(&inet.addr())
                        {
                            tracing::debug!("mDNS interface capacity");
                            continue;
                        }
                        let addr = inet.addr();
                        if addr.is_loopback() {
                            continue;
                        }
                        if addr.is_ipv4() && self.config.enable_ipv6
                            || addr.is_ipv6() && !self.config.enable_ipv6
                        {
                            continue;
                        }
                        if let Entry::Vacant(e) = self.if_tasks.entry(addr) {
                            match InterfaceState::<P::Socket, P::Timer>::new(
                                addr,
                                self.config.clone(),
                                self.local_peer_id,
                                self.listen_addresses.clone(),
                                self.query_response_sender.clone(),
                            ) {
                                Ok(iface_state) => {
                                    e.insert(P::spawn(iface_state));
                                }
                                Err(err) => {
                                    tracing::error!("failed to create `InterfaceState`: {}", err)
                                }
                            }
                        }
                    }
                    Ok(IfEvent::Down(inet)) => {
                        if let Some(handle) = self.if_tasks.remove(&inet.addr()) {
                            tracing::info!(instance=%inet.addr(), "dropping instance");

                            handle.abort();
                        }
                    }
                    Err(err) => tracing::error!("if watch returned an error: {}", err),
                }
            }
            // Emit discovered event.
            let mut discovered = Vec::new();

            while let Poll::Ready(Some((peer, addr, expiration))) =
                self.query_response_receiver.poll_next_unpin(cx)
            {
                if self.observe(peer, &addr, expiration) {
                    discovered.push((peer, addr.clone()));
                    self.pending_events
                        .push_back(ToSwarm::NewExternalAddrOfPeer {
                            peer_id: peer,
                            address: addr,
                        });
                }
            }

            if !discovered.is_empty() {
                let event = Event::Discovered(discovered);
                // Push to the front of the queue so that the behavior event is reported before
                // the individual discovered addresses.
                self.pending_events
                    .push_front(ToSwarm::GenerateEvent(event));
                continue;
            }
            // Emit expired event.
            let now = Instant::now();
            let mut closest_expiration = None;
            let mut expired = Vec::new();
            self.discovered_nodes.retain(|(peer, addr, expiration)| {
                if *expiration <= now {
                    tracing::info!(%peer, address=%addr, "expired peer on address");
                    expired.push((*peer, addr.clone()));
                    return false;
                }
                closest_expiration =
                    Some(closest_expiration.unwrap_or(*expiration).min(*expiration));
                true
            });
            if !expired.is_empty() {
                let event = Event::Expired(expired);
                self.pending_events.push_back(ToSwarm::GenerateEvent(event));
                continue;
            }
            if let Some(closest_expiration) = closest_expiration {
                let mut timer = P::Timer::at(closest_expiration);
                let _ = Pin::new(&mut timer).poll_next(cx);

                self.closest_expiration = Some(timer);
            }

            return Poll::Pending;
        }
    }
}

/// Event that can be produced by the `Mdns` behaviour.
#[derive(Debug, Clone)]
pub enum Event {
    /// Discovered nodes through mDNS.
    Discovered(Vec<(PeerId, Multiaddr)>),

    /// The given combinations of `PeerId` and `Multiaddr` have expired.
    ///
    /// Each discovered record has a time-to-live. When this TTL expires and the address hasn't
    /// been refreshed, we remove it from the list and emit it as an `Expired` event.
    Expired(Vec<(PeerId, Multiaddr)>),
}

#[cfg(all(test, feature = "tokio"))]
mod custody_tests {
    use super::tokio::Behaviour as Mdns;
    use super::{Config, Instant};
    use libp2p_core::Multiaddr;
    use std::time::Duration;
    #[tokio::test]
    async fn discovery_custody_bounds_population_addresses_and_retirement() {
        let peer = || {
            libp2p_identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id()
        };
        let limits = crate::CacheLimits {
            peers: 2,
            addresses_per_peer: 1,
            address_bytes: 64,
            responses: 2,
            interfaces: 1,
        };
        let mut behaviour = Mdns::new(Config::default(), peer(), limits).unwrap();
        let [a, b, c] = [peer(), peer(), peer()];
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
        let alternate: Multiaddr = "/ip4/127.0.0.1/tcp/2".parse().unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        assert!(behaviour.observe(a, &address, until));
        assert!(!behaviour.observe(a, &alternate, until));
        assert!(behaviour.observe(b, &address, until));
        assert!(!behaviour.observe(c, &address, until));
        assert!(!behaviour.observe(a, &address, until + Duration::from_secs(1)));
        assert_eq!(behaviour.discovered_nodes.len(), 2);
        behaviour.retain_nodes(|peer| *peer != a);
        assert_eq!(behaviour.discovered_nodes.len(), 1);
        assert!(behaviour.observe(c, &address, until));
        assert_eq!(behaviour.discovered_nodes.len(), 2);
    }
}
