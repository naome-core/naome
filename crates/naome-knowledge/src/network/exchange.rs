//! Request/response mechanics borrow routing addresses from the bounded contact
//! owner. Library hints never create a second, independently retained cache.
use super::*;
use libp2p::{
    core::{Endpoint, transport::PortUse},
    swarm::{ConnectionDenied, FromSwarm, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm},
};
use std::{
    ops::{Deref, DerefMut},
    task::{Context, Poll},
};
type Inner = request_response::Behaviour<Codec>;
pub(super) struct Exchange {
    inner: Inner,
    book: discovery::SharedBook,
}
impl Exchange {
    pub(super) fn new(inner: Inner, book: discovery::SharedBook) -> Self {
        Self { inner, book }
    }
}
impl Deref for Exchange {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.inner
    }
}
impl DerefMut for Exchange {
    fn deref_mut(&mut self) -> &mut Inner {
        &mut self.inner
    }
}
impl NetworkBehaviour for Exchange {
    type ConnectionHandler = <Inner as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = <Inner as NetworkBehaviour>::ToSwarm;
    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(id, local, remote)
    }
    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner
            .handle_established_inbound_connection(id, peer, local, remote)
    }
    fn handle_pending_outbound_connection(
        &mut self,
        _id: ConnectionId,
        peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let book = self.book.lock();
        Ok(peer
            .and_then(|peer| book.contacts.get(&peer))
            .filter(|contact| contact.enabled && !contact.infrastructure)
            .map(|contact| contact.addresses.iter().cloned().collect())
            .unwrap_or_default())
    }
    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        remote: &Multiaddr,
        role: Endpoint,
        port: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner
            .handle_established_outbound_connection(id, peer, remote, role, port)
    }
    fn on_swarm_event(&mut self, event: FromSwarm) {
        if matches!(event, FromSwarm::NewExternalAddrOfPeer(_)) {
            return;
        }
        self.inner.on_swarm_event(event);
    }
    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner.on_connection_handler_event(peer, id, event);
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx)
    }
}
