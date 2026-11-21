//! Negotiate a protocol only on connections to the identities authorized for it.
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm, derive_prelude::Either, dummy,
    },
};
use std::{
    collections::BTreeSet,
    task::{Context, Poll},
};

pub struct PeerProtocols<B> {
    pub inner: B,
    peers: BTreeSet<PeerId>,
}

impl<B> PeerProtocols<B> {
    pub fn new(inner: B, peers: &BTreeSet<PeerId>) -> Self {
        Self {
            inner,
            peers: peers.clone(),
        }
    }
}

impl<B: NetworkBehaviour> NetworkBehaviour for PeerProtocols<B> {
    type ConnectionHandler = Either<THandler<B>, dummy::ConnectionHandler>;
    type ToSwarm = B::ToSwarm;

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.peers.contains(&peer) {
            self.inner
                .handle_established_inbound_connection(id, peer, local, remote)
                .map(Either::Left)
        } else {
            Ok(Either::Right(dummy::ConnectionHandler))
        }
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role: Endpoint,
        port: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.peers.contains(&peer) {
            self.inner
                .handle_established_outbound_connection(id, peer, addr, role, port)
                .map(Either::Left)
        } else {
            Ok(Either::Right(dummy::ConnectionHandler))
        }
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        let peer = match event {
            FromSwarm::ConnectionEstablished(e) => Some(e.peer_id),
            FromSwarm::ConnectionClosed(e) => Some(e.peer_id),
            FromSwarm::AddressChange(e) => Some(e.peer_id),
            FromSwarm::DialFailure(e) => e.peer_id,
            FromSwarm::ListenFailure(e) => e.peer_id,
            FromSwarm::NewExternalAddrOfPeer(e) => Some(e.peer_id),
            _ => None,
        };
        if peer.is_none_or(|p| self.peers.contains(&p)) {
            self.inner.on_swarm_event(event);
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            Either::Left(event) => self.inner.on_connection_handler_event(peer, id, event),
            Either::Right(never) => match never {},
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx).map(|event| event.map_in(Either::Left))
    }
}
