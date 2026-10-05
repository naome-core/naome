//! Enforce contact admission at the Noise-authenticated connection boundary,
//! including connections initiated by Kademlia or DCUtR internally.

use super::SharedBook;
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    swarm::{
        ConnectionDenied, ConnectionId, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm, behaviour::FromSwarm, dummy,
    },
};
use std::{
    convert::Infallible,
    task::{Context, Poll},
    time::Instant,
};

pub(crate) struct Gate(pub SharedBook);

fn denied(error: String) -> ConnectionDenied {
    ConnectionDenied::new(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        error,
    ))
}

impl NetworkBehaviour for Gate {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let peer = peer.ok_or_else(|| denied("routing requires a target peer ID".into()))?;
        let mut book = self.0.lock();
        book.admit(peer, Instant::now()).map_err(denied)?;
        Ok(Vec::new())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.0
            .lock()
            .accepts_inbound(peer, local, remote)
            .map_err(denied)?;
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        remote: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.0
            .lock()
            .accepts_endpoint(peer, remote)
            .map_err(denied)?;
        Ok(dummy::ConnectionHandler)
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }
    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
    fn on_swarm_event(&mut self, _: FromSwarm) {}
}
