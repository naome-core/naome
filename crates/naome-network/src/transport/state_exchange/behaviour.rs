//! Select a separately budgeted codec only after Noise has authenticated the peer.
use super::codec::{STATE_PROTOCOL, StateCodec};
use super::{StateConfig, WireRequest, WireResponse};
use crate::transport::{REQUEST_TIMEOUT, inbound_retention::InboundRetentionBudget};
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    request_response,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
    },
};
use std::{
    sync::Arc,
    task::{Context, Poll},
};
type Inner = request_response::Behaviour<StateCodec>;

pub(in crate::transport) struct Behaviour {
    peers: Vec<(PeerId, Inner)>,
    recovery: Option<Inner>,
    cursor: usize,
}
impl Behaviour {
    fn configured_inner(config: Option<&StateConfig>) -> Inner {
        let maximum = config.map_or(0, |c| c.maximum);
        let codec = StateCodec {
            context: config.map(|c| c.context),
            maximum,
            global: config.map(|c| Arc::clone(&c.budget)),
            requests: Arc::new(InboundRetentionBudget::new(2, 4 * maximum)),
            responses: Arc::new(InboundRetentionBudget::new(2, 4 * maximum)),
        };
        let protocols = config.map(|_| (STATE_PROTOCOL, request_response::ProtocolSupport::Full));
        Inner::with_codec(
            codec,
            protocols,
            request_response::Config::default()
                .with_request_timeout(REQUEST_TIMEOUT)
                .with_max_concurrent_streams(2),
        )
    }
    pub(in crate::transport) fn new(
        peers: impl Iterator<Item = PeerId>,
        config: Option<&StateConfig>,
    ) -> Self {
        Self {
            peers: peers
                .map(|peer| (peer, Self::configured_inner(config)))
                .collect(),
            recovery: config
                .and_then(|c| c.recovery_registry.as_ref())
                .map(|_| Self::configured_inner(config)),
            cursor: 0,
        }
    }
    fn inner(&mut self, peer: PeerId) -> Option<&mut Inner> {
        self.peers
            .iter_mut()
            .find(|(p, _)| *p == peer)
            .map(|(_, inner)| inner)
            .or(self.recovery.as_mut())
    }
    pub(in crate::transport) fn is_connected(&self, peer: &PeerId) -> bool {
        self.peers.iter().find(|(p, _)| p == peer).map_or_else(
            || {
                self.recovery
                    .as_ref()
                    .is_some_and(|inner| inner.is_connected(peer))
            },
            |(_, inner)| inner.is_connected(peer),
        )
    }
    pub(in crate::transport) fn send_request(
        &mut self,
        peer: &PeerId,
        request: WireRequest,
    ) -> request_response::OutboundRequestId {
        self.inner(*peer)
            .expect("configured state_exchange peer")
            .send_request(peer, request)
    }
    pub(in crate::transport) fn send_response(
        &mut self,
        peer: PeerId,
        channel: request_response::ResponseChannel<WireResponse>,
        response: WireResponse,
    ) -> Result<(), ()> {
        self.inner(peer)
            .expect("configured state_exchange peer")
            .send_response(channel, response)
            .map_err(|_| ())
    }
}
impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = <Inner as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = request_response::Event<WireRequest, WireResponse>;
    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner(peer)
            .ok_or_else(|| {
                ConnectionDenied::new(std::io::Error::other("unconfigured state_exchange peer"))
            })?
            .handle_established_inbound_connection(id, peer, local, remote)
    }
    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        address: &Multiaddr,
        role: Endpoint,
        port: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner(peer)
            .ok_or_else(|| {
                ConnectionDenied::new(std::io::Error::other("unconfigured state_exchange peer"))
            })?
            .handle_established_outbound_connection(id, peer, address, role, port)
    }
    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        let peer = match event {
            FromSwarm::ConnectionEstablished(e) => Some(e.peer_id),
            FromSwarm::ConnectionClosed(e) => Some(e.peer_id),
            FromSwarm::AddressChange(e) => Some(e.peer_id),
            FromSwarm::DialFailure(e) => e.peer_id,
            _ => None,
        };
        if let Some(inner) = peer.and_then(|peer| self.inner(peer)) {
            inner.on_swarm_event(event);
        }
    }
    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner(peer)
            .expect("authenticated configured state_exchange handler")
            .on_connection_handler_event(peer, id, event);
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        for _ in 0..self.peers.len() {
            let index = self.cursor;
            self.cursor = (self.cursor + 1) % self.peers.len();
            if let Poll::Ready(event) = self.peers[index].1.poll(cx) {
                return Poll::Ready(event);
            }
        }
        if let Some(recovery) = self.recovery.as_mut() {
            return recovery.poll(cx);
        }
        Poll::Pending
    }
}
