//! Select a separately budgeted codec only after Noise has authenticated the peer.
use super::{
    CANDIDATE_OFFER_MAX_BYTES, CANDIDATE_OFFER_PROTOCOL, CandidateOfferCodec, OfferRequest,
};
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
type Inner = request_response::Behaviour<CandidateOfferCodec>;

pub(in crate::transport) struct Behaviour {
    peers: Vec<(PeerId, Inner)>,
    cursor: usize,
}
impl Behaviour {
    pub(in crate::transport) fn new(peers: impl Iterator<Item = PeerId>) -> Self {
        Self {
            peers: peers
                .map(|peer| {
                    (
                        peer,
                        Inner::with_codec(
                            CandidateOfferCodec::new(Arc::new(InboundRetentionBudget::new(
                                2,
                                2 * CANDIDATE_OFFER_MAX_BYTES,
                            ))),
                            [(
                                CANDIDATE_OFFER_PROTOCOL,
                                request_response::ProtocolSupport::Full,
                            )],
                            request_response::Config::default()
                                .with_request_timeout(REQUEST_TIMEOUT)
                                .with_max_concurrent_streams(1),
                        ),
                    )
                })
                .collect(),
            cursor: 0,
        }
    }
    fn inner(&mut self, peer: PeerId) -> Option<&mut Inner> {
        self.peers
            .iter_mut()
            .find(|(p, _)| *p == peer)
            .map(|(_, inner)| inner)
    }
    pub(in crate::transport) fn is_connected(&self, peer: &PeerId) -> bool {
        self.peers
            .iter()
            .find(|(p, _)| p == peer)
            .is_some_and(|(_, inner)| inner.is_connected(peer))
    }
    pub(in crate::transport) fn send_request(
        &mut self,
        peer: &PeerId,
        request: OfferRequest,
    ) -> request_response::OutboundRequestId {
        self.inner(*peer)
            .expect("configured offer peer")
            .send_request(peer, request)
    }
    pub(in crate::transport) fn send_response(
        &mut self,
        peer: PeerId,
        channel: request_response::ResponseChannel<[u8; 32]>,
        response: [u8; 32],
    ) -> Result<(), [u8; 32]> {
        self.inner(peer)
            .ok_or(response)?
            .send_response(channel, response)
    }
}
impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = <Inner as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = request_response::Event<OfferRequest, [u8; 32]>;
    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner(peer)
            .ok_or_else(|| ConnectionDenied::new(std::io::Error::other("unconfigured offer peer")))?
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
            .ok_or_else(|| ConnectionDenied::new(std::io::Error::other("unconfigured offer peer")))?
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
            .expect("authenticated configured offer handler")
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
        Poll::Pending
    }
}
