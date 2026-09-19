//! Authenticated research envelopes sharing the fixed Noise/Yamux sessions.
use super::inbound_retention::{InboundRetentionBudget, InboundRetentionPermit};
use super::{
    NetworkEvent, PeerId, PendingBudget, PendingPermit, RequestStartError, StaticArtifactNetwork,
    StaticPeer,
};
use libp2p::{Multiaddr, identity, request_response};
use naome_ledger::profile::Genesis;
pub use naome_protocol::state_exchange::*;
use sha2::{Digest, Sha256};
use std::{fmt, net::SocketAddr, sync::Arc};
mod behaviour;
mod codec;
pub(super) use behaviour::Behaviour;

pub(super) struct ResearchConfig {
    context: ResearchContext,
    maximum: usize,
    budget: Arc<InboundRetentionBudget>,
    outbound: Arc<InboundRetentionBudget>,
    listen: Multiaddr,
}
struct Custody {
    _global: InboundRetentionPermit,
    peer: Option<InboundRetentionPermit>,
}
impl fmt::Debug for Custody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResearchCustody")
    }
}
#[derive(Debug)]
pub(super) struct WireRequest {
    request: ResearchRequest,
    custody: Arc<Custody>,
}
#[derive(Debug)]
pub(super) struct WireResponse {
    response: ResearchResponse,
    _custody: Arc<Custody>,
}
pub(super) struct PendingResearch {
    pub(super) peer_index: usize,
    request: ResearchRequest,
    digest: [u8; 32],
    custody: Arc<Custody>,
    permit: PendingPermit,
    outbound_slot: InboundRetentionPermit,
}
#[derive(Debug)]
#[must_use]
pub struct InboundResearch {
    peer: PeerId,
    wire: WireRequest,
    channel: request_response::ResponseChannel<WireResponse>,
}
impl InboundResearch {
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }
    pub fn request(&self) -> &ResearchRequest {
        &self.wire.request
    }
}
#[must_use]
pub struct ResearchTicket {
    id: request_response::OutboundRequestId,
    peer: PeerId,
    digest: [u8; 32],
    budget: Arc<PendingBudget>,
    _custody: Arc<Custody>,
}
impl fmt::Debug for ResearchTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResearchTicket")
            .field("peer", &self.peer)
            .field("id", &self.id)
            .finish()
    }
}
impl ResearchTicket {
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }
    pub fn accepts_event(&self, event: &ResearchEvent) -> bool {
        self.id == event.id
            && self.peer == event.peer
            && self.digest == event.digest
            && Arc::ptr_eq(&self.budget, &event.permit.budget)
    }
    pub fn complete(
        self,
        event: ResearchEvent,
    ) -> Result<Result<ResearchReceivedResponse, ResearchFailure>, Box<ResearchMismatch>> {
        if !self.accepts_event(&event) {
            return Err(Box::new(ResearchMismatch {
                ticket: self,
                event,
            }));
        }
        Ok(event.result.map(|wire| ResearchReceivedResponse {
            wire,
            _permit: event.permit,
            _outbound_slot: event.outbound_slot,
            _request_custody: event.custody,
        }))
    }
}
#[must_use]
pub struct ResearchEvent {
    id: request_response::OutboundRequestId,
    peer: PeerId,
    digest: [u8; 32],
    result: Result<WireResponse, ResearchFailure>,
    custody: Arc<Custody>,
    permit: PendingPermit,
    outbound_slot: InboundRetentionPermit,
}
impl ResearchEvent {
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }
}
impl fmt::Debug for ResearchEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResearchEvent")
            .field("peer", &self.peer)
            .field("id", &self.id)
            .field("result", &self.result)
            .finish()
    }
}
#[derive(Debug)]
#[must_use]
pub struct ResearchMismatch {
    ticket: ResearchTicket,
    event: ResearchEvent,
}
impl ResearchMismatch {
    pub fn into_parts(self) -> (ResearchTicket, ResearchEvent) {
        (self.ticket, self.event)
    }
}
#[must_use]
pub struct ResearchReceivedResponse {
    wire: WireResponse,
    _permit: PendingPermit,
    _outbound_slot: InboundRetentionPermit,
    _request_custody: Arc<Custody>,
}
impl ResearchReceivedResponse {
    pub fn response(&self) -> &ResearchResponse {
        &self.wire.response
    }
}
impl fmt::Debug for ResearchReceivedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResearchReceivedResponse")
            .field("response", &self.wire.response)
            .finish()
    }
}
#[derive(Debug)]
pub enum ResearchFailure {
    Transport(request_response::OutboundFailure),
    Correlation,
}
#[derive(Debug)]
pub enum ResearchStartError {
    Transport(RequestStartError),
    NotConfigured,
    Wire(ResearchWireError),
    Capacity,
}
#[derive(Debug)]
pub enum ResearchRespondError {
    NotConfigured,
    Wire(ResearchWireError),
    Capacity,
    ChannelClosed,
}
#[derive(Debug)]
pub enum ResearchNetworkBuildError {
    Transport(super::BuildError),
    Identity,
    Endpoint,
    Limits,
}
macro_rules! debug_error { ($($ty:ty),+) => { $(impl fmt::Display for $ty { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { write!(f,"{self:?}") } } impl std::error::Error for $ty {})+ }; }
debug_error!(
    ResearchFailure,
    ResearchStartError,
    ResearchRespondError,
    ResearchNetworkBuildError
);
fn fingerprint(request: &ResearchRequest) -> [u8; 32] {
    Sha256::digest(request.to_wire_bytes()).into()
}

/// Converts a registered Ed25519 transport key into its authenticated peer identity.
pub fn research_peer_id(transport_key: [u8; 32]) -> Result<PeerId, ResearchNetworkBuildError> {
    let key = identity::ed25519::PublicKey::try_from_bytes(&transport_key)
        .map_err(|_| ResearchNetworkBuildError::Identity)?;
    Ok(identity::PublicKey::from(key).to_peer_id())
}

impl StaticArtifactNetwork {
    /// Uses only the immutable genesis transport keys and literal TCP endpoints.
    pub fn new_research(
        identity: identity::Keypair,
        genesis: &Genesis,
    ) -> Result<Self, ResearchNetworkBuildError> {
        let local = identity.public().to_peer_id();
        let mut peers = Vec::new();
        let mut listen = None;
        for validator in genesis.validators() {
            let peer = research_peer_id(validator.transport_key)?;
            let endpoint: SocketAddr = validator
                .endpoint
                .parse()
                .map_err(|_| ResearchNetworkBuildError::Endpoint)?;
            if matches!(endpoint, SocketAddr::V6(a) if a.scope_id() != 0 || a.flowinfo() != 0) {
                return Err(ResearchNetworkBuildError::Endpoint);
            }
            let address: Multiaddr = match endpoint {
                SocketAddr::V4(a) => format!("/ip4/{}/tcp/{}", a.ip(), a.port()),
                SocketAddr::V6(a) => format!("/ip6/{}/tcp/{}", a.ip(), a.port()),
            }
            .parse()
            .map_err(|_| ResearchNetworkBuildError::Endpoint)?;
            if peer == local {
                listen = Some(address);
            } else {
                peers.push(StaticPeer::new(peer, address));
            }
        }
        let listen = listen.ok_or(ResearchNetworkBuildError::Identity)?;
        let maximum = usize::try_from(genesis.profile().limits().transport_frame_bytes)
            .map_err(|_| ResearchNetworkBuildError::Limits)?;
        let frames = usize::try_from(genesis.profile().limits().transport_buffer_frames)
            .map_err(|_| ResearchNetworkBuildError::Limits)?;
        if !(RESEARCH_FRAME_HEADER_BYTES..=RESEARCH_MAX_FRAME_BYTES).contains(&maximum)
            || frames == 0
        {
            return Err(ResearchNetworkBuildError::Limits);
        }
        let bytes = maximum
            .checked_mul(frames)
            .ok_or(ResearchNetworkBuildError::Limits)?;
        let config = ResearchConfig {
            context: ResearchContext::new(
                *genesis.id().as_bytes(),
                *genesis.profile().id().as_bytes(),
            ),
            maximum,
            budget: Arc::new(InboundRetentionBudget::new(frames, bytes)),
            outbound: Arc::new(InboundRetentionBudget::new(super::MAX_STATIC_PEERS, 0)),
            listen,
        };
        let mut network =
            Self::build(identity, peers.clone()).map_err(ResearchNetworkBuildError::Transport)?;
        network.swarm.behaviour_mut().state_exchange =
            Behaviour::new(peers.iter().map(StaticPeer::peer_id), Some(&config));
        network.research = Some(config);
        Ok(network)
    }
    pub fn research_listen_address(&self) -> Option<&Multiaddr> {
        self.research.as_ref().map(|c| &c.listen)
    }
    /// The immutable run context required by every research frame.
    pub fn research_context(&self) -> Option<ResearchContext> {
        self.research.as_ref().map(|c| c.context)
    }
    /// Local partition control; this cannot authorize a key absent from genesis.
    pub fn set_research_peer_enabled(
        &mut self,
        peer: PeerId,
        enabled: bool,
    ) -> Result<(), ResearchStartError> {
        if self.research.is_none() || !self.is_configured_peer(&peer) {
            return Err(ResearchStartError::NotConfigured);
        }
        if enabled {
            self.swarm.behaviour_mut().allowed.allow_peer(peer);
        } else {
            self.swarm.behaviour_mut().allowed.disallow_peer(peer);
            let _ = self.swarm.disconnect_peer_id(peer);
        }
        Ok(())
    }
    pub fn request_research(
        &mut self,
        peer: PeerId,
        body: ResearchRequestBody,
    ) -> Result<ResearchTicket, ResearchStartError> {
        let config = self
            .research
            .as_ref()
            .ok_or(ResearchStartError::NotConfigured)?;
        let request = ResearchRequest::new(config.context, body, config.maximum)
            .map_err(ResearchStartError::Wire)?;
        let custody = Arc::new(Custody {
            _global: InboundRetentionBudget::try_acquire(&config.budget, 2 * request.wire_len())
                .ok_or(ResearchStartError::Capacity)?,
            peer: None,
        });
        let digest = fingerprint(&request);
        let connected = self.swarm.behaviour().state_exchange.is_connected(&peer)
            && self
                .swarm
                .behaviour()
                .allowed
                .allowed_peers()
                .contains(&peer);
        let (peer_index, permit) = self
            .acquire_request_permit(peer, connected)
            .map_err(ResearchStartError::Transport)?;
        let mut outbound_slot = InboundRetentionBudget::try_acquire(&config.outbound, 0)
            .ok_or(ResearchStartError::Capacity)?;
        if !outbound_slot.bind_peer(peer) {
            return Err(ResearchStartError::Transport(
                RequestStartError::AlreadyPending(peer),
            ));
        }
        let id = self.swarm.behaviour_mut().state_exchange.send_request(
            &peer,
            WireRequest {
                request: request.clone(),
                custody: Arc::clone(&custody),
            },
        );
        let ticket = ResearchTicket {
            id,
            peer,
            digest,
            budget: Arc::clone(&self.pending_budget),
            _custody: Arc::clone(&custody),
        };
        let replaced = self.pending.insert(
            (peer, id),
            PendingResearch {
                peer_index,
                request,
                digest,
                custody,
                permit,
                outbound_slot,
            },
        );
        debug_assert!(replaced.is_none());
        Ok(ticket)
    }
    pub fn respond_research(
        &mut self,
        inbound: InboundResearch,
        body: ResearchResponseBody,
    ) -> Result<(), ResearchRespondError> {
        let config = self
            .research
            .as_ref()
            .ok_or(ResearchRespondError::NotConfigured)?;
        let response = ResearchResponse::new(
            config.context,
            fingerprint(inbound.request()),
            body,
            config.maximum,
        )
        .map_err(ResearchRespondError::Wire)?;
        if !response.matches_request(inbound.request()) {
            return Err(ResearchRespondError::Wire(ResearchWireError::ResponseKind));
        }
        let custody = Arc::new(Custody {
            _global: InboundRetentionBudget::try_acquire(&config.budget, 2 * response.wire_len())
                .ok_or(ResearchRespondError::Capacity)?,
            peer: None,
        });
        self.swarm
            .behaviour_mut()
            .state_exchange
            .send_response(
                inbound.peer,
                inbound.channel,
                WireResponse {
                    response,
                    _custody: custody,
                },
            )
            .map_err(|_| ResearchRespondError::ChannelClosed)
    }
    pub(super) fn handle_research_event(
        &mut self,
        event: request_response::Event<WireRequest, WireResponse>,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    mut request,
                    channel,
                    ..
                } => {
                    if !self.is_configured_peer(&peer)
                        || !Arc::get_mut(&mut request.custody)?
                            .peer
                            .as_mut()?
                            .bind_peer(peer)
                    {
                        return None;
                    }
                    Some(NetworkEvent::InboundResearch(InboundResearch {
                        peer,
                        wire: request,
                        channel,
                    }))
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => self.finish_research(request_id, peer, Ok(response)),
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => self.finish_research(request_id, peer, Err(ResearchFailure::Transport(error))),
            request_response::Event::InboundFailure { .. }
            | request_response::Event::ResponseSent { .. } => None,
        }
    }
    fn finish_research(
        &mut self,
        id: request_response::OutboundRequestId,
        actual: PeerId,
        mut result: Result<WireResponse, ResearchFailure>,
    ) -> Option<NetworkEvent> {
        let pending = self.pending.remove(&(actual, id))?;
        let peer = self.pending_peer_id(pending.peer_index);
        if peer != actual
            || result.as_ref().is_ok_and(|wire| {
                wire.response.request_digest() != &pending.digest
                    || !wire.response.matches_request(&pending.request)
            })
        {
            result = Err(ResearchFailure::Correlation);
        }
        Some(NetworkEvent::OutboundResearch(ResearchEvent {
            id,
            peer,
            digest: pending.digest,
            result,
            custody: pending.custody,
            permit: pending.permit,
            outbound_slot: pending.outbound_slot,
        }))
    }
}
#[cfg(test)]
mod tests;
