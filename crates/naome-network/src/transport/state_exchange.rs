//! Authenticated state_exchange envelopes sharing the fixed Noise/Yamux sessions.
use super::inbound_retention::{InboundRetentionBudget, InboundRetentionPermit};
use super::rate_limit::TokenBucket;
use super::{
    NetworkEvent, PeerId, PendingBudget, PendingPermit, RecoveryLease, RequestStartError,
    StateNetwork, StaticPeer,
};
use libp2p::{
    Multiaddr, identity, request_response,
    swarm::{ConnectionId, DialError},
};
use naome_ledger::{
    authority::{AuthoritySnapshot, HandoffPlan, PeriodKeys},
    profile::Genesis,
    state::LedgerState,
    time::TimeCertificate,
};
pub use naome_protocol::state_exchange::*;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::Instant;
mod behaviour;
mod codec;
mod recovery;
pub(super) use behaviour::Behaviour;
pub use recovery::{RECOVERY_HELLO_BYTES, RecoveryError, RecoveryHello};

pub(super) struct StateConfig {
    context: StateContext,
    maximum: usize,
    budget: Arc<InboundRetentionBudget>,
    outbound: Arc<InboundRetentionBudget>,
    listen: Option<Multiaddr>,
    lane: StateLane,
    selected_authority: [u8; 32],
    active_peers: HashSet<PeerId>,
    courier_peers: HashSet<PeerId>,
    recovery_registry: Option<Arc<LedgerState>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateLane {
    Active,
    Handoff,
    Recovery,
}
impl StateLane {
    fn permits(self, active: bool, body: &StateRequestBody) -> bool {
        use StateRequestBody as R;
        match body {
            R::Handshake
            | R::History { .. }
            | R::PendingAgreement { .. }
            | R::Proof { .. }
            | R::Offer(_)
            | R::CandidateOffer(_)
            | R::Agreement(_)
            | R::ReadySignature(_)
            | R::TerminalSignature(_)
            | R::Finalized(_) => true,
            R::TimeReport(_) | R::UserAction(_) | R::Proposal(_) | R::Vote(_) => {
                self == Self::Active && active
            }
            R::RecoveryChallenge | R::RecoveryHello(_) => false,
        }
    }
}
fn permits_recovery(granted: bool, body: &StateRequestBody) -> bool {
    use StateRequestBody as R;
    match body {
        R::RecoveryChallenge | R::RecoveryHello(_) => true,
        R::Handshake
        | R::History { .. }
        | R::PendingAgreement { .. }
        | R::Proof { .. }
        | R::Finalized(_)
        | R::Offer(_)
        | R::CandidateOffer(_)
        | R::Agreement(_)
        | R::ReadySignature(_)
        | R::TerminalSignature(_) => granted,
        R::TimeReport(_) | R::UserAction(_) | R::Proposal(_) | R::Vote(_) => false,
    }
}
fn permits_reverse_recovery(body: &StateRequestBody) -> bool {
    matches!(
        body,
        StateRequestBody::Offer(_)
            | StateRequestBody::CandidateOffer(_)
            | StateRequestBody::Agreement(_)
            | StateRequestBody::ReadySignature(_)
            | StateRequestBody::TerminalSignature(_)
            | StateRequestBody::Finalized(_)
    )
}
struct Custody {
    _global: InboundRetentionPermit,
    peer: Option<InboundRetentionPermit>,
}
impl fmt::Debug for Custody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StateCustody")
    }
}
#[derive(Debug)]
pub(super) struct WireRequest {
    request: StateRequest,
    custody: Arc<Custody>,
}
#[derive(Debug)]
pub(super) struct WireResponse {
    response: StateResponse,
    _custody: Arc<Custody>,
}
pub(super) struct PendingState {
    pub(super) peer_index: Option<usize>,
    pub(super) request: StateRequest,
    digest: [u8; 32],
    custody: Arc<Custody>,
    permit: PendingPermit,
    outbound_slot: InboundRetentionPermit,
}
#[derive(Debug)]
#[must_use]
pub struct InboundState {
    peer: PeerId,
    recovery_owner: Option<naome_ledger::AccountId>,
    wire: WireRequest,
    channel: request_response::ResponseChannel<WireResponse>,
}
impl InboundState {
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }
    /// Present only for an owner-authenticated history/handoff recovery peer.
    pub const fn recovery_owner(&self) -> Option<naome_ledger::AccountId> {
        self.recovery_owner
    }
    pub fn request(&self) -> &StateRequest {
        &self.wire.request
    }
}
#[must_use]
pub struct StateTicket {
    id: request_response::OutboundRequestId,
    peer: PeerId,
    digest: [u8; 32],
    budget: Arc<PendingBudget>,
    _custody: Arc<Custody>,
}
impl fmt::Debug for StateTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateTicket")
            .field("peer", &self.peer)
            .field("id", &self.id)
            .finish()
    }
}
impl StateTicket {
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }
    pub fn accepts_event(&self, event: &StateEvent) -> bool {
        self.id == event.id
            && self.peer == event.peer
            && self.digest == event.digest
            && Arc::ptr_eq(&self.budget, &event.permit.budget)
    }
    pub fn complete(
        self,
        event: StateEvent,
    ) -> Result<Result<StateReceivedResponse, StateFailure>, Box<StateMismatch>> {
        if !self.accepts_event(&event) {
            return Err(Box::new(StateMismatch {
                ticket: self,
                event,
            }));
        }
        Ok(event.result.map(|wire| StateReceivedResponse {
            wire,
            _permit: event.permit,
            _outbound_slot: event.outbound_slot,
            _request_custody: event.custody,
        }))
    }
}
#[must_use]
pub struct StateEvent {
    id: request_response::OutboundRequestId,
    peer: PeerId,
    digest: [u8; 32],
    result: Result<WireResponse, StateFailure>,
    custody: Arc<Custody>,
    permit: PendingPermit,
    outbound_slot: InboundRetentionPermit,
}
impl StateEvent {
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }
}
impl fmt::Debug for StateEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateEvent")
            .field("peer", &self.peer)
            .field("id", &self.id)
            .field("result", &self.result)
            .finish()
    }
}
#[derive(Debug)]
#[must_use]
pub struct StateMismatch {
    ticket: StateTicket,
    event: StateEvent,
}
impl StateMismatch {
    pub fn into_parts(self) -> (StateTicket, StateEvent) {
        (self.ticket, self.event)
    }
}
#[must_use]
pub struct StateReceivedResponse {
    wire: WireResponse,
    _permit: PendingPermit,
    _outbound_slot: InboundRetentionPermit,
    _request_custody: Arc<Custody>,
}
impl StateReceivedResponse {
    pub fn response(&self) -> &StateResponse {
        &self.wire.response
    }
}
impl fmt::Debug for StateReceivedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateReceivedResponse")
            .field("response", &self.wire.response)
            .finish()
    }
}
#[derive(Debug)]
pub enum StateFailure {
    Transport(request_response::OutboundFailure),
    Correlation,
}
#[derive(Debug)]
pub enum StateStartError {
    Transport(RequestStartError),
    NotConfigured,
    Wire(StateWireError),
    Capacity,
    Lane,
}
#[derive(Debug)]
pub enum StateRespondError {
    NotConfigured,
    Wire(StateWireError),
    Capacity,
    ChannelClosed,
    Lane,
}
#[derive(Debug)]
pub enum StateNetworkBuildError {
    Transport(super::BuildError),
    Identity,
    Endpoint,
    Limits,
    Authority,
}
#[derive(Debug)]
pub enum RecoveryDialError {
    NotConfigured,
    Endpoint,
    Capacity,
    Transport(DialError),
}
macro_rules! debug_error { ($($ty:ty),+) => { $(impl fmt::Display for $ty { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { write!(f,"{self:?}") } } impl std::error::Error for $ty {})+ }; }
debug_error!(
    StateFailure,
    StateStartError,
    StateRespondError,
    StateNetworkBuildError
);
debug_error!(RecoveryDialError);
fn fingerprint(request: &StateRequest) -> [u8; 32] {
    Sha256::digest(request.to_wire_bytes()).into()
}

/// Converts a registered Ed25519 transport key into its authenticated peer identity.
pub fn state_peer_id(transport_key: [u8; 32]) -> Result<PeerId, StateNetworkBuildError> {
    let key = identity::ed25519::PublicKey::try_from_bytes(&transport_key)
        .map_err(|_| StateNetworkBuildError::Identity)?;
    Ok(identity::PublicKey::from(key).to_peer_id())
}

impl StateNetwork {
    /// Initial selected authority at the first record height.
    pub fn new_state(
        identity: identity::Keypair,
        genesis: &Genesis,
    ) -> Result<Self, StateNetworkBuildError> {
        let snapshot = AuthoritySnapshot::from_genesis(genesis)
            .map_err(|_| StateNetworkBuildError::Authority)?;
        Self::new_active(identity, genesis, &snapshot)
    }
    /// A sealed parent's active validators plus its bounded pending candidates.
    pub fn new_for_parent(
        identity: identity::Keypair,
        parent: &LedgerState,
    ) -> Result<Self, StateNetworkBuildError> {
        let mut bindings = Vec::new();
        for unit in parent.authority().units() {
            if let Some(keys) = unit.keys() {
                bindings.push((keys.clone(), true));
            }
        }
        for family in parent.join_queue() {
            let entry = parent
                .join_intent(*family)
                .ok_or(StateNetworkBuildError::Authority)?;
            if entry.expires() <= parent.time() {
                continue;
            }
            let intent = entry.intent();
            bindings.push((
                PeriodKeys::new(
                    *intent.consensus_key(),
                    *intent.transport_key(),
                    intent.endpoint().to_owned(),
                )
                .map_err(|_| StateNetworkBuildError::Authority)?,
                false,
            ));
        }
        Self::from_bindings(
            identity,
            parent.genesis(),
            parent.authority(),
            bindings,
            StateLane::Active,
            36,
            Some(Arc::new(parent.clone())),
        )
    }
    pub fn new_active(
        identity: identity::Keypair,
        genesis: &Genesis,
        authority: &AuthoritySnapshot,
    ) -> Result<Self, StateNetworkBuildError> {
        let bindings = authority
            .units()
            .iter()
            .filter_map(|unit| unit.keys().cloned().map(|keys| (keys, true)))
            .collect();
        Self::from_bindings(
            identity,
            genesis,
            authority,
            bindings,
            StateLane::Active,
            36,
            None,
        )
    }
    /// The incoming prepared authority and the selected outgoing fresh-key couriers.
    pub fn new_staged(
        identity: identity::Keypair,
        parent: &LedgerState,
        plan: &HandoffPlan,
        time: &TimeCertificate,
    ) -> Result<Self, StateNetworkBuildError> {
        let incoming = parent
            .prepare_handoff_certified(plan, time)
            .map_err(|_| StateNetworkBuildError::Authority)?;
        let mut bindings: Vec<(PeriodKeys, bool)> = incoming
            .units()
            .iter()
            .filter_map(|unit| unit.keys().cloned().map(|keys| (keys, true)))
            .collect();
        for offer in plan.offers() {
            if !bindings
                .iter()
                .any(|(keys, _)| keys.transport() == offer.keys().transport())
            {
                bindings.push((offer.keys().clone(), false));
            }
        }
        Self::from_bindings(
            identity,
            parent.genesis(),
            &incoming,
            bindings,
            StateLane::Handoff,
            5,
            Some(Arc::new(parent.clone())),
        )
    }
    /// A vacant or retired owner's fresh transport for authenticated catch-up.
    /// It starts without a listener or ordinary static-peer authority. The
    /// caller may bind a fresh endpoint to serve owner-authenticated history
    /// and finalized evidence without gaining consensus authority.
    pub fn new_recovery_only(
        identity: identity::Keypair,
        last_selected: &LedgerState,
    ) -> Result<Self, StateNetworkBuildError> {
        let public = identity
            .public()
            .try_into_ed25519()
            .map_err(|_| StateNetworkBuildError::Identity)?
            .to_bytes();
        if last_selected.used_period_keys().contains(&public)
            || last_selected.accounts().values().any(|key| *key == public)
        {
            return Err(StateNetworkBuildError::Identity);
        }
        Self::from_bindings(
            identity,
            last_selected.genesis(),
            last_selected.authority(),
            Vec::new(),
            StateLane::Recovery,
            2,
            Some(Arc::new(last_selected.clone())),
        )
    }
    fn from_bindings(
        identity: identity::Keypair,
        genesis: &Genesis,
        authority: &AuthoritySnapshot,
        bindings: Vec<(PeriodKeys, bool)>,
        lane: StateLane,
        maximum_peers: usize,
        recovery_registry: Option<Arc<LedgerState>>,
    ) -> Result<Self, StateNetworkBuildError> {
        if authority.genesis() != genesis.id() || bindings.len() > maximum_peers + 1 {
            return Err(StateNetworkBuildError::Authority);
        }
        let local = identity.public().to_peer_id();
        let mut peers = Vec::new();
        let mut listen = None;
        let mut active_peers = HashSet::new();
        let mut courier_peers = HashSet::new();
        let mut seen = HashSet::new();
        for (keys, active) in bindings {
            let peer = state_peer_id(*keys.transport())?;
            if !seen.insert(peer) {
                return Err(StateNetworkBuildError::Authority);
            }
            let endpoint: SocketAddr = keys
                .endpoint()
                .parse()
                .map_err(|_| StateNetworkBuildError::Endpoint)?;
            if matches!(endpoint, SocketAddr::V6(a) if a.scope_id() != 0 || a.flowinfo() != 0) {
                return Err(StateNetworkBuildError::Endpoint);
            }
            let address: Multiaddr = match endpoint {
                SocketAddr::V4(a) => format!("/ip4/{}/tcp/{}", a.ip(), a.port()),
                SocketAddr::V6(a) => format!("/ip6/{}/tcp/{}", a.ip(), a.port()),
            }
            .parse()
            .map_err(|_| StateNetworkBuildError::Endpoint)?;
            if active {
                active_peers.insert(peer);
            } else {
                courier_peers.insert(peer);
            }
            if peer == local {
                listen = Some(address);
            } else {
                peers.push(StaticPeer::new(peer, address));
            }
        }
        let listen = if lane == StateLane::Recovery {
            None
        } else {
            Some(listen.ok_or(StateNetworkBuildError::Identity)?)
        };
        let maximum = usize::try_from(genesis.profile().limits().transport_frame_bytes)
            .map_err(|_| StateNetworkBuildError::Limits)?;
        let frames = usize::try_from(genesis.profile().limits().transport_buffer_frames)
            .map_err(|_| StateNetworkBuildError::Limits)?;
        if !(STATE_FRAME_HEADER_BYTES..=STATE_MAX_FRAME_BYTES).contains(&maximum) || frames == 0 {
            return Err(StateNetworkBuildError::Limits);
        }
        let bytes = maximum
            .checked_mul(frames)
            .ok_or(StateNetworkBuildError::Limits)?;
        let config = StateConfig {
            context: StateContext::new(
                *genesis.id().as_bytes(),
                *genesis.profile().id().as_bytes(),
            ),
            maximum,
            budget: Arc::new(InboundRetentionBudget::new(frames, bytes)),
            outbound: Arc::new(InboundRetentionBudget::with_peer_limit(
                super::MAX_PENDING_REQUESTS,
                0,
                2,
            )),
            listen,
            lane,
            selected_authority: authority.id(),
            active_peers,
            courier_peers,
            recovery_registry,
        };
        let mut network = Self::build_with_limit(
            identity,
            peers.clone(),
            maximum_peers + usize::from(config.recovery_registry.is_some()) * 2,
            config.recovery_registry.is_some(),
        )
        .map_err(StateNetworkBuildError::Transport)?;
        network.swarm.behaviour_mut().state_exchange =
            Behaviour::new(peers.iter().map(StaticPeer::peer_id), Some(&config));
        network.state_exchange = Some(config);
        Ok(network)
    }
    pub fn state_listen_address(&self) -> Option<&Multiaddr> {
        self.state_exchange.as_ref().and_then(|c| c.listen.as_ref())
    }
    /// The immutable run context required by every state_exchange frame.
    pub fn state_context(&self) -> Option<StateContext> {
        self.state_exchange.as_ref().map(|c| c.context)
    }
    pub fn state_lane(&self) -> Option<StateLane> {
        self.state_exchange.as_ref().map(|c| c.lane)
    }
    pub fn state_authority_id(&self) -> Option<[u8; 32]> {
        self.state_exchange.as_ref().map(|c| c.selected_authority)
    }
    /// Promotes an already authenticated fresh-key handoff transport only
    /// when its complete static roster is exactly the selected authority.
    /// The caller must first verify and durably select the sealed successor.
    pub(super) fn promote_staged_selected(&mut self, selected: &LedgerState) -> bool {
        let Some(config) = self.state_exchange.as_ref() else {
            return false;
        };
        let Some(parent) = config.recovery_registry.as_ref() else {
            return false;
        };
        if config.lane != StateLane::Handoff
            || config.selected_authority != selected.authority().id()
            || config.context.genesis() != selected.genesis().id().as_bytes()
            || config.context.profile() != selected.genesis().profile().id().as_bytes()
            || !config.courier_peers.is_empty()
            // A join intent finalized in this record was not in the parent's
            // staged roster. Rebuild the selected transport with its courier.
            || selected.join_queue().iter().any(|family| {
                selected
                    .join_intent(*family)
                    .is_none_or(|entry| entry.expires() > selected.time())
            })
            || selected.terminated()
            || parent.height().checked_add(1) != Some(selected.height())
            || parent
                .authority()
                .units()
                .iter()
                .zip(selected.authority().units())
                .any(|(old, new)| {
                    old.slot() != new.slot() || old.id() != new.id() || old.owner() != new.owner()
                })
            || !self.recovery_dials.is_empty()
            || !self.recovery_challenges.is_empty()
            || !self.recovery_grants.is_empty()
            || !self.recovery_remote_grants.is_empty()
            || !self.recovery_rates.is_empty()
            || !self.recovery_pending_auth.is_empty()
            || !self.recovery_leases.is_empty()
            || !self.swarm.behaviour().sessions.recovery_idle()
        {
            return false;
        }
        let local = self.local_peer_id();
        let mut exact_peers = HashSet::new();
        let mut local_selected = false;
        for keys in selected
            .authority()
            .units()
            .iter()
            .filter_map(|unit| unit.keys())
        {
            let Ok(peer) = state_peer_id(*keys.transport()) else {
                return false;
            };
            let Ok(endpoint) = keys.endpoint().parse::<SocketAddr>() else {
                return false;
            };
            let Ok(address) = (match endpoint {
                SocketAddr::V4(value) => format!("/ip4/{}/tcp/{}", value.ip(), value.port()),
                SocketAddr::V6(value) => format!("/ip6/{}/tcp/{}", value.ip(), value.port()),
            })
            .parse::<Multiaddr>() else {
                return false;
            };
            if peer == local {
                local_selected = true;
                if config.listen.as_ref() != Some(&address) {
                    return false;
                }
            } else if self.swarm.behaviour().sessions.peer_address(&peer) != Some(&address) {
                return false;
            }
            exact_peers.insert(peer);
        }
        if !local_selected || exact_peers != config.active_peers {
            return false;
        }
        // Old handoff responses can no longer govern the selected period.
        // The caller drops its tickets before trying promotion.
        self.pending.clear();
        let config = self.state_exchange.as_mut().expect("checked state config");
        config.lane = StateLane::Active;
        config.recovery_registry = Some(Arc::new(selected.clone()));
        true
    }
    /// Dials a configured stable endpoint without pinning a stale remote PeerId.
    /// The actual Noise identity is returned in `NetworkEvent::RecoveryConnected`.
    pub fn dial_recovery(&mut self, endpoint: &str) -> Result<ConnectionId, RecoveryDialError> {
        if self
            .state_exchange
            .as_ref()
            .is_none_or(|c| c.recovery_registry.is_none())
        {
            return Err(RecoveryDialError::NotConfigured);
        }
        let socket: SocketAddr = endpoint.parse().map_err(|_| RecoveryDialError::Endpoint)?;
        if socket.port() == 0 || socket.ip().is_unspecified() || socket.to_string() != endpoint {
            return Err(RecoveryDialError::Endpoint);
        }
        let address: Multiaddr = match socket {
            SocketAddr::V4(addr) => format!("/ip4/{}/tcp/{}", addr.ip(), addr.port()),
            SocketAddr::V6(addr) => format!("/ip6/{}/tcp/{}", addr.ip(), addr.port()),
        }
        .parse()
        .map_err(|_| RecoveryDialError::Endpoint)?;
        let opts = self
            .swarm
            .behaviour_mut()
            .sessions
            .recovery_dial(address)
            .ok_or(RecoveryDialError::Capacity)?;
        let connection_id = opts.connection_id();
        if let Err(error) = self.swarm.dial(opts) {
            self.swarm
                .behaviour_mut()
                .sessions
                .cancel_recovery_dial(connection_id);
            return Err(RecoveryDialError::Transport(error));
        }
        self.recovery_dials.insert(connection_id);
        Ok(connection_id)
    }
    /// Drops one nonstatic recovery session and its owner grants. Static
    /// authority peers cannot be disconnected through this API.
    pub fn disconnect_recovery_peer(&mut self, peer: PeerId) -> bool {
        if self.is_configured_peer(&peer)
            || !self.swarm.behaviour().sessions.is_recovery_connected(&peer)
        {
            return false;
        }
        self.recovery_challenges.remove(&peer);
        self.recovery_grants.remove(&peer);
        self.recovery_remote_grants.remove(&peer);
        self.recovery_rates.remove(&peer);
        self.recovery_pending_auth.remove(&peer);
        self.recovery_leases.remove(&peer);
        self.pending.retain(|(pending, _), _| *pending != peer);
        self.swarm.disconnect_peer_id(peer).is_ok()
    }
    /// Local partition control for a selected static peer only.
    pub fn set_state_peer_enabled(
        &mut self,
        peer: PeerId,
        enabled: bool,
    ) -> Result<(), StateStartError> {
        if self.state_exchange.is_none() || !self.is_configured_peer(&peer) {
            return Err(StateStartError::NotConfigured);
        }
        if enabled {
            self.swarm.behaviour_mut().allowed.unblock_peer(peer);
        } else {
            self.swarm.behaviour_mut().allowed.block_peer(peer);
            let _ = self.swarm.disconnect_peer_id(peer);
        }
        Ok(())
    }
    pub fn request_state(
        &mut self,
        peer: PeerId,
        body: StateRequestBody,
    ) -> Result<StateTicket, StateStartError> {
        let config = self
            .state_exchange
            .as_ref()
            .ok_or(StateStartError::NotConfigured)?;
        if !self.is_configured_peer(&peer) {
            return Err(StateStartError::Transport(RequestStartError::UnknownPeer(
                peer,
            )));
        }
        if !config
            .lane
            .permits(config.active_peers.contains(&peer), &body)
            || !(config.active_peers.contains(&peer) || config.courier_peers.contains(&peer))
        {
            return Err(StateStartError::Lane);
        }
        let request = StateRequest::new(config.context, body, config.maximum)
            .map_err(StateStartError::Wire)?;
        let custody = Arc::new(Custody {
            _global: InboundRetentionBudget::try_acquire(&config.budget, 2 * request.wire_len())
                .ok_or(StateStartError::Capacity)?,
            peer: None,
        });
        let digest = fingerprint(&request);
        let connected = self.swarm.behaviour().state_exchange.is_connected(&peer)
            && !self
                .swarm
                .behaviour()
                .allowed
                .blocked_peers()
                .contains(&peer);
        let (peer_index, permit) = self
            .acquire_request_permit(peer, connected, request.body())
            .map_err(StateStartError::Transport)?;
        let mut outbound_slot = InboundRetentionBudget::try_acquire(&config.outbound, 0)
            .ok_or(StateStartError::Capacity)?;
        if !outbound_slot.bind_peer(peer) {
            return Err(StateStartError::Transport(
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
        let ticket = StateTicket {
            id,
            peer,
            digest,
            budget: Arc::clone(&self.pending_budget),
            _custody: Arc::clone(&custody),
        };
        let replaced = self.pending.insert(
            (peer, id),
            PendingState {
                peer_index: Some(peer_index),
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
    /// Sends a challenge, owner proof, or bounded replay/handoff request to an
    /// unknown Noise identity connected through a stable recovery endpoint.
    pub fn request_recovery_state(
        &mut self,
        peer: PeerId,
        body: StateRequestBody,
    ) -> Result<StateTicket, StateStartError> {
        self.request_recovery_with_grant(peer, body, false)
    }
    /// Delivers bounded handoff or finality evidence to a fresh recovery identity whose
    /// owner proof this node has verified on the current connection.
    pub fn request_recovery_evidence_to_owner(
        &mut self,
        peer: PeerId,
        body: StateRequestBody,
    ) -> Result<StateTicket, StateStartError> {
        self.request_recovery_with_grant(peer, body, true)
    }
    fn request_recovery_with_grant(
        &mut self,
        peer: PeerId,
        body: StateRequestBody,
        reverse: bool,
    ) -> Result<StateTicket, StateStartError> {
        let config = self
            .state_exchange
            .as_ref()
            .ok_or(StateStartError::NotConfigured)?;
        let permitted = if reverse {
            self.recovery_grants.contains_key(&peer)
                && permits_reverse_recovery(&body)
                && (config.lane != StateLane::Recovery
                    || matches!(body, StateRequestBody::Finalized(_)))
        } else {
            permits_recovery(self.recovery_remote_grants.contains(&peer), &body)
        };
        if config.recovery_registry.is_none() || self.is_configured_peer(&peer) || !permitted {
            return Err(StateStartError::Lane);
        }
        if !self.swarm.behaviour().sessions.is_recovery_connected(&peer)
            || !self.swarm.behaviour().state_exchange.is_connected(&peer)
            || self
                .swarm
                .behaviour()
                .allowed
                .blocked_peers()
                .contains(&peer)
        {
            return Err(StateStartError::Transport(
                RequestStartError::PeerDisconnected(peer),
            ));
        }
        if self
            .pending
            .keys()
            .any(|(pending_peer, _)| *pending_peer == peer)
        {
            return Err(StateStartError::Transport(
                RequestStartError::AlreadyPending(peer),
            ));
        }
        let request = StateRequest::new(config.context, body, config.maximum)
            .map_err(StateStartError::Wire)?;
        let custody = Arc::new(Custody {
            _global: InboundRetentionBudget::try_acquire(&config.budget, 2 * request.wire_len())
                .ok_or(StateStartError::Capacity)?,
            peer: None,
        });
        let permit =
            PendingBudget::try_acquire(&self.pending_budget).ok_or(StateStartError::Capacity)?;
        let mut outbound_slot = InboundRetentionBudget::try_acquire(&config.outbound, 0)
            .ok_or(StateStartError::Capacity)?;
        if !outbound_slot.bind_peer_exclusive(peer) {
            return Err(StateStartError::Transport(
                RequestStartError::AlreadyPending(peer),
            ));
        }
        let digest = fingerprint(&request);
        let id = self.swarm.behaviour_mut().state_exchange.send_request(
            &peer,
            WireRequest {
                request: request.clone(),
                custody: Arc::clone(&custody),
            },
        );
        let ticket = StateTicket {
            id,
            peer,
            digest,
            budget: Arc::clone(&self.pending_budget),
            _custody: Arc::clone(&custody),
        };
        let previous = self.pending.insert(
            (peer, id),
            PendingState {
                peer_index: None,
                request,
                digest,
                custody,
                permit,
                outbound_slot,
            },
        );
        debug_assert!(previous.is_none());
        Ok(ticket)
    }
    pub fn respond_state(
        &mut self,
        inbound: InboundState,
        body: StateResponseBody,
    ) -> Result<(), StateRespondError> {
        let useful = match &body {
            StateResponseBody::History(items) => !items.is_empty(),
            StateResponseBody::Agreement(Some(_))
            | StateResponseBody::Accepted
            | StateResponseBody::Proof { .. } => true,
            _ => false,
        };
        let recovery_owner = inbound.recovery_owner;
        let peer = inbound.peer;
        let config = self
            .state_exchange
            .as_ref()
            .ok_or(StateRespondError::NotConfigured)?;
        let response = StateResponse::new(
            config.context,
            fingerprint(inbound.request()),
            body,
            config.maximum,
        )
        .map_err(StateRespondError::Wire)?;
        if !response.matches_request(inbound.request()) {
            return Err(StateRespondError::Wire(StateWireError::ResponseKind));
        }
        let custody = Arc::new(Custody {
            _global: InboundRetentionBudget::try_acquire(&config.budget, 2 * response.wire_len())
                .ok_or(StateRespondError::Capacity)?,
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
            .map_err(|_| StateRespondError::ChannelClosed)?;
        if recovery_owner.is_some()
            && useful
            && let Some(lease) = self.recovery_leases.get_mut(&peer)
        {
            lease.useful_response(Instant::now());
        }
        Ok(())
    }
    pub(super) fn handle_state_event(
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
                    if !Arc::get_mut(&mut request.custody)?
                        .peer
                        .as_mut()?
                        .bind_peer(peer)
                    {
                        return None;
                    }
                    let inbound = InboundState {
                        peer,
                        recovery_owner: None,
                        wire: request,
                        channel,
                    };
                    if self.is_configured_peer(&peer) {
                        let allowed = self.state_exchange.as_ref().is_some_and(|config| {
                            config.lane.permits(
                                config.active_peers.contains(&peer),
                                inbound.request().body(),
                            ) && (config.active_peers.contains(&peer)
                                || config.courier_peers.contains(&peer))
                        });
                        return allowed.then_some(NetworkEvent::InboundState(inbound));
                    }
                    self.handle_recovery_inbound(inbound)
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => self.finish_state(request_id, peer, Ok(response)),
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => self.finish_state(request_id, peer, Err(StateFailure::Transport(error))),
            request_response::Event::InboundFailure { .. }
            | request_response::Event::ResponseSent { .. } => None,
        }
    }
    fn finish_state(
        &mut self,
        id: request_response::OutboundRequestId,
        actual: PeerId,
        mut result: Result<WireResponse, StateFailure>,
    ) -> Option<NetworkEvent> {
        let pending = self.pending.remove(&(actual, id))?;
        let peer = pending
            .peer_index
            .map_or(actual, |index| self.pending_peer_id(index));
        if peer != actual
            || result.as_ref().is_ok_and(|wire| {
                wire.response.request_digest() != &pending.digest
                    || !wire.response.matches_request(&pending.request)
            })
        {
            result = Err(StateFailure::Correlation);
        }
        if let Ok(wire) = &result
            && let StateRequestBody::RecoveryHello(bytes) = pending.request.body()
            && wire.response.body() == &StateResponseBody::Accepted
            && RecoveryHello::decode(bytes).is_ok()
        {
            self.recovery_remote_grants.insert(actual);
            self.recovery_pending_auth.remove(&actual);
        }
        if self.recovery_grants.contains_key(&actual)
            && permits_reverse_recovery(pending.request.body())
            && result
                .as_ref()
                .is_ok_and(|wire| wire.response.body() == &StateResponseBody::Accepted)
            && let Some(lease) = self.recovery_leases.get_mut(&actual)
        {
            lease.useful_response(Instant::now());
        }
        Some(NetworkEvent::OutboundState(StateEvent {
            id,
            peer,
            digest: pending.digest,
            result,
            custody: pending.custody,
            permit: pending.permit,
            outbound_slot: pending.outbound_slot,
        }))
    }

    fn handle_recovery_inbound(&mut self, mut inbound: InboundState) -> Option<NetworkEvent> {
        let peer = inbound.peer;
        let config = self.state_exchange.as_ref()?;
        if config.recovery_registry.is_none()
            || !self.swarm.behaviour().sessions.is_recovery_connected(&peer)
        {
            return None;
        }
        let rate = self
            .recovery_rates
            .entry(peer)
            .or_insert_with(|| TokenBucket::new(16, Duration::from_secs(1), Instant::now()));
        if !rate.try_take(Instant::now()) {
            let _ = self.respond_state(inbound, StateResponseBody::Busy);
            return None;
        }
        match inbound.request().body() {
            StateRequestBody::RecoveryChallenge | StateRequestBody::RecoveryHello(_)
                if self.recovery_grants.contains_key(&peer) =>
            {
                // A grant is bound to this connection. Repeating the owner
                // handshake cannot reset its absolute recovery lease.
                let _ = self.respond_state(
                    inbound,
                    StateResponseBody::Rejected(StateRejection::Unauthorized),
                );
                None
            }
            StateRequestBody::RecoveryChallenge => {
                let random = identity::Keypair::generate_ed25519()
                    .public()
                    .encode_protobuf();
                let nonce: [u8; 32] = Sha256::digest(random).into();
                self.recovery_challenges.insert(peer, nonce);
                let _ = self.respond_state(inbound, StateResponseBody::RecoveryNonce(nonce));
                None
            }
            StateRequestBody::RecoveryHello(bytes) => {
                let selected = config.recovery_registry.as_ref()?.clone();
                let context = config.context;
                let challenge = self.recovery_challenges.remove(&peer);
                let verified = challenge.and_then(|nonce| {
                    RecoveryHello::decode(bytes).ok().and_then(|hello| {
                        hello
                            .verify(&selected, context, self.local_peer_id(), peer, nonce)
                            .ok()
                    })
                });
                if let Some(owner) = verified {
                    if self
                        .respond_state(inbound, StateResponseBody::Accepted)
                        .is_ok()
                    {
                        self.recovery_grants.insert(peer, owner);
                        self.recovery_pending_auth.remove(&peer);
                        self.recovery_leases
                            .entry(peer)
                            .or_insert_with(|| RecoveryLease::new(Instant::now()));
                        Some(NetworkEvent::RecoveryAuthenticated {
                            peer_id: peer,
                            owner,
                        })
                    } else {
                        None
                    }
                } else {
                    let _ = self.respond_state(
                        inbound,
                        StateResponseBody::Rejected(StateRejection::Unauthorized),
                    );
                    None
                }
            }
            body if permits_recovery(self.recovery_grants.contains_key(&peer), body) => {
                inbound.recovery_owner = self.recovery_grants.get(&peer).copied();
                Some(NetworkEvent::InboundState(inbound))
            }
            body if config.lane == StateLane::Recovery
                && self.recovery_remote_grants.contains(&peer)
                && permits_reverse_recovery(body) =>
            {
                Some(NetworkEvent::InboundState(inbound))
            }
            _ => {
                let _ = self.respond_state(
                    inbound,
                    StateResponseBody::Rejected(StateRejection::Unauthorized),
                );
                None
            }
        }
    }
}
#[cfg(test)]
mod tests;
