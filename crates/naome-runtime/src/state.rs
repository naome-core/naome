//! Independent state validator/observer scheduling and authenticated delivery.
//!
//! All consensus and durable signing authority stays in `StateNode`. Queue
//! acceptance is explicitly not a finalized receipt. The async boundary keeps
//! all pending transport tickets and exact retry bytes inside this owner.

mod delivery;
mod input;
mod lifecycle;
mod proof_fetch_slot;
mod schedule;
#[cfg(test)]
mod tests;

use ed25519_dalek::SigningKey;
use naome_consensus::state::StatePhase;
use naome_ledger::{
    AuthorityUnitId, LedgerError, LedgerState, OperationId, ResolutionId, ValidatorId,
    authentication::SignedOperation,
    authority::{CandidateAdmissionOffer, HandoffPlan, NextPeriodKeys},
    time::SignedTimeReport,
};
use naome_network::{PeerId, StateNetwork, StateTicket, StateTransportEvent, StateTransportPair};
use naome_node::state::{StateNode, StateNodeError};
use naome_protocol::state_exchange::StateRequestBody;
use naome_storage::state::{StateHandoffJournal, StatePeriodCustody, StateStorageError};
use naome_storage::state::{StateHistory, StateSigner};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;

#[derive(Clone, Debug)]
pub struct StateRuntimeConfig {
    pub tick_interval: Duration,
    /// Round-zero delay; later rounds double it up to a sixteen-fold cap.
    pub proposal_timeout: Duration,
    /// Round-zero delay, with the same bounded consensus-round growth.
    pub prevote_timeout: Duration,
    /// Round-zero delay, with the same bounded consensus-round growth.
    pub precommit_timeout: Duration,
    /// Enables only explicit local fault-injection controls; canonical genesis
    /// and the fixed quorum denominator remain unchanged.
    pub allow_simulation_controls: bool,
}
impl Default for StateRuntimeConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_millis(500),
            proposal_timeout: Duration::from_secs(4),
            prevote_timeout: Duration::from_secs(4),
            precommit_timeout: Duration::from_secs(4),
            allow_simulation_controls: false,
        }
    }
}
#[derive(Debug)]
pub enum StateRuntimeError {
    Node(StateNodeError),
    Rejected(String),
    Clock(&'static str),
    Configuration(&'static str),
    Transport(String),
}
impl fmt::Display for StateRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(e) => e.fmt(f),
            Self::Rejected(e) => write!(f, "state request rejected: {e}"),
            Self::Clock(e) => write!(f, "state clock error: {e}"),
            Self::Configuration(e) => write!(f, "state runtime configuration: {e}"),
            Self::Transport(e) => write!(f, "state transport: {e}"),
        }
    }
}
impl std::error::Error for StateRuntimeError {}
impl From<StateNodeError> for StateRuntimeError {
    fn from(e: StateNodeError) -> Self {
        Self::Node(e)
    }
}
impl From<LedgerError> for StateRuntimeError {
    fn from(e: LedgerError) -> Self {
        Self::Rejected(e.to_string())
    }
}
impl From<StateStorageError> for StateRuntimeError {
    fn from(e: StateStorageError) -> Self {
        Self::Node(StateNodeError::Storage(e))
    }
}
type Result<T> = std::result::Result<T, StateRuntimeError>;

/// Local owner and paths for durable per-parent keys and sealed handoff.
pub struct StateHandoffSetup {
    pub owner_key: SigningKey,
    pub candidate_family: Option<ResolutionId>,
    /// Fresh non-authority Noise identity for owner-authenticated replay.
    pub recovery_key: Option<SigningKey>,
    /// Explicit stable alternate endpoints used when the last selected peer
    /// identities are stale after a missed period boundary.
    pub recovery_endpoints: Vec<String>,
    pub signer_directory: PathBuf,
    pub signer_anchor_directory: PathBuf,
    pub custody_directory: PathBuf,
    pub custody_anchor_directory: PathBuf,
    pub handoff_directory: PathBuf,
    pub handoff_anchor_directory: PathBuf,
    pub primary_endpoint: String,
    pub handoff_endpoint: String,
    pub initial_consensus_key_path: PathBuf,
    pub initial_transport_key_path: PathBuf,
    pub primary_listen_address: Option<SocketAddr>,
    pub handoff_listen_address: Option<SocketAddr>,
}

// Local transport custody is independent of the canonical account registry.
const MAX_PENDING_OPERATIONS: usize = 16;

#[derive(Clone, Debug)]
pub enum StateRuntimeEvent {
    Tick,
    Network,
    Finalized { height: u64 },
    Rejected { peer: PeerId, reason: String },
}
struct Delivery {
    peer: PeerId,
    body: StateRequestBody,
    id: [u8; 32],
    height: u64,
    queued_at: Instant,
}
struct ProofFetch {
    peer: PeerId,
    slot: Option<naome_ledger::AuthoritySlotId>,
    proof: naome_proof::ProofId,
    deadline: Instant,
    ticket: Option<StateTicket>,
    outcome: Option<std::result::Result<Vec<u8>, String>>,
}
struct Flight {
    delivery: Delivery,
    ticket: StateTicket,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryStage {
    Challenge,
    Hello,
    History,
    PendingAgreement,
}
struct RecoveryFlight {
    peer: PeerId,
    stage: RecoveryStage,
    ticket: StateTicket,
}

pub struct StateRuntime {
    node: StateNode,
    network: StateTransportPair,
    peers: Vec<PeerId>,
    handoff_peers: Vec<PeerId>,
    config: StateRuntimeConfig,
    pending: BTreeMap<OperationId, SignedOperation>,
    pending_bytes: usize,
    action_cursor: usize,
    rejections: VecDeque<(OperationId, u64, String)>,
    deferred: VecDeque<(OperationId, naome_ledger::AccountId, u64)>,
    time_reports: BTreeMap<ValidatorId, SignedTimeReport>,
    offers: BTreeMap<AuthorityUnitId, NextPeriodKeys>,
    candidate_offers: BTreeMap<ResolutionId, CandidateAdmissionOffer>,
    disabled_slots: BTreeSet<naome_ledger::AuthoritySlotId>,
    handoff_setup: Option<StateHandoffSetup>,
    current_custody: Option<StatePeriodCustody>,
    next_custody: Option<StatePeriodCustody>,
    own_time: Option<Arc<[u8]>>,
    outbox: VecDeque<Delivery>,
    flights: Vec<Flight>,
    recovery_flights: Vec<RecoveryFlight>,
    recovery_authenticated: BTreeSet<PeerId>,
    recovery_clients: BTreeSet<PeerId>,
    recovery_cursor: usize,
    last_recovery_probe: Instant,
    last_selected_at: Instant,
    offers_ready_at: Option<Instant>,
    proof_fetches: Vec<ProofFetch>,
    sent: BTreeSet<(PeerId, [u8; 32])>,
    acknowledged: VecDeque<(PeerId, [u8; 32])>,
    last_rebroadcast: Instant,
    disabled: Vec<PeerId>,
    next_tick: Instant,
    phase_started: Instant,
    last_position: Option<(u64, u64, StatePhase)>,
    last_utc: Option<u64>,
    last_clock: Option<(std::time::SystemTime, Instant)>,
    observed_height: u64,
    work_ready: bool,
}
impl StateRuntime {
    #[cfg(test)]
    fn new(
        history: StateHistory,
        signer: Option<StateSigner>,
        network: StateNetwork,
        peers: Vec<PeerId>,
        config: StateRuntimeConfig,
    ) -> Result<Self> {
        let pair = StateTransportPair::new(network)
            .map_err(|e| StateRuntimeError::Transport(e.to_string()))?;
        Self::new_inner(history, signer, pair, peers, config, None, None, None, None)
    }
    pub fn new_handoff(
        history: StateHistory,
        signer: Option<StateSigner>,
        mut network: StateTransportPair,
        peers: Vec<PeerId>,
        config: StateRuntimeConfig,
        mut setup: StateHandoffSetup,
    ) -> Result<Self> {
        let state = history.head()?.state();
        let selected_authority = state.authority().id();
        if network
            .active()
            .is_some_and(|active| active.state_authority_id() != Some(selected_authority))
            || network
                .recovery()
                .is_some_and(|recovery| recovery.state_authority_id() != Some(selected_authority))
        {
            return Err(StateRuntimeError::Configuration(
                "transport authority differs from selected history",
            ));
        }
        if setup.recovery_key.is_none() {
            setup.recovery_key = Some(lifecycle::fresh_recovery_key(state)?);
        }
        if state.terminated() {
            StatePeriodCustody::retire_terminal_selected(
                &setup.custody_directory,
                &setup.custody_anchor_directory,
                &history,
                &setup.owner_key,
            )?;
            let mut seed = zeroize::Zeroizing::new(
                setup
                    .recovery_key
                    .as_ref()
                    .expect("recovery key set")
                    .to_bytes(),
            );
            let identity = naome_network::Keypair::ed25519_from_bytes(&mut *seed)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            let recovery = StateNetwork::new_recovery_only(identity, state)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            network = StateTransportPair::from_recovery(recovery)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            lifecycle::listen_terminal_recovery(
                &mut network,
                &setup.primary_endpoint,
                setup.primary_listen_address,
            )?;
            return Self::new_inner(
                history,
                signer,
                network,
                Vec::new(),
                config,
                None,
                Some(setup),
                None,
                None,
            );
        }
        lifecycle::attach_recovery_network(
            &mut network,
            state,
            setup.recovery_key.as_ref().expect("recovery key set"),
        )?;
        let current_custody = if state.height() > 0
            && signer
                .as_ref()
                .is_some_and(|s| !s.stopped().unwrap_or(false))
        {
            StatePeriodCustody::open_for_selected(
                &setup.custody_directory,
                &setup.custody_anchor_directory,
                &history,
                &setup.owner_key,
            )?
        } else {
            None
        };
        let local_unit = state.authority().owner(naome_ledger::AccountId::for_key(
            setup.owner_key.verifying_key().as_bytes(),
        ));
        let next_endpoint = local_unit.map(|unit| {
            if unit
                .keys()
                .is_some_and(|keys| keys.endpoint() == setup.primary_endpoint)
            {
                setup.handoff_endpoint.clone()
            } else {
                setup.primary_endpoint.clone()
            }
        });
        let next_custody = if let Some((unit, endpoint)) = local_unit.zip(next_endpoint) {
            Some(StatePeriodCustody::stage_offer(
                &setup.custody_directory,
                &setup.custody_anchor_directory,
                state,
                unit.id(),
                &setup.owner_key,
                endpoint,
            )?)
        } else if let Some(family) = setup
            .candidate_family
            .filter(|family| lifecycle::candidate_still_live(state, *family))
        {
            Some(StatePeriodCustody::stage_candidate(
                &setup.custody_directory,
                &setup.custody_anchor_directory,
                state,
                family,
                &setup.owner_key,
            )?)
        } else {
            None
        };
        let height = state
            .height()
            .checked_add(1)
            .ok_or(StateRuntimeError::Configuration("height overflow"))?;
        if network.active().is_none()
            && let Some(candidate) = next_custody
                .as_ref()
                .and_then(StatePeriodCustody::candidate_offer)
        {
            let custody = next_custody.as_ref().expect("candidate custody exists");
            let mut seed = zeroize::Zeroizing::new(custody.transport_key().to_bytes());
            let identity = naome_network::Keypair::ed25519_from_bytes(&mut *seed)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            let active = StateNetwork::new_for_parent(identity, state)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            let bind = if candidate.keys().endpoint() == setup.primary_endpoint {
                setup.primary_listen_address
            } else {
                setup.handoff_listen_address
            };
            let listen = match bind {
                Some(address) => lifecycle::listen_address(address)?,
                None => active
                    .state_listen_address()
                    .ok_or(StateRuntimeError::Configuration(
                        "candidate endpoint missing",
                    ))?
                    .clone(),
            };
            network = StateTransportPair::new(active)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            network
                .active_mut()
                .expect("candidate lane installed")
                .listen_on(listen)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            lifecycle::attach_recovery_network(
                &mut network,
                state,
                setup.recovery_key.as_ref().expect("recovery key set"),
            )?;
        }
        let journal = StateHandoffJournal::open_or_create(
            &setup.handoff_directory,
            &setup.handoff_anchor_directory,
            state.genesis().clone(),
            height,
            history.maximum_round(),
            &history,
        )?;
        if let Some(staged) = network.staged() {
            let agreement = journal.agreement().ok_or(StateRuntimeError::Configuration(
                "staged transport has no selected-parent handoff agreement",
            ))?;
            if agreement.proposal().parent_commitment() != &history.head()?.commitment()
                || agreement.outgoing().id() != selected_authority
                || staged.state_authority_id() != Some(agreement.incoming().id())
            {
                return Err(StateRuntimeError::Configuration(
                    "staged transport differs from selected handoff agreement",
                ));
            }
        }
        let peers = if network.active().is_some() && peers.is_empty() {
            state
                .authority()
                .units()
                .iter()
                .filter_map(|unit| unit.keys())
                .map(|keys| {
                    naome_network::state_peer_id(*keys.transport())
                        .map_err(|error| StateRuntimeError::Transport(error.to_string()))
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            peers
        };
        let mut runtime = Self::new_inner(
            history,
            signer,
            network,
            peers,
            config,
            Some(journal),
            Some(setup),
            current_custody,
            next_custody,
        )?;
        if let Some(bytes) = runtime
            .next_custody
            .as_ref()
            .and_then(StatePeriodCustody::offer)
            .map(|offer| offer.encode())
        {
            runtime.accept_offer(&bytes)?;
        }
        if let Some(bytes) = runtime
            .next_custody
            .as_ref()
            .and_then(StatePeriodCustody::candidate_offer)
            .map(|offer| offer.encode())
        {
            runtime.accept_candidate_offer(&bytes)?;
        }
        Ok(runtime)
    }
    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        history: StateHistory,
        signer: Option<StateSigner>,
        network: StateTransportPair,
        mut peers: Vec<PeerId>,
        config: StateRuntimeConfig,
        journal: Option<StateHandoffJournal>,
        handoff_setup: Option<StateHandoffSetup>,
        current_custody: Option<StatePeriodCustody>,
        next_custody: Option<StatePeriodCustody>,
    ) -> Result<Self> {
        if config.tick_interval.is_zero()
            || config.proposal_timeout < config.tick_interval
            || config.prevote_timeout < config.tick_interval
            || config.precommit_timeout < config.tick_interval
        {
            return Err(StateRuntimeError::Configuration(
                "positive tick and phase intervals required",
            ));
        }
        peers.sort();
        peers.dedup();
        let local = network
            .active()
            .or(network.staged())
            .or(network.recovery())
            .ok_or(StateRuntimeError::Configuration("no state transport"))?
            .local_peer_id();
        if peers.len() > 4
            || peers.iter().any(|p| {
                *p == local || (!network.is_configured_peer(p) && network.active().is_some())
            })
        {
            return Err(StateRuntimeError::Configuration(
                "peers must be the configured remote research validators",
            ));
        }
        let genesis = history
            .head()
            .map_err(StateNodeError::from)?
            .state()
            .genesis();
        let expected = naome_protocol::state_exchange::StateContext::new(
            *genesis.id().as_bytes(),
            *genesis.profile().id().as_bytes(),
        );
        if network.state_context() != Some(expected) {
            return Err(StateRuntimeError::Configuration(
                "transport context differs from selected history",
            ));
        }
        let node = StateNode::new_with_handoff(history, signer, journal)?;
        let observed_height = node.state()?.height();
        let last_position = node.position()?;
        let now = Instant::now();
        Ok(Self {
            node,
            network,
            peers,
            handoff_peers: Vec::new(),
            config,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            action_cursor: 0,
            rejections: VecDeque::new(),
            deferred: VecDeque::new(),
            time_reports: BTreeMap::new(),
            offers: BTreeMap::new(),
            candidate_offers: BTreeMap::new(),
            disabled_slots: BTreeSet::new(),
            handoff_setup,
            current_custody,
            next_custody,
            own_time: None,
            outbox: VecDeque::new(),
            flights: Vec::new(),
            recovery_flights: Vec::new(),
            recovery_authenticated: BTreeSet::new(),
            recovery_clients: BTreeSet::new(),
            recovery_cursor: 0,
            last_recovery_probe: now - Duration::from_secs(10),
            last_selected_at: now,
            offers_ready_at: None,
            proof_fetches: Vec::new(),
            sent: BTreeSet::new(),
            acknowledged: VecDeque::new(),
            last_rebroadcast: now,
            disabled: Vec::new(),
            next_tick: now,
            phase_started: now,
            last_position,
            last_utc: None,
            last_clock: None,
            observed_height,
            work_ready: false,
        })
    }
    pub fn state(&self) -> Result<&LedgerState> {
        Ok(self.node.state()?)
    }
    pub fn history(&self) -> &StateHistory {
        self.node.history()
    }
    pub fn position(&self) -> Result<Option<(u64, u64, StatePhase)>> {
        Ok(self.node.position()?)
    }
    pub fn local_peer_id(&self) -> PeerId {
        self.network
            .active()
            .or(self.network.staged())
            .or(self.network.recovery())
            .expect("state transport configured")
            .local_peer_id()
    }
    pub fn pending_operations(&self) -> usize {
        self.pending.len()
    }
    /// A bounded local preview diagnostic, never a finalized rejection receipt.
    pub fn operation_rejection(&self, id: OperationId) -> Option<&str> {
        self.rejections
            .iter()
            .rev()
            .find(|entry| entry.0 == id)
            .map(|entry| entry.2.as_str())
    }
    /// Local custody yielded to active work; the exact signed bytes may retry.
    pub fn operation_deferred(&self, id: OperationId) -> bool {
        self.deferred.iter().any(|entry| entry.0 == id)
    }
    pub fn finality_bytes(&mut self, height: u64) -> Result<Vec<u8>> {
        Ok(self.node.finality_bytes(height)?)
    }
    pub fn accept_offer(&mut self, bytes: &[u8]) -> Result<()> {
        let offer = NextPeriodKeys::decode(bytes)?;
        let state = self.state()?;
        let unit = state.authority().unit(offer.unit()).ok_or_else(|| {
            StateRuntimeError::Rejected("period offer unit outside authority".into())
        })?;
        let owner_key = state.account_key(unit.owner()).ok_or_else(|| {
            StateRuntimeError::Rejected("period offer owner missing from registry".into())
        })?;
        offer.verify(
            state.authority(),
            state.head(),
            state.commitment(),
            state
                .authority()
                .effective_height()
                .checked_add(1)
                .ok_or(StateRuntimeError::Configuration("height overflow"))?,
            *owner_key,
        )?;
        if self
            .offers
            .get(&offer.unit())
            .is_some_and(|old| old != &offer)
        {
            return Err(StateRuntimeError::Rejected(
                "different offer for same unit and parent".into(),
            ));
        }
        if self.offers.len() >= 4 && !self.offers.contains_key(&offer.unit()) {
            return Err(StateRuntimeError::Rejected("period offer count".into()));
        }
        self.offers.insert(offer.unit(), offer);
        Ok(())
    }
    pub fn accept_candidate_offer(&mut self, bytes: &[u8]) -> Result<()> {
        let offer = CandidateAdmissionOffer::decode(bytes)?;
        let state = self.state()?;
        let entry = state.join_intent(offer.family()).ok_or_else(|| {
            StateRuntimeError::Rejected("candidate has no finalized intent".into())
        })?;
        let claim = state.claims().get(&offer.family()).ok_or_else(|| {
            StateRuntimeError::Rejected("candidate has no finalized claim".into())
        })?;
        if offer.intent_receipt() != entry.receipt().operation
            || offer.keys().consensus() != entry.intent().consensus_key()
            || offer.keys().transport() != entry.intent().transport_key()
            || offer.keys().endpoint() != entry.intent().endpoint()
        {
            return Err(StateRuntimeError::Rejected(
                "candidate offer differs from intent".into(),
            ));
        }
        let owner = *state
            .account_key(claim.author)
            .ok_or_else(|| StateRuntimeError::Rejected("candidate account missing".into()))?;
        offer.verify(state.authority(), state.head(), state.commitment(), owner)?;
        if self
            .candidate_offers
            .get(&offer.family())
            .is_some_and(|old| old != &offer)
        {
            return Err(StateRuntimeError::Rejected(
                "different candidate offer for same parent".into(),
            ));
        }
        if self.candidate_offers.len() >= 32 && !self.candidate_offers.contains_key(&offer.family())
        {
            return Err(StateRuntimeError::Rejected("candidate offer count".into()));
        }
        self.candidate_offers.insert(offer.family(), offer);
        Ok(())
    }
    fn handoff_plan(
        &self,
        time: &naome_ledger::time::TimeCertificate,
    ) -> Result<Option<HandoffPlan>> {
        if self.offers.len() < 3 {
            return Ok(None);
        }
        let offers: Vec<_> = self.offers.values().cloned().collect();
        let state = self.state()?;
        for family in state.join_queue() {
            if let Some(candidate) = self.candidate_offers.get(family) {
                let plan = HandoffPlan::new(offers.clone(), Some(candidate.clone()))?;
                if state.prepare_handoff_certified(&plan, time).is_ok() {
                    return Ok(Some(plan));
                }
            }
        }
        Ok(Some(HandoffPlan::new(offers, None)?))
    }
    /// Validates authenticated queue input, but promises no admission receipt.
    pub fn submit_operation(&mut self, operation: SignedOperation) -> Result<OperationId> {
        operation.verify_signature(self.state()?.genesis())?;
        let body = naome_ledger::operations::OperationBody::decode(
            operation.payload(),
            self.state()?.genesis(),
        )?;
        let id = operation.id();
        if self.state()?.receipt(id).is_some() || self.pending.contains_key(&id) {
            return Ok(id);
        }
        let current_height = self.state()?.height();
        if let Some((_, _, reason)) = self
            .rejections
            .iter()
            .find(|entry| entry.0 == id && entry.1 == current_height)
        {
            return Err(StateRuntimeError::Rejected(reason.clone()));
        }
        let state = self.state()?;
        if let naome_ledger::operations::OperationBody::JoinIntent(intent) = &body {
            intent.verify(state.genesis(), operation.author(), operation.nonce())?;
        }
        if matches!(body, naome_ledger::operations::OperationBody::Register) {
            if state.account_key(operation.author()).is_some() {
                return Err(StateRuntimeError::Rejected(
                    "account is already registered".into(),
                ));
            }
            if state.accounts().len() as u64
                >= state.genesis().profile().limits().registered_accounts
            {
                return Err(StateRuntimeError::Rejected(
                    "registered account capacity".into(),
                ));
            }
            if state.used_period_keys().contains(operation.public_key()) {
                return Err(StateRuntimeError::Rejected(
                    "period keys cannot register researcher accounts".into(),
                ));
            }
        } else if state.account_key(operation.author()) != Some(operation.public_key()) {
            return Err(StateRuntimeError::Rejected(
                "operation author is not registered".into(),
            ));
        }
        self.validate_queue_phase(&body, operation.author())?;
        if !Self::has_current_nonce(self.state()?, &operation) {
            return Err(StateRuntimeError::Rejected(
                "operation must use exact next finalized nonce".into(),
            ));
        }
        let limit = self.state()?.genesis().profile().limits();
        let bytes = operation.encode().len();
        let maximum_bytes = 2 * limit.record_bytes as usize;
        let active = matches!(
            body,
            naome_ledger::operations::OperationBody::Vote { .. }
                | naome_ledger::operations::OperationBody::Commit { .. }
                | naome_ledger::operations::OperationBody::Reveal { .. }
        );
        self.reserve_pending_slot(&operation, active, bytes, maximum_bytes)?;
        self.pending_bytes += bytes;
        self.rejections.retain(|entry| entry.0 != id);
        self.deferred.retain(|entry| entry.0 != id);
        self.pending.insert(id, operation);
        Ok(id)
    }
    fn reserve_pending_slot(
        &mut self,
        operation: &SignedOperation,
        active: bool,
        bytes: usize,
        maximum_bytes: usize,
    ) -> Result<()> {
        use naome_ledger::operations::OperationBody;
        let genesis = self.state()?.genesis();
        let ordinary = |op: &SignedOperation| {
            matches!(
                OperationBody::decode(op.payload(), genesis),
                Ok(OperationBody::Register
                    | OperationBody::JoinIntent(_)
                    | OperationBody::Submit { .. })
            )
        };
        let mut evicted = Vec::new();
        if let Some((id, occupied)) = self
            .pending
            .iter()
            .find(|(_, op)| op.author() == operation.author() && op.nonce() == operation.nonce())
        {
            if !active || !ordinary(occupied) {
                return Err(StateRuntimeError::Rejected(
                    "different pending operation already occupies this nonce".into(),
                ));
            }
            evicted.push(*id);
        }
        let mut count = self.pending.len() - evicted.len();
        let mut retained_bytes = self.pending_bytes
            - evicted
                .iter()
                .map(|id| self.pending[id].encode().len())
                .sum::<usize>();
        let fits = |count: usize, retained: usize| {
            count < MAX_PENDING_OPERATIONS
                && retained
                    .checked_add(bytes)
                    .is_some_and(|total| total <= maximum_bytes)
        };
        if active && !fits(count, retained_bytes) {
            for (id, pending) in &self.pending {
                if !evicted.contains(id) && ordinary(pending) {
                    evicted.push(*id);
                    count -= 1;
                    retained_bytes -= pending.encode().len();
                    if fits(count, retained_bytes) {
                        break;
                    }
                }
            }
        }
        if !fits(count, retained_bytes) {
            return Err(StateRuntimeError::Rejected(
                "pending operation capacity".into(),
            ));
        }
        // Commit evictions only after proving the new bounded queue fits.
        for id in evicted {
            let displaced = &self.pending[&id];
            let diagnostic = (id, displaced.author(), displaced.nonce());
            self.remove_pending(id);
            self.deferred.retain(|entry| entry.0 != id);
            if self.deferred.len() == MAX_PENDING_OPERATIONS {
                self.deferred.pop_front();
            }
            self.deferred.push_back(diagnostic);
        }
        Ok(())
    }
    fn validate_queue_phase(
        &self,
        body: &naome_ledger::operations::OperationBody,
        author: naome_ledger::AccountId,
    ) -> Result<()> {
        use naome_ledger::{operations::OperationBody, state::Phase};
        let state = self.state()?;
        if state.terminated() {
            return Err(StateRuntimeError::Rejected(
                "research run terminated".into(),
            ));
        }
        let active = state.active();
        let valid = match body {
            OperationBody::Register => state.registration_available(),
            OperationBody::JoinIntent(intent) => {
                state.can_submit_join_intent(author, intent.family(), intent.completion_ordinal())
            }
            OperationBody::Submit { question, .. } => {
                let family = question.resolution_id();
                !state.families().contains_key(&family)
                    && active.as_ref().is_none_or(|a| a.family != family)
                    && !state
                        .queued()
                        .any(|q| q.question().resolution_id() == family)
            }
            OperationBody::Vote {
                question, attempt, ..
            } => active.as_ref().is_some_and(|a| {
                a.electorate.contains(&author)
                    && a.phase == Phase::Voting
                    && a.question == *question
                    && a.number == *attempt
                    && !a.votes.contains_key(&author)
            }),
            OperationBody::Commit { round, .. } => active.as_ref().is_some_and(|a| {
                a.phase == Phase::Commit
                    && a.solution_round == Some(*round)
                    && a.commitments
                        < state.genesis().profile().limits().commitments_per_attempt as usize
                    && !state.has_active_commitment(author)
            }),
            OperationBody::Reveal {
                round,
                secret,
                original,
            } => {
                original.verify_signature(state.genesis(), *round, author)?;
                // Mirror the ledger's existing commitment check before giving
                // this input priority over ordinary registration custody.
                let commitment = naome_ledger::CommitmentId::for_original(
                    state.genesis(),
                    *round,
                    author,
                    original.original_hash(),
                    secret,
                );
                active
                    .as_ref()
                    .is_some_and(|a| a.phase == Phase::Reveal && a.solution_round == Some(*round))
                    && state.awaiting_reveal(author, commitment)
            }
        };
        if !valid {
            return Err(StateRuntimeError::Rejected(
                "operation does not match current finalized research phase or family".into(),
            ));
        }
        Ok(())
    }
    fn has_current_nonce(state: &LedgerState, operation: &SignedOperation) -> bool {
        state.next_nonce(operation.author()) == Some(operation.nonce())
            || (state.account_key(operation.author()).is_none()
                && operation.nonce() == 1
                && matches!(
                    naome_ledger::operations::OperationBody::decode(
                        operation.payload(),
                        state.genesis()
                    ),
                    Ok(naome_ledger::operations::OperationBody::Register)
                ))
    }
    fn reject_preview(&mut self, id: OperationId, reason: String) -> Result<()> {
        self.remove_pending(id);
        self.deferred.retain(|entry| entry.0 != id);
        self.rejections.retain(|entry| entry.0 != id);
        let maximum = self
            .state()?
            .genesis()
            .profile()
            .limits()
            .transport_buffer_frames as usize;
        if self.rejections.len() >= maximum {
            self.rejections.pop_front();
        }
        self.rejections
            .push_back((id, self.state()?.height(), reason));
        Ok(())
    }
    fn remove_pending(&mut self, id: OperationId) {
        if let Some(operation) = self.pending.remove(&id) {
            let bytes = operation.encode();
            self.pending_bytes -= bytes.len();
            self.outbox.retain(|d|!matches!(&d.body,StateRequestBody::UserAction(body) if body.as_ref()==bytes.as_slice()));
        }
    }
    /// Starts a real authenticated request to a configured remote validator.
    /// The selected checked library supplies the expected bytes; fetching grants
    /// no new mathematical or consensus authority. Duplicate requests coalesce.
    pub fn start_proof_fetch(&mut self, peer: PeerId, proof: naome_proof::ProofId) -> Result<()> {
        self.expire_proof_fetches();
        // Abandoned callers must not permanently occupy the bounded result
        // slots. Preserve every result through its original operation deadline,
        // and reclaim only terminal entries after that deadline has elapsed.
        let now = Instant::now();
        self.proof_fetches
            .retain(|fetch| fetch.outcome.is_none() || now < fetch.deadline);
        if !self.peers.contains(&peer) || self.disabled.contains(&peer) {
            return Err(StateRuntimeError::Rejected(
                "proof peer is unknown or disabled".into(),
            ));
        }
        if self.state()?.library().lookup(proof).is_none() {
            return Err(StateRuntimeError::Rejected(
                "proof is not in the selected verified library".into(),
            ));
        }
        if self
            .proof_fetches
            .iter()
            .any(|fetch| fetch.peer == peer && fetch.proof == proof)
        {
            return Ok(());
        }
        if self.proof_fetches.len() >= 4 {
            return Err(StateRuntimeError::Rejected("proof fetch capacity".into()));
        }
        self.proof_fetches.push(ProofFetch {
            peer,
            slot: None,
            proof,
            deadline: Instant::now() + Duration::from_secs(30),
            ticket: None,
            outcome: None,
        });
        Ok(())
    }
    /// Returns None while pending; consumes a completed result or explicit error.
    /// Dropped callers cannot grow retained results beyond four certificates.
    pub fn take_proof_fetch(
        &mut self,
        peer: PeerId,
        proof: naome_proof::ProofId,
    ) -> Result<Option<Vec<u8>>> {
        self.expire_proof_fetches();
        let index = self
            .proof_fetches
            .iter()
            .position(|fetch| fetch.peer == peer && fetch.proof == proof)
            .ok_or_else(|| {
                StateRuntimeError::Rejected(
                    "proof fetch was not requested or its result expired".into(),
                )
            })?;
        if self.proof_fetches[index].outcome.is_none() {
            return Ok(None);
        }
        match self
            .proof_fetches
            .swap_remove(index)
            .outcome
            .expect("completed fetch")
        {
            Ok(bytes) => Ok(Some(bytes)),
            Err(reason) => Err(StateRuntimeError::Transport(reason)),
        }
    }
    fn expire_proof_fetches(&mut self) {
        let now = Instant::now();
        for fetch in &mut self.proof_fetches {
            if fetch.outcome.is_none()
                && (now >= fetch.deadline || self.disabled.contains(&fetch.peer))
            {
                fetch.ticket = None;
                fetch.outcome = Some(Err(if self.disabled.contains(&fetch.peer) {
                    "proof peer disabled"
                } else {
                    "proof fetch timed out"
                }
                .into()));
            }
        }
    }
    pub fn set_peer_enabled(&mut self, peer: PeerId, enabled: bool) -> Result<()> {
        if !self.config.allow_simulation_controls {
            return Err(StateRuntimeError::Configuration(
                "simulation controls are disabled",
            ));
        }
        if !self.peers.contains(&peer) {
            return Err(StateRuntimeError::Configuration("unknown simulation peer"));
        }
        if let Some(active) = self.network.active_mut() {
            active
                .set_state_peer_enabled(peer, enabled)
                .map_err(|e| StateRuntimeError::Transport(e.to_string()))?;
        }
        self.disabled.retain(|p| *p != peer);
        if !enabled {
            self.disabled.push(peer);
            self.expire_proof_fetches();
        }
        Ok(())
    }
    /// Fault-injection control follows stable authority slots when keys rotate.
    pub fn set_slot_enabled(
        &mut self,
        slot: naome_ledger::AuthoritySlotId,
        enabled: bool,
    ) -> Result<()> {
        if !self.config.allow_simulation_controls {
            return Err(StateRuntimeError::Configuration(
                "simulation controls are disabled",
            ));
        }
        if self.state()?.authority().slot(slot).is_none() {
            return Err(StateRuntimeError::Configuration("unknown simulation slot"));
        }
        if enabled {
            self.disabled_slots.remove(&slot);
        } else {
            self.disabled_slots.insert(slot);
        }
        self.apply_slot_disables()
    }
    pub(super) fn apply_slot_disables(&mut self) -> Result<()> {
        let current = self.state()?.authority().clone();
        let staged = self
            .node
            .handoff_agreement()
            .map(|agreement| agreement.incoming().clone());
        let mut disabled = Vec::new();
        for (snapshot, handoff) in [(Some(current), false), (staged, true)] {
            let Some(snapshot) = snapshot else {
                continue;
            };
            for unit in snapshot.units() {
                let Some(keys) = unit.keys() else {
                    continue;
                };
                let peer = naome_network::state_peer_id(*keys.transport())
                    .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
                let blocked = self.disabled_slots.contains(&unit.slot());
                let network = if handoff {
                    self.network.staged_mut()
                } else {
                    self.network.active_mut()
                };
                if let Some(network) = network
                    && peer != network.local_peer_id()
                    && network.is_configured_peer(&peer)
                {
                    network
                        .set_state_peer_enabled(peer, !blocked)
                        .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
                }
                if blocked {
                    disabled.push(peer);
                }
            }
        }
        disabled.sort();
        disabled.dedup();
        self.disabled = disabled;
        self.expire_proof_fetches();
        if self.all_remote_slots_disabled()? {
            self.recovery_authenticated.clear();
            self.recovery_clients.clear();
            self.recovery_flights.clear();
        }
        Ok(())
    }
    /// Cancellation-safe one-event poll. Every mutation before the await has its
    /// publication/transport custody in `self`; dropping this future loses none.
    pub async fn step(&mut self) -> Result<StateRuntimeEvent> {
        self.drive()?;
        self.flush()?;
        let event = tokio::select! {
            event=self.network.next_event()=>match event {
                Some(StateTransportEvent::Active(event)) => self.network_event(event,naome_network::StateLane::Active)?,
                Some(StateTransportEvent::Handoff(event)) => self.network_event(event,naome_network::StateLane::Handoff)?,
                Some(StateTransportEvent::Recovery(event)) => self.network_event(event,naome_network::StateLane::Recovery)?,
                None => return Err(StateRuntimeError::Configuration("state transports exhausted")),
            },
            _=tokio::time::sleep_until(self.next_tick)=>{
                self.next_tick=Instant::now()+self.config.tick_interval;
                self.tick()?;
                StateRuntimeEvent::Tick
            }
        };
        self.drive()?;
        self.flush()?;
        let height = self.state()?.height();
        if height != self.observed_height {
            self.observed_height = height;
            return Ok(StateRuntimeEvent::Finalized { height });
        }
        Ok(event)
    }
    fn drive(&mut self) -> Result<()> {
        let before = self.state()?.height();
        self.node.drive()?;
        if self.state()?.height() == before {
            self.advance_handoff()?;
            self.node.drive()?;
        }
        if self.state()?.height() != before {
            self.on_height()?;
        }
        let position = self.node.position()?;
        if position != self.last_position {
            if position.map(|p| (p.0, p.1)) != self.last_position.map(|p| (p.0, p.1)) {
                self.outbox.clear();
                self.sent.clear();
                self.acknowledged.clear();
            }
            self.last_position = position;
            self.phase_started = Instant::now();
        }
        self.enqueue_publications()?;
        Ok(())
    }
    fn on_height(&mut self) -> Result<()> {
        self.activate_selected_period()?;
        self.last_selected_at = Instant::now();
        self.offers_ready_at = None;
        if self.network.active().is_none() {
            self.recovery_cursor = 0;
            self.last_recovery_probe = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
        self.recovery_flights.clear();
        self.recovery_authenticated.clear();
        self.recovery_clients.clear();
        self.time_reports.clear();
        self.own_time = None;
        self.work_ready = false;
        self.outbox.clear();
        self.sent.clear();
        self.acknowledged.clear();
        let state = self.node.state()?;
        let consumed: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(id, op)| {
                (state.receipt(*id).is_none() && !Self::has_current_nonce(state, op)).then_some(*id)
            })
            .chain(self.deferred.iter().filter_map(|(id, author, nonce)| {
                let next = state.next_nonce(*author);
                (state.receipt(*id).is_none()
                    && next != Some(*nonce)
                    && !(next.is_none() && *nonce == 1))
                    .then_some(*id)
            }))
            .collect();
        for id in consumed {
            self.reject_preview(
                id,
                "nonce consumed by a different finalized operation".into(),
            )?;
        }
        let state = self.node.state()?;
        self.pending
            .retain(|id, op| state.receipt(*id).is_none() && Self::has_current_nonce(state, op));
        self.deferred
            .retain(|entry| state.receipt(entry.0).is_none());
        self.pending_bytes = self.pending.values().map(|op| op.encode().len()).sum();
        self.last_position = self.node.position()?;
        self.phase_started = Instant::now();
        self.enqueue_period_offers()?;
        self.enqueue_latest_finality()?;
        Ok(())
    }
}
