//! Independent state validator/observer scheduling and authenticated delivery.
//!
//! All consensus and durable signing authority stays in `StateNode`. Queue
//! acceptance is explicitly not a finalized receipt. The async boundary keeps
//! all pending transport tickets and exact retry bytes inside this owner.

mod delivery;
mod input;
mod schedule;
#[cfg(test)]
mod tests;

use naome_consensus::state::StatePhase;
use naome_ledger::{
    LedgerError, LedgerState, OperationId, ValidatorId, authentication::SignedOperation,
    time::SignedTimeReport,
};
use naome_network::{PeerId, StateNetwork, StateTicket};
use naome_node::state::{StateNode, StateNodeError};
use naome_protocol::state_exchange::StateRequestBody;
use naome_storage::state::{StateHistory, StateSigner};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
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
type Result<T> = std::result::Result<T, StateRuntimeError>;

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
}
struct ProofFetch {
    peer: PeerId,
    proof: naome_proof::ProofId,
    deadline: Instant,
    ticket: Option<StateTicket>,
    outcome: Option<std::result::Result<Vec<u8>, String>>,
}
struct Flight {
    delivery: Delivery,
    ticket: StateTicket,
}

pub struct StateRuntime {
    node: StateNode,
    network: StateNetwork,
    peers: Vec<PeerId>,
    config: StateRuntimeConfig,
    pending: BTreeMap<OperationId, SignedOperation>,
    pending_bytes: usize,
    action_cursor: usize,
    rejections: VecDeque<(OperationId, u64, String)>,
    time_reports: BTreeMap<ValidatorId, SignedTimeReport>,
    own_time: Option<Arc<[u8]>>,
    outbox: VecDeque<Delivery>,
    flights: Vec<Flight>,
    proof_fetches: Vec<ProofFetch>,
    sent: BTreeSet<(PeerId, [u8; 32])>,
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
    pub fn new(
        history: StateHistory,
        signer: Option<StateSigner>,
        network: StateNetwork,
        mut peers: Vec<PeerId>,
        config: StateRuntimeConfig,
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
        if peers.len() > 3
            || peers
                .iter()
                .any(|p| *p == network.local_peer_id() || !network.is_configured_peer(p))
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
        let node = StateNode::new(history, signer)?;
        let observed_height = node.state()?.height();
        let last_position = node.position()?;
        let now = Instant::now();
        Ok(Self {
            node,
            network,
            peers,
            config,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            action_cursor: 0,
            rejections: VecDeque::new(),
            time_reports: BTreeMap::new(),
            own_time: None,
            outbox: VecDeque::new(),
            flights: Vec::new(),
            proof_fetches: Vec::new(),
            sent: BTreeSet::new(),
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
        self.network.local_peer_id()
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
    pub fn finality_bytes(&mut self, height: u64) -> Result<Vec<u8>> {
        Ok(self.node.finality_bytes(height)?)
    }
    /// Validates authenticated queue input, but promises no admission receipt.
    pub fn submit_operation(&mut self, operation: SignedOperation) -> Result<OperationId> {
        operation.verify(self.state()?.genesis())?;
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
        self.validate_queue_phase(&body, operation.author())?;
        if self.state()?.next_nonce(operation.author()) != Some(operation.nonce()) {
            return Err(StateRuntimeError::Rejected(
                "operation must use exact next finalized nonce".into(),
            ));
        }
        if self
            .pending
            .values()
            .any(|op| op.author() == operation.author() && op.nonce() == operation.nonce())
        {
            return Err(StateRuntimeError::Rejected(
                "different pending operation already occupies this nonce".into(),
            ));
        }
        let limit = self.state()?.genesis().profile().limits();
        let bytes = operation.encode().len();
        if self.pending.len() >= limit.accounts as usize
            || self
                .pending_bytes
                .checked_add(bytes)
                .is_none_or(|n| n > 2 * limit.record_bytes as usize)
        {
            return Err(StateRuntimeError::Rejected(
                "pending operation capacity".into(),
            ));
        }
        self.pending_bytes += bytes;
        self.rejections.retain(|entry| entry.0 != id);
        self.pending.insert(id, operation);
        Ok(id)
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
            } => {
                state
                    .genesis()
                    .validators()
                    .iter()
                    .any(|v| v.owner == author)
                    && active.as_ref().is_some_and(|a| {
                        a.phase == Phase::Voting
                            && a.question == *question
                            && a.number == *attempt
                            && !a.votes.contains_key(&author)
                    })
            }
            OperationBody::Commit { round, .. } => active
                .as_ref()
                .is_some_and(|a| a.phase == Phase::Commit && a.solution_round == Some(*round)),
            OperationBody::Reveal {
                round, original, ..
            } => {
                original.verify(state.genesis(), *round, author)?;
                active
                    .as_ref()
                    .is_some_and(|a| a.phase == Phase::Reveal && a.solution_round == Some(*round))
            }
        };
        if !valid {
            return Err(StateRuntimeError::Rejected(
                "operation does not match current finalized research phase or family".into(),
            ));
        }
        Ok(())
    }
    fn reject_preview(&mut self, id: OperationId, reason: String) -> Result<()> {
        if let Some(operation) = self.pending.remove(&id) {
            let bytes = operation.encode();
            self.pending_bytes -= bytes.len();
            self.outbox.retain(|d|!matches!(&d.body,StateRequestBody::UserAction(body) if body.as_ref()==bytes.as_slice()));
        }
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
        self.network
            .set_state_peer_enabled(peer, enabled)
            .map_err(|e| StateRuntimeError::Transport(e.to_string()))?;
        self.disabled.retain(|p| *p != peer);
        if !enabled {
            self.disabled.push(peer);
            self.expire_proof_fetches();
        }
        Ok(())
    }
    /// Cancellation-safe one-event poll. Every mutation before the await has its
    /// publication/transport custody in `self`; dropping this future loses none.
    pub async fn step(&mut self) -> Result<StateRuntimeEvent> {
        self.drive()?;
        self.flush()?;
        let event = tokio::select! {
            event=self.network.next_event()=>self.network_event(event)?,
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
        if self.state()?.height() != before {
            self.on_height()?;
        }
        let position = self.node.position()?;
        if position != self.last_position {
            if position.map(|p| (p.0, p.1)) != self.last_position.map(|p| (p.0, p.1)) {
                self.outbox.clear();
                self.sent.clear();
            }
            self.last_position = position;
            self.phase_started = Instant::now();
        }
        self.enqueue_publications()?;
        Ok(())
    }
    fn on_height(&mut self) -> Result<()> {
        self.time_reports.clear();
        self.own_time = None;
        self.work_ready = false;
        self.outbox.clear();
        self.sent.clear();
        let state = self.node.state()?;
        let consumed: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(id, op)| {
                (state.receipt(*id).is_none() && state.next_nonce(op.author()) != Some(op.nonce()))
                    .then_some(*id)
            })
            .collect();
        for id in consumed {
            self.reject_preview(
                id,
                "nonce consumed by a different finalized operation".into(),
            )?;
        }
        let state = self.node.state()?;
        self.pending.retain(|id, op| {
            state.receipt(*id).is_none() && state.next_nonce(op.author()) == Some(op.nonce())
        });
        self.pending_bytes = self.pending.values().map(|op| op.encode().len()).sum();
        self.last_position = self.node.position()?;
        self.phase_started = Instant::now();
        self.enqueue_latest_finality()?;
        Ok(())
    }
}
