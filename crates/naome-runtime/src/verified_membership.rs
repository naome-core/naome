//! Live membership node: authenticated gossip, explicit applications and replayed
//! observer catch-up. Peer status is only a hint; complete proofs grant finality.

use naome_consensus::verified_membership::*;
use naome_network::{PeerId, verified_membership::*};
use naome_node::verified_membership::{MembershipCandidate, MembershipNode, MembershipNodeError};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    time::Duration,
};
use tokio::time::{Instant, Interval, MissedTickBehavior};

const MAX_GOSSIP: usize = 2048;
const MAX_GOSSIP_BYTES: usize = MAX_ARTIFACT_BYTES * 4;
const RETRY_AFTER: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug)]
pub struct MembershipRuntimeTiming {
    pub phase_base: Duration,
    pub round_increment: Duration,
    pub tick: Duration,
}

#[derive(Debug)]
pub enum MembershipRuntimeError {
    Node(MembershipNodeError),
    Network(MembershipNetworkError),
    Timing,
    Identity,
    Limit,
}
impl fmt::Display for MembershipRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "membership runtime: {self:?}")
    }
}
impl Error for MembershipRuntimeError {}
impl From<MembershipNodeError> for MembershipRuntimeError {
    fn from(error: MembershipNodeError) -> Self {
        Self::Node(error)
    }
}
impl From<MembershipNetworkError> for MembershipRuntimeError {
    fn from(error: MembershipNetworkError) -> Self {
        Self::Network(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipRuntimeEvent {
    Progress,
    Network,
    InboxChanged,
    Refused,
    Idle,
}

enum Pending {
    Publication {
        peer: PeerId,
        id: [u8; 32],
    },
    Status {
        peer: PeerId,
    },
    Proof {
        peer: PeerId,
        height: u64,
        parent: [u8; 32],
    },
}

pub struct MembershipRuntime {
    node: MembershipNode,
    network: MembershipNetwork,
    timing: MembershipRuntimeTiming,
    tick: Interval,
    deadline: Instant,
    coordinate: (u64, u64, MembershipPhase),
    pending: HashMap<MembershipExchangeId, Pending>,
    delivered: HashMap<(PeerId, [u8; 32]), Instant>,
    remote: BTreeMap<PeerId, (u64, Instant)>,
    status_attempt: HashMap<PeerId, Instant>,
    proof_backoff: HashMap<PeerId, Instant>,
    gossip: BTreeMap<[u8; 32], MembershipPublication>,
    peer_cursor: usize,
    organization: Option<[u8; 32]>,
    status_served: std::collections::HashSet<PeerId>,
    proof_cursor: Option<PeerId>,
}

impl MembershipRuntime {
    pub fn new(
        mut node: MembershipNode,
        mut network: MembershipNetwork,
        timing: MembershipRuntimeTiming,
    ) -> Result<Self, MembershipRuntimeError> {
        if timing.phase_base.is_zero()
            || timing.tick.is_zero()
            || timing.phase_base > Duration::from_secs(3600)
            || timing.round_increment > Duration::from_secs(3600)
            || timing.tick > Duration::from_secs(60)
        {
            return Err(MembershipRuntimeError::Timing);
        }
        if node.journal().has_pending_signature() {
            return Err(MembershipNodeError::Journal(
                naome_storage::verified_membership::MembershipJournalError::PendingSignature,
            )
            .into());
        }
        let publications = node.replay_publications()?;
        network.update_membership(node.snapshot()?)?;
        let coordinate = (
            node.machine()?.branch().height(),
            node.machine()?.round(),
            node.machine()?.phase(),
        );
        let mut tick = tokio::time::interval(timing.tick);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut runtime = Self {
            node,
            network,
            timing,
            tick,
            deadline: Instant::now(),
            coordinate,
            pending: HashMap::new(),
            delivered: HashMap::new(),
            remote: BTreeMap::new(),
            status_attempt: HashMap::new(),
            proof_backoff: HashMap::new(),
            gossip: BTreeMap::new(),
            peer_cursor: 0,
            organization: None,
            status_served: std::collections::HashSet::new(),
            proof_cursor: None,
        };
        runtime.reset_deadline()?;
        runtime.retain(publications)?;
        runtime.validate_identity()?;
        Ok(runtime)
    }
    pub fn node(&self) -> &MembershipNode {
        &self.node
    }
    pub fn into_node(self) -> MembershipNode {
        self.node
    }
    pub fn bind_organization(
        &mut self,
        organization: [u8; 32],
    ) -> Result<(), MembershipRuntimeError> {
        self.organization = Some(organization);
        self.validate_identity()
    }
    fn validate_identity(&self) -> Result<(), MembershipRuntimeError> {
        let signer = self.node.machine()?.signer();
        if let Some(member) = self
            .node
            .snapshot()?
            .members()
            .iter()
            .find(|member| Some(member.consensus_key) == signer)
            && (self
                .organization
                .is_some_and(|organization| organization != member.organization)
                || !self.network.is_local_key(&member.network_key))
        {
            return Err(MembershipRuntimeError::Identity);
        }
        Ok(())
    }
    pub fn node_mut(&mut self) -> &mut MembershipNode {
        &mut self.node
    }
    pub fn network(&self) -> &MembershipNetwork {
        &self.network
    }
    pub fn network_mut(&mut self) -> &mut MembershipNetwork {
        &mut self.network
    }
    pub fn apply_event(
        &mut self,
        event: MembershipMachineEvent,
    ) -> Result<(), MembershipRuntimeError> {
        let publications = self.node.process(event)?;
        self.retain(publications)
    }

    pub async fn next_event(&mut self) -> Result<MembershipRuntimeEvent, MembershipRuntimeError> {
        self.refresh()?;
        if self.node.can_author()? {
            let publications = self.node.author()?;
            self.retain(publications)?;
            self.refresh()?;
            return Ok(MembershipRuntimeEvent::Progress);
        }
        tokio::select! {
            event = self.network.next_event() => self.network_event(event),
            _ = tokio::time::sleep_until(self.deadline) => {
                let machine = self.node.machine()?;
                let event = MembershipMachineEvent::Timeout { height: machine.branch().next_height().map_err(MembershipNodeError::from)?, round: machine.round(), phase: machine.phase() };
                let publications = self.node.process(event)?;
                self.retain(publications)?; self.refresh()?;
                // Known finality without its proposal freezes signing but must
                // not create a hot loop while proof acquisition is pending.
                if self.deadline <= Instant::now() { self.reset_deadline()?; }
                Ok(MembershipRuntimeEvent::Progress)
            },
            _ = self.tick.tick() => { self.schedule()?; Ok(MembershipRuntimeEvent::Idle) },
        }
    }

    fn reset_deadline(&mut self) -> Result<(), MembershipRuntimeError> {
        let round = self.node.machine()?.round();
        let increment = self
            .timing
            .round_increment
            .checked_mul(u32::try_from(round).map_err(|_| MembershipRuntimeError::Timing)?)
            .ok_or(MembershipRuntimeError::Timing)?;
        let duration = self
            .timing
            .phase_base
            .checked_add(increment)
            .ok_or(MembershipRuntimeError::Timing)?;
        self.deadline = Instant::now()
            .checked_add(duration)
            .ok_or(MembershipRuntimeError::Timing)?;
        Ok(())
    }
    fn refresh(&mut self) -> Result<(), MembershipRuntimeError> {
        self.validate_identity()?;
        let machine = self.node.machine()?;
        let coordinate = (machine.branch().height(), machine.round(), machine.phase());
        if coordinate != self.coordinate {
            self.coordinate = coordinate;
            self.reset_deadline()?;
            self.network.update_membership(self.node.snapshot()?)?;
        }
        let selected = coordinate.0;
        let floor = coordinate.1.saturating_sub(1);
        self.gossip.retain(|_, publication| match publication {
            MembershipPublication::Finality(proof) => proof.proposal.value.height() == selected,
            MembershipPublication::Proposal { proposal, .. } => {
                proposal.value.height() == selected + 1 && proposal.round >= floor
            }
            MembershipPublication::Vote(vote) => {
                vote.coordinate.height == selected + 1 && vote.coordinate.round >= floor
            }
            MembershipPublication::Certificate(certificate) => {
                certificate.coordinate().height == selected + 1
                    && certificate.coordinate().round >= floor
            }
        });
        let peers: std::collections::HashSet<_> = self.network.peers().into_iter().collect();
        self.remote.retain(|peer, _| peers.contains(peer));
        self.status_attempt.retain(|peer, _| peers.contains(peer));
        self.status_served.retain(|peer| peers.contains(peer));
        self.proof_backoff.retain(|peer, _| peers.contains(peer));
        self.delivered.retain(|(peer, _), _| peers.contains(peer));
        Ok(())
    }
    fn retain(
        &mut self,
        publications: Vec<MembershipPublication>,
    ) -> Result<(), MembershipRuntimeError> {
        self.refresh()?;
        for publication in publications {
            let id = publication.id();
            if self.gossip.contains_key(&id) {
                continue;
            }
            if self.gossip.len() >= MAX_GOSSIP
                || self
                    .gossip
                    .values()
                    .map(|publication| publication.to_bytes().len())
                    .sum::<usize>()
                    + publication.to_bytes().len()
                    > MAX_GOSSIP_BYTES
            {
                continue;
            }
            self.gossip.insert(id, publication);
        }
        Ok(())
    }

    fn network_event(
        &mut self,
        event: MembershipNetworkEvent,
    ) -> Result<MembershipRuntimeEvent, MembershipRuntimeError> {
        match event {
            MembershipNetworkEvent::Inbound(inbound) => self.inbound(inbound),
            MembershipNetworkEvent::Response(response) => {
                let Some(pending) = self.pending.remove(&response.id) else {
                    return Ok(MembershipRuntimeEvent::Refused);
                };
                match (pending, response.message) {
                    (Pending::Publication { peer, id }, MembershipResponseMessage::Receipt)
                        if peer == response.peer =>
                    {
                        self.delivered.insert((peer, id), Instant::now());
                    }
                    (
                        Pending::Status { peer },
                        MembershipResponseMessage::Status {
                            context, height, ..
                        },
                    ) if peer == response.peer
                        && context == self.node.machine()?.branch().context().0 =>
                    {
                        self.remote.insert(peer, (height, Instant::now()));
                    }
                    (
                        Pending::Proof {
                            peer,
                            height,
                            parent,
                        },
                        MembershipResponseMessage::Finality(bytes),
                    ) if peer == response.peer => {
                        let machine = self.node.machine()?;
                        if machine
                            .branch()
                            .next_height()
                            .map_err(MembershipNodeError::from)?
                            != height
                            || machine.branch().ancestry() != parent
                        {
                            return Ok(MembershipRuntimeEvent::Refused);
                        }
                        let proof = match MembershipFinalityProof::from_bytes(&bytes) {
                            Ok(proof)
                                if proof.proposal.value.height() == height
                                    && proof.proposal.value.parent() == parent =>
                            {
                                proof
                            }
                            _ => {
                                self.proof_backoff.insert(peer, Instant::now());
                                return Ok(MembershipRuntimeEvent::Refused);
                            }
                        };
                        match self.node.receive(MembershipPublication::Finality(proof)) {
                            Ok(publications) => {
                                self.retain(publications)?;
                                return Ok(MembershipRuntimeEvent::Progress);
                            }
                            Err(_) => {
                                self.proof_backoff.insert(peer, Instant::now());
                                return self.refused_or_poisoned();
                            }
                        }
                    }
                    (Pending::Proof { peer, .. }, _) => {
                        self.proof_backoff.insert(peer, Instant::now());
                    }
                    _ => {}
                }
                Ok(MembershipRuntimeEvent::Network)
            }
            MembershipNetworkEvent::Failed { id, peer } => {
                if matches!(self.pending.remove(&id), Some(Pending::Proof { .. })) {
                    self.proof_backoff.insert(peer, Instant::now());
                }
                Ok(MembershipRuntimeEvent::Network)
            }
            MembershipNetworkEvent::Connected(peer) => {
                self.status_attempt.remove(&peer);
                self.status_served.remove(&peer);
                self.delivered.retain(|(known, _), _| *known != peer);
                Ok(MembershipRuntimeEvent::Network)
            }
            MembershipNetworkEvent::Disconnected(peer) => {
                self.remote.remove(&peer);
                self.delivered.retain(|(known, _), _| *known != peer);
                self.proof_backoff.remove(&peer);
                self.status_attempt.remove(&peer);
                self.status_served.remove(&peer);
                Ok(MembershipRuntimeEvent::Network)
            }
            MembershipNetworkEvent::Listening(_) => Ok(MembershipRuntimeEvent::Network),
        }
    }

    fn refused_or_poisoned(&self) -> Result<MembershipRuntimeEvent, MembershipRuntimeError> {
        self.node.machine()?;
        Ok(MembershipRuntimeEvent::Refused)
    }
    fn inbound(
        &mut self,
        inbound: MembershipInbound,
    ) -> Result<MembershipRuntimeEvent, MembershipRuntimeError> {
        let mut event = MembershipRuntimeEvent::Network;
        let response = match &inbound.message {
            MembershipRequestMessage::Status { context }
                if *context == self.node.machine()?.branch().context().0 =>
            {
                let branch = self.node.machine()?.branch();
                MembershipResponseMessage::Status {
                    context: *context,
                    height: branch.height(),
                    ancestry: branch.ancestry(),
                }
            }
            MembershipRequestMessage::Finality { context, height }
                if *context == self.node.machine()?.branch().context().0 =>
            {
                match self.node.finalized_proof(*height)? {
                    Some(proof) => MembershipResponseMessage::Finality(proof.to_bytes()),
                    None => MembershipResponseMessage::Unavailable,
                }
            }
            MembershipRequestMessage::Application(bytes) => {
                match MembershipRequest::from_bytes(bytes)
                    .map_err(MembershipNodeError::from)
                    .and_then(|request| self.node.ingest_request(request))
                {
                    Ok(changed) => {
                        if changed {
                            event = MembershipRuntimeEvent::InboxChanged;
                        }
                        MembershipResponseMessage::Receipt
                    }
                    Err(_) => {
                        event = self.refused_or_poisoned()?;
                        MembershipResponseMessage::Unavailable
                    }
                }
            }
            MembershipRequestMessage::Approval(bytes) => {
                match MembershipApproval::from_bytes(bytes)
                    .map_err(MembershipNodeError::from)
                    .and_then(|approval| self.node.ingest_approval(approval))
                {
                    Ok(changed) => {
                        if changed {
                            event = MembershipRuntimeEvent::InboxChanged;
                        }
                        MembershipResponseMessage::Receipt
                    }
                    Err(_) => {
                        event = self.refused_or_poisoned()?;
                        MembershipResponseMessage::Unavailable
                    }
                }
            }
            MembershipRequestMessage::Candidate(bytes) => {
                match MembershipCandidate::from_bytes(bytes)
                    .and_then(|candidate| self.node.ingest_candidate(candidate))
                {
                    Ok(_) => MembershipResponseMessage::Receipt,
                    Err(_) => {
                        event = self.refused_or_poisoned()?;
                        MembershipResponseMessage::Unavailable
                    }
                }
            }
            MembershipRequestMessage::Publication(bytes) => {
                match MembershipPublication::from_bytes(bytes) {
                    Ok(publication)
                        if publication.height() == self.node.machine()?.branch().height() + 1 =>
                    {
                        match self.node.receive(publication.clone()) {
                            Ok(mut publications) => {
                                publications.push(publication);
                                self.retain(publications)?;
                                event = MembershipRuntimeEvent::Progress;
                                MembershipResponseMessage::Receipt
                            }
                            Err(_) => {
                                event = self.refused_or_poisoned()?;
                                MembershipResponseMessage::Unavailable
                            }
                        }
                    }
                    Ok(publication)
                        if publication.height() <= self.node.machine()?.branch().height() =>
                    {
                        match self.node.receive(publication) {
                            Ok(_) => MembershipResponseMessage::Receipt,
                            Err(_) => {
                                event = self.refused_or_poisoned()?;
                                MembershipResponseMessage::Unavailable
                            }
                        }
                    }
                    Ok(publication) => {
                        // A future publication is an acquisition hint only.
                        let current = self
                            .remote
                            .entry(inbound.peer)
                            .or_insert((0, Instant::now()));
                        current.0 = current.0.max(publication.height().saturating_sub(1));
                        MembershipResponseMessage::Unavailable
                    }
                    Err(_) => {
                        event = MembershipRuntimeEvent::Refused;
                        MembershipResponseMessage::Unavailable
                    }
                }
            }
            _ => {
                event = MembershipRuntimeEvent::Refused;
                MembershipResponseMessage::Unavailable
            }
        };
        let _ = self.network.respond(inbound, response);
        Ok(event)
    }

    fn schedule(&mut self) -> Result<(), MembershipRuntimeError> {
        self.refresh()?;
        let now = Instant::now();
        let context = self.node.machine()?.branch().context().0;
        let height = self
            .node
            .machine()?
            .branch()
            .next_height()
            .map_err(MembershipNodeError::from)?;
        if !self
            .pending
            .values()
            .any(|pending| matches!(pending, Pending::Proof { .. }))
        {
            let mut peers: Vec<_> = self
                .remote
                .iter()
                .filter(|(peer, (remote, _))| {
                    *remote >= height
                        && self
                            .proof_backoff
                            .get(peer)
                            .is_none_or(|last| now.duration_since(*last) >= RETRY_AFTER)
                })
                .map(|(peer, _)| *peer)
                .collect();
            if let Some(previous) = self.proof_cursor {
                let start = peers.partition_point(|peer| *peer <= previous);
                if start < peers.len() {
                    peers.rotate_left(start);
                }
            }
            for peer in peers {
                if let Ok(id) = self
                    .network
                    .send(peer, MembershipRequestMessage::Finality { context, height })
                {
                    self.proof_cursor = Some(peer);
                    self.pending.insert(
                        id,
                        Pending::Proof {
                            peer,
                            height,
                            parent: self.node.machine()?.branch().ancestry(),
                        },
                    );
                    break;
                }
            }
        }
        let mut packets = Vec::new();
        for publication in self.gossip.values() {
            packets.push(MembershipRequestMessage::Publication(
                publication.to_bytes(),
            ));
        }
        for request in self.node.requests().values() {
            packets.push(MembershipRequestMessage::Application(request.to_bytes()));
        }
        for approval in self.node.approval_messages() {
            packets.push(MembershipRequestMessage::Approval(approval.to_bytes()));
        }
        for candidate in self.node.candidates() {
            packets.push(MembershipRequestMessage::Candidate(candidate.to_bytes()));
        }
        let packets: Vec<_> = packets
            .into_iter()
            .map(|message| (packet_id(&message), message))
            .collect();
        let retained: std::collections::HashSet<_> = packets.iter().map(|(id, _)| *id).collect();
        self.delivered.retain(|(_, id), _| retained.contains(id));
        let mut peers = self.network.peers();
        if !peers.is_empty() {
            let start = self.peer_cursor % peers.len();
            peers.rotate_left(start);
            // Advance one position even when existing exchanges leave only one free slot.
            self.peer_cursor = (start + 1) % peers.len();
        }
        for peer in peers {
            let gossip_due = packets.iter().any(|(id, _)| {
                self.delivered
                    .get(&(peer, *id))
                    .is_none_or(|last| now.duration_since(*last) >= RETRY_AFTER)
            });
            if self
                .status_attempt
                .get(&peer)
                .is_none_or(|last| now.duration_since(*last) >= RETRY_AFTER)
                && (!self.status_served.contains(&peer) || !gossip_due)
                && let Ok(id) = self
                    .network
                    .send(peer, MembershipRequestMessage::Status { context })
            {
                self.pending.insert(id, Pending::Status { peer });
                self.status_attempt.insert(peer, now);
                self.status_served.insert(peer);
                continue;
            }
            let mut ordered: Vec<_> = packets.iter().collect();
            ordered.sort_by_key(|(id, _)| self.delivered.get(&(peer, *id)).copied());
            for (packet_id, message) in ordered {
                if self
                    .delivered
                    .get(&(peer, *packet_id))
                    .is_some_and(|last| now.duration_since(*last) < RETRY_AFTER)
                {
                    continue;
                }
                match self.network.send(peer, message.clone()) {
                    Ok(id) => {
                        self.status_served.remove(&peer);
                        self.pending.insert(
                            id,
                            Pending::Publication {
                                peer,
                                id: *packet_id,
                            },
                        );
                        self.delivered.insert((peer, *packet_id), now);
                        break;
                    }
                    Err(MembershipNetworkError::Busy) => break,
                    Err(_) => continue,
                }
            }
        }
        Ok(())
    }
}

fn packet_id(message: &MembershipRequestMessage) -> [u8; 32] {
    let (tag, bytes) = match message {
        MembershipRequestMessage::Publication(bytes) => (0, bytes),
        MembershipRequestMessage::Application(bytes) => (1, bytes),
        MembershipRequestMessage::Approval(bytes) => (2, bytes),
        MembershipRequestMessage::Candidate(bytes) => (3, bytes),
        _ => unreachable!("only gossip packets are hashed"),
    };
    let mut hash = Sha256::new();
    hash.update(b"naome/verified-membership/v0/gossip\0");
    hash.update([tag]);
    hash.update(bytes);
    hash.finalize().into()
}

#[cfg(all(test, unix))]
#[path = "verified_membership_tests.rs"]
mod tests;
