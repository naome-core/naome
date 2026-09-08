//! Explicit bounded archive synchronization and serving on configured sessions.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use naome_consensus::{ActiveAgreementEntry, ConsensusHeight};
use naome_network::{
    FinalityProofRequest, FinalityProofRespondError, FinalityProofResponse, FinalityProofTicket,
    Keypair, MAX_STATIC_PEERS, Multiaddr, NetworkEvent, OutboundFinalityProofEvent,
    OutboundFinalityProofFailure, PeerId, PeerSessionEvent, StaticArtifactNetwork, StaticPeer,
};
use naome_storage::FixedValidatorAnchoredFinalityJournalV0 as Journal;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::time::Instant;

use super::{
    Result,
    commands::{self, Failure},
    files, report,
};

const MAX_SYNC_HEIGHTS: u64 = 16;
const SYNC_NETWORK_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    identity_seed_file: PathBuf,
    listen: String,
    peers: Vec<Peer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    peer_id: String,
    address: String,
}

pub(super) struct Prepared {
    network: StaticArtifactNetwork,
    listen: Multiaddr,
}

impl Config {
    pub fn prepare(self, base: &Path, entries: &[ActiveAgreementEntry]) -> Result<Prepared> {
        if self.peers.len() > MAX_STATIC_PEERS {
            return Err("peers_limit");
        }
        let mut seed = files::seed(&base.join(self.identity_seed_file))?;
        let identity = Keypair::ed25519_from_bytes(&mut *seed).map_err(|_| "identity_seed")?;
        let public = identity
            .public()
            .try_into_ed25519()
            .map_err(|_| "identity_key")?
            .to_bytes();
        if entries
            .iter()
            .any(|entry| entry.consensus_key().as_bytes() == &public)
        {
            return Err("consensus_identity_reuse");
        }
        let peers = self
            .peers
            .into_iter()
            .map(|peer| {
                Ok(StaticPeer::new(
                    peer.peer_id.parse().map_err(|_| "peer_id")?,
                    tcp_address(&peer.address, false)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Prepared {
            network: StaticArtifactNetwork::new(identity, peers).map_err(|_| "network_config")?,
            listen: tcp_address(&self.listen, true)?,
        })
    }
}

impl Prepared {
    pub fn start(mut self) -> Result<Archive> {
        self.network
            .listen_on(self.listen)
            .map_err(|_| "network_listen")?;
        Ok(Archive {
            network: self.network,
            sync: None,
            following: None,
        })
    }
}

fn tcp_address(value: &str, listener: bool) -> Result<Multiaddr> {
    let fields = value.split('/').collect::<Vec<_>>();
    if fields.len() != 5
        || !fields[0].is_empty()
        || !matches!(fields[1], "ip4" | "ip6")
        || fields[3] != "tcp"
    {
        return Err("tcp_address");
    }
    let port: u16 = fields[4].parse().map_err(|_| "tcp_port")?;
    if !listener && port == 0 {
        return Err("tcp_peer_port_zero");
    }
    value.parse().map_err(|_| "tcp_address")
}

struct Sync {
    id: u64,
    peer: PeerId,
    last: u64,
    completed: u64,
    ticket: FinalityProofTicket,
    deadline: Instant,
}

struct Following {
    id: u64,
    peer: PeerId,
    count: u64,
    interval: Duration,
    due: Instant,
}

pub(super) struct Archive {
    pub network: StaticArtifactNetwork,
    sync: Option<Sync>,
    following: Option<Following>,
}

impl Archive {
    pub fn active(&self) -> bool {
        self.sync.is_some()
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.sync
            .as_ref()
            .map(|sync| sync.deadline)
            .or_else(|| self.following.as_ref().map(|follow| follow.due))
    }

    pub fn start_sync(
        &mut self,
        id: u64,
        peer: &str,
        count: u64,
        journal: &Journal,
    ) -> std::result::Result<Value, Failure> {
        if self.active() || self.following.is_some() {
            return Err(Failure::Rejected("sync_busy"));
        }
        self.start_pass(id, peer, count, journal)
    }

    fn start_pass(
        &mut self,
        id: u64,
        peer: &str,
        count: u64,
        journal: &Journal,
    ) -> std::result::Result<Value, Failure> {
        use Failure::{Fatal, Rejected};
        if self.active() {
            return Err(Rejected("sync_busy"));
        }
        if !(1..=MAX_SYNC_HEIGHTS).contains(&count) {
            return Err(Rejected("sync_count"));
        }
        let peer: PeerId = peer.parse().map_err(|_| Rejected("peer_id"))?;
        let height = journal
            .head()
            .map_err(|_| Fatal("finality_state"))?
            .verified_height()
            .map_or(0, |height| height.value());
        let last = height
            .checked_add(count)
            .ok_or(Rejected("sync_height_overflow"))?;
        let request =
            FinalityProofRequest::new(journal.context(), ConsensusHeight::new(height + 1))
                .expect("checked positive successor");
        let deadline = Instant::now()
            .checked_add(SYNC_NETWORK_TIMEOUT)
            .ok_or(Rejected("sync_deadline_overflow"))?;
        let ticket = self
            .network
            .request_finality_proof(peer, request)
            .map_err(|_| Rejected("sync_request_start"))?;
        self.sync = Some(Sync {
            id,
            peer,
            last,
            completed: 0,
            ticket,
            deadline,
        });
        Ok(
            json!({"kind": "sync_started", "peer_id": peer.to_string(), "first_height": (height + 1).to_string(), "last_height": last.to_string()}),
        )
    }

    pub fn follow(
        &mut self,
        id: u64,
        peer: &str,
        count: u64,
        millis: &str,
        journal: &Journal,
    ) -> std::result::Result<Value, Failure> {
        use Failure::{Fatal, Rejected};
        if self.active() || self.following.is_some() {
            return Err(Rejected("sync_busy"));
        }
        if !(1..=MAX_SYNC_HEIGHTS).contains(&count) {
            return Err(Rejected("sync_count"));
        }
        let peer: PeerId = peer.parse().map_err(|_| Rejected("peer_id"))?;
        if millis.is_empty()
            || !millis.bytes().all(|byte| byte.is_ascii_digit())
            || (millis.len() > 1 && millis.starts_with('0'))
        {
            return Err(Rejected("follow_interval"));
        }
        let millis: u64 = millis.parse().map_err(|_| Rejected("follow_interval"))?;
        if millis == 0 {
            return Err(Rejected("follow_interval"));
        }
        let interval = Duration::from_millis(millis);
        let due = Instant::now()
            .checked_add(interval)
            .ok_or(Rejected("follow_deadline_overflow"))?;
        if !self.network.is_configured_peer(&peer) {
            return Err(Rejected("follow_peer_not_configured"));
        }
        journal.head().map_err(|_| Fatal("finality_state"))?;
        self.following = Some(Following {
            id,
            peer,
            count,
            interval,
            due,
        });
        Ok(json!({"kind": "follow_started", "job": self.status()}))
    }

    pub fn status(&self) -> Value {
        let mut value = if let Some(sync) = &self.sync {
            json!({"id": sync.id, "peer_id": sync.peer.to_string(),
                "completed": sync.completed.to_string(), "next_height": sync.ticket.request().height().value().to_string(),
                "last_height": sync.last.to_string()})
        } else if let Some(follow) = &self.following {
            json!({"id": follow.id, "peer_id": follow.peer.to_string()})
        } else {
            return Value::Null;
        };
        if let Some(follow) = &self.following {
            value["following"] = json!(true);
            value["state"] = json!(if self.active() { "active" } else { "waiting" });
            value["count"] = json!(follow.count);
            value["interval_millis"] = json!(follow.interval.as_millis().to_string());
        }
        value
    }

    // A waiting intent holds no request. Each new pass derives its heights from
    // the current anchored head, including any intervening local import.
    pub fn elapsed(&mut self, journal: &Journal, output: &report::Output) -> Result<()> {
        if let Some(sync) = self.sync.take() {
            Self::stopped(sync, "network_deadline", output)?;
            return self.finish_follow("network_deadline", true, output);
        }
        let follow = self.following.as_ref().ok_or("sync_inactive")?;
        let (id, peer, count) = (follow.id, follow.peer.to_string(), follow.count);
        match self.start_pass(id, &peer, count, journal) {
            Ok(outcome) => output.emit(json!({"event": "sync_pass_started", "id": id, "outcome": outcome, "job": self.status()})),
            Err(Failure::Rejected(reason)) => {
                // Configuration was checked when intent was installed. Only
                // physical request custody/session absence is retryable here.
                self.finish_follow(reason, reason == "sync_request_start", output)
            }
            Err(Failure::Fatal(reason)) => Err(reason),
        }
    }

    fn finish_follow(
        &mut self,
        reason: &'static str,
        retry: bool,
        output: &report::Output,
    ) -> Result<()> {
        let Some(mut follow) = self.following.take() else {
            return Ok(());
        };
        let id = follow.id;
        if retry {
            if let Some(due) = Instant::now().checked_add(follow.interval) {
                follow.due = due;
                self.following = Some(follow);
                return output.emit(json!({"event": "follow_waiting", "id": id, "reason": reason, "job": self.status()}));
            }
            return output.emit(
                json!({"event": "follow_stopped", "id": id, "reason": "follow_deadline_overflow"}),
            );
        }
        output.emit(json!({"event": "follow_stopped", "id": id, "reason": reason}))
    }

    pub fn cancel(&mut self) -> std::result::Result<Value, Failure> {
        let job = self.status();
        let follow = self.following.take();
        if let Some(sync) = self.sync.take() {
            let mut outcome = json!({"kind": "sync_cancelled", "sync_id": sync.id,
                "completed": sync.completed.to_string(), "next_height": sync.ticket.request().height().value().to_string()});
            if follow.is_some() {
                outcome["job"] = job;
            }
            return Ok(outcome);
        }
        let follow = follow.ok_or(Failure::Rejected("sync_inactive"))?;
        Ok(json!({"kind": "sync_cancelled", "sync_id": follow.id, "job": job}))
    }

    fn stopped(sync: Sync, reason: &'static str, output: &report::Output) -> Result<()> {
        output.emit(json!({"event": "sync_stopped", "id": sync.id, "reason": reason,
            "completed": sync.completed.to_string(), "next_height": sync.ticket.request().height().value().to_string()}))
    }

    pub fn handle(
        &mut self,
        event: NetworkEvent,
        journal: &mut Journal,
        output: &report::Output,
    ) -> Result<bool> {
        match event {
            NetworkEvent::InboundFinalityProof(inbound) => {
                let peer = inbound.peer_id();
                let height = inbound.request().height().value();
                match self.network.respond_finality_proof_from_journal(inbound, journal) {
                    Ok(()) => output.emit(json!({"event": "proof_response_queued", "peer_id": peer.to_string(), "height": height.to_string()}))?,
                    Err(FinalityProofRespondError::Journal(_)) => return Err("finality_state"),
                    Err(_) => output.emit(json!({"event": "proof_response_failed", "peer_id": peer.to_string(), "height": height.to_string()}))?,
                }
            }
            NetworkEvent::OutboundFinalityProof(event) => return self.complete(event, journal, output),
            NetworkEvent::Listening { address } => output.emit(json!({"event": "listening", "address": address.to_string(), "peer_id": self.network.local_peer_id().to_string()}))?,
            NetworkEvent::PeerSession(event) => {
                let kind = match event {
                    PeerSessionEvent::Established { .. } => "established",
                    PeerSessionEvent::Disconnected { .. } => "disconnected",
                    PeerSessionEvent::DialFailed { .. } => "dial_failed",
                    _ => "other",
                };
                output.emit(json!({"event": "peer_session", "kind": kind, "peer_id": event.peer_id().to_string()}))?;
            }
            NetworkEvent::ListenerClosed { .. } | NetworkEvent::ListenerError { .. } => return Err("network_listener"),
            // This profile installs no consensus admission or general artifact service.
            _ => {},
        }
        Ok(false)
    }

    fn complete(
        &mut self,
        event: OutboundFinalityProofEvent,
        journal: &mut Journal,
        output: &report::Output,
    ) -> Result<bool> {
        // A late result after cancellation cannot resume or advance another command.
        if !self
            .sync
            .as_ref()
            .is_some_and(|sync| sync.ticket.accepts_event(&event))
        {
            output.emit(
                json!({"event": "sync_response_discarded", "peer_id": event.peer_id().to_string(),
                "height": event.request().height().value().to_string()}),
            )?;
            return Ok(false);
        }
        let sync = self.sync.take().expect("matching active sync");
        if Instant::now() >= sync.deadline {
            Self::stopped(sync, "network_deadline", output)?;
            self.finish_follow("network_deadline", true, output)?;
            return Ok(false);
        }
        let request = sync.ticket.request();
        let response = sync
            .ticket
            .complete(event)
            .map_err(|_| "sync_correlation")?;
        let stop = |reason| {
            output.emit(json!({"event": "sync_stopped", "id": sync.id,
            "reason": reason, "completed": sync.completed.to_string(),
            "next_height": request.height().value().to_string()}))
        };
        let response = match response {
            Ok(response) => response.into_response(),
            Err(error) => {
                let retry = !error.is_invalid_response()
                    && matches!(*error, OutboundFinalityProofFailure::Transport(_));
                stop("transport_failure")?;
                self.finish_follow("transport_failure", retry, output)?;
                return Ok(false);
            }
        };
        let FinalityProofResponse::Found {
            canonical_envelope,
            canonical_artifact,
        } = response
        else {
            stop("unavailable")?;
            self.finish_follow("unavailable", true, output)?;
            return Ok(false);
        };
        let parent_height = journal
            .head()
            .map_err(|_| "finality_state")?
            .verified_height()
            .map_or(0, |height| height.value());
        if parent_height.checked_add(1) != Some(request.height().value()) {
            return Err("sync_parent_changed");
        }
        let (outcome, halted) = match commands::import_response(
            &canonical_envelope,
            canonical_artifact,
            request,
            journal,
        ) {
            Ok(result) => result,
            Err(Failure::Rejected(reason)) => {
                stop(reason)?;
                self.finish_follow(reason, false, output)?;
                return Ok(false);
            }
            Err(Failure::Fatal(code)) => {
                output.emit(
                    json!({"event": "command_failed", "id": sync.id, "code": code,
                    "completed": sync.completed.to_string(), "strict_restart_required": true}),
                )?;
                return Err(code);
            }
        };
        output.emit(json!({"event": "sync_progress", "id": sync.id, "outcome": outcome}))?;
        if halted {
            return Ok(true);
        }
        let completed = sync.completed + 1;
        let height = request.height().value();
        if height == sync.last {
            output.emit(json!({"event": "sync_completed", "id": sync.id,
                "completed": completed.to_string(), "last_height": height.to_string()}))?;
            self.finish_follow("pass_completed", true, output)?;
            return Ok(false);
        }
        // A synchronous proof/fsync may outlast the network-wait budget; its
        // acknowledged prefix remains durable, but no later request starts.
        if Instant::now() >= sync.deadline {
            output.emit(
                json!({"event": "sync_stopped", "id": sync.id, "reason": "network_deadline",
                "completed": completed.to_string(), "next_height": (height + 1).to_string()}),
            )?;
            self.finish_follow("network_deadline", true, output)?;
            return Ok(false);
        }
        let request =
            FinalityProofRequest::new(journal.context(), ConsensusHeight::new(height + 1))
                .expect("successor below checked last height");
        match self.network.request_finality_proof(sync.peer, request) {
            Ok(ticket) => {
                self.sync = Some(Sync {
                    completed,
                    ticket,
                    ..sync
                })
            }
            Err(_) => {
                output.emit(json!({"event": "sync_stopped", "id": sync.id, "reason": "request_start",
                    "completed": completed.to_string(), "next_height": request.height().value().to_string()}))?;
                self.finish_follow("request_start", true, output)?;
            }
        }
        Ok(false)
    }
}
