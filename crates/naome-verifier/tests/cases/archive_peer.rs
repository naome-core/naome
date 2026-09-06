//! A real configured Noise peer supplies bounded malicious complete responses.

use std::{collections::VecDeque, time::Duration};

use naome_network::{
    FinalityProofRequest, InboundFinalityProofRequest, NetworkEvent, PeerId, StaticArtifactNetwork,
    StaticPeer,
};
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};

use super::archive::{config, identities, listening};
use crate::support::*;

struct Peer {
    process: Process,
    network: Option<StaticArtifactNetwork>,
    id: PeerId,
    requests: VecDeque<InboundFinalityProofRequest>,
    history: Vec<FinalityProofRequest>,
    layout: Layout,
}

impl Peer {
    async fn new(fixture: &Fixture) -> Self {
        let [(client, seed), _, (server, _)] = identities();
        let id = server.public().to_peer_id();
        let client_id = client.public().to_peer_id();
        let mut network = StaticArtifactNetwork::new(
            server,
            [StaticPeer::new(
                client_id,
                "/ip4/127.0.0.1/tcp/9".parse().unwrap(),
            )],
        )
        .unwrap();
        network
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let address = timeout(Duration::from_secs(10), async {
            loop {
                if let NetworkEvent::Listening { address } = network.next_event().await {
                    break address.to_string();
                }
            }
        })
        .await
        .unwrap();
        let layout = Layout::new();
        let mut process = Process::start(
            &layout,
            &config(fixture, &layout, "create", seed, &[(id, address)]),
        );
        process.ready();
        listening(&mut process);
        let mut peer = Self {
            layout,
            process,
            network: Some(network),
            id,
            requests: VecDeque::new(),
            history: Vec::new(),
        };
        peer.until(|event| event["event"] == "peer_session" && event["kind"] == "established")
            .await;
        peer
    }

    async fn pump(&mut self) {
        self.process.observe();
        let Some(network) = &mut self.network else {
            sleep(Duration::from_millis(1)).await;
            return;
        };
        tokio::select! {
            event = network.next_event() => if let NetworkEvent::InboundFinalityProof(inbound) = event {
                self.history.push(inbound.request());
                self.requests.push_back(inbound);
                assert!(self.history.len() <= 64);
            },
            _ = sleep(Duration::from_millis(1)) => {},
        }
    }

    async fn until(&mut self, predicate: impl Fn(&Value) -> bool) -> Value {
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(value) = self.process.observed.iter().find(|value| predicate(value)) {
                    return value.clone();
                }
                self.pump().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "peer reports: {:?}; requests: {:?}",
                self.process.observed, self.history
            )
        })
    }

    async fn command(&mut self, command: Value) -> Value {
        let id = command["id"].clone();
        self.process.send(command);
        self.until(|event| event["id"] == id).await
    }

    async fn start(&mut self, id: u64, count: u64) -> InboundFinalityProofRequest {
        assert_eq!(
            self.command(
                json!({"command":"sync","id":id,"peer_id":self.id.to_string(),"count":count})
            )
            .await["outcome"]["kind"],
            "sync_started"
        );
        self.inbound().await
    }

    async fn inbound(&mut self) -> InboundFinalityProofRequest {
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(inbound) = self.requests.pop_front() {
                    return inbound;
                }
                self.pump().await;
            }
        })
        .await
        .unwrap()
    }

    fn respond(&mut self, inbound: InboundFinalityProofRequest, proof: Option<(&[u8], &[u8])>) {
        self.network
            .as_mut()
            .unwrap()
            .respond_finality_proof(inbound, proof)
            .unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn archive_network_rejects_wrong_height_context_signature_payload_and_quorum_before_retry() {
    let fixture = Fixture::new();
    let first = fixture.proof(&[], 0, 1);
    let second = fixture.proof(&[&first], 0, 2);
    let mut wrong_signature = first.envelope.clone();
    *wrong_signature.last_mut().unwrap() ^= 1;
    let mut wrong_context = first.envelope.clone();
    wrong_context[0] ^= 1;
    let insufficient = envelope(
        &first,
        &fixture.keys[first.proposer],
        &[&fixture.keys[0], &fixture.keys[1]],
        2,
    );
    let mut peer = Peer::new(&fixture).await;
    let images = peer.layout.images();
    let mut id = 101;
    for (envelope, payload, reason) in [
        (&second.envelope, &second.payload, "response_address"),
        (&wrong_context, &first.payload, "envelope_context"),
        (&wrong_signature, &first.payload, "proof_verification"),
        (&first.envelope, &second.payload, "proof_verification"),
        (&insufficient, &first.payload, "proof_verification"),
    ] {
        let inbound = peer.start(id, 2).await;
        assert_eq!(inbound.request().height().value(), 1);
        assert_eq!(inbound.request().context(), fixture.context);
        peer.respond(inbound, Some((envelope, payload)));
        let stopped = peer
            .until(|event| event["event"] == "sync_stopped" && event["id"] == id)
            .await;
        assert_eq!(stopped["reason"], reason);
        assert_eq!(stopped["completed"], "0");
        assert_eq!(peer.layout.images(), images);
        assert_eq!(
            peer.history.len(),
            (id - 100) as usize,
            "no implicit data retry"
        );
        id += 1;
    }
    let inbound = peer.start(id, 2).await;
    peer.respond(inbound, Some((&first.envelope, &first.payload)));
    let next = peer.inbound().await;
    assert_eq!(next.request().height().value(), 2);
    peer.respond(next, None);
    let stopped = peer
        .until(|event| event["event"] == "sync_stopped" && event["id"] == id)
        .await;
    assert_eq!(stopped["reason"], "unavailable");
    assert_eq!(stopped["completed"], "1");
    assert_eq!(stopped["next_height"], "2");
    peer.process.shutdown();
    super::archive::check_history(&fixture, &peer.layout, &[&first]);
}

#[tokio::test(flavor = "current_thread")]
async fn archive_busy_cancel_and_late_response_preserve_prefix_and_require_explicit_restart() {
    let fixture = Fixture::new();
    let first = fixture.proof(&[], 0, 1);
    let second = fixture.proof(&[&first], 0, 2);
    let mut peer = Peer::new(&fixture).await;
    let images = peer.layout.images();
    for (id, count) in [(201, 0), (202, 17), (203, u64::MAX)] {
        assert_eq!(
            peer.command(
                json!({"command":"sync","id":id,"peer_id":peer.id.to_string(),"count":count})
            )
            .await["code"],
            "sync_count"
        );
    }
    assert!(peer.history.is_empty());
    let held = peer.start(204, 2).await;
    assert_eq!(
        peer.command(Proof::command(205, "missing")).await["code"],
        "sync_busy"
    );
    assert_eq!(
        peer.command(json!({"command":"sync","id":206,"peer_id":peer.id.to_string(),"count":1}))
            .await["code"],
        "sync_busy"
    );
    assert_eq!(
        peer.command(json!({"command":"status","id":207})).await["outcome"]["state"]["head"]["height"],
        "0"
    );
    let cancelled = peer
        .command(json!({"command":"cancel_sync","id":208}))
        .await;
    assert_eq!(cancelled["outcome"]["kind"], "sync_cancelled");
    assert_eq!(cancelled["outcome"]["sync_id"], 204);
    assert_eq!(cancelled["outcome"]["completed"], "0");
    assert_eq!(
        peer.command(json!({"command":"cancel_sync","id":209}))
            .await["code"],
        "sync_inactive"
    );
    assert_eq!(
        peer.command(json!({"command":"sync","id":210,"peer_id":peer.id.to_string(),"count":1}))
            .await["code"],
        "sync_request_start"
    );
    peer.respond(held, Some((&first.envelope, &first.payload)));
    peer.until(|event| event["event"] == "sync_response_discarded" && event["height"] == "1")
        .await;
    assert_eq!(peer.layout.images(), images);
    assert_eq!(peer.history.len(), 1);
    let inbound = peer.start(211, 1).await;
    peer.respond(inbound, Some((&first.envelope, &first.payload)));
    peer.until(|event| event["event"] == "sync_completed" && event["id"] == 211)
        .await;
    let inbound = peer.start(212, 2).await;
    assert_eq!(inbound.request().height().value(), 2);
    peer.respond(inbound, Some((&second.envelope, &second.payload)));
    let held = peer.inbound().await;
    assert_eq!(held.request().height().value(), 3);
    let prefix = peer.layout.images();
    // An ordinary shutdown abandons the unacknowledged request; strict reopen
    // resumes the retained head only, with no persistent synchronization task.
    peer.process.shutdown();
    drop(held);
    drop(peer.network.take());
    super::archive::check_history(&fixture, &peer.layout, &[&first, &second]);
    let mut reopened = Process::start(&peer.layout, &fixture.config("open"));
    assert_eq!(reopened.ready()["head"]["height"], "2");
    assert_eq!(peer.layout.images(), prefix);
    assert_eq!(
        reopened
            .request(json!({"command":"sync","id":213,"peer_id":peer.id.to_string(),"count":1}))["code"],
        "network_disabled"
    );
    reopened.shutdown();
    assert_eq!(peer.layout.images(), prefix);
}

#[tokio::test(flavor = "current_thread")]
async fn archive_connection_loss_keeps_only_acknowledged_prefix() {
    let fixture = Fixture::new();
    let first = fixture.proof(&[], 0, 1);
    let mut peer = Peer::new(&fixture).await;
    let inbound = peer.start(301, 2).await;
    peer.respond(inbound, Some((&first.envelope, &first.payload)));
    let held = peer.inbound().await;
    assert_eq!(held.request().height().value(), 2);
    let prefix = peer.layout.images();
    drop(peer.network.take());
    drop(held);
    let stopped = peer
        .until(|event| event["event"] == "sync_stopped" && event["id"] == 301)
        .await;
    assert_eq!(stopped["reason"], "transport_failure");
    assert_eq!(stopped["completed"], "1");
    assert_eq!(peer.layout.images(), prefix);
    assert_eq!(peer.history.len(), 2);
    peer.process.shutdown();
    super::archive::check_history(&fixture, &peer.layout, &[&first]);
}

#[tokio::test(flavor = "current_thread")]
async fn archive_anchor_failure_never_acknowledges_the_suffix_or_repairs_it_on_restart() {
    let fixture = Fixture::new();
    let first = fixture.proof(&[], 0, 1);
    let second = fixture.proof(&[&first], 0, 2);
    let mut peer = Peer::new(&fixture).await;
    let inbound = peer.start(401, 2).await;
    peer.respond(inbound, Some((&first.envelope, &first.payload)));
    let next = peer.inbound().await;
    assert_eq!(next.request().height().value(), 2);
    let prefix_journal = std::fs::read(peer.layout.journal()).unwrap();
    let prefix_anchor = std::fs::read(peer.layout.anchor()).unwrap();
    let collision = peer.layout.write(
        "finality-anchor/fixed-validator-finality.anchor.tmp-0000000000000002",
        b"caller-owned collision",
    );
    peer.respond(next, Some((&second.envelope, &second.payload)));
    let failed = peer.until(|event| event["event"] == "command_failed").await;
    assert_eq!(failed["id"], 401);
    assert_eq!(failed["code"], "finality_commit");
    assert_eq!(failed["completed"], "1");
    assert_eq!(failed["strict_restart_required"], true);
    let final_report = peer.until(|event| event["event"] == "error").await;
    assert_eq!(final_report["code"], "finality_commit");
    assert_eq!(final_report["locks_released"], true);
    assert!(!peer.process.exit().success());
    assert_eq!(
        peer.process
            .observed
            .iter()
            .filter(|event| event["event"] == "sync_progress")
            .count(),
        1
    );
    assert!(
        peer.process
            .observed
            .iter()
            .all(|event| event["event"] != "sync_completed")
    );
    assert_eq!(peer.history.len(), 2);
    assert_eq!(std::fs::read(peer.layout.anchor()).unwrap(), prefix_anchor);
    let suffix_journal = std::fs::read(peer.layout.journal()).unwrap();
    assert!(suffix_journal.len() > prefix_journal.len());
    assert!(suffix_journal.starts_with(&prefix_journal));
    assert_eq!(std::fs::read(collision).unwrap(), b"caller-owned collision");
    let images = peer.layout.images();
    for _ in 0..2 {
        let mut reopened = Process::start(&peer.layout, &fixture.config("open"));
        assert_eq!(reopened.event("error")["code"], "startup_open");
        assert!(!reopened.exit().success());
        assert_eq!(peer.layout.images(), images);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn archive_halted_history_is_never_served_or_reopened_as_ready() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let first = fixture.proof(&[], 0, 1);
    let sibling = fixture.proof(&[], 1, 2);
    first.write(&layout, "first");
    sibling.write(&layout, "sibling");
    let [(_, seed), _, _] = identities();
    let mut process = Process::start(&layout, &config(&fixture, &layout, "create", seed, &[]));
    process.ready();
    listening(&mut process);
    assert_eq!(
        process.request(Proof::command(601, "first"))["outcome"]["kind"],
        "finalized"
    );
    assert_eq!(
        process.request(Proof::command(602, "sibling"))["outcome"]["kind"],
        "halted"
    );
    assert_eq!(process.event("stopped")["reason"], "finality_halted");
    assert!(!process.exit().success());
    let images = layout.images();
    let mut peer = Peer::new(&fixture).await;
    let inbound = peer.start(603, 1).await;
    let result = fixture.inspect(&layout, |journal| {
        peer.network
            .as_mut()
            .unwrap()
            .respond_finality_proof_from_journal(inbound, journal)
    });
    assert!(matches!(
        result,
        Err(naome_network::FinalityProofRespondError::Journal(_))
    ));
    let stopped = peer
        .until(|event| event["event"] == "sync_stopped" && event["id"] == 603)
        .await;
    assert_eq!(stopped["reason"], "transport_failure");
    assert_eq!(stopped["completed"], "0");
    peer.process.shutdown();
    let mut reopened = Process::start(&layout, &config(&fixture, &layout, "open", seed, &[]));
    assert!(reopened.event("halted")["state"]["head"].is_null());
    assert_eq!(reopened.event("stopped")["reason"], "finality_halted");
    assert!(!reopened.exit().success());
    assert!(reopened.observed.iter().all(|event| !matches!(
        event["event"].as_str(),
        Some("ready" | "listening" | "proof_response_queued")
    )));
    assert_eq!(layout.images(), images);
}
