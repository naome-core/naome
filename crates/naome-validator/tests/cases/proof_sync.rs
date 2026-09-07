use crate::explicit_proofs::result;
use crate::support::*;
use naome_consensus::ConsensusVoteRole as Role;
use serde_json::{Value, json};
use std::fs;

fn sync(node: &mut Process, peer: naome_network::PeerId, id: u64, count: u64) -> Value {
    result(
        node,
        json!({"command":"sync_finality", "id":id, "peer_id":peer.to_string(), "count":count}),
    )
}
fn install(node: &mut Process, layout: &Layout, proof: &Proof, label: &str) {
    proof.write(layout, label);
    if proof.round != 0 {
        assert_eq!(
            result(node, proof.higher_command(10, label, false))["event"],
            "transitioned"
        );
        node.event("timer_armed");
    }
    assert_eq!(
        result(node, proof.current_command(11, label, false))["event"],
        "finality"
    );
    node.event("timer_armed");
}
fn established(node: &mut Process) {
    node.until(|v| v["event"] == "peer_session" && v["state"] == "established");
}
fn state(node: &mut Process) -> Value {
    result(node, json!({"command":"status", "id":90}))
}

#[test]
fn proof_sync_two_processes_commit_bounded_prefix_without_sources_and_strictly_reopen() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::after_prefix(&fixture, &[&first], 0, 3, Role::Precommit);
    let third = Proof::after_prefix(&fixture, &[&first, &second], 0, 2, Role::Precommit);
    let source_layout = Layout::new();
    let receiver_layout = Layout::new();
    let receiver_config = fixture.config(
        &receiver_layout,
        1,
        "create",
        Some("/ip4/127.0.0.1/tcp/1"),
        false,
    );
    let mut receiver = Process::start(&receiver_layout, &receiver_config);
    receiver.ready();
    receiver.event("timer_armed");
    let address = receiver.event("listening")["address"]
        .as_str()
        .unwrap()
        .to_owned();
    let source_config = fixture
        .config(&source_layout, 0, "create", Some(&address), false)
        .replace("[network]", "[network]\nserve_finality_proofs = true");
    let mut source = Process::start(&source_layout, &source_config);
    source.ready();
    source.event("timer_armed");
    established(&mut source);
    established(&mut receiver);
    install(&mut source, &source_layout, &first, "first");
    install(&mut source, &source_layout, &second, "second");
    install(&mut source, &source_layout, &third, "third");
    let source_images = source_layout.images();
    assert_eq!(state(&mut receiver)["driver"]["height"], "1");
    assert!(result(&mut receiver, json!({"command":"sync_status", "id":20}))["job"].is_null());
    assert_eq!(
        sync(&mut receiver, fixture.peers[0], u64::MAX, 2)["event"],
        "sync_started"
    );
    let completed = receiver.event("sync_completed");
    assert_eq!(completed["id"], u64::MAX);
    assert_eq!(completed["completed"], "2");
    assert_eq!(completed["last_height"], "2");
    let finality = receiver.event("finality");
    assert_eq!(finality["state"]["driver"]["height"], "3");
    assert_eq!(
        finality["state"]["driver"]["head"],
        hex(second.value.artifact_block().id().as_bytes())
    );
    receiver.event("timer_armed");
    assert_eq!(
        state(&mut receiver)["driver"]["height"],
        "3",
        "bounded job must not fetch the third retained proof"
    );
    assert_eq!(
        source_layout.images(),
        source_images,
        "serving does not change provider authority"
    );
    receiver.shutdown();
    source.shutdown();
    assert!(
        receiver
            .observed
            .iter()
            .all(|v| v["event"] != "publication_prepared")
    );
    let durable = receiver_layout.images();
    let mut receiver = Process::start(
        &receiver_layout,
        &receiver_config.replace("mode = \"create\"", "mode = \"open\""),
    );
    assert_eq!(receiver.ready()["driver"]["height"], "3");
    receiver.event("timer_armed");
    let address = receiver.event("listening")["address"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(result(&mut receiver, json!({"command":"sync_status", "id":21}))["job"].is_null());
    assert_eq!(receiver_layout.images(), durable);
    let reopened_source = fixture
        .config(&source_layout, 0, "open", Some(&address), false)
        .replace("[network]", "[network]\nserve_finality_proofs = true");
    // Provider uses only durable proof records after original proof files vanish.
    for label in ["first", "second", "third"] {
        for suffix in ["control", "payload", "vote", "certificate", "envelope"] {
            let _ = fs::remove_file(source_layout.root.join(format!("{label}.{suffix}")));
        }
    }
    let mut source = Process::start(&source_layout, &reopened_source);
    source.ready();
    established(&mut source);
    established(&mut receiver);
    assert_eq!(
        sync(&mut receiver, fixture.peers[0], 22, 2)["event"],
        "sync_started"
    );
    let stopped = receiver.event("sync_stopped");
    assert_eq!(stopped["reason"], "unavailable");
    assert_eq!(stopped["job"]["completed"], "1");
    assert_eq!(state(&mut receiver)["driver"]["height"], "4");
    assert_eq!(
        state(&mut receiver)["driver"]["head"],
        hex(third.value.artifact_block().id().as_bytes())
    );
    receiver.shutdown();
    source.shutdown();
}

#[test]
fn proof_sync_schema_counts_and_peer_refusals_leave_authority_unchanged() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let before = layout.images();
    for count in [0, 17, u64::MAX] {
        node.send(json!({"command":"sync_finality", "id":1, "peer_id":fixture.peers[0].to_string(), "count":count}));
        assert_eq!(node.event("command_rejected")["code"], "sync_count");
    }
    for peer in ["bad-peer".to_owned(), fixture.peers[0].to_string()] {
        node.send(json!({"command":"sync_finality", "id":2, "peer_id":peer, "count":1}));
        node.event("command_rejected");
    }
    for command in [
        json!({"command":"sync_finality", "id":1, "peer_id":fixture.peers[0].to_string(), "count":"1"}),
        json!({"command":"sync_finality", "id":1, "peer_id":fixture.peers[0].to_string(), "count":1, "height":1}),
        json!(["sync_finality", 1, fixture.peers[0].to_string(), 1]),
    ] {
        node.send(command);
        assert_eq!(node.event("command_rejected")["code"], "command_schema");
    }
    node.write(format!("{{\"command\":\"sync_finality\",\"id\":1,\"peer_id\":\"{}\",\"count\":1,\"count\":2}}\n", fixture.peers[0]).as_bytes());
    assert_eq!(node.event("command_rejected")["code"], "command_schema");
    assert!(result(&mut node, json!({"command":"cancel_sync", "id":3}))["job"].is_null());
    assert_eq!(layout.images(), before);
    node.shutdown();
}

// This peer owns only a Noise key. Every supplied proof was prepared before
// the process/peer lifetime; it cannot produce or authorize consensus signatures.
struct Peer<'guard> {
    controls: tokio::sync::mpsc::Sender<Control>,
    reports: std::sync::mpsc::Receiver<&'static str>,
    handle: Option<std::thread::JoinHandle<()>>,
    _guard: &'guard std::sync::RwLockReadGuard<'static, ()>,
}
enum Control {
    Reply(Vec<u8>, Vec<u8>),
    Unavailable,
    DropProof,
    Ack,
    Stop,
}
impl<'guard> Peer<'guard> {
    fn start(
        guard: &'guard std::sync::RwLockReadGuard<'static, ()>,
        fixture: &Fixture,
        address: &str,
    ) -> Self {
        use naome_network::{Keypair, NetworkEvent, StaticArtifactNetwork, StaticPeer};
        let mut seed = fixture.noise[0];
        let key = Keypair::ed25519_from_bytes(&mut seed).unwrap();
        let consumer = fixture.peers[1];
        let address = address.parse().unwrap();
        let (controls, mut commands) = tokio::sync::mpsc::channel(2);
        let (send, reports) = std::sync::mpsc::sync_channel(32);
        let handle = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
                let mut network = StaticArtifactNetwork::new(key, [StaticPeer::new(consumer, address)]).unwrap();
                let mut proof = None; let mut consensus = None;
                loop {
                    tokio::select! {
                        command = commands.recv() => match command {
                            Some(Control::Reply(envelope, payload)) => {
                                network.respond_finality_proof(proof.take().expect("one held request"), Some((&envelope, &payload))).unwrap();
                            }
                            Some(Control::Unavailable) => { network.respond_finality_proof(proof.take().expect("held proof"), None).unwrap(); }
                            Some(Control::DropProof) => { drop(proof.take().expect("held proof")); }
                            Some(Control::Ack) => { let _ = network.acknowledge_consensus_push(consensus.take().expect("held publication")).unwrap(); }
                            Some(Control::Stop) | None => break,
                        },
                        event = network.next_event() => match event {
                            NetworkEvent::InboundFinalityProof(request) => { assert!(proof.replace(request).is_none()); send.try_send("proof").unwrap(); }
                            NetworkEvent::InboundConsensusPush(request) => { assert!(consensus.replace(request).is_none()); send.try_send("consensus").unwrap(); }
                            _ => {},
                        },
                    }
                }
            });
        });
        Self {
            controls,
            reports,
            handle: Some(handle),
            _guard: guard,
        }
    }
    fn held(&self, kind: &str) {
        assert_eq!(self.reports.recv_timeout(BOUND).unwrap(), kind);
    }
    fn reply(&self, envelope: Vec<u8>, payload: Vec<u8>) {
        self.controls
            .blocking_send(Control::Reply(envelope, payload))
            .unwrap();
    }
    fn ack(&self) {
        self.controls.blocking_send(Control::Ack).unwrap();
    }
}

#[path = "proof_following.rs"]
mod proof_following;
impl Drop for Peer<'_> {
    fn drop(&mut self) {
        let _ = self.controls.blocking_send(Control::Stop);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

fn waiting_node(fixture: &Fixture, layout: &Layout, publish: bool) -> (Process, String, String) {
    let config = fixture.config(layout, 1, "create", Some("/ip4/127.0.0.1/tcp/1"), publish);
    let mut node = Process::start(layout, &config);
    node.ready();
    node.event("timer_armed");
    let address = node.event("listening")["address"]
        .as_str()
        .unwrap()
        .to_owned();
    (node, config, address)
}

#[test]
fn proof_sync_rejects_authenticated_bad_proofs_without_authority_effect_and_accepts_retry() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    let future = Proof::after_prefix(&fixture, &[&proof], 0, 3, Role::Precommit);
    let sibling = Proof::new(&fixture, false, 2, Role::Precommit);
    let wrong_parent = Proof::after_prefix(&fixture, &[&sibling], 0, 3, Role::Precommit);
    let mut bad = proof.envelope.clone().unwrap();
    *bad.last_mut().unwrap() ^= 1;
    let mut foreign = proof.envelope.clone().unwrap();
    foreign[0] ^= 1;
    let cases = [
        (bad, proof.payload.clone()),
        (foreign, proof.payload.clone()),
        (proof.envelope.clone().unwrap(), vec![0]),
        (future.envelope.clone().unwrap(), future.payload.clone()),
    ];
    let layout = Layout::new();
    let (mut node, _, address) = waiting_node(&fixture, &layout, false);
    let guard = PARENT_JOURNALS.read().unwrap();
    let peer = Peer::start(&guard, &fixture, &address);
    established(&mut node);
    let images = layout.images();
    for (envelope, payload) in cases {
        assert_eq!(
            sync(&mut node, fixture.peers[0], 30, 1)["event"],
            "sync_started"
        );
        peer.held("proof");
        peer.reply(envelope, payload);
        assert_eq!(node.event("sync_stopped")["reason"], "proof_not_committed");
        node.event("finality_envelope_rejected");
        assert_eq!(layout.images(), images);
        assert_eq!(state(&mut node)["driver"]["height"], "1");
    }
    assert_eq!(
        sync(&mut node, fixture.peers[0], 31, 1)["event"],
        "sync_started"
    );
    peer.held("proof");
    peer.reply(proof.envelope.unwrap(), proof.payload);
    node.event("sync_completed");
    assert_eq!(node.event("finality")["state"]["driver"]["height"], "2");
    node.event("timer_armed");
    let images = layout.images();
    sync(&mut node, fixture.peers[0], 32, 1);
    peer.held("proof");
    peer.reply(wrong_parent.envelope.unwrap(), wrong_parent.payload);
    assert_eq!(node.event("sync_stopped")["reason"], "proof_not_committed");
    node.event("finality_envelope_rejected");
    assert_eq!(layout.images(), images);
    sync(&mut node, fixture.peers[0], 33, 1);
    peer.held("proof");
    peer.reply(future.envelope.unwrap(), future.payload);
    node.event("sync_completed");
    assert_eq!(node.event("finality")["state"]["driver"]["height"], "3");
    node.shutdown();
    drop(peer);
    drop(guard);
}

#[test]
fn proof_sync_cancel_discards_late_response_and_does_not_resume_after_strict_process_restart() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    let layout = Layout::new();
    let (mut node, config, address) = waiting_node(&fixture, &layout, false);
    let guard = PARENT_JOURNALS.read().unwrap();
    let peer = Peer::start(&guard, &fixture, &address);
    established(&mut node);
    let images = layout.images();
    sync(&mut node, fixture.peers[0], 40, 16);
    peer.held("proof");
    node.send(json!({"command":"sync_finality", "id":41, "peer_id":fixture.peers[0].to_string(), "count":1}));
    assert_eq!(node.event("command_rejected")["code"], "sync_busy");
    node.send(
        json!({"command":"acquire_ancestry", "id":41, "target":"invalid", "peer_id":"invalid"}),
    );
    assert_eq!(node.event("command_rejected")["code"], "sync_busy");
    assert_eq!(
        result(&mut node, json!({"command":"sync_status", "id":42}))["job"]["id"],
        40
    );
    assert_eq!(
        result(&mut node, json!({"command":"cancel_sync", "id":43}))["job"]["id"],
        40
    );
    assert_eq!(node.event("sync_stopped")["reason"], "cancelled");
    // Cancellation ends logical ownership; physical peer custody still rejects
    // a new request until the exact old response is consumed or times out.
    node.send(json!({"command":"sync_finality", "id":44, "peer_id":fixture.peers[0].to_string(), "count":1}));
    assert_eq!(node.event("command_rejected")["code"], "sync_request_start");
    peer.reply(proof.envelope.clone().unwrap(), proof.payload.clone());
    node.event("sync_response_discarded");
    assert_eq!(layout.images(), images);
    sync(&mut node, fixture.peers[0], 45, 2);
    peer.held("proof");
    peer.reply(proof.envelope.clone().unwrap(), proof.payload.clone());
    assert_eq!(node.event("sync_progress")["completed"], "1");
    peer.held("proof");
    assert_eq!(state(&mut node)["driver"]["height"], "2");
    let images = layout.images();
    node.signal(rustix::process::Signal::KILL);
    assert!(!node.exit().success());
    drop(peer);
    drop(guard);
    let mut node = Process::start(
        &layout,
        &config.replace("mode = \"create\"", "mode = \"open\""),
    );
    assert_eq!(node.ready()["driver"]["height"], "2");
    node.event("timer_armed");
    assert!(result(&mut node, json!({"command":"sync_status", "id":46}))["job"].is_null());
    assert_eq!(layout.images(), images);
    node.shutdown();
}

#[test]
fn proof_sync_live_head_change_discards_in_flight_response_without_historical_routing() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    let layout = Layout::new();
    proof.write(&layout, "proof");
    let (mut node, _, address) = waiting_node(&fixture, &layout, false);
    let guard = PARENT_JOURNALS.read().unwrap();
    let peer = Peer::start(&guard, &fixture, &address);
    established(&mut node);
    sync(&mut node, fixture.peers[0], 50, 2);
    peer.held("proof");
    assert_eq!(
        result(&mut node, proof.current_command(51, "proof", false))["event"],
        "finality"
    );
    assert_eq!(node.event("sync_stopped")["reason"], "sync_head_changed");
    let images = layout.images();
    peer.reply(proof.envelope.unwrap(), proof.payload);
    node.event("sync_response_discarded");
    assert_eq!(layout.images(), images);
    assert_eq!(state(&mut node)["driver"]["height"], "2");
    node.shutdown();
    drop(peer);
    drop(guard);
}

#[test]
fn proof_sync_retained_finality_and_live_publication_backpressure_dispose_response() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    for publication in [false, true] {
        let layout = Layout::new();
        proof.write(&layout, "proof");
        let (mut node, _, address) = waiting_node(&fixture, &layout, publication);
        let guard = PARENT_JOURNALS.read().unwrap();
        let peer = Peer::start(&guard, &fixture, &address);
        established(&mut node);
        sync(&mut node, fixture.peers[0], 60, 1);
        peer.held("proof");
        let command = if publication {
            json!({"command":"submit_proposal", "id":61, "control_file":"proof.control", "payload_file":"proof.payload"})
        } else {
            json!({"command":"submit_vote", "id":61, "vote_file":"proof.vote"})
        };
        assert_eq!(result(&mut node, command)["event"], "input_queued");
        node.event("admission");
        if publication {
            node.event("publication_prepared");
            node.event("peer_attempted");
            peer.held("consensus");
        } else {
            node.event("driver_blocked");
        }
        let images = layout.images();
        peer.reply(proof.envelope.clone().unwrap(), proof.payload.clone());
        assert_eq!(
            node.event("sync_stopped")["reason"],
            if publication {
                "proof_backpressure"
            } else {
                "proof_not_committed"
            }
        );
        if !publication {
            node.event("current_finality_unresolved");
        }
        assert_eq!(layout.images(), images);
        if publication {
            peer.ack();
            node.event("publication_complete");
        } else {
            result(
                &mut node,
                json!({"command":"discard_inbox", "id":62, "inbox":"finality"}),
            );
        }
        assert_eq!(
            sync(&mut node, fixture.peers[0], 63, 1)["event"],
            "sync_started"
        );
        peer.held("proof");
        peer.reply(proof.envelope.clone().unwrap(), proof.payload.clone());
        node.event("sync_completed");
        assert_eq!(node.event("finality")["state"]["driver"]["height"], "2");
        node.shutdown();
        drop(peer);
        drop(guard);
    }
}
