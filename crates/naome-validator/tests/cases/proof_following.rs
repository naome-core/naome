use super::*;
use std::time::{Duration, Instant};

fn follow(
    node: &mut Process,
    peer: naome_network::PeerId,
    id: u64,
    count: u64,
    millis: &str,
) -> Value {
    result(
        node,
        json!({"command":"follow_finality", "id":id, "peer_id":peer.to_string(), "count":count, "interval_millis":millis}),
    )
}
fn job(node: &mut Process) -> Value {
    result(node, json!({"command":"sync_status", "id":91}))["job"].clone()
}
fn cancel(node: &mut Process) {
    result(node, json!({"command":"cancel_sync", "id":92}));
    assert_eq!(node.event("follow_stopped")["reason"], "cancelled");
}

#[test]
fn proof_following_validates_before_installation_and_cancels_waiting_owner() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let (mut node, _, _) = waiting_node(&fixture, &layout, false);
    let before = layout.images();
    for millis in ["0", "01", "-1", "+1", " 1", "1.0", "18446744073709551616"] {
        node.send(json!({"command":"follow_finality", "id":1, "peer_id":fixture.peers[0].to_string(), "count":1, "interval_millis":millis}));
        assert_eq!(node.event("command_rejected")["code"], "follow_interval");
    }
    for count in [0, 17, u64::MAX] {
        node.send(json!({"command":"follow_finality", "id":2, "peer_id":fixture.peers[0].to_string(), "count":count, "interval_millis":"100"}));
        assert_eq!(node.event("command_rejected")["code"], "sync_count");
    }
    for command in [
        json!({"command":"follow_finality", "id":3, "peer_id":fixture.peers[0].to_string(), "count":1, "interval_millis":100}),
        json!({"command":"follow_finality", "id":3, "peer_id":fixture.peers[0].to_string(), "count":1, "interval_millis":"100", "height":1}),
    ] {
        node.send(command);
        assert_eq!(node.event("command_rejected")["code"], "command_schema");
    }
    assert!(job(&mut node).is_null());
    node.send(json!({"command":"follow_finality", "id":5, "peer_id":fixture.peers[1].to_string(), "count":1, "interval_millis":"100"}));
    assert_eq!(
        node.event("command_rejected")["code"],
        "follow_peer_not_configured"
    );
    // A configured but disconnected peer can be followed; the first pass waits.
    assert_eq!(
        follow(&mut node, fixture.peers[0], u64::MAX, 16, "60000")["event"],
        "follow_started"
    );
    let status = job(&mut node);
    assert_eq!(status["id"], u64::MAX);
    assert_eq!(status["state"], "waiting");
    assert_eq!(status["interval_millis"], "60000");
    node.send(json!({"command":"sync_finality", "id":4, "peer_id":fixture.peers[0].to_string(), "count":1}));
    assert_eq!(node.event("command_rejected")["code"], "sync_busy");
    cancel(&mut node);
    assert!(job(&mut node).is_null());
    assert_eq!(layout.images(), before);
    node.shutdown();
}

#[test]
fn proof_following_retries_absence_and_transport_then_derives_next_pass_from_live_height() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::after_prefix(&fixture, &[&first], 0, 3, Role::Precommit);
    let layout = Layout::new();
    let (mut node, _, address) = waiting_node(&fixture, &layout, false);
    let guard = PARENT_JOURNALS.read().unwrap();
    let peer = Peer::start(&guard, &fixture, &address);
    established(&mut node);
    let before = layout.images();
    let start = Instant::now();
    follow(&mut node, fixture.peers[0], 100, 1, "250");
    peer.held("proof");
    assert!(start.elapsed() >= Duration::from_millis(250));
    let waiting = Instant::now();
    peer.controls.blocking_send(Control::Unavailable).unwrap();
    assert_eq!(node.event("follow_waiting")["reason"], "unavailable");
    peer.held("proof");
    assert!(waiting.elapsed() >= Duration::from_millis(250));
    peer.controls.blocking_send(Control::DropProof).unwrap();
    assert_eq!(node.event("follow_waiting")["reason"], "transport_failure");
    assert_eq!(layout.images(), before);
    peer.held("proof");
    peer.reply(first.envelope.unwrap(), first.payload);
    assert_eq!(node.event("sync_completed")["last_height"], "1");
    assert_eq!(node.event("follow_waiting")["reason"], "pass_completed");
    assert_eq!(node.event("finality")["state"]["driver"]["height"], "2");
    peer.held("proof");
    peer.reply(second.envelope.unwrap(), second.payload);
    assert_eq!(node.event("sync_completed")["last_height"], "2");
    assert_eq!(node.event("finality")["state"]["driver"]["height"], "3");
    cancel(&mut node);
    node.shutdown();
    drop(peer);
    drop(guard);
}

#[test]
fn proof_following_invalid_proof_stops_until_explicit_restart_and_cancel_discards_late_response() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    let layout = Layout::new();
    let (mut node, _, address) = waiting_node(&fixture, &layout, false);
    let guard = PARENT_JOURNALS.read().unwrap();
    let peer = Peer::start(&guard, &fixture, &address);
    established(&mut node);
    let before = layout.images();
    follow(&mut node, fixture.peers[0], 110, 1, "100");
    peer.held("proof");
    let mut invalid = proof.envelope.clone().unwrap();
    *invalid.last_mut().unwrap() ^= 1;
    peer.reply(invalid, proof.payload.clone());
    assert_eq!(
        node.event("follow_stopped")["reason"],
        "proof_not_committed"
    );
    node.event("finality_envelope_rejected");
    assert!(job(&mut node).is_null());
    assert!(
        peer.reports
            .recv_timeout(Duration::from_millis(250))
            .is_err()
    );
    assert_eq!(layout.images(), before);
    follow(&mut node, fixture.peers[0], 111, 1, "100");
    peer.held("proof");
    cancel(&mut node);
    // A fresh follower cannot steal the outstanding physical ticket.
    follow(&mut node, fixture.peers[0], 112, 1, "100");
    assert_eq!(node.event("follow_waiting")["reason"], "sync_request_start");
    peer.reply(proof.envelope.clone().unwrap(), proof.payload.clone());
    node.event("sync_response_discarded");
    assert_eq!(state(&mut node)["driver"]["height"], "1");
    assert_eq!(layout.images(), before);
    peer.held("proof");
    peer.reply(proof.envelope.unwrap(), proof.payload);
    node.event("sync_completed");
    assert_eq!(node.event("finality")["state"]["driver"]["height"], "2");
    cancel(&mut node);
    node.shutdown();
    drop(peer);
    drop(guard);
}

#[test]
fn proof_following_sigkill_retains_verified_prefix_but_never_restores_following_intent() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    let layout = Layout::new();
    let (mut node, config, address) = waiting_node(&fixture, &layout, false);
    let guard = PARENT_JOURNALS.read().unwrap();
    let peer = Peer::start(&guard, &fixture, &address);
    established(&mut node);
    follow(&mut node, fixture.peers[0], 120, 2, "100");
    peer.held("proof");
    peer.reply(proof.envelope.unwrap(), proof.payload);
    node.event("sync_progress");
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
    assert!(job(&mut node).is_null());
    assert_eq!(layout.images(), images);
    node.shutdown();
}

#[test]
fn proof_following_retries_after_publication_or_current_finality_owner_releases() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    for publication in [false, true] {
        let layout = Layout::new();
        proof.write(&layout, "proof");
        let (mut node, _, address) = waiting_node(&fixture, &layout, publication);
        let guard = PARENT_JOURNALS.read().unwrap();
        let peer = Peer::start(&guard, &fixture, &address);
        established(&mut node);
        follow(&mut node, fixture.peers[0], 130, 1, "250");
        peer.held("proof");
        let command = if publication {
            json!({"command":"submit_proposal", "id":131, "control_file":"proof.control", "payload_file":"proof.payload"})
        } else {
            json!({"command":"submit_vote", "id":131, "vote_file":"proof.vote"})
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
            node.event("follow_waiting")["reason"],
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
                json!({"command":"discard_inbox", "id":132, "inbox":"finality"}),
            );
        }
        peer.held("proof");
        peer.reply(proof.envelope.clone().unwrap(), proof.payload.clone());
        node.event("sync_completed");
        assert_eq!(node.event("finality")["state"]["driver"]["height"], "2");
        cancel(&mut node);
        node.shutdown();
        drop(peer);
        drop(guard);
    }
}

#[test]
fn proof_following_external_head_change_discards_old_ticket_and_restarts_from_new_head() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::after_prefix(&fixture, &[&first], 0, 3, Role::Precommit);
    let layout = Layout::new();
    first.write(&layout, "first");
    let (mut node, _, address) = waiting_node(&fixture, &layout, false);
    let guard = PARENT_JOURNALS.read().unwrap();
    let peer = Peer::start(&guard, &fixture, &address);
    established(&mut node);
    follow(&mut node, fixture.peers[0], 140, 1, "250");
    peer.held("proof");
    assert_eq!(
        result(&mut node, first.current_command(141, "first", false))["event"],
        "finality"
    );
    assert_eq!(node.event("follow_waiting")["reason"], "sync_head_changed");
    let images = layout.images();
    peer.reply(first.envelope.unwrap(), first.payload);
    node.event("sync_response_discarded");
    assert_eq!(layout.images(), images);
    peer.held("proof");
    peer.reply(second.envelope.unwrap(), second.payload);
    assert_eq!(node.event("sync_completed")["last_height"], "2");
    assert_eq!(node.event("finality")["state"]["driver"]["height"], "3");
    cancel(&mut node);
    node.shutdown();
    drop(peer);
    drop(guard);
}

#[test]
fn proof_following_frequent_disconnected_retries_preserve_real_deadline_input_and_signal_teardown()
{
    for signal in [rustix::process::Signal::TERM, rustix::process::Signal::INT] {
        let fixture = Fixture::new();
        let layout = Layout::new();
        let config = fixture
            .config(&layout, 1, "create", Some("/ip4/127.0.0.1/tcp/1"), false)
            .replace("60000", "1000");
        let mut node = Process::start(&layout, &config);
        node.ready();
        node.event("timer_armed");
        let finality = layout.finality_images();
        follow(&mut node, fixture.peers[0], 150, 1, "10");
        assert_eq!(node.event("follow_waiting")["reason"], "sync_request_start");
        assert_eq!(node.event("timer_due")["admitted"], true);
        assert_eq!(state(&mut node)["driver"]["height"], "1");
        assert!(job(&mut node)["following"].as_bool().unwrap());
        assert_eq!(layout.finality_images(), finality);
        node.signal(signal);
        assert_eq!(node.event("stopped")["locks_released"], true);
        assert!(node.exit().success());
        let mut node = Process::start(
            &layout,
            &config.replace("mode = \"create\"", "mode = \"open\""),
        );
        node.ready();
        assert!(job(&mut node).is_null());
        node.shutdown();
    }
}
