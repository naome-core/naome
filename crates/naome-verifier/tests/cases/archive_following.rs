//! Following reuses a real Noise peer, independent proofs and the actual child.
use super::*;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use tokio::time::Instant;

fn follow(id: u64, peer: PeerId, count: u64, millis: &str) -> Value {
    json!({"command":"follow_finality", "id":id, "peer_id":peer.to_string(), "count":count, "interval_millis":millis})
}

async fn quiet(peer: &mut Peer, duration: Duration) {
    let end = Instant::now() + duration;
    while Instant::now() < end {
        peer.pump().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn archive_following_schema_delay_import_and_waiting_cancellation() {
    let fixture = Fixture::new();
    let first = fixture.proof(&[], 0, 1);
    let mut peer = Peer::new(&fixture).await;
    let images = peer.layout.images();
    let mut id = 1000;
    for millis in [
        "",
        "0",
        "00",
        "01",
        "+1",
        "-1",
        " 1",
        "1.0",
        "18446744073709551616",
    ] {
        assert_eq!(
            peer.command(follow(id, peer.id, 1, millis)).await["code"],
            "follow_interval"
        );
        id += 1;
    }
    for count in [0, 17, u64::MAX] {
        assert_eq!(
            peer.command(follow(id, peer.id, count, "10")).await["code"],
            "sync_count"
        );
        id += 1;
    }
    for millis in [json!(1), json!(null), json!(-1)] {
        let mut command = follow(id, peer.id, 1, "1");
        command["interval_millis"] = millis;
        peer.process.send(command);
        // Schema failures deliberately carry a null ID.
        peer.until(|event| event["event"] == "command_rejected" && event["id"].is_null())
            .await;
        peer.process.observed.retain(|event| !event["id"].is_null());
        id += 1;
    }
    let unknown = identities()[1].0.public().to_peer_id();
    assert_eq!(
        peer.command(follow(id, unknown, 1, "10")).await["code"],
        "follow_peer_not_configured"
    );
    assert_eq!(peer.layout.images(), images);
    assert!(peer.history.is_empty());

    // Prepare files before starting the clock. Bound all waiting-state work
    // to two seconds inside a ten-second interval, and explicitly verify that
    // budget before testing the first request's newly derived H2 address.
    first.write(&peer.layout, "first");
    let installed = Instant::now();
    timeout(Duration::from_secs(2), async {
        let started = peer.command(follow(1100, peer.id, 16, "10000")).await;
        assert_eq!(started["outcome"]["job"]["state"], "waiting");
        assert_eq!(started["outcome"]["job"]["count"], 16);
        assert_eq!(
            peer.command(follow(1101, peer.id, 1, "1")).await["code"],
            "sync_busy"
        );
        assert_eq!(
            peer.command(
                json!({"command":"sync","id":1102,"peer_id":peer.id.to_string(),"count":1})
            )
            .await["code"],
            "sync_busy"
        );
        assert_eq!(
            peer.command(Proof::command(1103, "first")).await["outcome"]["kind"],
            "finalized"
        );
    })
    .await
    .expect("waiting-state setup must finish within its two-second budget");
    assert!(installed.elapsed() < Duration::from_secs(2));
    let inbound = peer.inbound().await;
    assert!(installed.elapsed() >= Duration::from_secs(10));
    assert_eq!(inbound.request().height().value(), 2);
    assert_eq!(
        peer.command(Proof::command(1104, "missing")).await["code"],
        "sync_busy"
    );
    peer.respond(inbound, None);
    peer.until(|event| event["event"] == "follow_waiting" && event["id"] == 1100)
        .await;
    let cancelled = peer
        .command(json!({"command":"cancel_sync","id":1105}))
        .await;
    assert_eq!(cancelled["outcome"]["job"]["state"], "waiting");
    assert_eq!(cancelled["outcome"]["sync_id"], 1100);
    let count = peer.history.len();
    quiet(&mut peer, Duration::from_millis(10100)).await;
    assert_eq!(peer.history.len(), count);
    assert!(peer.command(json!({"command":"status","id":1106})).await["outcome"]["sync"].is_null());
    peer.process.shutdown();
    super::super::archive::check_history(&fixture, &peer.layout, &[&first]);
}

#[tokio::test(flavor = "current_thread")]
async fn archive_following_absence_partial_pass_cancelled_ticket_and_new_generation() {
    let fixture = Fixture::new();
    let first = fixture.proof(&[], 0, 1);
    let second = fixture.proof(&[&first], 0, 2);
    let mut peer = Peer::new(&fixture).await;
    assert_eq!(
        peer.command(follow(1200, peer.id, 2, "100")).await["outcome"]["kind"],
        "follow_started"
    );
    let absent = peer.inbound().await;
    let ended = Instant::now();
    peer.respond(absent, None);
    peer.until(|event| event["event"] == "follow_waiting" && event["reason"] == "unavailable")
        .await;
    let first_request = peer.inbound().await;
    assert!(ended.elapsed() >= Duration::from_millis(100));
    assert_eq!(first_request.request().height().value(), 1);
    peer.respond(first_request, Some((&first.envelope, &first.payload)));
    let held = peer.inbound().await;
    assert_eq!(held.request().height().value(), 2);
    let prefix = peer.layout.images();
    let cancelled = peer
        .command(json!({"command":"cancel_sync","id":1201}))
        .await;
    assert_eq!(cancelled["outcome"]["completed"], "1");
    assert_eq!(cancelled["outcome"]["job"]["state"], "active");
    assert_eq!(
        peer.command(follow(1202, peer.id, 1, "100")).await["outcome"]["kind"],
        "follow_started"
    );
    // Dropping logical custody cannot steal the still-occupied physical slot.
    peer.until(|event| {
        event["event"] == "follow_waiting"
            && event["id"] == 1202
            && event["reason"] == "sync_request_start"
    })
    .await;
    assert_eq!(peer.history.len(), 3);
    peer.respond(held, Some((&second.envelope, &second.payload)));
    peer.until(|event| event["event"] == "sync_response_discarded")
        .await;
    assert_eq!(peer.layout.images(), prefix);
    let next = peer.inbound().await;
    assert_eq!(next.request().height().value(), 2);
    peer.respond(next, Some((&second.envelope, &second.payload)));
    peer.until(|event| event["event"] == "sync_completed" && event["id"] == 1202)
        .await;
    assert_eq!(
        peer.command(json!({"command":"cancel_sync","id":1203}))
            .await["outcome"]["sync_id"],
        1202
    );
    peer.process.shutdown();
    super::super::archive::check_history(&fixture, &peer.layout, &[&first, &second]);
}

#[tokio::test(flavor = "current_thread")]
async fn archive_following_invalid_complete_proofs_stop_without_retry_or_authority_write() {
    let fixture = Fixture::new();
    let first = fixture.proof(&[], 0, 1);
    let second = fixture.proof(&[&first], 0, 2);
    let mut signature = first.envelope.clone();
    *signature.last_mut().unwrap() ^= 1;
    let mut context = first.envelope.clone();
    context[0] ^= 1;
    let insufficient = envelope(
        &first,
        &fixture.keys[first.proposer],
        &[&fixture.keys[0], &fixture.keys[1]],
        2,
    );
    let mut peer = Peer::new(&fixture).await;
    let images = peer.layout.images();
    for (index, (bytes, payload, reason)) in [
        (&second.envelope, &second.payload, "response_address"),
        (&context, &first.payload, "envelope_context"),
        (&signature, &first.payload, "proof_verification"),
        (&first.envelope, &second.payload, "proof_verification"),
        (&insufficient, &first.payload, "proof_verification"),
    ]
    .into_iter()
    .enumerate()
    {
        let id = 1300 + index as u64;
        peer.command(follow(id, peer.id, 1, "20")).await;
        let inbound = peer.inbound().await;
        peer.respond(inbound, Some((bytes, payload)));
        let stopped = peer
            .until(|event| event["event"] == "follow_stopped" && event["id"] == id)
            .await;
        assert_eq!(stopped["reason"], reason);
        quiet(&mut peer, Duration::from_millis(70)).await;
        assert_eq!(peer.history.len(), index + 1);
        assert_eq!(peer.layout.images(), images);
        assert!(
            peer.command(json!({"command":"status","id":1400+index}))
                .await["outcome"]["sync"]
                .is_null()
        );
    }
    peer.process.shutdown();
}

#[tokio::test(flavor = "current_thread")]
async fn archive_following_process_kill_retains_only_acknowledged_prefix_and_no_intent() {
    let fixture = Fixture::new();
    let first = fixture.proof(&[], 0, 1);
    let mut peer = Peer::new(&fixture).await;
    peer.command(follow(1500, peer.id, 2, "20")).await;
    let inbound = peer.inbound().await;
    peer.respond(inbound, Some((&first.envelope, &first.payload)));
    let held = peer.inbound().await;
    assert_eq!(held.request().height().value(), 2);
    let images = peer.layout.images();
    peer.process.child.kill().unwrap();
    let killed = peer.process.exit();
    assert!(!killed.success());
    #[cfg(unix)]
    assert_eq!(killed.signal(), Some(9), "actual SIGKILL termination");
    drop(held);
    drop(peer.network.take());
    let [(_, seed), _, _] = identities();
    let mut reopened = Process::start(
        &peer.layout,
        &config(
            &fixture,
            &peer.layout,
            "open",
            seed,
            &[(peer.id, "/ip4/127.0.0.1/tcp/9".into())],
        ),
    );
    assert_eq!(reopened.ready()["head"]["height"], "1");
    assert!(reopened.request(json!({"command":"status","id":1501}))["outcome"]["sync"].is_null());
    assert_eq!(
        reopened.request(json!({"command":"cancel_sync","id":1502}))["code"],
        "sync_inactive"
    );
    reopened.shutdown();
    assert_eq!(peer.layout.images(), images);
    super::super::archive::check_history(&fixture, &peer.layout, &[&first]);
}

#[tokio::test(flavor = "current_thread")]
async fn archive_following_disconnected_pass_retries_same_configured_peer_after_reconnect() {
    let fixture = Fixture::new();
    let first = fixture.proof(&[], 0, 1);
    let second = fixture.proof(&[&first], 0, 2);
    let mut peer = Peer::new(&fixture).await;
    peer.command(follow(1600, peer.id, 2, "100")).await;
    let inbound = peer.inbound().await;
    peer.respond(inbound, Some((&first.envelope, &first.payload)));
    let held = peer.inbound().await;
    assert_eq!(held.request().height().value(), 2);
    let prefix = peer.layout.images();
    drop(peer.network.take());
    drop(held);
    peer.until(|event| {
        event["event"] == "follow_waiting" && event["reason"] == "transport_failure"
    })
    .await;
    peer.until(|event| {
        event["event"] == "follow_waiting" && event["reason"] == "sync_request_start"
    })
    .await;
    assert_eq!(peer.layout.images(), prefix);
    let [(client, _), _, (server, _)] = identities();
    let mut network = StaticArtifactNetwork::new(
        server,
        [StaticPeer::new(
            client.public().to_peer_id(),
            "/ip4/127.0.0.1/tcp/9".parse().unwrap(),
        )],
    )
    .unwrap();
    network.listen_on(peer.address.parse().unwrap()).unwrap();
    peer.network = Some(network);
    let next = peer.inbound().await;
    assert_eq!(next.request().height().value(), 2);
    peer.respond(next, Some((&second.envelope, &second.payload)));
    let absent = peer.inbound().await;
    assert_eq!(absent.request().height().value(), 3);
    peer.respond(absent, None);
    let stopped = peer
        .until(|event| {
            event["event"] == "sync_stopped"
                && event["completed"] == "1"
                && event["next_height"] == "3"
        })
        .await;
    assert_eq!(stopped["reason"], "unavailable");
    assert_eq!(
        peer.command(json!({"command":"cancel_sync","id":1601}))
            .await["outcome"]["sync_id"],
        1600
    );
    assert_eq!(
        peer.history
            .iter()
            .map(|request| request.height().value())
            .collect::<Vec<_>>(),
        vec![1, 2, 2, 3]
    );
    peer.process.shutdown();
    super::super::archive::check_history(&fixture, &peer.layout, &[&first, &second]);
}

#[test]
fn archive_following_offline_rejection_and_waiting_signal_teardown_preserve_history() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let [(local, seed), _, (remote, _)] = identities();
    let remote = remote.public().to_peer_id();
    let mut offline = Process::start(&layout, &fixture.config("create"));
    offline.ready();
    let images = layout.images();
    assert_eq!(
        offline.request(follow(1700, remote, 1, "1"))["code"],
        "network_disabled"
    );
    offline.shutdown();
    for signal in StopSignal::ALL {
        let mut waiting = Process::start(
            &layout,
            &config(
                &fixture,
                &layout,
                "open",
                seed,
                &[(remote, "/ip4/127.0.0.1/tcp/9".into())],
            ),
        );
        waiting.ready();
        let started = waiting.request(follow(1701, remote, 1, "18446744073709551615"));
        // Very large intervals are checked against the platform's monotonic
        // range. If representable, they remain cancellable without allocation.
        if started["event"] == "command_rejected" {
            assert_eq!(started["code"], "follow_deadline_overflow");
            assert_eq!(
                waiting.request(follow(1702, remote, 1, "100000"))["outcome"]["kind"],
                "follow_started"
            );
        } else {
            assert_eq!(started["outcome"]["kind"], "follow_started");
        }
        assert_ne!(local.public().to_peer_id(), remote);
        waiting.signal(signal);
        let stopped = waiting.event("stopped");
        assert_eq!(stopped["locks_released"], true);
        assert_eq!(stopped["reason"], signal.reason());
        assert!(waiting.exit().success());
        assert_eq!(layout.images(), images);
    }
    let mut reopened = Process::start(&layout, &config(&fixture, &layout, "open", seed, &[]));
    reopened.ready();
    assert!(reopened.request(json!({"command":"status","id":1703}))["outcome"]["sync"].is_null());
    reopened.shutdown();
}
