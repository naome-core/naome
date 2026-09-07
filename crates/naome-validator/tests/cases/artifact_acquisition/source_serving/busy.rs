use super::*;

#[test]
fn serving_preserves_an_actual_outstanding_consensus_publication_until_its_receipt_arrives() {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 1, 0);
    let source = Layout::new();
    let destination = Layout::new();
    let plan = Plan::new(fixture.peers[0]);
    let peer = plan.peer;
    let client_config = source_config(
        &destination,
        fixture.config(
            &destination,
            1,
            "create",
            Some("/ip4/127.0.0.1/tcp/1"),
            false,
        ),
    );
    let mut client = Process::start(&destination, &client_config);
    client.ready();
    let listen = address(&mut client);
    let config = serving(source_config(
        &source,
        plan.configure(fixture.config(&source, 0, "create", Some(&listen), false)),
    ))
    .replace(
        "publication_targets = []",
        &format!("publication_targets = [{:?}]", peer.to_string()),
    );
    let mut server = Process::start(&source, &config);
    server.ready();
    let listen = address(&mut server);
    connected(&mut client, fixture.peers[0]);
    stage(&mut server, &source, &transfer);
    let guard = PARENT_JOURNALS.read().unwrap();
    let sdk = plan.start(
        &guard,
        fixture.definition,
        &listen,
        vec![],
        vec![],
        Some("consensus".into()),
    );
    connected(&mut server, peer);
    let target = hex(transfer.blocks[0].id().as_bytes());
    assert_eq!(
        result(
            &mut server,
            json!({"command":"author_candidate", "id":1, "target":target})
        )["event"],
        "proposal_authored"
    );
    let naome_network::ConsensusPushMessage::Proposal {
        canonical_proposal,
        canonical_artifact,
    } = sdk.message()
    else {
        panic!("held original proposal")
    };
    let before = result(&mut server, json!({"command":"status", "id":2}));
    assert_eq!(before["publication"]["deliveries"][0]["state"], "in_flight");
    let authority = source.images();
    let source_bytes = source_images(&source);
    acquire(
        &mut client,
        ancestry(3, fixture.peers[0], &transfer.blocks[0]),
    );
    response(&mut server, "block", false);
    assert_eq!(
        acquire(
            &mut client,
            fill(4, fixture.peers[0], &transfer.blocks[0], 1)
        )["validated_blocks"],
        1
    );
    response(&mut server, "payload", false);
    let after = result(&mut server, json!({"command":"status", "id":5}));
    assert_eq!(after["publication"], before["publication"]);
    assert_eq!(after["driver"], before["driver"]);
    assert_eq!(source.images(), authority);
    assert_eq!(source_images(&source), source_bytes);
    sdk.release();
    assert_eq!(server.event("finality")["state"]["driver"]["head"], target);
    for _ in 0..2 {
        assert!(matches!(
            sdk.message(),
            naome_network::ConsensusPushMessage::Vote { .. }
        ));
    }
    server.shutdown();
    client.shutdown();
    sdk.stop();
    drop(guard);
    let retained = fixture.retained_proposal(&source, 0);
    assert_eq!(
        retained.canonical_proposal_control_bytes(),
        canonical_proposal.as_slice()
    );
    assert_eq!(
        retained.canonical_artifact_bytes(),
        Some(canonical_artifact.as_slice())
    );
    assert_eq!(source_images(&source), source_bytes);
}

#[test]
fn both_exclusive_acquisition_phases_report_temporary_unavailability_then_cancel_restores_serving()
{
    for payload_phase in [false, true] {
        let fixture = Fixture::new();
        let transfer = Transfer::new(&fixture, 2, 0);
        let (blocks, payloads) = branch(&fixture, 3);
        let source = Layout::new();
        let destination = Layout::new();
        let plan = Plan::new(fixture.peers[1]);
        let peer = plan.peer;
        let config = serving(source_config(
            &source,
            plan.configure(fixture.config(
                &source,
                1,
                "create",
                Some("/ip4/127.0.0.1/tcp/1"),
                false,
            )),
        ));
        let mut server = Process::start(&source, &config);
        server.ready();
        let listen = address(&mut server);
        stage(&mut server, &source, &transfer);
        let client_config = source_config(
            &destination,
            fixture.config(&destination, 0, "create", Some(&listen), false),
        );
        let mut client = Process::start(&destination, &client_config);
        client.ready();
        connected(&mut client, fixture.peers[1]);
        acquire(&mut client, ancestry(1, fixture.peers[1], &blocks[0]));
        response(&mut server, "block", false);
        let before = source.images();
        let held = if payload_phase {
            hex(blocks[2].artifact_id().as_bytes())
        } else {
            hex(blocks[2].id().as_bytes())
        };
        let guard = PARENT_JOURNALS.read().unwrap();
        let sdk = plan.start(
            &guard,
            fixture.definition,
            &listen,
            blocks.clone(),
            payloads,
            Some(held.clone()),
        );
        connected(&mut server, peer);
        let command = if payload_phase {
            acquire(&mut server, ancestry(2, peer, &blocks[2]));
            sdk.request("block", &hex(blocks[2].id().as_bytes()));
            fill(3, peer, &blocks[2], 3)
        } else {
            ancestry(3, peer, &blocks[2])
        };
        assert_eq!(result(&mut server, command)["event"], "acquisition_started");
        sdk.request(if payload_phase { "payload" } else { "block" }, &held);
        let source_bytes = source_images(&source);
        assert_eq!(
            failed(&mut client, ancestry(4, fixture.peers[1], &blocks[1]))["code"],
            "source_block_unavailable"
        );
        response(&mut server, "block", true);
        assert_eq!(
            failed(&mut client, fill(5, fixture.peers[1], &blocks[0], 1))["code"],
            "source_payload_failure"
        );
        response(&mut server, "payload", true);
        assert_eq!(source_images(&source), source_bytes);
        assert_eq!(source.images(), before);
        assert_eq!(
            result(&mut server, json!({"command":"cancel_acquisition", "id":6}))["active"],
            true
        );
        server.event("acquisition_cancelled");
        sdk.release();
        server.event("network_event_discarded");
        acquire(&mut client, ancestry(7, fixture.peers[1], &blocks[1]));
        response(&mut server, "block", false);
        assert_eq!(
            acquire(&mut client, fill(8, fixture.peers[1], &blocks[1], 2))["validated_blocks"],
            2
        );
        response(&mut server, "payload", false);
        response(&mut server, "payload", false);
        assert_eq!(
            source_images(&source),
            source_bytes,
            "late response and serving cannot insert data"
        );
        server.signal(rustix::process::Signal::TERM);
        let stopped = server.event("stopped");
        assert_eq!(stopped["reason"], "sigterm");
        assert_eq!(stopped["locks_released"], true);
        assert!(server.exit().success());
        client.shutdown();
        sdk.stop();
        drop(guard);
        let mut reopened = Process::start(
            &source,
            &config.replace("mode = \"create\"", "mode = \"open\""),
        );
        reopened.ready();
        assert!(
            result(&mut reopened, json!({"command":"sources_status", "id":9}))["acquisition"]
                .is_null()
        );
        reopened.shutdown();
        assert_eq!(source.images(), before);
        assert_eq!(source_images(&source), source_bytes);
    }
}
