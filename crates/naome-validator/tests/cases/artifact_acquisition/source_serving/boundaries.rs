use super::*;

#[test]
fn retained_block_with_absent_payload_reports_unavailability_without_selected_journal_fallback() {
    use naome_storage::{
        ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreLimits, ArtifactPayloadStoreLimits,
        CanonicalArtifactPayloadStore,
    };
    let fixture = Fixture::new();
    let (blocks, _) = branch(&fixture, 1);
    let source = Layout::new();
    let destination = Layout::new();
    let config = serving(source_config(
        &source,
        fixture.config(&source, 1, "create", Some("/ip4/127.0.0.1/tcp/1"), false),
    ))
    .replace("[sources]\nmode = \"create\"", "[sources]\nmode = \"open\"");
    {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let mut candidates = ArtifactBlockCandidateStore::create(
            source.root.join("candidates"),
            fixture.definition,
            ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
        )
        .unwrap();
        let _ = candidates.insert(&blocks[0]).unwrap();
        let _payloads = CanonicalArtifactPayloadStore::create(
            source.root.join("payloads"),
            ArtifactPayloadStoreLimits::new(16, 1_048_576).unwrap(),
        )
        .unwrap();
    }
    let mut server = Process::start(&source, &config);
    server.ready();
    let listen = address(&mut server);
    let config = serving(source_config(
        &destination,
        fixture.config(&destination, 0, "create", Some(&listen), true),
    ));
    let mut client = Process::start(&destination, &config);
    client.ready();
    connected(&mut client, fixture.peers[1]);
    acquire(&mut client, ancestry(1, fixture.peers[1], &blocks[0]));
    response(&mut server, "block", false);
    assert_eq!(
        failed(&mut client, fill(2, fixture.peers[1], &blocks[0], 1))["code"],
        "source_payload_failure"
    );
    response(&mut server, "payload", false);
    let source_bytes = source_images(&source);
    let destination_bytes = source_images(&destination);
    let _ = fixture.proposal(&destination);
    assert_eq!(
        result(
            &mut client,
            json!({"command":"author_fresh", "id":3, "block_file":"block.bin", "payload_file":"payload.bin"})
        )["event"],
        "proposal_authored"
    );
    client.event("finality");
    server.event("finality");
    assert_eq!(
        source_images(&source),
        source_bytes,
        "received proposal must not populate source payloads"
    );
    assert_eq!(
        source_images(&destination),
        destination_bytes,
        "file authoring must not populate source payloads"
    );
    client.shutdown();
    // A fresh receiver has no local selected history to satisfy its request.
    let fresh = Layout::new();
    let config = source_config(
        &fresh,
        fixture.config(&fresh, 0, "create", Some(&listen), false),
    );
    let mut client = Process::start(&fresh, &config);
    client.ready();
    connected(&mut client, fixture.peers[1]);
    acquire(&mut client, ancestry(4, fixture.peers[1], &blocks[0]));
    response(&mut server, "block", false);
    assert_eq!(
        failed(&mut client, fill(5, fixture.peers[1], &blocks[0], 1))["code"],
        "source_payload_failure"
    );
    response(&mut server, "payload", false);
    assert_eq!(source_images(&source), source_bytes);
    client.shutdown();
    server.shutdown();
}

#[test]
fn serving_configuration_requires_explicit_boolean_and_sources_before_authority_creation() {
    let fixture = Fixture::new();
    for (value, code) in [
        ("true", "source_serving_requires_sources"),
        ("\"true\"", "config_schema"),
        ("1", "config_schema"),
    ] {
        let layout = Layout::new();
        let config = fixture.config(&layout, 0, "create", None, false).replace(
            "[network]",
            &format!("[network]\nserve_artifact_sources = {value}"),
        );
        let mut node = Process::start(&layout, &config);
        assert_eq!(node.event("error")["code"], code);
        assert!(!node.exit().success());
        assert!(layout.images().is_empty());
    }
}

#[test]
fn omitted_or_false_serving_drops_requests_and_file_authoring_and_received_proposals_do_not_populate_sources()
 {
    for explicit_false in [false, true] {
        let fixture = Fixture::new();
        let transfer = Transfer::new(&fixture, 1, 0);
        let source = Layout::new();
        let destination = Layout::new();
        let mut config = source_config(
            &source,
            fixture.config(&source, 1, "create", Some("/ip4/127.0.0.1/tcp/1"), false),
        );
        if explicit_false {
            config = config.replace("[network]", "[network]\nserve_artifact_sources = false");
        }
        let mut server = Process::start(&source, &config);
        server.ready();
        let listen = address(&mut server);
        stage(&mut server, &source, &transfer);
        let client_config = serving(source_config(
            &destination,
            fixture.config(&destination, 0, "create", Some(&listen), true),
        ));
        let mut client = Process::start(&destination, &client_config);
        client.ready();
        connected(&mut client, fixture.peers[1]);
        let failure = failed(
            &mut client,
            ancestry(1, fixture.peers[1], &transfer.blocks[0]),
        );
        assert_eq!(failure["code"], "source_ancestry_failure");
        server.event("network_event_discarded");
        let empty = source_images(&destination);
        let _ = fixture.proposal(&destination);
        assert_eq!(
            result(
                &mut client,
                json!({"command":"author_fresh", "id":2, "block_file":"block.bin", "payload_file":"payload.bin"})
            )["event"],
            "proposal_authored"
        );
        client.event("finality");
        server.event("finality");
        assert_eq!(
            source_images(&destination),
            empty,
            "file-backed authoring must not populate opted-in sources"
        );
        assert!(
            !server
                .observed
                .iter()
                .any(|v| v["event"] == "source_response_queued")
        );
        client.shutdown();
        server.shutdown();
    }
}

#[test]
fn missing_data_is_unavailable_and_corruption_is_a_distinct_failure_without_source_repair() {
    for candidate in [false, true] {
        let fixture = Fixture::new();
        let transfer = Transfer::new(&fixture, 1, 0);
        let source = Layout::new();
        let destination = Layout::new();
        let config = serving(source_config(
            &source,
            fixture.config(&source, 0, "create", Some("/ip4/127.0.0.1/tcp/1"), false),
        ));
        // Actor zero dials the configured actor one address, so start the
        // higher-peer client first to provide its concrete listener.
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
        let config = config.replace("/ip4/127.0.0.1/tcp/1\"", &format!("{listen}\""));
        let mut server = Process::start(&source, &config);
        server.ready();
        connected(&mut client, fixture.peers[0]);
        assert_eq!(
            failed(
                &mut client,
                ancestry(1, fixture.peers[0], &transfer.blocks[0])
            )["code"],
            "source_block_unavailable"
        );
        response(&mut server, "block", false);
        stage(&mut server, &source, &transfer);
        if !candidate {
            acquire(
                &mut client,
                ancestry(2, fixture.peers[0], &transfer.blocks[0]),
            );
            response(&mut server, "block", false);
        }
        let before = source.images();
        let path = source.root.join(if candidate {
            "candidates/artifact-block-candidate-store.log"
        } else {
            "payloads/artifact-payload-store.log"
        });
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(path, bytes).unwrap();
        let damaged = source_images(&source);
        let command = if candidate {
            ancestry(3, fixture.peers[0], &transfer.blocks[0])
        } else {
            fill(3, fixture.peers[0], &transfer.blocks[0], 1)
        };
        let failure = failed(&mut client, command);
        assert_eq!(
            failure["code"],
            if candidate {
                "source_ancestry_failure"
            } else {
                "source_payload_failure"
            }
        );
        let report = server.event("source_response_failed");
        assert_eq!(
            report["reason"],
            if candidate {
                "candidate_store"
            } else {
                "payload_store"
            }
        );
        let status = result(&mut server, json!({"command":"sources_status", "id":4}));
        assert!(
            status[if candidate {
                "candidate_entries"
            } else {
                "payload_entries"
            }]
            .is_null()
        );
        assert_eq!(
            status[if candidate {
                "payload_entries"
            } else {
                "candidate_entries"
            }],
            1
        );
        assert_eq!(source_images(&source), damaged);
        assert_eq!(source.images(), before);
        let _ = fixture.proposal(&source);
        assert_eq!(
            result(
                &mut server,
                json!({"command":"author_fresh", "id":5, "block_file":"block.bin", "payload_file":"payload.bin"})
            )["event"],
            "proposal_authored"
        );
        server.event("finality");
        server.shutdown();
        client.shutdown();
        let authority = source.images();
        let mut reopened = Process::start(
            &source,
            &config.replace("mode = \"create\"", "mode = \"open\""),
        );
        assert_eq!(
            reopened.event("error")["code"],
            if candidate {
                "source_candidates_open"
            } else {
                "source_payloads_open"
            }
        );
        assert!(!reopened.exit().success());
        assert_eq!(source.images(), authority);
        assert_eq!(source_images(&source), damaged);
    }
}
