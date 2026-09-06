use super::*;
use naome_storage::{ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreLimits};

fn rejected(node: &mut Process, command: Value, code: &str) {
    node.send(command);
    assert_eq!(node.event("command_rejected")["code"], code);
}

#[test]
fn strict_configuration_and_command_boundaries_precede_source_or_authority_effects() {
    let fixture = Fixture::new();
    for (from, to, code) in [
        (
            "candidate_entries = \"16\"",
            "candidate_entries = 16",
            "config_schema",
        ),
        (
            "candidate_entries = \"16\"",
            "candidate_entries = \"01\"",
            "config_decimal",
        ),
        (
            "candidate_entries = \"16\"",
            "candidate_entries = \"18446744073709551616\"",
            "config_decimal_range",
        ),
        (
            "candidate_entries = \"16\"",
            "candidate_entries = \"0\"",
            "source_candidate_limit",
        ),
        (
            "payload_entries = \"16\"",
            "payload_entries = \"0\"",
            "source_payload_limit",
        ),
        (
            "payload_bytes = \"1048576\"",
            "payload_bytes = \"0\"",
            "source_payload_limit",
        ),
        (
            "payload_directory = \"payloads\"",
            "payload_directory = \"absent\"",
            "source_directory",
        ),
        (
            "candidate_entries = \"16\"",
            "unexpected = true",
            "config_schema",
        ),
    ] {
        let layout = Layout::new();
        let config = source_config(&layout, fixture.config(&layout, 0, "create", None, false))
            .replace(from, to);
        let mut node = Process::start(&layout, &config);
        assert_eq!(node.event("error")["code"], code);
        assert!(!node.exit().success());
        assert!(layout.images().is_empty());
        assert!(source_images(&layout).is_empty());
    }
    let layout = Layout::new();
    let config = fixture.config(&layout, 0, "create", None, false);
    let mut disabled = Process::start(&layout, &config);
    disabled.ready();
    disabled.event("timer_armed");
    assert_eq!(
        result(&mut disabled, json!({"command":"sources_status", "id":1}))["enabled"],
        false
    );
    rejected(
        &mut disabled,
        json!({"command":"acquire_ancestry", "id":2, "target":"invalid", "peer_id":"invalid"}),
        "sources_disabled",
    );
    rejected(
        &mut disabled,
        json!({"command":"author_stored_retained", "id":3}),
        "sources_disabled",
    );
    disabled.shutdown();
    let authority = layout.images();
    // Source creation is independent of already existing authority open mode.
    let config = source_config(
        &layout,
        config.replace("mode = \"create\"", "mode = \"open\""),
    );
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let sources = source_images(&layout);
    for bytes in [
        "{\"command\":\"sources_status\",\"id\":1,\"id\":2}",
        "[\"sources_status\",1]",
        "{\"command\":\"author_stored_retained\",\"id\":1,\"target\":\"x\"}",
        "{\"command\":\"acquire_payloads\",\"id\":1,\"target\":\"x\",\"peer_id\":\"x\",\"max_blocks\":-1}",
        "{\"command\":\"acquire_payloads\",\"id\":1,\"target\":\"x\",\"peer_id\":\"x\",\"max_blocks\":\"1\"}",
    ] {
        node.write(format!("{bytes}\n").as_bytes());
        let error = node.event("command_rejected");
        assert_eq!(error["code"], "command_schema");
        assert!(error["id"].is_null());
    }
    let target = "00".repeat(32);
    let peer = fixture.peers[1].to_string();
    for (command, code) in [
        (
            json!({"command":"acquire_ancestry", "id":4, "target":target, "peer_id":"invalid"}),
            "source_peer_id",
        ),
        (
            json!({"command":"acquire_ancestry", "id":4, "target":"invalid", "peer_id":peer}),
            "source_block_id",
        ),
        (
            json!({"command":"acquire_anchored_ancestry", "id":4, "target":target, "anchor":"invalid", "peer_id":peer}),
            "source_block_id",
        ),
        (
            json!({"command":"acquire_ancestry_fallback", "id":4, "target":target, "peer_ids":[]}),
            "source_peer_count",
        ),
        (
            json!({"command":"acquire_payloads_fallback", "id":4, "target":target, "peer_ids":vec![peer.clone();9], "max_blocks":1}),
            "source_peer_count",
        ),
        (
            json!({"command":"acquire_payloads", "id":4, "target":target, "peer_id":peer, "max_blocks":0}),
            "source_block_limit",
        ),
    ] {
        rejected(&mut node, command, code);
    }
    assert_eq!(
        result(
            &mut node,
            json!({"command":"author_stored_retained", "id":5})
        )["event"],
        "proposal_rejected"
    );
    assert_eq!(layout.images(), authority);
    assert_eq!(source_images(&layout), sources);
    node.shutdown();
}

#[test]
fn source_open_failures_precede_authority_provision_and_release_earlier_handles() {
    let fixture = Fixture::new();
    for failure in ["missing", "existing", "payload"] {
        let layout = Layout::new();
        let config = source_config(&layout, fixture.config(&layout, 0, "create", None, false));
        if failure == "existing" {
            let _guard = PARENT_JOURNALS.read().unwrap();
            drop(
                ArtifactBlockCandidateStore::create(
                    layout.root.join("candidates"),
                    fixture.definition,
                    ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
                )
                .unwrap(),
            );
        }
        if failure == "payload" {
            fs::write(
                layout.root.join("payloads/artifact-payload-store.log"),
                b"complete existing file",
            )
            .unwrap();
        }
        let config = if failure == "missing" {
            config.replace("[sources]\nmode = \"create\"", "[sources]\nmode = \"open\"")
        } else {
            config
        };
        let mut node = Process::start(&layout, &config);
        assert_eq!(
            node.event("error")["code"],
            if failure == "payload" {
                "source_payloads_open"
            } else {
                "source_candidates_open"
            }
        );
        assert!(!node.exit().success());
        assert!(layout.images().is_empty());
        let _guard = PARENT_JOURNALS.read().unwrap();
        // Failure of the second store leaves a complete first-store prefix;
        // it neither rolls that prefix back nor retains its live ownership.
        let candidates = if failure == "missing" {
            ArtifactBlockCandidateStore::create(
                layout.root.join("candidates"),
                fixture.definition,
                ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
            )
        } else {
            ArtifactBlockCandidateStore::open(
                layout.root.join("candidates"),
                fixture.definition,
                ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
            )
        }
        .unwrap();
        assert_eq!(candidates.len().unwrap(), 0);
    }
}

#[test]
fn live_source_corruption_poisons_only_that_source_and_strict_reopen_refuses_without_repair() {
    for candidate in [false, true] {
        let fixture = Fixture::new();
        let layout = Layout::new();
        let provider = Plan::new(fixture.peers[0]);
        let peer = provider.peer;
        let config = source_config(
            &layout,
            provider.configure(fixture.config(&layout, 0, "create", None, false)),
        );
        let mut node = Process::start(&layout, &config);
        node.ready();
        let node_address = address(&mut node);
        let (blocks, payloads) = branch(&fixture, 1);
        let target = hex(blocks[0].id().as_bytes());
        let provider_guard = PARENT_JOURNALS.read().unwrap();
        let sdk = provider.start(
            &provider_guard,
            fixture.definition,
            &node_address,
            blocks.clone(),
            payloads,
            None,
        );
        connected(&mut node, peer);
        acquire(
            &mut node,
            json!({"command":"acquire_ancestry", "id":1, "target":target, "peer_id":peer.to_string()}),
        );
        sdk.request("block", &target);
        acquire(
            &mut node,
            json!({"command":"acquire_payloads", "id":2, "target":target, "peer_id":peer.to_string(), "max_blocks":1}),
        );
        sdk.request("payload", &hex(blocks[0].artifact_id().as_bytes()));
        let authority = layout.images();
        // Cached completion still performs process-level syntax checks.
        rejected(
            &mut node,
            json!({"command":"acquire_ancestry", "id":3, "target":target, "peer_id":"invalid"}),
            "source_peer_id",
        );
        rejected(
            &mut node,
            json!({"command":"acquire_payloads_fallback", "id":3, "target":target, "peer_ids":[], "max_blocks":1}),
            "source_peer_count",
        );
        let path = layout.root.join(if candidate {
            "candidates/artifact-block-candidate-store.log"
        } else {
            "payloads/artifact-payload-store.log"
        });
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        let damaged = source_images(&layout);
        let before_read = result(&mut node, json!({"command":"sources_status", "id":4}));
        assert_eq!(before_read["candidate_entries"], 1);
        assert_eq!(before_read["payload_entries"], 1);
        if candidate {
            rejected(
                &mut node,
                json!({"command":"acquire_ancestry", "id":5, "target":target, "peer_id":peer.to_string()}),
                "source_candidate_store",
            );
        } else {
            rejected(
                &mut node,
                json!({"command":"acquire_payloads", "id":5, "target":target, "peer_id":peer.to_string(), "max_blocks":1}),
                "source_payload_failure",
            );
        }
        assert_eq!(
            result(
                &mut node,
                json!({"command":"author_candidate", "id":6, "target":target})
            )["event"],
            "proposal_rejected"
        );
        let status = result(&mut node, json!({"command":"sources_status", "id":7}));
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
        assert_eq!(source_images(&layout), damaged);
        assert_eq!(layout.images(), authority);
        let block = fixture.proposal(&layout);
        assert_eq!(
            result(
                &mut node,
                json!({"command":"author_fresh", "id":8, "block_file":"block.bin", "payload_file":"payload.bin"})
            )["event"],
            "proposal_authored"
        );
        assert_eq!(
            node.event("finality")["state"]["driver"]["head"],
            hex(block.id().as_bytes())
        );
        node.shutdown();
        sdk.stop();
        drop(provider_guard);
        let authority = layout.images();
        let mut reopened = Process::start(
            &layout,
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
        assert_eq!(source_images(&layout), damaged);
        assert_eq!(layout.images(), authority);
    }
}

#[test]
fn structural_candidate_with_false_resulting_root_cannot_archive_payload_or_sign() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let provider = Plan::new(fixture.peers[0]);
    let peer = provider.peer;
    let config = source_config(
        &layout,
        provider.configure(fixture.config(&layout, 0, "create", None, false)),
    );
    let mut node = Process::start(&layout, &config);
    node.ready();
    let node_address = address(&mut node);
    let (blocks, payloads) = branch(&fixture, 1);
    let mut encoded = blocks[0].to_canonical_bytes();
    encoded[64] ^= 1;
    let invalid = ArtifactBlock::from_canonical_bytes(&encoded).unwrap();
    let target = hex(invalid.id().as_bytes());
    let provider_guard = PARENT_JOURNALS.read().unwrap();
    let sdk = provider.start(
        &provider_guard,
        fixture.definition,
        &node_address,
        vec![invalid],
        payloads,
        None,
    );
    connected(&mut node, peer);
    let authority = layout.images();
    acquire(
        &mut node,
        json!({"command":"acquire_ancestry", "id":1, "target":target, "peer_id":peer.to_string()}),
    );
    sdk.request("block", &target);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"acquire_payloads", "id":2, "target":target, "peer_id":peer.to_string(), "max_blocks":1})
        )["event"],
        "acquisition_started"
    );
    sdk.request("payload", &hex(invalid.artifact_id().as_bytes()));
    assert_eq!(
        node.event("acquisition_failed")["code"],
        "source_payload_failure"
    );
    let status = result(&mut node, json!({"command":"sources_status", "id":3}));
    assert_eq!(status["candidate_entries"], 1);
    assert_eq!(status["payload_entries"], 0);
    assert_eq!(layout.images(), authority);
    node.shutdown();
    sdk.stop();
    drop(provider_guard);
    let sources = source_images(&layout);
    let mut reopened = Process::start(
        &layout,
        &config.replace("mode = \"create\"", "mode = \"open\""),
    );
    reopened.ready();
    reopened.shutdown();
    assert_eq!(source_images(&layout), sources);
    assert_eq!(layout.images(), authority);
}
