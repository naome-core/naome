use super::source_bundles::Transfer;
use super::*;

fn status(node: &mut Process) -> Value {
    result(node, json!({"command":"proposal_status", "id":900}))["job"].clone()
}

fn start(node: &mut Process, target: &str, id: u64) {
    assert_eq!(
        result(
            node,
            json!({"command":"propose_height", "id":id, "target":target})
        )["event"],
        "proposal_job_started"
    );
}

fn stage(node: &mut Process, layout: &Layout, transfer: &Transfer) {
    layout.write("branch.bundle", &transfer.bytes);
    assert_eq!(
        result(node, transfer.command(true))["event"],
        "bundle_staged"
    );
}

fn waiting(node: &mut Process, state: &str) {
    node.until(|v| v["event"] == "proposal_job_waiting" && v["job"]["state"] == state);
}

#[test]
fn proposal_job_waits_for_source_then_authors_once_and_two_actual_nodes_finalize_and_reopen() {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 1, 0);
    let target = hex(transfer.blocks[0].id().as_bytes());
    let sender_layout = Layout::new();
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
    let receiver_address = address(&mut receiver);
    let config = source_config(
        &sender_layout,
        fixture.config(&sender_layout, 0, "create", Some(&receiver_address), true),
    );
    let mut node = Process::start(&sender_layout, &config);
    node.ready();
    connected(&mut node, fixture.peers[1]);
    connected(&mut receiver, fixture.peers[0]);
    let authority = sender_layout.images();
    start(&mut node, &target, 11);
    waiting(&mut node, "source_unavailable");
    assert_eq!(sender_layout.images(), authority);
    assert_eq!(status(&mut node)["target"], target);
    stage(&mut node, &sender_layout, &transfer);
    let attempt = node.event("proposal_job_attempt");
    assert_eq!(attempt["outcome"]["event"], "proposal_authored");
    for event in [node.event("finality"), receiver.event("finality")] {
        assert_eq!(event["state"]["driver"]["head"], target);
        assert_eq!(event["state"]["driver"]["height"], "2");
    }
    assert_eq!(
        node.event("proposal_job_stopped")["reason"],
        "height_changed"
    );
    assert!(status(&mut node).is_null());
    node.shutdown();
    receiver.shutdown();
    assert_eq!(
        node.observed
            .iter()
            .filter(|v| v["event"] == "proposal_job_attempt")
            .count(),
        1
    );
    assert_eq!(
        receiver
            .observed
            .iter()
            .filter(|v| v["event"] == "admission"
                && v["source"]["kind"] == "peer"
                && v["all_admitted"] == true)
            .count(),
        3
    );
    for (layout, config) in [
        (&sender_layout, &config),
        (&receiver_layout, &receiver_config),
    ] {
        let before = layout.images();
        let mut reopened = Process::start(
            layout,
            &config.replace("mode = \"create\"", "mode = \"open\""),
        );
        assert_eq!(reopened.ready()["driver"]["head"], target);
        assert!(status(&mut reopened).is_null());
        reopened.shutdown();
        assert_eq!(layout.images(), before);
    }
}

#[test]
fn proposal_job_preserves_already_completed_manual_proposal_in_the_current_round() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let transfer = Transfer::new(&fixture, 1, 0);
    let target = hex(transfer.blocks[0].id().as_bytes());
    let config = source_config(&layout, fixture.config(&layout, 0, "create", None, false)).replace(
        "[limits.finality]\nentries = \"8\"",
        "[limits.finality]\nentries = \"1\"",
    );
    let mut node = Process::start(&layout, &config);
    node.ready();
    stage(&mut node, &layout, &transfer);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"author_candidate", "id":70, "target":target})
        )["event"],
        "proposal_authored"
    );
    for _ in 0..3 {
        node.event("publication_complete");
    }
    let before = layout.images();
    // A different caller target cannot replace the durable proposal, even
    // after publication has completed and the process is otherwise idle.
    start(&mut node, &"01".repeat(32), 71);
    waiting(&mut node, "round_complete");
    assert_eq!(status(&mut node)["round"], "0");
    result(&mut node, json!({"command":"cancel_proposal", "id":72}));
    node.event("proposal_job_stopped");
    node.shutdown();
    assert_eq!(layout.images(), before);
    assert!(
        !node
            .observed
            .iter()
            .any(|v| v["event"] == "proposal_job_attempt")
    );
}

#[test]
fn proposal_job_validates_schema_excludes_manual_authoring_and_cancel_does_not_sign() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = source_config(&layout, fixture.config(&layout, 0, "create", None, false));
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let before = layout.images();
    for command in [
        json!({"command":"propose_height", "id":1}),
        json!({"command":"propose_height", "id":1, "target":"00", "height":1}),
        json!({"command":"proposal_status", "id":1, "extra":true}),
        json!({"command":"cancel_proposal", "id":1, "extra":true}),
    ] {
        node.send(command);
        assert_eq!(node.event("command_rejected")["code"], "command_schema");
    }
    node.send(json!({"command":"propose_height", "id":2, "target":"00"}));
    node.event("command_rejected");
    assert!(status(&mut node).is_null());
    let target = "01".repeat(32);
    start(&mut node, &target, u64::MAX);
    waiting(&mut node, "source_unavailable");
    assert_eq!(status(&mut node)["id"], u64::MAX);
    for command in [
        json!({"command":"propose_height", "id":3, "target":target}),
        json!({"command":"author_candidate", "id":4, "target":target}),
        json!({"command":"author_stored_retained", "id":5}),
        json!({"command":"author_fresh", "id":6, "block_file":"missing", "payload_file":"missing"}),
        json!({"command":"author_retained", "id":7, "payload_file":"missing"}),
    ] {
        node.send(command);
        assert_eq!(node.event("command_rejected")["code"], "proposal_busy");
    }
    assert_eq!(
        result(&mut node, json!({"command":"cancel_proposal", "id":8}))["event"],
        "proposal_job_cancelled"
    );
    assert_eq!(node.event("proposal_job_stopped")["reason"], "cancelled");
    assert!(status(&mut node).is_null());
    assert!(result(&mut node, json!({"command":"cancel_proposal", "id":9}))["job"].is_null());
    node.shutdown();
    assert_eq!(layout.images(), before);
    assert!(
        !node
            .observed
            .iter()
            .any(|v| v["event"] == "publication_prepared" || v["event"] == "proposal_job_attempt")
    );
}

#[test]
fn proposal_job_unscheduled_round_is_not_signed_and_sigkill_does_not_resume_intent() {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 1, 0);
    let target = hex(transfer.blocks[0].id().as_bytes());
    let layout = Layout::new();
    let config = source_config(&layout, fixture.config(&layout, 1, "create", None, false));
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    stage(&mut node, &layout, &transfer);
    let before = layout.images();
    start(&mut node, &target, 20);
    waiting(&mut node, "not_scheduled");
    assert_eq!(status(&mut node)["round_complete"], true);
    node.signal(rustix::process::Signal::KILL);
    assert!(!node.exit().success());
    assert_eq!(layout.images(), before);
    let mut reopened = Process::start(
        &layout,
        &config.replace("mode = \"create\"", "mode = \"open\""),
    );
    reopened.ready();
    assert!(status(&mut reopened).is_null());
    reopened.shutdown();
    assert_eq!(layout.images(), before);
}

#[test]
fn proposal_job_source_corruption_stops_intent_without_poisoning_signer_or_repairing_source() {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 1, 0);
    let target = hex(transfer.blocks[0].id().as_bytes());
    let layout = Layout::new();
    let config = source_config(&layout, fixture.config(&layout, 0, "create", None, false));
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    stage(&mut node, &layout, &transfer);
    let before = layout.images();
    let path = fs::read_dir(layout.root.join("candidates"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "log"))
        .unwrap();
    let mut damaged = fs::read(&path).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&path, &damaged).unwrap();
    start(&mut node, &target, 30);
    assert_eq!(
        node.event("proposal_job_attempt")["outcome"]["event"],
        "proposal_rejected"
    );
    assert_eq!(
        node.event("proposal_job_stopped")["reason"],
        "authoring_rejected"
    );
    assert!(status(&mut node).is_null());
    assert_eq!(layout.images(), before);
    assert_eq!(fs::read(&path).unwrap(), damaged);
    let _ = fixture.proposal(&layout);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"author_fresh", "id":31, "block_file":"block.bin", "payload_file":"payload.bin"})
        )["event"],
        "proposal_authored"
    );
    node.event("finality");
    node.shutdown();
    assert_eq!(fs::read(&path).unwrap(), damaged);
}

#[test]
fn proposal_job_actual_signed_publications_cannot_cross_chain_genesis_or_version() {
    for dimension in ["chain", "genesis", "version"] {
        let fixture = Fixture::new();
        let transfer = Transfer::new(&fixture, 1, 0);
        let target = hex(transfer.blocks[0].id().as_bytes());
        let sender_layout = Layout::new();
        let receiver_layout = Layout::new();
        let mut receiver_config = fixture.config(
            &receiver_layout,
            1,
            "create",
            Some("/ip4/127.0.0.1/tcp/1"),
            false,
        );
        receiver_config = match dimension {
            "chain" => receiver_config.replace(
                &hex(fixture.definition.deployment_discriminator()),
                &"a1".repeat(32),
            ),
            "genesis" => receiver_config.replace(
                &hex(fixture.context.genesis_id().as_bytes()),
                &"b2".repeat(32),
            ),
            "version" => receiver_config.replace("protocol_version = 7", "protocol_version = 8"),
            _ => unreachable!(),
        };
        let mut receiver = Process::start(&receiver_layout, &receiver_config);
        let initial = receiver.ready();
        let receiver_address = address(&mut receiver);
        let config = source_config(
            &sender_layout,
            fixture.config(&sender_layout, 0, "create", Some(&receiver_address), true),
        );
        let mut sender = Process::start(&sender_layout, &config);
        sender.ready();
        connected(&mut sender, fixture.peers[1]);
        connected(&mut receiver, fixture.peers[0]);
        let before = receiver_layout.images();
        stage(&mut sender, &sender_layout, &transfer);
        start(&mut sender, &target, 40);
        assert_eq!(
            sender.event("proposal_job_attempt")["outcome"]["event"],
            "proposal_authored"
        );
        assert_eq!(sender.event("finality")["state"]["driver"]["head"], target);
        for _ in 0..3 {
            let admission =
                receiver.until(|v| v["event"] == "admission" && v["source"]["kind"] == "peer");
            assert_eq!(admission["all_admitted"], false, "{dimension}: {admission}");
        }
        let state = result(&mut receiver, json!({"command":"status", "id":41}));
        assert_eq!(state["driver"]["height"], initial["driver"]["height"]);
        assert_eq!(state["driver"]["head"], initial["driver"]["head"]);
        sender.shutdown();
        receiver.shutdown();
        assert_eq!(receiver_layout.images(), before, "{dimension}");
        assert!(!receiver.observed.iter().any(|v| matches!(
            v["event"].as_str(),
            Some("publication_prepared" | "finality")
        )));
        // The adversarial inputs were ordinary durably completed signatures,
        // not forged bytes. Verify the exact sender proposal independently.
        let proposal = fixture.retained_proposal(&sender_layout, 0);
        let branch = naome_consensus::FixedConsensusBranchV0::try_from_virtual_genesis(
            fixture.context,
            &fixture.entries,
            ArtifactChainState::new(fixture.definition).branch_snapshot(),
        )
        .unwrap();
        let round = branch.begin_round_zero().unwrap();
        let verified = round
            .decode_and_verify_proposal_control(
                proposal.canonical_proposal_control_bytes(),
                proposal.canonical_artifact_bytes().unwrap().to_vec(),
            )
            .unwrap();
        assert_eq!(verified.value().artifact_block(), transfer.blocks[0]);
        let mut reopened = Process::start(
            &receiver_layout,
            &receiver_config.replace("mode = \"create\"", "mode = \"open\""),
        );
        assert_eq!(
            reopened.ready()["driver"]["head"],
            initial["driver"]["head"]
        );
        reopened.shutdown();
        assert_eq!(receiver_layout.images(), before);
    }
}

#[test]
fn proposal_job_waits_across_missed_proposer_round_then_weighted_peers_finalize() {
    let mut fixture = Fixture::new();
    // Noise's ordered initiator must be the process started second.
    fixture.noise.swap(0, 1);
    fixture.peers.swap(0, 1);
    let transfer = Transfer::new(&fixture, 1, 0);
    let target = hex(transfer.blocks[0].id().as_bytes());
    let minority_layout = Layout::new();
    let majority_layout = Layout::new();
    let timeouts = |config: String| {
        config
            .replace(
                "[timeouts.proposal]\nbase_millis = \"60000\"",
                "[timeouts.proposal]\nbase_millis = \"10000\"",
            )
            .replace("base_millis = \"60000\"", "base_millis = \"500\"")
    };
    // Start the round-zero proposer first so its missed-proposal deadline
    // precedes the next proposer's. The next round's Proposal interval then
    // covers process startup skew before the minority authors.
    let majority_config = timeouts(fixture.config(
        &majority_layout,
        0,
        "create",
        Some("/ip4/127.0.0.1/tcp/1"),
        true,
    ));
    let mut majority = Process::start(&majority_layout, &majority_config);
    majority.ready();
    let majority_address = address(&mut majority);
    let minority_config = source_config(
        &minority_layout,
        timeouts(fixture.config(&minority_layout, 1, "create", Some(&majority_address), true)),
    );
    let mut minority = Process::start(&minority_layout, &minority_config);
    minority.ready();
    connected(&mut minority, fixture.peers[0]);
    connected(&mut majority, fixture.peers[1]);
    stage(&mut minority, &minority_layout, &transfer);
    start(&mut minority, &target, 50);
    waiting(&mut minority, "not_scheduled");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    let attempt = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "bounded scheduled-proposer wait"
        );
        if let Some(event) = minority.observe(std::time::Duration::from_millis(500)) {
            assert!(
                !matches!(event["event"].as_str(), Some("fatal" | "stopped" | "error")),
                "{event}"
            );
            if event["event"] == "proposal_job_attempt" {
                break event;
            }
        }
    };
    assert_eq!(attempt["outcome"]["event"], "proposal_authored");
    let authored_round: u64 = attempt["job"]["round"].as_str().unwrap().parse().unwrap();
    assert!(authored_round > 0);
    for finality in [minority.event("finality"), majority.event("finality")] {
        assert_eq!(finality["state"]["driver"]["head"], target);
    }
    assert_eq!(
        minority.event("proposal_job_stopped")["reason"],
        "height_changed"
    );
    minority.shutdown();
    majority.shutdown();
    assert_eq!(
        minority
            .observed
            .iter()
            .filter(|v| v["event"] == "proposal_job_attempt")
            .count(),
        1
    );
    // The missed proposer fires its real deadline. Its quorum-weight nil
    // evidence may advance the minority before the minority's own deadline.
    assert!(majority.observed.iter().any(|v| v["event"] == "timer_due"));
    let branch = naome_consensus::FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &fixture.entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let mut round = branch.begin_round_zero().unwrap();
    for _ in 0..authored_round {
        assert_ne!(round.proposer(), fixture.entries[1].consensus_key());
        round = round.advance_round().unwrap();
    }
    assert_eq!(round.proposer(), fixture.entries[1].consensus_key());
    let mut signer_fixture = Fixture::new();
    signer_fixture.keys.swap(0, 1);
    let proposal = signer_fixture.retained_proposal(&minority_layout, authored_round);
    let verified = round
        .decode_and_verify_proposal_control(
            proposal.canonical_proposal_control_bytes(),
            proposal.canonical_artifact_bytes().unwrap().to_vec(),
        )
        .unwrap();
    assert_eq!(verified.value().artifact_block(), transfer.blocks[0]);
    for (layout, config) in [
        (&minority_layout, &minority_config),
        (&majority_layout, &majority_config),
    ] {
        let before = layout.images();
        // Keep restart observation before another local test deadline.
        let config = config
            .replace("mode = \"create\"", "mode = \"open\"")
            .replace("base_millis = \"10000\"", "base_millis = \"60000\"")
            .replace("base_millis = \"500\"", "base_millis = \"60000\"");
        let mut reopened = Process::start(layout, &config);
        assert_eq!(reopened.ready()["driver"]["head"], target);
        assert!(status(&mut reopened).is_null());
        reopened.shutdown();
        assert_eq!(
            without_delivery_progress(&layout.images()),
            without_delivery_progress(&before)
        );
    }
}

#[test]
fn proposal_job_cancellation_and_deadline_progress_survive_exclusive_source_acquisition() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let provider = Plan::new(fixture.peers[0]);
    let peer = provider.peer;
    let config = source_config(
        &layout,
        provider.configure(fixture.config(&layout, 0, "create", None, false)),
    )
    .replace(
        "[timeouts.proposal]\nbase_millis = \"60000\"",
        "[timeouts.proposal]\nbase_millis = \"1500\"",
    );
    let mut node = Process::start(&layout, &config);
    node.ready();
    let node_address = address(&mut node);
    let (blocks, payloads) = branch(&fixture, 1);
    let target = hex(blocks[0].id().as_bytes());
    let guard = PARENT_JOURNALS.read().unwrap();
    let sdk = provider.start(
        &guard,
        fixture.definition,
        &node_address,
        blocks,
        payloads,
        Some(target.clone()),
    );
    connected(&mut node, peer);
    start(&mut node, &target, 60);
    waiting(&mut node, "source_unavailable");
    assert_eq!(
        result(
            &mut node,
            json!({"command":"acquire_ancestry", "id":61, "target":target, "peer_id":peer.to_string()})
        )["event"],
        "acquisition_started"
    );
    sdk.request("block", &target);
    assert_eq!(status(&mut node)["id"], 60);
    result(&mut node, json!({"command":"cancel_proposal", "id":62}));
    assert_eq!(node.event("proposal_job_stopped")["reason"], "cancelled");
    assert!(status(&mut node).is_null());
    node.send(json!({"command":"propose_height", "id":63, "target":target}));
    assert_eq!(node.event("command_rejected")["code"], "sources_busy");
    // The source worker still owns its exact request, but it cannot delay the
    // ordinary real Proposal deadline and its anchored nil prevote.
    let due = |v: &Value| v["event"] == "timer_due";
    if !node.observed.iter().any(due) {
        node.until(due);
    }
    let publication = |v: &Value| v["event"] == "publication_complete";
    if !node.observed.iter().any(publication) {
        node.until(publication);
    }
    assert!(
        !result(&mut node, json!({"command":"sources_status", "id":64}))["acquisition"].is_null()
    );
    sdk.release();
    assert_eq!(node.event("acquisition_complete")["id"], 61);
    assert!(status(&mut node).is_null());
    node.shutdown();
    sdk.stop();
    drop(guard);
    assert!(
        !node
            .observed
            .iter()
            .any(|v| v["event"] == "proposal_job_attempt" || v["event"] == "finality")
    );
}

#[test]
fn proposal_job_missing_retained_payload_never_falls_back_to_available_fresh_candidate() {
    let fixture = history::dominant_fixture();
    let transfer = Transfer::new(&fixture, 1, 0);
    let fresh_target = hex(transfer.blocks[0].id().as_bytes());
    let layout = Layout::new();
    let config = source_config(&layout, fixture.config(&layout, 0, "create", None, false))
        .replace(
            "[limits.finality]\nentries = \"8\"",
            "[limits.finality]\nentries = \"1\"",
        )
        .replace(
            "[timeouts.precommit]\nbase_millis = \"60000\"",
            "[timeouts.precommit]\nbase_millis = \"3000\"",
        );
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    stage(&mut node, &layout, &transfer);
    let retained_bytes = payload(2);
    let artifact = ArtifactDag::new()
        .apply_canonical_artifact_bytes(retained_bytes.clone())
        .unwrap()
        .artifact_id();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact)
        .unwrap();
    assert_ne!(block.id(), transfer.blocks[0].id());
    layout.write("retained.block", block.to_canonical_bytes());
    layout.write("retained.payload", retained_bytes);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"author_fresh", "id":70, "block_file":"retained.block", "payload_file":"retained.payload"})
        )["event"],
        "proposal_authored"
    );
    for _ in 0..3 {
        node.event("publication_complete");
    }
    assert_eq!(
        result(
            &mut node,
            json!({"command":"discard_inbox", "id":71, "inbox":"finality"})
        )["discarded_items"],
        1
    );
    let next =
        |v: &Value| v["event"] == "transitioned" && v["round"] == "1" && v["phase"] == "Proposal";
    if !node.observed.iter().any(next) {
        node.until(next);
    }
    // File-backed authoring did not populate the source store. Only the
    // different fresh candidate's payload exists there.
    assert_eq!(
        result(&mut node, json!({"command":"sources_status", "id":72}))["payload_entries"],
        1
    );
    let authority = layout.images();
    let sources = source_images(&layout);
    start(&mut node, &fresh_target, 73);
    waiting(&mut node, "source_unavailable");
    assert_eq!(status(&mut node)["round"], "1");
    assert_eq!(layout.images(), authority);
    assert_eq!(source_images(&layout), sources);
    result(&mut node, json!({"command":"cancel_proposal", "id":74}));
    node.event("proposal_job_stopped");
    node.shutdown();
    assert_eq!(layout.images(), authority);
    assert!(
        !node
            .observed
            .iter()
            .any(|v| v["event"] == "proposal_job_attempt" || v["event"] == "finality")
    );
    let proposal = fixture.retained_proposal(&layout, 0);
    let branch = naome_consensus::FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &fixture.entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap();
    let verified = round
        .decode_and_verify_proposal_control(
            proposal.canonical_proposal_control_bytes(),
            proposal.canonical_artifact_bytes().unwrap().to_vec(),
        )
        .unwrap();
    assert_eq!(verified.value().artifact_block(), block);
}
