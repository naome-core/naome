use super::*;

#[test]
fn active_acquisition_refuses_bundles_before_inputs_until_explicit_cancel_and_discards_late_reply()
{
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 1, 0);
    let (blocks, payloads) = branch(&fixture, 2);
    let layout = Layout::new();
    layout.write("branch.bundle", &transfer.bytes);
    let plan = Plan::new(fixture.peers[1]);
    let peer = plan.peer;
    let target = hex(blocks[1].id().as_bytes());
    let config = source_config(
        &layout,
        plan.configure(fixture.config(&layout, 1, "create", None, false)),
    );
    let mut node = Process::start(&layout, &config);
    node.ready();
    let address = address(&mut node);
    initial_arm(&mut node);
    assert_eq!(
        result(&mut node, transfer.command(true))["event"],
        "bundle_staged"
    );
    let provider_guard = PARENT_JOURNALS.read().unwrap();
    let sdk = plan.start(
        &provider_guard,
        fixture.definition,
        &address,
        blocks,
        payloads,
        Some(target.clone()),
    );
    connected(&mut node, peer);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"acquire_ancestry", "id":1,"target":target,"peer_id":peer.to_string()})
        )["event"],
        "acquisition_started"
    );
    sdk.request("block", &target);
    let authority = layout.images();
    let sources = source_images(&layout);
    let active = result(&mut node, json!({"command":"sources_status","id":2}));
    let state = result(&mut node, json!({"command":"status","id":3}));
    for stage in [false, true] {
        let mut input = transfer.command(stage);
        input["target"] = json!("invalid");
        input["max_blocks"] = json!(0);
        input["bundle_file"] = json!("missing.bundle");
        reject(&mut node, input, "sources_busy");
    }
    assert!(!layout.root.join("missing.bundle").exists());
    assert_eq!(
        result(&mut node, json!({"command":"sources_status","id":4})),
        active
    );
    assert_eq!(result(&mut node, json!({"command":"status","id":5})), state);
    assert_eq!(source_images(&layout), sources);
    assert_eq!(layout.images(), authority);
    assert_eq!(
        result(&mut node, json!({"command":"cancel_acquisition","id":6}))["active"],
        true
    );
    node.event("acquisition_cancelled");
    let mut input = transfer.command(false);
    input["bundle_file"] = json!("idle.bundle");
    assert_eq!(result(&mut node, input)["event"], "bundle_exported");
    assert_eq!(
        result(&mut node, transfer.command(true))["event"],
        "bundle_staged"
    );
    sdk.release();
    node.event("network_event_discarded");
    let idle = result(&mut node, json!({"command":"sources_status","id":7}));
    assert!(idle["acquisition"].is_null());
    assert_eq!(idle["candidate_entries"], 1);
    assert_eq!(idle["payload_entries"], 1);
    assert_eq!(
        fs::read(layout.root.join("idle.bundle")).unwrap(),
        transfer.bytes
    );
    assert_eq!(source_images(&layout), sources);
    assert_eq!(layout.images(), authority);
    assert!(
        !node
            .observed
            .iter()
            .any(|v| v["event"] == "acquisition_complete" && v["id"] == 1)
    );
    node.shutdown();
    sdk.stop();
    drop(provider_guard);
}

#[test]
fn bundle_staging_and_export_preserve_real_in_flight_precommit_and_its_original_receipt() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::after_prefix(&fixture, &[&first], 0, 2, Role::Precommit);
    let higher = Proof::after_prefix(&fixture, &[&first, &second], 1, 3, Role::Prevote);
    let transfer = Transfer::new(&fixture, 3, 2);
    assert_eq!(transfer.blocks[2], higher.value.artifact_block());
    let layout = Layout::new();
    higher.write(&layout, "higher");
    layout.write("branch.bundle", &transfer.bytes);
    let plan = Plan::new(fixture.peers[1]);
    let peer = plan.peer;
    let config = source_config(
        &layout,
        plan.configure(fixture.config(&layout, 1, "create", None, false))
            .replace(
                "publication_targets = []",
                &format!("publication_targets = [{:?}]", peer.to_string()),
            ),
    );
    let mut node = Process::start(&layout, &config);
    node.ready();
    let address = address(&mut node);
    initial_arm(&mut node);
    select(&mut node, &layout, &[&first, &second]);
    let provider_guard = PARENT_JOURNALS.read().unwrap();
    let sdk = plan.start(
        &provider_guard,
        fixture.definition,
        &address,
        vec![],
        vec![],
        None,
    );
    connected(&mut node, peer);
    sdk.hold_consensus();
    result(
        &mut node,
        json!({"command":"submit_proposal","id":1,"control_file":"higher.control","payload_file":"higher.payload"}),
    );
    assert_eq!(node.event("admission")["all_admitted"], true);
    result(
        &mut node,
        json!({"command":"submit_vote","id":2,"vote_file":"higher.vote"}),
    );
    assert_eq!(node.event("admission")["all_admitted"], true);
    let transitioned = node.event("transitioned");
    assert_eq!(transitioned["height"], "3");
    assert_eq!(transitioned["phase"], "Precommit");
    assert_eq!(node.event("peer_attempted")["started"], true);
    let naome_network::ConsensusPushMessage::Vote { canonical_vote } = sdk.message() else {
        panic!("actual precommit");
    };
    assert_eq!(
        naome_consensus::UnverifiedConsensusVoteRouteV0::inspect(&canonical_vote)
            .unwrap()
            .role(),
        Role::Precommit
    );
    let state = result(&mut node, json!({"command":"status","id":3}));
    assert_eq!(state["publication"]["released_proposal"], true);
    assert_eq!(state["publication"]["deliveries"][0]["state"], "in_flight");
    let authority = layout.images();
    let staged = result(&mut node, transfer.command(true));
    assert_eq!(staged["event"], "bundle_staged");
    assert_eq!(staged["candidate_inserted_count"], 1);
    assert_eq!(staged["payload_inserted_count"], 1);
    assert_eq!(staged["state"], state);
    assert_eq!(layout.images(), authority);
    let sources = source_images(&layout);
    let mut input = transfer.command(false);
    input["bundle_file"] = json!("in-flight.bundle");
    let exported = result(&mut node, input);
    assert_eq!(exported["event"], "bundle_exported");
    assert_eq!(exported["state"], state);
    assert_eq!(source_images(&layout), sources);
    assert_eq!(layout.images(), authority);
    assert_eq!(
        fs::read(layout.root.join("in-flight.bundle")).unwrap(),
        transfer.bytes
    );
    assert!(!node.observed.iter().any(|v| v["event"] == "peer_completed"));
    sdk.release();
    let receipt = node.event("peer_completed");
    assert_eq!(receipt["peer"], peer.to_string());
    assert_eq!(receipt["received"], true);
    let complete = node.event("publication_complete");
    assert_eq!(complete["disposed"]["released_proposal"], true);
    assert_eq!(complete["disposed"]["deliveries"][0]["state"], "received");
    assert_eq!(source_images(&layout), sources);
    assert_eq!(layout.images(), authority);
    node.shutdown();
    sdk.stop();
    drop(provider_guard);
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    let ready = reopened.ready();
    for field in ["height", "round", "phase", "head"] {
        assert_eq!(ready["driver"][field], state["driver"][field]);
    }
    reopened.shutdown();
    assert_eq!(source_images(&layout), sources);
    assert_eq!(layout.images(), authority);
}
