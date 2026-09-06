use super::*;
use naome_network::ConsensusPushMessage;

#[test]
fn shared_peer_slot_refuses_each_direction_without_automatic_retry() {
    for acquisition_first in [false, true] {
        let fixture = Fixture::new();
        let layout = Layout::new();
        let provider = Plan::new(fixture.peers[0]);
        let peer = provider.peer;
        let config = source_config(
            &layout,
            provider.configure(fixture.config(&layout, 0, "create", None, false)),
        )
        .replace(
            "publication_targets = []",
            &format!("publication_targets = [{:?}]", peer.to_string()),
        );
        let mut node = Process::start(&layout, &config);
        node.ready();
        let node_address = address(&mut node);
        let (blocks, payloads) = branch(&fixture, 2);
        let target = hex(blocks[1].id().as_bytes());
        let hold = if acquisition_first {
            target.clone()
        } else {
            "consensus".into()
        };
        let provider_guard = PARENT_JOURNALS.read().unwrap();
        let sdk = provider.start(
            &provider_guard,
            fixture.definition,
            &node_address,
            blocks.clone(),
            payloads,
            Some(hold),
        );
        connected(&mut node, peer);
        let sources = source_images(&layout);
        let mut command = json!({"command":"acquire_ancestry", "id":1, "target":target, "peer_id":peer.to_string()});
        if acquisition_first {
            assert_eq!(
                result(&mut node, command.clone())["event"],
                "acquisition_started"
            );
            sdk.request("block", &target);
        }
        let selected = fixture.proposal(&layout);
        assert_eq!(
            result(
                &mut node,
                json!({"command":"author_fresh", "id":2, "block_file":"block.bin", "payload_file":"payload.bin"})
            )["event"],
            "proposal_authored"
        );
        if acquisition_first {
            let finality = node.event("finality");
            assert_eq!(
                finality["state"]["driver"]["head"],
                hex(selected.id().as_bytes())
            );
            assert_eq!(
                node.observed
                    .iter()
                    .filter(|v| v["event"] == "peer_attempted" && v["started"] == false)
                    .count(),
                3
            );
            assert_eq!(
                node.observed
                    .iter()
                    .filter(|v| v["event"] == "publication_complete"
                        && v["disposed"]["deliveries"][0]["state"] == "refused")
                    .count(),
                3
            );
            let authority = layout.images();
            sdk.release();
            assert_eq!(
                node.event("acquisition_failed")["code"],
                "source_selected_head_changed"
            );
            let status = result(&mut node, json!({"command":"status", "id":3}));
            assert!(status["publication"].is_null());
            assert_eq!(
                node.observed
                    .iter()
                    .filter(|v| v["event"] == "peer_attempted")
                    .count(),
                3
            );
            assert_eq!(layout.images(), authority);
        } else {
            assert!(matches!(
                sdk.message(),
                ConsensusPushMessage::Proposal { .. }
            ));
            let status = result(&mut node, json!({"command":"status", "id":3}));
            assert_eq!(status["publication"]["deliveries"][0]["state"], "in_flight");
            let authority = layout.images();
            node.send(command.clone());
            assert_eq!(
                node.event("command_rejected")["code"],
                "source_request_start"
            );
            assert_eq!(layout.images(), authority);
            assert!(
                result(&mut node, json!({"command":"sources_status", "id":4}))["acquisition"]
                    .is_null()
            );
            sdk.release();
            assert_eq!(
                node.event("finality")["state"]["driver"]["head"],
                hex(selected.id().as_bytes())
            );
            for _ in 0..2 {
                assert!(matches!(sdk.message(), ConsensusPushMessage::Vote { .. }));
            }
            assert_eq!(
                source_images(&layout),
                sources,
                "slot release must not retry acquisition"
            );
            let authority = layout.images();
            // Only this new explicit command retries the previously refused
            // request, now against the advanced selected parent.
            command["id"] = json!(5);
            acquire(&mut node, command);
            sdk.request("block", &target);
            assert_eq!(
                result(&mut node, json!({"command":"sources_status", "id":6}))["candidate_entries"],
                1
            );
            assert_eq!(layout.images(), authority);
        }
        if acquisition_first {
            assert_eq!(source_images(&layout), sources);
        }
        node.shutdown();
        sdk.stop();
        drop(provider_guard);
    }
}

#[test]
fn real_phase_deadline_and_status_continue_while_source_response_is_held() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let provider = Plan::new(fixture.peers[0]);
    let peer = provider.peer;
    let config = source_config(
        &layout,
        provider.configure(fixture.config(&layout, 0, "create", None, false)),
    )
    .replace("60000", "5000")
    .replace(
        "publication_targets = []",
        &format!("publication_targets = [{:?}]", peer.to_string()),
    );
    let mut node = Process::start(&layout, &config);
    let initial = node.ready();
    let node_address = address(&mut node);
    let (blocks, payloads) = branch(&fixture, 1);
    let target = hex(blocks[0].id().as_bytes());
    let provider_guard = PARENT_JOURNALS.read().unwrap();
    let sdk = provider.start(
        &provider_guard,
        fixture.definition,
        &node_address,
        blocks,
        payloads,
        Some(target.clone()),
    );
    connected(&mut node, peer);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"acquire_ancestry", "id":1, "target":target, "peer_id":peer.to_string()})
        )["event"],
        "acquisition_started"
    );
    sdk.request("block", &target);
    let authority = layout.images();
    let sources = source_images(&layout);
    assert_eq!(node.event("timer_due")["admitted"], true);
    assert_eq!(node.event("peer_attempted")["started"], false);
    assert_eq!(
        node.event("publication_complete")["disposed"]["deliveries"][0]["state"],
        "refused"
    );
    let status = result(&mut node, json!({"command":"status", "id":2}));
    assert_eq!(status["driver"]["head"], initial["driver"]["head"]);
    assert_ne!(
        layout.images(),
        authority,
        "actual timeout voting writes signer intent"
    );
    let finality = |images: Vec<(PathBuf, Vec<u8>)>| {
        images
            .into_iter()
            .filter(|(path, _)| {
                path.starts_with("finality-journal") || path.starts_with("finality-anchor")
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(finality(layout.images()), finality(authority));
    assert_eq!(
        result(&mut node, json!({"command":"sources_status", "id":3}))["acquisition"]["id"],
        1
    );
    assert_eq!(source_images(&layout), sources);
    assert_eq!(
        result(&mut node, json!({"command":"cancel_acquisition", "id":4}))["active"],
        true
    );
    node.event("acquisition_cancelled");
    sdk.release();
    node.event("network_event_discarded");
    node.shutdown();
    sdk.stop();
    drop(provider_guard);
    assert_eq!(source_images(&layout), sources);
}
