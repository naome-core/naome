use super::*;
use naome_consensus::VerifiedConsensusVoteV0;
use naome_network::ConsensusPushMessage;
use naome_storage::{
    FixedValidatorAnchoredFinalityJournalV0, FixedValidatorAnchoredVoteSafetyJournalV0,
    FixedValidatorFinalityReplayLimitV0, FixedValidatorVoteSafetyReplayLimitV0,
};
use sha2::{Digest, Sha256};

#[test]
fn reserved_consensus_crosses_acquisition_while_acquisition_remains_explicit() {
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
            assert!(matches!(
                sdk.message(),
                ConsensusPushMessage::Proposal { .. }
            ));
            for _ in 0..2 {
                assert!(matches!(sdk.message(), ConsensusPushMessage::Vote { .. }));
            }
            let finality = node.event("finality");
            assert_eq!(
                finality["state"]["driver"]["head"],
                hex(selected.id().as_bytes())
            );
            assert_eq!(
                node.observed
                    .iter()
                    .filter(|v| v["event"] == "peer_attempted" && v["started"] == true)
                    .count(),
                3
            );
            assert_eq!(
                node.observed
                    .iter()
                    .filter(|v| v["event"] == "publication_complete"
                        && v["disposed"]["deliveries"][0]["state"] == "received")
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
    // Timeout votes may replace vote anchors and delivery snapshots at any
    // point; only the finality directories must remain unchanged while live.
    let finality_before = layout.finality_images();
    let sources = source_images(&layout);
    assert_eq!(node.event("timer_due")["admitted"], true);
    assert_eq!(node.event("peer_attempted")["started"], true);
    let ConsensusPushMessage::Vote { canonical_vote } = sdk.message() else {
        panic!("the real phase deadline must publish a vote");
    };
    let vote =
        VerifiedConsensusVoteV0::decode_and_verify(&canonical_vote, fixture.context).unwrap();
    assert_eq!(vote.signer(), fixture.entries[0].consensus_key());
    let complete = node.event("publication_complete");
    assert_eq!(
        complete["disposed"]["message_sha256"]["control"],
        hex(&Sha256::digest(&canonical_vote))
    );
    assert_eq!(
        complete["disposed"]["deliveries"][0]["peer"],
        peer.to_string()
    );
    assert_eq!(complete["disposed"]["deliveries"][0]["state"], "received");
    let status = result(&mut node, json!({"command":"status", "id":2}));
    assert_eq!(status["driver"]["head"], initial["driver"]["head"]);
    assert_eq!(layout.finality_images(), finality_before);
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
    assert_eq!(layout.finality_images(), finality_before);
    let stopped = layout.images();
    {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let finality = FixedValidatorAnchoredFinalityJournalV0::open(
            layout.root.join("finality-journal"),
            layout.root.join("finality-anchor"),
            fixture.definition,
            fixture.context,
            &fixture.entries,
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        )
        .unwrap();
        let journal = FixedValidatorAnchoredVoteSafetyJournalV0::open(
            layout.root.join("vote-journal"),
            layout.root.join("vote-anchor"),
            fixture.context,
            finality.fixed_agreement_set_id(),
            fixture.keys[0].clone(),
            FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        )
        .unwrap();
        let retained = journal
            .retained_signed_vote(vote.position(), vote.role())
            .unwrap()
            .unwrap();
        assert_eq!(
            retained.canonical_bytes(),
            canonical_vote,
            "strict replay must retain the exact published timeout vote"
        );
        assert_eq!(
            complete["disposed"]["signer_state"],
            hex(retained.state_id().as_bytes())
        );
    }
    assert_eq!(
        layout.images(),
        stopped,
        "strict replay must not rewrite files"
    );
}
