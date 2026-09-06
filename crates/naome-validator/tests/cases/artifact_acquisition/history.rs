use super::*;
use naome_consensus::{ActiveAgreementEntry, AgreementWeight};

pub(super) fn dominant_fixture() -> Fixture {
    let mut fixture = Fixture::new();
    fixture.entries[0] =
        ActiveAgreementEntry::new(fixture.entries[0].consensus_key(), AgreementWeight::new(7));
    fixture
}

#[test]
fn current_head_anchor_and_captured_payload_have_distinct_history_change_boundaries() {
    for mode in ["current", "anchor", "payload"] {
        let fixture = dominant_fixture();
        let layout = Layout::new();
        let provider = Plan::new(fixture.peers[0]);
        let peer = provider.peer;
        let config = source_config(
            &layout,
            provider.configure(fixture.config(&layout, 0, "create", None, false)),
        );
        let mut node = Process::start(&layout, &config);
        let initial = node.ready();
        let node_address = address(&mut node);
        let bytes = payload(2);
        let artifact = ArtifactDag::new()
            .apply_canonical_artifact_bytes(bytes.clone())
            .unwrap()
            .artifact_id();
        let sibling = ArtifactChainState::new(fixture.definition)
            .prepare_block(artifact)
            .unwrap();
        let target = hex(sibling.id().as_bytes());
        let hold = if mode == "payload" {
            hex(artifact.as_bytes())
        } else {
            target.clone()
        };
        let provider_guard = PARENT_JOURNALS.read().unwrap();
        let sdk = provider.start(
            &provider_guard,
            fixture.definition,
            &node_address,
            vec![sibling],
            vec![bytes.clone()],
            Some(hold.clone()),
        );
        connected(&mut node, peer);
        let mut command = json!({"command":"acquire_ancestry", "id":1, "target":target, "peer_id":peer.to_string()});
        if mode == "payload" {
            acquire(&mut node, command.clone());
            sdk.request("block", &target);
            command = json!({"command":"acquire_payloads", "id":2, "target":target, "peer_id":peer.to_string(), "max_blocks":1});
        } else if mode == "anchor" {
            command["command"] = json!("acquire_anchored_ancestry");
            command["anchor"] = initial["driver"]["head"].clone();
        }
        assert_eq!(result(&mut node, command)["event"], "acquisition_started");
        sdk.request(
            if mode == "payload" {
                "payload"
            } else {
                "block"
            },
            &hold,
        );
        let selected = fixture.proposal(&layout);
        assert_eq!(
            result(
                &mut node,
                json!({"command":"author_fresh", "id":3, "block_file":"block.bin", "payload_file":"payload.bin"})
            )["event"],
            "proposal_authored"
        );
        assert_eq!(
            node.event("finality")["state"]["driver"]["head"],
            hex(selected.id().as_bytes())
        );
        node.event("timer_armed");
        let authority = layout.images();
        sdk.release();
        if mode == "current" {
            assert_eq!(
                node.event("acquisition_failed")["code"],
                "source_selected_head_changed"
            );
        } else {
            assert_eq!(node.event("acquisition_complete")["job"]["target"], target);
            if mode == "anchor" {
                acquire(
                    &mut node,
                    json!({"command":"acquire_payloads", "id":4, "target":target, "peer_id":peer.to_string(), "max_blocks":1}),
                );
                sdk.request("payload", &hex(artifact.as_bytes()));
            }
            let sources = source_images(&layout);
            assert_eq!(
                result(
                    &mut node,
                    json!({"command":"author_candidate", "id":5, "target":target})
                )["event"],
                "proposal_rejected"
            );
            assert_eq!(source_images(&layout), sources);
        }
        let status = result(&mut node, json!({"command":"sources_status", "id":6}));
        assert_eq!(
            status["candidate_entries"],
            if mode == "current" { 0 } else { 1 }
        );
        assert_eq!(
            status["payload_entries"],
            if mode == "current" { 0 } else { 1 }
        );
        assert_eq!(
            layout.images(),
            authority,
            "completion/rejection cannot modify the advanced signer"
        );
        // The same signer is eligible and healthy at its actual new height.
        // The sibling refusal above cannot be explained by an ineligible signer.
        let mut chain = ArtifactChainState::new(fixture.definition);
        chain.apply_block(&selected, payload(1)).unwrap();
        let child = chain.prepare_block(artifact).unwrap();
        layout.write("child.bin", child.to_canonical_bytes());
        layout.write("child.payload", bytes);
        assert_eq!(
            result(
                &mut node,
                json!({"command":"author_fresh", "id":7, "block_file":"child.bin", "payload_file":"child.payload"})
            )["event"],
            "proposal_authored"
        );
        assert_eq!(
            node.event("finality")["state"]["driver"]["head"],
            hex(child.id().as_bytes())
        );
        node.shutdown();
        sdk.stop();
        drop(provider_guard);
        let sources = source_images(&layout);
        let authority = layout.images();
        let mut reopened = Process::start(
            &layout,
            &config.replace("mode = \"create\"", "mode = \"open\""),
        );
        assert_eq!(
            reopened.ready()["driver"]["head"],
            hex(child.id().as_bytes())
        );
        reopened.shutdown();
        assert_eq!(source_images(&layout), sources);
        assert_eq!(layout.images(), authority);
    }
}
