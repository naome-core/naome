mod contention;
mod history;
mod integrity;
mod lifecycle;
mod provider;
mod retained;

use std::{fs, path::PathBuf};

use naome_chain::{ArtifactBlock, ArtifactChainState, ArtifactDag};
use naome_proof::{ArtifactPayload, ProofCertificate};
use serde_json::{Value, json};

use crate::support::*;
use provider::Plan;

fn payload(axiom: u8) -> Vec<u8> {
    ArtifactPayload::Proof(
        ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, axiom]).unwrap(),
    )
    .to_canonical_bytes()
}

fn branch(fixture: &Fixture, count: u8) -> (Vec<ArtifactBlock>, Vec<Vec<u8>>) {
    let mut chain = ArtifactChainState::new(fixture.definition);
    let mut blocks = Vec::new();
    let mut payloads = Vec::new();
    for axiom in 1..=count {
        let bytes = payload(axiom);
        let artifact = ArtifactDag::new()
            .apply_canonical_artifact_bytes(bytes.clone())
            .unwrap()
            .artifact_id();
        let block = chain.prepare_block(artifact).unwrap();
        chain.apply_block(&block, bytes.clone()).unwrap();
        blocks.push(block);
        payloads.push(bytes);
    }
    (blocks, payloads)
}

pub(super) fn source_config(layout: &Layout, config: String) -> String {
    for directory in ["candidates", "payloads"] {
        fs::create_dir(layout.root.join(directory)).unwrap();
    }
    format!(
        "{config}\n[sources]\nmode = \"create\"\ncandidate_directory = \"candidates\"\npayload_directory = \"payloads\"\ncandidate_entries = \"16\"\npayload_entries = \"16\"\npayload_bytes = \"1048576\"\n"
    )
}

fn source_images(layout: &Layout) -> Vec<(PathBuf, Vec<u8>)> {
    let mut result = Vec::new();
    for directory in ["candidates", "payloads"] {
        for entry in fs::read_dir(layout.root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            result.push((
                path.strip_prefix(&layout.root).unwrap().to_owned(),
                fs::read(path).unwrap(),
            ));
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

fn result(node: &mut Process, command: Value) -> Value {
    let id = command["id"].clone();
    node.send(command);
    let response = node.until(|v| {
        v["id"] == id && (v["event"] == "command_result" || v["event"] == "command_rejected")
    });
    assert_eq!(response["event"], "command_result", "{response}");
    response["outcome"].clone()
}

fn acquire(node: &mut Process, command: Value) -> Value {
    let id = command["id"].clone();
    let started = result(node, command);
    if started["event"] == "acquisition_complete" {
        return started["job"].clone();
    }
    assert_eq!(started["event"], "acquisition_started");
    let terminal = node.until(|v| {
        v["id"] == id
            && (v["event"] == "acquisition_complete" || v["event"] == "acquisition_failed")
    });
    assert_eq!(terminal["event"], "acquisition_complete", "{terminal}");
    terminal["job"].clone()
}

fn address(node: &mut Process) -> String {
    node.event("listening")["address"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn connected(node: &mut Process, peer: naome_network::PeerId) {
    node.until(|v| {
        v["event"] == "peer_session" && v["state"] == "established" && v["peer"] == peer.to_string()
    });
}

#[test]
fn all_six_network_acquisition_forms_then_explicit_authoring_actual_peer_finality_and_reopen() {
    for (anchored, fallback) in [(false, false), (true, false), (false, true), (true, true)] {
        let fixture = Fixture::new();
        let layout = Layout::new();
        let receiver_layout = Layout::new();
        let provider = Plan::new(fixture.peers[0]);
        let unavailable = Plan::new(fixture.peers[0]);
        let source_peer = provider.peer;
        let empty_peer = unavailable.peer;
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
            &layout,
            unavailable.configure(provider.configure(fixture.config(
                &layout,
                0,
                "create",
                Some(&receiver_address),
                true,
            ))),
        );
        let mut node = Process::start(&layout, &config);
        let initial = node.ready();
        let node_address = address(&mut node);
        connected(&mut receiver, fixture.peers[0]);
        let (blocks, payloads) = branch(&fixture, 1);
        let target = hex(blocks[0].id().as_bytes());
        let artifact = hex(blocks[0].artifact_id().as_bytes());
        let provider_guard = PARENT_JOURNALS.read().unwrap();
        let sdk = provider.start(
            &provider_guard,
            fixture.definition,
            &node_address,
            blocks.clone(),
            payloads,
            None,
        );
        connected(&mut node, source_peer);
        let empty = unavailable.start(
            &provider_guard,
            fixture.definition,
            &node_address,
            vec![],
            vec![],
            None,
        );
        connected(&mut node, empty_peer);
        let authority = layout.images();
        let mut ancestry = json!({"command": match (anchored, fallback) {
            (false, false) => "acquire_ancestry", (true, false) => "acquire_anchored_ancestry",
            (false, true) => "acquire_ancestry_fallback", (true, true) => "acquire_anchored_ancestry_fallback",
        }, "id": 1, "target": target});
        if anchored {
            ancestry["anchor"] = initial["driver"]["head"].clone();
        }
        if fallback {
            ancestry["peer_ids"] = json!([empty_peer.to_string(), source_peer.to_string()]);
        } else {
            ancestry["peer_id"] = json!(source_peer.to_string());
        }
        assert_eq!(acquire(&mut node, ancestry)["kind"], "ancestry");
        sdk.request("block", &target);
        if fallback {
            empty.request("block", &target);
        }
        let mut command = json!({"command": if fallback {"acquire_payloads_fallback"} else {"acquire_payloads"}, "id": 2, "target": target, "max_blocks": 1});
        if fallback {
            command["peer_ids"] = json!([empty_peer.to_string(), source_peer.to_string()]);
        } else {
            command["peer_id"] = json!(source_peer.to_string());
        }
        assert_eq!(acquire(&mut node, command)["validated_blocks"], 1);
        sdk.request("payload", &artifact);
        if fallback {
            empty.request("payload", &artifact);
        }
        assert_eq!(
            layout.images(),
            authority,
            "acquisition cannot sign or finalize"
        );
        assert!(!layout.root.join("block.bin").exists());
        assert!(!layout.root.join("payload.bin").exists());
        let sources = source_images(&layout);
        assert_eq!(
            result(
                &mut node,
                json!({"command":"author_candidate", "id":3, "target":target})
            )["event"],
            "proposal_authored"
        );
        for finality in [node.event("finality"), receiver.event("finality")] {
            assert_eq!(finality["state"]["driver"]["head"], target);
            assert_eq!(finality["state"]["driver"]["height"], "2");
        }
        assert_eq!(source_images(&layout), sources);
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
        node.shutdown();
        receiver.shutdown();
        sdk.stop();
        empty.stop();
        drop(provider_guard);
        for (layout, config) in [(&layout, &config), (&receiver_layout, &receiver_config)] {
            let before = layout.images();
            let mut reopened = Process::start(
                layout,
                &config.replace("mode = \"create\"", "mode = \"open\""),
            );
            assert_eq!(reopened.ready()["driver"]["head"], target);
            if layout.root.join("candidates").exists() {
                let status = result(&mut reopened, json!({"command":"sources_status", "id":4}));
                assert_eq!(status["candidate_entries"], 1);
                assert_eq!(status["payload_entries"], 1);
                assert!(status["acquisition"].is_null());
            }
            reopened.shutdown();
            assert_eq!(layout.images(), before);
        }
        assert_eq!(source_images(&layout), sources);
    }
}
