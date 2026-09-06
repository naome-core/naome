use super::*;
use std::os::unix::fs::symlink;

fn reject(node: &mut Process, input: Value, code: &str) {
    node.send(input);
    assert_eq!(node.event("command_rejected")["code"], code);
}

#[test]
fn candidate_proof_schema_disabled_sources_and_independent_file_caps_precede_delegation() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    let layout = Layout::new();
    write_proof(&proof, &layout, "input");
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut disabled = Process::start(&layout, &config);
    disabled.ready();
    disabled.event("timer_armed");
    let authority = layout.images();
    for conflict in [false, true] {
        let mut input = command(&proof, "missing", conflict);
        input["target"] = json!("invalid");
        input["vote_files"] = json!([]);
        reject(&mut disabled, input, "sources_disabled");
    }
    disabled.shutdown();
    assert_eq!(layout.images(), authority);
    let config = source_config(&layout, config.replace("create", "open"));
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let initial = result(&mut node, json!({"command":"status", "id":1}));
    let sources = source_images(&layout);
    for conflict in [false, true] {
        let template = command(&proof, "input", conflict);
        for field in [
            "payload_file",
            "height",
            "parent",
            "root",
            "winner",
            "max_round",
            "candidate_directory",
        ] {
            let mut input = template.clone();
            input[field] = json!("extra");
            reject(&mut node, input, "command_schema");
        }
        for value in [json!(-1), json!("1"), json!(null), json!(1.5)] {
            let mut input = template.clone();
            input["evidence_round"] = value;
            reject(&mut node, input, "command_schema");
        }
        let name = template["command"].as_str().unwrap();
        node.write(format!("{{\"command\":\"{name}\",\"id\":1,\"target\":\"x\",\"target\":\"x\",\"evidence_round\":0,\"control_file\":\"missing\",\"vote_files\":[\"missing\"]}}\n").as_bytes());
        assert_eq!(node.event("command_rejected")["code"], "command_schema");
        for target in [
            "ab".into(),
            "AB".repeat(32),
            format!("0x{}", "ab".repeat(32)),
        ] {
            let mut input = template.clone();
            input["target"] = json!(target);
            reject(&mut node, input, "source_block_id");
        }
        for votes in [
            json!([]),
            json!(vec!["missing"; naome_consensus::MAX_ACTIVE_VALIDATORS + 1]),
        ] {
            let mut input = template.clone();
            input["control_file"] = json!("missing");
            input["vote_files"] = votes;
            reject(&mut node, input, "proof_vote_count");
        }
        for (field, cap) in [
            (
                "control_file",
                naome_network::CONSENSUS_PUSH_MAX_PROPOSAL_BYTES,
            ),
            ("vote_files", naome_network::CONSENSUS_PUSH_VOTE_BYTES),
        ] {
            layout.write("oversized", vec![0; cap + 1]);
            let mut input = template.clone();
            input[field] = if field == "vote_files" {
                json!(["oversized"])
            } else {
                json!("oversized")
            };
            reject(&mut node, input, "file_too_large");
        }
        layout.write("short.vote", [0]);
        let mut input = template.clone();
        input["vote_files"] = json!(["short.vote"]);
        reject(&mut node, input, "proof_vote_length");
        reject(&mut node, command(&proof, "missing", conflict), "file_open");
        let link = layout.root.join("linked.control");
        symlink(layout.root.join("input.control"), &link).unwrap();
        let mut input = template;
        input["control_file"] = json!("linked.control");
        reject(&mut node, input, "file_open");
        fs::remove_file(link).unwrap();
        assert_eq!(
            result(&mut node, json!({"command":"status", "id":2})),
            initial
        );
        assert_eq!(layout.images(), authority);
        assert_eq!(source_images(&layout), sources);
    }
    node.shutdown();
}

#[test]
fn candidate_proof_corruption_continues_positive_then_consumes_historical_without_source_repair() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let sibling = Proof::new(&fixture, false, 2, Role::Precommit);
    for candidate in [false, true] {
        let layout = Layout::new();
        write_proof(&sibling, &layout, "input");
        let plan = Plan::new(fixture.peers[1]);
        let peer = plan.peer;
        let config = source_config(
            &layout,
            plan.configure(fixture.config(&layout, 1, "create", None, false)),
        );
        let mut node = Process::start(&layout, &config);
        node.ready();
        let address = address(&mut node);
        initial_arm(&mut node);
        let provider_guard = PARENT_JOURNALS.read().unwrap();
        let sdk = plan.start(
            &provider_guard,
            fixture.definition,
            &address,
            vec![sibling.value.artifact_block()],
            vec![sibling.payload.clone()],
            None,
        );
        connected(&mut node, peer);
        load(&mut node, &sdk, peer, &sibling);
        let path = layout.root.join(if candidate {
            "candidates/artifact-block-candidate-store.log"
        } else {
            "payloads/artifact-payload-store.log"
        });
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        let damaged = source_images(&layout);
        let authority = layout.images();
        let before = result(&mut node, json!({"command":"status", "id":1}));
        let rejected = result(&mut node, command(&sibling, "input", false));
        assert_eq!(rejected["event"], "candidate_finality_rejected");
        assert_eq!(rejected["state"], before);
        assert_eq!(layout.images(), authority);
        let sources = result(&mut node, json!({"command":"sources_status", "id":2}));
        assert!(
            sources[if candidate {
                "candidate_entries"
            } else {
                "payload_entries"
            }]
            .is_null()
        );
        assert_eq!(
            sources[if candidate {
                "payload_entries"
            } else {
                "candidate_entries"
            }],
            1
        );
        assert_eq!(source_images(&layout), damaged);
        select(&mut node, &layout, &[&first]);
        let selected = layout.images();
        failed(&result(&mut node, command(&sibling, "input", true)), true);
        stopped(&mut node);
        assert_eq!(layout.images(), selected);
        assert_eq!(source_images(&layout), damaged);
        sdk.stop();
        drop(provider_guard);
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
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
        assert_eq!(layout.images(), selected);
    }
}
