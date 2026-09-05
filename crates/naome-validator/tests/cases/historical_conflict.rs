use super::{explicit_proofs::result, *};
use naome_consensus::{ConsensusVoteRole as Role, VerifiedFixedConsensusTransitionV0};
use serde_json::Value;
use std::path::Path;

fn command(proof: &Proof, prefix: &str, batch: bool) -> Value {
    if batch {
        json!({"command":"halt_historical_votes", "id":u64::MAX, "evidence_round":proof.round, "proof":Proof::files(prefix)})
    } else {
        json!({"command":"halt_historical_envelope", "id":u64::MAX, "envelope_file":format!("{prefix}.envelope"), "payload_file":format!("{prefix}.payload")})
    }
}

fn select_prefix(node: &mut Process, layout: &Layout, prefix: &[&Proof]) {
    for (index, proof) in prefix.iter().enumerate() {
        let name = format!("selected-{index}");
        proof.write(layout, &name);
        if proof.round > 0 {
            let checkpoint = result(node, proof.higher_command(index as u64, &name, false));
            assert_eq!(checkpoint["event"], "transitioned");
            node.event("timer_armed");
        }
        let outcome = result(node, proof.current_command(index as u64 + 10, &name, true));
        assert_eq!(outcome["event"], "finality");
        assert_eq!(
            outcome["state"]["driver"]["height"],
            (index + 2).to_string()
        );
        assert_eq!(
            outcome["state"]["driver"]["head"],
            hex(proof.value.artifact_block().id().as_bytes())
        );
        node.event("timer_armed");
    }
}

fn assert_halt(outcome: &Value, first: &Proof, sibling: &Proof) {
    assert_eq!(outcome["event"], "finality_stopped");
    assert_eq!(outcome["kind"], "SelectedSibling");
    assert_eq!(outcome["height"], "1");
    assert_eq!(
        outcome["first_ancestry"],
        hex(first.value.ancestry_id().as_bytes())
    );
    assert_eq!(
        outcome["second_ancestry"],
        hex(sibling.value.ancestry_id().as_bytes())
    );
    assert_eq!(
        outcome["finality_state_id"],
        outcome["signer_finality_state_id"]
    );
    assert!(outcome["state"]["driver"].is_null());
}

fn stopped(node: &mut Process) -> Value {
    let stopped = node.event("stopped");
    assert_eq!(stopped["reason"], "command_fatal");
    assert_eq!(stopped["locks_released"], true);
    assert!(!node.exit().success());
    stopped
}

#[test]
fn direct_historical_proofs_halt_a_running_process_after_two_selected_heights_and_strictly_restart_terminal()
 {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::after_prefix(&fixture, &[&first], 0, 3, Role::Precommit);
    let sibling = Proof::after_prefix(&fixture, &[], 2, 2, Role::Precommit);
    for batch in [false, true] {
        let layout = Layout::new();
        sibling.write(&layout, "sibling");
        let config = fixture.config(&layout, 1, "create", None, false);
        let mut node = Process::start(&layout, &config);
        node.ready();
        node.event("timer_armed");
        select_prefix(&mut node, &layout, &[&first, &second]);
        let initial = result(&mut node, json!({"command":"status", "id":50}));
        assert_eq!(initial["driver"]["height"], "3");
        assert_eq!(initial["driver"]["round"], "0");
        assert_eq!(initial["driver"]["phase"], "Proposal");
        let before = layout.images();
        let outcome = result(&mut node, command(&sibling, "sibling", batch));
        assert_halt(&outcome, &first, &sibling);
        let stop = stopped(&mut node);
        assert!(stop["discarded"]["driver"].is_null());
        assert_ne!(layout.images(), before);
        let durable = layout.images();
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
        assert_eq!(reopened.event("error")["code"], "startup_finality_stopped");
        assert!(!reopened.exit().success());
        assert_eq!(layout.images(), durable);
    }
}

#[test]
fn historical_schema_and_independent_source_caps_refuse_before_invocation_then_accept_valid_submission()
 {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let sibling = Proof::after_prefix(&fixture, &[], 2, 2, Role::Precommit);
    let layout = Layout::new();
    sibling.write(&layout, "sibling");
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    select_prefix(&mut node, &layout, &[&first]);
    let before = layout.images();
    let initial = result(&mut node, json!({"command":"status", "id":60}));
    for batch in [false, true] {
        let template = command(&sibling, "missing", batch);
        for field in ["height", "parent", "target", "winner"] {
            let mut changed = template.clone();
            changed[field] = json!(0);
            node.send(changed);
            assert_eq!(node.event("command_rejected")["code"], "command_schema");
        }
        if batch {
            for files in [json!([]), json!(vec!["missing"; 257])] {
                let mut changed = template.clone();
                changed["proof"]["vote_files"] = files;
                node.send(changed);
                assert_eq!(node.event("command_rejected")["code"], "proof_vote_count");
            }
            for malformed in [json!(["missing", "missing", ["missing"]]), json!(null)] {
                let mut changed = template.clone();
                changed["proof"] = malformed;
                node.send(changed);
                assert_eq!(node.event("command_rejected")["code"], "command_schema");
            }
            let mut changed = template.clone();
            changed["proof"]["extra"] = json!(0);
            node.send(changed);
            assert_eq!(node.event("command_rejected")["code"], "command_schema");
        } else {
            let mut changed = template.clone();
            changed["evidence_round"] = json!(0);
            node.send(changed);
            assert_eq!(node.event("command_rejected")["code"], "command_schema");
        }
        node.send(template);
        assert_eq!(node.event("command_rejected")["code"], "file_open");
    }
    node.write(b"{\"command\":\"halt_historical_votes\",\"id\":1,\"evidence_round\":2,\"proof\":{\"control_file\":\"missing\",\"control_file\":\"missing\",\"payload_file\":\"missing\",\"vote_files\":[\"missing\"]}}\n");
    assert_eq!(node.event("command_rejected")["code"], "command_schema");
    node.write(b"{\"command\":\"halt_historical_envelope\",\"id\":1,\"envelope_file\":\"missing\",\"envelope_file\":\"missing\",\"payload_file\":\"missing\"}\n");
    assert_eq!(node.event("command_rejected")["code"], "command_schema");
    for (batch, field, cap) in [
        (
            false,
            "envelope_file",
            VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH,
        ),
        (
            false,
            "payload_file",
            naome_network::CONSENSUS_PUSH_MAX_PAYLOAD_BYTES,
        ),
        (
            true,
            "control_file",
            naome_network::CONSENSUS_PUSH_MAX_PROPOSAL_BYTES,
        ),
        (
            true,
            "payload_file",
            naome_network::CONSENSUS_PUSH_MAX_PAYLOAD_BYTES,
        ),
        (true, "vote_files", naome_network::CONSENSUS_PUSH_VOTE_BYTES),
    ] {
        layout.write("oversized", vec![0; cap + 1]);
        let mut changed = command(&sibling, "sibling", batch);
        if batch {
            changed["proof"][field] = if field == "vote_files" {
                json!(["oversized"])
            } else {
                json!("oversized")
            };
        } else {
            changed[field] = json!("oversized");
        }
        node.send(changed);
        assert_eq!(node.event("command_rejected")["code"], "file_too_large");
        assert_eq!(layout.images(), before);
    }
    assert_eq!(
        result(&mut node, json!({"command":"status", "id":61})),
        initial
    );
    assert_eq!(layout.images(), before);
    assert_halt(
        &result(&mut node, command(&sibling, "sibling", true)),
        &first,
        &sibling,
    );
    stopped(&mut node);
}

#[test]
fn historical_delegated_rejections_stop_without_authority_writes_and_reopen_at_the_selected_head() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::after_prefix(&fixture, &[&first], 0, 3, Role::Precommit);
    let sibling = Proof::after_prefix(&fixture, &[], 2, 2, Role::Precommit);
    let next = Proof::after_prefix(&fixture, &[&first, &second], 0, 2, Role::Precommit);
    for batch in [false, true] {
        for mode in [
            "selected",
            "next",
            "bad-proof",
            "bad-payload",
            "round-overflow",
        ] {
            if !batch && mode == "round-overflow" {
                continue;
            }
            let layout = Layout::new();
            let input = match mode {
                "selected" => &first,
                "next" => &next,
                _ => &sibling,
            };
            input.write(&layout, "input");
            if mode == "bad-proof" {
                layout.write(
                    if batch {
                        "input.control"
                    } else {
                        "input.envelope"
                    },
                    [0],
                );
            }
            if mode == "bad-payload" {
                layout.write("input.payload", [0]);
            }
            let config = fixture.config(&layout, 1, "create", None, false);
            let mut node = Process::start(&layout, &config);
            node.ready();
            node.event("timer_armed");
            select_prefix(&mut node, &layout, &[&first, &second]);
            let initial = result(&mut node, json!({"command":"status", "id":50}));
            let before = layout.images();
            let mut input_command = command(input, "input", batch);
            if mode == "round-overflow" {
                input_command["evidence_round"] = json!(u64::MAX);
            }
            let outcome = result(&mut node, input_command);
            assert_eq!(outcome["event"], "proof_failed");
            assert_eq!(outcome["operation"], "historical_finality_conflict");
            assert_eq!(outcome["strict_restart_required"], true);
            assert!(outcome["state"]["driver"].is_null());
            assert_eq!(layout.images(), before);
            stopped(&mut node);
            let mut reopened = Process::start(&layout, &config.replace("create", "open"));
            let ready = reopened.ready();
            for field in ["height", "round", "phase", "head"] {
                assert_eq!(ready["driver"][field], initial["driver"][field]);
            }
            reopened.shutdown();
            assert_eq!(layout.images(), before);
        }
    }
}

#[test]
fn historical_halt_or_consuming_rejection_preserves_real_height_three_inflight_publication_for_disposal()
 {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::after_prefix(&fixture, &[&first], 0, 3, Role::Precommit);
    let sibling = Proof::after_prefix(&fixture, &[], 2, 2, Role::Precommit);
    let higher = Proof::after_prefix(&fixture, &[&first, &second], 1, 2, Role::Prevote);
    for batch in [false, true] {
        for distinct in [false, true] {
            let layout = Layout::new();
            let peer_layout = Layout::new();
            first.write(&layout, "first");
            sibling.write(&layout, "sibling");
            higher.write(&layout, "higher");
            let config = fixture.config(&layout, 1, "create", Some("/ip4/127.0.0.1/tcp/1"), true);
            let mut node = Process::start(&layout, &config);
            node.ready();
            let address = node.event("listening")["address"]
                .as_str()
                .unwrap()
                .to_owned();
            if !node
                .observed
                .iter()
                .any(|event| event["event"] == "timer_armed")
            {
                node.event("timer_armed");
            }
            select_prefix(&mut node, &layout, &[&first, &second]);
            let mut peer = Process::start(
                &peer_layout,
                &fixture.config(&peer_layout, 0, "create", Some(&address), false),
            );
            peer.ready();
            node.until(|v| v["event"] == "peer_session" && v["state"] == "established");
            peer.until(|v| v["event"] == "peer_session" && v["state"] == "established");
            peer.signal(rustix::process::Signal::STOP);
            assert_eq!(
                result(
                    &mut node,
                    json!({"command":"submit_proposal", "id":20, "control_file":"higher.control", "payload_file":"higher.payload"})
                )["event"],
                "input_queued"
            );
            assert_eq!(node.event("admission")["all_admitted"], true);
            assert_eq!(
                result(
                    &mut node,
                    json!({"command":"submit_vote", "id":21, "vote_file":"higher.vote"})
                )["event"],
                "input_queued"
            );
            assert_eq!(node.event("admission")["all_admitted"], true);
            let transitioned = node.event("transitioned");
            assert_eq!(transitioned["height"], "3");
            assert_eq!(transitioned["round"], higher.round.to_string());
            assert_eq!(transitioned["phase"], "Precommit");
            assert_eq!(node.event("peer_attempted")["started"], true);
            let initial = result(&mut node, json!({"command":"status", "id":22}));
            assert_eq!(initial["publication"]["released_proposal"], true);
            assert_eq!(
                initial["publication"]["deliveries"][0]["state"],
                "in_flight"
            );
            let before = layout.images();
            let outcome = result(
                &mut node,
                command(
                    if distinct { &sibling } else { &first },
                    if distinct { "sibling" } else { "first" },
                    batch,
                ),
            );
            if distinct {
                assert_halt(&outcome, &first, &sibling);
                assert_ne!(layout.images(), before);
            } else {
                assert_eq!(outcome["event"], "proof_failed");
                assert_eq!(outcome["operation"], "historical_finality_conflict");
                assert_eq!(outcome["strict_restart_required"], true);
                assert_eq!(layout.images(), before);
            }
            assert!(outcome["state"]["driver"].is_null());
            assert_eq!(outcome["state"]["publication"], initial["publication"]);
            assert_eq!(outcome["state"]["timer"], initial["timer"]);
            let stop = stopped(&mut node);
            assert_eq!(stop["discarded"]["publication"], initial["publication"]);
            assert!(stop["discarded"]["driver"].is_null());
            assert!(!node.observed.iter().any(|v| v["event"] == "peer_completed"));
            peer.signal(rustix::process::Signal::CONT);
            peer.shutdown();
            let durable = layout.images();
            let mut reopened = Process::start(&layout, &config.replace("create", "open"));
            if distinct {
                assert_eq!(reopened.event("error")["code"], "startup_finality_stopped");
                assert!(!reopened.exit().success());
            } else {
                let ready = reopened.ready();
                for field in ["height", "round", "phase", "head"] {
                    assert_eq!(ready["driver"][field], initial["driver"][field]);
                }
                reopened.shutdown();
            }
            assert_eq!(layout.images(), durable);
        }
    }
}

#[test]
fn historical_anchor_failures_stop_the_process_and_strict_reopen_refuses_each_partial_pair() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::after_prefix(&fixture, &[&first], 0, 3, Role::Precommit);
    let sibling = Proof::after_prefix(&fixture, &[], 2, 2, Role::Precommit);
    for batch in [false, true] {
        for (directory, offset) in [("finality-anchor", 149), ("vote-anchor", 184)] {
            let layout = Layout::new();
            sibling.write(&layout, "sibling");
            let config = fixture.config(&layout, 1, "create", None, false);
            let mut node = Process::start(&layout, &config);
            node.ready();
            node.event("timer_armed");
            select_prefix(&mut node, &layout, &[&first, &second]);
            let before = layout.images();
            let name = fs::read_dir(layout.root.join(directory))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .find(|name| name.ends_with(".anchor"))
                .unwrap();
            let bytes = fs::read(layout.root.join(directory).join(&name)).unwrap();
            let next = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap()) + 1;
            let collision = layout
                .root
                .join(directory)
                .join(format!("{name}.tmp-{next:016x}"));
            fs::write(&collision, b"historical conflict anchor collision").unwrap();
            let outcome = result(&mut node, command(&sibling, "sibling", batch));
            assert_eq!(outcome["event"], "proof_failed");
            assert_eq!(outcome["operation"], "historical_finality_conflict");
            assert_eq!(outcome["strict_restart_required"], true);
            assert!(outcome["state"]["driver"].is_null());
            stopped(&mut node);
            fs::remove_file(collision).unwrap();
            let after = layout.images();
            for ((path, old), (actual_path, new)) in before.iter().zip(&after) {
                assert_eq!(path, actual_path);
                let changes = path == Path::new("finality-journal/artifact-chain.journal")
                    || (directory == "vote-anchor"
                        && ((path.starts_with("finality-anchor")
                            && path
                                .extension()
                                .is_some_and(|extension| extension == "anchor"))
                            || (path.starts_with("vote-journal")
                                && path
                                    .extension()
                                    .is_some_and(|extension| extension == "journal"))));
                if changes {
                    assert_ne!(old, new, "{path:?}");
                } else {
                    assert_eq!(old, new, "{path:?}");
                }
            }
            let mut reopened = Process::start(&layout, &config.replace("create", "open"));
            assert_eq!(reopened.event("error")["code"], "startup_open");
            assert!(!reopened.exit().success());
            assert_eq!(layout.images(), after);
        }
    }
}
