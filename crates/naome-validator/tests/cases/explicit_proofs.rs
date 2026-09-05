use super::*;
use naome_consensus::{ConsensusVoteRole as Role, VerifiedQuorumCertificateV0};
use serde_json::Value;

fn result(node: &mut Process, command: Value) -> Value {
    let id = command["id"].clone();
    node.send(command);
    node.until(|value| value["event"] == "command_result" && value["id"] == id)["outcome"].clone()
}

#[test]
fn target_tags_extras_and_nonscalar_roles_fail_schema_before_any_source_read() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let before = layout.images();
    let template = json!({"command":"advance_higher_votes", "id":5, "evidence_round":1,
        "role":"prevote", "target":{"kind":"nil"}, "vote_files":["missing.vote"]});
    let mut observed = Vec::new();
    for changed in [
        json!({"target":{"kind":"nil", "unexpected":true}}),
        json!({"target":{"kind":"nil", "root":"00".repeat(32)}}),
        json!({"role":{"prevote":null}}),
        json!({"role":{"precommit":null}}),
        json!({"target":{"kind":0}}),
        json!({"target":{"kind":1,"root":"00".repeat(32)}}),
        json!({"target":{"kind":true}}),
        json!({"target":{"kind":null}}),
        json!({"target":{"kind":"0"}}),
        json!({"target":{"kind":"Nil"}}),
        json!({"target":{}}),
        json!({"target":{"kind":"proposal"}}),
        json!({"target":{"kind":"nil","root":null}}),
        json!({"target":{"kind":"proposal","root":null}}),
    ] {
        let mut command = template.clone();
        for (field, value) in changed.as_object().unwrap() {
            command[field] = value.clone();
        }
        node.send(command);
        observed.push(node.event("command_rejected")["code"].clone());
        assert_eq!(layout.images(), before);
    }
    // The valid scalar/nil representation passes schema and reaches source I/O.
    node.send(template);
    assert_eq!(node.event("command_rejected")["code"], "file_open");
    node.shutdown();
    assert_eq!(observed, vec![json!("command_schema"); 14]);
}

#[test]
fn command_target_and_nested_proofs_require_objects_and_keep_duplicate_field_rejection() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let before = layout.images();
    let template = json!({"command":"advance_higher_votes", "id":5, "evidence_round":1,
        "role":"prevote", "target":{"kind":"nil"}, "vote_files":["missing.vote"]});
    let mut commands = vec![
        json!(["status", 5]),
        json!(["advance_higher_votes",5,1,"prevote",{"kind":"nil"},["missing.vote"]]),
    ];
    for target in [json!(["nil"]), json!(["proposal", "00".repeat(32)])] {
        let mut command = template.clone();
        command["target"] = target;
        commands.push(command);
    }
    let array = json!(["missing.control", "missing.payload", ["missing.vote"]]);
    commands
        .push(json!({"command":"finalize_lower_votes", "id":5, "evidence_round":0, "proof":array}));
    for field in ["first", "second"] {
        let mut command = json!({"command":"halt_lower_conflict", "id":5, "evidence_round":0, "first":Proof::files("missing"), "second":Proof::files("missing")});
        command[field] = array.clone();
        commands.push(command);
    }
    let mut observed = Vec::new();
    for command in commands {
        node.send(command);
        observed.push(node.until(|v| v["event"] == "command_rejected" || v["event"] == "command_result")["code"].clone());
        assert_eq!(layout.images(), before);
    }
    // A JSON Value intermediate would erase these duplicate fields. Keep the
    // streaming map entries intact so every boundary still rejects duplicates.
    for command in [
        r#"{"command":"status","id":5,"id":6}"#,
        r#"{"command":"status","command":"shutdown","id":5}"#,
        r#"{"command":"status","id":5}{"command":"shutdown","id":6}"#,
        r#"{"command":"advance_higher_votes","id":5,"evidence_round":1,"role":"prevote","role":"precommit","target":{"kind":"nil"},"vote_files":["missing"]}"#,
        r#"{"command":"advance_higher_votes","id":5,"evidence_round":1,"role":"prevote","target":{"kind":"nil","kind":"nil"},"vote_files":["missing"]}"#,
        r#"{"command":"advance_higher_votes","id":5,"evidence_round":1,"role":"prevote","target":{"kind":"proposal","root":"bad","root":"bad"},"vote_files":["missing"]}"#,
        r#"{"command":"finalize_lower_votes","id":5,"evidence_round":0,"proof":{"control_file":"missing","control_file":"missing","payload_file":"missing","vote_files":["missing"]}}"#,
    ] {
        node.write(format!("{command}\n").as_bytes());
        assert_eq!(node.event("command_rejected")["code"], "command_schema");
        assert_eq!(layout.images(), before);
    }
    node.shutdown();
    assert_eq!(observed, vec![json!("command_schema"); 7]);
}

fn advance(node: &mut Process, proof: &Proof, batch: bool) -> Value {
    let outcome = result(node, proof.higher_command(1, "higher", batch));
    assert_eq!(outcome["event"], "transitioned");
    assert_eq!(outcome["round"], proof.round.to_string());
    assert_eq!(outcome["state"]["driver"]["height"], "1");
    node.event("timer_armed");
    outcome
}

fn finality_images(layout: &Layout) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    layout
        .images()
        .into_iter()
        .filter(|(path, _)| {
            path.starts_with("finality-journal") || path.starts_with("finality-anchor")
        })
        .collect()
}

#[test]
fn both_higher_proof_forms_checkpoint_each_role_without_finality_and_strictly_restart() {
    let fixture = Fixture::new();
    for role in [Role::Prevote, Role::Precommit] {
        let proof = Proof::new(&fixture, true, 1, role);
        for batch in [false, true] {
            let layout = Layout::new();
            proof.write(&layout, "higher");
            let config = fixture.config(&layout, 1, "create", None, false);
            let mut node = Process::start(&layout, &config);
            let initial = node.ready();
            node.event("timer_armed");
            let before = layout.images();
            let finality_before = finality_images(&layout);
            let outcome = advance(&mut node, &proof, batch);
            let phase = match role {
                Role::Prevote => "Prevote",
                Role::Precommit => "Precommit",
            };
            assert_eq!(outcome["phase"], phase);
            assert_eq!(
                outcome["state"]["driver"]["head"],
                initial["driver"]["head"]
            );
            assert_eq!(finality_images(&layout), finality_before);
            assert_ne!(layout.images(), before);
            node.shutdown();
            let durable = layout.images();
            let mut reopened = Process::start(&layout, &config.replace("create", "open"));
            let state = reopened.ready();
            assert_eq!(state["driver"]["round"], proof.round.to_string());
            assert_eq!(state["driver"]["phase"], phase);
            assert_eq!(state["driver"]["head"], initial["driver"]["head"]);
            reopened.shutdown();
            assert_eq!(layout.images(), durable);
        }
    }
}

#[test]
fn both_lower_proof_forms_finalize_exact_child_after_checkpoint_and_strictly_restart() {
    let fixture = Fixture::new();
    let higher = Proof::new(&fixture, true, 1, Role::Prevote);
    let lower = Proof::new(&fixture, false, 1, Role::Precommit);
    for batch in [false, true] {
        let layout = Layout::new();
        higher.write(&layout, "higher");
        lower.write(&layout, "lower");
        let config = fixture.config(&layout, 1, "create", None, false);
        let mut node = Process::start(&layout, &config);
        node.ready();
        node.event("timer_armed");
        advance(&mut node, &higher, batch);
        let outcome = result(&mut node, lower.lower_command(2, "lower", batch));
        assert_eq!(outcome["event"], "finality");
        let expected = hex(lower.value.artifact_block().id().as_bytes());
        assert_eq!(outcome["state"]["driver"]["head"], expected);
        assert_eq!(outcome["state"]["driver"]["height"], "2");
        assert_eq!(outcome["state"]["driver"]["round"], "0");
        node.shutdown();
        let durable = layout.images();
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
        let state = reopened.ready();
        assert_eq!(state["driver"]["head"], expected);
        assert_eq!(state["driver"]["height"], "2");
        assert_eq!(state["driver"]["round"], "0");
        assert_eq!(state["driver"]["phase"], "Proposal");
        reopened.shutdown();
        assert_eq!(layout.images(), durable);
    }
}

#[test]
fn explicit_proof_file_schema_and_route_refusals_preserve_authority_for_valid_resubmission() {
    let fixture = Fixture::new();
    let higher = Proof::new(&fixture, true, 1, Role::Prevote);
    let lower = Proof::new(&fixture, false, 1, Role::Precommit);
    let layout = Layout::new();
    higher.write(&layout, "higher");
    lower.write(&layout, "lower");
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let before = layout.images();
    let template = higher.higher_command(10, "higher", true);
    let mut cases = Vec::new();
    for votes in [json!([]), json!(vec!["missing"; 257])] {
        let mut command = template.clone();
        command["vote_files"] = votes;
        cases.push((command, "proof_vote_count"));
    }
    let mut command = template.clone();
    command["target"]["root"] = json!("A".repeat(64));
    cases.push((command, "proof_root"));
    for (field, value) in [
        ("role", json!("proposal")),
        ("evidence_round", json!(-1)),
        ("evidence_round", json!("1")),
        ("evidence_round", json!(1.0)),
    ] {
        let mut command = template.clone();
        command[field] = value;
        cases.push((command, "command_schema"));
    }
    let mut command = template.clone();
    command["target"]["unexpected"] = json!(0);
    cases.push((command, "command_schema"));
    let mut command = lower.lower_command(10, "lower", true);
    command["proof"]["unexpected"] = json!(0);
    cases.push((command, "command_schema"));
    let pair = json!({"command":"halt_lower_conflict", "id":10, "evidence_round":0, "first":Proof::files("missing"), "second": {"control_file":"missing", "payload_file":"missing", "vote_files":[]}});
    cases.push((pair, "proof_vote_count"));
    layout.write("short.vote", [0]);
    layout.write(
        "large.vote",
        vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES + 1],
    );
    layout.write(
        "large.certificate",
        vec![0; VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH + 1],
    );
    for (path, code) in [
        ("short.vote", "proof_vote_length"),
        ("large.vote", "file_too_large"),
        ("missing", "file_open"),
    ] {
        let mut command = template.clone();
        command["vote_files"] = json!([path]);
        cases.push((command, code));
    }
    cases.push((
        json!({"command":"advance_higher_quorum", "id":10, "certificate_file":"large.certificate"}),
        "file_too_large",
    ));
    for (command, code) in cases {
        node.send(command);
        assert_eq!(node.event("command_rejected")["code"], code);
        assert_eq!(layout.images(), before);
    }
    // Canonically bounded hostile inputs reach the existing strict verifier.
    let mut damaged = higher.vote.clone();
    *damaged.last_mut().unwrap() ^= 1;
    layout.write("damaged.vote", damaged);
    for changed in [
        json!({"vote_files":["damaged.vote"]}),
        json!({"vote_files":["higher.vote", "damaged.vote"]}),
        json!({"vote_files":["higher.vote", "higher.vote"]}),
        json!({"vote_files":vec!["higher.vote"; 256]}),
        json!({"evidence_round":u64::MAX}),
        json!({"role":"precommit"}),
        json!({"target":{"kind":"nil"}}),
    ] {
        let mut command = template.clone();
        for (key, value) in changed.as_object().unwrap() {
            command[key] = value.clone();
        }
        assert_eq!(result(&mut node, command)["event"], "higher_round_rejected");
        assert_eq!(layout.images(), before);
    }
    advance(&mut node, &higher, true);
    node.shutdown();
}

#[test]
fn lower_pair_neutral_halt_and_same_pair_consuming_failure_have_distinct_restart_results() {
    let fixture = Fixture::new();
    let higher = Proof::new(&fixture, true, 1, Role::Prevote);
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::new(&fixture, false, 2, Role::Precommit);
    for distinct in [false, true] {
        let layout = Layout::new();
        higher.write(&layout, "higher");
        first.write(&layout, "first");
        second.write(&layout, "second");
        let config = fixture.config(&layout, 1, "create", None, false);
        let mut node = Process::start(&layout, &config);
        node.ready();
        node.event("timer_armed");
        advance(&mut node, &higher, false);
        let before = layout.images();
        let command = json!({"command":"halt_lower_conflict", "id":11, "evidence_round":0, "first":Proof::files("first"), "second":Proof::files(if distinct {"second"} else {"first"})});
        let outcome = result(&mut node, command);
        assert!(outcome["state"]["driver"].is_null());
        assert_eq!(
            outcome["event"],
            if distinct {
                "finality_stopped"
            } else {
                "proof_failed"
            }
        );
        if distinct {
            assert_eq!(outcome["kind"], "PreselectionPair");
            assert_eq!(outcome["height"], "1");
            let ordered =
                if first.value.proposal_signing_root() < second.value.proposal_signing_root() {
                    [&first, &second]
                } else {
                    [&second, &first]
                };
            assert_eq!(
                outcome["first_ancestry"],
                hex(ordered[0].value.ancestry_id().as_bytes())
            );
            assert_eq!(
                outcome["second_ancestry"],
                hex(ordered[1].value.ancestry_id().as_bytes())
            );
            assert_eq!(
                outcome["finality_state_id"],
                outcome["signer_finality_state_id"]
            );
            assert_ne!(layout.images(), before);
        } else {
            assert_eq!(outcome["strict_restart_required"], true);
            assert_eq!(layout.images(), before);
        }
        let stopped = node.event("stopped");
        assert_eq!(stopped["reason"], "command_fatal");
        assert_eq!(stopped["locks_released"], true);
        assert!(!node.exit().success());
        let durable = layout.images();
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
        if distinct {
            assert_eq!(reopened.event("error")["code"], "startup_finality_stopped");
            assert!(!reopened.exit().success());
        } else {
            assert_eq!(
                reopened.ready()["driver"]["round"],
                higher.round.to_string()
            );
            reopened.shutdown();
        }
        assert_eq!(layout.images(), durable);
    }
}

#[test]
fn retained_current_finality_precedes_every_positive_proof_then_exact_proposal_completes() {
    let fixture = Fixture::new();
    let higher = Proof::new(&fixture, true, 1, Role::Prevote);
    let lower = Proof::new(&fixture, false, 1, Role::Precommit);
    let layout = Layout::new();
    higher.write(&layout, "higher");
    lower.write(&layout, "lower");
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    assert_eq!(
        result(
            &mut node,
            json!({"command":"submit_vote", "id":2, "vote_file":"lower.vote"})
        )["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], true);
    node.event("driver_blocked");
    let before = layout.images();
    for command in [
        higher.higher_command(3, "higher", false),
        higher.higher_command(4, "higher", true),
        lower.lower_command(5, "lower", false),
        lower.lower_command(6, "lower", true),
    ] {
        let outcome = result(&mut node, command);
        assert_eq!(outcome["event"], "current_finality_unresolved");
        assert_eq!(outcome["state"]["driver"]["height"], "1");
        assert_eq!(outcome["state"]["driver"]["round"], "0");
        assert_eq!(outcome["state"]["driver"]["finality_inbox"], 1);
        assert_eq!(layout.images(), before);
    }
    assert_eq!(
        result(
            &mut node,
            json!({"command":"submit_proposal", "id":7, "control_file":"lower.control", "payload_file":"lower.payload"})
        )["event"],
        "input_queued"
    );
    let finality = node.event("finality");
    assert_eq!(finality["state"]["driver"]["height"], "2");
    assert_eq!(
        finality["state"]["driver"]["head"],
        hex(lower.value.artifact_block().id().as_bytes())
    );
    node.shutdown();
}

#[test]
fn in_flight_publication_blocks_positive_proofs_but_not_pair_verification_or_halt() {
    let fixture = Fixture::new();
    let higher = Proof::new(&fixture, true, 1, Role::Prevote);
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::new(&fixture, false, 2, Role::Precommit);
    let layout = Layout::new();
    let peer_layout = Layout::new();
    higher.write(&layout, "higher");
    first.write(&layout, "first");
    second.write(&layout, "second");
    // The weight-1 signer uses the larger Noise ID. Its configured peer dials
    // the observed listener, then stops before any publication can be received.
    let config = fixture.config(&layout, 1, "create", Some("/ip4/127.0.0.1/tcp/1"), true);
    let mut node = Process::start(&layout, &config);
    node.ready();
    let address = node.event("listening")["address"]
        .as_str()
        .unwrap()
        .to_owned();
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
            json!({"command":"submit_proposal", "id":2, "control_file":"higher.control", "payload_file":"higher.payload"})
        )["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], true);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"submit_vote", "id":3, "vote_file":"higher.vote"})
        )["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], true);
    let transitioned = node.event("transitioned");
    assert_eq!(transitioned["phase"], "Precommit");
    assert_eq!(transitioned["round"], higher.round.to_string());
    assert_eq!(node.event("peer_attempted")["started"], true);
    let before = layout.images();
    let initial = result(&mut node, json!({"command":"status", "id":4}));
    assert_eq!(initial["publication"]["released_proposal"], true);
    assert_eq!(
        initial["publication"]["deliveries"][0]["state"],
        "in_flight"
    );
    for command in [
        higher.higher_command(5, "higher", false),
        higher.higher_command(6, "higher", true),
        first.lower_command(7, "first", false),
        first.lower_command(8, "first", true),
    ] {
        let outcome = result(&mut node, command);
        assert_eq!(outcome["event"], "proof_refused");
        assert_eq!(outcome["reason"], "busy");
        assert_eq!(outcome["state"], initial);
        assert_eq!(layout.images(), before);
    }
    layout.write("damaged.control", [0]);
    let mut damaged = Proof::files("second");
    damaged["control_file"] = json!("damaged.control");
    let rejected = result(
        &mut node,
        json!({"command":"halt_lower_conflict", "id":9, "evidence_round":0, "first":Proof::files("first"), "second":damaged}),
    );
    assert_eq!(rejected["event"], "lower_round_conflict_rejected");
    assert_eq!(rejected["state"], initial);
    assert_eq!(layout.images(), before);
    let halted = result(
        &mut node,
        json!({"command":"halt_lower_conflict", "id":10, "evidence_round":0, "first":Proof::files("first"), "second":Proof::files("second")}),
    );
    assert_eq!(halted["event"], "finality_stopped");
    assert_eq!(halted["kind"], "PreselectionPair");
    assert_eq!(halted["state"]["publication"], initial["publication"]);
    assert!(halted["state"]["driver"].is_null());
    let stopped = node.event("stopped");
    assert_eq!(stopped["locks_released"], true);
    assert_eq!(stopped["discarded"]["publication"], initial["publication"]);
    assert!(stopped["discarded"]["driver"].is_null());
    assert!(!node.exit().success());
    assert!(!node.observed.iter().any(|v| v["event"] == "peer_completed"));
    // Process::drop kills/reaps the stopped peer on assertion failure, too.
    peer.signal(rustix::process::Signal::CONT);
    peer.shutdown();
    let durable = layout.images();
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    assert_eq!(reopened.event("error")["code"], "startup_finality_stopped");
    assert!(!reopened.exit().success());
    assert_eq!(layout.images(), durable);
}
