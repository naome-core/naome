use super::{explicit_proofs::result, *};
use naome_consensus::ConsensusVoteRole as Role;
use serde_json::Value;

fn command(first: &str, second: &str) -> Value {
    json!({"command":"halt_current_conflict", "id":u64::MAX,
        "first":Proof::files(first), "second":Proof::files(second)})
}

fn assert_halt(outcome: &Value, first: &Proof, second: &Proof) {
    assert_eq!(outcome["event"], "finality_stopped");
    assert_eq!(outcome["kind"], "PreselectionPair");
    assert_eq!(outcome["height"], "1");
    let ordered = if first.value.proposal_signing_root() < second.value.proposal_signing_root() {
        [first, second]
    } else {
        [second, first]
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
    assert!(outcome["state"]["driver"].is_null());
}

#[test]
fn current_pair_schema_and_both_counts_precede_any_source_read() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let initial = result(&mut node, json!({"command":"status", "id":1}));
    let before = layout.images();
    let template = command("missing", "missing");
    let mut cases = Vec::new();
    for field in ["evidence_round", "root", "parent", "winner"] {
        let mut changed = template.clone();
        changed[field] = json!(0);
        cases.push((changed, "command_schema"));
    }
    for field in ["first", "second"] {
        for proof in [
            json!(["missing", "missing", ["missing"]]),
            json!(null),
            json!(0),
        ] {
            let mut changed = template.clone();
            changed[field] = proof;
            cases.push((changed, "command_schema"));
        }
        let mut changed = template.clone();
        changed[field]["extra"] = json!(0);
        cases.push((changed, "command_schema"));
        for votes in [json!([]), json!(vec!["missing"; 257])] {
            let mut changed = template.clone();
            changed[field]["vote_files"] = votes;
            cases.push((changed, "proof_vote_count"));
        }
    }
    for (command, code) in cases {
        node.send(command);
        assert_eq!(node.event("command_rejected")["code"], code);
        assert_eq!(layout.images(), before);
    }
    node.write(b"{\"command\":\"halt_current_conflict\",\"id\":1,\"first\":{\"control_file\":\"missing\",\"control_file\":\"missing\",\"payload_file\":\"missing\",\"vote_files\":[\"missing\"]},\"second\":{\"control_file\":\"missing\",\"payload_file\":\"missing\",\"vote_files\":[\"missing\"]}}\n");
    assert_eq!(node.event("command_rejected")["code"], "command_schema");
    node.send(template);
    assert_eq!(node.event("command_rejected")["code"], "file_open");
    assert_eq!(
        result(&mut node, json!({"command":"status", "id":2})),
        initial
    );
    assert_eq!(layout.images(), before);
    node.shutdown();
}

#[test]
fn complete_current_pair_bypasses_saturated_inbox_without_selecting_its_first_value() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::new(&fixture, false, 2, Role::Precommit);
    let higher = Proof::new(&fixture, true, 2, Role::Precommit);
    for reverse in [false, true] {
        let layout = Layout::new();
        first.write(&layout, "first");
        second.write(&layout, "second");
        higher.write(&layout, "higher");
        layout.write("damaged.control", [0]);
        let config = fixture.config(&layout, 1, "create", None, false).replace(
            "[limits.finality]\nentries = \"8\"",
            "[limits.finality]\nentries = \"1\"",
        );
        let mut node = Process::start(&layout, &config);
        let ready = node.ready();
        node.event("timer_armed");
        for (prefix, admitted) in [("first", true), ("second", false)] {
            assert_eq!(
                result(
                    &mut node,
                    json!({"command":"submit_vote", "id":1,
                "vote_file":format!("{prefix}.vote")})
                )["event"],
                "input_queued"
            );
            assert_eq!(node.event("admission")["all_admitted"], admitted);
            if admitted {
                node.event("driver_blocked");
            }
        }
        let initial = result(&mut node, json!({"command":"status", "id":2}));
        assert_eq!(initial["driver"]["height"], "1");
        assert_eq!(initial["driver"]["round"], "0");
        assert_eq!(initial["driver"]["head"], ready["driver"]["head"]);
        assert_eq!(initial["driver"]["finality_inbox"], 1);
        let before = layout.images();
        for side in ["first", "second"] {
            let mut damaged = command("first", "second");
            damaged[side]["control_file"] = json!("damaged.control");
            let rejected = result(&mut node, damaged);
            assert_eq!(rejected["event"], "current_round_conflict_rejected");
            assert_eq!(rejected["state"], initial);
            assert_eq!(layout.images(), before);
        }
        let rejected = result(&mut node, command("first", "higher"));
        assert_eq!(rejected["event"], "current_round_conflict_rejected");
        assert_eq!(rejected["state"], initial);
        assert_eq!(layout.images(), before);
        let pair = if reverse {
            command("second", "first")
        } else {
            command("first", "second")
        };
        let outcome = result(&mut node, pair);
        assert_halt(&outcome, &first, &second);
        assert_ne!(layout.images(), before);
        assert!(!node.observed.iter().any(|v| v["event"] == "finality"));
        assert!(
            node.observed
                .iter()
                .any(|v| v["event"] == "command_result" && v["id"].as_u64() == Some(u64::MAX))
        );
        let stopped = node.event("stopped");
        assert_eq!(stopped["reason"], "command_fatal");
        assert_eq!(stopped["locks_released"], true);
        assert!(!node.exit().success());
        let durable = layout.images();
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
        assert_eq!(reopened.event("error")["code"], "startup_finality_stopped");
        assert!(!reopened.exit().success());
        assert_eq!(layout.images(), durable);
    }
}

#[test]
fn identical_current_pair_consumes_driver_without_writes_and_strictly_reopens_healthy() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    let layout = Layout::new();
    proof.write(&layout, "first");
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    let initial = node.ready();
    node.event("timer_armed");
    let before = layout.images();
    let outcome = result(&mut node, command("first", "first"));
    assert_eq!(outcome["event"], "proof_failed");
    assert_eq!(outcome["operation"], "current_round_conflict");
    assert_eq!(outcome["strict_restart_required"], true);
    assert!(outcome["state"]["driver"].is_null());
    assert_eq!(layout.images(), before);
    let stopped = node.event("stopped");
    assert_eq!(stopped["reason"], "command_fatal");
    assert_eq!(stopped["locks_released"], true);
    assert!(!node.exit().success());
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    let state = reopened.ready();
    for field in ["height", "round", "phase", "head"] {
        assert_eq!(state["driver"][field], initial["driver"][field]);
    }
    reopened.shutdown();
    assert_eq!(layout.images(), before);
}

#[test]
fn in_flight_current_publication_preserves_custody_through_pair_rejection_and_halt() {
    let fixture = Fixture::new();
    let higher = Proof::new(&fixture, true, 1, Role::Prevote);
    let first = Proof::new(&fixture, true, 1, Role::Precommit);
    let second = Proof::new(&fixture, true, 2, Role::Precommit);
    assert_eq!(first.round, higher.round);
    assert_eq!(second.round, higher.round);
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
        json!({"command":"halt_current_conflict", "id":9, "first":Proof::files("first"), "second":damaged}),
    );
    assert_eq!(rejected["event"], "current_round_conflict_rejected");
    assert_eq!(rejected["state"], initial);
    assert_eq!(layout.images(), before);
    let halted = result(
        &mut node,
        json!({"command":"halt_current_conflict", "id":10, "first":Proof::files("first"), "second":Proof::files("second")}),
    );
    assert_halt(&halted, &first, &second);
    assert_eq!(halted["state"]["publication"], initial["publication"]);
    assert!(halted["state"]["driver"].is_null());
    let stopped = node.event("stopped");
    assert_eq!(stopped["reason"], "command_fatal");
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
