use super::*;
use naome_consensus::ConsensusVoteRole as Role;
use serde_json::Value;

const CLASSES: [(&str, &str); 4] = [
    ("higher", "higher_inbox"),
    ("current", "current_inbox"),
    ("finality", "finality_inbox"),
    ("nil_precommit", "nil_precommit_inbox"),
];

fn result(node: &mut Process, command: Value) -> Value {
    let id = command["id"].clone();
    node.send(command);
    node.until(|value| value["event"] == "command_result" && value["id"] == id)["outcome"].clone()
}

fn status(node: &mut Process) -> Value {
    result(node, json!({"command":"status", "id":0}))
}

fn discard(node: &mut Process, inbox: &str, expected: usize, previous: &Value) -> Value {
    let outcome = result(
        node,
        json!({"command":"discard_inbox", "id":u64::MAX, "inbox":inbox}),
    );
    assert_eq!(outcome["event"], "inbox_discarded");
    assert_eq!(outcome["inbox"], inbox);
    assert_eq!(outcome["discarded_items"], expected);
    let mut after = previous.clone();
    let field = CLASSES.iter().find(|(class, _)| *class == inbox).unwrap().1;
    after["driver"][field] = json!(0);
    assert_eq!(outcome["state"], after);
    after
}

#[test]
fn inbox_disposal_requires_an_explicit_exact_scalar_class() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let before = layout.images();
    let initial = status(&mut node);
    for class in [
        json!(0),
        json!(true),
        Value::Null,
        json!({"higher":null}),
        json!(["higher"]),
        json!("Higher"),
        json!("all"),
        json!(""),
    ] {
        node.send(json!({"command":"discard_inbox", "id":1, "inbox":class}));
        assert_eq!(node.event("command_rejected")["code"], "command_schema");
    }
    for command in [
        "{\"command\":\"discard_inbox\",\"id\":1}",
        "{\"command\":\"discard_inbox\",\"id\":1,\"inbox\":\"higher\",\"inbox\":\"current\"}",
        "{\"command\":\"discard_inbox\",\"id\":1,\"inbox\":\"higher\",\"extra\":true}",
        "[\"discard_inbox\",1,\"higher\"]",
    ] {
        node.write(format!("{command}\n").as_bytes());
        assert_eq!(node.event("command_rejected")["code"], "command_schema");
    }
    for (class, _) in CLASSES {
        assert_eq!(discard(&mut node, class, 0, &initial), initial);
    }
    assert_eq!(status(&mut node), initial);
    assert_eq!(layout.images(), before);
    node.shutdown();
}

#[test]
fn explicitly_selected_vote_classes_discard_without_touching_other_custody_or_authority() {
    let fixture = Fixture::new();
    let higher = Proof::new(&fixture, true, 1, Role::Prevote);
    let current = Proof::new(&fixture, false, 1, Role::Prevote);
    let finality = Proof::new(&fixture, false, 1, Role::Precommit);
    let layout = Layout::new();
    for (class, proof) in [
        ("higher", &higher),
        ("current", &current),
        ("finality", &finality),
    ] {
        proof.write(&layout, class);
    }
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    for class in ["current", "higher", "finality"] {
        assert_eq!(
            result(
                &mut node,
                json!({"command":"submit_vote", "id":1, "vote_file":format!("{class}.vote")})
            )["event"],
            "input_queued"
        );
        assert_eq!(node.event("admission")["all_admitted"], true);
    }
    let before = layout.images();
    let mut state = status(&mut node);
    assert_eq!(state["driver"]["higher_inbox"], 1);
    assert_eq!(state["driver"]["current_inbox"], 1);
    assert_eq!(state["driver"]["finality_inbox"], 1);
    for (class, _) in CLASSES {
        state = discard(
            &mut node,
            class,
            usize::from(class != "nil_precommit"),
            &state,
        );
        assert_eq!(status(&mut node), state);
        assert_eq!(discard(&mut node, class, 0, &state), state);
        assert_eq!(layout.images(), before);
    }
    node.shutdown();
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    let ready = reopened.ready();
    assert_eq!(ready["driver"]["height"], "1");
    for (_, field) in CLASSES {
        assert_eq!(ready["driver"][field], 0);
    }
    reopened.shutdown();
    assert_eq!(layout.images(), before);
}

#[test]
fn nil_round_progress_keeps_both_charged_classes_until_individual_disposal() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture
        .config(&layout, 0, "create", None, false)
        .replace("base_millis = \"60000\"", "base_millis = \"50\"")
        .replace(
            "round_increment_millis = \"1\"",
            "round_increment_millis = \"60000\"",
        );
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.until(|event| {
        event["event"] == "transitioned" && event["phase"] == "Proposal" && event["round"] == "1"
    });
    node.event("timer_armed");
    let before = layout.images();
    let initial = status(&mut node);
    assert_eq!(initial["driver"]["current_inbox"], 1);
    assert_eq!(initial["driver"]["nil_precommit_inbox"], 1);
    assert_eq!(initial["driver"]["height"], "1");
    let cleared_nil = discard(&mut node, "nil_precommit", 1, &initial);
    assert_eq!(status(&mut node), cleared_nil);
    assert_eq!(
        discard(&mut node, "nil_precommit", 0, &cleared_nil),
        cleared_nil
    );
    let cleared_both = discard(&mut node, "current", 1, &cleared_nil);
    assert_eq!(status(&mut node), cleared_both);
    assert_eq!(layout.images(), before);
    node.shutdown();
    let open = config
        .replace("create", "open")
        .replace("base_millis = \"50\"", "base_millis = \"60000\"");
    let mut reopened = Process::start(&layout, &open);
    let ready = reopened.ready();
    for (_, field) in CLASSES {
        assert_eq!(ready["driver"][field], 0);
    }
    reopened.shutdown();
    assert_eq!(layout.images(), before);
}

#[test]
fn stale_current_and_finality_saturation_require_explicit_disposal_and_replay_before_next_height() {
    let mut fixture = Fixture::new();
    fixture.entries[0] = naome_consensus::ActiveAgreementEntry::new(
        fixture.entries[0].consensus_key(),
        naome_consensus::AgreementWeight::new(4),
    );
    let layout = Layout::new();
    let config = fixture
        .config(&layout, 0, "create", None, false)
        .replace(
            "[limits.current]\nentries = \"8\"",
            "[limits.current]\nentries = \"2\"",
        )
        .replace(
            "[limits.finality]\nentries = \"8\"",
            "[limits.finality]\nentries = \"2\"",
        );
    let mut node = Process::start(&layout, &config);
    node.ready();
    let mut selected = naome_chain::ArtifactChainState::new(fixture.definition);
    for axiom in [1, 2] {
        node.event("timer_armed");
        let payload = naome_proof::ArtifactPayload::Proof(
            naome_proof::ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, axiom])
                .unwrap(),
        )
        .to_canonical_bytes();
        let artifact = naome_chain::ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = selected.prepare_block(artifact).unwrap();
        layout.write("next.block", block.to_canonical_bytes());
        layout.write("next.payload", &payload);
        let author = json!({"command":"author_fresh", "id":1, "block_file":"next.block", "payload_file":"next.payload"});
        assert_eq!(
            result(&mut node, author.clone())["event"],
            "proposal_authored"
        );
        if axiom == 2 {
            let admission = node.event("admission");
            assert_eq!(admission["all_admitted"], false);
            assert_eq!(admission["routes"].as_array().unwrap().len(), 2);
            assert!(
                admission["routes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|route| route["admitted"] == false)
            );
            node.event("publication_complete");
            node.event("driver_blocked");
            let before = layout.images();
            let initial = status(&mut node);
            assert_eq!(initial["driver"]["height"], "2");
            assert_eq!(initial["driver"]["phase"], "Proposal");
            assert_eq!(initial["driver"]["current_inbox"], 2);
            assert_eq!(initial["driver"]["finality_inbox"], 2);
            let current = discard(&mut node, "current", 2, &initial);
            let both = discard(&mut node, "finality", 2, &current);
            assert_eq!(status(&mut node), both);
            assert_eq!(discard(&mut node, "finality", 0, &both), both);
            assert_eq!(layout.images(), before);
            // A new explicit command replays the same anchored proposal. The
            // discard neither retained its bytes nor re-admitted them itself.
            assert_eq!(result(&mut node, author)["event"], "proposal_authored");
        }
        let finalized = node.event("finality")["state"].clone();
        assert_eq!(
            finalized["driver"]["height"],
            (u64::from(axiom) + 1).to_string()
        );
        assert_eq!(finalized["driver"]["head"], hex(block.id().as_bytes()));
        selected.apply_block(&block, payload).unwrap();
    }
    node.shutdown();
    let durable = layout.images();
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    let ready = reopened.ready();
    assert_eq!(ready["driver"]["height"], "3");
    assert_eq!(
        ready["driver"]["head"],
        hex(selected.head_block_id().as_bytes())
    );
    reopened.shutdown();
    assert_eq!(layout.images(), durable);
}

#[test]
fn only_higher_disposal_reopens_rejected_due_work_without_rearming() {
    let fixture = Fixture::new();
    let higher = Proof::new(&fixture, true, 1, Role::Prevote);
    let layout = Layout::new();
    higher.write(&layout, "higher");
    let config = fixture
        .config(&layout, 1, "create", None, false)
        .replace(
            "[limits.higher]\nentries = \"8\"",
            "[limits.higher]\nentries = \"1\"",
        )
        .replace(
            "[timeouts.proposal]\nbase_millis = \"60000\"",
            "[timeouts.proposal]\nbase_millis = \"2000\"",
        );
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    assert_eq!(
        result(
            &mut node,
            json!({"command":"submit_proposal", "id":1,
        "control_file":"higher.control", "payload_file":"higher.payload"})
        )["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], true);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"submit_vote", "id":2,
        "vote_file":"higher.vote"})
        )["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], false);
    node.event("driver_blocked");
    assert_eq!(node.event("timer_due")["admitted"], false);
    let before = layout.images();
    let initial = status(&mut node);
    assert_eq!(initial["driver"]["height"], "1");
    assert_eq!(initial["driver"]["round"], "0");
    assert_eq!(initial["driver"]["phase"], "Proposal");
    assert_eq!(initial["driver"]["higher_inbox"], 1);
    assert_eq!(initial["driver"]["timeout_due"], false);
    assert_eq!(initial["timer"], true);
    for class in ["current", "finality", "nil_precommit"] {
        assert_eq!(discard(&mut node, class, 0, &initial), initial);
        node.event("driver_blocked");
        assert_eq!(status(&mut node), initial);
        assert_eq!(layout.images(), before);
    }
    assert!(
        !node
            .observed
            .iter()
            .any(|v| v["event"] == "timer_due" && v["admitted"] == true)
    );
    discard(&mut node, "higher", 1, &initial);
    let start = node.observed.len();
    assert_eq!(node.event("timer_due")["admitted"], true);
    assert!(
        !node.observed[start..]
            .iter()
            .any(|v| v["event"] == "timer_armed")
    );
    let transitioned = node.event("transitioned");
    assert_eq!(transitioned["height"], "1");
    assert_eq!(transitioned["round"], "0");
    assert_eq!(transitioned["phase"], "Prevote");
    node.event("publication_complete");
    let progressed = status(&mut node);
    assert_eq!(progressed["timer"], true);
    assert_eq!(progressed["driver"]["higher_inbox"], 0);
    assert_eq!(progressed["driver"]["phase"], "Prevote");
    node.shutdown();
    let durable = layout.images();
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    let ready = reopened.ready();
    assert_eq!(ready["driver"]["height"], "1");
    assert_eq!(ready["driver"]["higher_inbox"], 0);
    reopened.shutdown();
    assert_eq!(layout.images(), durable);
}

#[test]
fn disposal_preserves_in_flight_released_publication_and_completion_does_not_reinsert() {
    let fixture = Fixture::new();
    let current = Proof::new(&fixture, false, 1, Role::Prevote);
    let higher = Proof::new(&fixture, true, 1, Role::Prevote);
    let layout = Layout::new();
    let peer_layout = Layout::new();
    current.write(&layout, "current");
    higher.write(&layout, "higher");
    let config = fixture.config(&layout, 1, "create", Some("/ip4/127.0.0.1/tcp/1"), true);
    let mut node = Process::start(&layout, &config);
    node.ready();
    let address = node.event("listening")["address"]
        .as_str()
        .unwrap()
        .to_owned();
    // Retain the old-position current proposal/local prevote and finality
    // proposal before a higher-round publication takes over the runtime.
    assert_eq!(
        result(
            &mut node,
            json!({"command":"submit_proposal", "id":1,
        "control_file":"current.control", "payload_file":"current.payload"})
        )["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], true);
    node.event("publication_complete");
    assert_eq!(status(&mut node)["timer"], true);
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
            json!({"command":"submit_proposal", "id":2,
        "control_file":"higher.control", "payload_file":"higher.payload"})
        )["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], true);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"submit_vote", "id":3,
        "vote_file":"higher.vote"})
        )["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], true);
    let transitioned = node.event("transitioned");
    assert_eq!(transitioned["phase"], "Precommit");
    assert_eq!(transitioned["round"], higher.round.to_string());
    assert_eq!(node.event("peer_attempted")["started"], true);
    let before = layout.images();
    let initial = status(&mut node);
    assert_eq!(initial["publication"]["released_proposal"], true);
    assert_eq!(initial["publication"]["local_admission_attempted"], true);
    assert_eq!(
        initial["publication"]["deliveries"][0]["state"],
        "in_flight"
    );
    assert_eq!(initial["driver"]["current_inbox"], 2);
    assert_eq!(initial["driver"]["finality_inbox"], 2);
    let mut state = initial.clone();
    for class in ["current", "finality", "higher", "nil_precommit"] {
        let field = CLASSES.iter().find(|(name, _)| *name == class).unwrap().1;
        let count = state["driver"][field].as_u64().unwrap() as usize;
        state = discard(&mut node, class, count, &state);
        assert_eq!(status(&mut node), state);
        assert_eq!(discard(&mut node, class, 0, &state), state);
        assert_eq!(layout.images(), before);
    }
    let refused = result(&mut node, higher.higher_command(4, "higher", false));
    assert_eq!(refused["event"], "proof_refused");
    assert_eq!(refused["reason"], "busy");
    assert_eq!(refused["state"], state);
    assert!(!node.observed.iter().any(|v| v["event"] == "peer_completed"));
    peer.signal(rustix::process::Signal::CONT);
    let receipt = node.event("peer_completed");
    assert_eq!(receipt["received"], true);
    assert_eq!(receipt["peer"], fixture.peers[0].to_string());
    let complete = node.event("publication_complete");
    assert_eq!(complete["disposed"]["released_proposal"], true);
    assert_eq!(complete["disposed"]["local_admission_attempted"], true);
    assert_eq!(complete["disposed"]["deliveries"][0]["state"], "received");
    let after = status(&mut node);
    assert_eq!(after["timer"], true);
    assert!(after["publication"].is_null());
    assert_eq!(after["driver"], state["driver"]);
    for (_, field) in CLASSES {
        assert_eq!(after["driver"][field], 0);
    }
    assert_eq!(layout.images(), before);
    node.shutdown();
    peer.shutdown();
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    let ready = reopened.ready();
    assert_eq!(ready["driver"]["height"], "1");
    assert_eq!(ready["driver"]["round"], higher.round.to_string());
    assert_eq!(ready["driver"]["head"], state["driver"]["head"]);
    for (_, field) in CLASSES {
        assert_eq!(ready["driver"][field], 0);
    }
    reopened.shutdown();
    assert_eq!(layout.images(), before);
}
