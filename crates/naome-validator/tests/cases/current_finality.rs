use super::{explicit_proofs::result, *};
use naome_consensus::ConsensusVoteRole as Role;
use serde_json::Value;

fn assert_child(state: &Value, proof: &Proof) {
    assert_eq!(
        state["driver"]["head"],
        hex(proof.value.artifact_block().id().as_bytes())
    );
    assert_eq!(state["driver"]["height"], "2");
    assert_eq!(state["driver"]["round"], "0");
    assert_eq!(state["driver"]["phase"], "Proposal");
}

#[test]
fn both_current_forms_finalize_with_capacity_one_and_strictly_reopen_exact_child() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::new(&fixture, false, 2, Role::Precommit);
    for batch in [false, true] {
        for retained in [false, true] {
            let layout = Layout::new();
            proof.write(&layout, "proof");
            second.write(&layout, "second");
            let config = fixture.config(&layout, 1, "create", None, false).replace(
                "[limits.finality]\nentries = \"8\"",
                "[limits.finality]\nentries = \"1\"",
            );
            let mut node = Process::start(&layout, &config);
            node.ready();
            node.event("timer_armed");
            let before = layout.images();
            if retained {
                assert_eq!(
                    result(
                        &mut node,
                        json!({"command":"submit_vote", "id":1, "vote_file":"proof.vote"})
                    )["event"],
                    "input_queued"
                );
                assert_eq!(node.event("admission")["all_admitted"], true);
                node.event("driver_blocked");
                let blocked = result(&mut node, proof.current_command(2, "proof", batch));
                assert_eq!(blocked["event"], "current_finality_unresolved");
                assert_eq!(blocked["state"]["driver"]["finality_inbox"], 1);
                assert_eq!(layout.images(), before);
                // Capacity one cannot retain a proposal plus its quorum. A second
                // raw precommit latches saturation without introducing voting work.
                assert_eq!(
                    result(
                        &mut node,
                        json!({"command":"submit_vote", "id":3, "vote_file":"second.vote"})
                    )["event"],
                    "input_queued"
                );
                assert_eq!(node.event("admission")["all_admitted"], false);
            }
            let outcome = result(&mut node, proof.current_command(4, "proof", batch));
            assert_eq!(outcome["event"], "finality");
            assert_child(&outcome["state"], &proof);
            assert_eq!(
                outcome["state"]["driver"]["finality_inbox"],
                usize::from(retained)
            );
            assert_ne!(layout.images(), before);
            node.event("timer_armed");
            node.shutdown();
            let durable = layout.images();
            let mut reopened = Process::start(&layout, &config.replace("create", "open"));
            let state = reopened.ready();
            assert_child(&state, &proof);
            assert_eq!(state["driver"]["finality_inbox"], 0);
            reopened.shutdown();
            assert_eq!(layout.images(), durable);
        }
    }
}

#[test]
fn both_current_forms_use_the_owned_checkpoint_round_and_allow_rejected_proof_retry() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, true, 1, Role::Precommit);
    let old = Proof::new(&fixture, false, 1, Role::Precommit);
    for batch in [false, true] {
        let layout = Layout::new();
        proof.write(&layout, "proof");
        old.write(&layout, "old");
        layout.write("damaged", [0]);
        let config = fixture.config(&layout, 1, "create", None, false);
        let mut node = Process::start(&layout, &config);
        node.ready();
        node.event("timer_armed");
        let advanced = result(&mut node, proof.higher_command(1, "proof", batch));
        assert_eq!(advanced["event"], "transitioned");
        assert_eq!(
            advanced["state"]["driver"]["round"],
            proof.round.to_string()
        );
        assert_eq!(advanced["state"]["driver"]["phase"], "Precommit");
        node.event("timer_armed");
        let initial = result(&mut node, json!({"command":"status", "id":2}));
        let before = layout.images();
        for field in ["old", "control_file", "payload_file", "proof"] {
            let mut command = proof.current_command(3, "proof", batch);
            if field == "old" {
                command = old.current_command(3, "old", batch);
            } else if batch {
                if field == "proof" {
                    command["proof"]["vote_files"] = json!(["old.vote"]);
                } else {
                    command["proof"][field] = json!("damaged");
                }
            } else if field == "proof" {
                command["certificate_file"] = json!("old.certificate");
            } else {
                command[field] = json!("damaged");
            }
            let rejected = result(&mut node, command);
            assert_eq!(rejected["event"], "current_round_finality_rejected");
            assert_eq!(rejected["state"], initial);
            assert_eq!(layout.images(), before);
        }
        let outcome = result(&mut node, proof.current_command(4, "proof", batch));
        assert_eq!(outcome["event"], "finality");
        assert_child(&outcome["state"], &proof);
        node.shutdown();
        let durable = layout.images();
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
        assert_child(&reopened.ready(), &proof);
        reopened.shutdown();
        assert_eq!(layout.images(), durable);
    }
}

#[test]
fn current_proof_schema_and_file_bounds_precede_single_runtime_invocation() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    for batch in [false, true] {
        let layout = Layout::new();
        proof.write(&layout, "proof");
        layout.write(
            "large.certificate",
            vec![0; naome_consensus::VerifiedPrecommitCertificateV0::MAX_BYTE_LENGTH + 1],
        );
        layout.write(
            "short.vote",
            vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES - 1],
        );
        layout.write(
            "large.vote",
            vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES + 1],
        );
        let config = fixture.config(&layout, 1, "create", None, false);
        let mut node = Process::start(&layout, &config);
        node.ready();
        node.event("timer_armed");
        let initial = result(&mut node, json!({"command":"status", "id":1}));
        let before = layout.images();
        let template = proof.current_command(2, "missing", batch);
        let mut cases = vec![];
        for field in ["evidence_round", "root", "parent", "winner"] {
            let mut command = template.clone();
            command[field] = json!(0);
            cases.push((command, "command_schema"));
        }
        if batch {
            for value in [json!(["missing", "missing", ["missing"]]), json!(null)] {
                let mut command = template.clone();
                command["proof"] = value;
                cases.push((command, "command_schema"));
            }
            let mut command = template.clone();
            command["proof"]["evidence_round"] = json!(0);
            cases.push((command, "command_schema"));
            for value in [json!([]), json!(vec!["missing"; 257])] {
                let mut command = template.clone();
                command["proof"]["vote_files"] = value;
                cases.push((command, "proof_vote_count"));
            }
            for (path, code) in [
                ("short.vote", "proof_vote_length"),
                ("large.vote", "file_too_large"),
            ] {
                let mut command = proof.current_command(2, "proof", batch);
                command["proof"]["vote_files"] = json!([path]);
                cases.push((command, code));
            }
        } else {
            let mut command = proof.current_command(2, "proof", batch);
            command["certificate_file"] = json!("large.certificate");
            cases.push((command, "file_too_large"));
        }
        for (command, code) in cases {
            node.send(command);
            assert_eq!(node.event("command_rejected")["code"], code);
            assert_eq!(layout.images(), before);
        }
        let duplicate = if batch {
            r#"{"command":"finalize_current_votes","id":2,"proof":{"control_file":"missing","control_file":"missing","payload_file":"missing","vote_files":["missing"]}}"#
        } else {
            r#"{"command":"finalize_current_quorum","id":2,"control_file":"missing","payload_file":"missing","certificate_file":"missing","certificate_file":"missing"}"#
        };
        node.write(format!("{duplicate}\n").as_bytes());
        assert_eq!(node.event("command_rejected")["code"], "command_schema");
        node.send(template);
        assert_eq!(node.event("command_rejected")["code"], "file_open");
        assert_eq!(
            result(&mut node, json!({"command":"status", "id":3})),
            initial
        );
        assert_eq!(layout.images(), before);
        let outcome = result(&mut node, proof.current_command(4, "proof", batch));
        assert_eq!(outcome["event"], "finality");
        assert_child(&outcome["state"], &proof);
        node.shutdown();
    }
}

#[test]
fn current_finality_anchor_failures_stop_process_release_locks_and_refuse_strict_reopen() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, false, 1, Role::Precommit);
    for batch in [false, true] {
        for (directory, offset) in [("finality-anchor", 149), ("vote-anchor", 184)] {
            let layout = Layout::new();
            proof.write(&layout, "proof");
            let config = fixture.config(&layout, 1, "create", None, false);
            let mut node = Process::start(&layout, &config);
            node.ready();
            node.event("timer_armed");
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
            fs::write(&collision, b"process finality anchor collision").unwrap();
            let outcome = result(&mut node, proof.current_command(1, "proof", batch));
            assert_eq!(outcome["event"], "driver_unavailable");
            assert!(outcome["state"]["driver"].is_null());
            let stopped = node.event("stopped");
            assert_eq!(stopped["reason"], "command_fatal");
            assert_eq!(stopped["locks_released"], true);
            assert!(!node.exit().success());
            fs::remove_file(collision).unwrap();
            let durable = layout.images();
            let mut reopened = Process::start(&layout, &config.replace("create", "open"));
            assert_eq!(reopened.event("error")["code"], "startup_open");
            assert!(!reopened.exit().success());
            assert_eq!(layout.images(), durable);
        }
    }
}
