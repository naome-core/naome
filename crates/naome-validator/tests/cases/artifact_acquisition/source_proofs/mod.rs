mod boundaries;
mod conflict;
mod custody;

use super::*;
use naome_consensus::ConsensusVoteRole as Role;
use provider::Provider;

fn command(proof: &Proof, prefix: &str, conflict: bool) -> Value {
    json!({"command": if conflict { "halt_candidate_conflict_votes" } else { "finalize_candidate_votes" },
        "id": u64::MAX, "target": hex(proof.value.artifact_block().id().as_bytes()),
        "evidence_round": proof.round, "control_file": format!("{prefix}.control"),
        "vote_files": [format!("{prefix}.vote")]})
}

fn write_proof(proof: &Proof, layout: &Layout, prefix: &str) {
    layout.write(&format!("{prefix}.control"), &proof.control);
    layout.write(&format!("{prefix}.vote"), &proof.vote);
    assert!(!layout.root.join(format!("{prefix}.payload")).exists());
}

fn initial_arm(node: &mut Process) {
    if !node.observed.iter().any(|v| v["event"] == "timer_armed") {
        node.event("timer_armed");
    }
}

fn load(node: &mut Process, sdk: &Provider<'_>, peer: naome_network::PeerId, proof: &Proof) {
    let block = proof.value.artifact_block();
    let target = hex(block.id().as_bytes());
    acquire(
        node,
        json!({"command":"acquire_ancestry", "id":10, "target":target, "peer_id":peer.to_string()}),
    );
    sdk.request("block", &target);
    acquire(
        node,
        json!({"command":"acquire_payloads", "id":11, "target":target, "peer_id":peer.to_string(), "max_blocks":1}),
    );
    sdk.request("payload", &hex(block.artifact_id().as_bytes()));
}

fn select(node: &mut Process, layout: &Layout, prefix: &[&Proof]) {
    for (index, proof) in prefix.iter().enumerate() {
        let name = format!("selected-{index}");
        proof.write(layout, &name);
        if proof.round > 0 {
            assert_eq!(
                result(node, proof.higher_command(20, &name, true))["event"],
                "transitioned"
            );
            node.event("timer_armed");
        }
        let selected = result(node, proof.current_command(21, &name, true));
        assert_eq!(selected["event"], "finality");
        assert_eq!(
            selected["state"]["driver"]["head"],
            hex(proof.value.artifact_block().id().as_bytes())
        );
        node.event("timer_armed");
    }
}

fn halt(outcome: &Value, first: &Proof, sibling: &Proof) {
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
    let stop = node.event("stopped");
    assert_eq!(stop["reason"], "command_fatal");
    assert_eq!(stop["locks_released"], true);
    assert!(!node.exit().success());
    stop
}

fn failed(outcome: &Value, conflict: bool) {
    assert_eq!(outcome["event"], "proof_failed");
    assert_eq!(
        outcome["operation"],
        if conflict {
            "candidate_finality_conflict"
        } else {
            "candidate_finality"
        }
    );
    assert_eq!(outcome["strict_restart_required"], true);
    assert!(outcome["state"]["driver"].is_null());
}

#[test]
fn candidate_proofs_acquire_missing_sources_then_finalize_current_lower_and_above_signer_rounds_and_reopen()
 {
    let fixture = Fixture::new();
    let current = Proof::new(&fixture, false, 1, Role::Precommit);
    let higher = Proof::after_prefix(&fixture, &[], 2, 1, Role::Precommit);
    for relative_round in ["current", "lower", "higher"] {
        let proof = if relative_round == "higher" {
            &higher
        } else {
            &current
        };
        let layout = Layout::new();
        write_proof(proof, &layout, "input");
        higher.write(&layout, "advance");
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
        if relative_round == "lower" {
            assert_eq!(
                result(&mut node, higher.higher_command(1, "advance", true))["event"],
                "transitioned"
            );
            node.event("timer_armed");
        }
        let initial = result(&mut node, json!({"command":"status", "id":2}));
        assert_eq!(
            initial["driver"]["round"],
            if relative_round == "lower" {
                higher.round.to_string()
            } else {
                "0".into()
            }
        );
        let authority = layout.images();
        if relative_round == "current" {
            result(
                &mut node,
                json!({"command":"submit_vote", "id":3, "vote_file":"input.vote"}),
            );
            assert_eq!(node.event("admission")["all_admitted"], true);
            assert_eq!(
                result(&mut node, command(proof, "input", false))["event"],
                "current_finality_unresolved"
            );
            assert_eq!(
                result(
                    &mut node,
                    json!({"command":"discard_inbox", "id":4, "inbox":"finality"})
                )["discarded_items"],
                1
            );
        }
        let provider_guard = PARENT_JOURNALS.read().unwrap();
        let sdk = plan.start(
            &provider_guard,
            fixture.definition,
            &address,
            vec![proof.value.artifact_block()],
            vec![proof.payload.clone()],
            None,
        );
        connected(&mut node, peer);
        let target = hex(proof.value.artifact_block().id().as_bytes());
        for payload_missing in [false, true] {
            let sources = source_images(&layout);
            let rejection = result(&mut node, command(proof, "input", false));
            assert_eq!(rejection["event"], "candidate_finality_rejected");
            assert_eq!(rejection["state"], initial);
            assert_eq!(layout.images(), authority);
            assert_eq!(source_images(&layout), sources);
            if !payload_missing {
                acquire(
                    &mut node,
                    json!({"command":"acquire_ancestry", "id":5, "target":target, "peer_id":peer.to_string()}),
                );
                sdk.request("block", &target);
            }
        }
        acquire(
            &mut node,
            json!({"command":"acquire_payloads", "id":6, "target":target, "peer_id":peer.to_string(), "max_blocks":1}),
        );
        sdk.request(
            "payload",
            &hex(proof.value.artifact_block().artifact_id().as_bytes()),
        );
        let sources = source_images(&layout);
        for mode in ["control", "duplicate", "signature", "round"] {
            let mut input = command(proof, "input", false);
            match mode {
                "control" => {
                    layout.write("bad.control", [0]);
                    input["control_file"] = json!("bad.control");
                }
                "duplicate" => input["vote_files"] = json!(["input.vote", "input.vote"]),
                "signature" => {
                    let mut vote = proof.vote.clone();
                    *vote.last_mut().unwrap() ^= 1;
                    layout.write("bad.vote", vote);
                    input["vote_files"] = json!(["bad.vote"]);
                }
                "round" => input["evidence_round"] = json!(u64::MAX),
                _ => unreachable!(),
            }
            let rejected = result(&mut node, input);
            assert_eq!(
                rejected["event"], "candidate_finality_rejected",
                "{mode}: {rejected}"
            );
            assert_eq!(rejected["state"], initial);
            assert_eq!(layout.images(), authority);
            assert_eq!(source_images(&layout), sources);
        }
        let selected = result(&mut node, command(proof, "input", false));
        assert_eq!(selected["event"], "finality");
        for (field, expected) in [("height", "2"), ("round", "0"), ("phase", "Proposal")] {
            assert_eq!(selected["state"]["driver"][field], expected);
        }
        assert_eq!(selected["state"]["driver"]["head"], target);
        assert_eq!(node.event("timer_armed")["phase"], "Proposal");
        assert_ne!(layout.images(), authority);
        assert_eq!(source_images(&layout), sources);
        node.shutdown();
        sdk.stop();
        drop(provider_guard);
        let durable = layout.images();
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
        let ready = reopened.ready();
        for field in ["height", "round", "phase", "head"] {
            assert_eq!(ready["driver"][field], selected["state"]["driver"][field]);
        }
        reopened.shutdown();
        assert_eq!(layout.images(), durable);
        assert_eq!(source_images(&layout), sources);
    }
}
