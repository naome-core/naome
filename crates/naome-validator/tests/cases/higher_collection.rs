use super::*;
use naome_consensus::{
    ConsensusVoteRole as Role, ConsensusVoteTarget, UnverifiedConsensusVoteRouteV0,
};
use std::os::unix::process::ExitStatusExt;

fn result(node: &mut Process, command: serde_json::Value) -> serde_json::Value {
    let id = command["id"].clone();
    node.send(command);
    node.until(|value| value["event"] == "command_result" && value["id"] == id)["outcome"].clone()
}

#[test]
fn raw_higher_votes_checkpoint_through_process_runtime_and_survive_sigkill_without_publication() {
    let fixture = Fixture::new();
    for role in [Role::Prevote, Role::Precommit] {
        let proof = Proof::new(&fixture, true, 1, role);
        for nil in [false, true] {
            let vote = if nil {
                Proof::nil_vote(&fixture, proof.round, role)
            } else {
                proof.vote.clone()
            };
            let route = UnverifiedConsensusVoteRouteV0::inspect(&vote).unwrap();
            assert_eq!(route.target() == ConsensusVoteTarget::Nil, nil);
            let layout = Layout::new();
            layout.write("higher.vote", &vote);
            let config = fixture.config(&layout, 1, "create", None, false);
            let mut node = Process::start(&layout, &config);
            let initial = node.ready();
            node.event("timer_armed");
            let finality = layout.finality_images();
            assert_eq!(
                result(
                    &mut node,
                    json!({"command":"submit_vote", "id":1, "vote_file":"higher.vote"})
                )["event"],
                "input_queued"
            );
            assert_eq!(node.event("admission")["all_admitted"], true);
            let transitioned = node.event("transitioned");
            assert_eq!(transitioned["round"], proof.round.to_string());
            assert_eq!(
                transitioned["phase"],
                if role == Role::Prevote {
                    "Prevote"
                } else {
                    "Precommit"
                }
            );
            node.event("timer_armed");
            assert!(!node.observed.iter().any(|value| matches!(
                value["event"].as_str(),
                Some("publication_prepared" | "publication_complete" | "finality")
            )));
            assert_eq!(layout.finality_images(), finality);
            node.child.kill().unwrap();
            assert_eq!(node.exit().signal(), Some(9));
            let durable = layout.images();
            let mut reopened = Process::start(&layout, &config.replace("create", "open"));
            let state = reopened.ready();
            assert_eq!(state["driver"]["height"], initial["driver"]["height"]);
            assert_eq!(state["driver"]["head"], initial["driver"]["head"]);
            assert_eq!(state["driver"]["round"], proof.round.to_string());
            assert_eq!(
                state["driver"]["phase"],
                if role == Role::Prevote {
                    "Prevote"
                } else {
                    "Precommit"
                }
            );
            assert_eq!(state["driver"]["higher_inbox"], 0);
            reopened.event("timer_armed");
            reopened.shutdown();
            assert!(!reopened.observed.iter().any(|value| matches!(
                value["event"].as_str(),
                Some("publication_prepared" | "publication_complete" | "finality")
            )));
            assert_eq!(layout.images(), durable);
        }
    }
}

#[test]
fn process_shared_higher_capacity_requires_explicit_disposal_before_quorum_retry() {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, true, 1, Role::Prevote);
    let vote = Proof::nil_vote(&fixture, proof.round, Role::Precommit);
    let layout = Layout::new();
    proof.write(&layout, "proof");
    layout.write("nil.vote", vote);
    let config = fixture.config(&layout, 1, "create", None, false).replace(
        "[limits.higher]\nentries = \"8\"",
        "[limits.higher]\nentries = \"1\"",
    );
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    assert_eq!(
        result(
            &mut node,
            json!({"command":"submit_proposal", "id":1, "control_file":"proof.control", "payload_file":"proof.payload"})
        )["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], true);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"submit_vote", "id":2, "vote_file":"nil.vote"})
        )["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], false);
    node.event("driver_blocked");
    let discarded = result(
        &mut node,
        json!({"command":"discard_inbox", "id":3, "inbox":"higher"}),
    );
    assert_eq!(discarded["event"], "inbox_discarded");
    assert_eq!(discarded["state"]["driver"]["higher_inbox"], 0);
    assert_eq!(
        result(
            &mut node,
            json!({"command":"submit_vote", "id":4, "vote_file":"nil.vote"})
        )["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], true);
    let transition = node.event("transitioned");
    assert_eq!(transition["round"], proof.round.to_string());
    assert_eq!(transition["phase"], "Precommit");
    node.shutdown();
}
