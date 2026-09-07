use super::*;
use naome_consensus::ConsensusVoteRole as Role;
use std::os::unix::process::ExitStatusExt;

pub(super) fn enable(layout: &Layout, config: &str) -> String {
    fs::create_dir(layout.root.join("evidence")).unwrap();
    format!("{config}\n[evidence]\ndirectory = \"evidence\"\nmode = \"create\"\n")
}
fn result(node: &mut Process, command: serde_json::Value) -> serde_json::Value {
    let id = command["id"].clone();
    node.send(command);
    node.until(|value| value["event"] == "command_result" && value["id"] == id)["outcome"].clone()
}

#[test]
fn durable_evidence_sigkill_reopens_partial_higher_proposal_and_finishes_with_only_the_missing_vote()
 {
    let fixture = Fixture::new();
    let proof = Proof::new(&fixture, true, 1, Role::Precommit);
    for dispose in [false, true] {
        let layout = Layout::new();
        proof.write(&layout, "proof");
        let config = enable(&layout, &fixture.config(&layout, 1, "create", None, false));
        let mut node = Process::start(&layout, &config);
        assert_eq!(node.ready()["durable_evidence"], true);
        node.event("timer_armed");
        assert_eq!(
            result(
                &mut node,
                json!({"command":"submit_proposal", "id":1,
            "control_file":"proof.control", "payload_file":"proof.payload"})
            )["event"],
            "input_queued"
        );
        assert_eq!(node.event("admission")["all_admitted"], true);
        if dispose {
            let discarded = result(
                &mut node,
                json!({"command":"discard_inbox", "id":2, "inbox":"higher"}),
            );
            assert_eq!(discarded["event"], "inbox_discarded");
            assert_eq!(discarded["discarded_items"], 1);
        }
        node.child.kill().unwrap();
        assert_eq!(node.exit().signal(), Some(9));
        let before = layout.images();
        fs::remove_file(layout.root.join("proof.control")).unwrap();
        fs::remove_file(layout.root.join("proof.payload")).unwrap();
        let open = config.replace("mode = \"create\"", "mode = \"open\"");
        let mut reopened = Process::start(&layout, &open);
        let ready = reopened.ready();
        assert_eq!(ready["driver"]["higher_inbox"], usize::from(!dispose));
        reopened.event("timer_armed");
        assert_eq!(layout.images(), before);
        assert_eq!(
            result(
                &mut reopened,
                json!({"command":"submit_vote", "id":3, "vote_file":"proof.vote"})
            )["event"],
            "input_queued"
        );
        assert_eq!(reopened.event("admission")["all_admitted"], true);
        if dispose {
            reopened.event("transitioned");
            reopened.event("timer_armed");
            let state = result(&mut reopened, json!({"command":"status", "id":4}));
            assert_eq!(state["driver"]["height"], "1");
            assert!(!reopened.observed.iter().any(|v| v["event"] == "finality"));
        } else {
            let finalized = reopened.event("finality");
            assert_eq!(finalized["state"]["driver"]["height"], "2");
            assert!(
                !reopened
                    .observed
                    .iter()
                    .any(|v| v["event"] == "publication_prepared")
            );
        }
        reopened.shutdown();
        let durable = layout.images();
        let mut second = Process::start(&layout, &open);
        assert_eq!(
            second.ready()["driver"]["height"],
            if dispose { "1" } else { "2" }
        );
        second.shutdown();
        assert_eq!(layout.images(), durable);
    }
}

#[test]
fn durable_evidence_corrupt_or_missing_image_refuses_open_without_repair_or_authority_change() {
    let fixture = Fixture::new();
    for missing in [false, true] {
        let layout = Layout::new();
        let config = enable(&layout, &fixture.config(&layout, 1, "create", None, false));
        let mut node = Process::start(&layout, &config);
        node.ready();
        node.shutdown();
        let before = layout.images();
        let path = layout
            .root
            .join("evidence/fixed-validator-retained.evidence");
        if missing {
            fs::remove_file(&path).unwrap();
        } else {
            fs::write(&path, b"corrupt raw custody").unwrap();
        }
        let mut reopened = Process::start(
            &layout,
            &config.replace("mode = \"create\"", "mode = \"open\""),
        );
        assert_eq!(reopened.event("error")["code"], "evidence_journal");
        assert!(!reopened.exit().success());
        assert_eq!(layout.images(), before);
        if missing {
            assert!(!path.exists());
        } else {
            assert_eq!(fs::read(&path).unwrap(), b"corrupt raw custody");
        }
    }
}
