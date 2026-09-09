use super::*;
use naome_consensus::{
    ConsensusPosition, ConsensusRound, ConsensusVoteRole, VerifiedConsensusVoteV0,
};
use naome_storage::{
    FixedValidatorAnchoredVoteSafetyJournalV0, FixedValidatorVoteSafetyReplayLimitV0,
};
use rustix::process::Signal;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, os::unix::process::ExitStatusExt};

pub(super) type Signed = BTreeMap<(u64, u64, u8), (Vec<u8>, Vec<u8>, [u8; 32])>;

// An independent oracle reads only stopped owners, verifies actual signatures,
// and compares all old completion identities as well as exact message bytes.
pub(super) fn signed(corpus: &Corpus, layout: &Layout, actor: usize, through: u64) -> Signed {
    signed_with_limits(corpus, layout, actor, through, (8, 64, 4))
}

pub(super) fn signed_with_limits(
    corpus: &Corpus,
    layout: &Layout,
    actor: usize,
    through: u64,
    limits: (u64, u64, u64),
) -> Signed {
    let before = layout.images();
    let result = {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let finality = FixedValidatorAnchoredFinalityJournalV0::open(
            layout.root.join("finality-journal"),
            layout.root.join("finality-anchor"),
            corpus.definition,
            corpus.context,
            &corpus.entries,
            FixedValidatorFinalityReplayLimitV0::new(limits.0).unwrap(),
        )
        .unwrap();
        let journal = FixedValidatorAnchoredVoteSafetyJournalV0::open(
            layout.root.join("vote-journal"),
            layout.root.join("vote-anchor"),
            corpus.context,
            finality.fixed_agreement_set_id(),
            corpus.keys[actor].clone(),
            FixedValidatorVoteSafetyReplayLimitV0::new(limits.1).unwrap(),
        )
        .unwrap();
        assert!(journal.pending_vote().unwrap().is_none());
        assert!(journal.pending_proposal().unwrap().is_none());
        assert!(journal.halt().unwrap().is_none());
        assert!(journal.proposal_halt().unwrap().is_none());
        assert!(journal.finality_conflict_stop().unwrap().is_none());
        let mut signed = BTreeMap::new();
        for height in 1..=through {
            for round in 0..=limits.2 {
                let position = ConsensusPosition::new(
                    ConsensusHeight::new(height),
                    ConsensusRound::new(round),
                );
                if let Some(proposal) = journal.retained_signed_proposal(position).unwrap() {
                    let payload = proposal.canonical_artifact_bytes().unwrap().to_vec();
                    let parent = finality
                        .parent_for_height(position.height())
                        .unwrap()
                        .unwrap();
                    let mut cursor = parent.begin_round_zero().unwrap();
                    for _ in 0..round {
                        cursor = cursor.advance_round().unwrap();
                    }
                    let verified = cursor
                        .decode_and_verify_proposal_control(
                            proposal.canonical_proposal_control_bytes(),
                            payload.clone(),
                        )
                        .unwrap();
                    assert_eq!(
                        verified.proposal_signing_root(),
                        proposal.proposal_signing_root()
                    );
                    assert_eq!(cursor.proposer(), corpus.entries[actor].consensus_key());
                    signed.insert(
                        (height, round, 0),
                        (
                            proposal.canonical_proposal_control_bytes().to_vec(),
                            payload,
                            *proposal.state_id().as_bytes(),
                        ),
                    );
                }
                for (index, role) in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit]
                    .into_iter()
                    .enumerate()
                {
                    if let Some(vote) = journal.retained_signed_vote(position, role).unwrap() {
                        let verified = VerifiedConsensusVoteV0::decode_and_verify(
                            vote.canonical_bytes(),
                            corpus.context,
                        )
                        .unwrap();
                        assert_eq!(verified.signer(), corpus.entries[actor].consensus_key());
                        assert_eq!(verified.position(), position);
                        assert_eq!(verified.role(), role);
                        signed.insert(
                            (height, round, index as u8 + 1),
                            (
                                vote.canonical_bytes().to_vec(),
                                Vec::new(),
                                *vote.state_id().as_bytes(),
                            ),
                        );
                    }
                }
            }
        }
        signed
    };
    assert_eq!(
        layout.images(),
        before,
        "strict replay must not change signer or delivery files"
    );
    result
}

#[test]
fn four_process_sigkill_before_receipt_replays_exact_publication_and_finalizes_next_height() {
    let corpus = Corpus::new([1; 4]);
    assert!(
        corpus
            .entries
            .iter()
            .all(|entry| entry.agreement_weight().units() == 1)
    );
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    let (mut nodes, baseline) = start_on_h1(&corpus, &layouts, &mut gates, 120_000);
    let sender = corpus.proposers[1];
    let receiver = (sender + 1) % 4;
    let original_pids = nodes.each_ref().map(|node| node.child.id());
    let listening = nodes[sender]
        .observed
        .iter()
        .find(|event| event["event"] == "listening")
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_owned();
    for (gate, &(_, higher)) in gates.iter().zip(&PAIRS) {
        if higher == sender {
            gate.allow_backend_restart();
        }
    }
    let start = nodes[sender].observed.len();
    // SIGSTOP prevents the actual recipient from consuming the encrypted body
    // and producing its stream receipt. Other validators continue normally.
    nodes[receiver].signal(Signal::STOP);
    corpus.author(&mut nodes, &layouts, 1);
    pump_until(
        &mut nodes,
        "durable H2 proposal with one receipt withheld",
        |nodes| {
            (0..4)
                .filter(|&actor| actor != sender && actor != receiver)
                .all(|actor| {
                    nodes[sender].observed[start..].iter().any(|event| {
                        event["event"] == "peer_completed"
                            && event["received"] == true
                            && event["peer"] == corpus.peers[actor].to_string()
                    })
                })
        },
    );
    nodes[sender].send(json!({"command":"status", "id": 71}));
    pump_until(&mut nodes, "held publication status", |nodes| {
        nodes[sender]
            .observed
            .iter()
            .any(|event| event["event"] == "command_result" && event["id"] == 71)
    });
    assert_eq!(finality_images(&layouts[sender]), baseline[sender]);
    let before_kill = nodes[sender]
        .observed
        .iter()
        .find(|event| event["event"] == "command_result" && event["id"] == 71)
        .unwrap()["outcome"]["publication"]
        .clone();
    assert_eq!(before_kill["local_admission_attempted"], true);
    let deliveries = before_kill["deliveries"].as_array().unwrap();
    assert_eq!(deliveries.len(), 3);
    assert!(deliveries.iter().all(|delivery| {
        if delivery["peer"] == corpus.peers[receiver].to_string() {
            delivery["state"] == "in_flight"
        } else {
            delivery["state"] == "received"
        }
    }));
    nodes[sender].child.kill().unwrap();
    assert_eq!(nodes[sender].exit().signal(), Some(Signal::KILL.as_raw()));
    let before = signed(&corpus, &layouts[sender], sender, 2);
    let proposal = before
        .get(&(2, 0, 0))
        .expect("exact H2 signed proposal completed before SIGKILL");
    assert_eq!(proposal.1, corpus.payloads[1]);
    assert_eq!(before_kill["signer_state"], hex(&proposal.2));
    let expected_digests = json!({"control": hex(&Sha256::digest(&proposal.0)), "artifact": hex(&Sha256::digest(&proposal.1))});
    assert_eq!(before_kill["message_sha256"], expected_digests);
    assert!(
        !before.contains_key(&(2, 0, 1)),
        "pending proposal publication must precede another signature"
    );
    // Recovery must not read caller source files or sign the proposal again.
    fs::remove_file(layouts[sender].root.join("block.bin")).unwrap();
    fs::remove_file(layouts[sender].root.join("payload.bin")).unwrap();
    let config = corpus
        .config(&layouts[sender], sender, &gates, 120_000)
        .replace("mode = \"create\"", "mode = \"open\"")
        .replace("[network]", "[network]\npublication_retry_millis = \"100\"")
        .replace(
            "listen = \"/ip4/127.0.0.1/tcp/0\"",
            &format!("listen = {listening:?}"),
        );
    nodes[sender] = Process::start(&layouts[sender], &config);
    let ready = nodes[sender].ready();
    assert_eq!(ready["driver"]["height"], "2");
    assert_eq!(ready["driver"]["phase"], "Proposal");
    assert!(ready["publication_recovery_remaining"].as_u64().unwrap() >= 1);
    nodes[receiver].signal(Signal::CONT);
    pump_until(
        &mut nodes,
        "exact recovered proposal received and H2 finalized",
        |nodes| {
            nodes
                .iter()
                .all(|node| finality(node, &corpus.blocks[1], "3"))
        },
    );
    assert!(
        nodes[sender]
            .observed
            .iter()
            .any(|event| event["event"] == "publication_recovered"
                && event["signer_state"] == hex(&proposal.2))
    );
    assert!(nodes[sender].observed.iter().any(|event| {
        event["event"] == "publication_complete"
            && event["disposed"]["signer_state"] == hex(&proposal.2)
            && event["disposed"]["recovered"] == true
            && event["disposed"]["message_sha256"] == expected_digests
            && event["disposed"]["deliveries"]
                .as_array()
                .unwrap()
                .iter()
                .all(|delivery| {
                    if delivery["peer"] == corpus.peers[receiver].to_string() {
                        delivery["state"] == "received"
                    } else {
                        delivery["state"] == "previously_received"
                    }
                })
    }));
    assert!(
        nodes[receiver]
            .observed
            .iter()
            .any(|event| event["event"] == "admission"
                && event["source"]["kind"] == "peer"
                && event["source"]["peer"] == corpus.peers[sender].to_string()
                && event["all_admitted"] == true
                && event["message_sha256"] == expected_digests),
        "the actual resumed recipient must receive the exact persisted signed control and payload"
    );
    pump_until(
        &mut nodes,
        "periodic pass after managed reconnect and receipts",
        |nodes| {
            nodes[sender].observed.iter().any(|event| {
                event["event"] == "publication_retry_scheduled" && event["queued"] == "0"
            })
        },
    );
    // Wait until every current publication has transferred before separately
    // asking the actual next scheduled proposer to author a further height.
    for node in &mut nodes {
        node.send(json!({"command":"status", "id": 70}));
    }
    pump_until(&mut nodes, "H3 authoring boundary", |nodes| {
        nodes.iter().all(|node| {
            node.observed
                .iter()
                .any(|event| event["event"] == "command_result" && event["id"] == 70)
        })
    });
    corpus.author(&mut nodes, &layouts, 2);
    pump_until(&mut nodes, "H3 finalized after crash recovery", |nodes| {
        nodes
            .iter()
            .all(|node| finality(node, &corpus.blocks[2], "4"))
    });
    for (actor, node) in nodes.iter_mut().enumerate() {
        if actor == sender {
            assert_ne!(node.child.id(), original_pids[actor]);
        } else {
            assert_eq!(node.child.id(), original_pids[actor]);
        }
        node.shutdown();
    }
    for (actor, layout) in layouts.iter().enumerate() {
        corpus.verify(layout, 3);
        let _ = signed(&corpus, layout, actor, 3);
    }
    let after = signed(&corpus, &layouts[sender], sender, 3);
    for (slot, old) in before {
        assert_eq!(
            after.get(&slot),
            Some(&old),
            "no replacement or re-sign of completed slot {slot:?}"
        );
    }
    // Quorum finality may overtake a local precommit. It must not force a new
    // signature merely to satisfy a fixture's expected publication count.
    for gate in &mut gates {
        gate.finish();
    }
}
