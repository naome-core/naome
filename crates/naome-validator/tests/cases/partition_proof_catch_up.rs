use super::*;
use naome_consensus::{ConsensusVoteTarget, VerifiedConsensusVoteV0};
use publication_restart::signed;
use rustix::process::Signal;
use std::os::unix::process::ExitStatusExt;

fn command(nodes: &mut [Process; 4], actor: usize, value: Value) -> Value {
    let id = value["id"].clone();
    nodes[actor].send(value);
    pump_until(nodes, "operator command result", |nodes| {
        nodes[actor]
            .observed
            .iter()
            .any(|v| v["event"] == "command_result" && v["id"] == id)
    });
    nodes[actor]
        .observed
        .iter()
        .find(|v| v["event"] == "command_result" && v["id"] == id)
        .unwrap()["outcome"]
        .clone()
}

fn quiescent(nodes: &mut [Process; 4], actor: usize, id: &mut u64) -> Value {
    let deadline = Instant::now() + MILESTONE_BOUND;
    loop {
        *id += 1;
        let state = command(nodes, actor, json!({"command":"status", "id":*id}));
        if state["publication"].is_null()
            && state["publication_recovery_remaining"] == 0
            && state["driver"]["pending_command"] == false
            && state["timer"] == true
        {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "publication did not drain: {state}"
        );
    }
}

// A status response is not a reservation against the next real deadline or
// publication. Retry only this exact start refusal; every other failure remains
// fatal to the harness and an accepted pass must still commit its exact proof.
fn start_sync(
    nodes: &mut [Process; 4],
    actor: usize,
    peer: PeerId,
    id: &mut u64,
    refused: &mut Vec<(usize, u64)>,
) -> u64 {
    let deadline = Instant::now() + MILESTONE_BOUND;
    loop {
        *id += 1;
        let current = *id;
        nodes[actor].send(json!({"command":"sync_finality", "id":current,
            "peer_id":peer.to_string(), "count":1}));
        let accepted = loop {
            let mut result = None;
            for (index, node) in nodes.iter_mut().enumerate() {
                if let Some(event) = node.observe(Duration::from_millis(1)) {
                    if index == actor
                        && event["id"] == current
                        && event["event"] == "command_rejected"
                        && event["code"] == "sync_request_start"
                    {
                        refused.push((actor, current));
                        result = Some(false);
                    } else {
                        healthy(&event);
                        assert_ne!(event["event"], "stopped");
                        if index == actor
                            && event["id"] == current
                            && event["event"] == "command_result"
                        {
                            assert_eq!(event["outcome"]["event"], "sync_started");
                            result = Some(true);
                        }
                    }
                }
                assert!(node.child.try_wait().unwrap().is_none());
            }
            assert!(
                Instant::now() < deadline,
                "bounded proof start did not become available"
            );
            if let Some(result) = result {
                break result;
            }
        };
        if accepted {
            return current;
        }
    }
}

fn prefix_preserved(layout: &Layout, baseline: &Images) {
    let current = finality_images(layout);
    for (path, bytes) in baseline
        .iter()
        .filter(|(path, _)| path.starts_with("finality-journal"))
    {
        assert!(
            current
                .iter()
                .find(|(p, _)| p == path)
                .unwrap()
                .1
                .starts_with(bytes)
        );
    }
}

fn selected_proofs(corpus: &Corpus, layout: &Layout) -> Vec<(Vec<u8>, ConsensusVoteTarget)> {
    let before = layout.images();
    let result = {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let journal = FixedValidatorAnchoredFinalityJournalV0::open(
            layout.root.join("finality-journal"),
            layout.root.join("finality-anchor"),
            corpus.definition,
            corpus.context,
            &corpus.entries,
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        )
        .unwrap();
        (1..=3)
            .map(|height| {
                let record = journal
                    .finality_record(ConsensusHeight::new(height))
                    .unwrap()
                    .unwrap();
                (
                    record.canonical_envelope_bytes().to_vec(),
                    ConsensusVoteTarget::Proposal(record.value().proposal_signing_root()),
                )
            })
            .collect()
    };
    assert_eq!(layout.images(), before);
    result
}

fn run(kill_minority: bool) {
    let corpus = Corpus::new([3, 2, 1, 1]);
    let weights: Vec<_> = corpus
        .entries
        .iter()
        .map(|v| v.agreement_weight().units())
        .collect();
    let total: u128 = weights.iter().sum();
    assert_eq!(total, 7);
    assert!(3 * (weights[0] + weights[1]) > 2 * total);
    assert!(3 * (weights[2] + weights[3]) <= 2 * total);
    assert_eq!(corpus.proposers, [0, 1, 2]);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    // The minority must reach R1 Prevote through real R0 deadlines, then
    // remain available across bounded restart, mesh and operator milestones.
    // Five-second later-round deadlines can exhaust round 4 before catch-up.
    let reconnect_bound = naome_network::DIAL_RETRY_MAX + MILESTONE_BOUND;
    let catch_up_budget_millis =
        u64::try_from((MILESTONE_BOUND * 12 + reconnect_bound).as_millis()).unwrap();
    let configs = std::array::from_fn(|actor| {
        let mut config = corpus.config(
            &layouts[actor],
            actor,
            &gates,
            if actor < 2 {
                catch_up_budget_millis
            } else {
                5000
            },
        );
        if actor >= 2 {
            let initial =
                "[timeouts.prevote]\nbase_millis = \"5000\"\nround_increment_millis = \"1\"";
            assert!(config.contains(initial));
            config = config.replace(
                initial,
                &format!("[timeouts.prevote]\nbase_millis = \"5000\"\nround_increment_millis = \"{catch_up_budget_millis}\""),
            );
        }
        config.replace("[network]", "[network]\nserve_finality_proofs = true")
    });
    let (mut nodes, baseline) = start_on_h1_with_configs(&corpus, &layouts, &mut gates, &configs);
    let original_pids = nodes.each_ref().map(|node| node.child.id());
    let cut_start = nodes.each_ref().map(|node| node.observed.len());
    for (gate, &(a, b)) in gates.iter().zip(&PAIRS) {
        if (a < 2) != (b < 2) {
            gate.cut();
        }
    }
    pump_until(
        &mut nodes,
        "both partition endpoints disconnected",
        |nodes| {
            (0..4).all(|actor| {
                (0..4)
                    .filter(|&other| (actor < 2) != (other < 2))
                    .all(|other| {
                        nodes[actor].observed[cut_start[actor]..].iter().any(|v| {
                            v["event"] == "peer_session"
                                && v["state"] == "disconnected"
                                && v["peer"] == corpus.peers[other].to_string()
                        })
                    })
            })
        },
    );
    corpus.author(&mut nodes, &layouts, 1);
    pump_until(
        &mut nodes,
        "quorum H2 and minority durable later-round voting",
        |nodes| {
            for actor in 2..4 {
                assert_eq!(finality_images(&layouts[actor]), baseline[actor]);
            }
            (0..2).all(|actor| finality(&nodes[actor], &corpus.blocks[1], "3"))
                && (2..4).all(|actor| {
                    nodes[actor].observed[cut_start[actor]..].iter().any(|v| {
                        v["event"] == "transitioned"
                            && v["height"] == "2"
                            && v["round"] == "1"
                            && v["phase"] == "Prevote"
                    })
                })
        },
    );
    let mut id = 100;
    let mut refused_sync_starts = Vec::new();
    for actor in 2..4 {
        let state = quiescent(&mut nodes, actor, &mut id);
        assert_eq!(state["driver"]["height"], "2");
        assert_eq!(state["driver"]["round"], "1");
        assert_eq!(state["driver"]["phase"], "Prevote");
        assert_eq!(finality_images(&layouts[actor]), baseline[actor]);
        assert!(
            nodes[actor].observed[cut_start[actor]..]
                .iter()
                .any(|v| { v["event"] == "timer_due" && v["admitted"] == true })
        );
        assert!(nodes[actor].observed[cut_start[actor]..].iter().all(|v| {
            v["event"] != "admission"
                || v["source"]["kind"] != "peer"
                || v["source"]["peer"] == corpus.peers[5 - actor].to_string()
        }));
    }
    // All honest proof material must come from running signers and their
    // retained history. No caller proposal source survives the partition.
    for layout in &layouts {
        for file in ["block.bin", "payload.bin"] {
            let path = layout.root.join(file);
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }
    let mut before_crash = None;
    if kill_minority {
        let actor = 2;
        let listening = nodes[actor]
            .observed
            .iter()
            .find(|v| v["event"] == "listening")
            .unwrap()["address"]
            .as_str()
            .unwrap()
            .to_owned();
        for (gate, &(a, b)) in gates.iter().zip(&PAIRS) {
            if a == actor || b == actor {
                gate.cut();
            }
            if b == actor {
                gate.allow_backend_restart();
            }
        }
        nodes[actor].child.kill().unwrap();
        assert_eq!(nodes[actor].exit().signal(), Some(Signal::KILL.as_raw()));
        before_crash = Some(signed(&corpus, &layouts[actor], actor, 2));
        // Reopen may atomically replace the independent delivery snapshot.
        // Capture authority paths while stopped, then read those exact files
        // without enumerating the live publication directory or its temps.
        let before: Images = layouts[actor]
            .images()
            .into_iter()
            .filter(|(path, _)| {
                matches!(
                    path.extension().and_then(|v| v.to_str()),
                    Some("journal" | "anchor")
                )
            })
            .collect();
        assert_eq!(before.len(), 4);
        let config = configs[actor]
            .replace("mode = \"create\"", "mode = \"open\"")
            .replace(
                "listen = \"/ip4/127.0.0.1/tcp/0\"",
                &format!("listen = {listening:?}"),
            );
        nodes[actor] = Process::start(&layouts[actor], &config);
        let ready = nodes[actor].ready();
        assert_eq!(ready["driver"]["height"], "2");
        assert_eq!(ready["driver"]["round"], "1");
        assert_eq!(ready["driver"]["phase"], "Prevote");
        assert_eq!(
            ready["driver"]["head"],
            hex(corpus.blocks[0].id().as_bytes())
        );
        for inbox in [
            "higher_inbox",
            "current_inbox",
            "finality_inbox",
            "nil_precommit_inbox",
        ] {
            assert_eq!(ready["driver"][inbox], 0);
        }
        for (path, bytes) in before {
            assert_eq!(
                fs::read(layouts[actor].root.join(&path)).unwrap(),
                bytes,
                "restart changed authority {path:?}"
            );
        }
        assert!(
            command(&mut nodes, actor, json!({"command":"sync_status", "id":90}))["job"].is_null()
        );
    }
    for (actor, node) in nodes.iter_mut().enumerate() {
        assert!(node.child.try_wait().unwrap().is_none());
        assert_eq!(
            node.child.id() == original_pids[actor],
            !kill_minority || actor != 2
        );
    }
    let heal_start = nodes.each_ref().map(|node| node.observed.len());
    for gate in &gates {
        gate.heal();
    }
    // A long cut can reach the transport's capped dial backoff. The usual
    // milestone bound alone is shorter than one legitimate retry interval.
    pump_until_with_bound(
        &mut nodes,
        "complete mesh restored before catch-up",
        reconnect_bound,
        |nodes| {
            (0..4).all(|actor| {
                (0..4).filter(|&other| other != actor).all(|other| {
                    nodes[actor]
                        .observed
                        .iter()
                        .rev()
                        .find(|v| {
                            v["event"] == "peer_session"
                                && v["peer"] == corpus.peers[other].to_string()
                                && matches!(
                                    v["state"].as_str(),
                                    Some("established" | "disconnected")
                                )
                        })
                        .is_some_and(|v| v["state"] == "established")
                })
            })
        },
    );
    for actor in 2..4 {
        let state = quiescent(&mut nodes, actor, &mut id);
        assert_eq!(
            state["driver"]["height"], "2",
            "old raw messages cannot explain catch-up"
        );
        assert!(
            state["driver"]["round"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                >= 1
        );
        assert_eq!(finality_images(&layouts[actor]), baseline[actor]);
        let sync_id = start_sync(
            &mut nodes,
            actor,
            corpus.peers[0],
            &mut id,
            &mut refused_sync_starts,
        );
        pump_until(
            &mut nodes,
            "one exact live-produced proof commits",
            |nodes| {
                nodes[actor].observed.iter().any(|v| {
                    v["event"] == "sync_completed"
                        && v["id"] == sync_id
                        && v["completed"] == "1"
                        && v["last_height"] == "2"
                }) && finality(&nodes[actor], &corpus.blocks[1], "3")
            },
        );
        let state = quiescent(&mut nodes, actor, &mut id);
        assert_eq!(state["driver"]["height"], "3");
        assert_eq!(state["driver"]["round"], "0");
        assert_eq!(state["driver"]["phase"], "Proposal");
        assert!(nodes[0].observed[heal_start[0]..].iter().any(|v| {
            v["event"] == "proof_response_queued"
                && v["height"] == "2"
                && v["peer"] == corpus.peers[actor].to_string()
        }));
        prefix_preserved(&layouts[actor], &baseline[actor]);
    }
    // Exclude weight 2 for H3. The 3+1+1 component now needs both recovered
    // minorities' actual votes; either one's absence leaves at most 4/7.
    assert!(3 * (weights[0] + weights[2] + weights[3]) > 2 * total);
    for actor in 2..4 {
        assert!(3 * (weights[0] + weights[actor]) <= 2 * total);
    }
    let h3_start = nodes.each_ref().map(|node| node.observed.len());
    for (gate, &(a, b)) in gates.iter().zip(&PAIRS) {
        if a == 1 || b == 1 {
            gate.cut();
        }
    }
    pump_until(
        &mut nodes,
        "H3 quorum excludes old weight-two member",
        |nodes| {
            [0, 2, 3].into_iter().all(|actor| {
                nodes[actor].observed[h3_start[actor]..].iter().any(|v| {
                    v["event"] == "peer_session"
                        && v["state"] == "disconnected"
                        && v["peer"] == corpus.peers[1].to_string()
                })
            })
        },
    );
    corpus.author(&mut nodes, &layouts, 2);
    pump_until(
        &mut nodes,
        "recovered signers produce necessary H3 quorum",
        |nodes| {
            [0, 2, 3]
                .into_iter()
                .all(|actor| finality(&nodes[actor], &corpus.blocks[2], "4"))
        },
    );
    assert!(!finality(&nodes[1], &corpus.blocks[2], "4"));
    for actor in [0, 2, 3] {
        for route in ["CurrentProposalPrevote", "CurrentProposalPrecommit"] {
            assert!(
                nodes[actor].observed[h3_start[actor]..]
                    .iter()
                    .any(|v| { admitted(v, route) && v["source"]["kind"] == "local_publication" })
            );
        }
    }
    for gate in &gates {
        gate.heal();
    }
    pump_until_with_bound(
        &mut nodes,
        "managed replay heals final H3 recipient",
        reconnect_bound,
        |nodes| {
            nodes
                .iter()
                .all(|node| finality(node, &corpus.blocks[2], "4"))
        },
    );
    for (actor, node) in nodes.iter_mut().enumerate() {
        assert_eq!(
            node.child.id() == original_pids[actor],
            !kill_minority || actor != 2
        );
        assert_eq!(node.shutdown()["locks_released"], true);
        for event in &node.observed {
            if event["event"] == "command_rejected"
                && event["code"] == "sync_request_start"
                && event["id"]
                    .as_u64()
                    .is_some_and(|id| refused_sync_starts.contains(&(actor, id)))
            {
                continue;
            }
            healthy(event);
        }
    }
    let histories = layouts.each_ref().map(|layout| corpus.verify(layout, 3));
    assert!(histories.iter().all(|history| history == &histories[0]));
    let proofs = layouts
        .each_ref()
        .map(|layout| selected_proofs(&corpus, layout));
    let signatures =
        std::array::from_fn::<_, 4, _>(|actor| signed(&corpus, &layouts[actor], actor, 3));
    for actor in 2..4 {
        assert_eq!(
            proofs[actor][1], proofs[0][1],
            "catch-up retains the provider's exact first proof"
        );
        for (&(height, _, role), (bytes, _, _)) in &signatures[actor] {
            if height == 2 && role != 0 {
                assert_eq!(
                    VerifiedConsensusVoteV0::decode_and_verify(bytes, corpus.context)
                        .unwrap()
                        .target(),
                    ConsensusVoteTarget::Nil
                );
            }
        }
        for role in 1..=2 {
            let (bytes, _, _) = &signatures[actor][&(3, 0, role)];
            assert_eq!(
                VerifiedConsensusVoteV0::decode_and_verify(bytes, corpus.context)
                    .unwrap()
                    .target(),
                proofs[actor][2].1
            );
        }
    }
    assert!(
        signatures[2].contains_key(&(3, 0, 0)),
        "recovered scheduled proposer authored H3"
    );
    if let Some(before) = before_crash {
        assert!(before.contains_key(&(2, 1, 1)));
        for (slot, message) in before {
            assert_eq!(
                signatures[2].get(&slot),
                Some(&message),
                "completed slot changed across restart/catch-up: {slot:?}"
            );
        }
    }
    for actor in 0..4 {
        prefix_preserved(&layouts[actor], &baseline[actor]);
    }
    for (gate, &(a, b)) in gates.iter_mut().zip(&PAIRS) {
        if (a < 2) != (b < 2) {
            assert!(
                gate.counts().0 >= 2,
                "healing must forward a new connection"
            );
            assert!(gate.counts().1 > 0, "isolation must reject actual redials");
        }
        gate.finish();
    }
}

#[test]
fn actual_partitioned_signers_catch_up_live_proof_and_form_next_quorum() {
    run(false);
}

#[test]
fn actual_killed_partitioned_signer_catches_up_live_proof_and_forms_next_quorum() {
    run(true);
}
