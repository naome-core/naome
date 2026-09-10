//! A faulty weighted proposer equivocates over the network; no process commands.
use super::*;

#[test]
fn autonomous_supervisor_survives_byzantine_equivocation_and_finalizes_three_heights() {
    run(false);
}

#[test]
fn continuous_supervisor_survives_byzantine_equivocation_and_finalizes_three_heights() {
    run(true);
}

fn run(continuous: bool) {
    let _fixture_guard = super::super::autonomous_supervisor::process_fixture_guard();
    let fixture = Fixture::new();
    let layouts: [Layout; 4] = std::array::from_fn(|_| Layout::new());
    let unused_gates = std::array::from_fn(|_| Gate::bind());
    let configs: [String; 4] = std::array::from_fn(|actor| {
        let prepared = super::super::autonomous_supervisor::configured(
            &fixture.corpus,
            &layouts[actor],
            actor,
            &unused_gates,
        );
        let (_, sources) = prepared.split_once("[sources]").unwrap();
        let sources = sources
            .lines()
            .map(|line| {
                if line.starts_with("peers = ") {
                    format!("peers = [{:?}]", fixture.peer.to_string())
                } else if continuous && line.starts_with("targets = ") {
                    "candidate_inbox = \"candidate-inbox.json\"".to_owned()
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let base = fixture
            .config(&layouts[actor], actor)
            .replace(
                "[network]\n",
                "[network]\npublication_retry_millis = \"100\"\n",
            )
            .replace("base_millis = \"10000\"", "base_millis = \"3000\"")
            .replace("vote_preparations = \"64\"", "vote_preparations = \"256\"")
            .replace("catch_up_heights = \"0\"", "catch_up_heights = \"16\"")
            .replace(
                "proposal_preparations = \"8\"",
                "proposal_preparations = \"128\"",
            )
            .replace("max_round = \"4\"", "max_round = \"32\"")
            .replace("max_round = \"8\"", "max_round = \"32\"");
        format!("{base}\n[sources]{sources}")
    });
    let mut nodes: [Process; 4] = std::array::from_fn(|actor| {
        let mut node = Process::start(&layouts[actor], &configs[actor]);
        drop(node.child.stdin.take());
        node
    });
    let addresses = nodes.each_mut().map(|node| {
        node.ready();
        node.event("listening")["address"]
            .as_str()
            .unwrap()
            .to_owned()
    });
    let bridge = Bridge::start(&fixture, addresses);
    if continuous {
        for layout in &layouts {
            fs::write(layout.root.join("candidate-inbox.json"), serde_json::to_vec(&json!({"candidates":fixture.corpus.blocks.iter().map(|block| hex(block.id().as_bytes())).collect::<Vec<_>>()})).unwrap()).unwrap();
        }
    }
    pump_until(&mut nodes, "autonomous Byzantine sessions", |nodes| {
        nodes.iter().all(|node| {
            node.observed
                .iter()
                .any(|e| e["event"] == "peer_session" && e["state"] == "established")
        })
    });
    bridge.inject(
        (0..4)
            .flat_map(|to| {
                let side = to / 2;
                [
                    (
                        to,
                        Wire::Proposal(
                            fixture.controls[side].clone(),
                            fixture.payloads[side].clone(),
                        ),
                    ),
                    (to, fixture.faulty_vote(side, ConsensusVoteRole::Prevote)),
                    (to, fixture.faulty_vote(side, ConsensusVoteRole::Precommit)),
                ]
            })
            .collect(),
    );
    pump_until(&mut nodes, "autonomous equivocation prevotes", |_| {
        let trace = bridge.snapshot();
        (0..4).all(|actor| {
            vote(&trace, &fixture, actor, 0, 0)
                == Some(ConsensusVoteTarget::Proposal(
                    fixture.values[actor / 2].proposal_signing_root(),
                ))
        })
    });
    assert!(
        nodes
            .iter()
            .all(|node| !node.observed.iter().any(|e| e["event"] == "finality"))
    );
    assert!(bridge.snapshot().dropped_cross_group > 0);
    bridge.heal();
    pump_until(&mut nodes, "autonomous Byzantine recovery", |nodes| {
        nodes.iter().all(|node| {
            node.observed.iter().any(|e| {
                e["event"] == "finality"
                    && e["state"]["driver"]["height"] == "4"
                    && e["state"]["driver"]["head"] == hex(fixture.corpus.blocks[2].id().as_bytes())
            })
        })
    });
    // Capture the authenticated vote oracle, then join the relay while its
    // destinations are still alive. Pending duplicate deliveries must not race
    // intentional validator shutdown.
    let trace = bridge.snapshot();
    assert!(trace.votes.keys().any(|(_, height, _, _)| *height == 3));
    drop(bridge);
    for node in &nodes {
        node.signal(rustix::process::Signal::TERM);
    }
    for node in &mut nodes {
        node.event("stopped");
        assert!(node.exit().success());
        assert!(!node.observed.iter().any(|e| e["event"] == "command_result"));
    }
    let prefixes = layouts.each_ref().map(|layout| {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let journal = FixedValidatorAnchoredFinalityJournalV0::open(
            layout.root.join("finality-journal"),
            layout.root.join("finality-anchor"),
            fixture.corpus.definition,
            fixture.corpus.context,
            &fixture.entries,
            FixedValidatorFinalityReplayLimitV0::new(32).unwrap(),
        )
        .unwrap();
        assert_eq!(journal.finalized_len().unwrap(), 3);
        (1..=3)
            .map(|height| {
                let record = journal
                    .finality_record(ConsensusHeight::new(height))
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    record.value().artifact_block(),
                    fixture.corpus.blocks[height as usize - 1]
                );
                assert_eq!(
                    record.canonical_artifact_bytes(),
                    fixture.corpus.payloads[height as usize - 1]
                );
                record.value().ancestry_id()
            })
            .collect::<Vec<_>>()
    });
    assert!(prefixes.iter().all(|prefix| prefix == &prefixes[0]));
}
