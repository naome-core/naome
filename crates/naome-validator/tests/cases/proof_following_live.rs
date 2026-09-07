use super::*;

#[test]
fn proof_following_actual_quorum_produces_two_later_heights_while_followers_receive_no_publications()
 {
    let corpus = Corpus::new([3, 2, 1, 1]);
    assert_eq!(corpus.proposers, [0, 1, 2]);
    let layouts: [Layout; 4] = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    let configs: [String; 4] = std::array::from_fn(|actor| {
        let targets = (0..2)
            .filter(|&other| other != actor)
            .map(|other| format!("{:?}", corpus.peers[other].to_string()))
            .collect::<Vec<_>>()
            .join(", ");
        corpus
            .config(&layouts[actor], actor, &gates, 120_000)
            .lines()
            .map(|line| {
                if line.starts_with("publication_targets =") {
                    format!("publication_targets = [{targets}]\n")
                } else {
                    format!("{line}\n")
                }
            })
            .collect::<String>()
            .replace("[network]", "[network]\nserve_finality_proofs = true")
    });
    let mut nodes: [Process; 4] =
        std::array::from_fn(|actor| Process::start(&layouts[actor], &configs[actor]));
    let addresses = nodes.each_mut().map(|node| {
        node.ready();
        let event = node.event("listening");
        let port = event["address"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .parse::<u16>()
            .unwrap();
        ([127, 0, 0, 1], port).into()
    });
    for (gate, &(_, higher)) in gates.iter_mut().zip(&PAIRS) {
        gate.start(addresses[higher]);
    }
    pump_until(&mut nodes, "complete authenticated mesh", |nodes| {
        nodes.iter().enumerate().all(|(actor, node)| {
            (0..4).filter(|&other| other != actor).all(|other| {
                node.observed.iter().any(|v| {
                    v["event"] == "peer_session"
                        && v["state"] == "established"
                        && v["peer"] == corpus.peers[other].to_string()
                })
            })
        })
    });
    let baseline = layouts.each_ref().map(finality_images);
    for (actor, node) in nodes.iter_mut().enumerate().skip(2) {
        node.send(json!({"command":"follow_finality", "id":100 + actor, "peer_id":corpus.peers[0].to_string(), "count":1, "interval_millis":"250"}));
    }
    pump_until(
        &mut nodes,
        "followers observe absent H1 before any signing",
        |nodes| {
            (2..4).all(|actor| {
                nodes[actor]
                    .observed
                    .iter()
                    .any(|v| v["event"] == "follow_waiting" && v["reason"] == "unavailable")
            })
        },
    );
    for actor in 2..4 {
        assert_eq!(finality_images(&layouts[actor]), baseline[actor]);
    }
    for index in 0..2 {
        let start = nodes.each_ref().map(|node| node.observed.len());
        if index == 0 {
            assert_eq!(PAIRS[1], (0, 2));
            gates[1].cut();
            pump_until(&mut nodes, "chosen proof peer disconnected", |nodes| {
                nodes[2].observed[start[2]..].iter().any(|v| {
                    v["event"] == "peer_session"
                        && v["state"] == "disconnected"
                        && v["peer"] == corpus.peers[0].to_string()
                })
            });
        }
        corpus.author(&mut nodes, &layouts, index);
        if index == 0 {
            pump_until(
                &mut nodes,
                "other follower advances while chosen peer remains unavailable",
                |nodes| {
                    [0, 1, 3]
                        .into_iter()
                        .all(|actor| finality(&nodes[actor], &corpus.blocks[0], "2"))
                        && nodes[2].observed[start[2]..].iter().any(|v| {
                            v["event"] == "follow_waiting" && v["reason"] == "sync_request_start"
                        })
                },
            );
            assert_eq!(finality_images(&layouts[2]), baseline[2]);
            assert!(!finality(&nodes[2], &corpus.blocks[0], "2"));
            gates[1].heal();
        }
        pump_until(
            &mut nodes,
            "quorum produces proof and both followers commit it",
            |nodes| {
                nodes
                    .iter()
                    .all(|node| finality(node, &corpus.blocks[index], &(index + 2).to_string()))
            },
        );
        let completed_height = (index + 1).to_string();
        for actor in 2..4 {
            assert!(
                nodes[actor].observed[start[actor]..]
                    .iter()
                    .any(|v| v["event"] == "sync_completed"
                        && v["last_height"] == completed_height
                        && v["completed"] == "1")
            );
            assert!(
                nodes[actor]
                    .observed
                    .iter()
                    .all(|v| v["event"] != "publication_prepared"
                        && (v["event"] != "admission" || v["source"]["kind"] != "peer"))
            );
        }
        let start = nodes.each_ref().map(|node| node.observed.len());
        pump_until(
            &mut nodes,
            "next height remains absent between production commands",
            |nodes| {
                (2..4).all(|actor| {
                    nodes[actor].observed[start[actor]..]
                        .iter()
                        .any(|v| v["event"] == "follow_waiting" && v["reason"] == "unavailable")
                })
            },
        );
    }
    // Original caller source files are unnecessary to strict proof replay.
    for layout in &layouts {
        for file in ["block.bin", "payload.bin"] {
            let _ = fs::remove_file(layout.root.join(file));
        }
    }
    for gate in &mut gates {
        gate.finish();
    }
    for node in &mut nodes {
        assert_eq!(node.shutdown()["locks_released"], true);
    }
    let histories = layouts.each_ref().map(|layout| corpus.verify(layout, 2));
    assert!(histories.iter().all(|history| history == &histories[0]));
    let proofs = layouts.each_ref().map(|layout| {
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
        (1..=2)
            .map(|height| {
                journal
                    .finality_record(ConsensusHeight::new(height))
                    .unwrap()
                    .unwrap()
                    .canonical_envelope_bytes()
                    .to_vec()
            })
            .collect::<Vec<_>>()
    });
    for actor in 2..4 {
        assert_eq!(proofs[actor], proofs[0]);
    }
    for actor in 2..4 {
        let mut node = Process::start(
            &layouts[actor],
            &configs[actor].replace("mode = \"create\"", "mode = \"open\""),
        );
        assert_eq!(node.ready()["driver"]["height"], "3");
        assert!(crate::explicit_proofs::result(&mut node, json!({"command":"sync_status", "id":200}))["job"].is_null());
        node.shutdown();
    }
}
