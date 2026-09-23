use super::*;

fn stable_validator_slots(status: &Value) -> Vec<Value> {
    status["validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|unit| {
            serde_json::json!({
                "index": unit["index"],
                "owner": unit["owner"],
                "slot": unit["slot"],
                "unit": unit["unit"],
            })
        })
        .collect()
}

fn active_ingress(lab: &Lab) -> usize {
    let start = Instant::now();
    loop {
        if let Some(index) = (0..lab.nodes.len()).find(|index| {
            lab.nodes[*index].is_some()
                && lab
                    .status(*index)
                    .is_some_and(|status| status["consensus_position"].is_object())
        }) {
            return index;
        }
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "no selected validator available for action ingress"
        );
        thread::sleep(Duration::from_millis(40));
    }
}

fn archive_has_earned_owner_quorum_vote(
    genesis_path: &str,
    archive_path: &str,
    owner: &str,
    after_height: u64,
) -> bool {
    let genesis = naome_ledger::profile::Genesis::decode(&fs::read(genesis_path).unwrap()).unwrap();
    let manifest: Value =
        serde_json::from_slice(&fs::read(Path::new(archive_path).join("manifest.json")).unwrap())
            .unwrap();
    let mut branch =
        naome_consensus::state::StateBranch::from_genesis(naome_ledger::LedgerState::new(genesis))
            .unwrap();
    let mut signed = false;
    for height in 1..=manifest["height"].as_u64().unwrap() {
        let bytes =
            fs::read(Path::new(archive_path).join(format!("{height:08}.finality"))).unwrap();
        let finality = branch
            .decode_finality(&bytes, manifest["maximum_round"].as_u64().unwrap())
            .unwrap();
        if height > after_height {
            for unit in branch.authority().units() {
                let unit_owner = unit
                    .owner()
                    .as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                if unit_owner == owner
                    && let Some(keys) = unit.keys()
                {
                    signed |= finality
                        .quorum()
                        .vote_set()
                        .votes()
                        .iter()
                        .any(|vote| vote.signer().as_bytes() == keys.consensus());
                }
            }
        }
        branch = finality.into_branch();
    }
    signed
}

#[test]
fn new_researcher_registers_proves_receives_reward_and_survives_replay_and_restart() {
    let _guard = process_guard();
    let mut lab = Lab::new();
    let account = command(&["account".into(), "create".into(), lab.key(6)]);
    let author = account["account"].as_str().unwrap().to_owned();
    // Mathematical preparation needs no preallocated genesis identity.
    let package = lab.file("researcher.package");
    command(&[
        "package".into(),
        lab.file("genesis.bin"),
        lab.key(6),
        package.clone(),
        path(example("solution-a.nao")),
        "--helper".into(),
        path(example("helper-h.nao")),
    ]);
    for index in 0..4 {
        lab.start(index);
    }
    let initial = lab.wait(0, |s| s["height"] == 0);
    assert_eq!(initial["registered_accounts"], 6);
    assert_eq!(initial["remaining_account_slots"], 250);
    assert_eq!(initial["registration_available"], true);
    assert!(
        !raw(&[
            "submit".into(),
            lab.config(active_ingress(&lab)),
            lab.key(6),
            path(example("question-a.nao")),
            "Before registration".into(),
            lab.file("unregistered.submit"),
        ])
        .status
        .success()
    );
    let registration_args = [
        "account".into(),
        "register".into(),
        lab.config(active_ingress(&lab)),
        lab.key(6),
        lab.file("register.action"),
    ];
    let registration = command(&registration_args);
    let joined = lab.wait(0, |s| s["registered_accounts"] == 7);
    let registered = joined["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["account"] == author)
        .unwrap();
    assert_eq!(registered["balance_atoms"], "0");
    assert_eq!(registered["next_nonce"], 2);
    assert_eq!(joined["remaining_account_slots"], 249);
    assert_eq!(
        stable_validator_slots(&joined),
        stable_validator_slots(&initial)
    );
    lab.assert_same(&[0, 1, 2, 3], &joined);
    for retry in [
        registration_args.to_vec(),
        vec![
            "send".into(),
            lab.config(active_ingress(&lab)),
            lab.file("register.action"),
        ],
    ] {
        let receipt = command(&retry);
        assert_eq!(receipt["operation"], registration["operation"]);
        assert_eq!(receipt["result"]["status"], "finalized");
        assert_eq!(receipt["result"]["height"], joined["height"]);
    }
    let submission = lab.submit(
        active_ingress(&lab),
        6,
        example("question-a.nao"),
        "researcher",
    );
    lab.wait_phase(0, &submission, "Voting");
    assert!(
        !raw(&[
            "vote".into(),
            lab.config(active_ingress(&lab)),
            lab.key(6),
            "YES".into(),
            lab.file("researcher.vote"),
        ])
        .status
        .success(),
        "registration must not grant validator agenda votes"
    );
    lab.approve(&[0, 1, 2], "researcher", &submission);
    lab.solve(active_ingress(&lab), 6, &package, "researcher", &submission);
    let settled = lab.wait(0, |s| s["paid_completions"] == 1);
    lab.assert_same(&[0, 1, 2, 3], &settled);
    let genesis =
        naome_ledger::profile::Genesis::decode(&fs::read(lab.file("genesis.bin")).unwrap())
            .unwrap();
    let researcher = settled["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["account"] == author)
        .unwrap();
    assert_eq!(
        researcher["balance_atoms"],
        genesis
            .profile()
            .rewards()
            .author_without_citations_atoms
            .to_string()
    );
    assert_eq!(researcher["next_nonce"], 5);
    assert_eq!(settled["claims"][0]["author"], author);
    assert_eq!(
        stable_validator_slots(&settled),
        stable_validator_slots(&initial)
    );
    assert_eq!(settled["join_intents_count"], 0);
    let family = settled["claims"][0]["family"].as_str().unwrap().to_owned();
    let consensus_key = lab.file("candidate-consensus.key");
    let transport_key = lab.file("candidate-transport.key");
    command(&[
        "join-key".into(),
        "create-consensus".into(),
        consensus_key.clone(),
    ]);
    command(&[
        "join-key".into(),
        "create-transport".into(),
        transport_key.clone(),
    ]);
    let intent_action = lab.file("researcher-join.action");
    let prepared = command(&[
        "join-intent".into(),
        lab.config(active_ingress(&lab)),
        lab.key(6),
        family.clone(),
        consensus_key.clone(),
        transport_key.clone(),
        format!("127.0.0.1:{}", lab.base + 10),
        intent_action.clone(),
    ]);
    assert_eq!(prepared["status"], "join_intent_prepared");
    assert_eq!(prepared["active_voting_rights"], false);
    command(&[
        "send".into(),
        lab.config(active_ingress(&lab)),
        intent_action.clone(),
    ]);
    let settled = lab.wait(0, |s| s["join_intents_count"] == 1);
    lab.assert_same(&[0, 1, 2, 3], &settled);
    assert_eq!(
        stable_validator_slots(&settled),
        stable_validator_slots(&initial)
    );
    let exact_retry = command(&[
        "send".into(),
        lab.config(active_ingress(&lab)),
        intent_action,
    ]);
    assert_eq!(exact_retry["result"]["status"], "finalized");
    let archive = lab.file("researcher-archive");
    command(&["export".into(), lab.config(0), archive.clone()]);
    let replayed = command(&["verify".into(), lab.file("genesis.bin"), archive.clone()]);
    for field in [
        "state",
        "head",
        "height",
        "accounts",
        "registered_accounts",
        "claims",
        "join_intents_count",
        "validators",
    ] {
        assert_eq!(replayed[field], settled[field], "archive {field}");
    }
    let inspected = command(&[
        "inspect".into(),
        lab.file("genesis.bin"),
        archive,
        submission,
        lab.file("researcher-inspection"),
    ]);
    assert_eq!(inspected["join_intent"]["status"], "QUEUED");
    assert_eq!(inspected["join_intent"]["active_voting_rights"], false);
    for index in 0..4 {
        lab.stop(index);
    }
    for index in 0..4 {
        lab.start(index);
    }
    lab.assert_same(&[0, 1, 2, 3], &settled);
    let retry = command(&registration_args);
    assert_eq!(retry["operation"], registration["operation"]);
    assert_eq!(retry["result"]["status"], "finalized");
    assert_eq!(lab.status(0).unwrap()["state"], settled["state"]);

    // Provision the finalized claimant as a separate process. Import consumes
    // the registered source keys only after its independent observer is durable.
    let recovery = lab.file("candidate-recovery.json");
    let endpoints = (0..8)
        .map(|offset| format!("127.0.0.1:{}", lab.base + offset))
        .collect::<Vec<_>>();
    fs::write(&recovery, serde_json::to_vec(&endpoints).unwrap()).unwrap();
    let candidate = lab.root.join("node-4");
    let provisioned = command(&[
        "candidate-setup".into(),
        path(&candidate),
        lab.file("genesis.bin"),
        lab.file("researcher-archive"),
        lab.key(6),
        family.clone(),
        consensus_key.clone(),
        transport_key.clone(),
        format!("127.0.0.1:{}", lab.base + 10),
        format!("127.0.0.1:{}", lab.base + 11),
        recovery,
    ]);
    assert_eq!(provisioned["status"], "candidate_provisioned");
    assert_eq!(provisioned["active_voting_rights"], false);
    assert!(!std::path::Path::new(&consensus_key).exists());
    assert!(!std::path::Path::new(&transport_key).exists());
    lab.start(4);
    lab.assert_same(&[4], &settled);
    // A new record gives the prepared candidate a canonical handoff point.
    lab.submit(
        active_ingress(&lab),
        5,
        example("question-b.nao"),
        "candidate-handoff",
    );
    let selected = lab.wait(0, |status| {
        status["validators"].as_array().is_some_and(|units| {
            units
                .iter()
                .any(|unit| unit["owner"] == author && unit["available"] == true)
        }) && status["consumed_claims"]
            .as_array()
            .is_some_and(|claims| claims.iter().any(|claim| claim == &family))
    });
    assert!(selected["authority"]["active_slots"].as_u64().unwrap() >= 3);
    assert_eq!(selected["join_queue"], serde_json::json!([]));
    // Other peers can seal the next period while this status is being read.
    // Require the same installed unit and consumed claim at or beyond the
    // selected height; the archive below verifies the exact selected state.
    for index in [0, 1, 3, 4] {
        let peer = lab.wait(index, |status| {
            status["height"].as_u64() >= selected["height"].as_u64()
                && status["consumed_claims"] == selected["consumed_claims"]
        });
        assert_eq!(
            stable_validator_slots(&peer),
            stable_validator_slots(&selected),
            "node {index}"
        );
        assert!(
            peer["validators"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unit| { unit["owner"] == author && unit["available"] == true })
        );
    }
    assert!(lab.status(4).unwrap()["consensus_position"].is_object());
    let selected_archive = lab.file("candidate-selected-archive");
    command(&["export".into(), lab.config(4), selected_archive.clone()]);
    let verified = command(&["verify".into(), lab.file("genesis.bin"), selected_archive]);
    assert!(verified["height"].as_u64() >= selected["height"].as_u64());
    assert_eq!(verified["consumed_claims"], selected["consumed_claims"]);
    assert_eq!(
        stable_validator_slots(&verified),
        stable_validator_slots(&selected)
    );
    assert!(
        verified["validators"]
            .as_array()
            .unwrap()
            .iter()
            .any(|unit| { unit["owner"] == author && unit["available"] == true })
    );

    // A valid handoff may leave any bootstrap slot vacant. Keep exactly two
    // currently selected bootstrap signers beside the installed claimant.
    // Every following 3-of-4 quorum must contain the claimant's signature.
    let bootstrap = {
        let start = Instant::now();
        loop {
            let height = lab.status(4).unwrap()["height"].as_u64().unwrap();
            let live: Vec<_> = (0..4)
                .filter(|index| {
                    lab.status(*index).is_some_and(|status| {
                        status["height"]
                            .as_u64()
                            .is_some_and(|peer_height| peer_height >= height)
                            && status["consensus_position"].is_object()
                    })
                })
                .take(2)
                .collect();
            if live.len() == 2 {
                break live;
            }
            assert!(
                start.elapsed() < Duration::from_secs(90),
                "two selected bootstrap signers did not catch up"
            );
            thread::sleep(Duration::from_millis(40));
        }
    };
    assert!(lab.status(4).unwrap()["consensus_position"].is_object());
    let stopped: Vec<_> = (0..4).filter(|index| !bootstrap.contains(index)).collect();
    for index in &stopped {
        lab.stop(*index);
    }
    let after_stop = lab.status(4).unwrap()["height"].as_u64().unwrap();
    // Supply substantive work before demanding the next record. An idle
    // proposal intentionally does not consume this finite run merely to
    // rotate period keys.
    let question = lab.file("successor-question.nao");
    fs::write(
        &question,
        "foundation = \"naome:zfc\"\nstatement = forall(z, forall(y, forall(x, equal(x, x))))\n",
    )
    .unwrap();
    let submission = lab.submit(
        active_ingress(&lab),
        4,
        PathBuf::from(question),
        "successor-service",
    );
    let successor = lab.wait(4, |status| {
        status["height"]
            .as_u64()
            .is_some_and(|height| height > after_stop)
            && status["validators"].as_array().is_some_and(|units| {
                units
                    .iter()
                    .any(|unit| unit["owner"] == author && unit["available"] == true)
            })
    });
    assert!(successor["consensus_position"].is_object());

    // The next completion pays the earned owner from the outgoing service
    // snapshot. Its author is a different account, making the service share
    // separately measurable.
    let solution = lab.file("successor-solution.nao");
    fs::write(
        &solution,
        "foundation = \"naome:zfc\"\nstatement = forall(z, forall(y, forall(x, equal(x, x))))\nproof:\n    p0 = equality_reflexivity(x)\n    p1 = generalization(p0, x)\n    p2 = generalization(p1, y)\n    p3 = generalization(p2, z)\n    return p3\n",
    )
    .unwrap();
    let package = lab.file("successor.package");
    command(&[
        "package".into(),
        lab.file("genesis.bin"),
        lab.key(4),
        package.clone(),
        solution,
    ]);
    lab.approve(
        &[bootstrap[0], bootstrap[1], 6],
        "successor-service",
        &submission,
    );
    lab.solve(
        active_ingress(&lab),
        4,
        &package,
        "successor-service",
        &submission,
    );
    let paid = lab.wait(4, |status| status["paid_completions"] == 2);
    let balance = |status: &Value| {
        status["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|account| account["account"] == author)
            .unwrap()["balance_atoms"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
    };
    assert_eq!(
        balance(&paid),
        balance(&selected) + genesis.profile().rewards().validator_atoms_each
    );
    let successor_archive = lab.file("successor-archive");
    command(&["export".into(), lab.config(4), successor_archive.clone()]);
    let verified = command(&[
        "verify".into(),
        lab.file("genesis.bin"),
        successor_archive.clone(),
    ]);
    assert_eq!(verified["paid_completions"], 2);
    assert!(archive_has_earned_owner_quorum_vote(
        &lab.file("genesis.bin"),
        &successor_archive,
        &author,
        after_stop,
    ));

    for index in 0..5 {
        lab.stop(index);
    }
    let mut restart = bootstrap.clone();
    restart.push(stopped[0]);
    restart.push(4);
    for index in &restart {
        lab.start(*index);
    }
    // Live validators may seal later periods while the processes restart. A
    // restart must recover the consumed claim and eventually give the new
    // owner a fresh selected key, even if an intervening slot was vacant.
    let resumed = lab.wait(4, |status| {
        status["height"].as_u64() > selected["height"].as_u64()
            && status["consumed_claims"]
                .as_array()
                .is_some_and(|claims| claims.iter().any(|claim| claim == &family))
            && status["validators"].as_array().is_some_and(|units| {
                units
                    .iter()
                    .any(|unit| unit["owner"] == author && unit["available"] == true)
            })
    });
    for index in restart.iter().copied().filter(|index| *index != 4) {
        let peer = lab.wait(index, |status| {
            status["height"].as_u64() >= resumed["height"].as_u64()
                && status["consumed_claims"] == resumed["consumed_claims"]
                && status["validators"].as_array().is_some_and(|units| {
                    units
                        .iter()
                        .any(|unit| unit["owner"] == author && unit["available"] == true)
                })
        });
        assert_eq!(
            stable_validator_slots(&peer),
            stable_validator_slots(&resumed)
        );
    }
    assert!(resumed["consensus_position"].is_object());
    assert!(!std::path::Path::new(&consensus_key).exists());
    assert!(!std::path::Path::new(&transport_key).exists());
    for index in restart {
        lab.stop(index);
    }
}
