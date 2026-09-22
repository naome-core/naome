use super::*;

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
            lab.config(0),
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
        lab.config(0),
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
    assert_eq!(joined["validators"], initial["validators"]);
    lab.assert_same(&[0, 1, 2, 3], &joined);
    for retry in [
        registration_args.to_vec(),
        vec!["send".into(), lab.config(0), lab.file("register.action")],
    ] {
        let receipt = command(&retry);
        assert_eq!(receipt["operation"], registration["operation"]);
        assert_eq!(receipt["result"]["status"], "finalized");
        assert_eq!(receipt["result"]["height"], joined["height"]);
    }
    let submission = lab.submit(0, 6, example("question-a.nao"), "researcher");
    lab.wait_phase(0, &submission, "Voting");
    assert!(
        !raw(&[
            "vote".into(),
            lab.config(0),
            lab.key(6),
            "YES".into(),
            lab.file("researcher.vote"),
        ])
        .status
        .success(),
        "registration must not grant validator agenda votes"
    );
    lab.approve(&[0, 1, 2], "researcher", &submission);
    lab.solve(0, 6, &package, "researcher", &submission);
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
    assert_eq!(settled["validators"], initial["validators"]);
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
        lab.config(0),
        lab.key(6),
        family,
        consensus_key,
        transport_key,
        format!("127.0.0.1:{}", lab.base + 10),
        intent_action.clone(),
    ]);
    assert_eq!(prepared["status"], "join_intent_prepared");
    assert_eq!(prepared["active_voting_rights"], false);
    command(&["send".into(), lab.config(0), intent_action.clone()]);
    let settled = lab.wait(0, |s| s["join_intents_count"] == 1);
    lab.assert_same(&[0, 1, 2, 3], &settled);
    assert_eq!(settled["validators"], initial["validators"]);
    let exact_retry = command(&["send".into(), lab.config(0), intent_action]);
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
    assert_eq!(inspected["join_intent"]["status"], "PENDING_NO_AUTHORITY");
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
    for index in 0..4 {
        lab.stop(index);
    }
}
