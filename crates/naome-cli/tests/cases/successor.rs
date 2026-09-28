use super::*;

/// Slow local process qualification: four independent validator processes
/// finish one paid run, restart from the terminal bridge, and cite its proof.
#[test]
#[ignore = "runs a complete terminal-to-successor four-process scenario"]
fn paid_proof_survives_terminal_successor_and_is_cited_once() {
    let _guard = process_guard();
    // One ordinary admission record plus the protected completion and terminal
    // reservation. With 65, admission itself consumes the ability to open.
    let mut lab = Lab::new_with_records(66);
    let first_package = lab.file("first.package");
    command(&[
        "package".into(),
        lab.file("genesis.bin"),
        lab.key(4),
        first_package.clone(),
        path(example("solution-a.nao")),
        "--helper".into(),
        path(example("helper-h.nao")),
    ]);
    for index in 0..4 {
        lab.start(index);
    }
    for index in 0..4 {
        lab.wait(index, |status| status["height"] == 0);
    }
    let first = lab.submit(0, 4, example("question-a.nao"), "first");
    lab.approve(&[0, 1, 2], "first", &first);
    lab.solve(0, 4, &first_package, "first", &first);
    let paid = lab.wait(0, |status| status["paid_completions"] == 1);
    let first_balance = paid["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["account"] == paid["claims"][0]["author"])
        .unwrap()["balance_atoms"]
        .clone();
    let terminal = lab.wait(0, |status| status["terminated"] == true);
    lab.assert_same(&[0, 1, 2, 3], &terminal);
    let predecessor = lab.file("predecessor-archive");
    command(&["export".into(), lab.config(0), predecessor.clone()]);
    let verified = command(&[
        "verify".into(),
        lab.file("genesis.bin"),
        predecessor.clone(),
    ]);
    assert_eq!(verified["terminated"], true);
    for index in 0..4 {
        lab.stop(index);
    }
    let old_config = (0..4).map(|index| lab.config(index)).collect::<Vec<_>>();
    let mut next_config = Vec::new();
    for (index, config) in old_config.iter().enumerate() {
        let dir = lab.file(&format!("successor-{index}"));
        let result = command(&[
            "continue-node".into(),
            config.clone(),
            predecessor.clone(),
            dir.clone(),
        ]);
        assert_eq!(result["signer_ready"], true);
        next_config.push(path(Path::new(&dir).join("node.json")));
    }
    let resumed = command(&[
        "continue-node".into(),
        old_config[0].clone(),
        predecessor.clone(),
        lab.file("successor-0"),
    ]);
    assert_eq!(resumed["signer_ready"], true);
    lab.successor_configs = Some(next_config);
    for index in 0..4 {
        lab.start(index);
    }
    let opening = lab.wait(0, |status| status["paid_completions"] == 1);
    for index in 1..4 {
        lab.wait(index, |status| status["paid_completions"] == 1);
    }
    assert_eq!(opening["paid_completions"], 1);
    assert_eq!(opening["proof_count"], paid["proof_count"]);
    assert_eq!(opening["reserve_atoms"], terminal["reserve_atoms"]);
    assert_eq!(opening["accounts"], terminal["accounts"]);
    assert_eq!(opening["claims"], terminal["claims"]);
    let historical = command(&["question".into(), lab.config(0), first.clone()]);
    assert_eq!(historical["status"], "Completed");
    assert!(historical["normalization"]["recorded_sha256"].is_string());
    assert!(
        !raw(&["send".into(), lab.config(0), lab.file("first.submit")])
            .status
            .success()
    );
    lab.stop(0);
    lab.start(0);
    lab.wait(0, |status| status["paid_completions"] == 1);
    let helper =
        naome_authoring::compile(&fs::read_to_string(example("helper-h.nao")).unwrap()).unwrap();
    let helper_id = helper
        .proof_id()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let proof = lab.file("predecessor-helper.proof");
    command(&[
        "fetch-proof".into(),
        lab.config(0),
        helper_id,
        proof.clone(),
    ]);
    let second_package = lab.file("second.package");
    command(&[
        "package".into(),
        path(Path::new(&lab.file("successor-0")).join("genesis.bin")),
        lab.key(5),
        second_package.clone(),
        path(example("solution-b-original.nao")),
        "--reference".into(),
        proof,
        "--helper".into(),
        path(example("helper-h-duplicate.nao")),
    ]);
    let second = lab.submit(0, 5, example("question-b.nao"), "second");
    lab.approve(&[0, 1, 2], "second", &second);
    lab.solve(0, 5, &second_package, "second", &second);
    let cited = lab.wait(0, |status| status["paid_completions"] == 2);
    assert_eq!(cited["claims"].as_array().unwrap().len(), 2);
    let cited_first_balance = cited["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["account"] == paid["claims"][0]["author"])
        .unwrap()["balance_atoms"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let opening_genesis =
        naome_ledger::profile::Genesis::decode(&fs::read(lab.file("genesis.bin")).unwrap())
            .unwrap();
    assert_eq!(
        u128::from(cited_first_balance),
        first_balance.as_str().unwrap().parse::<u128>().unwrap()
            + opening_genesis.profile().rewards().citation_pool_atoms,
        "the predecessor family earns only its new citation payment"
    );
    let successor_archive = lab.file("successor-archive");
    command(&["export".into(), lab.config(0), successor_archive.clone()]);
    for index in 0..4 {
        lab.stop(index);
    }
    let lineage = command(&[
        "verify-lineage".into(),
        lab.file("genesis.bin"),
        predecessor.clone(),
        path(Path::new(&lab.file("successor-0")).join("genesis.bin")),
        successor_archive.clone(),
    ]);
    assert_eq!(lineage["runs"], 2);
    assert_eq!(lineage["paid_completions"], 2);
    let inspected = command(&[
        "inspect-lineage".into(),
        lab.file("genesis.bin"),
        predecessor.clone(),
        path(Path::new(&lab.file("successor-0")).join("genesis.bin")),
        successor_archive.clone(),
        second,
        lab.file("successor-inspection"),
    ]);
    assert_eq!(inspected["status"], "Completed");
    let inspected_old = command(&[
        "inspect-lineage".into(),
        lab.file("genesis.bin"),
        predecessor.clone(),
        path(Path::new(&lab.file("successor-0")).join("genesis.bin")),
        successor_archive.clone(),
        first,
        lab.file("predecessor-inspection-from-successor"),
    ]);
    assert_eq!(inspected_old["status"], "Completed");
    assert!(inspected_old["normalization"]["recorded_sha256"].is_string());
    let predecessor_frame = Path::new(&predecessor).join("00000001.finality");
    let original = fs::read(&predecessor_frame).unwrap();
    let mut altered = original.clone();
    altered[0] ^= 1;
    fs::write(&predecessor_frame, altered).unwrap();
    assert!(
        !raw(&[
            "verify-lineage".into(),
            lab.file("genesis.bin"),
            predecessor.clone(),
            path(Path::new(&lab.file("successor-0")).join("genesis.bin")),
            successor_archive.clone(),
        ])
        .status
        .success()
    );
    fs::write(&predecessor_frame, original).unwrap();
    fs::remove_file(&predecessor_frame).unwrap();
    assert!(
        !raw(&[
            "verify-lineage".into(),
            lab.file("genesis.bin"),
            predecessor,
            path(Path::new(&lab.file("successor-0")).join("genesis.bin")),
            successor_archive,
        ])
        .status
        .success()
    );
}
