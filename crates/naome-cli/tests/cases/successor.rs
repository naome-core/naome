use super::*;
use std::net::TcpListener;

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
    let available = TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway_address = available.local_addr().unwrap().to_string();
    drop(available);
    let successor_genesis = path(Path::new(&lab.file("successor-0")).join("genesis.bin"));
    let mut gateway = Command::new(BIN)
        .args([
            "gateway",
            "serve",
            &successor_genesis,
            &lab.file("successor-0/control.sock"),
            &gateway_address,
        ])
        .stdout(File::create(lab.root.join("result-gateway.log")).unwrap())
        .stderr(File::create(lab.root.join("result-gateway.errors")).unwrap())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !raw(&["gateway".into(), "results".into(), gateway_address.clone()])
        .status
        .success()
    {
        assert!(started.elapsed() < Duration::from_secs(10));
        thread::sleep(Duration::from_millis(50));
    }
    let catalogue = command(&["gateway".into(), "results".into(), gateway_address.clone()]);
    assert_eq!(catalogue["items"][0]["submission"], first);
    let stale_cursor = catalogue["items"][0]["cursor"].as_str().unwrap().to_owned();
    let detail = command(&[
        "gateway".into(),
        "result".into(),
        gateway_address.clone(),
        first.clone(),
    ]);
    assert_eq!(detail["question_status"], "Completed");
    let root = detail["root_proof"].as_str().unwrap().to_owned();
    let participant_genesis = lab.file("result-client-genesis.bin");
    command(&[
        "gateway".into(),
        "genesis".into(),
        gateway_address.clone(),
        participant_genesis.clone(),
    ]);
    let proof_directory = lab.file("result-client-proofs");
    let downloaded = command(&[
        "gateway".into(),
        "download-proof".into(),
        gateway_address.clone(),
        participant_genesis.clone(),
        root.clone(),
        proof_directory.clone(),
    ]);
    assert_eq!(downloaded["root"], root);
    assert!(downloaded["dependency_order"].as_array().unwrap().len() >= 2);
    let mut check_args = vec![
        "check-proof".into(),
        participant_genesis,
        path(Path::new(&proof_directory).join(format!("{root}.proof"))),
    ];
    for id in downloaded["dependency_order"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
    {
        if id != root {
            check_args.push(path(
                Path::new(&proof_directory).join(format!("{id}.proof")),
            ));
        }
    }
    assert_eq!(command(&check_args)["proof"], root);
    assert!(
        raw(&[
            "gateway".into(),
            "result".into(),
            gateway_address.clone(),
            "zz".repeat(32)
        ])
        .status
        .code()
            != Some(0)
    );
    let helper =
        naome_authoring::compile(&fs::read_to_string(example("helper-h.nao")).unwrap()).unwrap();
    let helper_id = helper
        .proof_id()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let proof = lab.file("predecessor-helper.proof");
    fs::copy(
        Path::new(&proof_directory).join(format!("{helper_id}.proof")),
        &proof,
    )
    .unwrap();
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
    for index in 1..4 {
        lab.stop(index);
    }
    let stale = raw(&[
        "gateway".into(),
        "results".into(),
        gateway_address.clone(),
        stale_cursor,
    ]);
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("stale"));
    let first_page = command(&[
        "gateway".into(),
        "results".into(),
        gateway_address.clone(),
        "--limit".into(),
        "1".into(),
    ]);
    assert_eq!(first_page["items"].as_array().unwrap().len(), 1);
    let cursor = first_page["next_cursor"].as_str().unwrap().to_owned();
    let second_page = command(&[
        "gateway".into(),
        "results".into(),
        gateway_address.clone(),
        cursor,
        "--limit".into(),
        "1".into(),
    ]);
    let seen = [
        first_page["items"][0]["submission"].as_str().unwrap(),
        second_page["items"][0]["submission"].as_str().unwrap(),
    ];
    assert!(seen.contains(&first.as_str()) && seen.contains(&second.as_str()));
    assert!(second_page["next_cursor"].is_null());
    gateway.kill().unwrap();
    gateway.wait().unwrap();
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
