use super::*;
use ed25519_dalek::SigningKey;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn portable_config_uses_its_own_directory_and_preserves_absolute_paths() {
    let dir = Directory::new();
    let mut config = dir.config();
    config.history = PathBuf::from("data/history");
    config.signer_anchor = PathBuf::from("anchors/signer");
    config.control_socket = PathBuf::from("control.sock");
    let path = dir.0.join("node.json");
    files::create(&path, &serde_json::to_vec(&config).unwrap(), true).unwrap();
    let relocated = dir.0.join("moved");
    files::directory(&relocated).unwrap();
    fs::rename(&path, relocated.join("node.json")).unwrap();
    let read = NodeConfig::read(&relocated.join("node.json")).unwrap();
    assert_eq!(
        read.history,
        relocated.canonicalize().unwrap().join("data/history")
    );
    assert_eq!(
        read.signer_anchor,
        relocated.canonicalize().unwrap().join("anchors/signer")
    );
    assert_eq!(
        read.control_socket,
        relocated.canonicalize().unwrap().join("control.sock")
    );
    assert_eq!(read.genesis, config.genesis);
    assert!(!read.history.exists());
    assert!(!read.signer_anchor.exists());
}

#[test]
fn custom_endpoints_do_not_require_reduced_work_or_signing_limits() {
    let dir = Directory::new();
    let plan = dir.0.join("endpoints.json");
    let endpoints = [
        "10.10.0.1:4100",
        "10.10.0.2:4100",
        "10.10.0.3:4100",
        "10.10.0.4:4100",
    ];
    fs::write(&plan, serde_json::to_vec(&endpoints).unwrap()).unwrap();
    let order = dir.0.join("retirement.json");
    fs::write(&order, b"[2,0,3,1]").unwrap();
    let mut args = vec![
        "unused".into(),
        "lab".into(),
        "128".into(),
        "44100".into(),
        order.to_str().unwrap().into(),
        "standard".into(),
        plan.to_str().unwrap().into(),
    ];
    let (standard, actual, retirement_order) = parameters(&args).unwrap();
    assert_eq!(retirement_order, [2, 0, 3, 1]);
    assert_eq!(actual, endpoints);
    assert_eq!(
        standard,
        Profile::with_limits(
            TimingKind::Lab,
            Limits {
                run_records: 128,
                ..Limits::default()
            }
        )
        .unwrap()
    );
    args[5] = "compact".into();
    let (compact, actual, _) = parameters(&args).unwrap();
    assert_eq!(actual, endpoints);
    assert_ne!(compact.id(), standard.id());
    assert!(compact.required_storage_bytes().unwrap() < standard.required_storage_bytes().unwrap());
    args.truncate(5);
    assert_eq!(parameters(&args).unwrap().0, standard);
    args[1] = "ci-test".into();
    let ci = parameters(&args).unwrap().0;
    assert_eq!(ci.kind(), TimingKind::CiTest);
    assert_eq!(ci.timing().voting_seconds, 1);
    assert_ne!(ci.id(), standard.id());
    args.push("unknown".into());
    assert!(parameters(&args).is_err());
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "nr-setup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        files::directory(&path).unwrap();
        Self(path)
    }
    fn config(&self) -> NodeConfig {
        NodeConfig {
            version: 5,
            primary_endpoint: "127.0.0.1:44000".into(),
            candidate_family: None,
            recovery_endpoints: vec!["127.0.0.1:44000".into(), "127.0.0.1:44004".into()],
            genesis: self.0.join("genesis.bin"),
            history: self.0.join("history"),
            history_anchor: self.0.join("history-anchor"),
            signer: self.0.join("signer"),
            signer_anchor: self.0.join("signer-anchor"),
            custody: self.0.join("custody"),
            custody_anchor: self.0.join("custody-anchor"),
            handoff: self.0.join("handoff"),
            handoff_anchor: self.0.join("handoff-anchor"),
            consensus_key: self.0.join("consensus.key"),
            transport_key: self.0.join("transport.key"),
            account_key: self.0.join("account.key"),
            agenda_profile: self.0.join("profile.txt"),
            control_socket: self.0.join("control.sock"),
            maximum_round: 8,
            simulation: true,
            listen_address: None,
            handoff_endpoint: "127.0.0.1:44004".into(),
            handoff_listen_address: None,
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn key(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

#[tokio::test]
async fn changing_local_agenda_profile_cannot_change_genesis_or_reinitialize_history() {
    let dir = Directory::new();
    let config = dir.config();
    let profile = Profile::with_limits(
        TimingKind::Lab,
        Limits {
            run_records: 256,
            record_bytes: 128 * 1024,
            package_bytes: 64 * 1024,
            transport_frame_bytes: 192 * 1024,
            consensus_rounds: 8,
            ..Limits::default()
        },
    )
    .unwrap();
    let accounts = (1..=4).map(key).collect::<Vec<_>>();
    let validators: Vec<_> = (0..4)
        .map(|i| ValidatorRegistration {
            owner: AccountId::for_key(&accounts[i]),
            consensus_key: key(101 + i as u8),
            transport_key: key(201 + i as u8),
            endpoint: format!("127.0.0.1:{}", 43000 + i),
        })
        .collect();
    let retirement_order = [2, 0, 3, 1].map(|i| validators[i].id()).to_vec();
    let genesis = Genesis::new(
        profile,
        "naome:zfc".into(),
        STATE_CHECKER_PROFILE.into(),
        naome_ledger::profile::STATE_PROTOCOL_VERSION,
        100,
        [42; 32],
        accounts,
        validators,
        retirement_order,
    )
    .unwrap();
    let original = genesis.encode();
    files::create(&config.genesis, &original, false).unwrap();
    files::create(&config.agenda_profile, b"original agenda", true).unwrap();
    let config_file = dir.0.join("node.json");
    files::create(&config_file, &serde_json::to_vec(&config).unwrap(), true).unwrap();
    let source = dir.0.join("new-profile.txt");
    files::create(&source, b"Prioritize reusable foundational results.", false).unwrap();
    super::super::run(vec![
        "profile".into(),
        config_file.to_str().unwrap().into(),
        source.to_str().unwrap().into(),
    ])
    .await
    .unwrap();
    assert_eq!(
        files::read(&config.agenda_profile, 16384, true).unwrap(),
        b"Prioritize reusable foundational results."
    );
    assert_eq!(config.genesis().unwrap().id(), genesis.id());
    assert_eq!(
        config.genesis().unwrap().profile().id(),
        genesis.profile().id()
    );
    assert_eq!(
        files::read(&config.genesis, 16384, false).unwrap(),
        original
    );
    let empty = dir.0.join("empty-profile.txt");
    files::create(&empty, b" \n", false).unwrap();
    assert!(
        super::super::run(vec![
            "profile".into(),
            config_file.to_str().unwrap().into(),
            empty.to_str().unwrap().into()
        ])
        .await
        .is_err()
    );
    assert_eq!(
        files::read(&config.agenda_profile, 16384, true).unwrap(),
        b"Prioritize reusable foundational results."
    );
    assert!(
        run(&[
            dir.0.to_str().unwrap().into(),
            "lab".into(),
            "256".into(),
            "43000".into(),
            "compact".into()
        ])
        .is_err()
    );
    assert_eq!(
        files::read(&config.genesis, 16384, false).unwrap(),
        original
    );
}

#[test]
fn node_configuration_rejects_unknown_fields_versions_and_public_permissions() {
    let dir = Directory::new();
    let config = dir.config();
    let valid = dir.0.join("valid.json");
    files::create(&valid, &serde_json::to_vec(&config).unwrap(), true).unwrap();
    assert_eq!(NodeConfig::read(&valid).unwrap().maximum_round, 8);
    for (name, field, value) in [
        ("extra", "unknown", serde_json::json!(true)),
        ("version", "version", serde_json::json!(1)),
        ("round", "maximum_round", serde_json::json!(0)),
    ] {
        let mut body = serde_json::to_value(&config).unwrap();
        body[field] = value;
        let path = dir.0.join(name);
        files::create(&path, &serde_json::to_vec(&body).unwrap(), true).unwrap();
        assert!(NodeConfig::read(&path).is_err());
    }
    // Updating only a version number cannot reinterpret the old profile field.
    let mut old = serde_json::to_value(&config).unwrap();
    let profile = old
        .as_object_mut()
        .unwrap()
        .remove("agenda_profile")
        .unwrap();
    old["research_profile"] = profile;
    for version in [1, 2] {
        old["version"] = serde_json::json!(version);
        let bytes = serde_json::to_vec(&old).unwrap();
        let path = dir.0.join(format!("old-profile-{version}"));
        files::create(&path, &bytes, true).unwrap();
        assert!(NodeConfig::read(&path).is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    fs::set_permissions(&valid, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(NodeConfig::read(&valid).is_err());
}

#[test]
fn explicit_peer_endpoints_are_genesis_bound_and_invalid_plans_create_no_state() {
    let dir = Directory::new();
    let plan = dir.0.join("endpoints.json");
    let output = dir.0.join("run");
    let order = dir.0.join("retirement.json");
    fs::write(&order, b"[2,0,3,1]").unwrap();
    let args = vec![
        output.to_str().unwrap().into(),
        "short-test".into(),
        "160".into(),
        "44100".into(),
        order.to_str().unwrap().into(),
        "compact".into(),
        plan.to_str().unwrap().into(),
    ];
    for endpoints in [
        vec!["127.0.0.1:1"; 4],
        vec!["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", "0.0.0.0:4"],
        vec!["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", "127.0.0.1:0"],
        vec!["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", "example.org:4"],
        vec!["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"],
        vec![
            "127.0.0.1:1",
            "127.0.0.1:2",
            "127.0.0.1:3",
            "[0:0:0:0:0:0:0:1]:4",
        ],
        vec![
            "127.0.0.1:1",
            "127.0.0.1:2",
            "127.0.0.1:3",
            "[::ffff:127.0.0.1]:4",
        ],
        vec!["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", "[fe80::1%1]:4"],
    ] {
        fs::write(&plan, serde_json::to_vec(&endpoints).unwrap()).unwrap();
        assert!(run(&args).is_err());
        assert!(!output.exists());
    }
    let expected = [
        "172.30.88.10:4200",
        "172.30.88.11:4200",
        "172.30.88.12:4200",
        "172.30.88.13:4200",
    ];
    fs::write(&plan, serde_json::to_vec(&expected).unwrap()).unwrap();
    for invalid_order in [
        b"[0,1,2,2]".as_slice(),
        b"[0,1,2,4]",
        b"[0,1,2]",
        b"[0,1,2,3,4]",
        b"[0,1,2,\"3\"]",
    ] {
        fs::write(&order, invalid_order).unwrap();
        assert!(run(&args).is_err());
        assert!(!output.exists());
    }
    fs::write(&order, b"[2,0,3,1]").unwrap();
    let mut omitted = args.clone();
    omitted.remove(4);
    assert!(run(&omitted).is_err());
    assert!(!output.exists());
    let symlink = dir.0.join("endpoints-link.json");
    std::os::unix::fs::symlink(&plan, &symlink).unwrap();
    let mut invalid = args.clone();
    invalid[6] = symlink.to_str().unwrap().into();
    assert!(run(&invalid).is_err());
    assert!(!output.exists());
    invalid = args.clone();
    invalid[2] = "0".into();
    assert!(run(&invalid).is_err());
    assert!(!output.exists());
    run(&args).unwrap();
    let key_path = output.join("node-0/consensus.key");
    let original_key = fs::read(&key_path).unwrap();
    assert_eq!(
        fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(run(&args).is_err());
    assert_eq!(fs::read(&key_path).unwrap(), original_key);
    assert!(
        !fs::read(output.join("genesis.bin"))
            .unwrap()
            .windows(32)
            .any(|part| part == &original_key[9..])
    );
    for index in 0..4 {
        let config = NodeConfig::read(&output.join(format!("node-{index}/node.json"))).unwrap();
        let genesis = config.genesis().unwrap();
        let history = naome_storage::state::StateHistory::open(
            &config.history,
            &config.history_anchor,
            genesis.clone(),
            config.maximum_round,
        )
        .unwrap();
        assert_eq!(history.head().unwrap().state().height(), 0);
        let signer = naome_storage::state::StateSigner::open(
            &config.signer,
            &config.signer_anchor,
            genesis,
            files::key(&config.consensus_key, 2).unwrap(),
            config.maximum_round,
        )
        .unwrap();
        drop(signer);
    }
    let genesis = Genesis::decode(&fs::read(output.join("genesis.bin")).unwrap()).unwrap();
    let selected = [2, 0, 3, 1].map(|index| {
        let key = files::key(&output.join(format!("node-{index}/consensus.key")), 2).unwrap();
        naome_ledger::ValidatorId::for_key(key.verifying_key().as_bytes())
    });
    assert_eq!(genesis.retirement_order(), &selected);
    let actual = genesis
        .validators()
        .iter()
        .map(|v| v.endpoint.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected.into_iter().collect());
    let config_path = output.join("node-0/node.json");
    let config = NodeConfig::read(&config_path).unwrap();
    assert_eq!(config.listen_address, None);
    let bytes = genesis.encode();
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    value["listen_address"] = serde_json::json!("127.0.0.1:4100");
    fs::write(&config_path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        NodeConfig::read(&config_path)
            .unwrap()
            .listen_address
            .unwrap()
            .to_string(),
        "127.0.0.1:4100"
    );
    assert_eq!(fs::read(output.join("genesis.bin")).unwrap(), bytes);
}
