use super::*;
use ed25519_dalek::SigningKey;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
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
            version: 1,
            genesis: self.0.join("genesis.bin"),
            history: self.0.join("history"),
            history_anchor: self.0.join("history-anchor"),
            signer: self.0.join("signer"),
            signer_anchor: self.0.join("signer-anchor"),
            consensus_key: self.0.join("consensus.key"),
            transport_key: self.0.join("transport.key"),
            account_key: self.0.join("account.key"),
            research_profile: self.0.join("profile.txt"),
            control_socket: self.0.join("control.sock"),
            maximum_round: 8,
            simulation: true,
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
    let validators = (0..4)
        .map(|i| ValidatorRegistration {
            owner: AccountId::for_key(&accounts[i]),
            consensus_key: key(101 + i as u8),
            transport_key: key(201 + i as u8),
            endpoint: format!("127.0.0.1:{}", 43000 + i),
        })
        .collect();
    let genesis = Genesis::new(
        profile,
        "naome:zfc".into(),
        RESEARCH_CHECKER_PROFILE.into(),
        1,
        100,
        [42; 32],
        accounts,
        validators,
    )
    .unwrap();
    let original = genesis.encode();
    files::create(&config.genesis, &original, false).unwrap();
    files::create(&config.research_profile, b"original agenda", true).unwrap();
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
        files::read(&config.research_profile, 16384, true).unwrap(),
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
        files::read(&config.research_profile, 16384, true).unwrap(),
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
        ("version", "version", serde_json::json!(2)),
        ("round", "maximum_round", serde_json::json!(0)),
    ] {
        let mut body = serde_json::to_value(&config).unwrap();
        body[field] = value;
        let path = dir.0.join(name);
        files::create(&path, &serde_json::to_vec(&body).unwrap(), true).unwrap();
        assert!(NodeConfig::read(&path).is_err());
    }
    fs::set_permissions(&valid, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(NodeConfig::read(&valid).is_err());
}
