//! Supplemental control-boundary tests; the independent process suite exercises
//! actual consensus. These tests inspect files at the instant of transmission.
use super::*;
use ed25519_dalek::SigningKey;
use naome_ledger::profile::{Profile, RESEARCH_CHECKER_PROFILE, ValidatorRegistration};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::net::UnixListener;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    config: NodeConfig,
    config_path: PathBuf,
    genesis: Genesis,
    key: SigningKey,
    package: ProofPackage,
    package_path: PathBuf,
    secret: PathBuf,
    action: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "nr-act-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        files::directory(&root).unwrap();
        let account_key = root.join("account.key");
        let key = files::write_key(&account_key, 1).unwrap();
        let mut accounts = vec![key.verifying_key().to_bytes()];
        accounts
            .extend((1..4).map(|i| SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes()));
        let validators = (0..4)
            .map(|i| ValidatorRegistration {
                owner: AccountId::for_key(&accounts[i]),
                consensus_key: SigningKey::from_bytes(&[100 + i as u8; 32])
                    .verifying_key()
                    .to_bytes(),
                transport_key: SigningKey::from_bytes(&[200 + i as u8; 32])
                    .verifying_key()
                    .to_bytes(),
                endpoint: format!("127.0.0.1:{}", 44000 + i),
            })
            .collect();
        let genesis = Genesis::new(
            Profile::short_test(),
            "naome:zfc".into(),
            RESEARCH_CHECKER_PROFILE.into(),
            1,
            100,
            [8; 32],
            accounts,
            validators,
        )
        .unwrap();
        let config = NodeConfig {
            version: 1,
            genesis: root.join("genesis.bin"),
            history: root.join("history"),
            history_anchor: root.join("history-anchor"),
            signer: root.join("signer"),
            signer_anchor: root.join("signer-anchor"),
            consensus_key: root.join("consensus.key"),
            transport_key: root.join("transport.key"),
            account_key,
            research_profile: root.join("profile.txt"),
            control_socket: root.join("control.sock"),
            maximum_round: 64,
            simulation: true,
        };
        files::create(&config.genesis, &genesis.encode(), false).unwrap();
        let config_path = root.join("node.json");
        files::create(&config_path, &serde_json::to_vec(&config).unwrap(), true).unwrap();
        let checked = naome_authoring::compile("foundation = \"naome:zfc\"\nstatement = forall(x,equal(x,x))\nproof:\n    p0 = equality_reflexivity(x)\n    p1 = generalization(p0,x)\n    return p1\n").unwrap();
        let package = ProofPackage::new(
            AccountId::for_key(key.verifying_key().as_bytes()),
            checked.proof_id(),
            vec![(checked.proof_id(), checked.canonical_proof_bytes().to_vec())],
            genesis.profile(),
        )
        .unwrap();
        let package_path = root.join("original.package");
        files::create(&package_path, &package.encode().unwrap(), false).unwrap();
        let secret_directory = root.join("secrets");
        files::directory(&secret_directory).unwrap();
        Self {
            secret: secret_directory.join("commit.secret"),
            action: root.join("actions/commit.action"),
            root,
            config,
            config_path,
            genesis,
            key,
            package,
            package_path,
        }
    }
    fn round(&self) -> SolutionRoundId {
        SolutionRoundId::from_bytes([19; 32])
    }
    fn author(&self) -> AccountId {
        AccountId::for_key(self.key.verifying_key().as_bytes())
    }
    fn status(&self, phase: &str, nonce: u64) -> Value {
        json!({"genesis":files::hex(self.genesis.id().as_bytes()),"active":{"phase":phase,"round":files::hex(self.round().as_bytes())},"accounts":[{"account":files::hex(self.author().as_bytes()),"next_nonce":nonce}]})
    }
    fn args(&self, command: &str, action: &Path) -> Vec<String> {
        let mut args = vec![
            command.into(),
            self.config_path.to_str().unwrap().into(),
            self.config.account_key.to_str().unwrap().into(),
        ];
        if command == "commit" {
            args.push(self.package_path.to_str().unwrap().into());
        }
        args.push(self.secret.to_str().unwrap().into());
        args.push(action.to_str().unwrap().into());
        args
    }
    fn bundle(&self) -> SecretBundle {
        let original =
            SignedOriginal::sign(&self.genesis, self.round(), self.package.clone(), &self.key)
                .unwrap();
        let secret = Zeroizing::new([23; 32]);
        let commitment = CommitmentId::for_original(
            &self.genesis,
            self.round(),
            self.author(),
            original.original_hash(),
            &secret,
        );
        let commit = OperationBody::Commit {
            round: self.round(),
            commitment,
        }
        .sign(&self.genesis, 7, &self.key)
        .unwrap();
        SecretBundle {
            round: self.round(),
            secret,
            original,
            commit,
        }
    }
    fn listener(&self) -> UnixListener {
        if self.config.control_socket.exists() {
            fs::remove_file(&self.config.control_socket).unwrap();
        }
        UnixListener::bind(&self.config.control_socket).unwrap()
    }
}

async fn request(listener: &UnixListener) -> (tokio::net::UnixStream, Request) {
    let (mut stream, _) =
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
    let request = serde_json::from_slice(&control::read(&mut stream).await.unwrap()).unwrap();
    (stream, request)
}
async fn respond(stream: &mut tokio::net::UnixStream, value: Value) {
    control::write(stream, &serde_json::to_vec(&value).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn commit_secret_precedes_transmission_and_missing_action_or_lost_ack_reuses_exact_intent() {
    let fixture = Fixture::new();
    // The separate action directory deliberately does not exist. The new
    // commitment stops after synchronizing its secret, before any Submit.
    let listener = fixture.listener();
    let status = fixture.status("Commit", 7);
    let server = tokio::spawn(async move {
        let (mut stream, message) = request(&listener).await;
        assert!(matches!(message, Request::Status));
        respond(&mut stream, status).await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    assert!(run(&fixture.args("commit", &fixture.action)).await.is_err());
    server.await.unwrap();
    assert!(!fixture.action.exists());
    let secret_bytes = files::read(&fixture.secret, 65536, true).unwrap();
    let expected = SecretBundle::read(&fixture.secret, &fixture.genesis, fixture.author())
        .unwrap()
        .commit
        .encode();
    assert_eq!(
        fs::metadata(&fixture.secret).unwrap().permissions().mode() & 0o077,
        0
    );
    files::directory(fixture.action.parent().unwrap()).unwrap();

    for acknowledge in [false, true] {
        let listener = fixture.listener();
        let secret = fixture.secret.clone();
        let action = fixture.action.clone();
        let sent = expected.clone();
        let original_secret = secret_bytes.clone();
        let server = tokio::spawn(async move {
            let (mut stream, message) = request(&listener).await;
            let Request::Submit { bytes } = message else {
                panic!("retry must not request a new nonce or phase")
            };
            assert_eq!(bytes, files::hex(&sent));
            assert_eq!(files::read(&secret, 65536, true).unwrap(), original_secret);
            assert_eq!(files::read(&action, 65536, true).unwrap(), sent);
            if acknowledge {
                respond(
                    &mut stream,
                    json!({"status":"finalized","height":9,"operation_index":0}),
                )
                .await;
            }
        });
        let result = run(&fixture.args("commit", &fixture.action)).await;
        assert_eq!(result.is_ok(), acknowledge);
        server.await.unwrap();
        assert_eq!(files::read(&fixture.action, 65536, true).unwrap(), expected);
        assert_eq!(SignedOperation::decode(&expected).unwrap().nonce(), 7);
    }
}

#[tokio::test]
async fn retained_reveal_after_lost_ack_resends_without_open_phase_or_new_nonce() {
    let fixture = Fixture::new();
    let bundle = fixture.bundle();
    files::create(
        &fixture.secret,
        &bundle.encode(&fixture.genesis).unwrap(),
        true,
    )
    .unwrap();
    let reveal = fixture.root.join("reveal.action");
    let listener = fixture.listener();
    let status = fixture.status("Reveal", 8);
    let secret = fixture.secret.clone();
    let action = reveal.clone();
    let server = tokio::spawn(async move {
        let (mut stream, message) = request(&listener).await;
        assert!(matches!(message, Request::Status));
        respond(&mut stream, status).await;
        let (_stream, message) = request(&listener).await;
        let Request::Submit { bytes } = message else {
            panic!("expected reveal submission")
        };
        assert!(secret.exists());
        let saved = files::read(&action, 65536, true).unwrap();
        assert_eq!(bytes, files::hex(&saved));
        saved // Deliberately close without acknowledging the transported reveal.
    });
    assert!(run(&fixture.args("reveal", &reveal)).await.is_err());
    let expected = server.await.unwrap();
    assert_eq!(SignedOperation::decode(&expected).unwrap().nonce(), 8);
    let listener = fixture.listener();
    let sent = expected.clone();
    let server = tokio::spawn(async move {
        let (mut stream, message) = request(&listener).await;
        let Request::Submit { bytes } = message else {
            panic!("closed-phase retry must submit its retained action directly")
        };
        assert_eq!(bytes, files::hex(&sent));
        respond(
            &mut stream,
            json!({"status":"finalized","height":12,"operation_index":0}),
        )
        .await;
    });
    run(&fixture.args("reveal", &reveal)).await.unwrap();
    server.await.unwrap();
    assert_eq!(files::read(&reveal, 65536, true).unwrap(), expected);
}

#[tokio::test]
async fn mismatched_private_bundle_author_genesis_secret_or_retained_reveal_never_transmits() {
    let fixture = Fixture::new();
    let bundle = fixture.bundle();
    let bytes = bundle.encode(&fixture.genesis).unwrap();
    files::create(&fixture.secret, &bytes, true).unwrap();
    assert!(
        SecretBundle::read(
            &fixture.secret,
            &fixture.genesis,
            AccountId::for_key(SigningKey::from_bytes(&[1; 32]).verifying_key().as_bytes())
        )
        .is_err()
    );
    for offset in [8, 72, bytes.len() - 1] {
        let mut altered = bytes.to_vec();
        altered[offset] ^= 1;
        let path = fixture.root.join(format!("mismatch-{offset}.secret"));
        files::create(&path, &altered, true).unwrap();
        assert!(SecretBundle::read(&path, &fixture.genesis, fixture.author()).is_err());
    }
    let reveal = fixture.root.join("wrong-reveal.action");
    let wrong = OperationBody::Reveal {
        round: bundle.round,
        secret: [24; 32],
        original: bundle.original,
    }
    .sign(&fixture.genesis, 8, &fixture.key)
    .unwrap();
    files::create(&reveal, &wrong.encode(), true).unwrap();
    let listener = fixture.listener();
    assert!(run(&fixture.args("reveal", &reveal)).await.is_err());
    let mut args = fixture.args("commit", &fixture.action);
    let other_key = fixture.root.join("other.key");
    files::write_key(&other_key, 1).unwrap();
    args[2] = other_key.to_str().unwrap().into();
    assert!(run(&args).await.is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    assert!(!fixture.action.exists());
}
