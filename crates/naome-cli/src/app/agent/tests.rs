//! Fake providers exercise adapter boundaries only; they are not AI evidence.
use super::*;
use ed25519_dalek::SigningKey;
use naome_ledger::profile::{Genesis, Profile, RESEARCH_CHECKER_PROFILE, ValidatorRegistration};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::UnixListener;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "nr-agent-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        files::directory(&path).unwrap();
        Self(path)
    }
    fn executable(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(name);
        files::create(
            &path,
            format!("#!/bin/sh\n/bin/cat >/dev/null\n{body}\n").as_bytes(),
            true,
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}
fn output(value: serde_json::Value) -> String {
    format!("printf '%s' {}", quoted(&value.to_string()))
}
fn decision() -> serde_json::Value {
    json!({"decision":"YES","reason":"supplementary adapter fixture","provider":"fake-test-provider","tool_calls":0})
}

#[tokio::test]
async fn fake_provider_accepts_only_bounded_complete_decisions() {
    let dir = Directory::new();
    let good = dir.executable("good", &output(decision()));
    assert_eq!(invoke(&good, b"{}", 2).await.unwrap().decision, "YES");
    let mut malformed = vec![
        json!({}),
        json!({"decision":"YES","reason":"x","provider":"fake","tool_calls":0,"extra":true}),
    ];
    for (field, value) in [
        ("decision", json!("MAYBE")),
        ("reason", json!(" ")),
        ("reason", json!("x".repeat(4097))),
        ("provider", json!("")),
        ("provider", json!("x".repeat(129))),
        ("tool_calls", json!(-1)),
    ] {
        let mut item = decision();
        item[field] = value;
        malformed.push(item);
    }
    for (index, value) in malformed.into_iter().enumerate() {
        let executable = dir.executable(&format!("bad-{index}"), &output(value));
        assert!(invoke(&executable, b"{}", 2).await.is_err());
    }
    let large = dir.executable(
        "oversized",
        &format!("printf '%s' {}", quoted(&"x".repeat(8193))),
    );
    assert!(
        invoke(&large, b"{}", 2)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("8192")
    );
    let failed = dir.executable("failed", &format!("{}\nexit 7", output(decision())));
    assert!(invoke(&failed, b"{}", 2).await.is_err());
}

#[tokio::test]
async fn fake_provider_timeout_does_not_accept_early_json_or_leave_late_children() {
    let dir = Directory::new();
    let early = dir.executable(
        "early",
        &format!("{}\nexec /bin/sleep 30", output(decision())),
    );
    assert!(
        invoke(&early, b"{}", 1)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("time limit")
    );
    let marker = dir.0.join("late-output");
    let late = dir.executable(
        "late",
        &format!(
            "(/bin/sleep 2; printf late > {}) &\nwait",
            quoted(marker.to_str().unwrap())
        ),
    );
    assert!(invoke(&late, b"{}", 1).await.is_err());
    tokio::time::sleep(Duration::from_millis(1400)).await;
    assert!(
        !marker.exists(),
        "timed-out provider descendants must not continue producing output"
    );
}

#[tokio::test]
async fn successful_provider_exit_still_terminates_its_remaining_process_group() {
    let dir = Directory::new();
    let marker = dir.0.join("orphan-output");
    let executable = dir.executable(
        "successful-with-child",
        &format!(
            "(/bin/sleep 1; printf late > {}) </dev/null >/dev/null 2>/dev/null &\n{}",
            quoted(marker.to_str().unwrap()),
            output(decision()),
        ),
    );
    assert_eq!(invoke(&executable, b"{}", 2).await.unwrap().decision, "YES");
    tokio::time::sleep(Duration::from_millis(1400)).await;
    assert!(
        !marker.exists(),
        "successful leader exit must not detach provider descendants"
    );
}

struct Fixture {
    directory: Directory,
    config: NodeConfig,
    key: PathBuf,
    config_file: PathBuf,
    status: serde_json::Value,
}
impl Fixture {
    fn new() -> Self {
        let directory = Directory::new();
        let root = &directory.0;
        let key = root.join("account.key");
        let owner = files::write_key(&key, 1).unwrap();
        let mut accounts = vec![owner.verifying_key().to_bytes()];
        accounts.extend((1..4).map(|seed| {
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes()
        }));
        let validators = (0..4)
            .map(|i| ValidatorRegistration {
                owner: AccountId::for_key(&accounts[i]),
                consensus_key: SigningKey::from_bytes(&[100 + i as u8; 32])
                    .verifying_key()
                    .to_bytes(),
                transport_key: SigningKey::from_bytes(&[200 + i as u8; 32])
                    .verifying_key()
                    .to_bytes(),
                endpoint: format!("127.0.0.1:{}", 42000 + i),
            })
            .collect();
        let genesis = Genesis::new(
            Profile::short_test(),
            "naome:zfc".into(),
            RESEARCH_CHECKER_PROFILE.into(),
            1,
            100,
            [9; 32],
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
            account_key: key.clone(),
            research_profile: root.join("research-profile.txt"),
            control_socket: root.join("control.sock"),
            maximum_round: 64,
            simulation: true,
            listen_address: None,
        };
        files::directory(&config.signer).unwrap();
        files::create(&config.genesis, &genesis.encode(), false).unwrap();
        files::create(
            &config.research_profile,
            b"Small reusable exact mathematical targets.",
            true,
        )
        .unwrap();
        let config_file = root.join("node.json");
        files::create(&config_file, &serde_json::to_vec(&config).unwrap(), true).unwrap();
        let status = json!({"genesis":files::hex(genesis.id().as_bytes()),"active":{
            "phase":"Voting","question":"11".repeat(32),"submission":"22".repeat(32),"attempt":1,
            "deadline":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()+60},
            "accounts":[{"account":files::hex(AccountId::for_key(owner.verifying_key().as_bytes()).as_bytes()),"next_nonce":1}]});
        Self {
            directory,
            config,
            key,
            config_file,
            status,
        }
    }
    fn server(&self, responses: Vec<serde_json::Value>) -> tokio::task::JoinHandle<Vec<Request>> {
        let listener = UnixListener::bind(&self.config.control_socket).unwrap();
        tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                requests.push(
                    serde_json::from_slice(&control::read(&mut stream).await.unwrap()).unwrap(),
                );
                control::write(&mut stream, &serde_json::to_vec(&response).unwrap())
                    .await
                    .unwrap();
            }
            requests
        })
    }
    fn args(&self, executable: &Path) -> Vec<String> {
        [
            self.config_file.clone(),
            self.key.clone(),
            self.directory.0.join("action.bin"),
            self.directory.0.join("report.json"),
            executable.to_path_buf(),
        ]
        .into_iter()
        .map(|p| p.to_str().unwrap().to_owned())
        .collect()
    }
    fn assert_no_vote_files(&self) {
        assert!(!self.directory.0.join("action.bin").exists());
        assert!(!self.directory.0.join("report.json").exists());
    }
}

#[tokio::test]
async fn changed_or_expired_voting_context_never_creates_a_signed_action() {
    for expired in [false, true] {
        let fixture = Fixture::new();
        let executable = fixture
            .directory
            .executable("provider", &output(decision()));
        let mut latest = fixture.status.clone();
        if expired {
            latest["active"]["deadline"] = json!(1);
        } else {
            latest["active"]["phase"] = json!("Commit");
        }
        let server = fixture.server(vec![
            fixture.status.clone(),
            json!({"source":"formal fixture","purpose":"test only"}),
            latest,
        ]);
        let result = run(&fixture.args(&executable)).await;
        assert!(result.is_err());
        fixture.assert_no_vote_files();
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 3);
        assert!(matches!(requests.last(), Some(Request::Status)));
    }
}

#[tokio::test]
async fn reported_tool_excess_exhausts_two_attempts_without_signing() {
    let fixture = Fixture::new();
    let attempts = fixture.directory.0.join("attempts");
    let mut response = decision();
    response["tool_calls"] = json!(5);
    let executable = fixture.directory.executable(
        "provider",
        &format!(
            "printf x >> {}\n{}",
            quoted(attempts.to_str().unwrap()),
            output(response)
        ),
    );
    let server = fixture.server(vec![
        fixture.status.clone(),
        json!({"source":"formal fixture","purpose":"test only"}),
        fixture.status.clone(),
        json!({"source":"formal fixture","purpose":"test only"}),
    ]);
    let result = run(&fixture.args(&executable)).await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("tool-call limit")
    );
    assert!(run(&fixture.args(&executable)).await.is_err());
    assert_eq!(fs::read(attempts).unwrap(), b"xx");
    fixture.assert_no_vote_files();
    assert_eq!(server.await.unwrap().len(), 4);
}

#[test]
fn durable_budget_reserves_before_calls_and_rejects_concurrent_or_changed_context() {
    let directory = Directory::new();
    let question = "11".repeat(32);
    let budget = budget::Budget::open(&directory.0, &question, 1, "context".into(), 2, 4).unwrap();
    assert!(budget::Budget::open(&directory.0, &question, 1, "context".into(), 2, 4).is_err());
    budget.reserve(1, 4, b"request").unwrap();
    drop(budget);
    let budget = budget::Budget::open(&directory.0, &question, 1, "context".into(), 2, 4).unwrap();
    let (used, tools, result) = budget.load().unwrap();
    assert_eq!((used, tools), (1, 0));
    assert!(result.is_none());
    let request = budget.reserve(2, 0, b"retry").unwrap();
    budget
        .complete(2, request, serde_json::from_value(decision()).unwrap(), 10)
        .unwrap();
    assert_eq!(budget.load().unwrap().2.unwrap().index, 2);
    drop(budget);
    let changed = budget::Budget::open(&directory.0, &question, 1, "changed".into(), 2, 4).unwrap();
    assert!(changed.load().is_err());
}

#[tokio::test]
async fn retained_vote_retry_submits_identical_bytes_without_provider_or_new_nonce() {
    let fixture = Fixture::new();
    let calls = fixture.directory.0.join("provider-calls");
    let executable = fixture.directory.executable(
        "provider",
        &format!(
            "printf x >> {}\n{}",
            quoted(calls.to_str().unwrap()),
            output(decision())
        ),
    );
    let server = fixture.server(vec![
        fixture.status.clone(),
        json!({"source":"formal fixture","purpose":"test only"}),
        fixture.status.clone(),
        json!({"status":"pending"}),
        json!({"status":"finalized"}),
    ]);
    let mut args = fixture.args(&executable);
    run(&args).await.unwrap();
    let first = files::read(Path::new(&args[2]), 65536, true).unwrap();
    args[4] = "/nonexistent-provider-must-not-run".into();
    run(&args).await.unwrap();
    assert_eq!(
        files::read(Path::new(&args[2]), 65536, true).unwrap(),
        first
    );
    assert_eq!(fs::read(calls).unwrap(), b"x");
    let requests = server.await.unwrap();
    assert!(
        matches!((&requests[3], &requests[4]), (Request::Submit {bytes:a}, Request::Submit {bytes:b}) if a == b)
    );
}
