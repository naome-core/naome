//! Fake providers exercise adapter boundaries only; they are not AI evidence.
use super::*;
use ed25519_dalek::SigningKey;
use naome_ledger::profile::{Genesis, Profile, STATE_CHECKER_PROFILE, ValidatorRegistration};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::UnixListener;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf, PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "nr-agent-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        files::directory(&path).unwrap();
        // Keep hard links beside the checked-in launcher on the same filesystem,
        // independently of where the OS temporary/control-socket directory lives.
        let providers =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("target/agent-provider-fixtures");
        fs::create_dir_all(&providers).unwrap();
        let providers = providers.join(path.file_name().unwrap());
        files::directory(&providers).unwrap();
        Self(path, providers)
    }
    fn executable(&self, name: &str, body: &str) -> PathBuf {
        self.raw_executable(name, &format!("/bin/cat >/dev/null\n{body}"))
    }
    fn raw_executable(&self, name: &str, body: &str) -> PathBuf {
        let path = self.1.join(name);
        // A newly written executable can transiently be held writable by a
        // concurrently forked child before its exec closes inherited FDs.
        // Hard-link a stable checked-in launcher; the generated body is read as
        // shell input, so Linux ETXTBSY cannot mask adapter behavior.
        files::create(
            &self.1.join(format!("{name}.body")),
            format!("{body}\n").as_bytes(),
            true,
        )
        .unwrap();
        fs::hard_link(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/agent-provider.sh"),
            &path,
        )
        .unwrap();
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_dir_all(&self.1);
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
        let validators: Vec<_> = (0..4)
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
        let retirement_order = [2, 0, 3, 1].map(|i| validators[i].id()).to_vec();
        let genesis = Genesis::new(
            Profile::short_test(),
            "naome:zfc".into(),
            STATE_CHECKER_PROFILE.into(),
            naome_ledger::profile::STATE_PROTOCOL_VERSION,
            100,
            [9; 32],
            accounts,
            validators,
            retirement_order,
        )
        .unwrap();
        let config = NodeConfig {
            version: 2,
            genesis: root.join("genesis.bin"),
            history: root.join("history"),
            history_anchor: root.join("history-anchor"),
            signer: root.join("signer"),
            signer_anchor: root.join("signer-anchor"),
            consensus_key: root.join("consensus.key"),
            transport_key: root.join("transport.key"),
            account_key: key.clone(),
            agenda_profile: root.join("agenda-profile.txt"),
            control_socket: root.join("control.sock"),
            maximum_round: 64,
            simulation: true,
            listen_address: None,
        };
        files::directory(&config.signer).unwrap();
        files::create(&config.genesis, &genesis.encode(), false).unwrap();
        files::create(
            &config.agenda_profile,
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
        let requests = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("fixture must receive all three requests")
            .unwrap();
        assert_eq!(requests.len(), 3);
        assert!(matches!(requests.last(), Some(Request::Status {})));
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

fn review_args(args: &[String]) -> Vec<String> {
    let mut args = args.to_vec();
    args.remove(2);
    args
}
fn question_fixture() -> serde_json::Value {
    json!({"source":"statement = forall(x, equal(x,x))","purpose":"Equality reflexivity.",
        "formal_targets":{"R":"forall(b0, equal(b0,b0))","not_R":"not_(forall(b0, equal(b0,b0)))","submitted_negation_parity":false}})
}
fn structured_provider(directory: &Directory, decision: &str, marker: &Path) -> PathBuf {
    let script = format!(
        "import hashlib,json,sys\nb=sys.stdin.buffer.read()\nprint(json.dumps({{'version':2,'decision':{decision:?},'provider':'fixture-v2','tool_calls':0,'assessment':{{'input_sha256':hashlib.sha256(b).hexdigest()}}}}))"
    );
    directory.raw_executable(
        "structured",
        &format!(
            "printf x >> {}\nexec python3 -c {}",
            quoted(marker.to_str().unwrap()),
            quoted(&script)
        ),
    )
}

#[tokio::test]
async fn review_only_then_vote_uses_one_retained_decision_and_identical_report() {
    let fixture = Fixture::new();
    let marker = fixture.directory.0.join("calls");
    let executable = structured_provider(&fixture.directory, "YES", &marker);
    let server = fixture.server(vec![
        fixture.status.clone(),
        question_fixture(),
        fixture.status.clone(),
        fixture.status.clone(),
        question_fixture(),
        fixture.status.clone(),
        json!({"status":"pending"}),
        fixture.status.clone(),
        question_fixture(),
        fixture.status.clone(),
    ]);
    let args = fixture.args(&executable);
    review(&review_args(&args)).await.unwrap();
    assert!(!Path::new(&args[2]).exists());
    let report = files::read(Path::new(&args[3]), 16384, true).unwrap();
    assert!(
        !fs::read_dir(&fixture.config.signer).unwrap().any(|e| e
            .unwrap()
            .path()
            .extension()
            .is_some_and(|v| v == "action"))
    );
    run(&args).await.unwrap();
    assert!(Path::new(&args[2]).exists());
    assert_eq!(
        report,
        files::read(Path::new(&args[3]), 16384, true).unwrap()
    );
    // Even after a vote exists, a review cannot take the retry-submit shortcut.
    review(&review_args(&args)).await.unwrap();
    assert_eq!(fs::read(marker).unwrap(), b"x");
    let requests = server.await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| matches!(r, Request::Submit { .. }))
            .count(),
        1
    );
}

#[tokio::test]
async fn review_result_is_terminal_and_never_silently_signs_no() {
    let fixture = Fixture::new();
    let marker = fixture.directory.0.join("calls");
    let executable = structured_provider(&fixture.directory, "REVIEW", &marker);
    let server = fixture.server(vec![
        fixture.status.clone(),
        question_fixture(),
        fixture.status.clone(),
        fixture.status.clone(),
        question_fixture(),
        fixture.status.clone(),
    ]);
    let args = fixture.args(&executable);
    run(&args).await.unwrap();
    run(&args).await.unwrap();
    assert!(!Path::new(&args[2]).exists());
    assert!(Path::new(&args[3]).exists());
    assert_eq!(fs::read(marker).unwrap(), b"x");
    assert!(
        server
            .await
            .unwrap()
            .iter()
            .all(|r| !matches!(r, Request::Submit { .. }))
    );
}

#[tokio::test]
async fn v2_decisions_require_version_and_exact_input_binding() {
    let directory = Directory::new();
    let marker = directory.0.join("calls");
    let executable = structured_provider(&directory, "YES", &marker);
    let accepted = invoke(&executable, b"bounded request", 5).await.unwrap();
    assert!(accepted.reason.is_none());
    for (field, value) in [
        ("version", json!(3)),
        ("assessment", json!([])),
        ("assessment", json!({"input_sha256":"00".repeat(32)})),
        ("version", json!(1)),
    ] {
        let mut invalid = serde_json::to_value(&accepted).unwrap();
        invalid[field] = value;
        let executable = directory.executable(
            &format!(
                "bad-{field}-{}",
                files::hex(files::random().unwrap().as_ref())
            ),
            &output(invalid),
        );
        assert!(invoke(&executable, b"bounded request", 2).await.is_err());
    }
}

#[tokio::test]
async fn changed_provider_configuration_cannot_reset_review_budget_or_rescore_in_place() {
    let fixture = Fixture::new();
    let marker = fixture.directory.0.join("calls");
    let executable = structured_provider(&fixture.directory, "YES", &marker);
    let config = fixture.directory.0.join("provider.json");
    files::create(&config, b"{\"policy\":1}", true).unwrap();
    let mut args = fixture.args(&executable);
    args.extend(["--provider-config".into(), config.to_str().unwrap().into()]);
    let server = fixture.server(vec![
        fixture.status.clone(),
        question_fixture(),
        fixture.status.clone(),
        fixture.status.clone(),
        question_fixture(),
    ]);
    review(&review_args(&args)).await.unwrap();
    files::replace_private(&config, b"{\"policy\":2}").unwrap();
    let error = run(&args).await.err().unwrap().to_string();
    assert!(error.contains("context or allowance changed"));
    assert_eq!(fs::read(marker).unwrap(), b"x");
    assert!(!Path::new(&args[2]).exists());
    assert_eq!(server.await.unwrap().len(), 5);
}

#[tokio::test]
async fn failed_reviews_consume_the_voting_budget() {
    let fixture = Fixture::new();
    let marker = fixture.directory.0.join("calls");
    let executable = fixture.directory.executable(
        "invalid",
        &format!(
            "printf x >> {}\nprintf '{{}}'",
            quoted(marker.to_str().unwrap())
        ),
    );
    let server = fixture.server(vec![
        fixture.status.clone(),
        question_fixture(),
        fixture.status.clone(),
        question_fixture(),
    ]);
    let args = fixture.args(&executable);
    assert!(review(&review_args(&args)).await.is_err());
    assert!(run(&args).await.is_err());
    assert_eq!(fs::read(marker).unwrap(), b"xx");
    fixture.assert_no_vote_files();
    assert_eq!(server.await.unwrap().len(), 4);
}

#[tokio::test]
async fn kev_engine_receives_compiler_context_and_returns_unsigned_structured_assessment() {
    // Exercise Rust -> real Python context/policy engine -> Rust, with an injected
    // transport fixture. This deliberately makes no model inference or network call.
    let fixture = Fixture::new();
    let settings = fixture.directory.0.join("kev.json");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let script = format!(
        r#"import json,sys
sys.path.insert(0, {tools:?})
from naome_kev import config,engine
from naome_kev.schema import encode
p={settings:?}
# The fixture config is created before the CLI reads it (outside this provider).
def transport(settings,payload):
    assert settings['model'] == config.MODEL
    assert payload['state']['compiler_facts']['formal_targets']['R'].startswith('forall')
    return {{'model':config.MODEL,'usage':{{'input_tokens':100,'output_tokens':0}},'answers':{{k:{{'type':'noul','noul':({{'excluded':.05,'relevance':.9999999999999999,'value':.24800000000000003}}.get(k,.95))}} for k in ('relevance','value','fidelity','sufficient','excluded')}}}}
print(encode(engine.evaluate(sys.stdin.buffer.read(),transport)).decode())
"#,
        tools = root.join("tools").to_str().unwrap(),
        settings = settings.to_str().unwrap()
    );
    let make_config = format!(
        "import sys;sys.path.insert(0,{:?});from naome_kev import config;from naome_kev.schema import encode;sys.stdout.buffer.write(encode(config.default({:?})))",
        root.join("tools").to_str().unwrap(),
        fixture.directory.0.to_str().unwrap()
    );
    let created = std::process::Command::new("python3")
        .args(["-c", &make_config])
        .output()
        .unwrap();
    assert!(created.status.success());
    files::create(&settings, &created.stdout, true).unwrap();
    let executable = fixture.directory.raw_executable(
        "kev-fixture",
        &format!("exec python3 -c {}", quoted(&script)),
    );
    let mut args = fixture.args(&executable);
    args.extend([
        "--provider-config".into(),
        settings.to_str().unwrap().into(),
    ]);
    let server = fixture.server(vec![
        fixture.status.clone(),
        question_fixture(),
        fixture.status.clone(),
    ]);
    review(&review_args(&args)).await.unwrap();
    let report: serde_json::Value =
        serde_json::from_slice(&files::read(Path::new(&args[3]), 16384, true).unwrap()).unwrap();
    assert_eq!(report["decision"]["decision"], "YES");
    assert_eq!(report["decision"]["assessment"]["score_bps"], 7744);
    let replay = std::process::Command::new("python3")
        .arg(root.join("tools/agenda_agent_kev.py"))
        .args(["replay", &args[3], settings.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let comparison: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(comparison["result"]["score_bps"], 7744);
    assert!(
        report["decision"]["assessment"]["model"]
            .as_str()
            .unwrap()
            .starts_with("kev-4b@485ace8703592fcf405488b262449990824cfed1+")
    );
    assert!(report["decision"].get("reason").is_none());
    assert!(!Path::new(&args[2]).exists());
    assert_eq!(server.await.unwrap().len(), 3);
}

#[tokio::test]
async fn configured_request_rejects_legacy_response_downgrade() {
    let directory = Directory::new();
    let executable = directory.executable("legacy", &output(decision()));
    assert!(invoke(&executable, b"{\"version\":2}", 2).await.is_err());
    assert!(invoke(&executable, b"{\"version\":1}", 2).await.is_ok());
}

#[tokio::test]
async fn legacy_report_survives_interruption_before_action_copy() {
    let fixture = Fixture::new();
    let marker = fixture.directory.0.join("calls");
    let executable = fixture.directory.executable(
        "legacy",
        &format!(
            "printf x >> {}\n{}",
            quoted(marker.to_str().unwrap()),
            output(decision())
        ),
    );
    let server = fixture.server(vec![
        fixture.status.clone(),
        question_fixture(),
        fixture.status.clone(),
        json!({"status":"pending"}),
        fixture.status.clone(),
        question_fixture(),
        fixture.status.clone(),
        json!({"status":"pending"}),
    ]);
    let args = fixture.args(&executable);
    run(&args).await.unwrap();
    let action = files::read(Path::new(&args[2]), 65536, true).unwrap();
    let operation = SignedOperation::decode(&action).unwrap();
    let mut report: serde_json::Value =
        serde_json::from_slice(&files::read(Path::new(&args[3]), 16384, true).unwrap()).unwrap();
    report["operation"] = json!(files::hex(operation.id().as_bytes()));
    let legacy = serde_json::to_vec_pretty(&report).unwrap();
    files::replace_private(Path::new(&args[3]), &legacy).unwrap();
    fs::remove_file(&args[2]).unwrap();
    run(&args).await.unwrap();
    assert_eq!(
        files::read(Path::new(&args[2]), 65536, true).unwrap(),
        action
    );
    assert_eq!(
        files::read(Path::new(&args[3]), 16384, true).unwrap(),
        legacy
    );
    assert_eq!(fs::read(marker).unwrap(), b"x");
    assert_eq!(server.await.unwrap().len(), 8);
    report["question_id"] = json!("wrong");
    assert!(save_report(Path::new(&args[3]), &report, Some(&operation)).is_err());
}
