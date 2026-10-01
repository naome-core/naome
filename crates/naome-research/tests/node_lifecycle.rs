//! Real offline CLI processes; configured provider executable never exists.

use naome_research::{
    journal::write_new,
    node::{
        Config, Node,
        budget::{Allowance, Budgets, Period},
    },
    provider::ProviderConfig,
    run::Interests,
    state::PoolConfig,
};
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

struct Fixture {
    root: PathBuf,
    config: Config,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "naome-node-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let identity_file = root.join("key.json");
        write_new(&identity_file, &[39u8; 32]).unwrap();
        let config = Config {
            version: 2,
            directory: root.join("node"),
            identity_file,
            run_label: "offline-cli-node".into(),
            interests: Interests {
                topics: vec!["Formal logic".into()],
                context: "Offline CLI fixture".into(),
            },
            provider: ProviderConfig {
                codex_binary: root.join("provider-never-created"),
                codex_home: root.join("never-authenticated"),
                model: "offline-model".into(),
                timeout_seconds: 1,
                max_output_bytes: 4096,
                disabled_registries: Default::default(),
                pure_js: None,
            },
            budgets: Budgets {
                timezone: "Europe/Berlin".into(),
                research: Allowance {
                    amount: 0,
                    period: Period::Day,
                },
                discoveries: Allowance {
                    amount: 0,
                    period: Period::Hour,
                },
                evaluations: Allowance {
                    amount: 0,
                    period: Period::Hour,
                },
            },
            credit: 1,
            pool: PoolConfig::default(),
        };
        let path = root.join("config.json");
        write_new(&path, &config).unwrap();
        Self { root, config, path }
    }
    fn command(&self, verb: &str) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_naome-research"));
        c.arg(verb).arg(&self.path).stdin(Stdio::null());
        c
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn cli_run_requires_existing_initialized_store_and_snapshot_is_read_only() {
    let f = Fixture::new();
    let output = f.command("node-run").output().unwrap();
    assert!(!output.status.success());
    assert!(!f.config.directory.exists());
    let node = Node::initialize(f.config.clone(), 1_790_841_600).unwrap();
    let before = node.checkpoint().clone();
    let output = f.command("node-status").output().unwrap();
    assert!(output.status.success());
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["attempts_admitted"], 0);
    assert_eq!(node.checkpoint(), &before);
    // An independent reader is permitted; another writer cannot acquire this store.
    let output = f.command("node-run").output().unwrap();
    assert!(!output.status.success());
    assert_eq!(node.checkpoint(), &before);
}

#[cfg(unix)]
#[test]
fn dormant_cli_sigterm_stops_and_restart_preserves_checkpoint_and_single_identity() {
    let f = Fixture::new();
    assert!(f.command("init-node").output().unwrap().status.success());
    let before = f.command("node-status").output().unwrap();
    let before: Value = serde_json::from_slice(&before.stdout).unwrap();
    let mut child = f
        .command("node-run")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if Node::open(f.config.clone()).is_err() {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "CLI must take the writer lock"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // The signal listener registers before this bounded offline observation.
    std::thread::sleep(Duration::from_millis(80));
    let snapshot = f.command("node-status").output().unwrap();
    assert!(snapshot.status.success());
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            panic!("dormant signal stop watchdog");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stopped: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(stopped["lifecycle"], "stopped");
    assert_eq!(stopped["attempts_admitted"], 0);
    let reopened = Node::open(f.config.clone()).unwrap();
    assert!(
        reopened.checkpoint().state["clock"].as_i64().unwrap()
            >= before["greatest_observed_clock"].as_i64().unwrap()
    );
    assert_eq!(reopened.checkpoint().state["attempts"], 0);
    assert_eq!(stopped["profile"], before["profile"]);
    assert!(!f.config.provider.codex_home.exists());
}

#[test]
fn large_definition_scheduler_process_regression() {
    const CONFIG_ENV: &str = "NAOME_NODE_LARGE_CONTEXT_FIXTURE_CONFIG";
    const RESULT_ENV: &str = "NAOME_NODE_LARGE_CONTEXT_FIXTURE_RESULT";
    if let Some(config) = std::env::var_os(CONFIG_ENV) {
        use naome_research::{
            node::{Control, ProviderOutcome, budget::Phase},
            provider::ProviderReply,
            state::hex,
        };
        use serde_json::json;
        let config = naome_research::node::read_config(std::path::Path::new(&config)).unwrap();
        let mut node = Node::open(config).unwrap();
        let control = Control::default();
        let now = node.checkpoint().state["clock"].as_i64().unwrap();
        let mut calls = 0;
        let status=node.run_with(&control,||Ok(now),|reservation,control|{
            assert_eq!(reservation.phase,Phase::Solve);assert!(reservation.prompt_text.len()<=32*1024);
            assert!(reservation.prompt_text.contains("definition_id"));assert!(!reservation.prompt_text.contains(&" ".repeat(40*1024)));
            let value=json!({"question_id":hex(&reservation.target.unwrap()),"outcome":"proof","source":"foundation = \"naome:zfc\"\nstatement = forall(x0, equal(x0, x0))\nproof:\n p0 = equality_reflexivity(x0)\n p1 = generalization(p0, x0)\n return p1\n","dependencies":[]});
            let usage=json!({"complete":true,"total":{"inputTokens":2,"outputTokens":3,"totalTokens":5},"responseUsage":[{"responseId":"offline-context-response","inputTokens":2,"outputTokens":3,"totalTokens":5}]});
            calls+=1;control.stop();ProviderOutcome {reply:Some(ProviderReply {raw_response:value.to_string(),value,usage:usage.clone(),computation:vec![]}),error:None,known_usage:usage,provenance:json!({"offline_process":true}),retained_raw_response:None}
        }).unwrap();
        assert_eq!(calls, 1);
        write_new(
            std::path::Path::new(&std::env::var_os(RESULT_ENV).unwrap()),
            &status,
        )
        .unwrap();
        return;
    }
    use naome_research::{formal::FormulaInput, node::Action, state::Question};
    let mut f = Fixture::new();
    f.config.budgets.research.amount = 20;
    let mut node = Node::initialize(f.config.clone(), 1_790_841_600).unwrap();
    let definition = format!(
        "foundation = \"naome:zfc\"\ndefinition self_equal = relation(x):\n equal(x, x)\n{}",
        " ".repeat(40 * 1024)
    );
    let question = Question {
        title: "Accepted large definition context".into(),
        context: String::new(),
        formula: FormulaInput::Forall {
            variable: 0,
            body: Box::new(FormulaInput::Equal { left: 0, right: 0 }),
        },
        definitions: vec![definition.clone()],
    };
    let id = question.id().unwrap();
    let publish = node.sign(Action::Publish { question }).unwrap();
    node.submit(publish).unwrap();
    let assessment = node
        .sign(Action::Evaluate {
            question: id,
            yes: true,
        })
        .unwrap();
    node.submit(assessment).unwrap();
    node.tick(1_790_841_600).unwrap();
    assert!(node.pending(id).unwrap().is_some());
    drop(node);
    let config = f.root.join("large-context-config.json");
    let result = f.root.join("large-context-result.json");
    write_new(&config, &f.config).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "large_definition_scheduler_process_regression",
            "--nocapture",
        ])
        .env(CONFIG_ENV, &config)
        .env(RESULT_ENV, &result)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            panic!("large context process must not enter a retry loop");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let status: Value = serde_json::from_slice(&fs::read(result).unwrap()).unwrap();
    assert_eq!(status["finalized_blocks"], 1);
    assert_eq!(status["accounting_unknown"], Value::Null);
    let node = Node::open(f.config.clone()).unwrap();
    assert_eq!(
        node.question(id).unwrap().unwrap().definitions,
        vec![definition]
    );
    assert!(!f.config.provider.codex_home.exists());
}

#[test]
fn exhausted_phase_child_process_sleeps_and_resumes_at_observed_renewal() {
    const CONFIG_ENV: &str = "NAOME_NODE_RENEWAL_FIXTURE_CONFIG";
    const CLOCK_ENV: &str = "NAOME_NODE_RENEWAL_FIXTURE_CLOCK";
    const RESULT_ENV: &str = "NAOME_NODE_RENEWAL_FIXTURE_RESULT";
    use naome_research::node::{
        Control, ProviderOutcome,
        budget::{Phase, window},
    };
    use serde_json::json;
    if let Some(config) = std::env::var_os(CONFIG_ENV) {
        let config = naome_research::node::read_config(std::path::Path::new(&config)).unwrap();
        let mut node = Node::open(config).unwrap();
        let control = Control::default();
        let clock = PathBuf::from(std::env::var_os(CLOCK_ENV).unwrap());
        let mut calls = 0;
        let status=node.run_with(&control,||fs::read_to_string(&clock).map_err(|e|e.to_string())?.parse().map_err(|_|"fixture clock invalid".into()),|reservation,control|{
            assert_eq!(reservation.phase,Phase::Discover);calls+=1;control.stop();
            ProviderOutcome {reply:None,error:Some("offline renewal fixture failure".into()),known_usage:json!({"complete":true,"total":{"inputTokens":1,"outputTokens":1,"totalTokens":2},"responseUsage":[{"responseId":"renewed-offline-response","inputTokens":1,"outputTokens":1,"totalTokens":2}]}),provenance:json!({"offline_process":true}),retained_raw_response:None}
        }).unwrap();
        assert_eq!(calls, 1);
        write_new(
            std::path::Path::new(&std::env::var_os(RESULT_ENV).unwrap()),
            &status,
        )
        .unwrap();
        return;
    }
    let mut f = Fixture::new();
    f.config.budgets.discoveries.amount = 1;
    let t0 = 1_790_841_600;
    let boundary = window(t0, &f.config.budgets.timezone, Period::Hour)
        .unwrap()
        .end;
    let mut node = Node::initialize(f.config.clone(), t0).unwrap();
    let first = node
        .reserve(
            Phase::Discover,
            None,
            t0,
            "offline first attempt".into(),
            json!({}),
        )
        .unwrap();
    node.record_response(&first,ProviderOutcome {reply:None,error:Some("offline first failure".into()),known_usage:json!({"complete":true,"total":{"inputTokens":1,"outputTokens":1,"totalTokens":2},"responseUsage":[{"responseId":"initial-offline-response","inputTokens":1,"outputTokens":1,"totalTokens":2}]}),provenance:json!({}),retained_raw_response:None}).unwrap();
    node.recover_provider().unwrap();
    drop(node);
    let config = f.root.join("renewal-config.json");
    let clock = f.root.join("renewal-clock.txt");
    let result = f.root.join("renewal-result.json");
    write_new(&config, &f.config).unwrap();
    fs::write(&clock, (boundary - 1).to_string()).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "exhausted_phase_child_process_sleeps_and_resumes_at_observed_renewal",
            "--nocapture",
        ])
        .env(CONFIG_ENV, &config)
        .env(CLOCK_ENV, &clock)
        .env(RESULT_ENV, &result)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        let snapshot = Node::inspect(f.config.clone()).unwrap();
        if snapshot.checkpoint().state["clock"] == boundary - 1 {
            break;
        }
        if started.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            panic!("child must observe exhausted same-window wait");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(80));
    let snapshot = Node::inspect(f.config.clone()).unwrap();
    assert_eq!(snapshot.checkpoint().state["attempts"], 1);
    assert!(!result.exists());
    drop(snapshot);
    // No Control notification: the real child timer must wake, reread this
    // injected operator clock, renew the bucket and admit the next attempt.
    let next_clock = clock.with_extension("next");
    fs::write(&next_clock, (boundary + 1).to_string()).unwrap();
    fs::rename(next_clock, &clock).unwrap();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            panic!("child renewal/resume watchdog");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let status: Value = serde_json::from_slice(&fs::read(result).unwrap()).unwrap();
    assert_eq!(status["attempts_admitted"], 2);
    assert_eq!(status["budgets"]["discovery_attempts"]["spent"], 1);
    let node = Node::open(f.config.clone()).unwrap();
    assert_eq!(
        node.window_ledger(Phase::Discover, first.window.start)
            .unwrap()
            .unwrap()
            .spent,
        1
    );
    assert!(!f.config.provider.codex_home.exists());
}
