//! Native process evidence for WAL crash recovery and live operator changes.
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

struct Fixture {
    directory: PathBuf,
    child: Option<Child>,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "naome-native-program-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self {
            directory,
            child: None,
        }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_naome"));
        command
            .env("NAOME_NODE_DIR", self.directory.join("node"))
            .env_remove("NAOME_EFFECTIVE_RESOURCES")
            .env_remove("NAOME_RESOURCE_CONFIG");
        command
    }
    fn call(&self, args: &[&str]) -> Value {
        let mut child = self
            .command()
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let end = Instant::now() + Duration::from_secs(120);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= end {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "CLI deadline {args:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn work(&self) -> PathBuf {
        self.directory.join("proof.sqlite3")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn live_profile_switch_and_killed_writer_preserve_committed_proof_work() {
    let mut fixture = Fixture::new();
    let work = fixture.work();
    fixture.call(&["proof", "new", text(&work)]);
    let source = fixture.directory.join("large.ndjson");
    let mut file = fs::File::create(&source).unwrap();
    writeln!(file, "{}", json!({"op":"equal","left":0,"right":0})).unwrap();
    // Deep formulas exceed both the old recursive codec and its global node
    // budget. Their input and pending traversal stay in disk-backed tables.
    for i in 0..70_000u64 {
        writeln!(file, "{}", json!({"op":"not","formula":i})).unwrap();
    }
    writeln!(
        file,
        "{}",
        json!({"op":"simplification","antecedent":70000,"consequent":70000})
    )
    .unwrap();
    writeln!(
        file,
        "{}",
        json!({"op":"generalization","premise":70001,"variable":0})
    )
    .unwrap();
    writeln!(file, "{}", json!({"op":"seal","proof":70002})).unwrap();
    drop(file);
    fixture.call(&["proof", "append", text(&work), text(&source)]);
    fixture.call(&["resources", "light"]);
    fixture.child = Some(
        fixture
            .command()
            .args(["--json", "proof", "run", text(&work)])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let wait = |condition: &mut dyn FnMut() -> bool| {
        while !condition() {
            assert!(Instant::now() < deadline, "native proof progress deadline");
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    wait(&mut || {
        fixture.call(&["proof", "status", text(&work)])["last_recorded_budget"]["selection"]["profile"]
            == "light"
    });
    fixture.call(&["resources", "heavy"]);
    wait(&mut || {
        fixture.call(&["proof", "status", text(&work)])["last_recorded_budget"]["selection"]["profile"]
            == "heavy"
    });
    wait(&mut || {
        fixture.call(&["proof", "status", text(&work)])["transformation_equations"]
            .as_u64()
            .unwrap()
            > 0
    });
    let before = fixture.call(&["proof", "status", text(&work)]);
    assert!(before["committed_commands"].as_u64().unwrap() > 0);
    let child = fixture.child.as_mut().unwrap();
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    fixture.child = None;
    let after = fixture.call(&["proof", "status", text(&work)]);
    assert!(
        after["committed_commands"].as_u64().unwrap()
            >= before["committed_commands"].as_u64().unwrap()
    );
    assert_eq!(after["fully_checked"], false);
    assert_eq!(after["requires_recheck"], true);
    let custom = fixture.directory.join("custom.json");
    fs::write(&custom,serde_json::to_vec(&json!({"memory_bytes":32*1024*1024,"concurrency":1,"cache_bytes":32768,"batch_steps":512,"network_requests":1})).unwrap()).unwrap();
    fixture.call(&["resources", "custom", text(&custom)]);
    let result = fixture.call(&["--json", "proof", "run", text(&work)]);
    assert_eq!(result["fully_checked"], true);
    assert_eq!(result["checked_commands"], 70004);
    assert!(
        result["database_bytes"].as_u64().unwrap()
            > result["budget"]["budget"]["cache_bytes"].as_u64().unwrap()
    );
    assert!(
        result["budget"]["observed"]["process_rss"]
            .as_u64()
            .unwrap()
            > 0
    );
    eprintln!(
        "native proof resource measurement: {}",
        json!({"commands":result["checked_commands"],"database_bytes":result["database_bytes"],"memory_budget":result["budget"]["budget"]["memory_bytes"],"cache_budget":result["budget"]["budget"]["cache_bytes"],"rss":result["budget"]["observed"]["process_rss"],"peak_rss":result["budget"]["observed"]["peak_rss"],"cpu_ms":result["budget"]["observed"]["process_cpu_ms"]})
    );
    let history = fixture.call(&["proof", "history", text(&work)]);
    assert!(
        history
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["snapshot"]["selection"]["profile"] == "light")
    );
    assert!(
        history
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["snapshot"]["selection"]["profile"] == "heavy")
    );
}

#[test]
fn cli_rejects_invalid_custom_limits_before_changing_the_selected_profile() {
    let fixture = Fixture::new();
    fixture.call(&["resources", "light"]);
    let path = fixture.directory.join("invalid.json");
    fs::write(&path,r#"{"memory_bytes":1,"concurrency":0,"cache_bytes":0,"batch_steps":0,"network_requests":0}"#).unwrap();
    let output = fixture
        .command()
        .args(["resources", "custom", text(&path)])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        fixture.call(&["resources"])["configured"]["profile"],
        "light"
    );
}
