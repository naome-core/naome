//! Real, independent local processes using authenticated TCP and durable stores.
//! Accelerated supplementary evidence; the lab-window run is qualified separately.
#![cfg(unix)]

use serde_json::Value;
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    process::{Child, Command, Output},
    thread,
    time::{Duration, Instant},
};

#[path = "cases/lifecycle.rs"]
mod lifecycle;

#[path = "cases/state_safety.rs"]
mod state_safety;

fn process_guard() -> std::sync::MutexGuard<'static, ()> {
    static ACTIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

const BIN: &str = env!("CARGO_BIN_EXE_naome");
// Compile all three process packages in one matching-profile --no-run barrier.
// A missing sibling is a qualification failure, never a fallback to `naome`.
fn process_binary(name: &str) -> PathBuf {
    let binary = Path::new(BIN).with_file_name(name);
    assert!(
        binary.is_file(),
        "required process binary absent: {}",
        binary.display()
    );
    binary
}
fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/research-mvp")
        .join(name)
}
fn raw(args: &[String]) -> Output {
    let binary = if args.first().is_some_and(|arg| arg == "verify") {
        process_binary("naome-verifier")
    } else {
        PathBuf::from(BIN)
    };
    Command::new(binary).args(args).output().unwrap()
}
fn command(args: &[String]) -> Value {
    let output = raw(args);
    assert!(
        output.status.success(),
        "command {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid command output: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}
fn path(path: impl AsRef<Path>) -> String {
    path.as_ref().to_str().unwrap().to_owned()
}
struct Lab {
    root: PathBuf,
    nodes: Vec<Option<Child>>,
    base: u16,
}
impl Lab {
    fn new() -> Self {
        let mut random = [0; 4];
        getrandom::fill(&mut random).unwrap();
        let root = PathBuf::from(format!(
            "/tmp/nmr-{}-{}",
            std::process::id(),
            u32::from_ne_bytes(random)
        ));
        let base = (0..1000)
            .find_map(|offset| {
                let base = 20000 + ((u32::from_ne_bytes(random) + offset) % 40000) as u16;
                (0..4)
                    .map(|i| std::net::TcpListener::bind(("127.0.0.1", base + i)))
                    .collect::<std::io::Result<Vec<_>>>()
                    .ok()
                    .map(|_| base)
            })
            .unwrap();
        command(&[
            "setup".into(),
            path(&root),
            "short-test".into(),
            "128".into(),
            base.to_string(),
            "compact".into(),
        ]);
        Self {
            root,
            nodes: (0..4).map(|_| None).collect(),
            base,
        }
    }
    fn config(&self, index: usize) -> String {
        path(self.root.join(format!("node-{index}/node.json")))
    }
    fn key(&self, index: usize) -> String {
        path(self.root.join(format!("accounts/account-{index}.key")))
    }
    fn file(&self, name: &str) -> String {
        path(self.root.join(name))
    }
    fn start(&mut self, index: usize) {
        assert!(self.nodes[index].is_none());
        let stdout = File::create(self.root.join(format!("node-{index}.events"))).unwrap();
        let stderr = File::create(self.root.join(format!("node-{index}.errors"))).unwrap();
        self.nodes[index] = Some(
            Command::new(process_binary("naome-validator"))
                .args(["start", &self.config(index)])
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .unwrap(),
        );
    }
    fn status(&self, index: usize) -> Option<Value> {
        let output = raw(&["status".into(), self.config(index)]);
        output
            .status
            .success()
            .then(|| serde_json::from_slice(&output.stdout).unwrap())
    }
    fn wait(&self, index: usize, predicate: impl Fn(&Value) -> bool) -> Value {
        let start = Instant::now();
        loop {
            if let Some(status) = self.status(index)
                && predicate(&status)
            {
                return status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(90),
                "node {index} timeout; status={:?}; errors={}",
                self.status(index),
                fs::read_to_string(self.root.join(format!("node-{index}.errors")))
                    .unwrap_or_default()
            );
            thread::sleep(Duration::from_millis(40));
        }
    }
    fn stop(&mut self, index: usize) {
        if self.nodes[index].is_none() {
            return;
        }
        command(&["shutdown".into(), self.config(index)]);
        let mut child = self.nodes[index].take().unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if start.elapsed() > Duration::from_secs(10) {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("node shutdown timed out");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn submit(&self, node: usize, author: usize, source: PathBuf, label: &str) -> String {
        let result = command(&[
            "submit".into(),
            self.config(node),
            self.key(author),
            path(source),
            format!("Research target {label}"),
            self.file(&format!("{label}.submit")),
        ]);
        result["operation"].as_str().unwrap().to_owned()
    }
    fn assert_question_can_progress(&self, node: usize, submission: &str) {
        let output = raw(&["question".into(), self.config(node), submission.into()]);
        if output.status.success() {
            let question: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(
                matches!(question["status"].as_str(), Some("Queued" | "Active")),
                "question {submission} reached terminal state before the expected phase: {question}"
            );
        }
    }
    fn wait_phase(&self, node: usize, submission: &str, phase: &str) {
        self.wait(node, |s| {
            if s["active"]["submission"] == submission && s["active"]["phase"] == phase {
                return true;
            }
            self.assert_question_can_progress(node, submission);
            false
        });
    }
    fn wait_receipt(&self, node: usize, submission: &str, operation: &Value) {
        let id = operation["operation"]
            .as_str()
            .expect("signed operation ID");
        self.wait(node, |_| {
            let receipt = command(&["receipt".into(), self.config(node), id.into()]);
            if receipt["status"] == "finalized" {
                return true;
            }
            assert_ne!(receipt["status"], "rejected", "operation {id}: {receipt}");
            self.assert_question_can_progress(node, submission);
            false
        });
    }
    fn approve(&self, owners: &[usize], label: &str, submission: &str) {
        for &index in owners {
            self.wait_phase(index, submission, "Voting");
        }
        let votes = thread::scope(|scope| {
            let mut handles = Vec::new();
            for &index in owners {
                let args = [
                    "vote".into(),
                    self.config(index),
                    self.key(index),
                    "YES".into(),
                    self.file(&format!("{label}-vote-{index}")),
                ];
                handles.push(scope.spawn(move || (index, command(&args))));
            }
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        // Every intended YES must be finalized, not merely accepted by a
        // transport socket, before the test claims successful approval.
        for (index, vote) in votes {
            self.wait_receipt(index, submission, &vote);
        }
    }
    fn solve(&self, node: usize, author: usize, package: &str, label: &str, submission: &str) {
        self.wait_phase(node, submission, "Commit");
        let commit = command(&[
            "commit".into(),
            self.config(node),
            self.key(author),
            package.into(),
            self.file(&format!("{label}.secret")),
            self.file(&format!("{label}.commit")),
        ]);
        self.wait_receipt(node, submission, &commit);
        self.wait_phase(node, submission, "Reveal");
        let reveal = command(&[
            "reveal".into(),
            self.config(node),
            self.key(author),
            self.file(&format!("{label}.secret")),
            self.file(&format!("{label}.reveal")),
        ]);
        self.wait_receipt(node, submission, &reveal);
    }
    fn assert_same(&self, indices: &[usize], expected: &Value) {
        for &index in indices {
            let status = self.wait(index, |s| s["state"] == expected["state"]);
            for field in [
                "state",
                "head",
                "height",
                "accounts",
                "reserve_atoms",
                "claims",
                "library_root",
                "paid_completions",
            ] {
                assert_eq!(status[field], expected[field], "node {index}: {field}");
            }
        }
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        for child in self.nodes.iter_mut().flatten() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if std::thread::panicking() {
            eprintln!(
                "retained private process diagnostics: {}",
                self.root.display()
            );
        } else {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

#[test]
fn four_process_research_recovery_partition_and_independent_replay() {
    let _guard = process_guard();
    let mut lab = Lab::new();
    let a_package = lab.file("a.package");
    command(&[
        "package".into(),
        lab.file("genesis.bin"),
        lab.key(4),
        a_package.clone(),
        path(example("solution-a.nao")),
        "--helper".into(),
        path(example("helper-h.nao")),
    ]);
    for index in 0..4 {
        lab.start(index);
    }
    for index in 0..4 {
        lab.wait(index, |s| s["height"] == 0);
    }
    let a = lab.submit(0, 4, example("question-a.nao"), "a");
    lab.approve(&[0, 1, 2], "a", &a);
    lab.solve(0, 4, &a_package, "a", &a);
    let first = lab.wait(0, |s| s["paid_completions"] == 1);
    lab.assert_same(&[0, 1, 2, 3], &first);
    assert_eq!(
        command(&["question".into(), lab.config(0), a])["status"],
        "Completed"
    );

    // H is requested from another independently persisted node while the first
    // submission provider is unavailable. All remaining nodes retain quorum.
    lab.stop(0);
    let helper =
        naome_authoring::compile(&fs::read_to_string(example("helper-h.nao")).unwrap()).unwrap();
    let helper_id = helper
        .proof_id()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let remote = first["validators"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["endpoint"] == format!("127.0.0.1:{}", lab.base + 2))
        .unwrap()["index"]
        .as_u64()
        .unwrap();
    let h = command(&[
        "fetch-proof-from".into(),
        lab.config(1),
        remote.to_string(),
        helper_id.clone(),
        lab.file("h.proof"),
    ]);
    assert_eq!(h["retrieval"], "authenticated peer-to-peer network");
    command(&[
        "check-proof".into(),
        lab.file("genesis.bin"),
        lab.file("h.proof"),
    ]);
    let b_package = lab.file("b.package");
    command(&[
        "package".into(),
        lab.file("genesis.bin"),
        lab.key(5),
        b_package.clone(),
        path(example("solution-b-original.nao")),
        "--reference".into(),
        lab.file("h.proof"),
        "--helper".into(),
        path(example("helper-h-duplicate.nao")),
    ]);
    let b = lab.submit(1, 5, example("question-b.nao"), "b");
    lab.approve(&[1, 2, 3], "b", &b);
    lab.solve(1, 5, &b_package, "b", &b);
    let second = lab.wait(1, |s| s["paid_completions"] == 2);
    lab.assert_same(&[1, 2, 3], &second);
    assert_eq!(
        command(&["question".into(), lab.config(1), b])["status"],
        "Completed"
    );
    let h_after = command(&[
        "fetch-proof".into(),
        lab.config(2),
        helper_id,
        lab.file("h-again.proof"),
    ]);
    for field in ["author", "recipient", "height", "operation_index"] {
        assert_eq!(h_after[field], h[field]);
    }
    let original = h["recipient"].as_str().unwrap();
    assert_eq!(
        second["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["account"] == original)
            .unwrap()["balance_atoms"],
        "800000000"
    );
    let c = lab.submit(1, 4, example("question-c.nao"), "c");
    lab.wait(1, |s| {
        s["active"].is_null()
            && s["queued"] == 0
            && s["height"].as_u64().unwrap() > second["height"].as_u64().unwrap()
    });
    assert_eq!(
        command(&["question".into(), lab.config(1), c])["status"],
        "KnownUnpaid"
    );
    lab.start(0);
    let settled = lab.wait(1, |s| s["active"].is_null() && s["queued"] == 0);
    lab.assert_same(&[0, 1, 2, 3], &settled);
    assert_eq!(settled["paid_completions"], 2);
    assert_eq!(settled["claims"].as_array().unwrap().len(), 2);

    // A 2:2 partition must not finalize even an otherwise admissible submission.
    let validators = settled["validators"].as_array().unwrap();
    let canonical = (0..4)
        .map(|node| {
            validators
                .iter()
                .find(|v| v["endpoint"] == format!("127.0.0.1:{}", lab.base + node as u16))
                .unwrap()["index"]
                .as_u64()
                .unwrap() as usize
        })
        .collect::<Vec<_>>();
    for local in 0..4 {
        for (remote, &index) in canonical.iter().enumerate() {
            if local / 2 != remote / 2 {
                command(&[
                    "peer".into(),
                    lab.config(local),
                    index.to_string(),
                    "off".into(),
                ]);
            }
        }
    }
    let d_source = lab.root.join("d.nao");
    fs::write(
        &d_source,
        "foundation = \"naome:zfc\"\nstatement = forall(a,forall(b,forall(c,equal(c,c))))\n",
    )
    .unwrap();
    let d = lab.submit(0, 4, d_source, "d");
    thread::sleep(Duration::from_secs(5));
    for index in 0..4 {
        assert_eq!(lab.status(index).unwrap()["state"], settled["state"]);
    }
    for local in 0..4 {
        for (remote, &index) in canonical.iter().enumerate() {
            if local / 2 != remote / 2 {
                command(&[
                    "peer".into(),
                    lab.config(local),
                    index.to_string(),
                    "on".into(),
                ]);
            }
        }
    }
    let recovered = lab.wait(0, |s| {
        s["height"].as_u64().unwrap() > settled["height"].as_u64().unwrap() + 1
            && s["active"].is_null()
            && s["queued"] == 0
    });
    assert_eq!(
        command(&["question".into(), lab.config(0), d])["status"],
        "NotApproved"
    );
    lab.assert_same(&[0, 1, 2, 3], &recovered);
    for index in 0..4 {
        lab.stop(index);
    }
    for index in 0..4 {
        lab.start(index);
    }
    lab.assert_same(&[0, 1, 2, 3], &recovered);
    let archive = lab.file("observer");
    command(&["export".into(), lab.config(2), archive.clone()]);
    let verified = command(&["verify".into(), lab.file("genesis.bin"), archive.clone()]);
    for field in [
        "state",
        "accounts",
        "claims",
        "reserve_atoms",
        "library_root",
    ] {
        assert_eq!(verified[field], recovered[field]);
    }
    let frame = Path::new(&archive).join("00000001.finality");
    let mut corrupted = fs::read(&frame).unwrap();
    *corrupted.last_mut().unwrap() ^= 1;
    fs::write(frame, corrupted).unwrap();
    assert!(
        !raw(&["verify".into(), lab.file("genesis.bin"), archive])
            .status
            .success()
    );
    for index in 0..4 {
        lab.stop(index);
    }
}
