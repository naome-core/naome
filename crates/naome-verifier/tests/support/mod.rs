use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactChainDefinition, ArtifactChainState};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusProtocolVersion, FixedConsensusBranchV0,
};
use naome_storage::{
    FixedValidatorAnchoredFinalityJournalV0 as Journal, FixedValidatorFinalityReplayLimitV0,
};
use serde_json::{Value, json};

mod proofs;
pub use proofs::{Proof, envelope};

const BOUND: Duration = Duration::from_secs(15);
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
// A fork must not temporarily inherit another test's parent-owned journal
// descriptors before exec. This excludes spawn only, not child execution.
static PARENT_JOURNALS: RwLock<()> = RwLock::new(());

pub fn spawn(command: &mut Command) -> Child {
    let _guard = PARENT_JOURNALS.write().unwrap();
    command.spawn().unwrap()
}

pub struct Layout {
    pub root: PathBuf,
}

impl Layout {
    pub fn new() -> Self {
        loop {
            let root = env::temp_dir().join(format!(
                "naome-verifier-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    for directory in ["finality-journal", "finality-anchor"] {
                        fs::create_dir(root.join(directory)).unwrap();
                    }
                    return Self { root };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("test directory: {error}"),
            }
        }
    }

    pub fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    pub fn images(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut images = Vec::new();
        for directory in ["finality-journal", "finality-anchor"] {
            for entry in fs::read_dir(self.root.join(directory)).unwrap() {
                let path = entry.unwrap().path();
                images.push((
                    path.strip_prefix(&self.root).unwrap().to_path_buf(),
                    fs::read(&path).unwrap(),
                ));
            }
        }
        images.sort_by(|a, b| a.0.cmp(&b.0));
        images
    }

    pub fn journal(&self) -> PathBuf {
        self.root.join("finality-journal/artifact-chain.journal")
    }
    pub fn anchor(&self) -> PathBuf {
        self.root
            .join("finality-anchor/fixed-validator-finality.anchor")
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

pub struct Fixture {
    pub definition: ArtifactChainDefinition,
    pub context: ConsensusContextV0,
    pub keys: [SigningKey; 4],
    pub entries: Vec<ActiveAgreementEntry>,
}

impl Fixture {
    pub fn new() -> Self {
        let definition = ArtifactChainDefinition::new([0x91; 32]);
        let context = ConsensusContextV0::new(
            definition.id(),
            ConsensusGenesisId::from_bytes([0x92; 32]),
            ConsensusProtocolVersion::new(7),
        );
        let keys = std::array::from_fn(|index| SigningKey::from_bytes(&[0xa0 + index as u8; 32]));
        let entries = keys
            .iter()
            .zip([3, 1, 1, 1])
            .map(|(key, weight)| {
                ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(weight))
            })
            .collect();
        Self {
            definition,
            context,
            keys,
            entries,
        }
    }

    pub fn genesis(&self) -> FixedConsensusBranchV0 {
        FixedConsensusBranchV0::try_from_virtual_genesis(
            self.context,
            &self.entries,
            ArtifactChainState::new(self.definition).branch_snapshot(),
        )
        .unwrap()
    }

    pub fn config(&self, mode: &str) -> String {
        let validators = self
            .entries
            .iter()
            .map(|entry| {
                format!(
                    "[[validators]]\nconsensus_key = {:?}\nweight = {:?}\n",
                    hex(entry.consensus_key().as_bytes()),
                    entry.agreement_weight().units().to_string()
                )
            })
            .collect::<String>();
        format!(
            "version = 0\nmode = {mode:?}\ndeployment_discriminator = {:?}\ngenesis_id = {:?}\nprotocol_version = 7\nfinality_max_round = \"8\"\n{validators}[directories]\nfinality_journal = \"finality-journal\"\nfinality_anchor = \"finality-anchor\"\n",
            hex(self.definition.deployment_discriminator()),
            hex(self.context.genesis_id().as_bytes())
        )
    }

    pub fn inspect<T>(&self, layout: &Layout, inspect: impl FnOnce(&Journal) -> T) -> T {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let journal = Journal::open(
            layout.root.join("finality-journal"),
            layout.root.join("finality-anchor"),
            self.definition,
            self.context,
            &self.entries,
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        )
        .unwrap();
        inspect(&journal)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn consensus_key(key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(key.verifying_key().to_bytes())
}

pub struct Process {
    pub child: Child,
    pub observed: Vec<Value>,
    receiver: mpsc::Receiver<Value>,
}

impl Process {
    pub fn start(layout: &Layout, config: &str) -> Self {
        Self::start_path(&layout.write("verifier.toml", config))
    }

    pub fn start_path(path: &Path) -> Self {
        Self::start_executable(Path::new(env!("CARGO_BIN_EXE_naome-verifier")), path)
    }

    pub fn start_executable(executable: &Path, path: &Path) -> Self {
        let mut child = spawn(
            Command::new(executable)
                .arg(path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit()),
        );
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::sync_channel(256);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let value: Value =
                    serde_json::from_str(&line.unwrap()).expect("process reports JSONL");
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            observed: Vec::new(),
            receiver,
        }
    }

    pub fn unobserved(child: Child) -> Self {
        Self {
            child,
            observed: Vec::new(),
            receiver: mpsc::channel().1,
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        let input = self.child.stdin.as_mut().unwrap();
        input.write_all(bytes).unwrap();
        input.flush().unwrap();
    }

    pub fn send(&mut self, value: Value) {
        self.write(format!("{value}\n").as_bytes());
    }

    pub fn observe(&mut self) -> Option<Value> {
        match self.receiver.try_recv() {
            Ok(value) => {
                self.observed.push(value.clone());
                assert!(self.observed.len() < 4096, "bounded transcript");
                Some(value)
            }
            Err(mpsc::TryRecvError::Empty) => None,
            Err(error) => panic!("process report channel ended: {error}; {:?}", self.observed),
        }
    }

    pub fn until(&mut self, predicate: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + BOUND;
        loop {
            let value = self
                .receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|error| {
                    panic!(
                        "process event {error}; observed {:?}; exit {:?}",
                        self.observed,
                        self.child.try_wait()
                    )
                });
            self.observed.push(value.clone());
            assert!(self.observed.len() < 4096, "bounded transcript");
            if predicate(&value) {
                return value;
            }
        }
    }

    pub fn event(&mut self, event: &str) -> Value {
        self.until(|value| value["event"] == event)
    }
    pub fn ready(&mut self) -> Value {
        self.event("ready")["state"].clone()
    }

    pub fn request(&mut self, command: Value) -> Value {
        let id = command["id"].clone();
        self.send(command);
        self.until(|value| value["id"] == id)
    }

    pub fn status(&mut self) -> Value {
        let response = self.request(json!({"command": "status", "id": 800}));
        assert_eq!(response["outcome"]["kind"], "status");
        response["outcome"]["state"].clone()
    }

    pub fn shutdown(&mut self) {
        self.send(json!({"command": "shutdown", "id": 900}));
        let stopped = self.event("stopped");
        assert_eq!(stopped["reason"], "shutdown");
        assert_eq!(stopped["locks_released"], true);
        assert!(self.exit().success());
    }

    pub fn signal(&self, signal: rustix::process::Signal) {
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(self.child.id() as i32).unwrap(),
            signal,
        )
        .unwrap();
    }

    pub fn exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + BOUND;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "process did not exit with its pipes open"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
