use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactBlock, ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusProtocolVersion, FixedConsensusBranchV0,
};
use naome_network::{Keypair, PeerId};
use naome_proof::{ArtifactPayload, ProofCertificate};
use serde_json::{Value, json};

mod proofs;
pub use proofs::Proof;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub const BOUND: Duration = Duration::from_secs(15);

pub struct Layout {
    pub root: PathBuf,
}
impl Layout {
    pub fn new() -> Self {
        loop {
            let root = env::temp_dir().join(format!(
                "naome-validator-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    for directory in [
                        "finality-journal",
                        "finality-anchor",
                        "vote-journal",
                        "vote-anchor",
                    ] {
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
    pub fn seed(&self, name: &str, bytes: &[u8]) {
        let path = self.write(name, bytes);
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    pub fn images(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut images = Vec::new();
        for directory in [
            "finality-journal",
            "finality-anchor",
            "vote-journal",
            "vote-anchor",
        ] {
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
}
impl Drop for Layout {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

pub struct Fixture {
    pub definition: ArtifactChainDefinition,
    pub context: ConsensusContextV0,
    pub keys: [SigningKey; 2],
    pub entries: [ActiveAgreementEntry; 2],
    pub noise: [[u8; 32]; 2],
    pub peers: [PeerId; 2],
}
impl Fixture {
    pub fn new() -> Self {
        let definition = ArtifactChainDefinition::new([0x71; 32]);
        let context = ConsensusContextV0::new(
            definition.id(),
            ConsensusGenesisId::from_bytes([0x72; 32]),
            ConsensusProtocolVersion::new(7),
        );
        let keys = [
            SigningKey::from_bytes(&[0x73; 32]),
            SigningKey::from_bytes(&[0x74; 32]),
        ];
        let entries = [
            ActiveAgreementEntry::new(key(&keys[0]), AgreementWeight::new(3)),
            ActiveAgreementEntry::new(key(&keys[1]), AgreementWeight::new(1)),
        ];
        let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
            context,
            &entries,
            ArtifactChainState::new(definition).branch_snapshot(),
        )
        .unwrap();
        assert_eq!(
            branch.begin_round_zero().unwrap().proposer(),
            key(&keys[0]),
            "the actual scheduled proposer must own weight 3"
        );
        let mut noise = [[101; 32], [102; 32]];
        if identity(noise[0]).to_bytes() > identity(noise[1]).to_bytes() {
            noise.swap(0, 1);
        }
        let peers = [identity(noise[0]), identity(noise[1])];
        Self {
            definition,
            context,
            keys,
            entries,
            noise,
            peers,
        }
    }

    pub fn config(
        &self,
        layout: &Layout,
        index: usize,
        mode: &str,
        peer: Option<&str>,
        publish: bool,
    ) -> String {
        layout.seed("signing.seed", &self.keys[index].to_bytes());
        layout.seed("noise.seed", &self.noise[index]);
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
        let peer_id = self.peers[1 - index];
        let peers = peer
            .map(|address| {
                format!(
                    "[{{ peer_id = {:?}, address = {:?} }}]",
                    peer_id.to_string(),
                    address
                )
            })
            .unwrap_or("[]".into());
        let targets = if publish {
            format!("[{:?}]", peer_id.to_string())
        } else {
            "[]".into()
        };
        format!(
            r#"version = 0
mode = "{mode}"
deployment_discriminator = "{deployment}"
genesis_id = "{genesis}"
protocol_version = 7
signing_seed_file = "signing.seed"
{validators}
[directories]
finality_journal = "finality-journal"
finality_anchor = "finality-anchor"
vote_journal = "vote-journal"
vote_anchor = "vote-anchor"
[network]
identity_seed_file = "noise.seed"
listen = "/ip4/127.0.0.1/tcp/0"
peers = {peers}
publication_targets = {targets}
[limits]
finality_max_round = "8"
vote_preparations = "32"
proposal_preparations = "8"
recovery_max_round = "4"
catch_up_heights = "0"
driver_max_round = "4"
[limits.higher]
entries = "8"
bytes = "1048576"
[limits.current]
entries = "8"
bytes = "1048576"
[limits.finality]
entries = "8"
bytes = "1048576"
[limits.nil_precommit]
entries = "8"
bytes = "1048576"
[timeouts.proposal]
base_millis = "60000"
round_increment_millis = "1"
[timeouts.prevote]
base_millis = "60000"
round_increment_millis = "1"
[timeouts.precommit]
base_millis = "60000"
round_increment_millis = "1"
"#,
            deployment = hex(self.definition.deployment_discriminator()),
            genesis = hex(self.context.genesis_id().as_bytes())
        )
    }

    pub fn proposal(&self, layout: &Layout) -> ArtifactBlock {
        let payload = ArtifactPayload::Proof(
            ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, 1]).unwrap(),
        )
        .to_canonical_bytes();
        let artifact = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = ArtifactChainState::new(self.definition)
            .prepare_block(artifact)
            .unwrap();
        layout.write("block.bin", block.to_canonical_bytes());
        layout.write("payload.bin", payload);
        block
    }

    pub fn create_node(&self, layout: &Layout) -> naome_node::FixedValidatorNodeReadyV0 {
        use naome_node::*;
        use naome_storage::*;
        FixedValidatorNodeProvisionV0::new(
            self.definition,
            self.context,
            &self.entries,
            FixedValidatorNodeDirectoriesV0::new(
                &layout.root.join("finality-journal"),
                &layout.root.join("finality-anchor"),
                &layout.root.join("vote-journal"),
                &layout.root.join("vote-anchor"),
            ),
            FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
            FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
            FixedValidatorProposalReplayLimitV0::new(8).unwrap(),
            FixedValidatorSignerRecoveryRoundLimitV0::new(4),
            FixedValidatorSignerCatchUpHeightLimitV0::new(0),
        )
        .create(self.keys[0].clone())
        .unwrap()
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn key(key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(key.verifying_key().to_bytes())
}
fn identity(mut seed: [u8; 32]) -> PeerId {
    Keypair::ed25519_from_bytes(&mut seed)
        .unwrap()
        .public()
        .to_peer_id()
}

pub struct Process {
    pub child: Child,
    pub observed: Vec<Value>,
    receiver: mpsc::Receiver<Value>,
}

impl Process {
    pub fn unobserved(child: Child) -> Self {
        Self {
            child,
            observed: Vec::new(),
            receiver: mpsc::channel().1,
        }
    }

    pub fn start(layout: &Layout, config: &str) -> Self {
        let path = layout.write("validator.toml", config);
        Self::start_path(&path)
    }
    pub fn start_path(path: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_naome-validator"))
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::sync_channel(256);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let value: Value =
                    serde_json::from_str(&line.unwrap()).expect("process output is JSONL");
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
    pub fn send(&mut self, value: Value) {
        self.write(format!("{value}\n").as_bytes());
    }
    pub fn write(&mut self, bytes: &[u8]) {
        self.child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
        self.child.stdin.as_mut().unwrap().flush().unwrap();
    }
    pub fn until(&mut self, predicate: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + BOUND;
        loop {
            let value = self
                .receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|error| {
                    panic!(
                        "process event {error}; observed: {:?}; exit: {:?}",
                        self.observed,
                        self.child.try_wait()
                    )
                });
            self.observed.push(value.clone());
            assert!(self.observed.len() < 4096, "bounded test transcript");
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
    pub fn shutdown(&mut self) -> Value {
        self.send(json!({"command": "shutdown", "id": 900}));
        let stopped = self.event("stopped");
        assert_eq!(stopped["reason"], "shutdown");
        assert!(self.exit().success());
        stopped
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
                "process did not exit with stdin still open"
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
