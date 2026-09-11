use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
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

// Keep process creation disjoint from parent-owned journal lifetimes so a
// child cannot temporarily inherit their lock descriptors before exec.
// The guard covers spawn only; child processes still execute concurrently.
pub static PARENT_JOURNALS: RwLock<()> = RwLock::new(());

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
        self.images_in(&[
            "finality-journal",
            "finality-anchor",
            "vote-journal",
            "vote-anchor",
        ])
    }
    pub fn finality_images(&self) -> Vec<(PathBuf, Vec<u8>)> {
        self.images_in(&["finality-journal", "finality-anchor"])
    }
    pub fn images_in(&self, directories: &[&str]) -> Vec<(PathBuf, Vec<u8>)> {
        let mut images = Vec::new();
        for directory in directories {
            for entry in fs::read_dir(self.root.join(directory)).unwrap() {
                let path = entry.unwrap().path();
                images.push((
                    path.strip_prefix(&self.root).unwrap().to_path_buf(),
                    fs::read(&path).unwrap_or_else(|error| {
                        panic!("read test image {}: {error}", path.display())
                    }),
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

#[test]
fn finality_images_do_not_read_live_vote_paths_and_full_images_remain_strict() {
    use std::{os::unix::fs::symlink, panic::catch_unwind};

    let layout = Layout::new();
    layout.write("finality-journal/committed", b"finality");
    let before = layout.finality_images();
    // A dangling entry deterministically supplies the same NotFound read as
    // a temporary vote snapshot renamed after directory enumeration.
    let transient = layout.root.join("vote-journal/renamed-snapshot");
    symlink("no-longer-present", &transient).unwrap();
    assert_eq!(layout.finality_images(), before);
    assert!(catch_unwind(|| layout.images()).is_err());
    fs::remove_file(&transient).unwrap();
    assert_eq!(layout.images(), before);

    let missing_finality = layout.root.join("finality-anchor/missing-snapshot");
    symlink("no-longer-present", missing_finality).unwrap();
    assert!(catch_unwind(|| layout.finality_images()).is_err());
}

/// Compare authority and incidental files while allowing only the separately
/// specified delivery snapshot to record a receipt or a restart attempt.
pub fn without_delivery_progress(images: &[(PathBuf, Vec<u8>)]) -> Vec<&(PathBuf, Vec<u8>)> {
    images
        .iter()
        .filter(|(path, _)| {
            !path
                .extension()
                .is_some_and(|extension| extension == "deliveries")
        })
        .collect()
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

    /// Strict replay of stopped owners must retain the original signature,
    /// payload and completion identity even if ordinary consensus progressed.
    pub fn retained_proposal(
        &self,
        layout: &Layout,
        round: u64,
    ) -> naome_storage::FixedValidatorSignedProposalV0 {
        use naome_consensus::{ConsensusHeight, ConsensusPosition, ConsensusRound};
        use naome_storage::*;
        let before = layout.images();
        let proposal = {
            let _guard = PARENT_JOURNALS.read().unwrap();
            let finality = FixedValidatorAnchoredFinalityJournalV0::open(
                layout.root.join("finality-journal"),
                layout.root.join("finality-anchor"),
                self.definition,
                self.context,
                &self.entries,
                FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
            )
            .unwrap();
            let journal = FixedValidatorAnchoredVoteSafetyJournalV0::open(
                layout.root.join("vote-journal"),
                layout.root.join("vote-anchor"),
                self.context,
                finality.fixed_agreement_set_id(),
                self.keys[0].clone(),
                FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
            )
            .unwrap();
            assert!(journal.pending_vote().unwrap().is_none());
            assert!(journal.pending_proposal().unwrap().is_none());
            let proposal = journal
                .retained_signed_proposal(ConsensusPosition::new(
                    ConsensusHeight::new(1),
                    ConsensusRound::new(round),
                ))
                .unwrap()
                .unwrap()
                .clone();
            assert!(finality.finalized_len().unwrap() <= 1);
            if let Some(record) = finality.finality_record(ConsensusHeight::new(1)).unwrap() {
                assert_eq!(
                    record.value().proposal_signing_root(),
                    proposal.proposal_signing_root()
                );
                assert_eq!(
                    Some(record.canonical_artifact_bytes()),
                    proposal.canonical_artifact_bytes()
                );
            }
            proposal
        };
        assert_eq!(
            layout.images(),
            before,
            "strict journal replay is read-only"
        );
        proposal
    }

    /// Releasing recovered proposal custody permits fresh votes and finality.
    /// Check exact history prefixes and incidental files; callers also strictly
    /// reopen both anchored journals and compare the retained proposal.
    pub fn assert_append_only_restart_progress(
        &self,
        before: &[(PathBuf, Vec<u8>)],
        after: &[(PathBuf, Vec<u8>)],
    ) {
        let signer = hex(key(&self.keys[0]).as_bytes());
        let vote_journal = PathBuf::from(format!(
            "vote-journal/fixed-validator-vote-safety-{signer}.journal"
        ));
        let vote_anchor = PathBuf::from(format!(
            "vote-anchor/fixed-validator-vote-safety-{signer}.anchor"
        ));
        let deliveries = PathBuf::from(format!(
            "vote-journal/fixed-validator-publication-{signer}.deliveries"
        ));
        assert_eq!(before.len(), after.len());
        for ((path, old), (after_path, new)) in before.iter().zip(after) {
            assert_eq!(path, after_path);
            if path == &vote_journal || path == Path::new("finality-journal/artifact-chain.journal")
            {
                assert!(new.starts_with(old), "recovery rewrote journal {path:?}");
            } else if path == &deliveries {
                assert_ne!(old, new, "recovery must persist its resend attempt");
            } else if path != &vote_anchor
                && path != Path::new("finality-anchor/fixed-validator-finality.anchor")
            {
                assert_eq!(old, new, "recovery changed incidental file {path:?}");
            }
        }
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
    pub transcript_limit: usize,
    receiver: mpsc::Receiver<Value>,
}

impl Process {
    pub fn unobserved(child: Child) -> Self {
        Self {
            child,
            observed: Vec::new(),
            transcript_limit: 4096,
            receiver: mpsc::channel().1,
        }
    }

    pub fn start(layout: &Layout, config: &str) -> Self {
        let path = layout.write("validator.toml", config);
        Self::start_path(&path)
    }
    pub fn start_path(path: &Path) -> Self {
        Self::start_mode(path, false)
    }
    pub fn start_publisher(layout: &Layout, config: &str) -> Self {
        Self::start_mode(&layout.write("publisher.toml", config), true)
    }
    fn start_mode(path: &Path, publisher: bool) -> Self {
        let mut child = spawn(
            Command::new(env!("CARGO_BIN_EXE_naome-validator"))
                .args(publisher.then_some("--publisher"))
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
                    serde_json::from_str(&line.unwrap()).expect("process output is JSONL");
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            observed: Vec::new(),
            transcript_limit: 4096,
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
            assert!(
                self.observed.len() < self.transcript_limit,
                "bounded test transcript"
            );
            if predicate(&value) {
                return value;
            }
        }
    }
    pub fn event(&mut self, event: &str) -> Value {
        self.until(|value| value["event"] == event)
    }
    pub fn observe(&mut self, wait: Duration) -> Option<Value> {
        match self.receiver.recv_timeout(wait) {
            Ok(value) => {
                self.observed.push(value.clone());
                assert!(
                    self.observed.len() < self.transcript_limit,
                    "bounded test transcript"
                );
                Some(value)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("process output closed"),
        }
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
