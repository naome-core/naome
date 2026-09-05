use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactChainDefinition, ArtifactDag};
use naome_consensus::{ActiveAgreementEntry, ConsensusContextV0, ConsensusKey, ConsensusRound};
use naome_network::{
    Keypair, Multiaddr, NetworkEvent, PeerId, PeerSessionEvent, StaticArtifactNetwork, StaticPeer,
};
use naome_node::*;
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate};
use naome_storage::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::{env, fs, io};
use tokio::time::timeout;

const STORE_BYTE_LIMIT: u64 = 1 << 20;
static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct TestLayout {
    root: PathBuf,
    finality_journal: PathBuf,
    finality_anchor: PathBuf,
    vote_journal: PathBuf,
    pub vote_anchor: PathBuf,
}

impl TestLayout {
    pub fn new(label: &str) -> Self {
        loop {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = env::temp_dir().join(format!(
                "naome-runtime-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    let finality_journal = root.join("finality-journal");
                    let finality_anchor = root.join("finality-anchor");
                    let vote_journal = root.join("vote-journal");
                    let vote_anchor = root.join("vote-anchor");
                    for directory in [
                        &finality_journal,
                        &finality_anchor,
                        &vote_journal,
                        &vote_anchor,
                    ] {
                        fs::create_dir(directory).unwrap();
                    }
                    return Self {
                        root,
                        finality_journal,
                        finality_anchor,
                        vote_journal,
                        vote_anchor,
                    };
                }
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!("temporary test directory failed: {source}"),
            }
        }
    }

    fn node_directories(&self) -> FixedValidatorNodeDirectoriesV0<'_> {
        FixedValidatorNodeDirectoriesV0::new(
            &self.finality_journal,
            &self.finality_anchor,
            &self.vote_journal,
            &self.vote_anchor,
        )
    }

    pub fn authority_images(&self) -> [Vec<(String, Vec<u8>)>; 4] {
        [
            directory_image(&self.finality_journal),
            directory_image(&self.finality_anchor),
            directory_image(&self.vote_journal),
            directory_image(&self.vote_anchor),
        ]
    }
}

impl Drop for TestLayout {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn directory_image(directory: &Path) -> Vec<(String, Vec<u8>)> {
    let mut image = fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    image.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    image
}

pub fn provision<'input>(
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    entries: &'input [ActiveAgreementEntry],
    layout: &'input TestLayout,
) -> FixedValidatorNodeProvisionV0<'input> {
    FixedValidatorNodeProvisionV0::new(
        definition,
        context,
        entries,
        layout.node_directories(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(8).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(4),
        FixedValidatorSignerCatchUpHeightLimitV0::new(0),
    )
}

pub fn node_driver<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
) -> FixedValidatorNodeDriverV0<'node> {
    FixedValidatorNodeDriverV0::new(
        scope,
        FixedValidatorNodeHigherRoundInboxLimitsV0::new(8, STORE_BYTE_LIMIT).unwrap(),
        FixedValidatorNodeCurrentRoundInboxLimitsV0::new(8, STORE_BYTE_LIMIT).unwrap(),
        FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(8, STORE_BYTE_LIMIT).unwrap(),
        FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(8, STORE_BYTE_LIMIT).unwrap(),
        ConsensusRound::new(4),
    )
    .unwrap()
}

pub fn consensus_key(signing_key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(signing_key.verifying_key().to_bytes())
}

pub fn pairing_payload() -> Vec<u8> {
    ArtifactPayload::Proof(
        ProofCertificate::from_canonical_bytes(&[0x00, 0x00, 0x00, 0x01, 0x10, 0x01]).unwrap(),
    )
    .to_canonical_bytes()
}

pub fn artifact_id(payload: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.to_vec())
        .unwrap()
        .artifact_id()
}

fn address(port: u16) -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

fn ordered_identities() -> (Keypair, Keypair) {
    let first = Keypair::generate_ed25519();
    let second = Keypair::generate_ed25519();
    if first.public().to_peer_id().to_bytes() < second.public().to_peer_id().to_bytes() {
        (first, second)
    } else {
        (second, first)
    }
}

async fn listening_address(network: &mut StaticArtifactNetwork) -> Multiaddr {
    network.listen_on(address(0)).unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            match network.next_event().await {
                NetworkEvent::Listening { address } => return address,
                NetworkEvent::ListenerError { error, .. } => {
                    panic!("network listener failed: {error}")
                }
                NetworkEvent::ListenerClosed { reason, .. } => {
                    panic!("network listener closed: {reason:?}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("network listener did not start")
}

pub async fn connected_pair() -> (StaticArtifactNetwork, StaticArtifactNetwork, PeerId) {
    connected_pair_with_extra(None).await
}

pub async fn connected_pair_with_extra(
    extra: Option<PeerId>,
) -> (StaticArtifactNetwork, StaticArtifactNetwork, PeerId) {
    let (client_identity, server_identity) = ordered_identities();
    let client_peer_id = client_identity.public().to_peer_id();
    let server_peer_id = server_identity.public().to_peer_id();
    let mut server_peers = vec![StaticPeer::new(client_peer_id, address(1))];
    if let Some(extra) = extra {
        server_peers.push(StaticPeer::new(extra, address(1)));
    }
    let mut server = StaticArtifactNetwork::new(server_identity, server_peers).unwrap();
    let server_address = listening_address(&mut server).await;
    let mut client = StaticArtifactNetwork::new(
        client_identity,
        [StaticPeer::new(server_peer_id, server_address)],
    )
    .unwrap();
    let mut client_established = false;
    let mut server_established = false;
    timeout(Duration::from_secs(10), async {
        while !client_established || !server_established {
            tokio::select! {
                event = client.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert_eq!(peer_id, server_peer_id);
                        client_established = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) => {
                        panic!("managed dial to {peer_id} failed")
                    }
                    NetworkEvent::ListenerError { error, .. } => {
                        panic!("client listener failed: {error}")
                    }
                    _ => {}
                },
                event = server.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert_eq!(peer_id, client_peer_id);
                        server_established = true;
                    }
                    NetworkEvent::ListenerError { error, .. } => {
                        panic!("server listener failed: {error}")
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("managed Noise session did not establish");
    (client, server, server_peer_id)
}
