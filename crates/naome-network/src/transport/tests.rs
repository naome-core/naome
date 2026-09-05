use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use libp2p::core::{Endpoint, transport::PortUse};
use libp2p::swarm::{ConnectionId, NetworkBehaviour, ToSwarm};
use naome_chain::{
    ArtifactBlockId, ArtifactChainDefinition, ArtifactChainState, ArtifactDag, ArtifactSetRoot,
};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusPosition, ConsensusProtocolVersion, ConsensusValueV0,
    OwnedVerifiedFixedConsensusTransitionV0, ProposalSigningRoot, VerifiedProducerAuthorizationV0,
};
use naome_foundation::FreeVariable;
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};
use naome_protocol::artifact_exchange::ArtifactRequest;
use naome_storage::{
    ArtifactChainJournal, ArtifactChainJournalError, FixedValidatorFinalityCommitOutcomeV0,
    FixedValidatorFinalityJournalStateIdV0, FixedValidatorFinalityJournalV0,
    FixedValidatorFinalityReplayLimitV0,
};
use tokio::time::{Instant, timeout};

use super::{
    BuildError, INBOUND_APPLICATION_REQUEST_BURST, INBOUND_APPLICATION_REQUEST_REFILL_INTERVAL,
    MAX_PENDING_REQUESTS, MAX_STATIC_PEERS, NetworkEvent, OutboundArtifactEvent, PeerId,
    PeerSessionEvent, PendingBudget, RequestStartError, StaticArtifactNetwork, StaticPeer,
};

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);
const CONSENSUS_AUTHORIZATION_BODY_BYTES: usize = 116;
const CONSENSUS_VOTE_BODY_BYTES: usize = 118;

pub(crate) struct TestDirectory {
    path: PathBuf,
}
pub(crate) struct JournalSnapshot {
    pub(crate) bytes: Vec<u8>,
    pub(crate) head: ArtifactBlockId,
    pub(crate) root: ArtifactSetRoot,
    pub(crate) len: usize,
}

pub(crate) struct FinalityJournalSnapshot {
    bytes: Vec<u8>,
    state_id: FixedValidatorFinalityJournalStateIdV0,
    head: ArtifactBlockId,
    root: ArtifactSetRoot,
    finalized_len: usize,
}

pub(crate) struct FinalityFixture {
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    proposer: SigningKey,
    entries: [ActiveAgreementEntry; 1],
    replay_limit: FixedValidatorFinalityReplayLimitV0,
    selected: ArtifactChainState,
}

pub(crate) fn snapshot(
    directory: &TestDirectory,
    journal: &ArtifactChainJournal,
) -> JournalSnapshot {
    JournalSnapshot {
        bytes: directory.journal_bytes(),
        head: journal.head_block_id().unwrap(),
        root: journal.artifact_set_root().unwrap(),
        len: journal.len().unwrap(),
    }
}

pub(crate) fn assert_snapshot(
    directory: &TestDirectory,
    journal: &ArtifactChainJournal,
    expected: &JournalSnapshot,
) {
    assert_eq!(directory.journal_bytes(), expected.bytes);
    assert_eq!(journal.head_block_id().unwrap(), expected.head);
    assert_eq!(journal.artifact_set_root().unwrap(), expected.root);
    assert_eq!(journal.len().unwrap(), expected.len);
}

pub(crate) fn finality_snapshot(
    directory: &TestDirectory,
    journal: &FixedValidatorFinalityJournalV0,
) -> FinalityJournalSnapshot {
    FinalityJournalSnapshot {
        bytes: directory.journal_bytes(),
        state_id: journal.state_id().unwrap(),
        head: journal.artifact_head_block_id().unwrap(),
        root: journal.artifact_set_root().unwrap(),
        finalized_len: journal.finalized_len().unwrap(),
    }
}

pub(crate) fn assert_finality_snapshot(
    directory: &TestDirectory,
    journal: &FixedValidatorFinalityJournalV0,
    expected: &FinalityJournalSnapshot,
) {
    assert_eq!(directory.journal_bytes(), expected.bytes);
    assert_eq!(journal.state_id().unwrap(), expected.state_id);
    assert_eq!(journal.artifact_head_block_id().unwrap(), expected.head);
    assert_eq!(journal.artifact_set_root().unwrap(), expected.root);
    assert_eq!(journal.finalized_len().unwrap(), expected.finalized_len);
}

impl FinalityFixture {
    pub(crate) fn new() -> Self {
        let definition = test_chain_definition();
        let context = ConsensusContextV0::new(
            definition.id(),
            ConsensusGenesisId::from_bytes([0x52; 32]),
            ConsensusProtocolVersion::new(1),
        );
        let proposer = consensus_signing_key();
        let entries = [ActiveAgreementEntry::new(
            ConsensusKey::from_bytes(proposer.verifying_key().to_bytes()),
            AgreementWeight::new(1),
        )];
        Self {
            definition,
            context,
            proposer,
            entries,
            replay_limit: FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
            selected: ArtifactChainState::new(definition),
        }
    }

    pub(crate) fn create(&self, directory: &TestDirectory) -> FixedValidatorFinalityJournalV0 {
        FixedValidatorFinalityJournalV0::create(
            directory.path(),
            self.definition,
            self.context,
            &self.entries,
            self.replay_limit,
        )
        .unwrap()
    }

    pub(crate) fn commit_payload(
        &mut self,
        journal: &mut FixedValidatorFinalityJournalV0,
        payload: Vec<u8>,
    ) -> ArtifactBlockId {
        let transition = self.transition(journal, payload, 0);
        let block = transition.value().artifact_block();
        let block_id = block.id();
        let payload = transition.canonical_artifact_bytes().to_vec();
        assert!(matches!(
            journal.commit_verified(transition).unwrap(),
            FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
        ));
        self.selected.apply_block(&block, payload).unwrap();
        block_id
    }

    pub(crate) fn halt_with_conflict(
        &mut self,
        journal: &mut FixedValidatorFinalityJournalV0,
        selected_payload: Vec<u8>,
        conflicting_payload: Vec<u8>,
    ) {
        let selected = self.transition(journal, selected_payload, 0);
        let conflicting = self.transition(journal, conflicting_payload, 1);
        let selected_block = selected.value().artifact_block();
        let selected_payload = selected.canonical_artifact_bytes().to_vec();
        assert!(matches!(
            journal.commit_verified(selected).unwrap(),
            FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
        ));
        self.selected
            .apply_block(&selected_block, selected_payload)
            .unwrap();
        assert!(matches!(
            journal.commit_verified(conflicting).unwrap(),
            FixedValidatorFinalityCommitOutcomeV0::Halted(_)
        ));
    }

    fn transition(
        &self,
        journal: &FixedValidatorFinalityJournalV0,
        payload: Vec<u8>,
        round: u64,
    ) -> OwnedVerifiedFixedConsensusTransitionV0 {
        let artifact_id = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = self.selected.prepare_block(artifact_id).unwrap();
        let mut cursor = journal.head().unwrap().begin_round_zero().unwrap();
        for _ in 0..round {
            cursor = cursor.advance_round().unwrap();
        }
        let value = cursor.value_for_artifact_block(block);
        let bytes = consensus_envelope_bytes(value, cursor.position(), &self.proposer);
        cursor
            .decode_and_verify(&bytes, payload)
            .unwrap()
            .into_owned()
    }
}

impl TestDirectory {
    pub(crate) fn new(label: &str) -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-network-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!("temporary test directory failed: {source}"),
            }
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn journal_bytes(&self) -> Vec<u8> {
        fs::read(self.path.join("artifact-chain.journal")).unwrap()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

pub(crate) fn pairing_bytes() -> Vec<u8> {
    ArtifactPayload::Proof(
        ProofCertificate::from_canonical_bytes(&[0x00, 0x00, 0x00, 0x01, 0x10, 0x01]).unwrap(),
    )
    .to_canonical_bytes()
}

pub(crate) fn test_network_for_peers(peer_ids: &[super::PeerId]) -> StaticArtifactNetwork {
    let local = super::Keypair::generate_ed25519();
    assert!(!peer_ids.contains(&local.public().to_peer_id()));
    let peers = peer_ids
        .iter()
        .copied()
        .enumerate()
        .map(|(index, peer_id)| {
            StaticPeer::new(peer_id, address(u16::try_from(9 + index).unwrap()))
        })
        .collect::<Vec<_>>();
    let mut network = StaticArtifactNetwork::new(local, peers).unwrap();
    for &peer_id in peer_ids {
        network
            .swarm
            .behaviour_mut()
            .sessions
            .mark_connected_for_test(peer_id);
    }
    network
}

pub(crate) fn create_journal(
    directory: impl AsRef<Path>,
) -> Result<ArtifactChainJournal, ArtifactChainJournalError> {
    ArtifactChainJournal::create(directory, test_chain_definition())
}

pub(crate) fn test_chain_definition() -> ArtifactChainDefinition {
    ArtifactChainDefinition::new([0x41; 32])
}

fn consensus_signing_key() -> SigningKey {
    let mut seed = [0_u8; 32];
    seed[..2].copy_from_slice(&1_u16.to_be_bytes());
    seed[2] = 0xa5;
    SigningKey::from_bytes(&seed)
}

fn consensus_authorization_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    root: ProposalSigningRoot,
    proposer: &SigningKey,
) -> [u8; VerifiedProducerAuthorizationV0::BYTE_LENGTH] {
    let mut body = [0_u8; CONSENSUS_AUTHORIZATION_BODY_BYTES];
    body[..32].copy_from_slice(context.chain_id().as_bytes());
    body[32..64].copy_from_slice(context.genesis_id().as_bytes());
    body[64..68].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[68..76].copy_from_slice(&position.height().value().to_be_bytes());
    body[76..84].copy_from_slice(&position.round().value().to_be_bytes());
    body[84..].copy_from_slice(root.as_bytes());
    let proposer_key = ConsensusKey::from_bytes(proposer.verifying_key().to_bytes());
    let mut transcript = b"naome:consensus-producer-authorization:v0\0".to_vec();
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(proposer_key.as_bytes());
    let mut bytes = [0_u8; VerifiedProducerAuthorizationV0::BYTE_LENGTH];
    bytes[..CONSENSUS_AUTHORIZATION_BODY_BYTES].copy_from_slice(&body);
    bytes[CONSENSUS_AUTHORIZATION_BODY_BYTES..CONSENSUS_AUTHORIZATION_BODY_BYTES + 32]
        .copy_from_slice(proposer_key.as_bytes());
    bytes[CONSENSUS_AUTHORIZATION_BODY_BYTES + 32..]
        .copy_from_slice(&proposer.sign(&transcript).to_bytes());
    bytes
}

fn consensus_certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    root: ProposalSigningRoot,
    signer: &SigningKey,
) -> Vec<u8> {
    let mut body = [0_u8; CONSENSUS_VOTE_BODY_BYTES];
    body[0] = 2;
    body[1..33].copy_from_slice(context.chain_id().as_bytes());
    body[33..65].copy_from_slice(context.genesis_id().as_bytes());
    body[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    body[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    body[85] = 1;
    body[86..].copy_from_slice(root.as_bytes());
    let key = ConsensusKey::from_bytes(signer.verifying_key().to_bytes());
    let mut transcript = b"naome:consensus-precommit-signing:v0\0".to_vec();
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(key.as_bytes());
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&signer.sign(&transcript).to_bytes());
    bytes
}

fn consensus_envelope_bytes(
    value: ConsensusValueV0,
    position: ConsensusPosition,
    proposer: &SigningKey,
) -> Vec<u8> {
    let root = value.proposal_signing_root();
    let authorization = consensus_authorization_bytes(value.context(), position, root, proposer);
    let certificate = consensus_certificate_bytes(value.context(), position, root, proposer);
    let mut bytes = value.to_canonical_bytes().to_vec();
    bytes.extend_from_slice(&authorization);
    bytes.extend_from_slice(&certificate);
    bytes
}

pub(crate) fn apply_fresh_blocks(
    journal: &mut ArtifactChainJournal,
    payloads: impl IntoIterator<Item = Vec<u8>>,
) -> Vec<ArtifactId> {
    let mut identity = ArtifactDag::new();
    payloads
        .into_iter()
        .map(|bytes| {
            let artifact_id = identity
                .apply_canonical_artifact_bytes(bytes.clone())
                .unwrap()
                .artifact_id();
            let block = journal.prepare_block(artifact_id).unwrap();
            journal.apply_block(&block, bytes).unwrap();
            artifact_id
        })
        .collect()
}

fn apply_referenced_pair(journal: &mut ArtifactChainJournal) -> (ArtifactId, ArtifactId) {
    let parent_bytes = pairing_bytes();
    let mut identity = ArtifactDag::new();
    let parent_record = identity
        .apply_canonical_artifact_bytes(parent_bytes.clone())
        .unwrap();
    let parent_artifact_id = parent_record.artifact_id();
    let parent_proof_id = parent_record.as_proof().unwrap().proof_id();
    let root_bytes = referenced_generalization(parent_proof_id);
    let root_artifact_id = identity
        .apply_canonical_artifact_bytes(root_bytes.clone())
        .unwrap()
        .artifact_id();
    let parent_block = journal.prepare_block(parent_artifact_id).unwrap();
    journal.apply_block(&parent_block, parent_bytes).unwrap();
    let root_block = journal.prepare_block(root_artifact_id).unwrap();
    journal.apply_block(&root_block, root_bytes).unwrap();
    (parent_artifact_id, root_artifact_id)
}

pub(crate) fn union_bytes() -> Vec<u8> {
    ArtifactPayload::Proof(
        ProofCertificate::from_canonical_bytes(&[0x00, 0x00, 0x00, 0x01, 0x10, 0x02]).unwrap(),
    )
    .to_canonical_bytes()
}

fn referenced_generalization(proof_id: naome_proof::ProofId) -> Vec<u8> {
    let normal = ProofCertificate::new(vec![
        ProofStep::ProofReference { proof_id },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(7),
        },
    ])
    .unwrap()
    .into_unchecked_normal_form();
    ArtifactPayload::Proof(normal.certificate().clone()).to_canonical_bytes()
}

fn request(bytes: [u8; 32]) -> ArtifactRequest {
    ArtifactRequest::from_wire_bytes(&bytes).unwrap()
}

pub(crate) fn address(port: u16) -> super::Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

fn peer(identity: &super::Keypair, address: super::Multiaddr) -> StaticPeer {
    StaticPeer::new(identity.public().to_peer_id(), address)
}

fn ordered_identities() -> (super::Keypair, super::Keypair) {
    let first = super::Keypair::generate_ed25519();
    let second = super::Keypair::generate_ed25519();
    if first.public().to_peer_id().to_bytes() < second.public().to_peer_id().to_bytes() {
        (first, second)
    } else {
        (second, first)
    }
}

pub(crate) async fn listening_address(network: &mut StaticArtifactNetwork) -> super::Multiaddr {
    network.listen_on(address(0)).unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            match network.next_event().await {
                NetworkEvent::Listening { address } => return address,
                NetworkEvent::ListenerError { error, .. } => {
                    panic!("listener failed: {error}")
                }
                NetworkEvent::ListenerClosed { reason, .. } => {
                    panic!("listener closed: {reason:?}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("listener did not start")
}

async fn await_session(
    owner: &mut StaticArtifactNetwork,
    passive: &mut StaticArtifactNetwork,
    owner_peer_id: PeerId,
    passive_peer_id: PeerId,
) {
    let mut owner_established = false;
    let mut passive_established = false;
    timeout(Duration::from_secs(10), async {
        while !owner_established || !passive_established {
            tokio::select! {
                event = owner.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert_eq!(peer_id, passive_peer_id);
                        owner_established = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) => {
                        panic!("managed dial to {peer_id} failed");
                    }
                    NetworkEvent::ListenerError { error, .. } => panic!("owner listener failed: {error}"),
                    _ => {}
                },
                event = passive.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert_eq!(peer_id, owner_peer_id);
                        passive_established = true;
                    }
                    NetworkEvent::ListenerError { error, .. } => panic!("passive listener failed: {error}"),
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("managed peer session did not establish");
}

pub(crate) async fn connected_pair()
-> (StaticArtifactNetwork, StaticArtifactNetwork, PeerId, PeerId) {
    let (owner_identity, passive_identity) = ordered_identities();
    let owner_peer_id = owner_identity.public().to_peer_id();
    let passive_peer_id = passive_identity.public().to_peer_id();
    let mut passive = StaticArtifactNetwork::new(
        passive_identity,
        [StaticPeer::new(owner_peer_id, address(1))],
    )
    .unwrap();
    let passive_address = listening_address(&mut passive).await;
    let mut owner = StaticArtifactNetwork::new(
        owner_identity,
        [StaticPeer::new(passive_peer_id, passive_address)],
    )
    .unwrap();
    await_session(&mut owner, &mut passive, owner_peer_id, passive_peer_id).await;
    (owner, passive, owner_peer_id, passive_peer_id)
}

async fn exchange_once(
    client: &mut StaticArtifactNetwork,
    server: &mut StaticArtifactNetwork,
    server_journal: &ArtifactChainJournal,
    server_peer_id: PeerId,
    request: ArtifactRequest,
) -> OutboundArtifactEvent {
    client.request_artifact(server_peer_id, request).unwrap();
    receive_once(client, server, server_journal).await
}

async fn receive_once(
    client: &mut StaticArtifactNetwork,
    server: &mut StaticArtifactNetwork,
    server_journal: &ArtifactChainJournal,
) -> OutboundArtifactEvent {
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundArtifact(event) = event {
                        if let Some(error) = event.failure() {
                            panic!("outbound artifact exchange failed: {error}");
                        }
                        assert!(!event.is_deadline_exceeded(), "artifact exchange exceeded its deadline");
                        return event;
                    }
                },
                event = server.next_event() => match event {
                    NetworkEvent::InboundArtifactRequest(inbound) => {
                        server
                            .respond_artifact_from_journal(inbound, server_journal)
                            .unwrap();
                    }
                    NetworkEvent::InboundArtifactFailure { error, .. } => {
                        panic!("inbound artifact exchange failed: {error}")
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("artifact exchange timed out")
}

fn event_is_unavailable(event: &OutboundArtifactEvent) -> bool {
    match &event.outcome {
        super::OutboundArtifactOutcome::Response { response, .. } => response.is_unavailable(),
        _ => false,
    }
}

#[test]
fn referenced_dependency_is_selected_by_an_earlier_block_before_its_child() {
    let directory = TestDirectory::new("referenced-two-blocks");
    let mut journal = create_journal(directory.path()).unwrap();
    let virtual_genesis = journal.head_block_id().unwrap();

    let (parent_id, root_id) = apply_referenced_pair(&mut journal);

    assert_eq!(journal.len().unwrap(), 2);
    assert!(journal.artifact(parent_id).unwrap().is_some());
    assert!(journal.artifact(root_id).unwrap().is_some());
    let root_block = journal
        .block(journal.head_block_id().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(root_block.artifact_id(), root_id);
    let parent_block = journal
        .block(root_block.parent_block_id())
        .unwrap()
        .unwrap();
    assert_eq!(parent_block.artifact_id(), parent_id);
    assert_eq!(parent_block.parent_block_id(), virtual_genesis);
}

#[tokio::test]
async fn static_configuration_rejects_local_duplicate_and_excess_peers() {
    let local = super::Keypair::generate_ed25519();
    let local_peer_id = local.public().to_peer_id();
    assert!(matches!(
        StaticArtifactNetwork::new(local.clone(), [StaticPeer::new(local_peer_id, address(1))]),
        Err(BuildError::LocalPeer(peer_id)) if peer_id == local_peer_id
    ));

    let remote = super::Keypair::generate_ed25519();
    let duplicate = peer(&remote, address(2));
    assert!(matches!(
        StaticArtifactNetwork::new(local.clone(), [duplicate.clone(), duplicate]),
        Err(BuildError::DuplicatePeer(peer_id))
            if peer_id == remote.public().to_peer_id()
    ));

    let peers = (0..=MAX_STATIC_PEERS)
        .map(|index| {
            let remote = super::Keypair::generate_ed25519();
            peer(&remote, address(u16::try_from(index + 10).unwrap()))
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        StaticArtifactNetwork::new(local, peers),
        Err(BuildError::TooManyPeers { actual, maximum })
            if actual == MAX_STATIC_PEERS + 1 && maximum == MAX_STATIC_PEERS
    ));
}

#[tokio::test]
async fn composite_session_hooks_reject_wrong_direction_and_stale_dials() {
    let (owner_identity, passive_identity) = ordered_identities();
    let owner_peer_id = owner_identity.public().to_peer_id();
    let passive_peer_id = passive_identity.public().to_peer_id();
    let local_address = address(8);
    let remote_address = address(9);

    let mut owner = StaticArtifactNetwork::new(
        owner_identity,
        [StaticPeer::new(passive_peer_id, remote_address.clone())],
    )
    .unwrap();
    assert!(
        NetworkBehaviour::handle_established_inbound_connection(
            owner.swarm.behaviour_mut(),
            ConnectionId::new_unchecked(500),
            passive_peer_id,
            &local_address,
            &remote_address,
        )
        .is_err()
    );
    assert!(
        !owner
            .swarm
            .behaviour()
            .artifact_exchange
            .is_connected(&passive_peer_id)
    );

    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let managed_connection_id =
        match NetworkBehaviour::poll(&mut owner.swarm.behaviour_mut().sessions, &mut context) {
            Poll::Ready(ToSwarm::Dial { opts }) => opts.connection_id(),
            _ => panic!("the dial owner did not produce its initial managed dial"),
        };
    let stale_connection_id = ConnectionId::new_unchecked(501);
    assert_ne!(managed_connection_id, stale_connection_id);
    assert!(
        NetworkBehaviour::handle_established_outbound_connection(
            owner.swarm.behaviour_mut(),
            stale_connection_id,
            passive_peer_id,
            &remote_address,
            Endpoint::Dialer,
            PortUse::New,
        )
        .is_err()
    );
    assert!(
        !owner
            .swarm
            .behaviour()
            .artifact_exchange
            .is_connected(&passive_peer_id)
    );
    assert!(
        NetworkBehaviour::handle_established_outbound_connection(
            owner.swarm.behaviour_mut(),
            managed_connection_id,
            passive_peer_id,
            &remote_address,
            Endpoint::Dialer,
            PortUse::New,
        )
        .is_ok()
    );

    let mut passive = StaticArtifactNetwork::new(
        passive_identity,
        [StaticPeer::new(owner_peer_id, local_address.clone())],
    )
    .unwrap();
    assert!(
        NetworkBehaviour::handle_established_outbound_connection(
            passive.swarm.behaviour_mut(),
            ConnectionId::new_unchecked(502),
            owner_peer_id,
            &local_address,
            Endpoint::Dialer,
            PortUse::New,
        )
        .is_err()
    );
    assert!(
        !passive
            .swarm
            .behaviour()
            .artifact_exchange
            .is_connected(&owner_peer_id)
    );
    assert!(
        NetworkBehaviour::handle_established_inbound_connection(
            passive.swarm.behaviour_mut(),
            ConnectionId::new_unchecked(503),
            owner_peer_id,
            &remote_address,
            &local_address,
        )
        .is_ok()
    );
}

#[tokio::test]
async fn connection_limit_rejection_does_not_consume_pre_authentication_budget() {
    let local_identity = super::Keypair::generate_ed25519();
    let remote_identity = super::Keypair::generate_ed25519();
    let remote_peer_id = remote_identity.public().to_peer_id();
    let mut network = StaticArtifactNetwork::new(
        local_identity,
        [StaticPeer::new(remote_peer_id, address(9))],
    )
    .unwrap();
    let local_address = address(8);
    let remote_address = address(9);

    for index in 0..MAX_STATIC_PEERS {
        NetworkBehaviour::handle_pending_inbound_connection(
            &mut network.swarm.behaviour_mut().limits,
            ConnectionId::new_unchecked(index),
            &local_address,
            &remote_address,
        )
        .unwrap();
    }
    let tokens_before = network.swarm.behaviour().sessions.inbound_tokens_for_test();
    assert_eq!(tokens_before, super::INBOUND_AUTH_BURST);

    assert!(
        NetworkBehaviour::handle_pending_inbound_connection(
            network.swarm.behaviour_mut(),
            ConnectionId::new_unchecked(MAX_STATIC_PEERS),
            &local_address,
            &remote_address,
        )
        .is_err()
    );
    assert_eq!(
        network.swarm.behaviour().sessions.inbound_tokens_for_test(),
        tokens_before
    );
}

#[tokio::test]
async fn inbound_application_request_budget_has_exact_burst_and_lazy_refill() {
    let mut network = StaticArtifactNetwork::new(super::Keypair::generate_ed25519(), []).unwrap();
    assert_eq!(
        network.inbound_application_request_budget.tokens(),
        INBOUND_APPLICATION_REQUEST_BURST
    );

    let start = Instant::now();
    network.inbound_application_request_budget = super::rate_limit::TokenBucket::new(
        INBOUND_APPLICATION_REQUEST_BURST,
        INBOUND_APPLICATION_REQUEST_REFILL_INTERVAL,
        start,
    );
    let budget = &mut network.inbound_application_request_budget;
    for _ in 0..INBOUND_APPLICATION_REQUEST_BURST {
        assert!(budget.try_take(start));
    }
    assert!(!budget.try_take(start));
    assert!(
        !budget.try_take(
            start + INBOUND_APPLICATION_REQUEST_REFILL_INTERVAL - Duration::from_nanos(1)
        )
    );
    assert!(budget.try_take(start + INBOUND_APPLICATION_REQUEST_REFILL_INTERVAL));
    assert!(!budget.try_take(start + INBOUND_APPLICATION_REQUEST_REFILL_INTERVAL));
}

#[tokio::test]
async fn outbound_requests_are_authorized_and_bounded() {
    let local = super::Keypair::generate_ed25519();
    let remote = super::Keypair::generate_ed25519();
    let remote_peer_id = remote.public().to_peer_id();
    let mut network =
        StaticArtifactNetwork::new(local, [StaticPeer::new(remote_peer_id, address(9))]).unwrap();
    let requested = request([0x11; 32]);
    let unknown = super::Keypair::generate_ed25519().public().to_peer_id();

    assert_eq!(
        network.request_artifact(unknown, requested),
        Err(RequestStartError::UnknownPeer(unknown))
    );
    assert_eq!(
        network.request_artifact(remote_peer_id, requested),
        Err(RequestStartError::PeerDisconnected(remote_peer_id))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_connected_for_test(remote_peer_id);
    network.request_artifact(remote_peer_id, requested).unwrap();
    assert_eq!(
        network.request_artifact(remote_peer_id, request([0x22; 32])),
        Err(RequestStartError::AlreadyPending(remote_peer_id))
    );

    let limited_local = super::Keypair::generate_ed25519();
    let limited_remote = super::Keypair::generate_ed25519();
    let limited_peer_id = limited_remote.public().to_peer_id();
    let mut limited = StaticArtifactNetwork::new(
        limited_local,
        [StaticPeer::new(limited_peer_id, address(10))],
    )
    .unwrap();
    let budget = Arc::clone(&limited.pending_budget);
    let permits = (0..MAX_PENDING_REQUESTS)
        .map(|_| PendingBudget::try_acquire(&budget).unwrap())
        .collect::<Vec<_>>();
    assert!(PendingBudget::try_acquire(&budget).is_none());
    assert_eq!(
        limited.request_artifact(limited_peer_id, request([0x55; 32])),
        Err(RequestStartError::PeerDisconnected(limited_peer_id))
    );
    assert_eq!(
        limited.pending_budget.active.load(Ordering::Relaxed),
        MAX_PENDING_REQUESTS
    );
    limited
        .swarm
        .behaviour_mut()
        .sessions
        .mark_connected_for_test(limited_peer_id);
    assert_eq!(
        limited.request_artifact(limited_peer_id, request([0x66; 32])),
        Err(RequestStartError::GlobalLimit {
            maximum: MAX_PENDING_REQUESTS,
        })
    );
    drop(permits);
    assert!(PendingBudget::try_acquire(&budget).is_some());
}

#[tokio::test]
async fn a_disconnected_passive_peer_request_cannot_trigger_a_dial() {
    let (remote_owner, local_passive) = ordered_identities();
    let remote_peer_id = remote_owner.public().to_peer_id();
    let mut network =
        StaticArtifactNetwork::new(local_passive, [StaticPeer::new(remote_peer_id, address(9))])
            .unwrap();
    let requested = request([0x56; 32]);

    assert_eq!(
        network.request_artifact(remote_peer_id, requested),
        Err(RequestStartError::PeerDisconnected(remote_peer_id))
    );
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(
        network
            .swarm
            .behaviour()
            .sessions
            .connection_status(&remote_peer_id),
        Some(false)
    );
    assert!(
        !network
            .swarm
            .behaviour()
            .artifact_exchange
            .is_connected(&remote_peer_id)
    );
}

#[tokio::test]
async fn allowed_noise_peers_exchange_found_and_unavailable_responses() {
    let (mut client, mut server, _, server_peer_id) = connected_pair().await;

    let server_directory = TestDirectory::new("server");
    let mut server_journal = create_journal(server_directory.path()).unwrap();
    let proof_id = apply_fresh_blocks(&mut server_journal, [pairing_bytes()])[0];
    let client_directory = TestDirectory::new("client");
    let client_journal = create_journal(client_directory.path()).unwrap();

    let found = exchange_once(
        &mut client,
        &mut server,
        &server_journal,
        server_peer_id,
        ArtifactRequest::new(proof_id),
    )
    .await;
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 1);
    assert_eq!(found.peer_id(), server_peer_id);
    assert_eq!(found.request(), ArtifactRequest::new(proof_id));
    assert!(!event_is_unavailable(&found));
    assert!(client_journal.is_empty().unwrap());
    drop(found);
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(client_journal.artifact(proof_id).unwrap().is_none());

    let unknown = request([0xa5; 32]);
    let unavailable = exchange_once(
        &mut client,
        &mut server,
        &server_journal,
        server_peer_id,
        unknown,
    )
    .await;
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 1);
    assert!(event_is_unavailable(&unavailable));
    let before = client_directory.journal_bytes();
    drop(unavailable);
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(client_directory.journal_bytes(), before);
}

#[tokio::test]
async fn an_established_session_redials_after_close_and_remains_usable() {
    let (mut owner, mut passive, owner_peer_id, passive_peer_id) = connected_pair().await;
    owner.swarm.disconnect_peer_id(passive_peer_id).unwrap();

    let mut owner_disconnected = false;
    let mut passive_disconnected = false;
    let mut owner_reestablished = false;
    let mut passive_reestablished = false;
    timeout(Duration::from_secs(10), async {
        while !owner_reestablished || !passive_reestablished {
            tokio::select! {
                event = owner.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { peer_id }) => {
                        assert_eq!(peer_id, passive_peer_id);
                        owner_disconnected = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert!(owner_disconnected);
                        assert_eq!(peer_id, passive_peer_id);
                        owner_reestablished = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) => {
                        panic!("managed redial to {peer_id} failed");
                    }
                    _ => {}
                },
                event = passive.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { peer_id }) => {
                        assert_eq!(peer_id, owner_peer_id);
                        passive_disconnected = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert!(passive_disconnected);
                        assert_eq!(peer_id, owner_peer_id);
                        passive_reestablished = true;
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("managed session did not re-establish after close");

    let directory = TestDirectory::new("redial-server");
    let journal = create_journal(directory.path()).unwrap();
    let response = exchange_once(
        &mut owner,
        &mut passive,
        &journal,
        passive_peer_id,
        request([0x77; 32]),
    )
    .await;
    assert!(event_is_unavailable(&response));
}

#[tokio::test]
async fn simultaneous_bidirectional_requests_are_correlated() {
    let (mut network_a, mut network_b, peer_a, peer_b) = connected_pair().await;

    let directory_a = TestDirectory::new("bidirectional-a");
    let mut journal_a = create_journal(directory_a.path()).unwrap();
    let proof_a = apply_fresh_blocks(&mut journal_a, [pairing_bytes()])[0];
    let directory_b = TestDirectory::new("bidirectional-b");
    let mut journal_b = create_journal(directory_b.path()).unwrap();
    let proof_b = apply_fresh_blocks(&mut journal_b, [union_bytes()])[0];

    network_a
        .request_artifact(peer_b, ArtifactRequest::new(proof_b))
        .unwrap();
    network_b
        .request_artifact(peer_a, ArtifactRequest::new(proof_a))
        .unwrap();
    let mut response_a = None;
    let mut response_b = None;
    timeout(Duration::from_secs(15), async {
        while response_a.is_none() || response_b.is_none() {
            tokio::select! {
                event = network_a.next_event() => match event {
                    NetworkEvent::InboundArtifactRequest(inbound) => {
                        network_a
                            .respond_artifact_from_journal(inbound, &journal_a)
                            .unwrap();
                    }
                    NetworkEvent::OutboundArtifact(event) => {
                        if let Some(error) = event.failure() {
                            panic!("peer A request failed: {error}");
                        }
                        assert!(!event.is_deadline_exceeded());
                        response_a = Some(event);
                    }
                    _ => {}
                },
                event = network_b.next_event() => match event {
                    NetworkEvent::InboundArtifactRequest(inbound) => {
                        network_b
                            .respond_artifact_from_journal(inbound, &journal_b)
                            .unwrap();
                    }
                    NetworkEvent::OutboundArtifact(event) => {
                        if let Some(error) = event.failure() {
                            panic!("peer B request failed: {error}");
                        }
                        assert!(!event.is_deadline_exceeded());
                        response_b = Some(event);
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("simultaneous bidirectional exchange timed out");

    let response_a = response_a.unwrap();
    let response_b = response_b.unwrap();
    assert_eq!(response_a.peer_id(), peer_b);
    assert_eq!(response_a.request(), ArtifactRequest::new(proof_b));
    assert_eq!(response_b.peer_id(), peer_a);
    assert_eq!(response_b.request(), ArtifactRequest::new(proof_a));
    drop(response_a);
    drop(response_b);
    assert!(journal_a.artifact(proof_a).unwrap().is_some());
    assert!(journal_a.artifact(proof_b).unwrap().is_none());
    assert!(journal_b.artifact(proof_b).unwrap().is_some());
    assert!(journal_b.artifact(proof_a).unwrap().is_none());
}

#[tokio::test]
async fn a_closed_response_channel_is_never_reported_as_unavailable() {
    let (mut client, mut server, _, server_peer_id) = connected_pair().await;
    client
        .request_artifact(server_peer_id, request([0xb6; 32]))
        .unwrap();

    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundArtifact(event) = event {
                        assert_eq!(event.peer_id(), server_peer_id);
                        if event.failure().is_some() {
                            return;
                        }
                        panic!("closed response channel became a successful artifact response");
                    }
                },
                event = server.next_event() => {
                    if let NetworkEvent::InboundArtifactRequest(inbound) = event {
                        drop(inbound);
                    }
                },
            }
        }
    })
    .await
    .expect("closed response channel did not fail");
}

#[tokio::test]
async fn unlisted_authenticated_peer_cannot_deliver_a_request() {
    let (attacker_identity, server_identity) = ordered_identities();
    let server_peer_id = server_identity.public().to_peer_id();
    let attacker_peer_id = attacker_identity.public().to_peer_id();
    let authorized_identity = loop {
        let candidate = super::Keypair::generate_ed25519();
        if candidate.public().to_peer_id().to_bytes() < server_peer_id.to_bytes() {
            break candidate;
        }
    };

    let mut server =
        StaticArtifactNetwork::new(server_identity, [peer(&authorized_identity, address(1))])
            .unwrap();
    let server_address = listening_address(&mut server).await;
    let mut attacker = StaticArtifactNetwork::new(
        attacker_identity,
        [StaticPeer::new(server_peer_id, server_address)],
    )
    .unwrap();
    assert_eq!(
        attacker.request_artifact(server_peer_id, request([0x33; 32])),
        Err(RequestStartError::PeerDisconnected(server_peer_id))
    );
    assert_eq!(attacker.pending_budget.active.load(Ordering::Relaxed), 0);

    let requested = request([0x33; 32]);
    timeout(Duration::from_secs(10), async {
        let mut request_started = false;
        loop {
            tokio::select! {
                event = attacker.next_event() => {
                    match event {
                        NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id })
                            if !request_started =>
                        {
                            assert_eq!(peer_id, server_peer_id);
                            attacker.request_artifact(server_peer_id, requested).unwrap();
                            request_started = true;
                        }
                        NetworkEvent::OutboundArtifact(event) if event.failure().is_some() => {
                            assert_eq!(event.peer_id(), server_peer_id);
                            assert_eq!(event.request(), requested);
                            return;
                        }
                        NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id })
                            if !request_started =>
                        {
                            assert_eq!(peer_id, server_peer_id);
                            return;
                        }
                        _ => {}
                    }
                },
                event = server.next_event() => {
                    if let NetworkEvent::InboundArtifactRequest(inbound) = event {
                        panic!("unlisted peer {} delivered request", inbound.peer_id());
                    }
                },
            }
        }
    })
    .await
    .expect("unlisted peer was not rejected");

    assert_ne!(attacker_peer_id, authorized_identity.public().to_peer_id());
    assert_eq!(
        attacker.request_artifact(server_peer_id, request([0x34; 32])),
        Err(RequestStartError::PeerDisconnected(server_peer_id))
    );
    assert_eq!(attacker.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn expected_peer_id_mismatch_never_delivers_a_request() {
    let (client_identity, claimed_server) = ordered_identities();
    let client_peer_id = client_identity.public().to_peer_id();
    let client_peer_bytes = client_peer_id.to_bytes();
    let server_identity = loop {
        let candidate = super::Keypair::generate_ed25519();
        if candidate.public().to_peer_id().to_bytes() > client_peer_bytes
            && candidate.public().to_peer_id() != claimed_server.public().to_peer_id()
        {
            break candidate;
        }
    };
    let actual_server_peer_id = server_identity.public().to_peer_id();
    let claimed_server_peer_id = claimed_server.public().to_peer_id();

    let mut server = StaticArtifactNetwork::new(
        server_identity,
        [StaticPeer::new(client_peer_id, address(1))],
    )
    .unwrap();
    let server_address = listening_address(&mut server).await;
    let mut client = StaticArtifactNetwork::new(
        client_identity,
        [StaticPeer::new(claimed_server_peer_id, server_address)],
    )
    .unwrap();
    assert_eq!(
        client.request_artifact(claimed_server_peer_id, request([0x44; 32])),
        Err(RequestStartError::PeerDisconnected(claimed_server_peer_id))
    );

    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) = event {
                        assert_eq!(peer_id, claimed_server_peer_id);
                        return;
                    }
                },
                event = server.next_event() => {
                    if let NetworkEvent::InboundArtifactRequest(_) = event {
                        panic!("request reached a peer with the wrong authenticated identity");
                    }
                },
            }
        }
    })
    .await
    .expect("peer identity mismatch was not rejected");

    assert_ne!(actual_server_peer_id, claimed_server_peer_id);
}

#[tokio::test]
async fn static_address_is_reused_after_a_transient_dial_failure() {
    let (client_identity, server_identity) = ordered_identities();
    let server_peer_id = server_identity.public().to_peer_id();
    let client_peer_id = client_identity.public().to_peer_id();
    let client_peer_bytes = client_peer_id.to_bytes();
    let wrong_server_identity = loop {
        let candidate = super::Keypair::generate_ed25519();
        if candidate.public().to_peer_id().to_bytes() > client_peer_bytes
            && candidate.public().to_peer_id() != server_peer_id
        {
            break candidate;
        }
    };
    let server_directory = TestDirectory::new("redial-server");
    let mut server_journal = create_journal(server_directory.path()).unwrap();
    let proof_id = apply_fresh_blocks(&mut server_journal, [pairing_bytes()])[0];

    let mut wrong_server = StaticArtifactNetwork::new(
        wrong_server_identity,
        [StaticPeer::new(client_peer_id, address(1))],
    )
    .unwrap();
    let retry_address = listening_address(&mut wrong_server).await;
    let mut client = StaticArtifactNetwork::new(
        client_identity,
        [StaticPeer::new(server_peer_id, retry_address.clone())],
    )
    .unwrap();
    assert_eq!(
        client.request_artifact(server_peer_id, ArtifactRequest::new(proof_id)),
        Err(RequestStartError::PeerDisconnected(server_peer_id))
    );
    timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) = event {
                        assert_eq!(peer_id, server_peer_id);
                        return;
                    }
                }
                event = wrong_server.next_event() => {
                    if let NetworkEvent::InboundArtifactRequest(_) = event {
                        panic!("request reached a peer with the wrong authenticated identity");
                    }
                }
            }
        }
    })
    .await
    .expect("initial unavailable address did not fail");
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 0);
    drop(wrong_server);

    let mut server = StaticArtifactNetwork::new(
        server_identity,
        [StaticPeer::new(client_peer_id, address(1))],
    )
    .unwrap();
    server.listen_on(retry_address.clone()).unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            if let NetworkEvent::Listening { address: bound } = server.next_event().await {
                assert_eq!(bound, retry_address);
                return;
            }
        }
    })
    .await
    .expect("server did not bind the configured retry address");

    await_session(&mut client, &mut server, client_peer_id, server_peer_id).await;

    let response = exchange_once(
        &mut client,
        &mut server,
        &server_journal,
        server_peer_id,
        ArtifactRequest::new(proof_id),
    )
    .await;
    assert!(!event_is_unavailable(&response));
}
