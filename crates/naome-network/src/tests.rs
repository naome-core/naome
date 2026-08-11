use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use libp2p::core::{Endpoint, transport::PortUse};
use libp2p::futures::StreamExt;
use libp2p::swarm::{ConnectionId, NetworkBehaviour, ToSwarm};
use naome::proof_exchange::ProofRequest;
use naome_chain::{AddressedProofCandidate, ProofChainId, ProofDag};
use naome_foundation::FreeVariable;
use naome_proof::{ProofCertificate, ProofStep};
use naome_storage::{ProofChainJournal, ProofChainJournalError};
use tokio::time::timeout;

use super::{
    BuildError, DependencyAcquisitionProgress, MAX_PENDING_REQUESTS, MAX_STATIC_PEERS,
    NetworkEvent, OutboundProofEvent, PeerId, PeerSessionEvent, PendingBudget, RequestStartError,
    StaticPeer, StaticProofNetwork,
};

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) struct TestDirectory {
    path: PathBuf,
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
        fs::read(self.path.join("proof-chain.journal")).unwrap()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

fn pairing_bytes() -> Vec<u8> {
    vec![0x00, 0x00, 0x00, 0x01, 0x10, 0x01]
}

pub(crate) fn create_journal(
    directory: impl AsRef<Path>,
) -> Result<ProofChainJournal, ProofChainJournalError> {
    ProofChainJournal::create(directory, test_chain_id())
}

fn test_chain_id() -> ProofChainId {
    ProofChainId::from_bytes([0x41; 32])
}

pub(crate) fn apply_fresh_blocks(
    journal: &mut ProofChainJournal,
    payloads: impl IntoIterator<Item = Vec<u8>>,
) -> Vec<naome_proof::ProofId> {
    let mut identity = ProofDag::new();
    payloads
        .into_iter()
        .map(|bytes| {
            let proof_id = identity
                .apply_canonical_proof_bytes(bytes.clone())
                .unwrap()
                .proof_id();
            let block = journal.prepare_block(vec![proof_id]).unwrap();
            journal
                .apply_block(&block, vec![AddressedProofCandidate::new(proof_id, bytes)])
                .unwrap();
            proof_id
        })
        .collect()
}

fn apply_referenced_pair(
    journal: &mut ProofChainJournal,
) -> (naome_proof::ProofId, naome_proof::ProofId) {
    let parent_bytes = pairing_bytes();
    let mut identity = ProofDag::new();
    let parent_id = identity
        .apply_canonical_proof_bytes(parent_bytes.clone())
        .unwrap()
        .proof_id();
    let root_bytes = referenced_generalization(parent_id);
    let root_id = identity
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();
    let block = journal.prepare_block(vec![parent_id, root_id]).unwrap();
    journal
        .apply_block(
            &block,
            vec![
                AddressedProofCandidate::new(parent_id, parent_bytes),
                AddressedProofCandidate::new(root_id, root_bytes),
            ],
        )
        .unwrap();
    (parent_id, root_id)
}

fn union_bytes() -> Vec<u8> {
    vec![0x00, 0x00, 0x00, 0x01, 0x10, 0x02]
}

fn referenced_generalization(proof_id: naome_proof::ProofId) -> Vec<u8> {
    ProofCertificate::new(vec![
        ProofStep::ProofReference { proof_id },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(7),
        },
    ])
    .unwrap()
    .into_unchecked_normal_form()
    .canonical_bytes()
    .to_vec()
}

fn request(bytes: [u8; 32]) -> ProofRequest {
    ProofRequest::from_wire_bytes(&bytes).unwrap()
}

fn address(port: u16) -> super::Multiaddr {
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

async fn listening_address(network: &mut StaticProofNetwork) -> super::Multiaddr {
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
    owner: &mut StaticProofNetwork,
    passive: &mut StaticProofNetwork,
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

async fn connected_pair() -> (StaticProofNetwork, StaticProofNetwork, PeerId, PeerId) {
    let (owner_identity, passive_identity) = ordered_identities();
    let owner_peer_id = owner_identity.public().to_peer_id();
    let passive_peer_id = passive_identity.public().to_peer_id();
    let mut passive = StaticProofNetwork::new(
        passive_identity,
        [StaticPeer::new(owner_peer_id, address(1))],
    )
    .unwrap();
    let passive_address = listening_address(&mut passive).await;
    let mut owner = StaticProofNetwork::new(
        owner_identity,
        [StaticPeer::new(passive_peer_id, passive_address)],
    )
    .unwrap();
    await_session(&mut owner, &mut passive, owner_peer_id, passive_peer_id).await;
    (owner, passive, owner_peer_id, passive_peer_id)
}

async fn exchange_once(
    client: &mut StaticProofNetwork,
    server: &mut StaticProofNetwork,
    server_journal: &ProofChainJournal,
    server_peer_id: PeerId,
    request: ProofRequest,
) -> OutboundProofEvent {
    client.request_proof(server_peer_id, request).unwrap();
    receive_once(client, server, server_journal).await
}

async fn receive_once(
    client: &mut StaticProofNetwork,
    server: &mut StaticProofNetwork,
    server_journal: &ProofChainJournal,
) -> OutboundProofEvent {
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundProof(event) = event {
                        if let Some(error) = event.failure() {
                            panic!("outbound proof exchange failed: {error}");
                        }
                        assert!(!event.is_deadline_exceeded(), "proof exchange exceeded its deadline");
                        return event;
                    }
                },
                event = server.next_event() => match event {
                    NetworkEvent::InboundRequest(inbound) => {
                        server.respond_from_journal(inbound, server_journal).unwrap();
                    }
                    NetworkEvent::InboundFailure { error, .. } => {
                        panic!("inbound proof exchange failed: {error}")
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("proof exchange timed out")
}

fn event_is_unavailable(event: &OutboundProofEvent) -> bool {
    match &event.outcome {
        super::OutboundProofOutcome::Response { response, .. } => response.is_unavailable(),
        _ => false,
    }
}

#[tokio::test]
async fn dependency_acquisition_is_unselected_until_one_explicit_atomic_promotion() {
    let (mut client, mut server, _, server_peer_id) = connected_pair().await;

    let server_directory = TestDirectory::new("closure-server");
    let mut server_journal = create_journal(server_directory.path()).unwrap();
    let (parent_id, root_id) = apply_referenced_pair(&mut server_journal);

    let client_directory = TestDirectory::new("closure-client");
    let mut client_journal = create_journal(client_directory.path()).unwrap();
    let empty_bytes = client_directory.journal_bytes();
    let empty_root = client_journal.proof_set_root().unwrap();
    let mut acquisition = client
        .start_dependency_acquisition(&client_journal, server_peer_id, root_id)
        .unwrap();

    let closure = loop {
        let response = receive_once(&mut client, &mut server, &server_journal).await;
        assert!(acquisition.accepts_event(&response));
        assert_eq!(client_directory.journal_bytes(), empty_bytes);
        assert_eq!(client_journal.proof_set_root().unwrap(), empty_root);
        match acquisition
            .on_event(&mut client, &client_journal, response)
            .unwrap()
        {
            DependencyAcquisitionProgress::AwaitingResponse(next) => acquisition = next,
            DependencyAcquisitionProgress::Complete(closure) => break closure,
        }
    };

    assert_eq!(closure.requested_root(), root_id);
    assert_eq!(closure.candidate_count(), 2);
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 2);
    assert_eq!(client_directory.journal_bytes(), empty_bytes);
    assert_eq!(client_journal.proof_set_root().unwrap(), empty_root);
    assert!(client_journal.is_empty().unwrap());

    let block = client_journal
        .prepare_block(vec![parent_id, root_id])
        .unwrap();
    let accepted = closure.apply_block(&mut client_journal, &block).unwrap();
    assert_eq!(accepted.proof_id(), root_id);
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(client_journal.len().unwrap(), 2);
    assert!(client_journal.proof(parent_id).unwrap().is_some());
    assert!(client_journal.proof(root_id).unwrap().is_some());

    let selected_head = client_journal.head_block_id().unwrap();
    drop(client_journal);
    let reopened =
        ProofChainJournal::open_verified(client_directory.path(), test_chain_id(), selected_head)
            .unwrap();
    assert_eq!(reopened.len().unwrap(), 2);
}

#[tokio::test]
async fn dependency_acquisition_falls_back_to_another_authenticated_peer() {
    let mut identities = vec![
        super::Keypair::generate_ed25519(),
        super::Keypair::generate_ed25519(),
        super::Keypair::generate_ed25519(),
    ];
    identities.sort_unstable_by_key(|identity| identity.public().to_peer_id().to_bytes());
    let client_identity = identities.remove(0);
    let preferred_identity = identities.remove(0);
    let fallback_identity = identities.remove(0);
    let client_peer_id = client_identity.public().to_peer_id();
    let preferred_peer_id = preferred_identity.public().to_peer_id();
    let fallback_peer_id = fallback_identity.public().to_peer_id();

    let mut preferred = StaticProofNetwork::new(
        preferred_identity,
        [StaticPeer::new(client_peer_id, address(1))],
    )
    .unwrap();
    let preferred_address = listening_address(&mut preferred).await;
    let mut fallback = StaticProofNetwork::new(
        fallback_identity,
        [StaticPeer::new(client_peer_id, address(2))],
    )
    .unwrap();
    let fallback_address = listening_address(&mut fallback).await;
    let mut client = StaticProofNetwork::new(
        client_identity,
        [
            StaticPeer::new(fallback_peer_id, fallback_address),
            StaticPeer::new(preferred_peer_id, preferred_address),
        ],
    )
    .unwrap();

    let mut client_preferred = false;
    let mut client_fallback = false;
    let mut preferred_client = false;
    let mut fallback_client = false;
    timeout(Duration::from_secs(10), async {
        while !(client_preferred && client_fallback && preferred_client && fallback_client) {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) = event {
                        if peer_id == preferred_peer_id {
                            client_preferred = true;
                        } else if peer_id == fallback_peer_id {
                            client_fallback = true;
                        }
                    }
                },
                event = preferred.next_event() => {
                    if let NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) = event {
                        assert_eq!(peer_id, client_peer_id);
                        preferred_client = true;
                    }
                },
                event = fallback.next_event() => {
                    if let NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) = event {
                        assert_eq!(peer_id, client_peer_id);
                        fallback_client = true;
                    }
                },
            }
        }
    })
    .await
    .expect("all three managed peer sessions did not establish");

    let preferred_directory = TestDirectory::new("fallback-preferred-server");
    let preferred_journal = create_journal(preferred_directory.path()).unwrap();
    let fallback_directory = TestDirectory::new("fallback-source-server");
    let mut fallback_journal = create_journal(fallback_directory.path()).unwrap();
    let (parent_id, root_id) = apply_referenced_pair(&mut fallback_journal);
    let client_directory = TestDirectory::new("fallback-client");
    let mut client_journal = create_journal(client_directory.path()).unwrap();
    let empty_bytes = client_directory.journal_bytes();
    let mut acquisition = client
        .start_dependency_acquisition(&client_journal, preferred_peer_id, root_id)
        .unwrap();
    let mut observed_fallback = false;

    let closure = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    let NetworkEvent::OutboundProof(event) = event else {
                        continue;
                    };
                    assert!(acquisition.accepts_event(&event));
                    let response_peer = event.peer_id();
                    match acquisition.on_event(&mut client, &client_journal, event).unwrap() {
                        DependencyAcquisitionProgress::AwaitingResponse(next) => {
                            if response_peer == preferred_peer_id {
                                assert_eq!(next.pending_peer_id(), fallback_peer_id);
                                observed_fallback = true;
                            }
                            acquisition = next;
                        }
                        DependencyAcquisitionProgress::Complete(closure) => break closure,
                    }
                },
                event = preferred.next_event() => {
                    if let NetworkEvent::InboundRequest(inbound) = event {
                        preferred.respond_from_journal(inbound, &preferred_journal).unwrap();
                    }
                },
                event = fallback.next_event() => {
                    if let NetworkEvent::InboundRequest(inbound) = event {
                        fallback.respond_from_journal(inbound, &fallback_journal).unwrap();
                    }
                },
            }
        }
    })
    .await
    .expect("multi-peer dependency acquisition timed out");

    assert!(observed_fallback);
    assert_eq!(closure.candidate_count(), 2);
    assert_eq!(client_directory.journal_bytes(), empty_bytes);
    assert!(client_journal.is_empty().unwrap());
    let block = client_journal
        .prepare_block(vec![parent_id, root_id])
        .unwrap();
    assert_eq!(
        closure
            .apply_block(&mut client_journal, &block)
            .unwrap()
            .proof_id(),
        root_id
    );
    assert_eq!(client_journal.len().unwrap(), 2);
    assert!(client_journal.proof(parent_id).unwrap().is_some());
}

#[tokio::test]
async fn static_configuration_rejects_local_duplicate_and_excess_peers() {
    let local = super::Keypair::generate_ed25519();
    let local_peer_id = local.public().to_peer_id();
    assert!(matches!(
        StaticProofNetwork::new(local.clone(), [StaticPeer::new(local_peer_id, address(1))]),
        Err(BuildError::LocalPeer(peer_id)) if peer_id == local_peer_id
    ));

    let remote = super::Keypair::generate_ed25519();
    let duplicate = peer(&remote, address(2));
    assert!(matches!(
        StaticProofNetwork::new(local.clone(), [duplicate.clone(), duplicate]),
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
        StaticProofNetwork::new(local, peers),
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

    let mut owner = StaticProofNetwork::new(
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
            .exchange
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
            .exchange
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

    let mut passive = StaticProofNetwork::new(
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
            .exchange
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
    let mut network = StaticProofNetwork::new(
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
async fn outbound_requests_are_authorized_and_bounded() {
    let local = super::Keypair::generate_ed25519();
    let remote = super::Keypair::generate_ed25519();
    let remote_peer_id = remote.public().to_peer_id();
    let mut network =
        StaticProofNetwork::new(local, [StaticPeer::new(remote_peer_id, address(9))]).unwrap();
    let requested = request([0x11; 32]);
    let unknown = super::Keypair::generate_ed25519().public().to_peer_id();

    assert_eq!(
        network.request_proof(unknown, requested),
        Err(RequestStartError::UnknownPeer(unknown))
    );
    assert_eq!(
        network.request_proof(remote_peer_id, requested),
        Err(RequestStartError::PeerDisconnected(remote_peer_id))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_connected_for_test(remote_peer_id);
    network.request_proof(remote_peer_id, requested).unwrap();
    assert_eq!(
        network.request_proof(remote_peer_id, request([0x22; 32])),
        Err(RequestStartError::AlreadyPending(remote_peer_id))
    );

    let limited_local = super::Keypair::generate_ed25519();
    let limited_remote = super::Keypair::generate_ed25519();
    let limited_peer_id = limited_remote.public().to_peer_id();
    let mut limited = StaticProofNetwork::new(
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
        limited.request_proof(limited_peer_id, request([0x55; 32])),
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
        limited.request_proof(limited_peer_id, request([0x66; 32])),
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
        StaticProofNetwork::new(local_passive, [StaticPeer::new(remote_peer_id, address(9))])
            .unwrap();
    let requested = request([0x56; 32]);

    assert_eq!(
        network.request_proof(remote_peer_id, requested),
        Err(RequestStartError::PeerDisconnected(remote_peer_id))
    );
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(
        timeout(Duration::from_millis(50), network.swarm.select_next_some())
            .await
            .is_err(),
        "a disconnected proof request unexpectedly caused network activity"
    );
    assert_eq!(
        network
            .swarm
            .behaviour()
            .sessions
            .connection_status(&remote_peer_id),
        Some(false)
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
        ProofRequest::new(proof_id),
    )
    .await;
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 1);
    assert_eq!(found.peer_id(), server_peer_id);
    assert_eq!(found.request(), ProofRequest::new(proof_id));
    assert!(!event_is_unavailable(&found));
    assert!(client_journal.is_empty().unwrap());
    drop(found);
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(client_journal.proof(proof_id).unwrap().is_none());

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
        .request_proof(peer_b, ProofRequest::new(proof_b))
        .unwrap();
    network_b
        .request_proof(peer_a, ProofRequest::new(proof_a))
        .unwrap();
    let mut response_a = None;
    let mut response_b = None;
    timeout(Duration::from_secs(15), async {
        while response_a.is_none() || response_b.is_none() {
            tokio::select! {
                event = network_a.next_event() => match event {
                    NetworkEvent::InboundRequest(inbound) => {
                        network_a.respond_from_journal(inbound, &journal_a).unwrap();
                    }
                    NetworkEvent::OutboundProof(event) => {
                        if let Some(error) = event.failure() {
                            panic!("peer A request failed: {error}");
                        }
                        assert!(!event.is_deadline_exceeded());
                        response_a = Some(event);
                    }
                    _ => {}
                },
                event = network_b.next_event() => match event {
                    NetworkEvent::InboundRequest(inbound) => {
                        network_b.respond_from_journal(inbound, &journal_b).unwrap();
                    }
                    NetworkEvent::OutboundProof(event) => {
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
    assert_eq!(response_a.request(), ProofRequest::new(proof_b));
    assert_eq!(response_b.peer_id(), peer_a);
    assert_eq!(response_b.request(), ProofRequest::new(proof_a));
    drop(response_a);
    drop(response_b);
    assert!(journal_a.proof(proof_a).unwrap().is_some());
    assert!(journal_a.proof(proof_b).unwrap().is_none());
    assert!(journal_b.proof(proof_b).unwrap().is_some());
    assert!(journal_b.proof(proof_a).unwrap().is_none());
}

#[tokio::test]
async fn a_closed_response_channel_is_never_reported_as_unavailable() {
    let (mut client, mut server, _, server_peer_id) = connected_pair().await;
    client
        .request_proof(server_peer_id, request([0xb6; 32]))
        .unwrap();

    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundProof(event) = event {
                        assert_eq!(event.peer_id(), server_peer_id);
                        if event.failure().is_some() {
                            return;
                        }
                        panic!("closed response channel became a successful proof response");
                    }
                },
                event = server.next_event() => {
                    if let NetworkEvent::InboundRequest(inbound) = event {
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
        StaticProofNetwork::new(server_identity, [peer(&authorized_identity, address(1))]).unwrap();
    let server_address = listening_address(&mut server).await;
    let mut attacker = StaticProofNetwork::new(
        attacker_identity,
        [StaticPeer::new(server_peer_id, server_address)],
    )
    .unwrap();
    assert_eq!(
        attacker.request_proof(server_peer_id, request([0x33; 32])),
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
                            attacker.request_proof(server_peer_id, requested).unwrap();
                            request_started = true;
                        }
                        NetworkEvent::OutboundProof(event) if event.failure().is_some() => {
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
                    if let NetworkEvent::InboundRequest(inbound) = event {
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
        attacker.request_proof(server_peer_id, request([0x34; 32])),
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

    let mut server = StaticProofNetwork::new(
        server_identity,
        [StaticPeer::new(client_peer_id, address(1))],
    )
    .unwrap();
    let server_address = listening_address(&mut server).await;
    let mut client = StaticProofNetwork::new(
        client_identity,
        [StaticPeer::new(claimed_server_peer_id, server_address)],
    )
    .unwrap();
    assert_eq!(
        client.request_proof(claimed_server_peer_id, request([0x44; 32])),
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
                    if let NetworkEvent::InboundRequest(_) = event {
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

    let mut wrong_server = StaticProofNetwork::new(
        wrong_server_identity,
        [StaticPeer::new(client_peer_id, address(1))],
    )
    .unwrap();
    let retry_address = listening_address(&mut wrong_server).await;
    let mut client = StaticProofNetwork::new(
        client_identity,
        [StaticPeer::new(server_peer_id, retry_address.clone())],
    )
    .unwrap();
    assert_eq!(
        client.request_proof(server_peer_id, ProofRequest::new(proof_id)),
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
                    if let NetworkEvent::InboundRequest(_) = event {
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

    let mut server = StaticProofNetwork::new(
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
        ProofRequest::new(proof_id),
    )
    .await;
    assert!(!event_is_unavailable(&response));
}
