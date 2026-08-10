use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use naome::proof_exchange::ProofRequest;
use naome_foundation::FreeVariable;
use naome_proof::{ProofCertificate, ProofStep};
use naome_storage::ProofDagJournal;
use tokio::time::timeout;

use super::{
    BuildError, DependencyAcquisitionProgress, MAX_PENDING_REQUESTS, MAX_STATIC_PEERS,
    NetworkEvent, PeerId, PendingBudget, RequestStartError, StaticPeer, StaticProofNetwork,
};

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
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

    fn path(&self) -> &Path {
        &self.path
    }

    fn journal_bytes(&self) -> Vec<u8> {
        fs::read(self.path.join("proof-dag.journal")).unwrap()
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

async fn exchange_once(
    client: &mut StaticProofNetwork,
    server: &mut StaticProofNetwork,
    server_journal: &ProofDagJournal,
    server_peer_id: PeerId,
    request: ProofRequest,
) -> super::ReceivedProofResponse {
    client.request_proof(server_peer_id, request).unwrap();
    receive_once(client, server, server_journal).await
}

async fn receive_once(
    client: &mut StaticProofNetwork,
    server: &mut StaticProofNetwork,
    server_journal: &ProofDagJournal,
) -> super::ReceivedProofResponse {
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => match event {
                    NetworkEvent::Response(response) => return response,
                    NetworkEvent::OutboundFailure { error, .. } => {
                        panic!("outbound proof exchange failed: {error}")
                    }
                    NetworkEvent::ResponsePeerMismatch { expected, actual, .. } => {
                        panic!("response peer mismatch: {expected} != {actual}")
                    }
                    _ => {}
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

#[tokio::test]
async fn dependency_acquisition_is_unselected_until_one_explicit_atomic_promotion() {
    let server_identity = super::Keypair::generate_ed25519();
    let client_identity = super::Keypair::generate_ed25519();
    let server_peer_id = server_identity.public().to_peer_id();
    let client_peer_id = client_identity.public().to_peer_id();

    let mut server = StaticProofNetwork::new(
        server_identity,
        [StaticPeer::new(client_peer_id, address(1))],
    )
    .unwrap();
    let server_address = listening_address(&mut server).await;
    let mut client = StaticProofNetwork::new(
        client_identity,
        [StaticPeer::new(server_peer_id, server_address)],
    )
    .unwrap();

    let server_directory = TestDirectory::new("closure-server");
    let mut server_journal = ProofDagJournal::create(server_directory.path()).unwrap();
    let parent_id = server_journal
        .apply_canonical_proof_bytes(pairing_bytes())
        .unwrap()
        .proof_id();
    let root_id = server_journal
        .apply_canonical_proof_bytes(referenced_generalization(parent_id))
        .unwrap()
        .proof_id();

    let client_directory = TestDirectory::new("closure-client");
    let mut client_journal = ProofDagJournal::create(client_directory.path()).unwrap();
    let empty_bytes = client_directory.journal_bytes();
    let empty_root = client_journal.proof_set_root().unwrap();
    let mut acquisition = client
        .start_dependency_acquisition(&client_journal, server_peer_id, root_id)
        .unwrap();

    let closure = loop {
        let response = receive_once(&mut client, &mut server, &server_journal).await;
        assert!(acquisition.accepts_response(&response));
        assert_eq!(client_directory.journal_bytes(), empty_bytes);
        assert_eq!(client_journal.proof_set_root().unwrap(), empty_root);
        match acquisition
            .on_response(&mut client, &client_journal, response)
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

    let accepted = closure
        .apply_to_selected_state(&mut client_journal)
        .unwrap();
    assert_eq!(accepted.proof_id(), root_id);
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(client_journal.len().unwrap(), 2);
    assert!(client_journal.proof(parent_id).unwrap().is_some());
    assert!(client_journal.proof(root_id).unwrap().is_some());

    let selected_root = client_journal.proof_set_root().unwrap();
    drop(client_journal);
    let reopened = ProofDagJournal::open_verified(client_directory.path(), selected_root).unwrap();
    assert_eq!(reopened.len().unwrap(), 2);
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
        Err(RequestStartError::GlobalLimit {
            maximum: MAX_PENDING_REQUESTS,
        })
    );
    drop(permits);
    assert!(PendingBudget::try_acquire(&budget).is_some());
}

#[tokio::test]
async fn allowed_noise_peers_exchange_found_and_unavailable_responses() {
    let server_identity = super::Keypair::generate_ed25519();
    let client_identity = super::Keypair::generate_ed25519();
    let server_peer_id = server_identity.public().to_peer_id();
    let client_peer_id = client_identity.public().to_peer_id();

    let mut server = StaticProofNetwork::new(
        server_identity,
        [StaticPeer::new(client_peer_id, address(1))],
    )
    .unwrap();
    let server_address = listening_address(&mut server).await;
    let mut client = StaticProofNetwork::new(
        client_identity,
        [StaticPeer::new(server_peer_id, server_address)],
    )
    .unwrap();

    let server_directory = TestDirectory::new("server");
    let mut server_journal = ProofDagJournal::create(server_directory.path()).unwrap();
    let proof_id = server_journal
        .apply_canonical_proof_bytes(pairing_bytes())
        .unwrap()
        .proof_id();
    let client_directory = TestDirectory::new("client");
    let client_journal = ProofDagJournal::create(client_directory.path()).unwrap();

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
    assert!(!found.is_unavailable());
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
    assert!(unavailable.is_unavailable());
    let before = client_directory.journal_bytes();
    drop(unavailable);
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(client_directory.journal_bytes(), before);
}

#[tokio::test]
async fn simultaneous_bidirectional_requests_are_correlated() {
    let identity_a = super::Keypair::generate_ed25519();
    let identity_b = super::Keypair::generate_ed25519();
    let peer_a = identity_a.public().to_peer_id();
    let peer_b = identity_b.public().to_peer_id();
    let reserved_b = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port_b = reserved_b.local_addr().unwrap().port();

    let directory_a = TestDirectory::new("bidirectional-a");
    let mut journal_a = ProofDagJournal::create(directory_a.path()).unwrap();
    let proof_a = journal_a
        .apply_canonical_proof_bytes(pairing_bytes())
        .unwrap()
        .proof_id();
    let directory_b = TestDirectory::new("bidirectional-b");
    let mut journal_b = ProofDagJournal::create(directory_b.path()).unwrap();
    let proof_b = journal_b
        .apply_canonical_proof_bytes(union_bytes())
        .unwrap()
        .proof_id();

    let mut network_a =
        StaticProofNetwork::new(identity_a, [StaticPeer::new(peer_b, address(port_b))]).unwrap();
    let address_a = listening_address(&mut network_a).await;
    drop(reserved_b);
    let mut network_b =
        StaticProofNetwork::new(identity_b, [StaticPeer::new(peer_a, address_a)]).unwrap();
    network_b.listen_on(address(port_b)).unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            if let NetworkEvent::Listening { .. } = network_b.next_event().await {
                return;
            }
        }
    })
    .await
    .expect("second bidirectional listener did not start");

    let warmup = exchange_once(
        &mut network_a,
        &mut network_b,
        &journal_b,
        peer_b,
        request([0x7f; 32]),
    )
    .await;
    assert!(warmup.is_unavailable());
    drop(warmup);

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
                    NetworkEvent::Response(response) => response_a = Some(response),
                    NetworkEvent::OutboundFailure { error, .. } => {
                        panic!("peer A request failed: {error}");
                    }
                    _ => {}
                },
                event = network_b.next_event() => match event {
                    NetworkEvent::InboundRequest(inbound) => {
                        network_b.respond_from_journal(inbound, &journal_b).unwrap();
                    }
                    NetworkEvent::Response(response) => response_b = Some(response),
                    NetworkEvent::OutboundFailure { error, .. } => {
                        panic!("peer B request failed: {error}");
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
    let server_identity = super::Keypair::generate_ed25519();
    let client_identity = super::Keypair::generate_ed25519();
    let server_peer_id = server_identity.public().to_peer_id();
    let client_peer_id = client_identity.public().to_peer_id();
    let mut server = StaticProofNetwork::new(
        server_identity,
        [StaticPeer::new(client_peer_id, address(1))],
    )
    .unwrap();
    let server_address = listening_address(&mut server).await;
    let mut client = StaticProofNetwork::new(
        client_identity,
        [StaticPeer::new(server_peer_id, server_address)],
    )
    .unwrap();
    client
        .request_proof(server_peer_id, request([0xb6; 32]))
        .unwrap();

    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => match event {
                    NetworkEvent::OutboundFailure { peer_id, .. } => {
                        assert_eq!(peer_id, server_peer_id);
                        return;
                    }
                    NetworkEvent::Response(response) => {
                        panic!(
                            "closed response channel became unavailable: {}",
                            response.is_unavailable()
                        );
                    }
                    _ => {}
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
    let server_identity = super::Keypair::generate_ed25519();
    let authorized_identity = super::Keypair::generate_ed25519();
    let attacker_identity = super::Keypair::generate_ed25519();
    let server_peer_id = server_identity.public().to_peer_id();
    let attacker_peer_id = attacker_identity.public().to_peer_id();

    let mut server =
        StaticProofNetwork::new(server_identity, [peer(&authorized_identity, address(1))]).unwrap();
    let server_address = listening_address(&mut server).await;
    let mut attacker = StaticProofNetwork::new(
        attacker_identity,
        [StaticPeer::new(server_peer_id, server_address)],
    )
    .unwrap();
    attacker
        .request_proof(server_peer_id, request([0x33; 32]))
        .unwrap();

    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = attacker.next_event() => {
                    if let NetworkEvent::OutboundFailure { peer_id, .. } = event {
                        assert_eq!(peer_id, server_peer_id);
                        return;
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
}

#[tokio::test]
async fn expected_peer_id_mismatch_never_delivers_a_request() {
    let server_identity = super::Keypair::generate_ed25519();
    let client_identity = super::Keypair::generate_ed25519();
    let claimed_server = super::Keypair::generate_ed25519();
    let actual_server_peer_id = server_identity.public().to_peer_id();
    let claimed_server_peer_id = claimed_server.public().to_peer_id();
    let client_peer_id = client_identity.public().to_peer_id();

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
    client
        .request_proof(claimed_server_peer_id, request([0x44; 32]))
        .unwrap();

    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundFailure { peer_id, .. } = event {
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
    let server_identity = super::Keypair::generate_ed25519();
    let wrong_server_identity = super::Keypair::generate_ed25519();
    let client_identity = super::Keypair::generate_ed25519();
    let server_peer_id = server_identity.public().to_peer_id();
    let client_peer_id = client_identity.public().to_peer_id();
    let server_directory = TestDirectory::new("redial-server");
    let mut server_journal = ProofDagJournal::create(server_directory.path()).unwrap();
    let proof_id = server_journal
        .apply_canonical_proof_bytes(pairing_bytes())
        .unwrap()
        .proof_id();

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
    client
        .request_proof(server_peer_id, ProofRequest::new(proof_id))
        .unwrap();
    timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundFailure { peer_id, .. } = event {
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

    let response = exchange_once(
        &mut client,
        &mut server,
        &server_journal,
        server_peer_id,
        ProofRequest::new(proof_id),
    )
    .await;
    assert!(!response.is_unavailable());
}
