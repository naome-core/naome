use std::cell::Cell;
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::core::peer_record::PeerRecord;
use tokio::time::timeout;

use super::*;
use crate::address_store::SignedPeerRecord;
use crate::record_exchange::PeerRecordBatch;
use crate::tests::TestDirectory;
use crate::{
    Multiaddr, PeerRecordBootstrapResponder, PeerRecordBootstrapResponderEvent,
    PeerRecordPublicationError,
};

fn candidate(identity: &Keypair, address: Multiaddr, provenance: PeerId) -> DialCandidate {
    DialCandidate::for_test(identity.public().to_peer_id(), address, provenance)
}

fn signed_record(identity: &Keypair, address: Multiaddr) -> SignedPeerRecord {
    let record = PeerRecord::new_interop(identity, vec![address]).unwrap();
    SignedPeerRecord::from_envelope_bytes(record.into_signed_envelope().into_protobuf_encoding())
        .unwrap()
}

async fn listen(server: &mut PeerRecordBootstrapResponder) -> Multiaddr {
    server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    match timeout(Duration::from_secs(10), server.next_event())
        .await
        .expect("learned test responder did not start listening")
    {
        PeerRecordBootstrapResponderEvent::Listening { address } => address,
        event => panic!("learned test responder failed before listening: {event:?}"),
    }
}

async fn receive(
    client: &mut LearnedPeerRecordPullClient,
    server: &mut PeerRecordBootstrapResponder,
) -> LearnedPeerRecordPullEvent {
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => return event,
                event = server.next_event() => match event {
                    PeerRecordBootstrapResponderEvent::ResponseSent { .. }
                    | PeerRecordBootstrapResponderEvent::Listening { .. } => {}
                    event => panic!("learned test responder failed while serving: {event:?}"),
                },
            }
        }
    })
    .await
    .expect("learned peer-record pull timed out")
}

async fn receive_bootstrap(
    client: &mut PeerRecordBootstrapClient,
    server: &mut PeerRecordBootstrapResponder,
) -> PeerRecordBootstrapEvent {
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => return event,
                event = server.next_event() => match event {
                    PeerRecordBootstrapResponderEvent::ResponseSent { .. }
                    | PeerRecordBootstrapResponderEvent::Listening { .. } => {}
                    event => panic!("bootstrap test responder failed while serving: {event:?}"),
                },
            }
        }
    })
    .await
    .expect("configured-bootstrap peer-record pull timed out")
}

fn learned_client_with_test_transport(
    identity: Keypair,
    candidate: DialCandidate,
    transport_address: Multiaddr,
) -> LearnedPeerRecordPullClient {
    let candidates = validate_candidates(identity.public().to_peer_id(), [candidate]).unwrap();
    let endpoint = BootstrapPeer::new(candidates[0].peer_id(), transport_address).unwrap();
    let inner =
        PeerRecordBootstrapClient::from_validated_bootstraps(identity, vec![endpoint]).unwrap();
    LearnedPeerRecordPullClient { inner, candidates }
}

fn address_store_bytes(directory: &TestDirectory) -> Vec<u8> {
    fs::read(directory.path().join("peer-address-store.bin")).unwrap()
}

#[tokio::test]
async fn client_configuration_is_bounded_canonical_and_candidate_specific() {
    let empty =
        LearnedPeerRecordPullClient::new(Keypair::ed25519_from_bytes([250; 32]).unwrap(), [])
            .unwrap();
    assert!(empty.candidates().is_empty());

    let local = Keypair::generate_ed25519();
    let local_peer_id = local.public().to_peer_id();
    let root = Keypair::generate_ed25519().public().to_peer_id();
    let left = Keypair::generate_ed25519();
    let right = Keypair::generate_ed25519();
    let left_candidate = candidate(&left, "/ip4/127.0.0.1/tcp/39001".parse().unwrap(), root);
    let right_candidate = candidate(&right, "/ip4/127.0.0.1/tcp/39002".parse().unwrap(), root);
    let mut client =
        LearnedPeerRecordPullClient::new(local, [right_candidate.clone(), left_candidate.clone()])
            .unwrap();
    assert_eq!(client.local_peer_id(), local_peer_id);
    assert!(
        client.candidates()[0].peer_id().to_bytes() < client.candidates()[1].peer_id().to_bytes()
    );

    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    assert_eq!(
        client.start_pull(unknown),
        Err(LearnedPeerRecordPullStartError::UnknownCandidate(unknown))
    );
    client.start_pull(left.public().to_peer_id()).unwrap();
    assert_eq!(
        client.start_pull(left.public().to_peer_id()),
        Err(LearnedPeerRecordPullStartError::AlreadyActiveOrRetained(
            left.public().to_peer_id()
        ))
    );

    let local = Keypair::generate_ed25519();
    let local_candidate = candidate(&local, "/ip4/127.0.0.1/tcp/39003".parse().unwrap(), root);
    assert!(matches!(
        LearnedPeerRecordPullClient::new(local, [local_candidate]),
        Err(LearnedPeerRecordPullBuildError::LocalCandidate(_))
    ));
    assert!(matches!(
        LearnedPeerRecordPullClient::new(
            Keypair::generate_ed25519(),
            [left_candidate.clone(), left_candidate.clone()]
        ),
        Err(LearnedPeerRecordPullBuildError::DuplicateCandidate(_))
    ));

    let at_limit = (0..MAX_DIAL_CANDIDATES).map(|index| {
        let identity = Keypair::ed25519_from_bytes([u8::try_from(index + 1).unwrap(); 32]).unwrap();
        candidate(
            &identity,
            format!("/ip4/127.0.0.1/tcp/{}", 39_100 + index)
                .parse()
                .unwrap(),
            root,
        )
    });
    let at_limit =
        LearnedPeerRecordPullClient::new(Keypair::ed25519_from_bytes([249; 32]).unwrap(), at_limit)
            .unwrap();
    assert_eq!(at_limit.candidates().len(), MAX_DIAL_CANDIDATES);

    let local = Keypair::generate_ed25519();
    let consumed = Cell::new(0);
    let too_many = std::iter::repeat_with(|| {
        consumed.set(consumed.get() + 1);
        left_candidate.clone()
    });
    assert!(matches!(
        LearnedPeerRecordPullClient::new(local, too_many),
        Err(LearnedPeerRecordPullBuildError::TooManyCandidates {
            actual,
            maximum: MAX_DIAL_CANDIDATES,
        }) if actual == MAX_DIAL_CANDIDATES + 1
    ));
    assert_eq!(consumed.get(), MAX_DIAL_CANDIDATES + 1);
}

#[tokio::test]
async fn exact_noise_authenticated_candidate_owns_response_until_drop() {
    let left_identity = Keypair::ed25519_from_bytes([201; 32]).unwrap();
    let right_identity = Keypair::ed25519_from_bytes([202; 32]).unwrap();
    let (source_identity, other_identity) = if left_identity.public().to_peer_id().to_bytes()
        > right_identity.public().to_peer_id().to_bytes()
    {
        (left_identity, right_identity)
    } else {
        (right_identity, left_identity)
    };
    let source_peer_id = source_identity.public().to_peer_id();
    let other_peer_id = other_identity.public().to_peer_id();
    let advertised = Keypair::generate_ed25519();
    let advertised_peer_id = advertised.public().to_peer_id();
    let advertised_address: Multiaddr = "/ip4/31.1.0.1/tcp/4001".parse().unwrap();
    let source_directory = TestDirectory::new("learned-store-publication");
    let root = Keypair::generate_ed25519().public().to_peer_id();
    let mut source_store = PeerAddressStore::create(
        source_directory.path(),
        source_peer_id,
        [BootstrapPeer::new(root, "/ip4/127.0.0.1/tcp/39000".parse().unwrap()).unwrap()],
    )
    .unwrap();
    let stored_at = SystemTime::now();
    let _ = source_store
        .admit_record(
            root,
            signed_record(&advertised, advertised_address.clone()),
            stored_at,
        )
        .unwrap();
    let response = source_store
        .peer_record_publication(stored_at, &[advertised_peer_id])
        .unwrap();
    assert_eq!(response.records()[0].peer_id(), advertised_peer_id);
    assert_eq!(response.records()[0].addresses(), &[advertised_address]);
    let mut server = PeerRecordBootstrapResponder::new(source_identity, response).unwrap();
    let source_address = listen(&mut server).await;
    let configured = DialCandidate::for_test(source_peer_id, source_address, root);
    let other = DialCandidate::for_test(
        other_peer_id,
        "/ip4/127.0.0.1/tcp/39010".parse().unwrap(),
        root,
    );
    let mut client =
        LearnedPeerRecordPullClient::new(Keypair::generate_ed25519(), [configured.clone(), other])
            .unwrap();
    assert_eq!(client.candidates()[1], configured);

    client.start_pull(source_peer_id).unwrap();
    let LearnedPeerRecordPullEvent::Received(batch) = receive(&mut client, &mut server).await
    else {
        panic!("expected one authenticated learned response")
    };
    assert_eq!(batch.candidate(), &configured);
    assert_eq!(batch.record_count(), 1);
    assert!(!batch.is_empty());
    assert_eq!(
        client.start_pull(source_peer_id),
        Err(LearnedPeerRecordPullStartError::AlreadyActiveOrRetained(
            source_peer_id
        ))
    );
    drop(batch);
    client.start_pull(source_peer_id).unwrap();
}

#[tokio::test]
async fn wrong_noise_identity_reports_the_complete_candidate_and_releases_it() {
    let actual_identity = Keypair::generate_ed25519();
    let mut server =
        PeerRecordBootstrapResponder::new(actual_identity, PeerRecordBatch::new([]).unwrap())
            .unwrap();
    let address = listen(&mut server).await;
    let expected_identity = Keypair::generate_ed25519();
    let expected_peer_id = expected_identity.public().to_peer_id();
    let root = Keypair::generate_ed25519().public().to_peer_id();
    let configured = DialCandidate::for_test(expected_peer_id, address, root);
    let mut client =
        LearnedPeerRecordPullClient::new(Keypair::generate_ed25519(), [configured.clone()])
            .unwrap();

    client.start_pull(expected_peer_id).unwrap();
    let event = receive(&mut client, &mut server).await;
    assert!(matches!(
        event,
        LearnedPeerRecordPullEvent::Failed { candidate, error }
            if candidate == configured
                && matches!(*error, PeerRecordPullFailure::Transport(_))
    ));
    client.start_pull(expected_peer_id).unwrap();
}

#[tokio::test]
async fn failed_consuming_admission_releases_the_candidate_slot() {
    let source_identity = Keypair::generate_ed25519();
    let source_peer_id = source_identity.public().to_peer_id();
    let source_record = signed_record(&source_identity, "/ip4/41.1.0.1/tcp/4001".parse().unwrap());
    let mut server =
        PeerRecordBootstrapResponder::new(source_identity, PeerRecordBatch::new([]).unwrap())
            .unwrap();
    let loopback_address = listen(&mut server).await;
    let root_identity = Keypair::generate_ed25519();
    let root_peer_id = root_identity.public().to_peer_id();
    let configured = DialCandidate::for_test(source_peer_id, loopback_address, root_peer_id);
    let local = Keypair::generate_ed25519();
    let directory = TestDirectory::new("learned-admission-release");
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        [BootstrapPeer::new(root_peer_id, "/ip4/127.0.0.1/tcp/4001".parse().unwrap()).unwrap()],
    )
    .unwrap();
    let _ = store
        .admit_record(root_peer_id, source_record, SystemTime::now())
        .unwrap();
    let mut client = LearnedPeerRecordPullClient::new(local, [configured]).unwrap();

    client.start_pull(source_peer_id).unwrap();
    let LearnedPeerRecordPullEvent::Received(batch) = receive(&mut client, &mut server).await
    else {
        panic!("expected an authenticated empty learned response")
    };
    assert!(matches!(
        batch.admit_into(&mut store, SystemTime::now()),
        Err(PeerAddressStoreError::StaleDialCandidate(_))
    ));
    client.start_pull(source_peer_id).unwrap();
}

#[tokio::test]
async fn configured_bootstrap_to_learned_publication_is_atomic_and_reopens() {
    let destination_identity = Keypair::ed25519_from_bytes([211; 32]).unwrap();
    let destination_peer_id = destination_identity.public().to_peer_id();
    let left_root = Keypair::ed25519_from_bytes([212; 32]).unwrap();
    let right_root = Keypair::ed25519_from_bytes([213; 32]).unwrap();
    let (decoy_root, serving_root) = if left_root.public().to_peer_id().to_bytes()
        < right_root.public().to_peer_id().to_bytes()
    {
        (left_root, right_root)
    } else {
        (right_root, left_root)
    };
    let decoy_root_peer_id = decoy_root.public().to_peer_id();
    let serving_root_peer_id = serving_root.public().to_peer_id();
    let learned_identity = Keypair::ed25519_from_bytes([214; 32]).unwrap();
    let learned_peer_id = learned_identity.public().to_peer_id();
    let learned_global_address: Multiaddr = "/ip4/31.1.0.1/tcp/4101".parse().unwrap();
    let learned_record = signed_record(&learned_identity, learned_global_address.clone());
    let mut bootstrap_server = PeerRecordBootstrapResponder::new(
        serving_root.clone(),
        PeerRecordBatch::new([learned_record]).unwrap(),
    )
    .unwrap();
    let serving_root_address = listen(&mut bootstrap_server).await;
    let decoy_bootstrap = BootstrapPeer::new(
        decoy_root_peer_id,
        "/ip4/127.0.0.1/tcp/39000".parse().unwrap(),
    )
    .unwrap();
    let serving_bootstrap = BootstrapPeer::new(serving_root_peer_id, serving_root_address).unwrap();
    let bootstraps = vec![decoy_bootstrap.clone(), serving_bootstrap.clone()];
    let destination_directory = TestDirectory::new("two-hop-discovery-destination");
    let mut destination_store = PeerAddressStore::create(
        destination_directory.path(),
        destination_peer_id,
        bootstraps.clone(),
    )
    .unwrap();
    let mut bootstrap_client =
        PeerRecordBootstrapClient::new(destination_identity.clone(), bootstraps.clone()).unwrap();
    assert_eq!(bootstrap_client.bootstrap_peers().len(), 2);
    assert_eq!(
        bootstrap_client.bootstrap_peers()[1].peer_id(),
        serving_root_peer_id
    );
    bootstrap_client.start_pull(serving_root_peer_id).unwrap();
    let PeerRecordBootstrapEvent::Received(bootstrap_batch) =
        receive_bootstrap(&mut bootstrap_client, &mut bootstrap_server).await
    else {
        panic!("expected one authenticated configured-bootstrap publication")
    };
    assert_eq!(bootstrap_batch.source_peer_id(), serving_root_peer_id);
    let bootstrap_received_at = UNIX_EPOCH + Duration::from_secs(1_000_000);
    let bootstrap_admission = bootstrap_batch
        .admit_into(&mut destination_store, bootstrap_received_at)
        .unwrap();
    assert_eq!(bootstrap_admission.inserted(), 1);
    assert_eq!(destination_store.len().unwrap(), 1);
    drop(bootstrap_client);
    drop(bootstrap_server);

    let mut selected = destination_store
        .dial_candidates(bootstrap_received_at)
        .unwrap();
    assert_eq!(selected.len(), 1);
    let learned_candidate = selected.pop().unwrap();
    assert_eq!(learned_candidate.peer_id(), learned_peer_id);
    assert_eq!(learned_candidate.address(), &learned_global_address);
    assert_eq!(learned_candidate.source_peer_id(), serving_root_peer_id);

    let source_directory = TestDirectory::new("two-hop-discovery-source");
    let mut source_store =
        PeerAddressStore::create(source_directory.path(), learned_peer_id, [decoy_bootstrap])
            .unwrap();
    let advertised_identity = Keypair::ed25519_from_bytes([215; 32]).unwrap();
    let advertised_peer_id = advertised_identity.public().to_peer_id();
    let advertised_address: Multiaddr = "/ip4/51.2.0.1/tcp/4202".parse().unwrap();
    let advertised_record = signed_record(&advertised_identity, advertised_address.clone());
    let advertised_envelope = advertised_record.envelope_bytes().to_vec();
    let destination_record = signed_record(
        &destination_identity,
        "/ip4/41.1.0.1/tcp/4201".parse().unwrap(),
    );
    let source_received_at = bootstrap_received_at + Duration::from_secs(1);
    let _ = source_store
        .admit_record(decoy_root_peer_id, advertised_record, source_received_at)
        .unwrap();
    let _ = source_store
        .admit_record(decoy_root_peer_id, destination_record, source_received_at)
        .unwrap();

    let invalid_publication = source_store
        .peer_record_publication(
            source_received_at,
            &[advertised_peer_id, destination_peer_id],
        )
        .unwrap();
    let mut invalid_server =
        PeerRecordBootstrapResponder::new(learned_identity.clone(), invalid_publication).unwrap();
    let invalid_transport_address = listen(&mut invalid_server).await;
    // Stored learned addresses must be globally routable, while this local
    // multi-node harness can bind only loopback. Keep the real store-produced
    // candidate intact for admission and replace only the test transport dial.
    // Exact production candidate-address dialing remains covered separately.
    let mut invalid_client = learned_client_with_test_transport(
        destination_identity.clone(),
        learned_candidate.clone(),
        invalid_transport_address,
    );
    invalid_client.start_pull(learned_peer_id).unwrap();
    let LearnedPeerRecordPullEvent::Received(invalid_batch) =
        receive(&mut invalid_client, &mut invalid_server).await
    else {
        panic!("expected one authenticated mixed learned publication")
    };
    assert_eq!(invalid_batch.candidate(), &learned_candidate);
    assert_eq!(invalid_batch.record_count(), 2);
    let before_rejection = address_store_bytes(&destination_directory);
    let learned_received_at = source_received_at + Duration::from_secs(1);
    assert!(matches!(
        invalid_batch.admit_into(&mut destination_store, learned_received_at),
        Err(PeerAddressStoreError::LocalRecord(peer_id))
            if *peer_id == destination_peer_id
    ));
    assert_eq!(
        address_store_bytes(&destination_directory),
        before_rejection
    );
    assert_eq!(destination_store.len().unwrap(), 1);
    assert!(matches!(
        destination_store.peer_record_publication(
            learned_received_at,
            &[advertised_peer_id]
        ),
        Err(PeerRecordPublicationError::UnknownSubject(peer_id))
            if *peer_id == advertised_peer_id
    ));
    invalid_client.start_pull(learned_peer_id).unwrap();
    drop(invalid_client);
    drop(invalid_server);

    let publication = source_store
        .peer_record_publication(source_received_at, &[advertised_peer_id])
        .unwrap();
    let mut learned_server =
        PeerRecordBootstrapResponder::new(learned_identity, publication).unwrap();
    let learned_transport_address = listen(&mut learned_server).await;
    let mut learned_client = learned_client_with_test_transport(
        destination_identity,
        learned_candidate.clone(),
        learned_transport_address,
    );
    learned_client.start_pull(learned_peer_id).unwrap();
    let LearnedPeerRecordPullEvent::Received(learned_batch) =
        receive(&mut learned_client, &mut learned_server).await
    else {
        panic!("expected one authenticated learned publication")
    };
    assert_eq!(learned_batch.candidate(), &learned_candidate);
    assert_eq!(learned_batch.record_count(), 1);
    let learned_admission = learned_batch
        .admit_into(&mut destination_store, learned_received_at)
        .unwrap();
    assert_eq!(learned_admission.inserted(), 1);
    assert_eq!(learned_admission.replaced(), 0);
    assert_eq!(learned_admission.ignored_stale(), 0);
    assert_eq!(destination_store.len().unwrap(), 2);
    assert_ne!(
        address_store_bytes(&destination_directory),
        before_rejection
    );
    drop(learned_client);
    drop(learned_server);
    drop(destination_store);

    let reopened = PeerAddressStore::open(
        destination_directory.path(),
        destination_peer_id,
        bootstraps,
    )
    .unwrap();
    assert_eq!(reopened.len().unwrap(), 2);
    let reopened_candidates = reopened.dial_candidates(learned_received_at).unwrap();
    let advertised_candidate = reopened_candidates
        .iter()
        .find(|candidate| candidate.peer_id() == advertised_peer_id)
        .expect("the learned subject must remain dial-eligible after strict reopen");
    assert_eq!(advertised_candidate.address(), &advertised_address);
    assert_eq!(advertised_candidate.source_peer_id(), serving_root_peer_id);
    let reopened_publication = reopened
        .peer_record_publication(learned_received_at, &[advertised_peer_id])
        .unwrap();
    assert_eq!(reopened_publication.records().len(), 1);
    assert_eq!(
        reopened_publication.records()[0].envelope_bytes(),
        advertised_envelope
    );
}
