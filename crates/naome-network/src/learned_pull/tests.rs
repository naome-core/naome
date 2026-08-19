use std::cell::Cell;
use std::time::{Duration, SystemTime};

use libp2p::core::peer_record::PeerRecord;
use tokio::time::timeout;

use super::*;
use crate::address_store::SignedPeerRecord;
use crate::record_exchange::PeerRecordBatch;
use crate::tests::TestDirectory;
use crate::{Multiaddr, PeerRecordBootstrapResponder, PeerRecordBootstrapResponderEvent};

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
