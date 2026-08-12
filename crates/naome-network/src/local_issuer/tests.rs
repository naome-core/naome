use std::cell::Cell;
use std::fmt::Write as _;
use std::fs;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::core::peer_record::PeerRecord;
use libp2p::core::signed_envelope::SignedEnvelope;
use tokio::time::timeout;

use super::*;
use crate::tests::TestDirectory;
use crate::{
    BootstrapPeer, MAX_PEER_ADDRESS_BYTES, PEER_RECORD_TTL, PeerAddressStore, PeerRecordBatch,
    PeerRecordBootstrapClient, PeerRecordBootstrapEvent, PeerRecordBootstrapResponder,
    PeerRecordBootstrapResponderEvent, PeerRecordPullStartError,
};

const INITIAL_SNAPSHOT_GOLDEN: &str = "6e616f6d653a6c6f63616c2d706565722d7265636f72642d69737375657200260024080112208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c00000000000000297ff0498d36069867d61a481976c4944c0e5046bfea4b9a9ce860581aab499210";
const FIRST_ENVELOPE_GOLDEN: &str = "0a24080112208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c120203011a360a260024080112208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c102a1a0a0a08040b010001060fa12a406d2d62f0004a0db491bbdfe9743595f7c67e4009ccd61c4c268bd67f0aad8faba2c768327555cea28a55d627adfd3f6cf8892901d6e43aa119db6d7e19daf30e";

fn deterministic_key(seed: u8) -> Keypair {
    Keypair::ed25519_from_bytes([seed; 32]).unwrap()
}

fn global_address(group: u8, host: u8, port: u16) -> Multiaddr {
    format!("/ip4/{group}.1.0.{host}/tcp/{port}")
        .parse()
        .unwrap()
}

fn unix_time(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn snapshot(directory: &TestDirectory) -> Vec<u8> {
    fs::read(directory.path().join(SNAPSHOT_FILE_NAME)).unwrap()
}

fn write_snapshot(directory: &TestDirectory, bytes: &[u8]) {
    fs::write(directory.path().join(SNAPSHOT_FILE_NAME), bytes).unwrap();
}

fn replace_checksum(bytes: &mut Vec<u8>) {
    bytes.truncate(bytes.len() - CHECKSUM_BYTES);
    bytes.extend_from_slice(&snapshot_checksum(bytes));
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").unwrap();
    }
    encoded
}

struct CountingAddresses {
    observed: Rc<Cell<usize>>,
    next_host: u8,
}

impl CountingAddresses {
    fn new(observed: Rc<Cell<usize>>) -> Self {
        Self {
            observed,
            next_host: 1,
        }
    }
}

impl Iterator for CountingAddresses {
    type Item = Multiaddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.observed.set(self.observed.get() + 1);
        let address = global_address(11, self.next_host, 4_000 + u16::from(self.next_host));
        self.next_host = self.next_host.wrapping_add(1);
        Some(address)
    }
}

#[test]
fn create_issue_and_restart_preserve_exact_monotonic_snapshot() {
    let directory = TestDirectory::new("local-issuer-restart");
    let identity = deterministic_key(1);
    let peer_id = identity.public().to_peer_id();
    let first_address = global_address(11, 1, 4_001);
    let second_addresses = [
        global_address(12, 1, 4_002),
        global_address(13, 1, 4_003),
        global_address(14, 1, 4_004),
        global_address(15, 1, 4_005),
    ];

    let mut issuer = LocalPeerRecordIssuer::create(directory.path(), &identity, 41).unwrap();
    assert_eq!(issuer.peer_id(), peer_id);
    assert_eq!(issuer.last_issued_sequence().unwrap(), 41);

    let bytes = snapshot(&directory);
    assert_eq!(hex(&bytes), INITIAL_SNAPSHOT_GOLDEN);
    assert!(bytes.len() <= MAX_SNAPSHOT_BYTES);
    assert_eq!(&bytes[..SNAPSHOT_HEADER.len()], SNAPSHOT_HEADER);
    let peer_id_length = usize::from(bytes[SNAPSHOT_HEADER.len()]);
    let peer_id_start = SNAPSHOT_HEADER.len() + 1;
    let sequence_start = peer_id_start + peer_id_length;
    assert_eq!(
        &bytes[peer_id_start..sequence_start],
        peer_id.to_bytes().as_slice()
    );
    assert_eq!(
        &bytes[sequence_start..sequence_start + SEQUENCE_BYTES],
        41_u64.to_be_bytes().as_slice()
    );
    assert_eq!(
        &bytes[bytes.len() - CHECKSUM_BYTES..],
        snapshot_checksum(&bytes[..bytes.len() - CHECKSUM_BYTES]).as_slice()
    );

    let first = issuer.issue(&identity, [first_address.clone()]).unwrap();
    assert_eq!(first.peer_id(), peer_id);
    assert_eq!(first.sequence(), 42);
    assert_eq!(first.addresses(), std::slice::from_ref(&first_address));
    assert_eq!(issuer.last_issued_sequence().unwrap(), 42);
    assert_eq!(hex(first.envelope_bytes()), FIRST_ENVELOPE_GOLDEN);

    let envelope = SignedEnvelope::from_protobuf_encoding(first.envelope_bytes()).unwrap();
    let standard = PeerRecord::from_signed_envelope_interop(envelope).unwrap();
    assert_eq!(standard.peer_id(), peer_id);
    assert_eq!(standard.seq(), 42);
    assert_eq!(standard.addresses(), [first_address]);

    let second = issuer.issue(&identity, second_addresses.clone()).unwrap();
    assert_eq!(second.sequence(), 43);
    assert_eq!(second.addresses(), second_addresses);
    drop(issuer);

    assert!(matches!(
        LocalPeerRecordIssuer::create(directory.path(), &identity, 0),
        Err(LocalPeerRecordIssuerError::AlreadyExists(_))
    ));
    let mut reopened = LocalPeerRecordIssuer::open(directory.path(), &identity).unwrap();
    assert_eq!(reopened.last_issued_sequence().unwrap(), 43);
    assert_eq!(
        reopened
            .issue(&identity, [global_address(16, 1, 4_006)])
            .unwrap()
            .sequence(),
        44
    );
}

#[test]
fn identity_and_exhaustion_precede_address_allocation_and_consumption() {
    let directory = TestDirectory::new("local-issuer-precedence");
    let identity = deterministic_key(2);
    let wrong_identity = deterministic_key(3);
    let mut issuer = LocalPeerRecordIssuer::create(directory.path(), &identity, u64::MAX).unwrap();
    let original = snapshot(&directory);

    let wrong_observed = Rc::new(Cell::new(0));
    assert!(matches!(
        issuer.issue(
            &wrong_identity,
            CountingAddresses::new(Rc::clone(&wrong_observed))
        ),
        Err(LocalPeerRecordIssuerError::IdentityMismatch { .. })
    ));
    assert_eq!(wrong_observed.get(), 0);

    let exhausted_observed = Rc::new(Cell::new(0));
    assert!(matches!(
        issuer.issue(
            &identity,
            CountingAddresses::new(Rc::clone(&exhausted_observed))
        ),
        Err(LocalPeerRecordIssuerError::SequenceExhausted)
    ));
    assert_eq!(exhausted_observed.get(), 0);
    assert_eq!(issuer.last_issued_sequence().unwrap(), u64::MAX);
    assert_eq!(snapshot(&directory), original);
}

#[test]
fn invalid_address_inputs_are_bounded_and_leave_the_floor_unchanged() {
    let directory = TestDirectory::new("local-issuer-addresses");
    let identity = deterministic_key(4);
    let mut issuer = LocalPeerRecordIssuer::create(directory.path(), &identity, 7).unwrap();
    let original = snapshot(&directory);

    assert!(matches!(
        issuer.issue(&identity, []),
        Err(LocalPeerRecordIssuerError::InvalidRecord(source))
            if matches!(*source, SignedPeerRecordError::AddressCount { actual: 0, .. })
    ));

    let observed = Rc::new(Cell::new(0));
    assert!(matches!(
        issuer.issue(
            &identity,
            CountingAddresses::new(Rc::clone(&observed))
        ),
        Err(LocalPeerRecordIssuerError::InvalidRecord(source))
            if matches!(*source, SignedPeerRecordError::AddressCount { actual: 5, .. })
    ));
    assert_eq!(observed.get(), MAX_ADDRESSES_PER_PEER_RECORD + 1);

    let duplicate = global_address(17, 1, 4_001);
    assert!(matches!(
        issuer.issue(&identity, [duplicate.clone(), duplicate]),
        Err(LocalPeerRecordIssuerError::InvalidRecord(source))
            if matches!(*source, SignedPeerRecordError::DuplicateAddress { index: 1 })
    ));
    for unsupported in [
        "/ip4/127.0.0.1/tcp/4001",
        "/ip4/18.1.0.1/tcp/0",
        "/ip4/18.1.0.1/udp/4001",
        "/ip4/192.0.2.1/tcp/4001",
        "/ip6/2001:db8::1/tcp/4001",
    ] {
        assert!(matches!(
            issuer.issue(&identity, [unsupported.parse().unwrap()]),
            Err(LocalPeerRecordIssuerError::InvalidRecord(source))
                if matches!(*source, SignedPeerRecordError::UnsupportedAddress { index: 0, .. })
        ));
    }
    let oversized: Multiaddr = format!(
        "/ip4/18.1.0.1/tcp/4001{}",
        "/p2p-circuit".repeat(MAX_PEER_ADDRESS_BYTES)
    )
    .parse()
    .unwrap();
    assert!(oversized.len() > MAX_PEER_ADDRESS_BYTES);
    assert!(matches!(
        issuer.issue(&identity, [oversized]),
        Err(LocalPeerRecordIssuerError::InvalidRecord(source))
            if matches!(
                *source,
                SignedPeerRecordError::AddressTooLong {
                    index: 0,
                    actual,
                    maximum: MAX_PEER_ADDRESS_BYTES
                } if actual > MAX_PEER_ADDRESS_BYTES
            )
    ));
    assert_eq!(issuer.last_issued_sequence().unwrap(), 7);
    assert_eq!(snapshot(&directory), original);

    let maximum = (0..MAX_ADDRESSES_PER_PEER_RECORD)
        .map(|index| global_address(19 + index as u8, 1, 4_100 + index as u16))
        .collect::<Vec<_>>();
    let record = issuer.issue(&identity, maximum.clone()).unwrap();
    assert_eq!(record.sequence(), 8);
    assert_eq!(record.addresses(), maximum);
}

#[test]
fn lock_and_snapshot_tampering_fail_closed() {
    let directory = TestDirectory::new("local-issuer-corruption");
    let identity = deterministic_key(5);
    let other_identity = deterministic_key(6);
    let issuer = LocalPeerRecordIssuer::create(directory.path(), &identity, 23).unwrap();
    assert!(matches!(
        LocalPeerRecordIssuer::open(directory.path(), &identity),
        Err(LocalPeerRecordIssuerError::Locked)
    ));
    let canonical = snapshot(&directory);
    drop(issuer);

    assert!(matches!(
        LocalPeerRecordIssuer::open(directory.path(), &other_identity),
        Err(LocalPeerRecordIssuerError::IdentityMismatch { .. })
    ));

    let mut checksum_corrupt = canonical.clone();
    checksum_corrupt[SNAPSHOT_HEADER.len()] ^= 1;
    write_snapshot(&directory, &checksum_corrupt);
    assert!(matches!(
        LocalPeerRecordIssuer::open(directory.path(), &identity),
        Err(LocalPeerRecordIssuerError::ChecksumMismatch)
    ));

    let mut wrong_header = canonical.clone();
    wrong_header[0] ^= 1;
    replace_checksum(&mut wrong_header);
    write_snapshot(&directory, &wrong_header);
    assert!(matches!(
        LocalPeerRecordIssuer::open(directory.path(), &identity),
        Err(LocalPeerRecordIssuerError::InvalidHeader)
    ));

    let peer_id_length = usize::from(canonical[SNAPSHOT_HEADER.len()]);
    let peer_id_start = SNAPSHOT_HEADER.len() + 1;
    let other_peer_id = other_identity.public().to_peer_id().to_bytes();
    assert_eq!(other_peer_id.len(), peer_id_length);
    let mut wrong_identity = canonical.clone();
    wrong_identity[peer_id_start..peer_id_start + peer_id_length].copy_from_slice(&other_peer_id);
    replace_checksum(&mut wrong_identity);
    write_snapshot(&directory, &wrong_identity);
    assert!(matches!(
        LocalPeerRecordIssuer::open(directory.path(), &identity),
        Err(LocalPeerRecordIssuerError::IdentityMismatch { .. })
    ));

    let mut invalid_identity = canonical.clone();
    invalid_identity[peer_id_start..peer_id_start + peer_id_length].fill(0);
    replace_checksum(&mut invalid_identity);
    write_snapshot(&directory, &invalid_identity);
    assert!(matches!(
        LocalPeerRecordIssuer::open(directory.path(), &identity),
        Err(LocalPeerRecordIssuerError::InvalidPeerId)
    ));

    let mut trailing = canonical.clone();
    trailing.insert(trailing.len() - CHECKSUM_BYTES, 0);
    replace_checksum(&mut trailing);
    write_snapshot(&directory, &trailing);
    assert!(matches!(
        LocalPeerRecordIssuer::open(directory.path(), &identity),
        Err(LocalPeerRecordIssuerError::InvalidSnapshot(
            "trailing bytes"
        ))
    ));

    write_snapshot(&directory, &canonical[..MIN_SNAPSHOT_BYTES - 1]);
    assert!(matches!(
        LocalPeerRecordIssuer::open(directory.path(), &identity),
        Err(LocalPeerRecordIssuerError::InvalidHeader)
    ));

    write_snapshot(&directory, &[0; MAX_SNAPSHOT_BYTES + 1]);
    assert!(matches!(
        LocalPeerRecordIssuer::open(directory.path(), &identity),
        Err(LocalPeerRecordIssuerError::SnapshotTooLong {
            actual,
            maximum: MAX_SNAPSHOT_BYTES
        }) if actual == MAX_SNAPSHOT_BYTES + 1
    ));
}

#[test]
fn ambiguous_commit_failures_poison_and_reopen_old_or_new_snapshot() {
    let directory = TestDirectory::new("local-issuer-poison");
    let identity = deterministic_key(7);
    let wrong_identity = deterministic_key(8);
    let peer_id = identity.public().to_peer_id();
    let mut issuer = LocalPeerRecordIssuer::create(directory.path(), &identity, 10).unwrap();
    let old_snapshot = snapshot(&directory);

    issuer.commit_fault = Some(TestCommitFault::BeforeCommit);
    assert!(matches!(
        issuer.issue(&identity, [global_address(24, 1, 4_001)]),
        Err(LocalPeerRecordIssuerError::Commit { .. })
    ));
    assert_eq!(issuer.peer_id(), peer_id);
    assert!(matches!(
        issuer.last_issued_sequence(),
        Err(LocalPeerRecordIssuerError::Poisoned)
    ));
    let observed = Rc::new(Cell::new(0));
    assert!(matches!(
        issuer.issue(
            &wrong_identity,
            CountingAddresses::new(Rc::clone(&observed))
        ),
        Err(LocalPeerRecordIssuerError::Poisoned)
    ));
    assert_eq!(observed.get(), 0);
    assert_eq!(snapshot(&directory), old_snapshot);
    drop(issuer);

    let mut reopened = LocalPeerRecordIssuer::open(directory.path(), &identity).unwrap();
    assert_eq!(reopened.last_issued_sequence().unwrap(), 10);
    reopened.commit_fault = Some(TestCommitFault::AfterCommit);
    assert!(matches!(
        reopened.issue(&identity, [global_address(25, 1, 4_002)]),
        Err(LocalPeerRecordIssuerError::Commit { .. })
    ));
    assert!(matches!(
        reopened.last_issued_sequence(),
        Err(LocalPeerRecordIssuerError::Poisoned)
    ));
    assert_ne!(snapshot(&directory), old_snapshot);
    drop(reopened);

    let reopened = LocalPeerRecordIssuer::open(directory.path(), &identity).unwrap();
    assert_eq!(reopened.last_issued_sequence().unwrap(), 11);
}

async fn listening_address(responder: &mut PeerRecordBootstrapResponder) -> Multiaddr {
    responder
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    timeout(Duration::from_secs(10), async {
        match responder.next_event().await {
            PeerRecordBootstrapResponderEvent::Listening { address } => address,
            PeerRecordBootstrapResponderEvent::ListenerError { error, .. } => {
                panic!("responder listener failed: {error}")
            }
            PeerRecordBootstrapResponderEvent::ListenerClosed { reason, .. } => {
                panic!("responder listener closed: {reason:?}")
            }
            event => panic!("unexpected responder event before listening: {event:?}"),
        }
    })
    .await
    .expect("responder did not start listening")
}

async fn receive_flushed(
    client: &mut PeerRecordBootstrapClient,
    responder: &mut PeerRecordBootstrapResponder,
) -> crate::AuthenticatedPeerRecordBatch {
    timeout(Duration::from_secs(10), async {
        let mut received = None;
        let mut flushed = false;
        loop {
            if flushed && let Some(batch) = received.take() {
                return batch;
            }
            tokio::select! {
                event = client.next_event(), if received.is_none() => match event {
                    PeerRecordBootstrapEvent::Received(batch) => received = Some(batch),
                    PeerRecordBootstrapEvent::Failed { bootstrap_peer_id, error } => {
                        panic!("pull from {bootstrap_peer_id} failed: {error}")
                    }
                },
                event = responder.next_event(), if !flushed => match event {
                    PeerRecordBootstrapResponderEvent::ResponseSent { .. } => flushed = true,
                    PeerRecordBootstrapResponderEvent::Failed { requester_peer_id, error } => {
                        panic!("response to {requester_peer_id} failed: {error}")
                    }
                    PeerRecordBootstrapResponderEvent::ListenerError { error, .. } => {
                        panic!("responder listener failed: {error}")
                    }
                    PeerRecordBootstrapResponderEvent::ListenerClosed { reason, .. } => {
                        panic!("responder listener closed: {reason:?}")
                    }
                    PeerRecordBootstrapResponderEvent::Listening { .. } => {}
                },
            }
        }
    })
    .await
    .expect("peer-record pull timed out")
}

#[tokio::test]
async fn issued_records_flow_end_to_end_without_conflating_signer_and_source() {
    let issuer_directory = TestDirectory::new("local-issuer-e2e");
    let store_directory = TestDirectory::new("local-issuer-store-e2e");
    let signer = deterministic_key(20);
    let signer_peer_id = signer.public().to_peer_id();
    let mut issuer = LocalPeerRecordIssuer::create(issuer_directory.path(), &signer, 100).unwrap();
    let advertised = global_address(31, 1, 5_001);
    let initial_record = issuer.issue(&signer, [advertised.clone()]).unwrap();
    let next_record = issuer.issue(&signer, [advertised.clone()]).unwrap();

    let first_responder_identity = deterministic_key(21);
    let first_source = first_responder_identity.public().to_peer_id();
    let second_responder_identity = deterministic_key(22);
    let second_source = second_responder_identity.public().to_peer_id();
    assert_ne!(signer_peer_id, first_source);
    assert_ne!(signer_peer_id, second_source);
    let mut first_responder = PeerRecordBootstrapResponder::new(
        first_responder_identity,
        PeerRecordBatch::new([initial_record.clone()]).unwrap(),
    )
    .unwrap();
    let mut second_responder = PeerRecordBootstrapResponder::new(
        second_responder_identity,
        PeerRecordBatch::new([next_record]).unwrap(),
    )
    .unwrap();
    let first_address = listening_address(&mut first_responder).await;
    let second_address = listening_address(&mut second_responder).await;
    let first_bootstrap = BootstrapPeer::new(first_source, first_address).unwrap();
    let second_bootstrap = BootstrapPeer::new(second_source, second_address).unwrap();

    let client_identity = deterministic_key(23);
    let client_peer_id = client_identity.public().to_peer_id();
    assert_ne!(client_peer_id, signer_peer_id);
    let mut client = PeerRecordBootstrapClient::new(
        client_identity,
        [first_bootstrap.clone(), second_bootstrap.clone()],
    )
    .unwrap();
    let mut store = PeerAddressStore::create(
        store_directory.path(),
        client_peer_id,
        [first_bootstrap.clone(), second_bootstrap.clone()],
    )
    .unwrap();

    client.start_pull(first_source).unwrap();
    let initial_batch = receive_flushed(&mut client, &mut first_responder).await;
    assert_eq!(initial_batch.source_peer_id(), first_source);
    let initial_time = 1_000;
    let admission = initial_batch
        .admit_into(&mut store, unix_time(initial_time))
        .unwrap();
    assert_eq!(admission.inserted(), 1);
    assert_eq!(admission.replaced(), 0);
    let stored_snapshot = fs::read(store_directory.path().join("peer-address-store.bin")).unwrap();

    client.start_pull(first_source).unwrap();
    let replay = receive_flushed(&mut client, &mut first_responder).await;
    let replay_admission = replay
        .admit_into(&mut store, unix_time(initial_time + 1_000))
        .unwrap();
    assert_eq!(replay_admission.ignored_stale(), 1);
    assert_eq!(
        fs::read(store_directory.path().join("peer-address-store.bin")).unwrap(),
        stored_snapshot
    );
    assert!(
        store
            .dial_candidates(unix_time(initial_time + PEER_RECORD_TTL.as_secs()))
            .unwrap()
            .is_empty(),
        "an exact replay must not refresh the local receipt time"
    );

    client.start_pull(second_source).unwrap();
    let replacement = receive_flushed(&mut client, &mut second_responder).await;
    assert_eq!(replacement.source_peer_id(), second_source);
    let replacement_time = initial_time + PEER_RECORD_TTL.as_secs();
    let replacement_admission = replacement
        .admit_into(&mut store, unix_time(replacement_time))
        .unwrap();
    assert_eq!(replacement_admission.replaced(), 1);
    let candidates = store.dial_candidates(unix_time(replacement_time)).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].peer_id(), signer_peer_id);
    assert_eq!(candidates[0].address(), &advertised);
    assert_eq!(candidates[0].source_peer_id(), first_source);
    drop(store);

    let reopened = PeerAddressStore::open(
        store_directory.path(),
        client_peer_id,
        [first_bootstrap, second_bootstrap],
    )
    .unwrap();
    let candidates = reopened
        .dial_candidates(unix_time(replacement_time))
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].peer_id(), signer_peer_id);
    assert_eq!(candidates[0].source_peer_id(), first_source);
    assert_eq!(issuer.last_issued_sequence().unwrap(), 102);
    assert_eq!(
        client.start_pull(first_source),
        Ok(()),
        "admission must release the authenticated source slot"
    );
    assert_eq!(
        client.start_pull(first_source),
        Err(PeerRecordPullStartError::AlreadyActiveOrRetained(
            first_source
        ))
    );
}
