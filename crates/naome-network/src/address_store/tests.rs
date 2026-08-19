use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use libp2p::core::peer_record::PeerRecord;
use libp2p::core::signed_envelope::SignedEnvelope;
use libp2p::identity::Keypair;

use super::*;

const STANDARD_DOMAIN: &str = "libp2p-peer-record";
const STANDARD_PAYLOAD_TYPE: &[u8] = &[0x03, 0x01];
static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-address-store-{label}-{}-{sequence}",
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

    fn snapshot(&self) -> Vec<u8> {
        fs::read(self.path.join(STORE_FILE_NAME)).unwrap()
    }

    fn write_snapshot(&self, bytes: &[u8]) {
        fs::write(self.path.join(STORE_FILE_NAME), bytes).unwrap();
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

fn deterministic_key(seed: u8) -> Keypair {
    Keypair::ed25519_from_bytes([seed; 32]).unwrap()
}

fn private_address(port: u16) -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

fn global_address(group: u8, host: u8, port: u16) -> Multiaddr {
    format!("/ip4/{group}.1.0.{host}/tcp/{port}")
        .parse()
        .unwrap()
}

fn bootstrap(key: &Keypair, port: u16) -> BootstrapPeer {
    BootstrapPeer::new(key.public().to_peer_id(), private_address(port)).unwrap()
}

fn unix_time(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn push_varint(bytes: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        bytes.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
}

fn push_bytes_field(bytes: &mut Vec<u8>, field: u8, value: &[u8]) {
    bytes.push((field << 3) | 2);
    push_varint(bytes, u64::try_from(value.len()).unwrap());
    bytes.extend_from_slice(value);
}

fn peer_record_payload(subject: PeerId, sequence: u64, addresses: &[Multiaddr]) -> Vec<u8> {
    let mut payload = Vec::new();
    push_bytes_field(&mut payload, 1, &subject.to_bytes());
    payload.push(2 << 3);
    push_varint(&mut payload, sequence);
    for address in addresses {
        let mut address_info = Vec::new();
        push_bytes_field(&mut address_info, 1, &address.to_vec());
        push_bytes_field(&mut payload, 3, &address_info);
    }
    payload
}

fn envelope_bytes(
    signer: &Keypair,
    subject: PeerId,
    sequence: u64,
    addresses: &[Multiaddr],
) -> Vec<u8> {
    SignedEnvelope::new(
        signer,
        STANDARD_DOMAIN.to_owned(),
        STANDARD_PAYLOAD_TYPE.to_vec(),
        peer_record_payload(subject, sequence, addresses),
    )
    .unwrap()
    .into_protobuf_encoding()
}

fn record(signer: &Keypair, sequence: u64, addresses: Vec<Multiaddr>) -> SignedPeerRecord {
    SignedPeerRecord::from_envelope_bytes(envelope_bytes(
        signer,
        signer.public().to_peer_id(),
        sequence,
        &addresses,
    ))
    .unwrap()
}

fn batch(records: impl IntoIterator<Item = SignedPeerRecord>) -> PeerRecordBatch {
    PeerRecordBatch::new(records).unwrap()
}

fn selected_candidate(store: &PeerAddressStore, peer_id: PeerId, now: SystemTime) -> DialCandidate {
    store
        .dial_candidates(now)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.peer_id() == peer_id)
        .expect("the fresh distinct test subject is selected")
}

fn replace_checksum(bytes: &mut Vec<u8>) {
    bytes.truncate(bytes.len() - CHECKSUM_BYTES);
    bytes.extend_from_slice(&checksum(bytes));
}

fn first_envelope_bounds(bytes: &[u8]) -> (usize, usize, usize) {
    let mut position = STORE_HEADER.len();
    let local_length = usize::from(bytes[position]);
    position += 1 + local_length + CHECKSUM_BYTES + SALT_BYTES;
    assert_eq!(
        u16::from_be_bytes(bytes[position..position + 2].try_into().unwrap()),
        1
    );
    position += 2;
    let source_length = usize::from(bytes[position]);
    position += 1 + source_length + 8;
    let length_position = position;
    let envelope_length = usize::from(u16::from_be_bytes(
        bytes[position..position + 2].try_into().unwrap(),
    ));
    (length_position, position + 2, envelope_length)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn bootstrap_configuration_is_exact_bounded_and_canonical() {
    let local = deterministic_key(1);
    let first = deterministic_key(2);
    let second = deterministic_key(3);
    let local_id = local.public().to_peer_id();

    assert!(BootstrapPeer::new(first.public().to_peer_id(), private_address(4001)).is_ok());
    for address in [
        "/ip4/127.0.0.1/tcp/0",
        "/dns4/example.com/tcp/4001",
        "/ip4/127.0.0.1/udp/4001",
        "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWJ5xR8VQXrQ7R7QZ3BGeX8LCFVkiZ89CuajQZVEFzX8nW",
    ] {
        assert!(BootstrapPeer::new(first.public().to_peer_id(), address.parse().unwrap()).is_err());
    }

    assert!(matches!(
        validate_bootstraps(local_id, [bootstrap(&local, 4001)]),
        Err(BootstrapConfigError::LocalPeer(_))
    ));
    assert!(matches!(
        validate_bootstraps(local_id, [bootstrap(&first, 4001), bootstrap(&first, 4002)]),
        Err(BootstrapConfigError::DuplicatePeer(_))
    ));

    let ordered = validate_bootstraps(
        local_id,
        [bootstrap(&second, 4002), bootstrap(&first, 4001)],
    )
    .unwrap();
    assert!(ordered[0].peer_id().to_bytes() < ordered[1].peer_id().to_bytes());

    let too_many = (0..=MAX_BOOTSTRAP_PEERS)
        .map(|index| bootstrap(&deterministic_key(index as u8 + 10), 4100 + index as u16));
    assert!(matches!(
        validate_bootstraps(local_id, too_many),
        Err(BootstrapConfigError::TooManyPeers { .. })
    ));
    let oversized_multihash = libp2p::multihash::Multihash::<64>::wrap(0x12, &[0_u8; 50])
        .expect("the test digest fits the multihash capacity");
    let oversized_peer_id = PeerId::from_multihash(oversized_multihash)
        .expect("libp2p accepts a SHA-256 code without enforcing its digest length");
    assert!(oversized_peer_id.to_bytes().len() > MAX_PEER_ID_BYTES);
    assert!(matches!(
        validate_bootstraps(oversized_peer_id, []),
        Err(BootstrapConfigError::PeerIdTooLong { role: "local", .. })
    ));
    assert!(matches!(
        validate_bootstraps(
            local_id,
            [BootstrapPeer::new(oversized_peer_id, private_address(4999)).unwrap()]
        ),
        Err(BootstrapConfigError::PeerIdTooLong {
            role: "bootstrap",
            ..
        })
    ));
    assert_eq!(MAX_STORE_BYTES, 1_062_824);
}

#[test]
fn peer_id_comparator_matches_raw_encoded_identity_order() {
    let identity_short =
        PeerId::from_multihash(libp2p::multihash::Multihash::<64>::wrap(0, &[0x11; 4]).unwrap())
            .unwrap();
    let identity_long =
        PeerId::from_multihash(libp2p::multihash::Multihash::<64>::wrap(0, &[0x22; 20]).unwrap())
            .unwrap();
    let sha256 = PeerId::from_multihash(
        libp2p::multihash::Multihash::<64>::wrap(0x12, &[0x33; 32]).unwrap(),
    )
    .unwrap();
    let peer_ids = [
        deterministic_key(6).public().to_peer_id(),
        deterministic_key(7).public().to_peer_id(),
        identity_short,
        identity_long,
        sha256,
    ];

    for left in peer_ids {
        for right in peer_ids {
            assert_eq!(
                compare_peer_id_bytes(&left, &right),
                left.to_bytes().cmp(&right.to_bytes())
            );
        }
    }
}

#[test]
fn signed_records_require_standard_signatures_and_global_exact_endpoints() {
    let signer = deterministic_key(20);
    let valid_address = global_address(11, 1, 4001);
    let valid = record(&signer, 7, vec![valid_address.clone()]);
    assert_eq!(valid.peer_id(), signer.public().to_peer_id());
    assert_eq!(valid.sequence(), 7);
    assert_eq!(valid.addresses(), [valid_address]);

    let legacy = PeerRecord::new(&signer, vec![global_address(12, 1, 4001)])
        .unwrap()
        .into_signed_envelope()
        .into_protobuf_encoding();
    assert!(matches!(
        SignedPeerRecord::from_envelope_bytes(legacy),
        Err(SignedPeerRecordError::PeerRecord(_))
    ));

    let other = deterministic_key(21);
    let mismatched = envelope_bytes(
        &signer,
        other.public().to_peer_id(),
        8,
        &[global_address(13, 1, 4001)],
    );
    assert!(matches!(
        SignedPeerRecord::from_envelope_bytes(mismatched),
        Err(SignedPeerRecordError::PeerRecord(_))
    ));

    let mut mutated = valid.envelope_bytes().to_vec();
    *mutated.last_mut().unwrap() ^= 1;
    assert!(SignedPeerRecord::from_envelope_bytes(mutated).is_err());

    for address in [
        private_address(4001),
        "/ip4/11.1.1.1/tcp/0".parse().unwrap(),
        "/ip4/11.1.1.1/udp/4001".parse().unwrap(),
        "/ip4/192.0.2.1/tcp/4001".parse().unwrap(),
        "/ip6/2001:db8::1/tcp/4001".parse().unwrap(),
    ] {
        assert!(matches!(
            SignedPeerRecord::from_envelope_bytes(envelope_bytes(
                &signer,
                signer.public().to_peer_id(),
                9,
                &[address]
            )),
            Err(SignedPeerRecordError::UnsupportedAddress { .. })
        ));
    }

    let duplicate = global_address(14, 1, 4001);
    assert!(matches!(
        SignedPeerRecord::from_envelope_bytes(envelope_bytes(
            &signer,
            signer.public().to_peer_id(),
            10,
            &[duplicate.clone(), duplicate]
        )),
        Err(SignedPeerRecordError::DuplicateAddress { .. })
    ));
    let too_many = (0..=MAX_ADDRESSES_PER_PEER_RECORD)
        .map(|index| global_address(15 + index as u8, 1, 4001))
        .collect::<Vec<_>>();
    assert!(matches!(
        SignedPeerRecord::from_envelope_bytes(envelope_bytes(
            &signer,
            signer.public().to_peer_id(),
            11,
            &too_many
        )),
        Err(SignedPeerRecordError::AddressCount { .. })
    ));
}

#[test]
fn global_address_predicates_lock_the_protocol_boundaries() {
    for address in ["8.8.8.8", "11.0.0.1", "192.88.99.1", "223.255.255.254"] {
        assert!(is_global_ipv4(address.parse().unwrap()), "{address}");
    }
    for address in [
        "0.1.1.1",
        "10.1.1.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
    ] {
        assert!(!is_global_ipv4(address.parse().unwrap()), "{address}");
    }
    for address in ["2001:4860:4860::8888", "2fff::1"] {
        assert!(is_global_ipv6(address.parse().unwrap()), "{address}");
    }
    for address in [
        "2001:2::1",
        "2001:10::1",
        "2001:20::1",
        "2001:db8::1",
        "fc00::1",
        "ff00::1",
    ] {
        assert!(!is_global_ipv6(address.parse().unwrap()), "{address}");
    }
}

#[test]
fn create_open_lock_and_configuration_binding_are_strict() {
    let directory = TestDirectory::new("open");
    let local = deterministic_key(40);
    let first = deterministic_key(41);
    let second = deterministic_key(42);
    let bootstraps = vec![bootstrap(&second, 4002), bootstrap(&first, 4001)];
    let store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        bootstraps.clone(),
    )
    .unwrap();
    assert_eq!(store.len().unwrap(), 0);
    assert!(store.is_empty().unwrap());
    assert!(
        store.bootstrap_peers().unwrap()[0].peer_id().to_bytes()
            < store.bootstrap_peers().unwrap()[1].peer_id().to_bytes()
    );
    assert!(matches!(
        PeerAddressStore::open(
            directory.path(),
            local.public().to_peer_id(),
            bootstraps.clone()
        ),
        Err(PeerAddressStoreError::Locked)
    ));
    drop(store);
    fs::write(
        directory.path().join(TEMP_FILE_NAME),
        b"stale incomplete temporary image",
    )
    .unwrap();

    let reopened = PeerAddressStore::open(
        directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&first, 4001), bootstrap(&second, 4002)],
    )
    .unwrap();
    assert!(reopened.is_empty().unwrap());
    drop(reopened);

    assert!(matches!(
        PeerAddressStore::create(
            directory.path(),
            local.public().to_peer_id(),
            bootstraps.clone()
        ),
        Err(PeerAddressStoreError::AlreadyExists(_))
    ));
    assert!(matches!(
        PeerAddressStore::open(
            directory.path(),
            deterministic_key(43).public().to_peer_id(),
            bootstraps.clone()
        ),
        Err(PeerAddressStoreError::LocalPeerMismatch)
    ));
    assert!(matches!(
        PeerAddressStore::open(
            directory.path(),
            local.public().to_peer_id(),
            [bootstrap(&first, 4001)]
        ),
        Err(PeerAddressStoreError::BootstrapConfigurationMismatch)
    ));
}

#[test]
fn sequence_admission_is_atomic_and_retains_first_source() {
    let directory = TestDirectory::new("sequence");
    let local = deterministic_key(50);
    let first = deterministic_key(51);
    let second = deterministic_key(52);
    let subject = deterministic_key(53);
    let first_source = first.public().to_peer_id();
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&first, 4001), bootstrap(&second, 4002)],
    )
    .unwrap();

    let initial = record(&subject, 10, vec![global_address(31, 1, 4001)]);
    assert_eq!(
        store
            .admit_record(first_source, initial.clone(), unix_time(100))
            .unwrap(),
        PeerRecordAdmission::Inserted
    );
    let initial_snapshot = directory.snapshot();
    assert_eq!(
        store
            .admit_record(first_source, initial, unix_time(200))
            .unwrap(),
        PeerRecordAdmission::IgnoredStale
    );
    assert_eq!(directory.snapshot(), initial_snapshot);

    let older = record(&subject, 9, vec![global_address(32, 1, 4001)]);
    assert_eq!(
        store
            .admit_record(second.public().to_peer_id(), older, unix_time(300))
            .unwrap(),
        PeerRecordAdmission::IgnoredStale
    );
    assert_eq!(directory.snapshot(), initial_snapshot);

    let conflict = record(&subject, 10, vec![global_address(33, 1, 4001)]);
    assert!(matches!(
        store.admit_record(second.public().to_peer_id(), conflict, unix_time(300)),
        Err(PeerAddressStoreError::SequenceConflict { sequence: 10, .. })
    ));
    assert_eq!(directory.snapshot(), initial_snapshot);

    let newer = record(&subject, 11, vec![global_address(34, 1, 4001)]);
    assert_eq!(
        store
            .admit_record(second.public().to_peer_id(), newer, unix_time(300))
            .unwrap(),
        PeerRecordAdmission::Replaced
    );
    assert_eq!(store.records[0].source_peer_id, first_source);
    assert_eq!(store.records[0].received_at, 300);
    assert_ne!(directory.snapshot(), initial_snapshot);

    let local_record = record(&local, 1, vec![global_address(35, 1, 4001)]);
    assert!(matches!(
        store.admit_record(first_source, local_record, unix_time(300)),
        Err(PeerAddressStoreError::LocalRecord(_))
    ));
    let bootstrap_self_record = record(&first, 1, vec![global_address(36, 1, 4001)]);
    assert_eq!(
        store
            .admit_record(first_source, bootstrap_self_record, unix_time(300))
            .unwrap(),
        PeerRecordAdmission::Inserted
    );
}

#[test]
fn batch_admission_matches_single_admissions_and_reopens_identically() {
    let batch_directory = TestDirectory::new("batch-equivalence");
    let single_directory = TestDirectory::new("single-equivalence");
    let local = deterministic_key(5);
    let first_source = deterministic_key(6);
    let second_source = deterministic_key(7);
    let first_subject = deterministic_key(8);
    let stale_subject = deterministic_key(9);
    let new_subject = deterministic_key(10);
    let bootstraps = vec![
        bootstrap(&first_source, 4001),
        bootstrap(&second_source, 4002),
    ];
    let mut batch_store = PeerAddressStore::create(
        batch_directory.path(),
        local.public().to_peer_id(),
        bootstraps.clone(),
    )
    .unwrap();
    let mut single_store = PeerAddressStore::create(
        single_directory.path(),
        local.public().to_peer_id(),
        bootstraps.clone(),
    )
    .unwrap();
    batch_store.ordering_salt = [0x5a; SALT_BYTES];
    single_store.ordering_salt = [0x5a; SALT_BYTES];

    let initial_first = record(&first_subject, 5, vec![global_address(21, 1, 4001)]);
    let initial_stale = record(&stale_subject, 5, vec![global_address(22, 1, 4001)]);
    for store in [&mut batch_store, &mut single_store] {
        let _ = store
            .admit_record(
                first_source.public().to_peer_id(),
                initial_first.clone(),
                unix_time(100),
            )
            .unwrap();
        let _ = store
            .admit_record(
                first_source.public().to_peer_id(),
                initial_stale.clone(),
                unix_time(100),
            )
            .unwrap();
    }

    let replacement = record(&first_subject, 6, vec![global_address(23, 1, 4002)]);
    let insertion = record(&new_subject, 1, vec![global_address(24, 1, 4001)]);
    let source_id = second_source.public().to_peer_id();
    let commit_attempts = batch_store.commit_attempts;
    let admission = batch_store
        .admit_record_batch(
            source_id,
            batch([
                insertion.clone(),
                initial_stale.clone(),
                replacement.clone(),
            ]),
            unix_time(200),
        )
        .unwrap();
    assert_eq!(admission.inserted(), 1);
    assert_eq!(admission.replaced(), 1);
    assert_eq!(admission.ignored_stale(), 1);
    assert_eq!(admission.total(), 3);
    assert_eq!(batch_store.commit_attempts, commit_attempts + 1);

    assert_eq!(
        single_store
            .admit_record(source_id, insertion, unix_time(200))
            .unwrap(),
        PeerRecordAdmission::Inserted
    );
    assert_eq!(
        single_store
            .admit_record(source_id, initial_stale, unix_time(200))
            .unwrap(),
        PeerRecordAdmission::IgnoredStale
    );
    assert_eq!(
        single_store
            .admit_record(source_id, replacement, unix_time(200))
            .unwrap(),
        PeerRecordAdmission::Replaced
    );
    assert_eq!(batch_directory.snapshot(), single_directory.snapshot());
    let stored_first = batch_store
        .records
        .iter()
        .find(|stored| stored.record.peer_id == first_subject.public().to_peer_id())
        .unwrap();
    assert_eq!(
        stored_first.source_peer_id,
        first_source.public().to_peer_id()
    );
    let stored_stale = batch_store
        .records
        .iter()
        .find(|stored| stored.record.peer_id == stale_subject.public().to_peer_id())
        .unwrap();
    assert_eq!(stored_stale.received_at, 100);
    drop(batch_store);

    let reopened = PeerAddressStore::open(
        batch_directory.path(),
        local.public().to_peer_id(),
        bootstraps,
    )
    .unwrap();
    assert_eq!(reopened.len().unwrap(), 3);
    assert_eq!(batch_directory.snapshot(), single_directory.snapshot());
}

#[test]
fn empty_and_stale_batches_perform_no_commit() {
    let directory = TestDirectory::new("batch-stale");
    let local = deterministic_key(11);
    let source = deterministic_key(12);
    let first = deterministic_key(13);
    let second = deterministic_key(14);
    let source_id = source.public().to_peer_id();
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&source, 4001)],
    )
    .unwrap();
    let first_record = record(&first, 5, vec![global_address(25, 1, 4001)]);
    let second_record = record(&second, 5, vec![global_address(26, 1, 4001)]);
    let _ = store
        .admit_record(source_id, first_record.clone(), unix_time(100))
        .unwrap();
    let _ = store
        .admit_record(source_id, second_record, unix_time(100))
        .unwrap();
    let before = directory.snapshot();
    let commit_attempts = store.commit_attempts;
    fs::create_dir(directory.path().join(TEMP_FILE_NAME)).unwrap();

    let empty = store
        .admit_record_batch(source_id, batch([]), unix_time(200))
        .unwrap();
    assert_eq!(empty.total(), 0);
    let stale = store
        .admit_record_batch(
            source_id,
            batch([
                first_record,
                record(&second, 4, vec![global_address(27, 1, 4001)]),
            ]),
            unix_time(200),
        )
        .unwrap();
    assert_eq!(stale.ignored_stale(), 2);
    assert_eq!(stale.inserted(), 0);
    assert_eq!(stale.replaced(), 0);
    assert_eq!(directory.snapshot(), before);
    assert_eq!(store.len().unwrap(), 2);
    assert_eq!(store.commit_attempts, commit_attempts);
    fs::remove_dir(directory.path().join(TEMP_FILE_NAME)).unwrap();
}

#[test]
fn batch_preflight_errors_reject_every_record() {
    let directory = TestDirectory::new("batch-preflight");
    let local = deterministic_key(15);
    let source = deterministic_key(16);
    let unknown_source = deterministic_key(17);
    let first_subject = deterministic_key(18);
    let second_subject = deterministic_key(19);
    let first_subject_id = first_subject.public().to_peer_id();
    let second_subject_id = second_subject.public().to_peer_id();
    let (valid_subject, existing_subject) =
        if compare_peer_id_bytes(&first_subject_id, &second_subject_id).is_lt() {
            (first_subject, second_subject)
        } else {
            (second_subject, first_subject)
        };
    let source_id = source.public().to_peer_id();
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&source, 4001)],
    )
    .unwrap();
    let initial = record(&existing_subject, 5, vec![global_address(28, 1, 4001)]);
    let _ = store
        .admit_record(source_id, initial, unix_time(100))
        .unwrap();
    let before = directory.snapshot();

    let conflict = record(&existing_subject, 5, vec![global_address(29, 1, 4001)]);
    let valid_subject_id = valid_subject.public().to_peer_id();
    let existing_subject_id = existing_subject.public().to_peer_id();
    assert!(compare_peer_id_bytes(&valid_subject_id, &existing_subject_id).is_lt());
    assert!(matches!(
        store.admit_record_batch(
            source_id,
            batch([
                record(&valid_subject, 1, vec![global_address(30, 1, 4001)]),
                conflict,
            ]),
            unix_time(200),
        ),
        Err(PeerAddressStoreError::SequenceConflict { .. })
    ));
    assert_eq!(directory.snapshot(), before);
    assert_eq!(store.len().unwrap(), 1);

    assert!(matches!(
        store.admit_record_batch(
            source_id,
            batch([
                record(&local, 1, vec![global_address(31, 1, 4001)]),
                record(&existing_subject, 5, vec![global_address(29, 1, 4001)]),
            ]),
            unix_time(200),
        ),
        Err(PeerAddressStoreError::LocalRecord(_))
    ));
    assert_eq!(directory.snapshot(), before);
    assert!(matches!(
        store.admit_record_batch(
            unknown_source.public().to_peer_id(),
            batch([record(&valid_subject, 1, vec![global_address(30, 1, 4001)])]),
            UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap(),
        ),
        Err(PeerAddressStoreError::UnknownSource(_))
    ));
    assert_eq!(directory.snapshot(), before);
    assert!(matches!(
        store.admit_record_batch(
            source_id,
            batch([
                record(&local, 1, vec![global_address(31, 1, 4001)]),
                record(&existing_subject, 5, vec![global_address(29, 1, 4001)]),
            ]),
            UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap(),
        ),
        Err(PeerAddressStoreError::TimeBeforeUnixEpoch)
    ));
    assert_eq!(directory.snapshot(), before);
}

#[test]
fn batch_capacity_uses_the_complete_projected_state() {
    let release_directory = TestDirectory::new("batch-group-release");
    let local = deterministic_key(32);
    let source = deterministic_key(33);
    let source_id = source.public().to_peer_id();
    let mut release_store = PeerAddressStore::create(
        release_directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&source, 4001)],
    )
    .unwrap();
    let subjects = (34..34 + MAX_RECORDS_PER_NETWORK_GROUP as u8)
        .map(deterministic_key)
        .collect::<Vec<_>>();
    let initial = subjects
        .iter()
        .enumerate()
        .map(|(index, subject)| record(subject, 1, vec![global_address(80, index as u8 + 1, 4001)]))
        .collect::<Vec<_>>();
    let _ = release_store
        .admit_record_batch(source_id, batch(initial), unix_time(100))
        .unwrap();
    let replacement_subject = subjects
        .iter()
        .max_by(|left, right| {
            compare_peer_id_bytes(&left.public().to_peer_id(), &right.public().to_peer_id())
        })
        .unwrap();
    let new_subject = (100..=u8::MAX)
        .map(deterministic_key)
        .find(|candidate| {
            compare_peer_id_bytes(
                &candidate.public().to_peer_id(),
                &replacement_subject.public().to_peer_id(),
            )
            .is_lt()
        })
        .expect("a deterministic insertion subject sorts before the replacement");
    assert!(
        compare_peer_id_bytes(
            &new_subject.public().to_peer_id(),
            &replacement_subject.public().to_peer_id()
        )
        .is_lt()
    );
    let replacement = record(replacement_subject, 2, vec![global_address(81, 1, 4001)]);
    let insertion = record(&new_subject, 1, vec![global_address(80, 99, 4001)]);
    let admission = release_store
        .admit_record_batch(source_id, batch([insertion, replacement]), unix_time(200))
        .unwrap();
    assert_eq!(admission.inserted(), 1);
    assert_eq!(admission.replaced(), 1);
    assert_eq!(
        release_store.len().unwrap(),
        MAX_RECORDS_PER_NETWORK_GROUP + 1
    );

    let source_directory = TestDirectory::new("batch-source-cap");
    let mut source_store = PeerAddressStore::create(
        source_directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&source, 4001)],
    )
    .unwrap();
    let initial = (0..MAX_RECORDS_PER_BOOTSTRAP - 1)
        .map(|index| {
            let subject = deterministic_key(60 + index as u8);
            record(
                &subject,
                1,
                vec![global_address(150 + index as u8, 1, 4001)],
            )
        })
        .collect::<Vec<_>>();
    let _ = source_store
        .admit_record_batch(source_id, batch(initial), unix_time(100))
        .unwrap();
    let before = source_directory.snapshot();
    assert!(matches!(
        source_store.admit_record_batch(
            source_id,
            batch([
                record(
                    &deterministic_key(100),
                    1,
                    vec![global_address(200, 1, 4001)]
                ),
                record(
                    &deterministic_key(101),
                    1,
                    vec![global_address(201, 1, 4001)]
                ),
            ]),
            unix_time(200),
        ),
        Err(PeerAddressStoreError::SourceCapacity { .. })
    ));
    assert_eq!(source_store.len().unwrap(), MAX_RECORDS_PER_BOOTSTRAP - 1);
    assert_eq!(source_directory.snapshot(), before);

    let group_directory = TestDirectory::new("batch-group-cap");
    let mut group_store = PeerAddressStore::create(
        group_directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&source, 4001)],
    )
    .unwrap();
    let initial = (0..MAX_RECORDS_PER_NETWORK_GROUP)
        .map(|index| {
            record(
                &deterministic_key(110 + index as u8),
                1,
                vec![global_address(210, index as u8 + 1, 4001)],
            )
        })
        .collect::<Vec<_>>();
    let _ = group_store
        .admit_record_batch(source_id, batch(initial), unix_time(100))
        .unwrap();
    let before = group_directory.snapshot();
    assert!(matches!(
        group_store.admit_record_batch(
            source_id,
            batch([
                record(
                    &deterministic_key(118),
                    1,
                    vec![global_address(211, 1, 4001)]
                ),
                record(
                    &deterministic_key(119),
                    1,
                    vec![global_address(210, 99, 4001)]
                ),
            ]),
            unix_time(200),
        ),
        Err(PeerAddressStoreError::NetworkGroupCapacity { .. })
    ));
    assert_eq!(group_store.len().unwrap(), MAX_RECORDS_PER_NETWORK_GROUP);
    assert_eq!(group_directory.snapshot(), before);
}

#[test]
fn full_store_rejects_a_whole_batch_without_mutation() {
    let directory = TestDirectory::new("batch-total-cap");
    let local = deterministic_key(129);
    let sources = (130..130 + MAX_BOOTSTRAP_PEERS as u8)
        .map(deterministic_key)
        .collect::<Vec<_>>();
    let bootstraps = sources
        .iter()
        .enumerate()
        .map(|(index, source)| bootstrap(source, 4001 + index as u16))
        .collect::<Vec<_>>();
    let mut store =
        PeerAddressStore::create(directory.path(), local.public().to_peer_id(), bootstraps)
            .unwrap();
    for (source_index, source) in sources.iter().enumerate() {
        let records = (0..MAX_RECORDS_PER_BOOTSTRAP)
            .map(|record_index| {
                let subject = Keypair::generate_ed25519();
                let group = 40 + source_index as u8 * 4 + record_index as u8 / 8;
                record(
                    &subject,
                    1,
                    vec![global_address(group, record_index as u8 % 8 + 1, 4001)],
                )
            })
            .collect::<Vec<_>>();
        let admission = store
            .admit_record_batch(source.public().to_peer_id(), batch(records), unix_time(100))
            .unwrap();
        assert_eq!(admission.inserted(), MAX_RECORDS_PER_BOOTSTRAP);
    }
    assert_eq!(store.len().unwrap(), MAX_PEER_ADDRESS_RECORDS);
    let before = directory.snapshot();
    let extra = Keypair::generate_ed25519();
    assert!(matches!(
        store.admit_record_batch(
            sources[0].public().to_peer_id(),
            batch([record(&extra, 1, vec![global_address(72, 1, 4001)])]),
            unix_time(200),
        ),
        Err(PeerAddressStoreError::RecordCapacity { .. })
    ));
    assert_eq!(store.len().unwrap(), MAX_PEER_ADDRESS_RECORDS);
    assert_eq!(directory.snapshot(), before);
}

#[test]
fn failed_batch_commit_poisoning_never_installs_a_prefix() {
    let directory = TestDirectory::new("batch-poison");
    let local = deterministic_key(102);
    let source = deterministic_key(103);
    let source_id = source.public().to_peer_id();
    let bootstraps = vec![bootstrap(&source, 4001)];
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        bootstraps.clone(),
    )
    .unwrap();
    let before = directory.snapshot();
    let commit_attempts = store.commit_attempts;
    fs::create_dir(directory.path().join(TEMP_FILE_NAME)).unwrap();
    assert!(matches!(
        store.admit_record_batch(
            source_id,
            batch([
                record(
                    &deterministic_key(104),
                    1,
                    vec![global_address(152, 1, 4001)]
                ),
                record(
                    &deterministic_key(105),
                    1,
                    vec![global_address(153, 1, 4001)]
                ),
            ]),
            unix_time(200),
        ),
        Err(PeerAddressStoreError::Commit { .. })
    ));
    assert_eq!(directory.snapshot(), before);
    assert!(matches!(store.len(), Err(PeerAddressStoreError::Poisoned)));
    assert_eq!(store.commit_attempts, commit_attempts + 1);
    assert!(matches!(
        store.admit_record_batch(
            deterministic_key(106).public().to_peer_id(),
            batch([record(&local, 1, vec![global_address(154, 1, 4001)])]),
            UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap(),
        ),
        Err(PeerAddressStoreError::Poisoned)
    ));
    drop(store);
    fs::remove_dir(directory.path().join(TEMP_FILE_NAME)).unwrap();
    let reopened =
        PeerAddressStore::open(directory.path(), local.public().to_peer_id(), bootstraps).unwrap();
    assert!(reopened.is_empty().unwrap());
}

#[test]
fn expiry_retains_a_sequence_watermark_across_reopen() {
    let directory = TestDirectory::new("expiry");
    let local = deterministic_key(60);
    let source = deterministic_key(61);
    let subject = deterministic_key(62);
    let source_id = source.public().to_peer_id();
    let bootstraps = vec![bootstrap(&source, 4001)];
    let received_at = 1_000;
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        bootstraps.clone(),
    )
    .unwrap();
    let initial = record(&subject, 5, vec![global_address(41, 1, 4001)]);
    let _ = store
        .admit_record(source_id, initial.clone(), unix_time(received_at))
        .unwrap();
    assert_eq!(
        store.dial_candidates(unix_time(received_at)).unwrap().len(),
        1
    );
    assert_eq!(
        store
            .dial_candidates(unix_time(received_at + PEER_RECORD_TTL.as_secs() - 1))
            .unwrap()
            .len(),
        1
    );
    let expiry = received_at + PEER_RECORD_TTL.as_secs();
    assert!(store.dial_candidates(unix_time(expiry)).unwrap().is_empty());
    let expired_snapshot = directory.snapshot();
    assert_eq!(
        store
            .admit_record(source_id, initial, unix_time(expiry + 10))
            .unwrap(),
        PeerRecordAdmission::IgnoredStale
    );
    assert_eq!(directory.snapshot(), expired_snapshot);
    drop(store);

    let mut reopened =
        PeerAddressStore::open(directory.path(), local.public().to_peer_id(), bootstraps).unwrap();
    assert_eq!(reopened.len().unwrap(), 1);
    assert!(
        reopened
            .dial_candidates(unix_time(expiry + 10))
            .unwrap()
            .is_empty()
    );
    let newer = record(&subject, 6, vec![global_address(42, 1, 4001)]);
    assert_eq!(
        reopened
            .admit_record(source_id, newer, unix_time(expiry + 10))
            .unwrap(),
        PeerRecordAdmission::Replaced
    );
    assert_eq!(
        reopened
            .dial_candidates(unix_time(expiry + 10))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn learned_batch_preserves_root_lineage_and_existing_first_introducer_on_reopen() {
    let directory = TestDirectory::new("learned-lineage");
    let local = deterministic_key(20);
    let first_root = deterministic_key(21);
    let second_root = deterministic_key(22);
    let learned_source = deterministic_key(23);
    let existing_subject = deterministic_key(24);
    let inserted_subject = deterministic_key(25);
    let first_root_id = first_root.public().to_peer_id();
    let second_root_id = second_root.public().to_peer_id();
    let learned_source_id = learned_source.public().to_peer_id();
    let bootstraps = vec![bootstrap(&first_root, 4001), bootstrap(&second_root, 4002)];
    let learned_address = global_address(51, 1, 4101);
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        bootstraps.clone(),
    )
    .unwrap();
    let _ = store
        .admit_record(
            first_root_id,
            record(&learned_source, 1, vec![learned_address.clone()]),
            unix_time(100),
        )
        .unwrap();
    let _ = store
        .admit_record(
            second_root_id,
            record(&existing_subject, 1, vec![global_address(52, 1, 4201)]),
            unix_time(100),
        )
        .unwrap();
    let candidate = selected_candidate(&store, learned_source_id, unix_time(100));

    let admission = store
        .admit_learned_record_batch(
            &candidate,
            batch([
                record(&existing_subject, 2, vec![global_address(53, 1, 4202)]),
                record(&inserted_subject, 1, vec![global_address(54, 1, 4203)]),
            ]),
            unix_time(200),
        )
        .unwrap();
    assert_eq!(admission.inserted(), 1);
    assert_eq!(admission.replaced(), 1);
    let existing = store
        .records
        .iter()
        .find(|stored| stored.record.peer_id == existing_subject.public().to_peer_id())
        .unwrap();
    assert_eq!(existing.source_peer_id, second_root_id);
    let inserted = store
        .records
        .iter()
        .find(|stored| stored.record.peer_id == inserted_subject.public().to_peer_id())
        .unwrap();
    assert_eq!(inserted.source_peer_id, first_root_id);
    drop(store);

    let reopened =
        PeerAddressStore::open(directory.path(), local.public().to_peer_id(), bootstraps).unwrap();
    assert_eq!(
        selected_candidate(
            &reopened,
            inserted_subject.public().to_peer_id(),
            unix_time(200)
        )
        .source_peer_id(),
        first_root_id
    );
}

#[test]
fn learned_batch_revalidates_exact_retained_candidate_before_batch_errors() {
    let directory = TestDirectory::new("learned-revalidation");
    let local = deterministic_key(26);
    let root = deterministic_key(27);
    let other_root = deterministic_key(28);
    let learned_source = deterministic_key(29);
    let root_id = root.public().to_peer_id();
    let learned_source_id = learned_source.public().to_peer_id();
    let learned_address = global_address(55, 1, 4301);
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&root, 4001), bootstrap(&other_root, 4002)],
    )
    .unwrap();
    let _ = store
        .admit_record(
            root_id,
            record(&learned_source, 1, vec![learned_address.clone()]),
            unix_time(1_000),
        )
        .unwrap();
    let candidate = selected_candidate(&store, learned_source_id, unix_time(1_000));
    let before_errors = directory.snapshot();
    let unknown = DialCandidate::for_test(
        deterministic_key(30).public().to_peer_id(),
        learned_address.clone(),
        root_id,
    );
    let invalid_time = UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap();
    let local_record = record(&local, 1, vec![global_address(56, 1, 4302)]);
    let local_batch = || batch([local_record.clone()]);
    assert!(matches!(
        store.admit_learned_record_batch(&unknown, local_batch(), invalid_time),
        Err(PeerAddressStoreError::UnknownDialCandidate(_))
    ));

    let wrong_address =
        DialCandidate::for_test(learned_source_id, global_address(57, 1, 4303), root_id);
    assert!(matches!(
        store.admit_learned_record_batch(&wrong_address, local_batch(), invalid_time),
        Err(PeerAddressStoreError::StaleDialCandidate(_))
    ));
    let wrong_root = DialCandidate::for_test(
        learned_source_id,
        learned_address.clone(),
        other_root.public().to_peer_id(),
    );
    assert!(matches!(
        store.admit_learned_record_batch(&wrong_root, local_batch(), invalid_time),
        Err(PeerAddressStoreError::StaleDialCandidate(_))
    ));
    assert!(matches!(
        store.admit_learned_record_batch(&candidate, local_batch(), invalid_time),
        Err(PeerAddressStoreError::TimeBeforeUnixEpoch)
    ));
    assert!(matches!(
        store.admit_learned_record_batch(&candidate, local_batch(), unix_time(999)),
        Err(PeerAddressStoreError::StaleDialCandidate(_))
    ));
    assert!(matches!(
        store.admit_learned_record_batch(
            &candidate,
            local_batch(),
            unix_time(1_000 + PEER_RECORD_TTL.as_secs())
        ),
        Err(PeerAddressStoreError::StaleDialCandidate(_))
    ));
    assert!(matches!(
        store.admit_learned_record_batch(&candidate, local_batch(), unix_time(1_001)),
        Err(PeerAddressStoreError::LocalRecord(_))
    ));
    assert_eq!(directory.snapshot(), before_errors);

    let _ = store
        .admit_record(
            root_id,
            record(
                &learned_source,
                2,
                vec![learned_address.clone(), global_address(58, 1, 4304)],
            ),
            unix_time(1_100),
        )
        .unwrap();
    let after_source_refresh = directory.snapshot();
    let empty = store
        .admit_learned_record_batch(&candidate, batch([]), unix_time(1_101))
        .unwrap();
    assert_eq!(empty.total(), 0);
    assert_eq!(directory.snapshot(), after_source_refresh);

    let _ = store
        .admit_record(
            root_id,
            record(&learned_source, 3, vec![global_address(58, 2, 4305)]),
            unix_time(1_200),
        )
        .unwrap();
    assert!(matches!(
        store.admit_learned_record_batch(&candidate, batch([]), unix_time(1_201)),
        Err(PeerAddressStoreError::StaleDialCandidate(_))
    ));
}

#[test]
fn learned_batch_root_capacity_fails_without_installing_a_prefix() {
    let source_directory = TestDirectory::new("learned-root-capacity");
    let local = deterministic_key(31);
    let root = deterministic_key(32);
    let learned_source = deterministic_key(33);
    let root_id = root.public().to_peer_id();
    let learned_source_id = learned_source.public().to_peer_id();
    let mut source_store = PeerAddressStore::create(
        source_directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&root, 4001)],
    )
    .unwrap();
    let _ = source_store
        .admit_record(
            root_id,
            record(&learned_source, 1, vec![global_address(59, 1, 4401)]),
            unix_time(2_000),
        )
        .unwrap();
    let candidate = selected_candidate(&source_store, learned_source_id, unix_time(2_000));
    for index in 0..MAX_RECORDS_PER_BOOTSTRAP - 2 {
        let subject = deterministic_key(60 + index as u8);
        let _ = source_store
            .admit_record(
                root_id,
                record(&subject, 1, vec![global_address(80 + index as u8, 1, 4402)]),
                unix_time(2_000),
            )
            .unwrap();
    }
    assert_eq!(source_store.len().unwrap(), MAX_RECORDS_PER_BOOTSTRAP - 1);
    let before = source_directory.snapshot();
    assert!(matches!(
        source_store.admit_learned_record_batch(
            &candidate,
            batch([
                record(&deterministic_key(100), 1, vec![global_address(180, 1, 4501)]),
                record(&deterministic_key(101), 1, vec![global_address(181, 1, 4502)]),
            ]),
            unix_time(2_001),
        ),
        Err(PeerAddressStoreError::SourceCapacity { source, .. })
            if *source == root_id
    ));
    assert_eq!(source_directory.snapshot(), before);
    assert_eq!(source_store.len().unwrap(), MAX_RECORDS_PER_BOOTSTRAP - 1);
}

#[test]
fn source_and_network_group_capacity_reject_without_mutation() {
    let source_directory = TestDirectory::new("source-cap");
    let local = deterministic_key(70);
    let source = deterministic_key(71);
    let source_id = source.public().to_peer_id();
    let mut source_store = PeerAddressStore::create(
        source_directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&source, 4001)],
    )
    .unwrap();
    for index in 0..MAX_RECORDS_PER_BOOTSTRAP {
        let subject = deterministic_key(80 + index as u8);
        let _ = source_store
            .admit_record(
                source_id,
                record(&subject, 1, vec![global_address(40 + index as u8, 1, 4001)]),
                unix_time(1_000),
            )
            .unwrap();
    }
    let before = source_directory.snapshot();
    let extra = deterministic_key(120);
    assert!(matches!(
        source_store.admit_record(
            source_id,
            record(&extra, 1, vec![global_address(72, 1, 4001)]),
            unix_time(1_000)
        ),
        Err(PeerAddressStoreError::SourceCapacity { .. })
    ));
    assert_eq!(source_store.len().unwrap(), MAX_RECORDS_PER_BOOTSTRAP);
    assert_eq!(source_directory.snapshot(), before);
    let existing_subject = deterministic_key(80);
    assert_eq!(
        source_store
            .admit_record(
                source_id,
                record(&existing_subject, 2, vec![global_address(40, 2, 4002)]),
                unix_time(1_001)
            )
            .unwrap(),
        PeerRecordAdmission::Replaced
    );

    let group_directory = TestDirectory::new("group-cap");
    let group_source = deterministic_key(121);
    let group_source_id = group_source.public().to_peer_id();
    let mut group_store = PeerAddressStore::create(
        group_directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&group_source, 4002)],
    )
    .unwrap();
    for index in 0..MAX_RECORDS_PER_NETWORK_GROUP {
        let subject = deterministic_key(130 + index as u8);
        let _ = group_store
            .admit_record(
                group_source_id,
                record(&subject, 1, vec![global_address(73, index as u8 + 1, 4001)]),
                unix_time(1_000),
            )
            .unwrap();
    }
    let before = group_directory.snapshot();
    let extra = deterministic_key(150);
    assert!(matches!(
        group_store.admit_record(
            group_source_id,
            record(&extra, 1, vec![global_address(73, 99, 4001)]),
            unix_time(1_000)
        ),
        Err(PeerAddressStoreError::NetworkGroupCapacity { .. })
    ));
    assert_eq!(group_directory.snapshot(), before);
    let existing_subject = deterministic_key(130);
    assert_eq!(
        group_store
            .admit_record(
                group_source_id,
                record(&existing_subject, 2, vec![global_address(73, 100, 4002)]),
                unix_time(1_001)
            )
            .unwrap(),
        PeerRecordAdmission::Replaced
    );
}

#[test]
fn selection_is_salted_stable_and_diversified() {
    let directory = TestDirectory::new("selection");
    let local = deterministic_key(160);
    let sources = (161..=164).map(deterministic_key).collect::<Vec<_>>();
    let bootstraps = sources
        .iter()
        .enumerate()
        .map(|(index, source)| bootstrap(source, 4100 + index as u16))
        .collect::<Vec<_>>();
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        bootstraps.clone(),
    )
    .unwrap();
    for index in 0..12 {
        let subject = deterministic_key(180 + index);
        let source = &sources[usize::from(index) % sources.len()];
        let _ = store
            .admit_record(
                source.public().to_peer_id(),
                record(&subject, 1, vec![global_address(80 + index, 1, 4001)]),
                unix_time(10_000),
            )
            .unwrap();
    }

    let now = unix_time(10_500);
    let selected = store.dial_candidates(now).unwrap();
    assert_eq!(selected.len(), MAX_DIAL_CANDIDATES);
    let mut peers = BTreeSet::new();
    let mut groups = BTreeSet::new();
    let mut source_counts = BTreeMap::new();
    for candidate in &selected {
        assert!(peers.insert(candidate.peer_id()));
        assert!(groups.insert(network_group(candidate.address()).unwrap()));
        *source_counts.entry(candidate.source_peer_id()).or_insert(0) += 1;
    }
    assert!(
        source_counts
            .values()
            .all(|count| *count <= MAX_DIAL_CANDIDATES_PER_BOOTSTRAP)
    );
    assert_eq!(store.dial_candidates(now).unwrap(), selected);
    drop(store);

    let reopened =
        PeerAddressStore::open(directory.path(), local.public().to_peer_id(), bootstraps).unwrap();
    assert_eq!(reopened.dial_candidates(now).unwrap(), selected);
}

#[test]
fn each_selection_diversity_guard_is_independently_enforced() {
    let local = deterministic_key(200);

    let peer_directory = TestDirectory::new("selection-peer");
    let peer_source = deterministic_key(201);
    let peer_subject = deterministic_key(202);
    let mut peer_store = PeerAddressStore::create(
        peer_directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&peer_source, 4001)],
    )
    .unwrap();
    let _ = peer_store
        .admit_record(
            peer_source.public().to_peer_id(),
            record(
                &peer_subject,
                1,
                vec![global_address(101, 1, 4001), global_address(102, 1, 4001)],
            ),
            unix_time(1_000),
        )
        .unwrap();
    assert_eq!(
        peer_store.dial_candidates(unix_time(1_000)).unwrap().len(),
        1
    );

    let group_directory = TestDirectory::new("selection-group");
    let first_source = deterministic_key(203);
    let second_source = deterministic_key(204);
    let mut group_store = PeerAddressStore::create(
        group_directory.path(),
        local.public().to_peer_id(),
        [
            bootstrap(&first_source, 4001),
            bootstrap(&second_source, 4002),
        ],
    )
    .unwrap();
    for (source, subject, host) in [
        (&first_source, deterministic_key(205), 1),
        (&second_source, deterministic_key(206), 2),
    ] {
        let _ = group_store
            .admit_record(
                source.public().to_peer_id(),
                record(&subject, 1, vec![global_address(103, host, 4001)]),
                unix_time(1_000),
            )
            .unwrap();
    }
    assert_eq!(
        group_store.dial_candidates(unix_time(1_000)).unwrap().len(),
        1
    );

    let source_directory = TestDirectory::new("selection-source");
    let source = deterministic_key(207);
    let mut source_store = PeerAddressStore::create(
        source_directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&source, 4001)],
    )
    .unwrap();
    for index in 0..3 {
        let subject = deterministic_key(208 + index);
        let _ = source_store
            .admit_record(
                source.public().to_peer_id(),
                record(&subject, 1, vec![global_address(104 + index, 1, 4001)]),
                unix_time(1_000),
            )
            .unwrap();
    }
    assert_eq!(
        source_store
            .dial_candidates(unix_time(1_000))
            .unwrap()
            .len(),
        MAX_DIAL_CANDIDATES_PER_BOOTSTRAP
    );
}

#[test]
fn snapshot_corruption_and_non_normalized_envelopes_fail_closed() {
    let directory = TestDirectory::new("corruption");
    let local = deterministic_key(210);
    let source = deterministic_key(211);
    let subject = deterministic_key(212);
    let bootstraps = vec![bootstrap(&source, 4001)];
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        bootstraps.clone(),
    )
    .unwrap();
    let _ = store
        .admit_record(
            source.public().to_peer_id(),
            record(&subject, 1, vec![global_address(90, 1, 4001)]),
            unix_time(1_000),
        )
        .unwrap();
    drop(store);
    let canonical = directory.snapshot();

    let mut checksum_mismatch = canonical.clone();
    checksum_mismatch[STORE_HEADER.len()] ^= 1;
    directory.write_snapshot(&checksum_mismatch);
    assert!(matches!(
        PeerAddressStore::open(
            directory.path(),
            local.public().to_peer_id(),
            bootstraps.clone()
        ),
        Err(PeerAddressStoreError::ChecksumMismatch)
    ));

    let mut trailing = canonical.clone();
    trailing.insert(trailing.len() - CHECKSUM_BYTES, 0);
    replace_checksum(&mut trailing);
    directory.write_snapshot(&trailing);
    assert!(matches!(
        PeerAddressStore::open(
            directory.path(),
            local.public().to_peer_id(),
            bootstraps.clone()
        ),
        Err(PeerAddressStoreError::InvalidSnapshot("trailing bytes"))
    ));

    let mut impossible_count = canonical.clone();
    let count_position = STORE_HEADER.len()
        + 1
        + usize::from(canonical[STORE_HEADER.len()])
        + CHECKSUM_BYTES
        + SALT_BYTES;
    impossible_count[count_position..count_position + 2]
        .copy_from_slice(&(MAX_PEER_ADDRESS_RECORDS as u16).to_be_bytes());
    replace_checksum(&mut impossible_count);
    directory.write_snapshot(&impossible_count);
    assert!(matches!(
        PeerAddressStore::open(
            directory.path(),
            local.public().to_peer_id(),
            bootstraps.clone()
        ),
        Err(PeerAddressStoreError::InvalidSnapshot(
            "record count exceeds remaining bytes"
        ))
    ));

    let mut non_normalized = canonical.clone();
    let (length_position, envelope_start, envelope_length) = first_envelope_bounds(&non_normalized);
    let original_envelope =
        non_normalized[envelope_start..envelope_start + envelope_length].to_vec();
    let unknown_field = [0x78, 0x01];
    non_normalized.splice(
        envelope_start + envelope_length..envelope_start + envelope_length,
        unknown_field,
    );
    non_normalized[length_position..length_position + 2].copy_from_slice(
        &u16::try_from(envelope_length + unknown_field.len())
            .unwrap()
            .to_be_bytes(),
    );
    replace_checksum(&mut non_normalized);
    let extended =
        &non_normalized[envelope_start..envelope_start + envelope_length + unknown_field.len()];
    assert_eq!(
        SignedPeerRecord::from_envelope_bytes(extended.to_vec())
            .unwrap()
            .envelope_bytes(),
        original_envelope
    );
    directory.write_snapshot(&non_normalized);
    assert!(matches!(
        PeerAddressStore::open(
            directory.path(),
            local.public().to_peer_id(),
            bootstraps.clone()
        ),
        Err(PeerAddressStoreError::InvalidSnapshot(
            "signed envelope is not normalized"
        ))
    ));

    let oversized = vec![0_u8; MAX_STORE_BYTES + 1];
    directory.write_snapshot(&oversized);
    assert!(matches!(
        PeerAddressStore::open(directory.path(), local.public().to_peer_id(), bootstraps),
        Err(PeerAddressStoreError::SnapshotTooLong { .. })
    ));
}

#[test]
fn snapshot_revalidates_source_membership_and_subject_order() {
    let directory = TestDirectory::new("snapshot-semantics");
    let local = deterministic_key(221);
    let source = deterministic_key(222);
    let first = deterministic_key(223);
    let second = deterministic_key(224);
    let bootstraps = vec![bootstrap(&source, 4001)];
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        bootstraps.clone(),
    )
    .unwrap();
    for (subject, group) in [(&first, 92), (&second, 93)] {
        let _ = store
            .admit_record(
                source.public().to_peer_id(),
                record(subject, 1, vec![global_address(group, 1, 4001)]),
                unix_time(1_000),
            )
            .unwrap();
    }

    store.records.swap(0, 1);
    let unsorted = store.encode_snapshot(&[]).unwrap();
    assert!(matches!(
        decode_snapshot(
            &unsorted,
            local.public().to_peer_id(),
            &store.bootstraps,
            store.bootstrap_digest
        ),
        Err(PeerAddressStoreError::InvalidSnapshot(
            "record subjects are not strictly ordered"
        ))
    ));
    store.records.swap(0, 1);

    store.records[1].record = store.records[0].record.clone();
    let duplicate_subject = store.encode_snapshot(&[]).unwrap();
    assert!(matches!(
        decode_snapshot(
            &duplicate_subject,
            local.public().to_peer_id(),
            &store.bootstraps,
            store.bootstrap_digest
        ),
        Err(PeerAddressStoreError::InvalidSnapshot(
            "record subjects are not strictly ordered"
        ))
    ));

    store.records[0].source_peer_id = deterministic_key(225).public().to_peer_id();
    let unknown_source = store.encode_snapshot(&[]).unwrap();
    assert!(matches!(
        decode_snapshot(
            &unknown_source,
            local.public().to_peer_id(),
            &bootstraps,
            store.bootstrap_digest
        ),
        Err(PeerAddressStoreError::UnknownSource(_))
    ));
}

#[test]
fn commit_failure_poisoning_hides_state_and_reopen_recovers_old_snapshot() {
    let directory = TestDirectory::new("poison");
    let local = deterministic_key(213);
    let source = deterministic_key(214);
    let subject = deterministic_key(215);
    let bootstraps = vec![bootstrap(&source, 4001)];
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        bootstraps.clone(),
    )
    .unwrap();
    let old_snapshot = directory.snapshot();
    fs::create_dir(directory.path().join(TEMP_FILE_NAME)).unwrap();

    assert!(matches!(
        store.admit_record(
            source.public().to_peer_id(),
            record(&subject, 1, vec![global_address(91, 1, 4001)]),
            unix_time(1_000)
        ),
        Err(PeerAddressStoreError::Commit { .. })
    ));
    assert_eq!(directory.snapshot(), old_snapshot);
    assert!(matches!(store.len(), Err(PeerAddressStoreError::Poisoned)));
    assert!(matches!(
        store.dial_candidates(unix_time(1_000)),
        Err(PeerAddressStoreError::Poisoned)
    ));
    assert!(matches!(
        PeerAddressStore::open(
            directory.path(),
            local.public().to_peer_id(),
            bootstraps.clone()
        ),
        Err(PeerAddressStoreError::Locked)
    ));
    drop(store);
    fs::remove_dir(directory.path().join(TEMP_FILE_NAME)).unwrap();

    let reopened =
        PeerAddressStore::open(directory.path(), local.public().to_peer_id(), bootstraps).unwrap();
    assert!(reopened.is_empty().unwrap());
}

#[test]
fn digest_preimages_have_stable_goldens() {
    let local = deterministic_key(216);
    let first = deterministic_key(217);
    let second = deterministic_key(218);
    let bootstraps = validate_bootstraps(
        local.public().to_peer_id(),
        [bootstrap(&second, 4002), bootstrap(&first, 4001)],
    )
    .unwrap();
    assert_eq!(
        hex(&bootstrap_digest(&bootstraps)),
        "12db3d9fa493bd453d510e1c4cc434989ca7d04b1c93222c4467f22b7ce77ac1"
    );

    let salt = std::array::from_fn(|index| index as u8);
    assert_eq!(
        hex(&candidate_score(
            &salt,
            123,
            deterministic_key(219).public().to_peer_id(),
            &"/ip4/8.8.8.8/tcp/4001".parse().unwrap(),
            deterministic_key(220).public().to_peer_id()
        )),
        "68dd55e065e1df195c6e601e6ab45a04698fa0ef77f8e7ba06f434db1fae384f"
    );
}

#[test]
fn one_entry_snapshot_has_a_stable_complete_golden() {
    let directory = TestDirectory::new("snapshot-golden");
    let local = deterministic_key(226);
    let source = deterministic_key(227);
    let subject = deterministic_key(228);
    let mut store = PeerAddressStore::create(
        directory.path(),
        local.public().to_peer_id(),
        [bootstrap(&source, 4001)],
    )
    .unwrap();
    store.ordering_salt = std::array::from_fn(|index| index as u8);
    let _ = store
        .admit_record(
            source.public().to_peer_id(),
            record(
                &subject,
                9,
                vec!["/ip4/111.2.3.4/tcp/4001".parse().unwrap()],
            ),
            unix_time(123_456),
        )
        .unwrap();
    assert_eq!(
        hex(&store.encode_snapshot(&[]).unwrap()),
        "6e616f6d653a706565722d616464726573732d73746f72650026002408011220c91cb3ce2b84e4ba85f562ece41edfe4e27afc52d88d507f66a18638df823e9f16ad50f78bf9649113fd91c8b67f55cf9faffbbcff7e2f5f84e722e79e7820ea000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0001260024080112204dd9b6496a27571acb089a5e3482dfc86acdeddc4d1f28e15a9b04f026d7f226000000000001e24000a40a240801122099a7a471e0ad5d0eb66af0e10ab93292b943eb805de97911637db4be0c072e42120203011a360a2600240801122099a7a471e0ad5d0eb66af0e10ab93292b943eb805de97911637db4be0c072e4210091a0a0a08046f020304060fa12a4034b5287dce85c393caf8669500437d0504ed26de32d415de64b60fffe0cf1254c6ed2d5fc117e17685cd9d90b50f9ce079843ab4474b4c208cc5fd05025ba402d19dd12e8c01a550d6f3c324c8205367f36e382e75bad9cc722fb99ca6d44139"
    );
}

#[test]
fn receipt_time_overflow_is_rejected() {
    assert!(matches!(
        validate_receipt_time(u64::MAX),
        Err(PeerAddressStoreError::ReceiptTimeOverflow)
    ));
}
