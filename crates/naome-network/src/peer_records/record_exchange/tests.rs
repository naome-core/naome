use std::cell::Cell;

use libp2p::core::peer_record::PeerRecord;
use libp2p::core::signed_envelope::SignedEnvelope;
use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId};

use super::*;

const STANDARD_DOMAIN: &str = "libp2p-peer-record";
const STANDARD_PAYLOAD_TYPE: &[u8] = &[0x03, 0x01];

fn deterministic_key(seed: u8) -> Keypair {
    Keypair::ed25519_from_bytes([seed; 32]).unwrap()
}

fn push_varint(bytes: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        bytes.push(value as u8 & 0x7f | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
}

fn push_bytes_field(bytes: &mut Vec<u8>, field: u8, value: &[u8]) {
    bytes.push(field << 3 | 2);
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

fn record(seed: u8, sequence: u64) -> SignedPeerRecord {
    let signer = deterministic_key(seed);
    let address: Multiaddr = format!("/ip4/11.2.{}.4/tcp/4001", seed.max(1))
        .parse()
        .unwrap();
    SignedPeerRecord::from_envelope_bytes(envelope_bytes(
        &signer,
        signer.public().to_peer_id(),
        sequence,
        &[address],
    ))
    .unwrap()
}

fn wire_in_order(records: &[&SignedPeerRecord]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(u8::try_from(records.len()).unwrap());
    for record in records {
        bytes.extend_from_slice(
            &u16::try_from(record.envelope_bytes().len())
                .unwrap()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(record.envelope_bytes());
    }
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn empty_request_and_batch_have_exact_goldens() {
    assert_eq!(PeerRecordPullRequest.to_wire_bytes(), []);
    assert!(matches!(
        PeerRecordPullRequest::from_wire_bytes(&[]),
        Ok(PeerRecordPullRequest)
    ));
    assert!(matches!(
        PeerRecordPullRequest::from_wire_bytes(&[0]),
        Err(PeerRecordExchangeWireError::InvalidRequestLength {
            actual: 1,
            expected: 0
        })
    ));

    let batch = PeerRecordBatch::new([]).unwrap();
    assert!(batch.is_empty());
    assert_eq!(batch.len(), 0);
    assert_eq!(batch.to_wire_bytes().unwrap(), [0]);
    assert!(PeerRecordBatch::from_wire_bytes(&[0]).unwrap().is_empty());
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&[]),
        Err(PeerRecordExchangeWireError::MissingRecordCount)
    ));
}

#[test]
fn one_record_batch_has_a_stable_complete_golden() {
    let signer = deterministic_key(228);
    let address = "/ip4/111.2.3.4/tcp/4001".parse().unwrap();
    let record = SignedPeerRecord::from_envelope_bytes(envelope_bytes(
        &signer,
        signer.public().to_peer_id(),
        9,
        &[address],
    ))
    .unwrap();
    let batch = PeerRecordBatch::new([record]).unwrap();
    assert_eq!(
        hex(&batch.to_wire_bytes().unwrap()),
        "0100a40a240801122099a7a471e0ad5d0eb66af0e10ab93292b943eb805de97911637db4be0c072e42120203011a360a2600240801122099a7a471e0ad5d0eb66af0e10ab93292b943eb805de97911637db4be0c072e4210091a0a0a08046f020304060fa12a4034b5287dce85c393caf8669500437d0504ed26de32d415de64b60fffe0cf1254c6ed2d5fc117e17685cd9d90b50f9ce079843ab4474b4c208cc5fd05025ba402"
    );
    let decoded = PeerRecordBatch::from_wire_bytes(&batch.to_wire_bytes().unwrap()).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded.records()[0].peer_id(), signer.public().to_peer_id());
    assert_eq!(decoded.records()[0].sequence(), 9);
}

#[test]
fn maximum_batch_roundtrips_and_the_byte_cap_is_exact() {
    assert_eq!(MAX_PEER_RECORDS_PER_BATCH, 32);
    assert_eq!(PEER_RECORD_BATCH_MAX_BYTES, 131_137);
    let batch = PeerRecordBatch::new(
        (1..=MAX_PEER_RECORDS_PER_BATCH)
            .map(|index| record(u8::try_from(index).unwrap(), index as u64)),
    )
    .unwrap();
    let bytes = batch.to_wire_bytes().unwrap();
    let decoded = PeerRecordBatch::from_wire_bytes(&bytes).unwrap();
    assert_eq!(decoded.len(), MAX_PEER_RECORDS_PER_BATCH);
    assert!(
        decoded
            .records()
            .windows(2)
            .all(
                |pair| compare_peer_id_bytes(pair[0].peer_id_ref(), pair[1].peer_id_ref()).is_lt()
            )
    );
}

#[test]
fn constructor_stops_at_the_first_excess_record() {
    let consumed = Cell::new(0_usize);
    let records = (0_u8..)
        .inspect(|_| consumed.set(consumed.get() + 1))
        .map(|index| record(index.wrapping_add(1), u64::from(index)));
    assert!(matches!(
        PeerRecordBatch::new(records),
        Err(PeerRecordExchangeWireError::RecordCount {
            actual: 33,
            maximum: 32
        })
    ));
    assert_eq!(consumed.get(), MAX_PEER_RECORDS_PER_BATCH + 1);
}

#[test]
fn constructor_canonicalizes_order_and_rejects_duplicate_subjects() {
    let first = record(40, 1);
    let second = record(41, 1);
    let expected = PeerRecordBatch::new([first.clone(), second.clone()])
        .unwrap()
        .to_wire_bytes()
        .unwrap();
    let reversed = PeerRecordBatch::new([second, first.clone()])
        .unwrap()
        .to_wire_bytes()
        .unwrap();
    assert_eq!(expected, reversed);
    assert!(matches!(
        PeerRecordBatch::new([first.clone(), first]),
        Err(PeerRecordExchangeWireError::DuplicateSubject { index: 1, .. })
    ));
}

#[test]
fn decoder_rejects_duplicate_and_descending_subjects() {
    let first = record(50, 1);
    let second = record(51, 1);
    let (lower, higher) =
        if compare_peer_id_bytes(first.peer_id_ref(), second.peer_id_ref()).is_lt() {
            (first, second)
        } else {
            (second, first)
        };
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&wire_in_order(&[&lower, &lower])),
        Err(PeerRecordExchangeWireError::DuplicateSubject { index: 1, .. })
    ));
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&wire_in_order(&[&higher, &lower])),
        Err(PeerRecordExchangeWireError::NonCanonicalSubjectOrder { index: 1 })
    ));
}

#[test]
fn lengths_are_rejected_before_record_decoding() {
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&vec![0; PEER_RECORD_BATCH_MAX_BYTES + 1]),
        Err(PeerRecordExchangeWireError::ResponseTooLong { .. })
    ));
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&[33]),
        Err(PeerRecordExchangeWireError::RecordCount {
            actual: 33,
            maximum: 32
        })
    ));
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&[1, 0]),
        Err(PeerRecordExchangeWireError::TruncatedRecordLength { .. })
    ));
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&[1, 0, 0]),
        Err(PeerRecordExchangeWireError::EmptyRecord { index: 0 })
    ));
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&[1, 0x10, 0x01]),
        Err(PeerRecordExchangeWireError::RecordTooLong {
            index: 0,
            actual: 4097,
            maximum: 4096
        })
    ));
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&[1, 0, 1]),
        Err(PeerRecordExchangeWireError::TruncatedRecord {
            index: 0,
            expected: 1,
            actual: 0
        })
    ));
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&[1, 0, 1, 0]),
        Err(PeerRecordExchangeWireError::InvalidRecord { index: 0, .. })
    ));
    let mut maximum_record = vec![0_u8; 3 + MAX_SIGNED_PEER_RECORD_BYTES];
    maximum_record[0] = 1;
    maximum_record[1..3].copy_from_slice(
        &u16::try_from(MAX_SIGNED_PEER_RECORD_BYTES)
            .unwrap()
            .to_be_bytes(),
    );
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&maximum_record),
        Err(PeerRecordExchangeWireError::InvalidRecord { index: 0, .. })
    ));
    let mut maximum_response = Vec::with_capacity(PEER_RECORD_BATCH_MAX_BYTES);
    maximum_response.push(u8::try_from(MAX_PEER_RECORDS_PER_BATCH).unwrap());
    for _ in 0..MAX_PEER_RECORDS_PER_BATCH {
        maximum_response.extend_from_slice(
            &u16::try_from(MAX_SIGNED_PEER_RECORD_BYTES)
                .unwrap()
                .to_be_bytes(),
        );
        maximum_response.resize(maximum_response.len() + MAX_SIGNED_PEER_RECORD_BYTES, 0);
    }
    assert_eq!(maximum_response.len(), PEER_RECORD_BATCH_MAX_BYTES);
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&maximum_response),
        Err(PeerRecordExchangeWireError::InvalidRecord { index: 0, .. })
    ));
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&[1, 0, 2, 0]),
        Err(PeerRecordExchangeWireError::TruncatedRecord {
            index: 0,
            expected: 2,
            actual: 1
        })
    ));
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&[0, 1]),
        Err(PeerRecordExchangeWireError::TrailingBytes { actual: 1 })
    ));
}

#[test]
fn invalid_legacy_and_non_normalized_records_fail_closed() {
    let valid = record(60, 1);
    let mut invalid_signature = valid.envelope_bytes().to_vec();
    *invalid_signature.last_mut().unwrap() ^= 1;
    let invalid_wire = {
        let mut bytes = vec![1];
        bytes.extend_from_slice(
            &u16::try_from(invalid_signature.len())
                .unwrap()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&invalid_signature);
        bytes
    };
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&invalid_wire),
        Err(PeerRecordExchangeWireError::InvalidRecord { index: 0, .. })
    ));

    let legacy_key = deterministic_key(61);
    let legacy = PeerRecord::new(&legacy_key, vec!["/ip4/61.2.3.4/tcp/4001".parse().unwrap()])
        .unwrap()
        .into_signed_envelope()
        .into_protobuf_encoding();
    let legacy_wire = {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&u16::try_from(legacy.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&legacy);
        bytes
    };
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&legacy_wire),
        Err(PeerRecordExchangeWireError::InvalidRecord { index: 0, .. })
    ));

    let private_key = deterministic_key(62);
    let private = envelope_bytes(
        &private_key,
        private_key.public().to_peer_id(),
        1,
        &["/ip4/10.0.0.1/tcp/4001".parse().unwrap()],
    );
    let private_wire = {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&u16::try_from(private.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&private);
        bytes
    };
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&private_wire),
        Err(PeerRecordExchangeWireError::InvalidRecord { index: 0, .. })
    ));

    let mut non_normalized = valid.envelope_bytes().to_vec();
    non_normalized.extend_from_slice(&[0x78, 0x01]);
    let non_normalized_wire = {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&u16::try_from(non_normalized.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&non_normalized);
        bytes
    };
    assert!(matches!(
        PeerRecordBatch::from_wire_bytes(&non_normalized_wire),
        Err(PeerRecordExchangeWireError::NonCanonicalRecord { index: 0 })
    ));
}
