use super::*;
use crate::consensus_push::*;
use libp2p::futures::{executor::block_on, io::Cursor};
use libp2p::request_response::Codec;

fn budget() -> Arc<InboundRetentionBudget> {
    Arc::new(InboundRetentionBudget::new(
        CONSENSUS_PUSH_MAX_RETAINED_INBOUND_EVENTS,
        CONSENSUS_PUSH_MAX_RETAINED_INBOUND_BYTES,
    ))
}
fn proposal_header(control: usize, payload: usize) -> Vec<u8> {
    let mut bytes = vec![PROPOSAL_TAG];
    bytes.extend_from_slice(&u32::try_from(control).unwrap().to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(payload).unwrap().to_be_bytes());
    bytes
}
fn encode(codec: &mut ConsensusPushCodec, message: ConsensusPushMessage) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    block_on(codec.write_request(
        &CONSENSUS_PUSH_PROTOCOL,
        &mut output,
        ConsensusPushRequest {
            message,
            _inbound_permit: None,
        },
    ))
    .unwrap();
    output.into_inner()
}

#[test]
fn exact_frames_round_trip_both_variants_and_maximum_proposal() {
    assert_eq!(
        CONSENSUS_PUSH_PROTOCOL.as_ref(),
        "/naome/fixed-validator-consensus-push-v0"
    );
    assert_eq!(
        (
            CONSENSUS_PUSH_MIN_PROPOSAL_BYTES,
            CONSENSUS_PUSH_MAX_PROPOSAL_BYTES,
            CONSENSUS_PUSH_MAX_PAYLOAD_BYTES,
            CONSENSUS_PUSH_VOTE_BYTES
        ),
        (481, 25177, 4194305, 214)
    );
    let mut codec = ConsensusPushCodec::new(budget());
    for (control_bytes, payload_bytes) in [
        (CONSENSUS_PUSH_MIN_PROPOSAL_BYTES, 1),
        (
            CONSENSUS_PUSH_MAX_PROPOSAL_BYTES,
            CONSENSUS_PUSH_MAX_PAYLOAD_BYTES,
        ),
    ] {
        let bytes = encode(
            &mut codec,
            ConsensusPushMessage::Proposal {
                canonical_proposal: vec![0xa5; control_bytes],
                canonical_artifact: vec![0x5a; payload_bytes],
            },
        );
        assert_eq!(&bytes[..9], proposal_header(control_bytes, payload_bytes));
        assert_eq!(bytes.len(), 9 + control_bytes + payload_bytes);
        let request =
            block_on(codec.read_request(&CONSENSUS_PUSH_PROTOCOL, &mut Cursor::new(bytes)))
                .unwrap();
        assert_eq!(
            request.message(),
            &ConsensusPushMessage::Proposal {
                canonical_proposal: vec![0xa5; control_bytes],
                canonical_artifact: vec![0x5a; payload_bytes]
            }
        );
    }
    let bytes = encode(
        &mut codec,
        ConsensusPushMessage::Vote {
            canonical_vote: vec![0xff; CONSENSUS_PUSH_VOTE_BYTES],
        },
    );
    assert_eq!(bytes[0], VOTE_TAG);
    assert_eq!(bytes.len(), 1 + CONSENSUS_PUSH_VOTE_BYTES);
    let request =
        block_on(codec.read_request(&CONSENSUS_PUSH_PROTOCOL, &mut Cursor::new(bytes))).unwrap();
    assert_eq!(
        request.message(),
        &ConsensusPushMessage::Vote {
            canonical_vote: vec![0xff; CONSENSUS_PUSH_VOTE_BYTES]
        }
    );
    let mut receipt = Cursor::new(Vec::new());
    block_on(codec.write_response(&CONSENSUS_PUSH_PROTOCOL, &mut receipt, ConsensusPushReceipt))
        .unwrap();
    assert_eq!(receipt.into_inner(), [1]);
    assert_eq!(
        block_on(codec.read_response(&CONSENSUS_PUSH_PROTOCOL, &mut Cursor::new(vec![1]))).unwrap(),
        ConsensusPushReceipt
    );
}

#[test]
fn both_proposal_lengths_are_rejected_before_any_body_read() {
    let mut codec = ConsensusPushCodec::new(budget());
    for (control, payload) in [
        (0, 1),
        (CONSENSUS_PUSH_MIN_PROPOSAL_BYTES - 1, 1),
        (CONSENSUS_PUSH_MAX_PROPOSAL_BYTES + 1, 1),
        (CONSENSUS_PUSH_MIN_PROPOSAL_BYTES, 0),
        (
            CONSENSUS_PUSH_MAX_PROPOSAL_BYTES,
            CONSENSUS_PUSH_MAX_PAYLOAD_BYTES + 1,
        ),
        (u32::MAX as usize, u32::MAX as usize),
    ] {
        let mut bytes = proposal_header(control, payload);
        bytes.extend_from_slice(&[0xa5; 32]);
        let mut input = Cursor::new(bytes);
        assert_eq!(
            block_on(codec.read_request(&CONSENSUS_PUSH_PROTOCOL, &mut input))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(input.position(), 9);
    }
    let mut unknown = Cursor::new(vec![2, 0xff]);
    assert_eq!(
        block_on(codec.read_request(&CONSENSUS_PUSH_PROTOCOL, &mut unknown))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(unknown.position(), 1);
}

#[test]
fn truncated_and_trailing_frames_release_their_permits() {
    // One slot ensures any leaked permit turns the next decode into a capacity failure.
    let budget = Arc::new(InboundRetentionBudget::new(
        1,
        CONSENSUS_PUSH_MAX_RETAINED_INBOUND_BYTES,
    ));
    let mut codec = ConsensusPushCodec::new(budget);
    let header = proposal_header(CONSENSUS_PUSH_MIN_PROPOSAL_BYTES, 1);
    for prefix in 0..header.len() {
        assert_eq!(
            block_on(codec.read_request(
                &CONSENSUS_PUSH_PROTOCOL,
                &mut Cursor::new(header[..prefix].to_vec())
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    for message in [
        ConsensusPushMessage::Proposal {
            canonical_proposal: vec![0; CONSENSUS_PUSH_MIN_PROPOSAL_BYTES],
            canonical_artifact: vec![0; 1],
        },
        ConsensusPushMessage::Vote {
            canonical_vote: vec![0; CONSENSUS_PUSH_VOTE_BYTES],
        },
    ] {
        let bytes = encode(&mut codec, message);
        for length in [1, bytes.len() - 1] {
            assert_eq!(
                block_on(codec.read_request(
                    &CONSENSUS_PUSH_PROTOCOL,
                    &mut Cursor::new(bytes[..length].to_vec())
                ))
                .unwrap_err()
                .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            block_on(codec.read_request(&CONSENSUS_PUSH_PROTOCOL, &mut Cursor::new(trailing)))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        drop(
            block_on(codec.read_request(&CONSENSUS_PUSH_PROTOCOL, &mut Cursor::new(bytes)))
                .unwrap(),
        );
    }
}

#[test]
fn all_noncanonical_receipts_are_rejected() {
    let mut codec = ConsensusPushCodec::new(budget());
    assert_eq!(
        block_on(codec.read_response(&CONSENSUS_PUSH_PROTOCOL, &mut Cursor::new(Vec::<u8>::new())))
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    for byte in 0..=255 {
        if byte == 1 {
            continue;
        }
        let mut input = Cursor::new(vec![byte, 0]);
        assert_eq!(
            block_on(codec.read_response(&CONSENSUS_PUSH_PROTOCOL, &mut input))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(input.position(), 1);
    }
    assert_eq!(
        block_on(codec.read_response(&CONSENSUS_PUSH_PROTOCOL, &mut Cursor::new(vec![1, 0])))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn combined_byte_and_event_capacity_precedes_allocation_and_recovers_on_drop() {
    let budget = budget();
    let maximum = CONSENSUS_PUSH_MAX_PROPOSAL_BYTES + CONSENSUS_PUSH_MAX_PAYLOAD_BYTES;
    let permits: Vec<_> = (1..CONSENSUS_PUSH_MAX_RETAINED_INBOUND_EVENTS)
        .map(|_| InboundRetentionBudget::try_acquire(&budget, maximum).unwrap())
        .collect();
    let mut codec = ConsensusPushCodec::new(Arc::clone(&budget));
    let bytes = encode(
        &mut codec,
        ConsensusPushMessage::Proposal {
            canonical_proposal: vec![0; CONSENSUS_PUSH_MAX_PROPOSAL_BYTES],
            canonical_artifact: vec![0; CONSENSUS_PUSH_MAX_PAYLOAD_BYTES],
        },
    );
    let held =
        block_on(codec.read_request(&CONSENSUS_PUSH_PROTOCOL, &mut Cursor::new(bytes))).unwrap();
    for bytes in [
        proposal_header(CONSENSUS_PUSH_MIN_PROPOSAL_BYTES, 1),
        vec![VOTE_TAG],
    ] {
        let prefix_length = bytes.len();
        let mut input = Cursor::new(bytes);
        assert_eq!(
            block_on(codec.read_request(&CONSENSUS_PUSH_PROTOCOL, &mut input))
                .unwrap_err()
                .kind(),
            io::ErrorKind::OutOfMemory
        );
        assert_eq!(input.position(), prefix_length as u64);
    }
    drop(held);
    drop(permits);
    let votes: Vec<_> = (0..CONSENSUS_PUSH_MAX_RETAINED_INBOUND_EVENTS)
        .map(|_| {
            let mut bytes = vec![VOTE_TAG];
            bytes.resize(1 + CONSENSUS_PUSH_VOTE_BYTES, 0);
            block_on(codec.read_request(&CONSENSUS_PUSH_PROTOCOL, &mut Cursor::new(bytes))).unwrap()
        })
        .collect();
    assert!(InboundRetentionBudget::try_acquire(&budget, 1).is_none());
    drop(votes);
    assert!(InboundRetentionBudget::try_acquire(&budget, maximum).is_some());
    assert!(
        InboundRetentionBudget::try_acquire(&budget, CONSENSUS_PUSH_MAX_RETAINED_INBOUND_BYTES + 1)
            .is_none()
    );
}
