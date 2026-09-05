use crate::transport::inbound_retention::InboundRetentionBudget;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use libp2p::futures::AsyncRead;
use libp2p::futures::executor::block_on;
use libp2p::futures::io::Cursor;
use libp2p::request_response::Codec;
use naome_chain::{ArtifactBlockId, ArtifactChainId};
use naome_protocol::artifact_exchange::{
    ARTIFACT_REQUEST_BYTES, ARTIFACT_RESPONSE_MAX_BYTES, ArtifactRequest, ArtifactResponse,
};
use naome_protocol::block_exchange::{
    ARTIFACT_BLOCK_REQUEST_BYTES, ARTIFACT_BLOCK_RESPONSE_MAX_BYTES, ArtifactBlockRequest,
};
use naome_protocol::chain_head_announcement::{
    ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_BYTES, ArtifactChainHeadAnnouncement,
};
use naome_protocol::chain_head_exchange::{
    ARTIFACT_CHAIN_HEAD_REQUEST_BYTES, ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES,
    ArtifactChainHeadRequest, ArtifactChainHeadResponse,
};

use crate::recovery_bundle_push::{
    RECOVERY_BUNDLE_PUSH_MAX_BYTES, RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_BYTES,
    RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS, RecoveryBundlePushReceipt,
    RecoveryBundlePushRequest,
};
use crate::{MAX_PEER_RECORDS_PER_BATCH, MAX_SIGNED_PEER_RECORD_BYTES, PeerRecordBatch};

use super::{
    ARTIFACT_BLOCK_PROTOCOL, ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL,
    ARTIFACT_CHAIN_HEAD_PROTOCOL, ARTIFACT_PROTOCOL, ArtifactBlockCodec, ArtifactBlockWireResponse,
    ArtifactChainHeadAnnouncementCodec, ArtifactChainHeadAnnouncementReceipt,
    ArtifactChainHeadCodec, ArtifactCodec, PEER_RECORD_PROTOCOL, PeerRecordCodec,
    PeerRecordResponderCodec, PeerRecordResponderRequest, RECOVERY_BUNDLE_PUSH_PROTOCOL,
    RecoveryBundlePushCodec,
};

fn recovery_bundle_push_codec() -> RecoveryBundlePushCodec {
    RecoveryBundlePushCodec::new(Arc::new(InboundRetentionBudget::new(
        RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS,
        RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_BYTES,
    )))
}

struct PendingReader;

impl AsyncRead for PendingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }
}

struct FailingReader;

impl AsyncRead for FailingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "synthetic reset",
        )))
    }
}

fn request_bytes() -> [u8; ARTIFACT_REQUEST_BYTES] {
    let mut bytes = [0_u8; ARTIFACT_REQUEST_BYTES];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap();
    }
    bytes
}

fn block_request_bytes() -> [u8; ARTIFACT_BLOCK_REQUEST_BYTES] {
    [0x42; ARTIFACT_BLOCK_REQUEST_BYTES]
}

fn chain_head_request_bytes() -> [u8; ARTIFACT_CHAIN_HEAD_REQUEST_BYTES] {
    [
        0x71, 0x74, 0xca, 0xe8, 0x6b, 0x0c, 0xd1, 0x8e, 0x23, 0x64, 0x80, 0x5d, 0x1b, 0xb8, 0xda,
        0x7a, 0x34, 0x26, 0x2f, 0x3e, 0xfa, 0x6f, 0x5e, 0x2b, 0x72, 0x3e, 0xc6, 0x61, 0x2a, 0x9e,
        0xc1, 0x5e,
    ]
}

fn chain_head_announcement_bytes() -> [u8; ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_BYTES] {
    let mut bytes = [0_u8; ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_BYTES];
    bytes[..32].fill(0x11);
    bytes[32..].fill(0x22);
    bytes
}

const CHAIN_HEAD_FOUND_RESPONSE_GOLDEN: [u8; 1 + ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES] = [
    0x20, 0x71, 0xca, 0x84, 0xdc, 0xea, 0xe5, 0x1f, 0xd2, 0x33, 0x11, 0xeb, 0x1d, 0x79, 0xfc, 0x97,
    0x22, 0x3d, 0xba, 0x62, 0x82, 0x1d, 0x60, 0x4c, 0xd6, 0xf4, 0xd5, 0x70, 0x10, 0x34, 0xc5, 0xf6,
    0x2d,
];

#[test]
fn request_requires_exact_artifact_id_and_eof() {
    assert_eq!(ARTIFACT_PROTOCOL.as_ref(), "/naome/artifact-exchange");
    let expected = ArtifactRequest::from_wire_bytes(&request_bytes()).unwrap();
    let mut codec = ArtifactCodec;

    let mut exact = Cursor::new(request_bytes().to_vec());
    assert_eq!(
        block_on(codec.read_request(&ARTIFACT_PROTOCOL, &mut exact)).unwrap(),
        expected
    );

    for length in 0..ARTIFACT_REQUEST_BYTES {
        let mut truncated = Cursor::new(request_bytes()[..length].to_vec());
        assert_eq!(
            block_on(codec.read_request(&ARTIFACT_PROTOCOL, &mut truncated))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    let mut trailing_bytes = request_bytes().to_vec();
    trailing_bytes.push(0xff);
    let mut trailing = Cursor::new(trailing_bytes);
    assert_eq!(
        block_on(codec.read_request(&ARTIFACT_PROTOCOL, &mut trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut encoded = Cursor::new(Vec::new());
    block_on(codec.write_request(&ARTIFACT_PROTOCOL, &mut encoded, expected)).unwrap();
    assert_eq!(encoded.into_inner(), request_bytes());
}

#[test]
fn response_framing_distinguishes_unavailable_and_exact_payload() {
    let mut codec = ArtifactCodec;

    let mut unavailable = Cursor::new(0_u32.to_be_bytes().to_vec());
    let unavailable = block_on(codec.read_response(&ARTIFACT_PROTOCOL, &mut unavailable)).unwrap();
    assert!(unavailable.is_unavailable());

    let payload = vec![0x00, 0x00, 0x00, 0x01, 0x10, 0x01];
    let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    let mut found = Cursor::new(frame.clone());
    let found = block_on(codec.read_response(&ARTIFACT_PROTOCOL, &mut found)).unwrap();
    assert_eq!(found.into_wire_bytes(), payload);

    let mut encoded = Cursor::new(Vec::new());
    let response = ArtifactResponse::from_wire_bytes(frame[4..].to_vec()).unwrap();
    block_on(codec.write_response(&ARTIFACT_PROTOCOL, &mut encoded, response)).unwrap();
    assert_eq!(encoded.into_inner(), frame);
}

#[test]
fn oversized_response_stops_after_length_prefix() {
    let mut codec = ArtifactCodec;
    let oversized = u32::try_from(ARTIFACT_RESPONSE_MAX_BYTES + 1).unwrap();
    let mut frame = oversized.to_be_bytes().to_vec();
    frame.extend_from_slice(&[0xa5; 64]);
    let mut input = Cursor::new(frame);

    assert_eq!(
        block_on(codec.read_response(&ARTIFACT_PROTOCOL, &mut input))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(input.position(), 4);
}

#[test]
fn response_rejects_truncation_and_trailing_bytes() {
    let mut codec = ArtifactCodec;

    for prefix_length in 0..4 {
        let mut prefix = Cursor::new(3_u32.to_be_bytes()[..prefix_length].to_vec());
        assert_eq!(
            block_on(codec.read_response(&ARTIFACT_PROTOCOL, &mut prefix))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    let mut truncated = 3_u32.to_be_bytes().to_vec();
    truncated.extend_from_slice(&[1, 2]);
    let mut truncated = Cursor::new(truncated);
    assert_eq!(
        block_on(codec.read_response(&ARTIFACT_PROTOCOL, &mut truncated))
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );

    let mut unavailable_with_trailing = 0_u32.to_be_bytes().to_vec();
    unavailable_with_trailing.push(0xff);
    let mut unavailable_with_trailing = Cursor::new(unavailable_with_trailing);
    assert_eq!(
        block_on(codec.read_response(&ARTIFACT_PROTOCOL, &mut unavailable_with_trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut declared_shorter = 2_u32.to_be_bytes().to_vec();
    declared_shorter.extend_from_slice(&[1, 2, 3]);
    let mut declared_shorter = Cursor::new(declared_shorter);
    assert_eq!(
        block_on(codec.read_response(&ARTIFACT_PROTOCOL, &mut declared_shorter))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn maximum_response_is_accepted() {
    let mut codec = ArtifactCodec;
    let mut frame = Vec::with_capacity(4 + ARTIFACT_RESPONSE_MAX_BYTES);
    frame.extend_from_slice(
        &u32::try_from(ARTIFACT_RESPONSE_MAX_BYTES)
            .unwrap()
            .to_be_bytes(),
    );
    frame.resize(4 + ARTIFACT_RESPONSE_MAX_BYTES, 0x5a);
    let mut maximum = Cursor::new(frame);
    let decoded = block_on(codec.read_response(&ARTIFACT_PROTOCOL, &mut maximum)).unwrap();
    let decoded = decoded.into_wire_bytes();
    assert_eq!(decoded.len(), ARTIFACT_RESPONSE_MAX_BYTES);
    assert_eq!(decoded.first(), Some(&0x5a));
    assert_eq!(decoded.last(), Some(&0x5a));
}

#[test]
fn artifact_block_request_requires_exact_block_id_and_eof() {
    assert_eq!(
        ARTIFACT_BLOCK_PROTOCOL.as_ref(),
        "/naome/artifact-block-exchange"
    );
    let expected = ArtifactBlockRequest::new(ArtifactBlockId::from_bytes(block_request_bytes()));
    let mut codec = ArtifactBlockCodec;

    let mut exact = Cursor::new(block_request_bytes().to_vec());
    assert_eq!(
        block_on(codec.read_request(&ARTIFACT_BLOCK_PROTOCOL, &mut exact)).unwrap(),
        expected
    );

    for length in 0..ARTIFACT_BLOCK_REQUEST_BYTES {
        let mut truncated = Cursor::new(block_request_bytes()[..length].to_vec());
        assert_eq!(
            block_on(codec.read_request(&ARTIFACT_BLOCK_PROTOCOL, &mut truncated))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    let mut trailing_bytes = block_request_bytes().to_vec();
    trailing_bytes.push(0xff);
    let mut trailing = Cursor::new(trailing_bytes);
    assert_eq!(
        block_on(codec.read_request(&ARTIFACT_BLOCK_PROTOCOL, &mut trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut encoded = Cursor::new(Vec::new());
    block_on(codec.write_request(&ARTIFACT_BLOCK_PROTOCOL, &mut encoded, expected)).unwrap();
    assert_eq!(encoded.into_inner(), block_request_bytes());
}

#[test]
fn artifact_block_response_uses_bounded_u8_framing() {
    let mut codec = ArtifactBlockCodec;

    let mut unavailable = Cursor::new(vec![0]);
    let unavailable =
        block_on(codec.read_response(&ARTIFACT_BLOCK_PROTOCOL, &mut unavailable)).unwrap();
    assert!(unavailable.as_bytes().is_empty());
    let mut encoded_unavailable = Cursor::new(Vec::new());
    block_on(codec.write_response(
        &ARTIFACT_BLOCK_PROTOCOL,
        &mut encoded_unavailable,
        ArtifactBlockWireResponse::new(Vec::new()),
    ))
    .unwrap();
    assert_eq!(encoded_unavailable.into_inner(), [0x00]);

    let payload = vec![0x10, 0x20, 0x30];
    let mut frame = vec![u8::try_from(payload.len()).unwrap()];
    frame.extend_from_slice(&payload);
    let mut found = Cursor::new(frame.clone());
    let found = block_on(codec.read_response(&ARTIFACT_BLOCK_PROTOCOL, &mut found)).unwrap();
    assert_eq!(found.as_bytes(), payload);

    let mut encoded = Cursor::new(Vec::new());
    block_on(codec.write_response(
        &ARTIFACT_BLOCK_PROTOCOL,
        &mut encoded,
        ArtifactBlockWireResponse::new(payload),
    ))
    .unwrap();
    assert_eq!(encoded.into_inner(), frame);
}

#[test]
fn artifact_block_response_is_inline_and_roundtrips_every_bounded_length() {
    assert_eq!(
        size_of::<ArtifactBlockWireResponse>(),
        ARTIFACT_BLOCK_RESPONSE_MAX_BYTES + size_of::<u8>()
    );

    for length in 0..=ARTIFACT_BLOCK_RESPONSE_MAX_BYTES {
        let body = (0..length)
            .map(|index| u8::try_from(index).unwrap())
            .collect::<Vec<_>>();
        let mut frame = vec![u8::try_from(length).unwrap()];
        frame.extend_from_slice(&body);

        let mut input = Cursor::new(frame.clone());
        let mut codec = ArtifactBlockCodec;
        let response = block_on(codec.read_response(&ARTIFACT_BLOCK_PROTOCOL, &mut input)).unwrap();
        assert_eq!(response.as_bytes(), body, "decoded body length {length}");

        let mut output = Cursor::new(Vec::new());
        block_on(codec.write_response(&ARTIFACT_BLOCK_PROTOCOL, &mut output, response)).unwrap();
        assert_eq!(output.into_inner(), frame, "encoded body length {length}");
    }
}

#[test]
fn oversized_artifact_block_response_stops_after_u8_prefix() {
    let mut codec = ArtifactBlockCodec;
    let oversized = u8::try_from(ARTIFACT_BLOCK_RESPONSE_MAX_BYTES + 1).unwrap();
    let mut frame = vec![oversized];
    frame.extend_from_slice(&[0xa5; 64]);
    let mut input = Cursor::new(frame);

    assert_eq!(
        block_on(codec.read_response(&ARTIFACT_BLOCK_PROTOCOL, &mut input))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(input.position(), 1);
}

#[test]
fn artifact_block_response_rejects_truncation_and_trailing_bytes() {
    let mut codec = ArtifactBlockCodec;

    let mut prefix = Cursor::new(Vec::new());
    assert_eq!(
        block_on(codec.read_response(&ARTIFACT_BLOCK_PROTOCOL, &mut prefix))
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );

    for body_length in 0..ARTIFACT_BLOCK_RESPONSE_MAX_BYTES {
        let mut truncated = vec![u8::try_from(ARTIFACT_BLOCK_RESPONSE_MAX_BYTES).unwrap()];
        truncated.resize(1 + body_length, 0xa5);
        let mut truncated = Cursor::new(truncated);
        assert_eq!(
            block_on(codec.read_response(&ARTIFACT_BLOCK_PROTOCOL, &mut truncated))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof,
            "accepted truncated artifact-block body length {body_length}"
        );
    }

    for mut frame in [vec![0], vec![2]] {
        frame.extend_from_slice(&[1, 2, 3]);
        let mut trailing = Cursor::new(frame);
        assert_eq!(
            block_on(codec.read_response(&ARTIFACT_BLOCK_PROTOCOL, &mut trailing))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn maximum_artifact_block_response_is_accepted() {
    let mut codec = ArtifactBlockCodec;
    let mut frame = Vec::with_capacity(1 + ARTIFACT_BLOCK_RESPONSE_MAX_BYTES);
    frame.push(u8::try_from(ARTIFACT_BLOCK_RESPONSE_MAX_BYTES).unwrap());
    frame.resize(1 + ARTIFACT_BLOCK_RESPONSE_MAX_BYTES, 0x5a);
    let mut maximum = Cursor::new(frame);

    let decoded = block_on(codec.read_response(&ARTIFACT_BLOCK_PROTOCOL, &mut maximum)).unwrap();
    assert_eq!(decoded.as_bytes().len(), ARTIFACT_BLOCK_RESPONSE_MAX_BYTES);
    assert_eq!(decoded.as_bytes().first(), Some(&0x5a));
    assert_eq!(decoded.as_bytes().last(), Some(&0x5a));
}

#[test]
fn artifact_chain_head_request_requires_exact_chain_id_and_eof() {
    assert_eq!(
        ARTIFACT_CHAIN_HEAD_PROTOCOL.as_ref(),
        "/naome/artifact-chain-head-exchange"
    );
    let expected =
        ArtifactChainHeadRequest::new(ArtifactChainId::from_bytes(chain_head_request_bytes()));
    let mut codec = ArtifactChainHeadCodec;

    let mut exact = Cursor::new(chain_head_request_bytes().to_vec());
    assert_eq!(
        block_on(codec.read_request(&ARTIFACT_CHAIN_HEAD_PROTOCOL, &mut exact)).unwrap(),
        expected
    );

    for length in 0..ARTIFACT_CHAIN_HEAD_REQUEST_BYTES {
        let mut truncated = Cursor::new(chain_head_request_bytes()[..length].to_vec());
        assert_eq!(
            block_on(codec.read_request(&ARTIFACT_CHAIN_HEAD_PROTOCOL, &mut truncated))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    let mut trailing_bytes = chain_head_request_bytes().to_vec();
    trailing_bytes.push(0xff);
    let mut trailing = Cursor::new(trailing_bytes);
    assert_eq!(
        block_on(codec.read_request(&ARTIFACT_CHAIN_HEAD_PROTOCOL, &mut trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut encoded = Cursor::new(Vec::new());
    block_on(codec.write_request(&ARTIFACT_CHAIN_HEAD_PROTOCOL, &mut encoded, expected)).unwrap();
    assert_eq!(encoded.into_inner(), chain_head_request_bytes());
}

#[test]
fn artifact_chain_head_response_has_exact_one_byte_length_frames() {
    let mut codec = ArtifactChainHeadCodec;

    let mut unavailable = Cursor::new(vec![0]);
    let unavailable =
        block_on(codec.read_response(&ARTIFACT_CHAIN_HEAD_PROTOCOL, &mut unavailable)).unwrap();
    assert!(unavailable.is_unavailable());
    let mut encoded_unavailable = Cursor::new(Vec::new());
    block_on(codec.write_response(
        &ARTIFACT_CHAIN_HEAD_PROTOCOL,
        &mut encoded_unavailable,
        ArtifactChainHeadResponse::from_wire_bytes(&[]).unwrap(),
    ))
    .unwrap();
    assert_eq!(encoded_unavailable.into_inner(), [0]);

    let head: [u8; ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES] =
        CHAIN_HEAD_FOUND_RESPONSE_GOLDEN[1..].try_into().unwrap();
    let mut found = Cursor::new(CHAIN_HEAD_FOUND_RESPONSE_GOLDEN.to_vec());
    let found = block_on(codec.read_response(&ARTIFACT_CHAIN_HEAD_PROTOCOL, &mut found)).unwrap();
    assert_eq!(found.head_block_id().unwrap().as_bytes(), &head);

    let mut encoded_found = Cursor::new(Vec::new());
    block_on(codec.write_response(
        &ARTIFACT_CHAIN_HEAD_PROTOCOL,
        &mut encoded_found,
        ArtifactChainHeadResponse::from_wire_bytes(&head).unwrap(),
    ))
    .unwrap();
    assert_eq!(encoded_found.into_inner(), CHAIN_HEAD_FOUND_RESPONSE_GOLDEN);
}

#[test]
fn artifact_chain_head_response_rejects_every_noncanonical_frame() {
    let mut codec = ArtifactChainHeadCodec;

    let mut missing_prefix = Cursor::new(Vec::<u8>::new());
    assert_eq!(
        block_on(codec.read_response(&ARTIFACT_CHAIN_HEAD_PROTOCOL, &mut missing_prefix))
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );

    for declared in 0_u8..=u8::MAX {
        if matches!(declared, 0 | 32) {
            continue;
        }
        let mut frame = vec![declared];
        frame.extend_from_slice(&[0xa5; ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES]);
        let mut invalid = Cursor::new(frame);
        assert_eq!(
            block_on(codec.read_response(&ARTIFACT_CHAIN_HEAD_PROTOCOL, &mut invalid))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData,
            "accepted declared length {declared}"
        );
        assert_eq!(
            invalid.position(),
            1,
            "read body for invalid length {declared}"
        );
    }

    for body_length in 0..ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES {
        let mut frame = vec![u8::try_from(ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES).unwrap()];
        frame.resize(1 + body_length, 0xa5);
        let mut truncated = Cursor::new(frame);
        assert_eq!(
            block_on(codec.read_response(&ARTIFACT_CHAIN_HEAD_PROTOCOL, &mut truncated))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof,
            "accepted truncated head body length {body_length}"
        );
    }

    let mut unavailable_trailing = Cursor::new(vec![0, 0xff]);
    assert_eq!(
        block_on(codec.read_response(&ARTIFACT_CHAIN_HEAD_PROTOCOL, &mut unavailable_trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut found_trailing = vec![u8::try_from(ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES).unwrap()];
    found_trailing.extend_from_slice(&[0xa5; ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES]);
    found_trailing.push(0xff);
    let mut found_trailing = Cursor::new(found_trailing);
    assert_eq!(
        block_on(codec.read_response(&ARTIFACT_CHAIN_HEAD_PROTOCOL, &mut found_trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn artifact_chain_head_announcement_has_exact_request_and_receipt_frames() {
    assert_eq!(
        ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL.as_ref(),
        "/naome/artifact-chain-head-announcement"
    );
    let expected = ArtifactChainHeadAnnouncement::new(
        ArtifactChainId::from_bytes([0x11; 32]),
        ArtifactBlockId::from_bytes([0x22; 32]),
    );
    let mut codec = ArtifactChainHeadAnnouncementCodec;

    let mut exact = Cursor::new(chain_head_announcement_bytes().to_vec());
    assert_eq!(
        block_on(codec.read_request(&ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL, &mut exact))
            .unwrap(),
        expected
    );

    let mut encoded_request = Cursor::new(Vec::new());
    block_on(codec.write_request(
        &ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL,
        &mut encoded_request,
        expected,
    ))
    .unwrap();
    assert_eq!(
        encoded_request.into_inner(),
        chain_head_announcement_bytes()
    );

    let mut receipt = Cursor::new(vec![0x01]);
    assert_eq!(
        block_on(codec.read_response(&ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL, &mut receipt,))
            .unwrap(),
        ArtifactChainHeadAnnouncementReceipt
    );

    let mut encoded_receipt = Cursor::new(Vec::new());
    block_on(codec.write_response(
        &ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL,
        &mut encoded_receipt,
        ArtifactChainHeadAnnouncementReceipt,
    ))
    .unwrap();
    assert_eq!(encoded_receipt.into_inner(), [0x01]);
}

#[test]
fn artifact_chain_head_announcement_rejects_every_noncanonical_frame() {
    let mut codec = ArtifactChainHeadAnnouncementCodec;
    let bytes = chain_head_announcement_bytes();

    for length in 0..ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_BYTES {
        let mut truncated = Cursor::new(bytes[..length].to_vec());
        assert_eq!(
            block_on(
                codec.read_request(&ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL, &mut truncated,)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::UnexpectedEof,
            "accepted truncated announcement length {length}"
        );
    }

    let mut trailing_request = bytes.to_vec();
    trailing_request.push(0xff);
    let mut trailing_request = Cursor::new(trailing_request);
    assert_eq!(
        block_on(codec.read_request(
            &ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL,
            &mut trailing_request,
        ))
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidData
    );

    let mut missing_receipt = Cursor::new(Vec::<u8>::new());
    assert_eq!(
        block_on(codec.read_response(
            &ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL,
            &mut missing_receipt,
        ))
        .unwrap_err()
        .kind(),
        io::ErrorKind::UnexpectedEof
    );

    for receipt in 0_u8..=u8::MAX {
        if receipt == 0x01 {
            continue;
        }
        let mut invalid = Cursor::new(vec![receipt, 0xff]);
        assert_eq!(
            block_on(
                codec.read_response(&ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL, &mut invalid,)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidData,
            "accepted receipt byte {receipt:#04x}"
        );
        assert_eq!(invalid.position(), 1, "read past invalid receipt byte");
    }

    let mut trailing_receipt = Cursor::new(vec![0x01, 0xff]);
    assert_eq!(
        block_on(codec.read_response(
            &ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL,
            &mut trailing_receipt,
        ))
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn recovery_bundle_push_has_exact_request_and_receipt_frames() {
    assert_eq!(
        RECOVERY_BUNDLE_PUSH_PROTOCOL.as_ref(),
        "/naome/recovery-bundle-push-v0"
    );
    let mut codec = recovery_bundle_push_codec();
    let maximum_length = u32::try_from(RECOVERY_BUNDLE_PUSH_MAX_BYTES)
        .unwrap()
        .to_be_bytes();
    let mut encoded_request = Cursor::new(Vec::new());
    block_on(codec.write_request(
        &RECOVERY_BUNDLE_PUSH_PROTOCOL,
        &mut encoded_request,
        RecoveryBundlePushRequest::new(vec![0xa5; RECOVERY_BUNDLE_PUSH_MAX_BYTES]).unwrap(),
    ))
    .unwrap();
    let encoded_request = encoded_request.into_inner();
    assert_eq!(encoded_request.len(), 4 + RECOVERY_BUNDLE_PUSH_MAX_BYTES);
    assert_eq!(&encoded_request[..4], &maximum_length);
    assert!(encoded_request[4..].iter().all(|byte| *byte == 0xa5));

    let mut maximum = Cursor::new(encoded_request);
    let decoded =
        block_on(codec.read_request(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut maximum)).unwrap();
    assert_eq!(decoded.bundle_bytes().len(), RECOVERY_BUNDLE_PUSH_MAX_BYTES);
    assert_eq!(decoded.bundle_bytes()[0], 0xa5);
    assert_eq!(
        decoded.bundle_bytes()[RECOVERY_BUNDLE_PUSH_MAX_BYTES - 1],
        0xa5
    );
    drop(decoded);

    let mut receipt = Cursor::new(vec![0x01]);
    assert_eq!(
        block_on(codec.read_response(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut receipt)).unwrap(),
        RecoveryBundlePushReceipt
    );
    let mut encoded_receipt = Cursor::new(Vec::new());
    block_on(codec.write_response(
        &RECOVERY_BUNDLE_PUSH_PROTOCOL,
        &mut encoded_receipt,
        RecoveryBundlePushReceipt,
    ))
    .unwrap();
    assert_eq!(encoded_receipt.into_inner(), [0x01]);
}

#[test]
fn recovery_bundle_push_rejects_noncanonical_request_frames() {
    let mut codec = recovery_bundle_push_codec();
    for length in 0..4 {
        let prefix = 1_u32.to_be_bytes();
        let mut truncated = Cursor::new(prefix[..length].to_vec());
        assert_eq!(
            block_on(codec.read_request(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut truncated))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof,
            "accepted truncated length prefix of {length} bytes"
        );
    }

    let oversized = u32::try_from(RECOVERY_BUNDLE_PUSH_MAX_BYTES + 1)
        .unwrap()
        .to_be_bytes();
    let mut oversized = Cursor::new(oversized.to_vec());
    assert_eq!(
        block_on(codec.read_request(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut oversized))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(oversized.position(), 4, "read an oversized request body");

    let mut truncated_body = Cursor::new(vec![0, 0, 0, 2, 0xa5]);
    assert_eq!(
        block_on(codec.read_request(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut truncated_body))
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );

    let mut trailing = Cursor::new(vec![0, 0, 0, 1, 0xa5, 0xff]);
    assert_eq!(
        block_on(codec.read_request(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn recovery_bundle_push_rejects_noncanonical_receipts() {
    let mut codec = recovery_bundle_push_codec();
    let mut missing = Cursor::new(Vec::<u8>::new());
    assert_eq!(
        block_on(codec.read_response(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut missing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );

    let mut invalid = Cursor::new(vec![0x00]);
    assert_eq!(
        block_on(codec.read_response(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut invalid))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut trailing = Cursor::new(vec![0x01, 0xff]);
    assert_eq!(
        block_on(codec.read_response(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn recovery_bundle_push_retention_budget_precedes_body_allocation() {
    let budget = Arc::new(InboundRetentionBudget::new(
        RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS,
        RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_BYTES,
    ));
    let retained_peer_slots: Vec<_> = (1..RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS)
        .map(|_| {
            InboundRetentionBudget::try_acquire(&budget, RECOVERY_BUNDLE_PUSH_MAX_BYTES).unwrap()
        })
        .collect();
    let mut codec = RecoveryBundlePushCodec::new(Arc::clone(&budget));
    let mut maximum = Vec::with_capacity(4 + RECOVERY_BUNDLE_PUSH_MAX_BYTES);
    maximum.extend_from_slice(
        &u32::try_from(RECOVERY_BUNDLE_PUSH_MAX_BYTES)
            .unwrap()
            .to_be_bytes(),
    );
    maximum.resize(4 + RECOVERY_BUNDLE_PUSH_MAX_BYTES, 0xa5);
    let retained_maximum =
        block_on(codec.read_request(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut Cursor::new(maximum)))
            .unwrap();

    let mut blocked_body = Cursor::new(vec![0, 0, 0, 1, 0x5a]);
    assert_eq!(
        block_on(codec.read_request(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut blocked_body))
            .unwrap_err()
            .kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(
        blocked_body.position(),
        4,
        "read a body without a byte permit"
    );
    drop(retained_maximum);

    let admitted_nonzero = block_on(codec.read_request(
        &RECOVERY_BUNDLE_PUSH_PROTOCOL,
        &mut Cursor::new(vec![0, 0, 0, 1, 0x5a]),
    ))
    .unwrap();
    assert_eq!(admitted_nonzero.bundle_bytes(), [0x5a]);
    drop(admitted_nonzero);
    drop(retained_peer_slots);

    let mut retained_empty = Vec::new();
    for _ in 0..RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS {
        retained_empty.push(
            block_on(codec.read_request(
                &RECOVERY_BUNDLE_PUSH_PROTOCOL,
                &mut Cursor::new(vec![0, 0, 0, 0]),
            ))
            .unwrap(),
        );
    }
    let mut blocked_empty = Cursor::new(vec![0, 0, 0, 0]);
    assert_eq!(
        block_on(codec.read_request(&RECOVERY_BUNDLE_PUSH_PROTOCOL, &mut blocked_empty))
            .unwrap_err()
            .kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(blocked_empty.position(), 4);
    retained_empty.pop();
    let _ = block_on(codec.read_request(
        &RECOVERY_BUNDLE_PUSH_PROTOCOL,
        &mut Cursor::new(vec![0, 0, 0, 0]),
    ))
    .unwrap();
}

#[test]
fn canonical_128_byte_block_has_the_normative_found_frame() {
    let mut block = Vec::with_capacity(ARTIFACT_BLOCK_RESPONSE_MAX_BYTES);
    block.extend_from_slice(&[
        0x71, 0xca, 0x84, 0xdc, 0xea, 0xe5, 0x1f, 0xd2, 0x33, 0x11, 0xeb, 0x1d, 0x79, 0xfc, 0x97,
        0x22, 0x3d, 0xba, 0x62, 0x82, 0x1d, 0x60, 0x4c, 0xd6, 0xf4, 0xd5, 0x70, 0x10, 0x34, 0xc5,
        0xf6, 0x2d,
    ]);
    block.extend_from_slice(&[0x11; 32]);
    block.extend_from_slice(&[0x22; 32]);
    block.extend_from_slice(&[0x33; 32]);
    assert_eq!(block.len(), ARTIFACT_BLOCK_RESPONSE_MAX_BYTES);

    let mut expected = vec![0x80];
    expected.extend_from_slice(&block);
    let mut encoded = Cursor::new(Vec::new());
    block_on(ArtifactBlockCodec.write_response(
        &ARTIFACT_BLOCK_PROTOCOL,
        &mut encoded,
        ArtifactBlockWireResponse::new(block),
    ))
    .unwrap();
    assert_eq!(encoded.into_inner(), expected);
}

#[test]
fn peer_record_request_and_empty_response_have_exact_framing() {
    assert_eq!(PEER_RECORD_PROTOCOL.as_ref(), "/naome/peer-record-exchange");
    let mut codec = PeerRecordCodec;

    let mut request = Cursor::new(Vec::new());
    assert_eq!(
        block_on(codec.read_request(&PEER_RECORD_PROTOCOL, &mut request)).unwrap(),
        crate::PeerRecordPullRequest
    );
    let mut trailing = Cursor::new(vec![0xff]);
    assert_eq!(
        block_on(codec.read_request(&PEER_RECORD_PROTOCOL, &mut trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    let mut encoded_request = Cursor::new(Vec::new());
    block_on(codec.write_request(
        &PEER_RECORD_PROTOCOL,
        &mut encoded_request,
        crate::PeerRecordPullRequest,
    ))
    .unwrap();
    assert!(encoded_request.into_inner().is_empty());

    let mut response = Cursor::new(vec![0]);
    assert!(
        block_on(codec.read_response(&PEER_RECORD_PROTOCOL, &mut response))
            .unwrap()
            .is_empty()
    );
    let mut encoded_response = Cursor::new(Vec::new());
    block_on(codec.write_response(
        &PEER_RECORD_PROTOCOL,
        &mut encoded_response,
        PeerRecordBatch::new([]).unwrap(),
    ))
    .unwrap();
    assert_eq!(encoded_response.into_inner(), [0]);
}

#[test]
fn peer_record_response_preflights_each_declared_bound() {
    let mut codec = PeerRecordCodec;
    let mut excess_count = Cursor::new(vec![
        u8::try_from(MAX_PEER_RECORDS_PER_BATCH + 1).unwrap(),
        0xff,
    ]);
    assert_eq!(
        block_on(codec.read_response(&PEER_RECORD_PROTOCOL, &mut excess_count))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(excess_count.position(), 1);

    for (bytes, position) in [(vec![1, 0, 0], 3), (vec![1, 0x10, 0x01, 0xff], 3)] {
        let mut input = Cursor::new(bytes);
        assert_eq!(
            block_on(codec.read_response(&PEER_RECORD_PROTOCOL, &mut input))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(input.position(), position);
    }

    for bytes in [vec![1], vec![1, 0, 1]] {
        let mut input = Cursor::new(bytes);
        assert_eq!(
            block_on(codec.read_response(&PEER_RECORD_PROTOCOL, &mut input))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}

#[test]
fn peer_record_response_rejects_trailing_and_reaches_the_exact_body_cap() {
    let mut codec = PeerRecordCodec;
    let mut trailing = Cursor::new(vec![0, 0xff]);
    assert_eq!(
        block_on(codec.read_response(&PEER_RECORD_PROTOCOL, &mut trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut maximum = Vec::with_capacity(crate::PEER_RECORD_BATCH_MAX_BYTES);
    maximum.push(u8::try_from(MAX_PEER_RECORDS_PER_BATCH).unwrap());
    for _ in 0..MAX_PEER_RECORDS_PER_BATCH {
        maximum.extend_from_slice(
            &u16::try_from(MAX_SIGNED_PEER_RECORD_BYTES)
                .unwrap()
                .to_be_bytes(),
        );
        maximum.resize(maximum.len() + MAX_SIGNED_PEER_RECORD_BYTES, 0xa5);
    }
    assert_eq!(maximum.len(), crate::PEER_RECORD_BATCH_MAX_BYTES);
    let mut maximum = Cursor::new(maximum);
    assert_eq!(
        block_on(codec.read_response(&PEER_RECORD_PROTOCOL, &mut maximum))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        maximum.position(),
        u64::try_from(crate::PEER_RECORD_BATCH_MAX_BYTES).unwrap()
    );
}

#[tokio::test(start_paused = true)]
async fn responder_request_reader_classifies_eof_invalid_timeout_and_io() {
    let mut codec = PeerRecordResponderCodec;

    let mut exact = Cursor::new(Vec::new());
    assert!(matches!(
        codec
            .read_request(&PEER_RECORD_PROTOCOL, &mut exact)
            .await
            .unwrap(),
        PeerRecordResponderRequest::Valid
    ));

    let mut nonempty = Cursor::new(vec![0xff; 64]);
    assert!(matches!(
        codec
            .read_request(&PEER_RECORD_PROTOCOL, &mut nonempty)
            .await
            .unwrap(),
        PeerRecordResponderRequest::Invalid
    ));
    assert_eq!(nonempty.position(), 1);

    let started = tokio::time::Instant::now();
    let mut pending = PendingReader;
    assert!(matches!(
        codec
            .read_request(&PEER_RECORD_PROTOCOL, &mut pending)
            .await
            .unwrap(),
        PeerRecordResponderRequest::ReadTimedOut
    ));
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(10)
    );

    let mut failing = FailingReader;
    let PeerRecordResponderRequest::ReadFailed(source) = codec
        .read_request(&PEER_RECORD_PROTOCOL, &mut failing)
        .await
        .unwrap()
    else {
        panic!("expected the exact read failure")
    };
    assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);

    let publication = Arc::new(vec![0_u8]);
    let mut encoded = Cursor::new(Vec::new());
    codec
        .write_response(&PEER_RECORD_PROTOCOL, &mut encoded, publication)
        .await
        .unwrap();
    assert_eq!(encoded.into_inner(), [0]);
}
