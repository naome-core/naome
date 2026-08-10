use std::io;

use libp2p::futures::executor::block_on;
use libp2p::futures::io::Cursor;
use libp2p::request_response::Codec;
use naome::proof_exchange::{
    PROOF_REQUEST_BYTES, PROOF_RESPONSE_MAX_BYTES, ProofRequest, ProofResponse,
};

use super::{PROTOCOL, ProofCodec};

fn request_bytes() -> [u8; PROOF_REQUEST_BYTES] {
    let mut bytes = [0_u8; PROOF_REQUEST_BYTES];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap();
    }
    bytes
}

#[test]
fn request_requires_exact_proof_id_and_eof() {
    assert_eq!(PROTOCOL.as_ref(), "/naome/proof-exchange");
    let expected = ProofRequest::from_wire_bytes(&request_bytes()).unwrap();
    let mut codec = ProofCodec;

    let mut exact = Cursor::new(request_bytes().to_vec());
    assert_eq!(
        block_on(codec.read_request(&PROTOCOL, &mut exact)).unwrap(),
        expected
    );

    for length in 0..PROOF_REQUEST_BYTES {
        let mut truncated = Cursor::new(request_bytes()[..length].to_vec());
        assert_eq!(
            block_on(codec.read_request(&PROTOCOL, &mut truncated))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    let mut trailing_bytes = request_bytes().to_vec();
    trailing_bytes.push(0xff);
    let mut trailing = Cursor::new(trailing_bytes);
    assert_eq!(
        block_on(codec.read_request(&PROTOCOL, &mut trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut encoded = Cursor::new(Vec::new());
    block_on(codec.write_request(&PROTOCOL, &mut encoded, expected)).unwrap();
    assert_eq!(encoded.into_inner(), request_bytes());
}

#[test]
fn response_framing_distinguishes_unavailable_and_exact_payload() {
    let mut codec = ProofCodec;

    let mut unavailable = Cursor::new(0_u32.to_be_bytes().to_vec());
    let unavailable = block_on(codec.read_response(&PROTOCOL, &mut unavailable)).unwrap();
    assert!(unavailable.is_unavailable());

    let payload = vec![0x00, 0x00, 0x00, 0x01, 0x10, 0x01];
    let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    let mut found = Cursor::new(frame.clone());
    let found = block_on(codec.read_response(&PROTOCOL, &mut found)).unwrap();
    assert_eq!(found.into_wire_bytes(), payload);

    let mut encoded = Cursor::new(Vec::new());
    let response = ProofResponse::from_wire_bytes(frame[4..].to_vec()).unwrap();
    block_on(codec.write_response(&PROTOCOL, &mut encoded, response)).unwrap();
    assert_eq!(encoded.into_inner(), frame);
}

#[test]
fn oversized_response_stops_after_length_prefix() {
    let mut codec = ProofCodec;
    let oversized = u32::try_from(PROOF_RESPONSE_MAX_BYTES + 1).unwrap();
    let mut frame = oversized.to_be_bytes().to_vec();
    frame.extend_from_slice(&[0xa5; 64]);
    let mut input = Cursor::new(frame);

    assert_eq!(
        block_on(codec.read_response(&PROTOCOL, &mut input))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(input.position(), 4);
}

#[test]
fn response_rejects_truncation_and_trailing_bytes() {
    let mut codec = ProofCodec;

    for prefix_length in 0..4 {
        let mut prefix = Cursor::new(3_u32.to_be_bytes()[..prefix_length].to_vec());
        assert_eq!(
            block_on(codec.read_response(&PROTOCOL, &mut prefix))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    let mut truncated = 3_u32.to_be_bytes().to_vec();
    truncated.extend_from_slice(&[1, 2]);
    let mut truncated = Cursor::new(truncated);
    assert_eq!(
        block_on(codec.read_response(&PROTOCOL, &mut truncated))
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );

    let mut unavailable_with_trailing = 0_u32.to_be_bytes().to_vec();
    unavailable_with_trailing.push(0xff);
    let mut unavailable_with_trailing = Cursor::new(unavailable_with_trailing);
    assert_eq!(
        block_on(codec.read_response(&PROTOCOL, &mut unavailable_with_trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut declared_shorter = 2_u32.to_be_bytes().to_vec();
    declared_shorter.extend_from_slice(&[1, 2, 3]);
    let mut declared_shorter = Cursor::new(declared_shorter);
    assert_eq!(
        block_on(codec.read_response(&PROTOCOL, &mut declared_shorter))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn maximum_response_is_accepted() {
    let mut codec = ProofCodec;
    let mut frame = Vec::with_capacity(4 + PROOF_RESPONSE_MAX_BYTES);
    frame.extend_from_slice(
        &u32::try_from(PROOF_RESPONSE_MAX_BYTES)
            .unwrap()
            .to_be_bytes(),
    );
    frame.resize(4 + PROOF_RESPONSE_MAX_BYTES, 0x5a);
    let mut maximum = Cursor::new(frame);
    let decoded = block_on(codec.read_response(&PROTOCOL, &mut maximum)).unwrap();
    let decoded = decoded.into_wire_bytes();
    assert_eq!(decoded.len(), PROOF_RESPONSE_MAX_BYTES);
    assert_eq!(decoded.first(), Some(&0x5a));
    assert_eq!(decoded.last(), Some(&0x5a));
}
