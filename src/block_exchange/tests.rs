use naome_chain::{
    PROOF_BLOCK_BYTES, ProofBlock, ProofBlockDecodeError, ProofBlockId, ProofSetRoot,
};
use naome_proof::ProofId;

use super::{
    PROOF_BLOCK_REQUEST_BYTES, PROOF_BLOCK_RESPONSE_MAX_BYTES, ProofBlockExchangeWireError,
    ProofBlockRequest, ProofBlockResponse,
};

fn golden_block() -> ProofBlock {
    ProofBlock::new(
        ProofBlockId::from_bytes([
            0x71, 0xca, 0x84, 0xdc, 0xea, 0xe5, 0x1f, 0xd2, 0x33, 0x11, 0xeb, 0x1d, 0x79, 0xfc,
            0x97, 0x22, 0x3d, 0xba, 0x62, 0x82, 0x1d, 0x60, 0x4c, 0xd6, 0xf4, 0xd5, 0x70, 0x10,
            0x34, 0xc5, 0xf6, 0x2d,
        ]),
        ProofSetRoot::from_bytes([0x11; 32]),
        ProofSetRoot::from_bytes([0x22; 32]),
        ProofId::from_bytes([0x33; 32]),
    )
}

#[test]
fn request_is_exactly_one_raw_block_id() {
    let block_id = golden_block().id();
    let request = ProofBlockRequest::new(block_id);
    assert_eq!(request.block_id(), block_id);
    assert_eq!(request.to_wire_bytes(), *block_id.as_bytes());
    assert_eq!(
        ProofBlockRequest::from_wire_bytes(block_id.as_bytes()).unwrap(),
        request
    );

    for actual in 0..PROOF_BLOCK_REQUEST_BYTES {
        assert_eq!(
            ProofBlockRequest::from_wire_bytes(&block_id.as_bytes()[..actual]),
            Err(ProofBlockExchangeWireError::InvalidRequestLength {
                actual,
                expected: PROOF_BLOCK_REQUEST_BYTES,
            })
        );
    }
    let mut extended = block_id.as_bytes().to_vec();
    extended.push(0xff);
    assert_eq!(
        ProofBlockRequest::from_wire_bytes(&extended),
        Err(ProofBlockExchangeWireError::InvalidRequestLength {
            actual: PROOF_BLOCK_REQUEST_BYTES + 1,
            expected: PROOF_BLOCK_REQUEST_BYTES,
        })
    );
}

#[test]
fn unavailable_or_matching_fixed_block_is_the_only_response() {
    let block = golden_block();
    let expected_block_id = ProofBlockId::from_bytes([
        0x64, 0x1d, 0xa8, 0x6f, 0x08, 0x14, 0xc4, 0xeb, 0x26, 0x16, 0xc6, 0x66, 0x8d, 0x40, 0xc0,
        0x02, 0x7b, 0x48, 0x94, 0x0f, 0x22, 0x82, 0x8c, 0xea, 0xbd, 0xc0, 0x9e, 0x2a, 0x5d, 0xe9,
        0xab, 0xab,
    ]);
    assert_eq!(block.id(), expected_block_id);
    let request = ProofBlockRequest::new(expected_block_id);

    let unavailable = ProofBlockResponse::from_wire_bytes(request, &[]).unwrap();
    assert!(unavailable.is_unavailable());
    assert!(unavailable.to_wire_bytes().is_empty());
    assert_eq!(unavailable.into_block(), None);

    let bytes = block.to_canonical_bytes();
    assert_eq!(bytes.len(), PROOF_BLOCK_BYTES);
    let found = ProofBlockResponse::from_wire_bytes(request, &bytes).unwrap();
    assert!(!found.is_unavailable());
    assert_eq!(found.to_wire_bytes(), bytes);
    assert_eq!(found.into_block(), Some(block));
}

#[test]
fn response_length_decode_and_identity_checks_have_stable_precedence() {
    assert_eq!(PROOF_BLOCK_RESPONSE_MAX_BYTES, PROOF_BLOCK_BYTES);
    let block = golden_block();
    let request = ProofBlockRequest::new(block.id());

    let oversized = [0; PROOF_BLOCK_RESPONSE_MAX_BYTES + 1];
    assert_eq!(
        ProofBlockResponse::from_wire_bytes(request, &oversized).unwrap_err(),
        ProofBlockExchangeWireError::ResponseTooLong {
            actual: PROOF_BLOCK_RESPONSE_MAX_BYTES + 1,
            maximum: PROOF_BLOCK_RESPONSE_MAX_BYTES,
        }
    );
    assert_eq!(
        ProofBlockResponse::from_wire_bytes(request, &[0]).unwrap_err(),
        ProofBlockExchangeWireError::BlockDecode {
            source: ProofBlockDecodeError::InvalidLength {
                actual: 1,
                expected: PROOF_BLOCK_BYTES,
            },
        }
    );

    let mut substituted = block.to_canonical_bytes();
    substituted[0] ^= 1;
    let substituted_block = ProofBlock::from_canonical_bytes(&substituted).unwrap();
    assert_eq!(
        ProofBlockResponse::from_wire_bytes(request, &substituted).unwrap_err(),
        ProofBlockExchangeWireError::BlockIdMismatch {
            expected: block.id(),
            actual: substituted_block.id(),
        }
    );
}

#[test]
fn every_fixed_block_byte_is_request_identity_bearing() {
    let block = golden_block();
    let request = ProofBlockRequest::new(block.id());
    let bytes = block.to_canonical_bytes();

    for index in 0..bytes.len() {
        let mut mutated = bytes;
        mutated[index] ^= 1;
        assert!(
            matches!(
                ProofBlockResponse::from_wire_bytes(request, &mutated),
                Err(ProofBlockExchangeWireError::BlockIdMismatch { .. })
            ),
            "mutated response byte {index} bypassed exact request binding"
        );
    }
}
