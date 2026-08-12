use naome_chain::{
    PROOF_BATCH_MAX_CANDIDATES, PROOF_BLOCK_MAX_BYTES, ProofBlock, ProofBlockDecodeError,
    ProofBlockId, ProofSetRoot, ProofTransition, ProofTransitionError,
};
use naome_proof::ProofId;

use super::{
    PROOF_BLOCK_REQUEST_BYTES, PROOF_BLOCK_RESPONSE_MAX_BYTES, ProofBlockExchangeWireError,
    ProofBlockRequest, ProofBlockResponse,
};

fn proof_id(byte: u8) -> ProofId {
    ProofId::from_bytes([byte; 32])
}

fn transition(count: usize) -> ProofTransition {
    ProofTransition::new(
        ProofSetRoot::from_bytes([0x11; 32]),
        ProofSetRoot::from_bytes([0x22; 32]),
        (0..count)
            .map(|index| proof_id(u8::try_from(0x33 + index).unwrap()))
            .collect(),
    )
    .unwrap()
}

fn golden_block() -> ProofBlock {
    let virtual_genesis = ProofBlockId::from_bytes([
        0x71, 0xca, 0x84, 0xdc, 0xea, 0xe5, 0x1f, 0xd2, 0x33, 0x11, 0xeb, 0x1d, 0x79, 0xfc, 0x97,
        0x22, 0x3d, 0xba, 0x62, 0x82, 0x1d, 0x60, 0x4c, 0xd6, 0xf4, 0xd5, 0x70, 0x10, 0x34, 0xc5,
        0xf6, 0x2d,
    ]);
    let transition = ProofTransition::new(
        ProofSetRoot::from_bytes([0x11; 32]),
        ProofSetRoot::from_bytes([0x22; 32]),
        vec![proof_id(0x33), proof_id(0x44)],
    )
    .unwrap();
    ProofBlock::new(virtual_genesis, transition)
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
fn unavailable_or_matching_canonical_block_is_the_only_response() {
    let block = golden_block();
    let expected_block_id = ProofBlockId::from_bytes([
        0x47, 0x49, 0x83, 0xa0, 0x16, 0xeb, 0xf4, 0x66, 0x48, 0x8b, 0x63, 0x44, 0x85, 0xb9, 0xe6,
        0xe9, 0x3f, 0x16, 0x29, 0xbf, 0x3d, 0x0a, 0xfa, 0x5a, 0xfa, 0x56, 0x18, 0xf2, 0xe0, 0x4a,
        0x70, 0xf4,
    ]);
    assert_eq!(block.id(), expected_block_id);
    let request = ProofBlockRequest::new(expected_block_id);

    let unavailable = ProofBlockResponse::from_wire_bytes(request, &[]).unwrap();
    assert!(unavailable.is_unavailable());
    assert!(unavailable.to_wire_bytes().is_empty());
    assert_eq!(unavailable.into_block(), None);

    let bytes = block.to_canonical_bytes();
    assert_eq!(bytes.len(), 161);
    let found = ProofBlockResponse::from_wire_bytes(request, &bytes).unwrap();
    assert!(!found.is_unavailable());
    assert_eq!(found.to_wire_bytes(), bytes);
    assert_eq!(found.into_block(), Some(block));
}

#[test]
fn response_length_decode_and_identity_checks_have_stable_precedence() {
    assert_eq!(PROOF_BLOCK_RESPONSE_MAX_BYTES, PROOF_BLOCK_MAX_BYTES);

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
            source: ProofBlockDecodeError::UnexpectedEnd,
        }
    );

    let mut trailing = ProofBlock::new(block.parent_block_id(), transition(1)).to_canonical_bytes();
    trailing.push(0xff);
    assert_eq!(
        ProofBlockResponse::from_wire_bytes(request, &trailing).unwrap_err(),
        ProofBlockExchangeWireError::BlockDecode {
            source: ProofBlockDecodeError::Transition {
                source: ProofTransitionError::TrailingBytes { remaining: 1 },
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
fn every_canonical_response_size_reaches_identity_validation() {
    let parent = golden_block().parent_block_id();
    for count in 1..=PROOF_BATCH_MAX_CANDIDATES {
        let block = ProofBlock::new(parent, transition(count));
        let bytes = block.to_canonical_bytes();
        assert_eq!(bytes.len(), 97 + count * 32);
        assert_eq!(
            ProofBlockResponse::from_wire_bytes(ProofBlockRequest::new(block.id()), &bytes)
                .unwrap()
                .into_block(),
            Some(block)
        );
    }
}

#[test]
fn every_maximum_block_byte_is_decode_or_request_identity_bearing() {
    let block = ProofBlock::new(
        golden_block().parent_block_id(),
        transition(PROOF_BATCH_MAX_CANDIDATES),
    );
    let request = ProofBlockRequest::new(block.id());
    let bytes = block.to_canonical_bytes();
    assert_eq!(bytes.len(), PROOF_BLOCK_RESPONSE_MAX_BYTES);

    for index in 0..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[index] ^= 1;
        assert!(
            matches!(
                ProofBlockResponse::from_wire_bytes(request, &mutated),
                Err(ProofBlockExchangeWireError::BlockDecode { .. }
                    | ProofBlockExchangeWireError::BlockIdMismatch { .. })
            ),
            "mutated response byte {index} bypassed exact request binding"
        );
    }
}
