use naome_chain::{
    ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockDecodeError, ArtifactBlockId, ArtifactSetRoot,
};
use naome_proof::ArtifactId;

use super::{
    ARTIFACT_BLOCK_REQUEST_BYTES, ARTIFACT_BLOCK_RESPONSE_MAX_BYTES,
    ArtifactBlockExchangeWireError, ArtifactBlockRequest, ArtifactBlockResponse,
};

fn golden_block() -> ArtifactBlock {
    ArtifactBlock::new(
        ArtifactBlockId::from_bytes([
            0x71, 0xca, 0x84, 0xdc, 0xea, 0xe5, 0x1f, 0xd2, 0x33, 0x11, 0xeb, 0x1d, 0x79, 0xfc,
            0x97, 0x22, 0x3d, 0xba, 0x62, 0x82, 0x1d, 0x60, 0x4c, 0xd6, 0xf4, 0xd5, 0x70, 0x10,
            0x34, 0xc5, 0xf6, 0x2d,
        ]),
        ArtifactSetRoot::from_bytes([0x11; 32]),
        ArtifactSetRoot::from_bytes([0x22; 32]),
        ArtifactId::from_bytes([0x33; 32]),
    )
}

#[test]
fn request_is_exactly_one_raw_block_id() {
    let block_id = golden_block().id();
    let request = ArtifactBlockRequest::new(block_id);
    assert_eq!(request.block_id(), block_id);
    assert_eq!(request.to_wire_bytes(), *block_id.as_bytes());
    assert_eq!(
        ArtifactBlockRequest::from_wire_bytes(block_id.as_bytes()).unwrap(),
        request
    );

    for actual in 0..ARTIFACT_BLOCK_REQUEST_BYTES {
        assert_eq!(
            ArtifactBlockRequest::from_wire_bytes(&block_id.as_bytes()[..actual]),
            Err(ArtifactBlockExchangeWireError::InvalidRequestLength {
                actual,
                expected: ARTIFACT_BLOCK_REQUEST_BYTES,
            })
        );
    }
    let mut extended = block_id.as_bytes().to_vec();
    extended.push(0xff);
    assert_eq!(
        ArtifactBlockRequest::from_wire_bytes(&extended),
        Err(ArtifactBlockExchangeWireError::InvalidRequestLength {
            actual: ARTIFACT_BLOCK_REQUEST_BYTES + 1,
            expected: ARTIFACT_BLOCK_REQUEST_BYTES,
        })
    );
}

#[test]
fn unavailable_or_matching_fixed_block_is_the_only_response() {
    let block = golden_block();
    let expected_block_id = ArtifactBlockId::from_bytes([
        0xc7, 0x13, 0x2e, 0x96, 0x14, 0xc3, 0xf1, 0xbc, 0x96, 0x28, 0x86, 0x0e, 0xca, 0xf6, 0xb0,
        0x81, 0x8c, 0x49, 0x57, 0x30, 0x93, 0xe7, 0xea, 0x01, 0x5c, 0x1d, 0xe6, 0x61, 0xc9, 0x3e,
        0x24, 0x0e,
    ]);
    assert_eq!(block.id(), expected_block_id);
    let request = ArtifactBlockRequest::new(expected_block_id);

    let unavailable = ArtifactBlockResponse::from_wire_bytes(request, &[]).unwrap();
    assert!(unavailable.is_unavailable());
    assert!(unavailable.to_wire_bytes().is_empty());
    assert_eq!(unavailable.into_block(), None);

    let bytes = block.to_canonical_bytes();
    assert_eq!(bytes.len(), ARTIFACT_BLOCK_BYTES);
    let found = ArtifactBlockResponse::from_wire_bytes(request, &bytes).unwrap();
    assert!(!found.is_unavailable());
    assert_eq!(found.to_wire_bytes(), bytes);
    assert_eq!(found.into_block(), Some(block));
}

#[test]
fn response_length_decode_and_identity_checks_have_stable_precedence() {
    assert_eq!(ARTIFACT_BLOCK_RESPONSE_MAX_BYTES, ARTIFACT_BLOCK_BYTES);
    let block = golden_block();
    let request = ArtifactBlockRequest::new(block.id());

    let oversized = [0; ARTIFACT_BLOCK_RESPONSE_MAX_BYTES + 1];
    assert_eq!(
        ArtifactBlockResponse::from_wire_bytes(request, &oversized).unwrap_err(),
        ArtifactBlockExchangeWireError::ResponseTooLong {
            actual: ARTIFACT_BLOCK_RESPONSE_MAX_BYTES + 1,
            maximum: ARTIFACT_BLOCK_RESPONSE_MAX_BYTES,
        }
    );
    assert_eq!(
        ArtifactBlockResponse::from_wire_bytes(request, &[0]).unwrap_err(),
        ArtifactBlockExchangeWireError::BlockDecode {
            source: ArtifactBlockDecodeError::InvalidLength {
                actual: 1,
                expected: ARTIFACT_BLOCK_BYTES,
            },
        }
    );

    let mut substituted = block.to_canonical_bytes();
    substituted[0] ^= 1;
    let substituted_block = ArtifactBlock::from_canonical_bytes(&substituted).unwrap();
    assert_eq!(
        ArtifactBlockResponse::from_wire_bytes(request, &substituted).unwrap_err(),
        ArtifactBlockExchangeWireError::BlockIdMismatch {
            expected: block.id(),
            actual: substituted_block.id(),
        }
    );
}

#[test]
fn every_fixed_block_byte_is_request_identity_bearing() {
    let block = golden_block();
    let request = ArtifactBlockRequest::new(block.id());
    let bytes = block.to_canonical_bytes();

    for index in 0..bytes.len() {
        let mut mutated = bytes;
        mutated[index] ^= 1;
        assert!(
            matches!(
                ArtifactBlockResponse::from_wire_bytes(request, &mutated),
                Err(ArtifactBlockExchangeWireError::BlockIdMismatch { .. })
            ),
            "mutated response byte {index} bypassed exact request binding"
        );
    }
}
