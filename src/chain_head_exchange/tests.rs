use naome_chain::{ArtifactBlockId, ArtifactChainId};

use super::{
    ARTIFACT_CHAIN_HEAD_REQUEST_BYTES, ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES,
    ArtifactChainHeadExchangeWireError, ArtifactChainHeadRequest, ArtifactChainHeadResponse,
};

#[test]
fn request_is_exactly_one_raw_chain_id() {
    let chain_id = ArtifactChainId::from_bytes([0x31; ARTIFACT_CHAIN_HEAD_REQUEST_BYTES]);
    let request = ArtifactChainHeadRequest::new(chain_id);
    assert_eq!(request.chain_id(), chain_id);
    assert_eq!(request.to_wire_bytes(), *chain_id.as_bytes());
    assert_eq!(
        ArtifactChainHeadRequest::from_wire_bytes(chain_id.as_bytes()).unwrap(),
        request
    );

    for actual in 0..ARTIFACT_CHAIN_HEAD_REQUEST_BYTES {
        assert_eq!(
            ArtifactChainHeadRequest::from_wire_bytes(&chain_id.as_bytes()[..actual]),
            Err(ArtifactChainHeadExchangeWireError::InvalidRequestLength {
                actual,
                expected: ARTIFACT_CHAIN_HEAD_REQUEST_BYTES,
            })
        );
    }
    let mut extended = chain_id.as_bytes().to_vec();
    extended.push(0xff);
    assert_eq!(
        ArtifactChainHeadRequest::from_wire_bytes(&extended),
        Err(ArtifactChainHeadExchangeWireError::InvalidRequestLength {
            actual: ARTIFACT_CHAIN_HEAD_REQUEST_BYTES + 1,
            expected: ARTIFACT_CHAIN_HEAD_REQUEST_BYTES,
        })
    );
}

#[test]
fn response_is_only_empty_or_one_raw_block_id() {
    let unavailable = ArtifactChainHeadResponse::from_wire_bytes(&[]).unwrap();
    assert!(unavailable.is_unavailable());
    assert_eq!(unavailable.head_block_id(), None);
    assert_eq!(unavailable.to_wire_bytes(), None);

    let head = ArtifactBlockId::from_bytes([0x42; ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES]);
    let found = ArtifactChainHeadResponse::from_wire_bytes(head.as_bytes()).unwrap();
    assert!(!found.is_unavailable());
    assert_eq!(found.head_block_id(), Some(head));
    assert_eq!(found.to_wire_bytes(), Some(*head.as_bytes()));

    let invalid = [0_u8; ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES + 1];
    for actual in 1..=invalid.len() {
        if actual == ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES {
            continue;
        }
        assert_eq!(
            ArtifactChainHeadResponse::from_wire_bytes(&invalid[..actual]),
            Err(ArtifactChainHeadExchangeWireError::InvalidResponseLength { actual })
        );
    }
}
