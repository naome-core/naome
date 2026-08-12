use naome_chain::{ProofBlockId, ProofChainId};

use super::{
    PROOF_CHAIN_HEAD_REQUEST_BYTES, PROOF_CHAIN_HEAD_RESPONSE_BYTES,
    ProofChainHeadExchangeWireError, ProofChainHeadRequest, ProofChainHeadResponse,
};

#[test]
fn request_is_exactly_one_raw_chain_id() {
    let chain_id = ProofChainId::from_bytes([0x31; PROOF_CHAIN_HEAD_REQUEST_BYTES]);
    let request = ProofChainHeadRequest::new(chain_id);
    assert_eq!(request.chain_id(), chain_id);
    assert_eq!(request.to_wire_bytes(), *chain_id.as_bytes());
    assert_eq!(
        ProofChainHeadRequest::from_wire_bytes(chain_id.as_bytes()).unwrap(),
        request
    );

    for actual in 0..PROOF_CHAIN_HEAD_REQUEST_BYTES {
        assert_eq!(
            ProofChainHeadRequest::from_wire_bytes(&chain_id.as_bytes()[..actual]),
            Err(ProofChainHeadExchangeWireError::InvalidRequestLength {
                actual,
                expected: PROOF_CHAIN_HEAD_REQUEST_BYTES,
            })
        );
    }
    let mut extended = chain_id.as_bytes().to_vec();
    extended.push(0xff);
    assert_eq!(
        ProofChainHeadRequest::from_wire_bytes(&extended),
        Err(ProofChainHeadExchangeWireError::InvalidRequestLength {
            actual: PROOF_CHAIN_HEAD_REQUEST_BYTES + 1,
            expected: PROOF_CHAIN_HEAD_REQUEST_BYTES,
        })
    );
}

#[test]
fn response_is_only_empty_or_one_raw_block_id() {
    let unavailable = ProofChainHeadResponse::from_wire_bytes(&[]).unwrap();
    assert!(unavailable.is_unavailable());
    assert_eq!(unavailable.head_block_id(), None);
    assert_eq!(unavailable.to_wire_bytes(), None);

    let head = ProofBlockId::from_bytes([0x42; PROOF_CHAIN_HEAD_RESPONSE_BYTES]);
    let found = ProofChainHeadResponse::from_wire_bytes(head.as_bytes()).unwrap();
    assert!(!found.is_unavailable());
    assert_eq!(found.head_block_id(), Some(head));
    assert_eq!(found.to_wire_bytes(), Some(*head.as_bytes()));

    let invalid = [0_u8; PROOF_CHAIN_HEAD_RESPONSE_BYTES + 1];
    for actual in 1..=invalid.len() {
        if actual == PROOF_CHAIN_HEAD_RESPONSE_BYTES {
            continue;
        }
        assert_eq!(
            ProofChainHeadResponse::from_wire_bytes(&invalid[..actual]),
            Err(ProofChainHeadExchangeWireError::InvalidResponseLength { actual })
        );
    }
}
