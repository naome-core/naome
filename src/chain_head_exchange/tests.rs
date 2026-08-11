use std::fs;

use naome_chain::{AddressedProofCandidate, ProofBlockId, ProofChainId, ProofChainState, ProofDag};
use naome_foundation::ZfcAxiom;
use naome_storage::ProofChainJournal;

use super::{
    PROOF_CHAIN_HEAD_REQUEST_BYTES, PROOF_CHAIN_HEAD_RESPONSE_BYTES,
    ProofChainHeadExchangeWireError, ProofChainHeadRequest, ProofChainHeadResponse,
    proof_chain_head_response,
};
use crate::tests::{TestDirectory, axiom_bytes};

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

#[test]
fn serving_is_chain_exact_read_only_and_survives_replay() {
    let directory = TestDirectory::new("proof-chain-head-exchange");
    let chain_id = ProofChainId::from_bytes([0x51; 32]);
    let other_chain_id = ProofChainId::from_bytes([0x52; 32]);
    let matching = ProofChainHeadRequest::new(chain_id);
    let mismatched = ProofChainHeadRequest::new(other_chain_id);
    let mut journal = ProofChainJournal::create(directory.path(), chain_id).unwrap();
    let genesis = ProofChainState::new(chain_id).head_block_id();
    let journal_path = directory.path().join("proof-chain.journal");
    let empty_image = fs::read(&journal_path).unwrap();

    assert_eq!(journal.chain_id(), chain_id);
    let empty = proof_chain_head_response(&journal, matching).unwrap();
    assert_eq!(empty.head_block_id(), Some(genesis));
    assert!(!empty.is_unavailable());
    assert!(
        proof_chain_head_response(&journal, mismatched)
            .unwrap()
            .is_unavailable()
    );
    assert_eq!(fs::read(&journal_path).unwrap(), empty_image);

    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let proof_id = ProofDag::new()
        .apply_canonical_proof_bytes(payload.clone())
        .unwrap()
        .proof_id();
    let block = journal.prepare_block(vec![proof_id]).unwrap();
    journal
        .apply_block(
            &block,
            vec![AddressedProofCandidate::new(proof_id, payload)],
        )
        .unwrap();
    let committed_image = fs::read(&journal_path).unwrap();

    assert_eq!(
        proof_chain_head_response(&journal, matching)
            .unwrap()
            .head_block_id(),
        Some(block.id())
    );
    assert_eq!(fs::read(&journal_path).unwrap(), committed_image);
    drop(journal);

    let reopened = ProofChainJournal::open(directory.path(), chain_id).unwrap();
    assert_eq!(reopened.chain_id(), chain_id);
    assert_eq!(
        proof_chain_head_response(&reopened, matching)
            .unwrap()
            .head_block_id(),
        Some(block.id())
    );
    assert_eq!(fs::read(journal_path).unwrap(), committed_image);
}
