use naome_chain::{
    AddressedProofCandidate, PROOF_BATCH_MAX_CANDIDATES, PROOF_BLOCK_MAX_BYTES, ProofBlock,
    ProofBlockDecodeError, ProofBlockId, ProofChainId, ProofDag, ProofSetRoot, ProofTransition,
    ProofTransitionError,
};
use naome_foundation::ZfcAxiom;
use naome_proof::ProofId;
use naome_storage::ProofChainJournal;

use super::{
    PROOF_BLOCK_REQUEST_BYTES, PROOF_BLOCK_RESPONSE_MAX_BYTES, ProofBlockExchangeWireError,
    ProofBlockRequest, ProofBlockResponse, proof_block_response,
};
use crate::tests::{TestDirectory, axiom_bytes};

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
        0xf4, 0x7e, 0xe4, 0xac, 0xce, 0x1f, 0x57, 0x97, 0xff, 0x77, 0x3e, 0x7b, 0x62, 0x0c, 0xfc,
        0x66, 0xb1, 0x01, 0xdf, 0xad, 0xb0, 0xb8, 0x7c, 0xb4, 0xf8, 0x3e, 0x3b, 0x94, 0x76, 0x5c,
        0x8b, 0x98,
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
        0x9b, 0x1d, 0xba, 0xde, 0x53, 0x00, 0xbb, 0xb3, 0x6e, 0x1b, 0x12, 0x62, 0x26, 0xdc, 0x94,
        0x03, 0x95, 0xd7, 0xcc, 0xd7, 0x42, 0xa2, 0xbd, 0x7a, 0x8d, 0x6f, 0x7c, 0xbb, 0x95, 0x43,
        0x23, 0x7f,
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

#[test]
fn serving_exposes_only_committed_selected_blocks_and_survives_replay() {
    let directory = TestDirectory::new("proof-block-exchange");
    let chain_id = ProofChainId::from_bytes([0x31; 32]);
    let mut journal = ProofChainJournal::create(directory.path(), chain_id).unwrap();
    let virtual_genesis = journal.head_block_id().unwrap();
    assert!(
        proof_block_response(&journal, ProofBlockRequest::new(virtual_genesis))
            .unwrap()
            .is_none()
    );

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

    assert_eq!(
        proof_block_response(&journal, ProofBlockRequest::new(block.id())).unwrap(),
        Some(&block)
    );
    assert!(
        proof_block_response(
            &journal,
            ProofBlockRequest::new(ProofBlockId::from_bytes([0xa5; 32])),
        )
        .unwrap()
        .is_none()
    );

    drop(journal);
    let reopened = ProofChainJournal::open(directory.path(), chain_id).unwrap();
    assert_eq!(
        proof_block_response(&reopened, ProofBlockRequest::new(block.id())).unwrap(),
        Some(&block)
    );
}
