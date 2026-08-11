use super::*;
use crate::{PROOF_BATCH_MAX_CANDIDATES, ProofSetRoot};

const CHAIN_BYTE: u8 = 0x11;
const PREVIOUS_ROOT_BYTE: u8 = 0x22;
const RESULTING_ROOT_BYTE: u8 = 0x33;

fn proof_id(byte: u8) -> ProofId {
    ProofId::from_bytes([byte; 32])
}

fn transition(count: usize) -> ProofTransition {
    ProofTransition::new(
        ProofSetRoot::from_bytes([PREVIOUS_ROOT_BYTE; 32]),
        ProofSetRoot::from_bytes([RESULTING_ROOT_BYTE; 32]),
        (0..count)
            .map(|index| proof_id(u8::try_from(0x44 + index).unwrap()))
            .collect(),
    )
    .unwrap()
}

fn chain() -> ProofChainState {
    ProofChainState::new(ProofChainId::from_bytes([CHAIN_BYTE; 32]))
}

#[test]
fn virtual_genesis_parent_and_first_block_match_fixed_goldens() {
    let chain_id = ProofChainId::from_bytes([CHAIN_BYTE; 32]);
    let chain = ProofChainState::new(chain_id);
    let expected_genesis = ProofBlockId::from_bytes([
        0xf4, 0x7e, 0xe4, 0xac, 0xce, 0x1f, 0x57, 0x97, 0xff, 0x77, 0x3e, 0x7b, 0x62, 0x0c, 0xfc,
        0x66, 0xb1, 0x01, 0xdf, 0xad, 0xb0, 0xb8, 0x7c, 0xb4, 0xf8, 0x3e, 0x3b, 0x94, 0x76, 0x5c,
        0x8b, 0x98,
    ]);
    let expected_block_id = ProofBlockId::from_bytes([
        0x9b, 0x1d, 0xba, 0xde, 0x53, 0x00, 0xbb, 0xb3, 0x6e, 0x1b, 0x12, 0x62, 0x26, 0xdc, 0x94,
        0x03, 0x95, 0xd7, 0xcc, 0xd7, 0x42, 0xa2, 0xbd, 0x7a, 0x8d, 0x6f, 0x7c, 0xbb, 0x95, 0x43,
        0x23, 0x7f,
    ]);

    assert_eq!(chain.head_block_id(), expected_genesis);
    assert_eq!(ProofChainId::from_bytes(*chain_id.as_bytes()), chain_id);
    assert_eq!(
        ProofBlockId::from_bytes(*expected_genesis.as_bytes()),
        expected_genesis
    );

    let golden_transition = ProofTransition::new(
        ProofSetRoot::from_bytes([0x11; 32]),
        ProofSetRoot::from_bytes([0x22; 32]),
        vec![proof_id(0x33), proof_id(0x44)],
    )
    .unwrap();
    let block = ProofBlock::new(expected_genesis, golden_transition);
    let mut expected_bytes = Vec::with_capacity(161);
    expected_bytes.extend_from_slice(expected_genesis.as_bytes());
    expected_bytes.extend_from_slice(&[0x11; 32]);
    expected_bytes.extend_from_slice(&[0x22; 32]);
    expected_bytes.push(2);
    expected_bytes.extend_from_slice(&[0x33; 32]);
    expected_bytes.extend_from_slice(&[0x44; 32]);

    assert_eq!(expected_bytes.len(), 161);
    assert_eq!(block.to_canonical_bytes(), expected_bytes);
    assert_eq!(block.id(), expected_block_id);
    assert_eq!(block.parent_block_id(), expected_genesis);
    assert_eq!(
        block.transition().proof_ids(),
        [proof_id(0x33), proof_id(0x44)]
    );
    assert_eq!(
        ProofBlock::from_canonical_bytes(&block.to_canonical_bytes()),
        Ok(block.clone())
    );
    assert_eq!(
        ProofBlockId::from_bytes(*expected_block_id.as_bytes()),
        expected_block_id
    );
}

#[test]
fn every_valid_size_round_trips_and_every_prefix_is_truncated() {
    let parent = chain().head_block_id();

    for count in 1..=PROOF_BATCH_MAX_CANDIDATES {
        let block = ProofBlock::new(parent, transition(count));
        let bytes = block.to_canonical_bytes();
        assert_eq!(bytes.len(), 32 + 65 + count * 32);

        for end in 0..bytes.len() {
            let expected = if end < BLOCK_ID_BYTES {
                ProofBlockDecodeError::UnexpectedEnd
            } else {
                ProofBlockDecodeError::Transition {
                    source: ProofTransitionError::UnexpectedEnd,
                }
            };
            assert_eq!(
                ProofBlock::from_canonical_bytes(&bytes[..end]),
                Err(expected),
                "count {count}, prefix length {end}"
            );
        }

        assert_eq!(ProofBlock::from_canonical_bytes(&bytes), Ok(block));
    }

    assert_eq!(PROOF_BLOCK_MAX_BYTES, 353);
    assert_eq!(
        ProofBlock::new(parent, transition(PROOF_BATCH_MAX_CANDIDATES))
            .to_canonical_bytes()
            .len(),
        PROOF_BLOCK_MAX_BYTES
    );
}

#[test]
fn trailing_bytes_and_absolute_limit_have_stable_precedence() {
    let parent = chain().head_block_id();
    let mut bytes = ProofBlock::new(parent, transition(1)).to_canonical_bytes();
    let canonical_len = bytes.len();
    bytes.resize(PROOF_BLOCK_MAX_BYTES, 0xaa);

    assert_eq!(
        ProofBlock::from_canonical_bytes(&bytes),
        Err(ProofBlockDecodeError::Transition {
            source: ProofTransitionError::TrailingBytes {
                remaining: PROOF_BLOCK_MAX_BYTES - canonical_len,
            },
        })
    );

    bytes.push(0xbb);
    assert_eq!(
        ProofBlock::from_canonical_bytes(&bytes),
        Err(ProofBlockDecodeError::InputTooLong {
            actual: PROOF_BLOCK_MAX_BYTES + 1,
            maximum: PROOF_BLOCK_MAX_BYTES,
        })
    );
}

#[test]
fn invalid_transition_counts_remain_nested_decode_errors() {
    let parent = chain().head_block_id();
    let mut bytes = Vec::with_capacity(97);
    bytes.extend_from_slice(parent.as_bytes());
    bytes.extend_from_slice(&[PREVIOUS_ROOT_BYTE; 32]);
    bytes.extend_from_slice(&[RESULTING_ROOT_BYTE; 32]);
    bytes.push(0);

    assert_eq!(
        ProofBlock::from_canonical_bytes(&bytes),
        Err(ProofBlockDecodeError::Transition {
            source: ProofTransitionError::Empty,
        })
    );

    *bytes.last_mut().unwrap() = u8::try_from(PROOF_BATCH_MAX_CANDIDATES + 1).unwrap();
    assert_eq!(
        ProofBlock::from_canonical_bytes(&bytes),
        Err(ProofBlockDecodeError::Transition {
            source: ProofTransitionError::TooManyProofs {
                actual: PROOF_BATCH_MAX_CANDIDATES + 1,
                maximum: PROOF_BATCH_MAX_CANDIDATES,
            },
        })
    );
}

#[test]
fn every_parent_root_and_proof_id_byte_is_identity_bearing() {
    let original = ProofBlock::new(chain().head_block_id(), transition(1));
    let original_id = original.id();
    let bytes = original.to_canonical_bytes();
    let count_offset = BLOCK_ID_BYTES + 32 + 32;

    for index in 0..bytes.len() {
        if index == count_offset {
            continue;
        }
        let mut mutated = bytes.clone();
        mutated[index] ^= 0x01;
        let decoded = ProofBlock::from_canonical_bytes(&mutated)
            .unwrap_or_else(|error| panic!("byte {index} produced {error:?}"));
        assert_ne!(decoded.id(), original_id, "byte {index}");
    }

    let different_count = ProofBlock::new(original.parent_block_id(), transition(2));
    assert_ne!(different_count.id(), original_id);

    let other_chain = ProofChainState::new(ProofChainId::from_bytes([CHAIN_BYTE + 1; 32]));
    assert_ne!(other_chain.head_block_id(), original.parent_block_id());
    assert_ne!(
        ProofBlock::new(other_chain.head_block_id(), transition(1)).id(),
        original_id
    );
}
