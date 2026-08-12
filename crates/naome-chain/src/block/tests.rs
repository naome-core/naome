use super::*;
use crate::{PROOF_BATCH_MAX_CANDIDATES, ProofSetRoot};

const CHAIN_BYTE: u8 = 0x11;
const PREVIOUS_ROOT_BYTE: u8 = 0x22;
const RESULTING_ROOT_BYTE: u8 = 0x33;

const DEFINITION_BYTES: [u8; 73] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x6e, 0x61, 0x6f, 0x6d, 0x65, 0x3a, 0x7a, 0x66, 0x63, 0xe9, 0xa9, 0x80, 0x28, 0x7e, 0x77, 0x0a,
    0xc3, 0x89, 0xd3, 0x73, 0x5f, 0xf0, 0x64, 0xe7, 0x44, 0x7f, 0x11, 0xc9, 0x64, 0x0e, 0xfd, 0xb9,
    0x0b, 0x91, 0x78, 0x17, 0x66, 0x49, 0x7f, 0x16, 0xca,
];
const DEFINITION_ID: [u8; 32] = [
    0x71, 0x74, 0xca, 0xe8, 0x6b, 0x0c, 0xd1, 0x8e, 0x23, 0x64, 0x80, 0x5d, 0x1b, 0xb8, 0xda, 0x7a,
    0x34, 0x26, 0x2f, 0x3e, 0xfa, 0x6f, 0x5e, 0x2b, 0x72, 0x3e, 0xc6, 0x61, 0x2a, 0x9e, 0xc1, 0x5e,
];
const VIRTUAL_GENESIS: [u8; 32] = [
    0x71, 0xca, 0x84, 0xdc, 0xea, 0xe5, 0x1f, 0xd2, 0x33, 0x11, 0xeb, 0x1d, 0x79, 0xfc, 0x97, 0x22,
    0x3d, 0xba, 0x62, 0x82, 0x1d, 0x60, 0x4c, 0xd6, 0xf4, 0xd5, 0x70, 0x10, 0x34, 0xc5, 0xf6, 0x2d,
];

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

fn definition(byte: u8) -> ProofChainDefinition {
    ProofChainDefinition::new([byte; 32])
}

fn chain() -> ProofChainState {
    ProofChainState::new(definition(CHAIN_BYTE))
}

#[test]
fn definition_identity_virtual_genesis_and_first_block_match_fixed_goldens() {
    let definition = definition(CHAIN_BYTE);
    let expected_chain_id = ProofChainId::from_bytes(DEFINITION_ID);
    let expected_genesis = ProofBlockId::from_bytes(VIRTUAL_GENESIS);
    let chain = ProofChainState::new(definition);
    let expected_block_id = ProofBlockId::from_bytes([
        0x47, 0x49, 0x83, 0xa0, 0x16, 0xeb, 0xf4, 0x66, 0x48, 0x8b, 0x63, 0x44, 0x85, 0xb9, 0xe6,
        0xe9, 0x3f, 0x16, 0x29, 0xbf, 0x3d, 0x0a, 0xfa, 0x5a, 0xfa, 0x56, 0x18, 0xf2, 0xe0, 0x4a,
        0x70, 0xf4,
    ]);

    assert_eq!(ProofChainDefinition::BYTE_LENGTH, DEFINITION_BYTES.len());
    assert_eq!(definition.to_canonical_bytes(), DEFINITION_BYTES);
    assert_eq!(definition.deployment_discriminator(), &[CHAIN_BYTE; 32]);
    assert_eq!(
        ProofChainDefinition::from_canonical_bytes(&DEFINITION_BYTES),
        Ok(definition)
    );
    assert_eq!(definition.id(), expected_chain_id);
    assert_eq!(chain.chain_id(), expected_chain_id);
    assert_eq!(chain.head_block_id(), expected_genesis);
    assert_eq!(
        expected_chain_id.virtual_genesis_block_id(),
        expected_genesis
    );
    assert_eq!(
        ProofChainId::from_bytes(*expected_chain_id.as_bytes()),
        expected_chain_id
    );
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
fn definition_decoder_is_exact_and_fixed_field_errors_have_stable_precedence() {
    for actual in 0..ProofChainDefinition::BYTE_LENGTH {
        assert_eq!(
            ProofChainDefinition::from_canonical_bytes(&DEFINITION_BYTES[..actual]),
            Err(ProofChainDefinitionDecodeError::InvalidLength {
                actual,
                expected: ProofChainDefinition::BYTE_LENGTH,
            }),
            "prefix length {actual}",
        );
    }

    let mut extended = DEFINITION_BYTES.to_vec();
    for extra in 1..=ProofChainDefinition::BYTE_LENGTH {
        extended.push(0xff);
        let actual = ProofChainDefinition::BYTE_LENGTH + extra;
        assert_eq!(
            ProofChainDefinition::from_canonical_bytes(&extended),
            Err(ProofChainDefinitionDecodeError::InvalidLength {
                actual,
                expected: ProofChainDefinition::BYTE_LENGTH,
            }),
            "extended length {actual}",
        );
    }

    let mut short_with_wrong_fields =
        DEFINITION_BYTES[..ProofChainDefinition::BYTE_LENGTH - 1].to_vec();
    short_with_wrong_fields[32] ^= 0x01;
    short_with_wrong_fields[41] ^= 0x01;
    assert_eq!(
        ProofChainDefinition::from_canonical_bytes(&short_with_wrong_fields),
        Err(ProofChainDefinitionDecodeError::InvalidLength {
            actual: ProofChainDefinition::BYTE_LENGTH - 1,
            expected: ProofChainDefinition::BYTE_LENGTH,
        })
    );
    let mut long_with_wrong_fields = DEFINITION_BYTES.to_vec();
    long_with_wrong_fields[32] ^= 0x01;
    long_with_wrong_fields[41] ^= 0x01;
    long_with_wrong_fields.push(0xff);
    assert_eq!(
        ProofChainDefinition::from_canonical_bytes(&long_with_wrong_fields),
        Err(ProofChainDefinitionDecodeError::InvalidLength {
            actual: ProofChainDefinition::BYTE_LENGTH + 1,
            expected: ProofChainDefinition::BYTE_LENGTH,
        })
    );

    let foundation_start = 32;
    let genesis_root_start = foundation_start + 9;
    for index in foundation_start..genesis_root_start {
        let mut bytes = DEFINITION_BYTES;
        bytes[index] ^= 0x01;
        bytes[genesis_root_start] ^= 0x01;
        assert_eq!(
            ProofChainDefinition::from_canonical_bytes(&bytes),
            Err(ProofChainDefinitionDecodeError::FoundationIdMismatch),
            "Foundation byte {index}",
        );
    }

    let expected_root =
        ProofSetRoot::from_bytes(DEFINITION_BYTES[genesis_root_start..].try_into().unwrap());
    for index in genesis_root_start..ProofChainDefinition::BYTE_LENGTH {
        let mut bytes = DEFINITION_BYTES;
        bytes[index] ^= 0x01;
        let actual = ProofSetRoot::from_bytes(bytes[genesis_root_start..].try_into().unwrap());
        assert_eq!(
            ProofChainDefinition::from_canonical_bytes(&bytes),
            Err(
                ProofChainDefinitionDecodeError::GenesisProofSetRootMismatch {
                    expected: expected_root,
                    actual,
                },
            ),
            "genesis-root byte {index}",
        );
    }
}

#[test]
fn every_discriminator_byte_is_identity_bearing_and_definitions_isolate_state() {
    let original_definition = definition(CHAIN_BYTE);
    let original_id = original_definition.id();
    let original_genesis = original_id.virtual_genesis_block_id();

    for index in 0..32 {
        let mut discriminator = [CHAIN_BYTE; 32];
        discriminator[index] ^= 0x01;
        let mut canonical = DEFINITION_BYTES;
        canonical[index] ^= 0x01;
        let changed_definition = ProofChainDefinition::from_canonical_bytes(&canonical).unwrap();
        assert_eq!(
            changed_definition,
            ProofChainDefinition::new(discriminator),
            "discriminator byte {index}",
        );
        assert_eq!(
            changed_definition.to_canonical_bytes(),
            canonical,
            "discriminator byte {index}",
        );
        let changed_id = changed_definition.id();
        assert_ne!(changed_id, original_id, "discriminator byte {index}");
        assert_ne!(
            changed_id.virtual_genesis_block_id(),
            original_genesis,
            "discriminator byte {index}",
        );
    }

    let mut selected = ProofChainState::new(original_definition);
    let foreign = ProofChainState::new(definition(CHAIN_BYTE + 1));
    let foreign_block = foreign.prepare_block(vec![proof_id(0x55)]).unwrap();
    let original_root = selected.proof_dag().proof_set_root();
    assert!(matches!(
        selected.apply_block(&foreign_block, Vec::new()),
        Err(ProofBlockApplyError::ParentBlockIdMismatch { expected, actual })
            if expected == original_genesis && actual == foreign.head_block_id()
    ));
    assert_eq!(selected.head_block_id(), original_genesis);
    assert_eq!(selected.proof_dag().proof_set_root(), original_root);
    assert!(selected.proof_dag().is_empty());
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

    let other_chain = ProofChainState::new(definition(CHAIN_BYTE + 1));
    assert_ne!(other_chain.head_block_id(), original.parent_block_id());
    assert_ne!(
        ProofBlock::new(other_chain.head_block_id(), transition(1)).id(),
        original_id
    );
}
