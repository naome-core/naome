use super::*;

const CHAIN_BYTE: u8 = 0x11;
const CHAIN_ID_BYTES: [u8; 32] = [
    0x33, 0xc9, 0x8c, 0x37, 0xf2, 0xa2, 0xd4, 0x80, 0xe7, 0x9c, 0x10, 0x6e, 0xfc, 0x0f, 0xbe, 0xaa,
    0x9e, 0x11, 0x79, 0xf4, 0x27, 0x4e, 0x42, 0x30, 0x33, 0xcc, 0x77, 0x75, 0xcf, 0x5f, 0x74, 0xb4,
];
const VIRTUAL_GENESIS_BYTES: [u8; 32] = [
    0x11, 0xe7, 0x21, 0x58, 0x8d, 0xde, 0x68, 0x90, 0xed, 0x98, 0x91, 0xc2, 0x82, 0x43, 0xe3, 0xe1,
    0xd6, 0xc6, 0x50, 0x1b, 0x08, 0xb9, 0xdd, 0x2c, 0x68, 0x3c, 0x1d, 0x80, 0x1a, 0x11, 0xe0, 0xe4,
];
const EXPECTED_BLOCK_ID_BYTES: [u8; 32] = [
    0xfb, 0xf9, 0xf0, 0x40, 0x55, 0x29, 0xde, 0xf0, 0xc7, 0x09, 0xf7, 0x5b, 0xd9, 0x60, 0x6b, 0xb4,
    0x73, 0x84, 0xbb, 0xfe, 0x14, 0xc8, 0xcc, 0x2c, 0x16, 0x55, 0xea, 0xaf, 0x17, 0xd6, 0xa9, 0xa4,
];
const DEFINITION_BYTES: [u8; 73] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x6e, 0x61, 0x6f, 0x6d, 0x65, 0x3a, 0x7a, 0x66, 0x63, 0xe9, 0xa9, 0x80, 0x28, 0x7e, 0x77, 0x0a,
    0xc3, 0x89, 0xd3, 0x73, 0x5f, 0xf0, 0x64, 0xe7, 0x44, 0x7f, 0x11, 0xc9, 0x64, 0x0e, 0xfd, 0xb9,
    0x0b, 0x91, 0x78, 0x17, 0x66, 0x49, 0x7f, 0x16, 0xca,
];

fn proof_id(byte: u8) -> ProofId {
    ProofId::from_bytes([byte; 32])
}

fn root(byte: u8) -> ProofSetRoot {
    ProofSetRoot::from_bytes([byte; 32])
}

fn definition(byte: u8) -> ProofChainDefinition {
    ProofChainDefinition::new([byte; 32])
}

fn block() -> ProofBlock {
    let definition = definition(CHAIN_BYTE);
    ProofBlock::new(
        definition.id().virtual_genesis_block_id(),
        root(0x22),
        root(0x33),
        proof_id(0x44),
    )
}

#[test]
fn definition_and_fixed_block_round_trip_exact_fields() {
    let definition = definition(CHAIN_BYTE);
    let chain_id = definition.id();
    let virtual_genesis = chain_id.virtual_genesis_block_id();
    let block = block();
    let bytes = block.to_canonical_bytes();

    assert_eq!(ProofChainDefinition::BYTE_LENGTH, DEFINITION_BYTES.len());
    assert_eq!(definition.to_canonical_bytes(), DEFINITION_BYTES);
    assert_eq!(
        ProofChainDefinition::from_canonical_bytes(&DEFINITION_BYTES),
        Ok(definition)
    );
    assert_eq!(definition.deployment_discriminator(), &[CHAIN_BYTE; 32]);
    assert_eq!(chain_id.as_bytes(), &CHAIN_ID_BYTES);
    assert_eq!(virtual_genesis.as_bytes(), &VIRTUAL_GENESIS_BYTES);
    assert_eq!(block.id().as_bytes(), &EXPECTED_BLOCK_ID_BYTES);
    assert_eq!(
        ProofBlockId::from_bytes(*virtual_genesis.as_bytes()),
        virtual_genesis
    );
    assert_eq!(PROOF_BLOCK_BYTES, 128);
    assert_eq!(bytes.len(), PROOF_BLOCK_BYTES);
    assert_eq!(&bytes[..32], virtual_genesis.as_bytes());
    assert_eq!(&bytes[32..64], root(0x22).as_bytes());
    assert_eq!(&bytes[64..96], root(0x33).as_bytes());
    assert_eq!(&bytes[96..], proof_id(0x44).as_bytes());
    assert_eq!(ProofBlock::from_canonical_bytes(&bytes), Ok(block));
    assert_eq!(block.parent_block_id(), virtual_genesis);
    assert_eq!(block.previous_proof_set_root(), root(0x22));
    assert_eq!(block.resulting_proof_set_root(), root(0x33));
    assert_eq!(block.proof_id(), proof_id(0x44));
    assert_eq!(ProofBlockId::from_bytes(*block.id().as_bytes()), block.id());
}

#[test]
fn definition_decoder_is_exact_and_fixed_field_errors_have_stable_precedence() {
    for actual in 0..ProofChainDefinition::BYTE_LENGTH {
        assert_eq!(
            ProofChainDefinition::from_canonical_bytes(&DEFINITION_BYTES[..actual]),
            Err(ProofChainDefinitionDecodeError::InvalidLength {
                actual,
                expected: ProofChainDefinition::BYTE_LENGTH,
            })
        );
    }

    let mut extended = DEFINITION_BYTES.to_vec();
    extended.push(0xff);
    assert_eq!(
        ProofChainDefinition::from_canonical_bytes(&extended),
        Err(ProofChainDefinitionDecodeError::InvalidLength {
            actual: ProofChainDefinition::BYTE_LENGTH + 1,
            expected: ProofChainDefinition::BYTE_LENGTH,
        })
    );

    let foundation_start = DEPLOYMENT_DISCRIMINATOR_BYTES;
    let genesis_root_start = foundation_start + FOUNDATION_ID_BYTES;
    let mut wrong_foundation = DEFINITION_BYTES;
    wrong_foundation[foundation_start] ^= 1;
    wrong_foundation[genesis_root_start] ^= 1;
    assert_eq!(
        ProofChainDefinition::from_canonical_bytes(&wrong_foundation),
        Err(ProofChainDefinitionDecodeError::FoundationIdMismatch)
    );

    let mut wrong_root = DEFINITION_BYTES;
    wrong_root[genesis_root_start] ^= 1;
    assert_eq!(
        ProofChainDefinition::from_canonical_bytes(&wrong_root),
        Err(
            ProofChainDefinitionDecodeError::GenesisProofSetRootMismatch {
                expected: ProofSetRoot::empty(),
                actual: ProofSetRoot::from_bytes(
                    wrong_root[genesis_root_start..].try_into().unwrap()
                ),
            }
        )
    );
}

#[test]
fn every_definition_discriminator_byte_is_identity_bearing() {
    let original = definition(CHAIN_BYTE);
    let original_id = original.id();
    let original_genesis = original_id.virtual_genesis_block_id();

    for index in 0..DEPLOYMENT_DISCRIMINATOR_BYTES {
        let mut bytes = original.to_canonical_bytes();
        bytes[index] ^= 1;
        let mutated = ProofChainDefinition::from_canonical_bytes(&bytes).unwrap();
        assert_ne!(mutated.id(), original_id);
        assert_ne!(mutated.id().virtual_genesis_block_id(), original_genesis);
    }
}

#[test]
fn fixed_block_decoder_rejects_every_other_length() {
    let bytes = block().to_canonical_bytes();
    for actual in 0..PROOF_BLOCK_BYTES {
        assert_eq!(
            ProofBlock::from_canonical_bytes(&bytes[..actual]),
            Err(ProofBlockDecodeError::InvalidLength {
                actual,
                expected: PROOF_BLOCK_BYTES,
            })
        );
    }

    let mut extended = bytes.to_vec();
    for extra in 1..=PROOF_BLOCK_BYTES {
        extended.push(0xff);
        assert_eq!(
            ProofBlock::from_canonical_bytes(&extended),
            Err(ProofBlockDecodeError::InvalidLength {
                actual: PROOF_BLOCK_BYTES + extra,
                expected: PROOF_BLOCK_BYTES,
            })
        );
    }
}

#[test]
fn every_parent_root_and_proof_byte_changes_block_identity() {
    let original = block();
    let original_id = original.id();
    let encoded = original.to_canonical_bytes();

    for index in 0..PROOF_BLOCK_BYTES {
        let mut mutated = encoded;
        mutated[index] ^= 1;
        let mutated = ProofBlock::from_canonical_bytes(&mutated).unwrap();
        assert_ne!(mutated.id(), original_id, "byte {index}");
    }
}

#[test]
fn chain_definition_domain_is_single_proof_block_specific() {
    let definition = definition(CHAIN_BYTE);
    let mut legacy = Sha256::new();
    legacy.update(b"naome:proof-chain-definition\0");
    legacy.update(definition.to_canonical_bytes());
    let legacy_id: [u8; 32] = legacy.finalize().into();
    assert_ne!(definition.id().as_bytes(), &legacy_id);
}
