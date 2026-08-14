use super::*;

const CHAIN_BYTE: u8 = 0x11;
const CHAIN_ID_BYTES: [u8; 32] = [
    0x10, 0x07, 0xf2, 0x12, 0x01, 0x5c, 0xb2, 0xd5, 0xbd, 0x3e, 0x58, 0xe9, 0x3f, 0xb0, 0x94, 0x1e,
    0x6d, 0xbb, 0x84, 0x96, 0xbf, 0x36, 0x69, 0x09, 0x33, 0x03, 0xcf, 0x65, 0xd3, 0x89, 0x5d, 0xe0,
];
const VIRTUAL_GENESIS_BYTES: [u8; 32] = [
    0x31, 0xca, 0x05, 0x2e, 0x8c, 0x26, 0x60, 0xd9, 0x8d, 0x4e, 0xb0, 0x58, 0x6a, 0xdc, 0x38, 0x87,
    0x02, 0x84, 0x1c, 0xf3, 0x1a, 0x92, 0x4c, 0x4c, 0x35, 0x63, 0xdf, 0xc9, 0x20, 0xd2, 0x85, 0x0c,
];
const EXPECTED_BLOCK_ID_BYTES: [u8; 32] = [
    0x13, 0xd7, 0x56, 0x59, 0x3f, 0xe0, 0x6f, 0x15, 0xe2, 0x2f, 0x7e, 0x0b, 0x55, 0xd6, 0x03, 0x7f,
    0x38, 0xaf, 0x73, 0x04, 0xaa, 0x5c, 0xe0, 0x6a, 0xcc, 0x9b, 0x8f, 0x83, 0x3c, 0x86, 0x70, 0x7d,
];
const DEFINITION_BYTES: [u8; 73] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x6e, 0x61, 0x6f, 0x6d, 0x65, 0x3a, 0x7a, 0x66, 0x63, 0x97, 0x6e, 0x57, 0x6e, 0xc6, 0x14, 0x5d,
    0x57, 0xb5, 0xe1, 0x92, 0xd1, 0xc3, 0x7a, 0x09, 0x38, 0xbb, 0x5c, 0x76, 0x66, 0x35, 0x32, 0xd0,
    0x35, 0x4f, 0xcd, 0x98, 0xba, 0x3f, 0xbf, 0x59, 0x7a,
];

fn artifact_id(byte: u8) -> ArtifactId {
    ArtifactId::from_bytes([byte; 32])
}

fn root(byte: u8) -> ArtifactSetRoot {
    ArtifactSetRoot::from_bytes([byte; 32])
}

fn definition(byte: u8) -> ArtifactChainDefinition {
    ArtifactChainDefinition::new([byte; 32])
}

fn block() -> ArtifactBlock {
    let definition = definition(CHAIN_BYTE);
    ArtifactBlock::new(
        definition.id().virtual_genesis_block_id(),
        root(0x22),
        root(0x33),
        artifact_id(0x44),
    )
}

#[test]
fn definition_and_fixed_block_round_trip_exact_fields() {
    let definition = definition(CHAIN_BYTE);
    let chain_id = definition.id();
    let virtual_genesis = chain_id.virtual_genesis_block_id();
    let block = block();
    let bytes = block.to_canonical_bytes();

    assert_eq!(ArtifactChainDefinition::BYTE_LENGTH, DEFINITION_BYTES.len());
    assert_eq!(definition.to_canonical_bytes(), DEFINITION_BYTES);
    assert_eq!(
        ArtifactChainDefinition::from_canonical_bytes(&DEFINITION_BYTES),
        Ok(definition)
    );
    assert_eq!(definition.deployment_discriminator(), &[CHAIN_BYTE; 32]);
    assert_eq!(chain_id.as_bytes(), &CHAIN_ID_BYTES);
    assert_eq!(virtual_genesis.as_bytes(), &VIRTUAL_GENESIS_BYTES);
    assert_eq!(block.id().as_bytes(), &EXPECTED_BLOCK_ID_BYTES);
    assert_eq!(
        ArtifactBlockId::from_bytes(*virtual_genesis.as_bytes()),
        virtual_genesis
    );
    assert_eq!(ARTIFACT_BLOCK_BYTES, 128);
    assert_eq!(bytes.len(), ARTIFACT_BLOCK_BYTES);
    assert_eq!(&bytes[..32], virtual_genesis.as_bytes());
    assert_eq!(&bytes[32..64], root(0x22).as_bytes());
    assert_eq!(&bytes[64..96], root(0x33).as_bytes());
    assert_eq!(&bytes[96..], artifact_id(0x44).as_bytes());
    assert_eq!(ArtifactBlock::from_canonical_bytes(&bytes), Ok(block));
    assert_eq!(block.parent_block_id(), virtual_genesis);
    assert_eq!(block.previous_artifact_set_root(), root(0x22));
    assert_eq!(block.resulting_artifact_set_root(), root(0x33));
    assert_eq!(block.artifact_id(), artifact_id(0x44));
    assert_eq!(
        ArtifactBlockId::from_bytes(*block.id().as_bytes()),
        block.id()
    );
}

#[test]
fn definition_decoder_is_exact_and_fixed_field_errors_have_stable_precedence() {
    for actual in 0..ArtifactChainDefinition::BYTE_LENGTH {
        assert_eq!(
            ArtifactChainDefinition::from_canonical_bytes(&DEFINITION_BYTES[..actual]),
            Err(ArtifactChainDefinitionDecodeError::InvalidLength {
                actual,
                expected: ArtifactChainDefinition::BYTE_LENGTH,
            })
        );
    }

    let mut extended = DEFINITION_BYTES.to_vec();
    extended.push(0xff);
    assert_eq!(
        ArtifactChainDefinition::from_canonical_bytes(&extended),
        Err(ArtifactChainDefinitionDecodeError::InvalidLength {
            actual: ArtifactChainDefinition::BYTE_LENGTH + 1,
            expected: ArtifactChainDefinition::BYTE_LENGTH,
        })
    );

    let foundation_start = DEPLOYMENT_DISCRIMINATOR_BYTES;
    let genesis_root_start = foundation_start + FOUNDATION_ID_BYTES;
    let mut wrong_foundation = DEFINITION_BYTES;
    wrong_foundation[foundation_start] ^= 1;
    wrong_foundation[genesis_root_start] ^= 1;
    assert_eq!(
        ArtifactChainDefinition::from_canonical_bytes(&wrong_foundation),
        Err(ArtifactChainDefinitionDecodeError::FoundationIdMismatch)
    );

    let mut wrong_root = DEFINITION_BYTES;
    wrong_root[genesis_root_start] ^= 1;
    assert_eq!(
        ArtifactChainDefinition::from_canonical_bytes(&wrong_root),
        Err(
            ArtifactChainDefinitionDecodeError::GenesisArtifactSetRootMismatch {
                expected: ArtifactSetRoot::empty(),
                actual: ArtifactSetRoot::from_bytes(
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
        let mutated = ArtifactChainDefinition::from_canonical_bytes(&bytes).unwrap();
        assert_ne!(mutated.id(), original_id);
        assert_ne!(mutated.id().virtual_genesis_block_id(), original_genesis);
    }
}

#[test]
fn fixed_block_decoder_rejects_every_other_length() {
    let bytes = block().to_canonical_bytes();
    for actual in 0..ARTIFACT_BLOCK_BYTES {
        assert_eq!(
            ArtifactBlock::from_canonical_bytes(&bytes[..actual]),
            Err(ArtifactBlockDecodeError::InvalidLength {
                actual,
                expected: ARTIFACT_BLOCK_BYTES,
            })
        );
    }

    let mut extended = bytes.to_vec();
    for extra in 1..=ARTIFACT_BLOCK_BYTES {
        extended.push(0xff);
        assert_eq!(
            ArtifactBlock::from_canonical_bytes(&extended),
            Err(ArtifactBlockDecodeError::InvalidLength {
                actual: ARTIFACT_BLOCK_BYTES + extra,
                expected: ARTIFACT_BLOCK_BYTES,
            })
        );
    }
}

#[test]
fn every_parent_root_and_artifact_byte_changes_block_identity() {
    let original = block();
    let original_id = original.id();
    let encoded = original.to_canonical_bytes();

    for index in 0..ARTIFACT_BLOCK_BYTES {
        let mut mutated = encoded;
        mutated[index] ^= 1;
        let mutated = ArtifactBlock::from_canonical_bytes(&mutated).unwrap();
        assert_ne!(mutated.id(), original_id, "byte {index}");
    }
}

#[test]
fn chain_definition_domain_is_single_artifact_specific() {
    let definition = definition(CHAIN_BYTE);
    for prior_domain in [
        b"naome:proof-chain-definition\0".as_slice(),
        b"naome:proof-chain-definition:single-proof-v0\0".as_slice(),
    ] {
        let mut prior = Sha256::new();
        prior.update(prior_domain);
        prior.update(definition.to_canonical_bytes());
        let prior_id: [u8; 32] = prior.finalize().into();
        assert_ne!(definition.id().as_bytes(), &prior_id);
    }
}
