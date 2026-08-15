use super::{ArtifactId, DefinitionId, DerivationId, ProofId, StatementId};

#[test]
fn identity_bytes_round_trip_without_claiming_validity() {
    let statement_bytes = [0x11; 32];
    let proof_bytes = [0x22; 32];
    let derivation_bytes = [0x33; 32];

    assert_eq!(
        StatementId::from_bytes(statement_bytes).as_bytes(),
        &statement_bytes
    );
    assert_eq!(ProofId::from_bytes(proof_bytes).as_bytes(), &proof_bytes);
    assert_eq!(
        DerivationId::from_bytes(derivation_bytes).as_bytes(),
        &derivation_bytes
    );
}

#[test]
fn typed_artifact_domains_are_distinct_and_stable() {
    let bytes = [0x11; 32];
    let proof = ArtifactId::from_proof_id(ProofId::from_bytes(bytes));
    let definition = ArtifactId::from_definition_id(DefinitionId::from_bytes(bytes));
    assert_ne!(proof, definition);
    assert_eq!(
        proof.as_bytes(),
        &[
            0x0c, 0xa3, 0x18, 0x6e, 0x2f, 0xfb, 0xf3, 0xb3, 0xc5, 0x0d, 0x84, 0xc7, 0xee, 0xe3,
            0xf8, 0x8a, 0x6e, 0xa1, 0x2d, 0x68, 0x6e, 0x23, 0xb0, 0xfb, 0xfe, 0x9e, 0x10, 0x6b,
            0xdb, 0x30, 0x97, 0x92,
        ]
    );
    assert_eq!(
        definition.as_bytes(),
        &[
            0x79, 0xa6, 0x99, 0xdd, 0x0a, 0xc1, 0xf6, 0xf7, 0x3e, 0x21, 0xdd, 0x4a, 0xb7, 0x37,
            0x7e, 0x68, 0xd7, 0xca, 0x6d, 0xa5, 0x69, 0x2c, 0x64, 0x7d, 0x51, 0x1b, 0x22, 0xa3,
            0x44, 0xa6, 0x60, 0xc4,
        ]
    );
    assert_eq!(ArtifactId::from_bytes(*proof.as_bytes()), proof);
    assert_eq!(ArtifactId::from_bytes(*definition.as_bytes()), definition);
}
