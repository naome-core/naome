use super::{DerivationId, ProofId, StatementId};

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
