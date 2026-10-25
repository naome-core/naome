use super::*;
use crate::{DefinedFormula, ProofStep};
use naome_foundation::FreeVariable;

#[test]
fn proof_and_definition_envelopes_have_exact_distinct_tags() {
    let proof = ProofCertificate::new(vec![ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(7),
    }])
    .unwrap();
    let proof_inner = proof.to_canonical_bytes();
    let proof_payload = ArtifactPayload::Proof(proof);
    let proof_bytes = proof_payload.to_canonical_bytes();
    assert_eq!(proof_bytes[0], PROOF);
    assert_eq!(&proof_bytes[1..], proof_inner);
    assert_eq!(
        ArtifactPayload::from_canonical_bytes(&proof_bytes).unwrap(),
        proof_payload
    );

    let definition = DefinitionCertificate::relation(
        1,
        DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0)),
    )
    .unwrap();
    let definition_inner = definition.to_canonical_bytes();
    let definition_payload = ArtifactPayload::Definition(definition);
    let definition_bytes = definition_payload.to_canonical_bytes();
    assert_eq!(definition_bytes[0], DEFINITION);
    assert_eq!(&definition_bytes[1..], definition_inner);
    assert_eq!(
        ArtifactPayload::from_canonical_bytes(&definition_bytes).unwrap(),
        definition_payload
    );
}

#[test]
fn envelope_rejects_empty_unknown_and_typed_mismatch() {
    assert_eq!(
        ArtifactPayload::from_canonical_bytes(&[]),
        Err(ArtifactPayloadError::UnexpectedEnd)
    );
    assert_eq!(
        ArtifactPayload::from_canonical_bytes(&[0xff]),
        Err(ArtifactPayloadError::UnknownTag(0xff))
    );
    assert!(matches!(
        ArtifactPayload::from_canonical_bytes(&[DEFINITION, 0, 0, 0, 1, 0x06, 0, 0, 0, 7]),
        Err(ArtifactPayloadError::Definition(_))
    ));
}
