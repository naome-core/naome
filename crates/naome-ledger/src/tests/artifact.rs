use naome_proof::{ArtifactPayload, DefinedFormula, DefinitionCertificate, ProofFormula};

use super::*;

fn relation_definition() -> DefinitionCertificate {
    let value = FreeVariable::new(0);
    DefinitionCertificate::relation(1, DefinedFormula::equal(value, value)).unwrap()
}

fn selected_definition_proof(definition_id: naome_proof::DefinitionId) -> ProofCertificate {
    let value = FreeVariable::new(0);
    let application =
        ProofFormula::from_defined(DefinedFormula::defined_relation(definition_id, [value]))
            .unwrap();
    certificate(vec![
        ProofStep::EqualityReflexivity { variable: value },
        ProofStep::Simplification {
            antecedent: application.clone(),
            consequent: application,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 2,
        },
        ProofStep::Generalization {
            premise: 3,
            variable: value,
        },
    ])
}

#[test]
fn tagged_definition_and_dependent_proof_admit_in_selected_order() {
    let definition = relation_definition();
    let definition_id = definition.definition_id();
    let definition_artifact_id = ArtifactId::from_definition_id(definition_id);
    let definition_bytes = ArtifactPayload::Definition(definition.clone()).to_canonical_bytes();
    let proof = selected_definition_proof(definition_id);
    let proof_inner = canonical_bytes(proof);
    let proof_bytes = tagged_proof(proof_inner.clone());

    let mut ledger = LedgerState::new();
    assert_eq!(
        ledger.apply_canonical_artifact_bytes(proof_bytes.clone()),
        Err(LedgerError::ProofCheck {
            source: CheckError::DefinitionExpansion {
                step: 1,
                source: naome_proof::DefinitionExpansionError::UnknownDefinition { definition_id },
            },
        })
    );
    assert!(!ledger.contains_definition(definition_id));

    let record = ledger
        .apply_canonical_artifact_bytes_with_expected_id(
            definition_bytes.clone(),
            definition_artifact_id,
        )
        .unwrap();
    let record = record.as_definition().unwrap();
    assert_eq!(record.definition_id(), definition_id);
    assert_eq!(record.artifact_id(), definition_artifact_id);
    assert_eq!(record.canonical_artifact_bytes(), definition_bytes);
    assert_eq!(
        record.canonical_definition_bytes(),
        definition.to_canonical_bytes()
    );
    assert!(record.direct_definition_dependencies().is_empty());
    assert_eq!(record.obligation_proof_id(), None);

    let proof_id = normalize_and_check_with_state(
        selected_definition_proof(definition_id),
        ledger.artifact_state(),
    )
    .unwrap()
    .proof_id();

    let proof_record = ledger
        .apply_canonical_artifact_bytes_with_expected_id(
            proof_bytes.clone(),
            ArtifactId::from_proof_id(proof_id),
        )
        .unwrap();
    let proof_record = proof_record.as_proof().unwrap();
    assert_eq!(proof_record.proof_id(), proof_id);
    assert_eq!(proof_record.canonical_proof_bytes(), proof_inner);
    assert_eq!(
        proof_record.direct_definition_dependencies(),
        [definition_id]
    );
    assert!(proof_record.direct_proof_dependencies().is_empty());
}

#[test]
fn artifact_address_mismatch_precedes_registration_for_both_types() {
    let definition = relation_definition();
    let definition_id = definition.definition_id();
    let actual = ArtifactId::from_definition_id(definition_id);
    let expected = ArtifactId::from_proof_id(ProofId::from_bytes([0x55; 32]));
    let bytes = ArtifactPayload::Definition(definition).to_canonical_bytes();
    let mut ledger = LedgerState::new();

    assert_eq!(
        ledger.apply_canonical_artifact_bytes_with_expected_id(bytes.clone(), expected),
        Err(LedgerError::ArtifactIdMismatch { expected, actual })
    );
    assert!(!ledger.contains_definition(definition_id));

    let record = ledger
        .apply_canonical_artifact_bytes_with_expected_id(bytes, actual)
        .unwrap();
    assert_eq!(record.artifact_id(), actual);
    assert!(ledger.contains_definition(definition_id));
}
