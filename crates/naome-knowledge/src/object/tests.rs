use super::*;
use naome_foundation::FreeVariable;

fn record() -> BinaryProof {
    let variable = FreeVariable::new(0);
    let certificate = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ])
    .unwrap();
    BinaryProof::from_checked(&naome_checker::normalize_and_check(certificate).unwrap()).unwrap()
}

#[test]
fn binary_and_envelope_preparation_share_canonical_acceptance_and_rejection() {
    let valid = record();
    let binary = valid.clone().prepare().unwrap();
    let envelope = valid.envelope().prepare().unwrap();
    assert_eq!(binary.record(), envelope.record());
    for case in 0..3 {
        let mut invalid = valid.clone();
        match case {
            0 => invalid.bytes = vec![0xff].into(),
            1 => invalid.id = ProofId::from_bytes([0; 32]),
            _ => {
                invalid.bytes = ProofCertificate::new(vec![
                    ProofStep::EqualityReflexivity {
                        variable: FreeVariable::new(0),
                    },
                    ProofStep::EqualityReflexivity {
                        variable: FreeVariable::new(1),
                    },
                    ProofStep::Generalization {
                        premise: 1,
                        variable: FreeVariable::new(1),
                    },
                ])
                .unwrap()
                .to_canonical_bytes()
                .into();
                invalid.id = content_id(invalid.statement, &invalid.bytes);
            }
        }
        let envelope = invalid.envelope();
        let binary_error = invalid.prepare().err().unwrap();
        let envelope_error = envelope.prepare().err().unwrap();
        assert_eq!(binary_error, envelope_error);
    }
}

#[test]
fn wrappers_keep_dependency_metadata_and_memory_admission_before_parsing() {
    let valid = record();
    let mut metadata = valid.clone();
    metadata.dependencies.insert(ProofId::from_bytes([7; 32]));
    assert!(
        metadata
            .prepare()
            .err()
            .unwrap()
            .contains("dependency metadata")
    );
    assert!(valid.envelope().prepare().is_ok());
    let mut malformed = valid;
    malformed.bytes = vec![0xff].into();
    let envelope = malformed.envelope();
    crate::resources::fail_next_memory_allocation();
    assert!(matches!(
        malformed.prepare(),
        Err(crate::Error::MemoryOverload { .. })
    ));
    crate::resources::fail_next_memory_allocation();
    assert!(matches!(
        envelope.prepare(),
        Err(crate::Error::MemoryOverload { .. })
    ));
}
