use super::*;
use naome_foundation::{FORMULA_MAX_BYTES, FreeVariable};

fn equality_body() -> DefinedFormula {
    let value = FreeVariable::new(0);
    DefinedFormula::equal(value, value)
}

fn identity_body() -> DefinedFormula {
    DefinedFormula::equal(FreeVariable::new(1), FreeVariable::new(0))
}

fn body_using_all(arity: u32) -> DefinedFormula {
    let mut body = equality_body();
    for identifier in 1..arity {
        let variable = FreeVariable::new(identifier);
        body = DefinedFormula::implies(body, DefinedFormula::equal(variable, variable));
    }
    body
}

#[test]
fn every_definition_kind_round_trips_without_an_obligation_address() {
    let definitions = [
        DefinitionCertificate::relation(1, equality_body()).unwrap(),
        DefinitionCertificate::function(1, identity_body()).unwrap(),
    ];
    for definition in &definitions {
        let bytes = definition.to_canonical_bytes();
        assert_eq!(
            &DefinitionCertificate::from_canonical_bytes(&bytes).unwrap(),
            definition
        );
    }
    assert_eq!(definitions[0].relation_arity(), 1);
    assert_eq!(definitions[1].relation_arity(), 2);
}

#[test]
fn interface_validation_requires_exact_used_bounded_formals() {
    assert_eq!(
        DefinitionCertificate::relation(
            1,
            DefinedFormula::equal(FreeVariable::new(1), FreeVariable::new(1)),
        ),
        Err(DefinitionCertificateError::UndeclaredFormalVariable {
            identifier: 1,
            arity: 1,
        })
    );
    assert_eq!(
        DefinitionCertificate::relation(2, equality_body()),
        Err(DefinitionCertificateError::MissingFormalVariable {
            identifier: 1,
            arity: 2,
        })
    );
    assert_eq!(
        DefinitionCertificate::relation(0, equality_body()),
        Err(DefinitionCertificateError::ZeroRelationArity)
    );
    assert_eq!(
        DefinitionCertificate::function(0, equality_body()),
        Err(DefinitionCertificateError::ZeroFunctionArity)
    );
    assert_eq!(
        DefinitionCertificate::relation(DEFINITION_MAX_GRAPH_ARITY + 1, equality_body()),
        Err(DefinitionCertificateError::ArityTooLarge {
            actual: u64::from(DEFINITION_MAX_GRAPH_ARITY) + 1,
            maximum: DEFINITION_MAX_GRAPH_ARITY,
        })
    );
    assert_eq!(
        DefinitionCertificate::function(DEFINITION_MAX_GRAPH_ARITY, identity_body()),
        Err(DefinitionCertificateError::ArityTooLarge {
            actual: u64::from(DEFINITION_MAX_GRAPH_ARITY) + 1,
            maximum: DEFINITION_MAX_GRAPH_ARITY,
        })
    );
    assert_eq!(
        DefinitionCertificate::function(u32::MAX, equality_body()),
        Err(DefinitionCertificateError::ArityTooLarge {
            actual: u64::from(u32::MAX) + 1,
            maximum: DEFINITION_MAX_GRAPH_ARITY,
        })
    );
    let _ = DefinitionCertificate::relation(
        DEFINITION_MAX_GRAPH_ARITY,
        body_using_all(DEFINITION_MAX_GRAPH_ARITY),
    )
    .unwrap();
    let _ = DefinitionCertificate::function(
        DEFINITION_MAX_GRAPH_ARITY - 1,
        body_using_all(DEFINITION_MAX_GRAPH_ARITY),
    )
    .unwrap();
}

#[test]
fn kind_body_and_arity_are_identity_bearing() {
    let relation = DefinitionCertificate::relation(1, equality_body()).unwrap();
    let wider = DefinitionCertificate::relation(2, identity_body()).unwrap();
    let function = DefinitionCertificate::function(1, identity_body()).unwrap();
    let alternate = DefinitionCertificate::relation(
        1,
        DefinedFormula::member(FreeVariable::new(0), FreeVariable::new(0)),
    )
    .unwrap();
    assert_ne!(relation.definition_id(), wider.definition_id());
    assert_ne!(wider.definition_id(), function.definition_id());
    assert_ne!(relation.definition_id(), alternate.definition_id());
}

#[test]
fn canonical_definition_body_rejects_selected_definition_applications() {
    let definition_id = DefinitionId::from_bytes([0x77; 32]);
    assert_eq!(
        DefinitionCertificate::relation(
            1,
            DefinedFormula::defined_relation(definition_id, [FreeVariable::new(0)]),
        ),
        Err(DefinitionCertificateError::DefinitionReference { definition_id })
    );
}

#[test]
fn relation_definition_identity_has_a_stable_domain_golden() {
    let definition = DefinitionCertificate::relation(1, equality_body()).unwrap();
    assert_eq!(
        definition.definition_id().as_bytes(),
        &[
            0x01, 0x96, 0xe7, 0x6e, 0xe0, 0xec, 0xab, 0xbe, 0x9e, 0x86, 0x3a, 0x19, 0xf1, 0x91,
            0xde, 0xd8, 0x7b, 0x59, 0x9a, 0x4b, 0x15, 0x8c, 0x52, 0xf7, 0x5d, 0x8e, 0xce, 0x35,
            0xba, 0x79, 0x60, 0x35,
        ]
    );
}

#[test]
fn strict_decoder_rejects_every_truncation_unknown_tag_and_trailing_byte() {
    let definition = DefinitionCertificate::function(1, identity_body()).unwrap();
    let bytes = definition.to_canonical_bytes();
    for end in 0..bytes.len() {
        assert!(DefinitionCertificate::from_canonical_bytes(&bytes[..end]).is_err());
    }
    assert_eq!(
        DefinitionCertificate::from_canonical_bytes(&[0x01]),
        Err(DefinitionCertificateError::UnknownKindTag(0x01))
    );
    assert_eq!(
        DefinitionCertificate::from_canonical_bytes(&[0xff]),
        Err(DefinitionCertificateError::UnknownKindTag(0xff))
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        DefinitionCertificate::from_canonical_bytes(&trailing),
        Err(DefinitionCertificateError::TrailingBytes { remaining: 1 })
    );
}

#[test]
fn complete_certificate_byte_limit_is_derived_from_the_formula_limit() {
    assert_eq!(DEFINITION_MAX_BYTES, FORMULA_MAX_BYTES + 9);
    assert_eq!(
        DefinitionCertificate::from_canonical_bytes(&vec![0; DEFINITION_MAX_BYTES + 1]),
        Err(DefinitionCertificateError::InputTooLong {
            actual: DEFINITION_MAX_BYTES + 1,
            maximum: DEFINITION_MAX_BYTES
        })
    );
}
