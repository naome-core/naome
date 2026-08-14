use super::{
    CERTIFICATE_MAX_BYTES, ProofCertificate, ProofCertificateError, ProofSeparation, ProofStep,
};
use naome_foundation::{FORMULA_MAX_DEPTH, Formula, FormulaCodecError, FreeVariable};

#[test]
fn certificate_requires_a_conclusion_step() {
    assert_eq!(
        ProofCertificate::new(Vec::new()),
        Err(ProofCertificateError::EmptyCertificate)
    );
}

#[test]
fn certificate_rejects_self_and_forward_references() {
    let x = FreeVariable::new(1);

    assert_eq!(
        ProofCertificate::new(vec![ProofStep::Generalization {
            premise: 0,
            variable: x,
        }]),
        Err(ProofCertificateError::ReferenceNotEarlier {
            step: 0,
            reference: 0,
        })
    );

    assert_eq!(
        ProofCertificate::new(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 2,
                variable: x,
            },
        ]),
        Err(ProofCertificateError::ReferenceNotEarlier {
            step: 1,
            reference: 2,
        })
    );
}

#[test]
fn certificate_accepts_only_earlier_local_references() {
    let x = FreeVariable::new(1);
    let certificate = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ])
    .unwrap();

    assert_eq!(certificate.steps().len(), 2);
}

#[test]
fn certificate_constructor_enforces_formula_codec_limits() {
    let x = FreeVariable::new(1);
    let mut oversized = Formula::equal(x, x);
    for _ in 0..FORMULA_MAX_DEPTH {
        oversized = Formula::negate(oversized);
    }

    assert_eq!(
        ProofCertificate::new(vec![ProofStep::VacuousUniversal {
            formula: oversized.into(),
        }]),
        Err(ProofCertificateError::Formula(
            FormulaCodecError::DepthLimitExceeded {
                maximum: FORMULA_MAX_DEPTH,
            }
        ))
    );
}

#[test]
fn certificate_constructor_enforces_the_total_byte_limit() {
    let element = FreeVariable::new(1);
    let source = FreeVariable::new(2);
    let result_variable = FreeVariable::new(3);
    let parameter = FreeVariable::new(4);
    let parameters = vec![parameter; CERTIFICATE_MAX_BYTES / 4 + 1];

    let construction = ProofCertificate::new(vec![ProofStep::Separation(ProofSeparation {
        predicate: (Formula::member(element, source)).into(),
        element,
        source,
        result: result_variable,
        parameters,
    })]);

    assert!(matches!(
        construction,
        Err(ProofCertificateError::InputTooLong {
            maximum: CERTIFICATE_MAX_BYTES,
            ..
        })
    ));
}
