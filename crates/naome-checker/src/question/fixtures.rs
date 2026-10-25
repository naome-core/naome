//! Fixed mathematical workloads shared by regressions and matched comparisons.
use super::*;
use crate::{ArtifactState, normalize_and_check};
use naome_foundation::FreeVariable;
use naome_proof::ProofCertificate;

/// An equivalence outside elementary structural matching. A single stored
/// direction must still be insufficient: B = (forall(x, x=x) -> A).
pub(super) fn guarded_equivalence(a: &Formula) -> (Formula, Vec<ProofStep>, Vec<ProofStep>) {
    let x = FreeVariable::new(0);
    let e = Formula::for_all(x, Formula::equal(x, x));
    let b = Formula::implies(e.clone(), a.clone());
    let identity = Formula::implies(b.clone(), b.clone());
    let forward = vec![ProofStep::Simplification {
        antecedent: a.clone().into(),
        consequent: e.clone().into(),
    }];
    let backward = vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
        ProofStep::Simplification {
            antecedent: e.clone().into(),
            consequent: b.clone().into(),
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
        ProofStep::Simplification {
            antecedent: b.clone().into(),
            consequent: identity.clone().into(),
        },
        ProofStep::Simplification {
            antecedent: b.clone().into(),
            consequent: b.clone().into(),
        },
        ProofStep::Frege {
            first: b.clone().into(),
            second: identity.into(),
            third: b.clone().into(),
        },
        ProofStep::ModusPonens {
            premise: 4,
            implication: 6,
        },
        ProofStep::ModusPonens {
            premise: 5,
            implication: 7,
        },
        ProofStep::Frege {
            first: b.clone().into(),
            second: e.into(),
            third: a.clone().into(),
        },
        ProofStep::ModusPonens {
            premise: 8,
            implication: 9,
        },
        ProofStep::ModusPonens {
            premise: 3,
            implication: 10,
        },
    ];
    (b, forward, backward)
}

pub(super) fn budget_case(decoys: usize, short_negative: bool) -> (ArtifactState, Formula) {
    // A = forall(x, eq(x,x)). The frozen primitive certificate derives
    // not(A -> not(A)); it contains no proof references or new inference rules.
    let hex: String = include_str!("fixtures/conjunction.hex")
        .split_whitespace()
        .collect();
    let bytes: Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
        .collect();
    let certificate = ProofCertificate::from_canonical_bytes(&bytes).unwrap();
    let negative = normalize_and_check(certificate.clone())
        .unwrap()
        .conclusion()
        .clone();
    let mut steps = certificate.steps().to_vec();
    let x = FreeVariable::new(0);
    let seed = Formula::for_all(x, Formula::equal(x, x));
    let previous = (steps.len() - 1) as u32;
    let bridge = steps.len() as u32;
    steps.push(ProofStep::Simplification {
        antecedent: negative.clone().into(),
        consequent: seed.clone().into(),
    });
    steps.push(ProofStep::ModusPonens {
        premise: previous,
        implication: bridge,
    });
    let mut state = ArtifactState::new();
    // Only the implication is registered; its internal conclusion is not a
    // stored exact answer. A real two-reference MP certificate is required.
    state
        .register_proof(normalize_and_check(ProofCertificate::new(steps).unwrap()).unwrap())
        .unwrap();
    state
        .register_proof(
            normalize_and_check(
                ProofCertificate::new(vec![
                    ProofStep::EqualityReflexivity { variable: x },
                    ProofStep::Generalization {
                        premise: 0,
                        variable: x,
                    },
                ])
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let target = if short_negative {
        negative.view().negated().unwrap().to_owned()
    } else {
        negative
    };
    let heavy = if short_negative {
        target.clone()
    } else {
        Formula::negate(target.clone())
    };
    for index in 1..=decoys {
        let mut pattern = Formula::for_all(x, Formula::member(x, x));
        for digit in format!("{index:b}").bytes() {
            pattern = if digit == b'1' {
                Formula::negate(pattern)
            } else {
                Formula::for_all(x, pattern)
            };
        }
        state
            .register_proof(
                normalize_and_check(
                    ProofCertificate::new(vec![ProofStep::Simplification {
                        antecedent: heavy.clone().into(),
                        consequent: pattern.into(),
                    }])
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    (state, target)
}
