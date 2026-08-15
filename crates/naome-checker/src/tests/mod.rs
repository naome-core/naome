use std::collections::BTreeSet;
use std::error::Error as _;

use naome_foundation::{
    FORMULA_MAX_DEPTH, FORMULA_MAX_NODES, Formula, FormulaCodecError, FreeVariable, Logic,
    LogicError, Replacement, SchemaError, Separation, ZfcAxiom,
};
use naome_proof::{
    CERTIFICATE_MAX_STEPS, DefinedFormula, DefinitionCertificate, DefinitionExpansionError,
    DefinitionId, ProofCertificate, ProofFormula, ProofId, ProofReplacement, ProofSeparation,
    ProofStep,
};

use super::{
    ArtifactState, ArtifactStateError, CHECKER_MAX_FORMULA_WORK_BYTES, CheckError,
    DefinitionCheckError, IdentityMode, charge_formula_work, check, check_definition_with_state,
    check_with_canonical_conclusion, last_uses, normalize_and_check,
    normalize_and_check_with_state,
};

fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
    ProofCertificate::new(steps).expect("the test certificate is structurally valid")
}

fn proof_formula(formula: DefinedFormula) -> ProofFormula {
    ProofFormula::from_defined(formula).expect("the test formula is canonically representable")
}

fn closed_equality(variable: FreeVariable) -> Formula {
    Formula::for_all(variable, Formula::equal(variable, variable))
}

fn canonical_length(formula: &Formula) -> usize {
    formula
        .encode_canonical()
        .expect("the test formula is within Formula limits")
        .len()
}

mod checking;
mod definitions;
mod identity;
mod limits;
mod rules;

fn balanced_closed_formula(depth: u32, variable: FreeVariable) -> Formula {
    if depth == 0 {
        return closed_equality(variable);
    }

    let child = balanced_closed_formula(depth - 1, variable);
    Formula::implies(child.clone(), child)
}

fn partitioned_weakening_proof(cuts: u8) -> (super::CheckedProof, ArtifactState) {
    let x = FreeVariable::new(100);
    let antecedents = [
        ZfcAxiom::Extensionality.formula(),
        ZfcAxiom::Pairing.formula(),
        ZfcAxiom::Union.formula(),
        ZfcAxiom::PowerSet.formula(),
    ];
    let mut state = ArtifactState::new();
    let mut steps = vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ];
    let mut premise = 1;
    let mut theorem = closed_equality(x);

    for (boundary, antecedent) in antecedents.into_iter().enumerate() {
        if cuts & (1 << boundary) != 0 {
            let prefix = normalize_and_check_with_state(certificate(steps), &state).unwrap();
            let proof_id = prefix.proof_id();
            state.register_proof(prefix).unwrap();
            steps = vec![ProofStep::ProofReference { proof_id }];
            premise = 0;
        }

        let implication = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::Simplification {
            antecedent: theorem.clone().into(),
            consequent: antecedent.clone().into(),
        });
        steps.push(ProofStep::ModusPonens {
            premise,
            implication,
        });
        premise = u32::try_from(steps.len() - 1).unwrap();
        theorem = Formula::implies(antecedent, theorem);
    }

    let checked = normalize_and_check_with_state(certificate(steps), &state).unwrap();
    assert_eq!(checked.conclusion(), &theorem);
    (checked, state)
}

fn inline_closed_fragment(inner: FreeVariable, outer: FreeVariable) -> super::CheckedProof {
    let theorem = closed_equality(inner);
    normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable: inner },
        ProofStep::Generalization {
            premise: 0,
            variable: inner,
        },
        ProofStep::Simplification {
            antecedent: theorem.into(),
            consequent: Formula::equal(outer, outer).into(),
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
        ProofStep::Generalization {
            premise: 3,
            variable: outer,
        },
    ]))
    .unwrap()
}

fn hidden_variable_proof(
    hidden: FreeVariable,
    outer: FreeVariable,
    remaining: FreeVariable,
) -> super::CheckedProof {
    let substitution =
        Logic::equality_substitution(hidden, remaining, Formula::equal(hidden, hidden));
    let open_fragment = Logic::generalization(hidden, substitution);
    normalize_and_check(certificate(vec![
        ProofStep::EqualitySubstitution {
            from: hidden,
            to: remaining,
            body: Formula::equal(hidden, hidden).into(),
        },
        ProofStep::Generalization {
            premise: 0,
            variable: hidden,
        },
        ProofStep::Simplification {
            antecedent: open_fragment.into(),
            consequent: Formula::equal(outer, outer).into(),
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
        ProofStep::Generalization {
            premise: 3,
            variable: outer,
        },
        ProofStep::Generalization {
            premise: 4,
            variable: remaining,
        },
    ]))
    .unwrap()
}

fn identity_proof(variable: FreeVariable, reordered: bool) -> ProofCertificate {
    let formula = Formula::equal(variable, variable);
    let axiom = ProofStep::Simplification {
        antecedent: formula.clone().into(),
        consequent: formula.into(),
    };
    let reflexivity = ProofStep::EqualityReflexivity { variable };
    let mut steps = if reordered {
        vec![axiom, reflexivity]
    } else {
        vec![reflexivity, axiom]
    };
    let (premise, implication) = if reordered { (1, 0) } else { (0, 1) };
    steps.push(ProofStep::ModusPonens {
        premise,
        implication,
    });
    steps.push(ProofStep::ModusPonens {
        premise,
        implication: 2,
    });
    steps.push(ProofStep::Generalization {
        premise: 3,
        variable,
    });
    certificate(steps)
}
