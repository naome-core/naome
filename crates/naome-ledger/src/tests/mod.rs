use std::error::Error;

use naome_checker::{
    CheckError, ProofStateError, normalize_and_check, normalize_and_check_with_state,
};
use naome_foundation::{Formula, FreeVariable, LogicError, Separation, ZfcAxiom};
use naome_proof::{
    CERTIFICATE_MAX_BYTES, ProofCertificate, ProofCertificateError, ProofId, ProofStep,
};

use super::{
    AddressedProofCandidate, LedgerError, LedgerState, PROOF_BATCH_MAX_CANDIDATES, ProofBatchError,
};

fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
    ProofCertificate::new(steps).unwrap()
}

fn identity(variable: FreeVariable) -> ProofCertificate {
    certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ])
}

fn identity_detour(variable: FreeVariable) -> ProofCertificate {
    let equality = Formula::equal(variable, variable);
    certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Simplification {
            antecedent: equality.clone(),
            consequent: equality,
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
            variable,
        },
    ])
}

fn referenced_generalization(proof_id: ProofId, variable: FreeVariable) -> ProofCertificate {
    let equality = Formula::equal(variable, variable);
    let identity = Formula::for_all(variable, equality);
    certificate(vec![
        ProofStep::ProofReference { proof_id },
        ProofStep::VacuousUniversal { formula: identity },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ])
}

fn proof_using_every_reference(
    references: &[(ProofId, Formula)],
    conclusion_axiom: ZfcAxiom,
) -> ProofCertificate {
    let mut steps = references
        .iter()
        .map(|(proof_id, _)| ProofStep::ProofReference {
            proof_id: *proof_id,
        })
        .collect::<Vec<_>>();
    let conclusion = conclusion_axiom.formula();
    steps.push(ProofStep::ZfcAxiom(conclusion_axiom));
    let mut conclusion_step = u32::try_from(steps.len() - 1).unwrap();

    for (reference_step, (_, premise)) in references.iter().enumerate().rev() {
        let implication_step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::Simplification {
            antecedent: conclusion.clone(),
            consequent: premise.clone(),
        });
        let conditional_step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::ModusPonens {
            premise: conclusion_step,
            implication: implication_step,
        });
        conclusion_step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::ModusPonens {
            premise: u32::try_from(reference_step).unwrap(),
            implication: conditional_step,
        });
    }

    certificate(steps)
}

fn canonical_bytes(certificate: ProofCertificate) -> Vec<u8> {
    certificate
        .into_unchecked_normal_form()
        .into_canonical_bytes()
        .into_vec()
}

fn axiom_candidate(axiom: ZfcAxiom) -> (Vec<u8>, ProofId) {
    let proof = certificate(vec![ProofStep::ZfcAxiom(axiom)]);
    let proof_id = normalize_and_check(proof.clone()).unwrap().proof_id();
    (canonical_bytes(proof), proof_id)
}

fn referenced_generalization_bytes(proof_id: ProofId, variable: FreeVariable) -> Vec<u8> {
    canonical_bytes(certificate(vec![
        ProofStep::ProofReference { proof_id },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ]))
}

fn reordered_identity_detour(variable: FreeVariable) -> ProofCertificate {
    let equality = Formula::equal(variable, variable);
    certificate(vec![
        ProofStep::Simplification {
            antecedent: equality.clone(),
            consequent: equality,
        },
        ProofStep::EqualityReflexivity { variable },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 0,
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
        ProofStep::Generalization {
            premise: 3,
            variable,
        },
    ])
}

fn duplicate_identity(variable: FreeVariable) -> ProofCertificate {
    let equality = Formula::equal(variable, variable);
    let identity = Formula::implies(equality.clone(), equality.clone());
    certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Simplification {
            antecedent: equality.clone(),
            consequent: equality,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 2,
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
        ProofStep::Simplification {
            antecedent: identity.clone(),
            consequent: identity,
        },
        ProofStep::ModusPonens {
            premise: 3,
            implication: 5,
        },
        ProofStep::ModusPonens {
            premise: 4,
            implication: 6,
        },
        ProofStep::Generalization {
            premise: 7,
            variable,
        },
    ])
}

mod batch;
mod single;
