use naome_foundation::{Formula, FreeVariable, ZfcAxiom};
use naome_proof::{ProofCertificate, ProofStep};

use super::{ProofState, ProofStateError};
use crate::normalize_and_check;

fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
    ProofCertificate::new(steps).unwrap()
}

fn direct_identity(variable: FreeVariable) -> crate::CheckedProof {
    normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ]))
    .unwrap()
}

fn axiom(axiom: ZfcAxiom) -> crate::CheckedProof {
    normalize_and_check(certificate(vec![ProofStep::ZfcAxiom(axiom)])).unwrap()
}

#[test]
fn alternative_proofs_share_one_stored_conclusion() {
    let x = FreeVariable::new(7);
    let direct = direct_identity(x);
    let formula = Formula::equal(x, x);
    let detour = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Simplification {
            antecedent: formula.clone(),
            consequent: formula,
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
            variable: x,
        },
    ]))
    .unwrap();
    assert_eq!(direct.statement_id, detour.statement_id);
    assert_ne!(direct.derivation_id, detour.derivation_id);
    assert_ne!(direct.proof_id, detour.proof_id);
    let direct_derivation_id = direct.derivation_id;
    let detour_derivation_id = detour.derivation_id;

    let mut state = ProofState::new();
    state.register(direct).unwrap();
    state.register(detour).unwrap();

    assert!(state.contains_derivation(direct_derivation_id));
    assert!(state.contains_derivation(detour_derivation_id));
    assert_eq!(state.proofs.len(), 2);
    assert_eq!(state.derivations.len(), 2);
    assert_eq!(state.statements.len(), 1);
}

#[test]
fn identity_collisions_fail_closed_without_mutating_state() {
    let x = FreeVariable::new(1);
    let original = direct_identity(x);
    let original_proof_id = original.proof_id;
    let original_statement_id = original.statement_id;
    let original_derivation_id = original.derivation_id;
    let mut state = ProofState::new();
    state.register(original).unwrap();
    let different_conclusion = || {
        normalize_and_check(certificate(vec![ProofStep::ZfcAxiom(
            naome_foundation::ZfcAxiom::Pairing,
        )]))
        .unwrap()
    };

    let mut conflicting_proof = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
        ProofStep::Generalization {
            premise: 1,
            variable: FreeVariable::new(2),
        },
    ]))
    .unwrap();
    conflicting_proof.proof_id = original_proof_id;
    assert_eq!(
        state.register(conflicting_proof),
        Err(ProofStateError::ProofIdentityCollision {
            proof_id: original_proof_id,
        })
    );

    let mut forged_duplicate = different_conclusion();
    forged_duplicate.proof_id = original_proof_id;
    forged_duplicate.derivation_id = original_derivation_id;
    forged_duplicate.statement_id = original_statement_id;
    assert_eq!(
        state.register(forged_duplicate),
        Err(ProofStateError::StatementIdentityCollision {
            statement_id: original_statement_id,
        })
    );

    let mut duplicate_derivation = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Simplification {
            antecedent: Formula::equal(x, x),
            consequent: Formula::equal(x, x),
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
            variable: x,
        },
    ]))
    .unwrap();
    let duplicate_derivation_proof_id = duplicate_derivation.proof_id;
    duplicate_derivation.derivation_id = original_derivation_id;
    assert_eq!(
        state.register(duplicate_derivation),
        Err(ProofStateError::DuplicateDerivation {
            derivation_id: original_derivation_id,
        })
    );

    let mut forged_derivation = different_conclusion();
    let forged_derivation_proof_id = forged_derivation.proof_id;
    forged_derivation.derivation_id = original_derivation_id;
    forged_derivation.statement_id = original_statement_id;
    assert_eq!(
        state.register(forged_derivation),
        Err(ProofStateError::StatementIdentityCollision {
            statement_id: original_statement_id,
        })
    );

    let mut conflicting_derivation = different_conclusion();
    let conflicting_derivation_proof_id = conflicting_derivation.proof_id;
    conflicting_derivation.derivation_id = original_derivation_id;
    assert_eq!(
        state.register(conflicting_derivation),
        Err(ProofStateError::DerivationIdentityCollision {
            derivation_id: original_derivation_id,
        })
    );

    let mut conflicting_statement = normalize_and_check(certificate(vec![ProofStep::ZfcAxiom(
        naome_foundation::ZfcAxiom::Extensionality,
    )]))
    .unwrap();
    let conflicting_proof_id = conflicting_statement.proof_id;
    conflicting_statement.statement_id = original_statement_id;
    assert_eq!(
        state.register(conflicting_statement),
        Err(ProofStateError::StatementIdentityCollision {
            statement_id: original_statement_id,
        })
    );

    assert_eq!(state.proofs.len(), 1);
    assert_eq!(state.derivations.len(), 1);
    assert_eq!(state.statements.len(), 1);
    assert!(!state.contains_proof(conflicting_proof_id));
    assert!(!state.contains_proof(duplicate_derivation_proof_id));
    assert!(!state.contains_proof(forged_derivation_proof_id));
    assert!(!state.contains_proof(conflicting_derivation_proof_id));
}

#[test]
fn single_registration_validation_matches_registration_without_mutating() {
    let proof = axiom(ZfcAxiom::Pairing);
    let proof_id = proof.proof_id();
    let derivation_id = proof.derivation_id();
    let statement_id = proof.statement_id();
    let mut state = ProofState::new();

    state.validate_registration(&proof).unwrap();
    state.validate_registration(&proof).unwrap();
    assert!(!state.contains_proof(proof_id));
    assert!(!state.contains_derivation(derivation_id));
    assert!(!state.contains_statement(statement_id));

    state.register(proof).unwrap();
    let duplicate = axiom(ZfcAxiom::Pairing);
    let expected = Err(ProofStateError::DuplicateProof { proof_id });
    assert_eq!(state.validate_registration(&duplicate), expected);
    assert!(state.contains_proof(proof_id));
    assert!(state.contains_derivation(derivation_id));
    assert!(state.contains_statement(statement_id));
}
