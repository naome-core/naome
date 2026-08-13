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

fn referenced_generalization(
    proof_id: naome_proof::ProofId,
    variable: FreeVariable,
) -> naome_proof::ProofNormalForm {
    certificate(vec![
        ProofStep::ProofReference { proof_id },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ])
    .into_unchecked_normal_form()
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
fn batch_resolves_staged_dependencies_and_commits_only_on_success() {
    let root = axiom(ZfcAxiom::Pairing);
    let root_id = root.proof_id();
    let mut state = ProofState::new();

    let child_id = state
        .apply_batch(|batch| {
            batch.register(root).unwrap();
            let child = batch
                .check_normal_form(referenced_generalization(root_id, FreeVariable::new(0)))
                .unwrap();
            let child_id = child.proof_id();
            batch.register(child).unwrap();
            Ok::<_, ()>(child_id)
        })
        .unwrap();

    assert!(state.contains_proof(root_id));
    assert!(state.contains_proof(child_id));
    assert_eq!(state.proofs.len(), 2);
    assert_eq!(state.derivations.len(), 2);
    assert_eq!(state.statements.len(), 2);
}

#[test]
fn validation_batch_resolves_staged_dependencies_without_committing() {
    let root = axiom(ZfcAxiom::Pairing);
    let root_id = root.proof_id();
    let state = ProofState::new();

    state
        .validate_batch(|batch| {
            batch.register(root).unwrap();
            let child = batch
                .check_normal_form(referenced_generalization(root_id, FreeVariable::new(0)))
                .unwrap();
            batch.register(child).unwrap();
            Ok::<_, ()>(())
        })
        .unwrap();

    assert!(!state.contains_proof(root_id));
    assert!(state.proofs.is_empty());
    assert!(state.derivations.is_empty());
    assert!(state.statements.is_empty());

    state
        .validate_batch(|batch| {
            batch.register(axiom(ZfcAxiom::Pairing)).unwrap();
            let child = batch
                .check_normal_form(referenced_generalization(root_id, FreeVariable::new(0)))
                .unwrap();
            batch.register(child).unwrap();
            Ok::<_, ()>(())
        })
        .unwrap();
    assert!(state.proofs.is_empty());
}

#[test]
fn batch_error_discards_staged_dependencies_and_collisions() {
    let selected = axiom(ZfcAxiom::Union);
    let selected_id = selected.proof_id();
    let staged = axiom(ZfcAxiom::Pairing);
    let staged_id = staged.proof_id();
    let mut state = ProofState::new();
    state.register(selected).unwrap();

    let mut dependent_id = None;
    let aborted = state.apply_batch(|batch| {
        batch.register(staged).unwrap();
        let dependent = batch
            .check_normal_form(referenced_generalization(staged_id, FreeVariable::new(1)))
            .unwrap();
        dependent_id = Some(dependent.proof_id());
        batch.register(dependent).unwrap();
        Err::<(), _>("abort")
    });
    assert_eq!(aborted, Err("abort"));
    assert!(state.contains_proof(selected_id));
    assert!(!state.contains_proof(staged_id));
    assert!(!state.contains_proof(dependent_id.unwrap()));
    assert_eq!(state.proofs.len(), 1);
    assert_eq!(state.derivations.len(), 1);
    assert_eq!(state.statements.len(), 1);

    let staged = axiom(ZfcAxiom::Pairing);
    let duplicate_selected = axiom(ZfcAxiom::Union);
    let base_collision = state.apply_batch(|batch| {
        batch.register(staged).unwrap();
        batch.register(duplicate_selected)
    });
    assert_eq!(
        base_collision,
        Err(ProofStateError::DuplicateProof {
            proof_id: selected_id,
        })
    );
    assert!(state.contains_proof(selected_id));
    assert!(!state.contains_proof(staged_id));
    assert_eq!(state.proofs.len(), 1);
    assert_eq!(state.derivations.len(), 1);
    assert_eq!(state.statements.len(), 1);

    let first = axiom(ZfcAxiom::Pairing);
    let duplicate = axiom(ZfcAxiom::Pairing);
    let collision = state.apply_batch(|batch| {
        batch.register(first).unwrap();
        batch.register(duplicate)
    });
    assert_eq!(
        collision,
        Err(ProofStateError::DuplicateProof {
            proof_id: staged_id,
        })
    );
    assert!(state.contains_proof(selected_id));
    assert!(!state.contains_proof(staged_id));
    assert_eq!(state.proofs.len(), 1);
    assert_eq!(state.derivations.len(), 1);
    assert_eq!(state.statements.len(), 1);
}
