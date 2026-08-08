//! Deterministic single-proof ledger state transitions for NAOME.
//!
//! A [`LedgerStateV0`] admits exactly one proof certificate per call. The
//! candidate is normalized and checked against the already accepted parent
//! state, then registered only after checking succeeds. Consequently, a proof
//! can cite only previously accepted proofs. Blocks, persistence, undo,
//! rewards, networking, and source parsing remain outside this crate.

use std::error::Error;
use std::fmt;

use naome_checker::{CheckError, ProofStateError, ProofStateV0, normalize_and_check_with_state};
use naome_proof::{DerivationId, ProofCertificateV0, ProofId, StatementId};

/// The novelty of an accepted proof's closed statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementNoveltyV0 {
    /// The statement was absent from the accepted parent state.
    New,
    /// The statement already had another accepted derivation.
    Existing,
}

/// The content identities and statement novelty produced by one state update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct AppliedProofV0 {
    proof_id: ProofId,
    derivation_id: DerivationId,
    statement_id: StatementId,
    statement_novelty: StatementNoveltyV0,
}

impl AppliedProofV0 {
    /// Returns the concrete checked proof identity.
    pub const fn proof_id(&self) -> ProofId {
        self.proof_id
    }

    /// Returns the reference-transparent checked derivation identity.
    pub const fn derivation_id(&self) -> DerivationId {
        self.derivation_id
    }

    /// Returns the checked closed statement identity.
    pub const fn statement_id(&self) -> StatementId {
        self.statement_id
    }

    /// Returns whether this transition introduced the statement.
    pub const fn statement_novelty(&self) -> StatementNoveltyV0 {
        self.statement_novelty
    }
}

/// The accepted proof state after zero or more single-proof transitions.
///
/// The inner proof state is private so callers cannot interleave checking and
/// mutation. Each successful [`Self::apply`] call contributes exactly one
/// checked proof; every failure leaves the state unchanged.
#[derive(Default)]
#[must_use]
pub struct LedgerStateV0 {
    proof_state: ProofStateV0,
}

impl LedgerStateV0 {
    /// Constructs an empty ledger state.
    pub const fn new() -> Self {
        Self {
            proof_state: ProofStateV0::new(),
        }
    }

    /// Returns whether the selected concrete proof has been accepted.
    pub fn contains_proof(&self, proof_id: ProofId) -> bool {
        self.proof_state.contains_proof(proof_id)
    }

    /// Returns whether the selected derivation has been accepted.
    pub fn contains_derivation(&self, derivation_id: DerivationId) -> bool {
        self.proof_state.contains_derivation(derivation_id)
    }

    /// Returns whether the selected statement has been accepted.
    pub fn contains_statement(&self, statement_id: StatementId) -> bool {
        self.proof_state.contains_statement(statement_id)
    }

    /// Normalizes, checks, and atomically registers exactly one proof.
    ///
    /// External references resolve only from the state that existed before
    /// this call. The candidate is not visible while it is being checked. A
    /// checking or registration error leaves the state unchanged.
    pub fn apply(
        &mut self,
        certificate: ProofCertificateV0,
    ) -> Result<AppliedProofV0, LedgerError> {
        let checked = normalize_and_check_with_state(certificate, &self.proof_state)
            .map_err(|source| LedgerError::Check { source })?;
        let statement_novelty = if self.proof_state.contains_statement(checked.statement_id()) {
            StatementNoveltyV0::Existing
        } else {
            StatementNoveltyV0::New
        };
        let applied = AppliedProofV0 {
            proof_id: checked.proof_id(),
            derivation_id: checked.derivation_id(),
            statement_id: checked.statement_id(),
            statement_novelty,
        };
        self.proof_state
            .register(checked)
            .map_err(|source| LedgerError::State { source })?;

        Ok(applied)
    }
}

/// A fail-closed single-proof ledger transition error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerError {
    /// Proof normalization or mathematical checking failed.
    Check { source: CheckError },
    /// The checked proof could not be registered in the parent state.
    State { source: ProofStateError },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Check { source } => write!(formatter, "proof checking failed: {source}"),
            Self::State { source } => write!(formatter, "proof registration failed: {source}"),
        }
    }
}

impl Error for LedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Check { source } => Some(source),
            Self::State { source } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use naome_checker::{CheckError, ProofStateError, normalize_and_check_with_state};
    use naome_foundation::{Formula, FreeVariable, ZfcAxiom};
    use naome_proof::{ProofCertificateV0, ProofId, ProofStepV0};

    use super::{LedgerError, LedgerStateV0, StatementNoveltyV0};

    fn certificate(steps: Vec<ProofStepV0>) -> ProofCertificateV0 {
        ProofCertificateV0::new(steps).unwrap()
    }

    fn identity(variable: FreeVariable) -> ProofCertificateV0 {
        certificate(vec![
            ProofStepV0::EqualityReflexivity { variable },
            ProofStepV0::Generalization {
                premise: 0,
                variable,
            },
        ])
    }

    fn identity_detour(variable: FreeVariable) -> ProofCertificateV0 {
        let equality = Formula::equal(variable, variable);
        certificate(vec![
            ProofStepV0::EqualityReflexivity { variable },
            ProofStepV0::Simplification {
                antecedent: equality.clone(),
                consequent: equality,
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStepV0::Generalization {
                premise: 3,
                variable,
            },
        ])
    }

    fn referenced_generalization(proof_id: ProofId, variable: FreeVariable) -> ProofCertificateV0 {
        let equality = Formula::equal(variable, variable);
        let identity = Formula::for_all(variable, equality);
        certificate(vec![
            ProofStepV0::ProofReference { proof_id },
            ProofStepV0::VacuousUniversal { formula: identity },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ])
    }

    fn proof_using_every_reference(
        references: &[(ProofId, Formula)],
        conclusion_axiom: ZfcAxiom,
    ) -> ProofCertificateV0 {
        let mut steps = references
            .iter()
            .map(|(proof_id, _)| ProofStepV0::ProofReference {
                proof_id: *proof_id,
            })
            .collect::<Vec<_>>();
        let conclusion = conclusion_axiom.formula();
        steps.push(ProofStepV0::ZfcAxiom(conclusion_axiom));
        let mut conclusion_step = u32::try_from(steps.len() - 1).unwrap();

        for (reference_step, (_, premise)) in references.iter().enumerate().rev() {
            let implication_step = u32::try_from(steps.len()).unwrap();
            steps.push(ProofStepV0::Simplification {
                antecedent: conclusion.clone(),
                consequent: premise.clone(),
            });
            let conditional_step = u32::try_from(steps.len()).unwrap();
            steps.push(ProofStepV0::ModusPonens {
                premise: conclusion_step,
                implication: implication_step,
            });
            conclusion_step = u32::try_from(steps.len()).unwrap();
            steps.push(ProofStepV0::ModusPonens {
                premise: u32::try_from(reference_step).unwrap(),
                implication: conditional_step,
            });
        }

        certificate(steps)
    }

    #[test]
    fn first_and_alternative_derivations_report_statement_novelty() {
        let variable = FreeVariable::new(7);
        let mut ledger = LedgerStateV0::new();

        let direct = ledger.apply(identity(variable)).unwrap();
        assert_eq!(direct.statement_novelty(), StatementNoveltyV0::New);
        assert!(ledger.contains_proof(direct.proof_id()));
        assert!(ledger.contains_derivation(direct.derivation_id()));
        assert!(ledger.contains_statement(direct.statement_id()));

        let detour = ledger.apply(identity_detour(variable)).unwrap();
        assert_eq!(detour.statement_id(), direct.statement_id());
        assert_ne!(detour.derivation_id(), direct.derivation_id());
        assert_ne!(detour.proof_id(), direct.proof_id());
        assert_eq!(detour.statement_novelty(), StatementNoveltyV0::Existing);
        assert!(ledger.contains_proof(detour.proof_id()));
        assert!(ledger.contains_derivation(detour.derivation_id()));
    }

    #[test]
    fn references_resolve_only_after_the_parent_proof_was_applied() {
        let variable = FreeVariable::new(9);
        let mut parent = LedgerStateV0::new();
        let source = parent.apply(identity(variable)).unwrap();
        let child = referenced_generalization(source.proof_id(), variable);

        let mut independent = LedgerStateV0::new();
        assert_eq!(
            independent.apply(child.clone()),
            Err(LedgerError::Check {
                source: CheckError::UnknownProofReference {
                    step: 0,
                    proof_id: source.proof_id(),
                },
            })
        );
        assert!(!independent.contains_proof(source.proof_id()));

        let applied_child = parent.apply(child).unwrap();
        assert_eq!(applied_child.statement_novelty(), StatementNoveltyV0::New);
        assert!(parent.contains_proof(applied_child.proof_id()));
        assert!(!independent.contains_proof(applied_child.proof_id()));
    }

    #[test]
    fn one_later_proof_can_use_five_previously_accepted_proofs() {
        let axioms = [
            ZfcAxiom::Extensionality,
            ZfcAxiom::Pairing,
            ZfcAxiom::Union,
            ZfcAxiom::PowerSet,
            ZfcAxiom::Infinity,
        ];
        let mut ledger = LedgerStateV0::new();
        let references = axioms
            .iter()
            .copied()
            .map(|axiom| {
                let applied = ledger
                    .apply(certificate(vec![ProofStepV0::ZfcAxiom(axiom)]))
                    .unwrap();
                (applied.proof_id(), axiom.formula())
            })
            .collect::<Vec<_>>();
        let proof = proof_using_every_reference(&references, ZfcAxiom::Choice);
        assert_eq!(proof.steps().len(), 21);

        let applied = ledger.apply(proof.clone()).unwrap();
        assert_eq!(applied.statement_novelty(), StatementNoveltyV0::New);
        assert!(ledger.contains_proof(applied.proof_id()));

        for missing in 0..references.len() {
            let mut incomplete = LedgerStateV0::new();
            for (index, axiom) in axioms.iter().copied().enumerate() {
                if index == missing {
                    continue;
                }

                let parent = incomplete
                    .apply(certificate(vec![ProofStepV0::ZfcAxiom(axiom)]))
                    .unwrap();
                assert_eq!(parent.proof_id(), references[index].0);
            }

            assert!(matches!(
                incomplete.apply(proof.clone()),
                Err(LedgerError::Check {
                    source: CheckError::UnknownProofReference { proof_id, .. }
                }) if proof_id == references[missing].0
            ));
            for (index, (proof_id, _)) in references.iter().enumerate() {
                assert_eq!(incomplete.contains_proof(*proof_id), index != missing);
            }
            assert!(!incomplete.contains_proof(applied.proof_id()));
        }
    }

    #[test]
    fn duplicate_artifacts_and_reference_aliases_leave_state_unchanged() {
        let variable = FreeVariable::new(11);
        let mut ledger = LedgerStateV0::new();
        let source = ledger.apply(identity(variable)).unwrap();

        assert_eq!(
            ledger.apply(identity(FreeVariable::new(42))),
            Err(LedgerError::State {
                source: ProofStateError::DuplicateProof {
                    proof_id: source.proof_id(),
                },
            })
        );
        let alias = certificate(vec![ProofStepV0::ProofReference {
            proof_id: source.proof_id(),
        }]);
        let alias_id = normalize_and_check_with_state(alias.clone(), &ledger.proof_state)
            .unwrap()
            .proof_id();
        assert_eq!(
            ledger.apply(alias),
            Err(LedgerError::State {
                source: ProofStateError::DuplicateDerivation {
                    derivation_id: source.derivation_id(),
                },
            })
        );

        assert!(!ledger.contains_proof(alias_id));
        assert!(ledger.contains_proof(source.proof_id()));
        assert!(ledger.contains_derivation(source.derivation_id()));
        assert!(ledger.contains_statement(source.statement_id()));
    }

    #[test]
    fn checker_and_registration_errors_expose_sources_without_partial_updates() {
        let variable = FreeVariable::new(13);
        let mut ledger = LedgerStateV0::new();
        let open = certificate(vec![ProofStepV0::EqualityReflexivity { variable }]);
        let open_error = ledger.apply(open).unwrap_err();
        assert!(matches!(
            open_error,
            LedgerError::Check {
                source: CheckError::OpenConclusion { step: 0 }
            }
        ));
        assert!(open_error.source().is_some());
        assert!(open_error.to_string().contains("proof checking failed"));

        let applied = ledger.apply(identity(variable)).unwrap();
        let duplicate_error = ledger.apply(identity(variable)).unwrap_err();
        assert!(matches!(
            duplicate_error,
            LedgerError::State {
                source: ProofStateError::DuplicateProof { .. }
            }
        ));
        assert!(duplicate_error.source().is_some());
        assert!(
            duplicate_error
                .to_string()
                .contains("proof registration failed")
        );
        assert!(ledger.contains_proof(applied.proof_id()));
        assert!(ledger.contains_derivation(applied.derivation_id()));
        assert!(ledger.contains_statement(applied.statement_id()));
    }
}
