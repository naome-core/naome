//! Deterministic single-proof ledger state transitions for NAOME.
//!
//! A [`LedgerStateV0`] admits exactly one proof certificate per call. The
//! authoring path normalizes an owned certificate; the strict byte path rejects
//! any submission that is not already its canonical root-proof normal form.
//! Both paths check against the accepted pre-transition state and register only
//! after checking succeeds. Blocks, persistence, undo, rewards, networking,
//! and source parsing remain outside this crate.

use std::error::Error;
use std::fmt;

use naome_checker::{
    CheckError, ProofStateError, ProofStateV0, check_normal_form_with_state,
    normalize_and_check_with_state,
};
use naome_proof::{DerivationId, ProofCertificateError, ProofCertificateV0, ProofId, StatementId};

/// The novelty of an accepted proof's closed statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementNoveltyV0 {
    /// The statement was absent from the accepted pre-transition state.
    New,
    /// The statement was present and this distinct derivation was accepted.
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
/// mutation. Each successful authoring or strict-byte admission contributes
/// exactly one checked proof; every failure leaves the state unchanged.
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

    /// Normalizes, checks, and atomically registers exactly one owned proof.
    ///
    /// This is the authoring path for an already constructed certificate. Use
    /// [`Self::apply_canonical_proof_bytes`] when the submitted representation
    /// itself must be canonical.
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
        self.register_checked(checked)
    }

    /// Strictly decodes, checks, and atomically registers one canonical proof.
    ///
    /// The complete input must already equal its canonical root-proof normal
    /// form. A structurally valid but non-canonical submission is rejected
    /// rather than silently rewritten. External references resolve only from
    /// the state that existed before this call.
    pub fn apply_canonical_proof_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<AppliedProofV0, LedgerError> {
        let certificate = ProofCertificateV0::from_canonical_bytes(bytes)
            .map_err(|source| LedgerError::Decode { source })?;
        let normal_form = certificate.into_unchecked_normal_form();
        if normal_form.certificate().to_canonical_bytes() != bytes {
            return Err(LedgerError::NonCanonicalProof);
        }
        let checked = check_normal_form_with_state(normal_form, &self.proof_state)
            .map_err(|source| LedgerError::Check { source })?;
        self.register_checked(checked)
    }

    fn register_checked(
        &mut self,
        checked: naome_checker::CheckedProofV0,
    ) -> Result<AppliedProofV0, LedgerError> {
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
    /// The submitted bytes are not one structurally valid complete certificate.
    Decode { source: ProofCertificateError },
    /// The submitted certificate is not already its root-proof normal form.
    NonCanonicalProof,
    /// Mathematical proof checking failed.
    Check { source: CheckError },
    /// The checked proof could not be registered in the pre-transition state.
    State { source: ProofStateError },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { source } => write!(formatter, "proof decoding failed: {source}"),
            Self::NonCanonicalProof => {
                formatter.write_str("submitted proof is not in canonical root-proof normal form")
            }
            Self::Check { source } => write!(formatter, "proof checking failed: {source}"),
            Self::State { source } => write!(formatter, "proof registration failed: {source}"),
        }
    }
}

impl Error for LedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode { source } => Some(source),
            Self::NonCanonicalProof => None,
            Self::Check { source } => Some(source),
            Self::State { source } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use naome_checker::{
        CheckError, ProofStateError, normalize_and_check, normalize_and_check_with_state,
    };
    use naome_foundation::{Formula, FreeVariable, LogicError, Separation, ZfcAxiom};
    use naome_proof::{
        CERTIFICATE_V0_MAX_BYTES, ProofCertificateError, ProofCertificateV0, ProofId, ProofStepV0,
    };

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

    fn canonical_bytes(certificate: ProofCertificateV0) -> Vec<u8> {
        certificate
            .into_unchecked_normal_form()
            .certificate()
            .to_canonical_bytes()
    }

    fn reordered_identity_detour(variable: FreeVariable) -> ProofCertificateV0 {
        let equality = Formula::equal(variable, variable);
        certificate(vec![
            ProofStepV0::Simplification {
                antecedent: equality.clone(),
                consequent: equality,
            },
            ProofStepV0::EqualityReflexivity { variable },
            ProofStepV0::ModusPonens {
                premise: 1,
                implication: 0,
            },
            ProofStepV0::ModusPonens {
                premise: 1,
                implication: 2,
            },
            ProofStepV0::Generalization {
                premise: 3,
                variable,
            },
        ])
    }

    fn duplicate_identity(variable: FreeVariable) -> ProofCertificateV0 {
        let equality = Formula::equal(variable, variable);
        let identity = Formula::implies(equality.clone(), equality.clone());
        certificate(vec![
            ProofStepV0::EqualityReflexivity { variable },
            ProofStepV0::EqualityReflexivity { variable },
            ProofStepV0::Simplification {
                antecedent: equality.clone(),
                consequent: equality,
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStepV0::ModusPonens {
                premise: 1,
                implication: 2,
            },
            ProofStepV0::Simplification {
                antecedent: identity.clone(),
                consequent: identity,
            },
            ProofStepV0::ModusPonens {
                premise: 3,
                implication: 5,
            },
            ProofStepV0::ModusPonens {
                premise: 4,
                implication: 6,
            },
            ProofStepV0::Generalization {
                premise: 7,
                variable,
            },
        ])
    }

    #[test]
    fn canonical_bytes_match_authoring_admission_and_duplicate_semantics() {
        let variable = FreeVariable::new(42);
        let bytes = canonical_bytes(identity(variable));
        let mut strict = LedgerStateV0::new();
        let strict_applied = strict.apply_canonical_proof_bytes(&bytes).unwrap();

        let mut authoring = LedgerStateV0::new();
        let authoring_applied = authoring.apply(identity(variable)).unwrap();
        assert_eq!(strict_applied, authoring_applied);
        assert_eq!(strict_applied.statement_novelty(), StatementNoveltyV0::New);
        assert_eq!(
            strict.apply_canonical_proof_bytes(&bytes),
            Err(LedgerError::State {
                source: ProofStateError::DuplicateProof {
                    proof_id: strict_applied.proof_id(),
                },
            })
        );
    }

    #[test]
    fn representation_mutations_are_noncanonical_and_atomic() {
        let zero = FreeVariable::new(0);
        let result = FreeVariable::new(3);
        let cases = [
            ("renamed free variable", identity(FreeVariable::new(42))),
            (
                "alternate topological order",
                reordered_identity_detour(zero),
            ),
            (
                "unreachable valid step",
                certificate(vec![
                    ProofStepV0::ZfcAxiom(ZfcAxiom::Pairing),
                    ProofStepV0::EqualityReflexivity { variable: zero },
                    ProofStepV0::Generalization {
                        premise: 1,
                        variable: zero,
                    },
                ]),
            ),
            (
                "unreachable invalid step",
                certificate(vec![
                    ProofStepV0::Separation(Separation {
                        predicate: Formula::equal(result, result),
                        element: FreeVariable::new(1),
                        source: FreeVariable::new(2),
                        result,
                        parameters: Vec::new(),
                    }),
                    ProofStepV0::EqualityReflexivity { variable: zero },
                    ProofStepV0::Generalization {
                        premise: 1,
                        variable: zero,
                    },
                ]),
            ),
            ("reachable duplicate nodes", duplicate_identity(zero)),
        ];

        for (name, certificate) in cases {
            let submitted = certificate.to_canonical_bytes();
            let canonical = canonical_bytes(certificate);
            assert_ne!(submitted, canonical, "{name}");

            let mut ledger = LedgerStateV0::new();
            assert_eq!(
                ledger.apply_canonical_proof_bytes(&submitted),
                Err(LedgerError::NonCanonicalProof),
                "{name}"
            );
            let applied = ledger
                .apply_canonical_proof_bytes(&canonical)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(applied.statement_novelty(), StatementNoveltyV0::New);
        }
    }

    #[test]
    fn decode_errors_precede_canonicality_without_mutation() {
        let valid = canonical_bytes(identity(FreeVariable::new(0)));
        let mut trailing = valid.clone();
        trailing.push(0);
        let over_limit = vec![0; CERTIFICATE_V0_MAX_BYTES + 1];
        let cases = [
            (&[0][..], ProofCertificateError::UnexpectedEnd),
            (
                trailing.as_slice(),
                ProofCertificateError::TrailingBytes { remaining: 1 },
            ),
            (
                over_limit.as_slice(),
                ProofCertificateError::InputTooLong {
                    actual: CERTIFICATE_V0_MAX_BYTES + 1,
                    maximum: CERTIFICATE_V0_MAX_BYTES,
                },
            ),
        ];

        let mut ledger = LedgerStateV0::new();
        for (bytes, source) in cases {
            let error = ledger.apply_canonical_proof_bytes(bytes).unwrap_err();
            assert_eq!(error, LedgerError::Decode { source });
            assert!(error.source().is_some());
        }
        assert_eq!(
            ledger
                .apply_canonical_proof_bytes(&valid)
                .unwrap()
                .statement_novelty(),
            StatementNoveltyV0::New
        );
    }

    #[test]
    fn canonicality_precedes_reachable_reference_checking() {
        let missing = ProofId::from_bytes([0x44; 32]);
        let invalid_inference = canonical_bytes(certificate(vec![
            ProofStepV0::ZfcAxiom(ZfcAxiom::Pairing),
            ProofStepV0::ZfcAxiom(ZfcAxiom::Union),
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]));
        let submitted = certificate(vec![
            ProofStepV0::ZfcAxiom(ZfcAxiom::Pairing),
            ProofStepV0::ProofReference { proof_id: missing },
        ]);
        let canonical = canonical_bytes(submitted.clone());
        let mut ledger = LedgerStateV0::new();

        assert_eq!(
            ledger.apply_canonical_proof_bytes(&submitted.to_canonical_bytes()),
            Err(LedgerError::NonCanonicalProof)
        );
        assert_eq!(
            ledger.apply_canonical_proof_bytes(&canonical),
            Err(LedgerError::Check {
                source: CheckError::UnknownProofReference {
                    step: 0,
                    proof_id: missing,
                },
            })
        );
        assert_eq!(
            ledger.apply_canonical_proof_bytes(&invalid_inference),
            Err(LedgerError::Check {
                source: CheckError::Logic {
                    step: 2,
                    source: LogicError::ModusPonensMismatch,
                },
            })
        );
    }

    #[test]
    fn canonical_five_reference_proof_requires_complete_pre_transition_state() {
        let axioms = [
            ZfcAxiom::Extensionality,
            ZfcAxiom::Pairing,
            ZfcAxiom::Union,
            ZfcAxiom::PowerSet,
            ZfcAxiom::Infinity,
        ];
        let parents = axioms
            .iter()
            .copied()
            .map(|axiom| {
                let proof = certificate(vec![ProofStepV0::ZfcAxiom(axiom)]);
                let proof_id = normalize_and_check(proof.clone()).unwrap().proof_id();
                (canonical_bytes(proof), proof_id, axiom.formula())
            })
            .collect::<Vec<_>>();
        let references = parents
            .iter()
            .map(|(_, proof_id, conclusion)| (*proof_id, conclusion.clone()))
            .collect::<Vec<_>>();
        let target = proof_using_every_reference(&references, ZfcAxiom::Choice);
        let target_bytes = canonical_bytes(target);
        let mut ledger = LedgerStateV0::new();

        for (bytes, _, _) in &parents[..parents.len() - 1] {
            let _ = ledger.apply_canonical_proof_bytes(bytes).unwrap();
        }
        assert_eq!(
            ledger.apply_canonical_proof_bytes(&target_bytes),
            Err(LedgerError::Check {
                source: CheckError::UnknownProofReference {
                    step: 4,
                    proof_id: parents[4].1,
                },
            })
        );

        let _ = ledger.apply_canonical_proof_bytes(&parents[4].0).unwrap();
        let applied = ledger.apply_canonical_proof_bytes(&target_bytes).unwrap();
        assert_eq!(applied.statement_novelty(), StatementNoveltyV0::New);
        assert!(ledger.contains_proof(applied.proof_id()));
    }

    #[test]
    fn absent_and_present_statements_report_state_relative_novelty() {
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
    fn references_resolve_only_from_the_selected_pre_transition_state() {
        let variable = FreeVariable::new(9);
        let mut selected = LedgerStateV0::new();
        let source = selected.apply(identity(variable)).unwrap();
        let dependent = referenced_generalization(source.proof_id(), variable);

        let mut independent = LedgerStateV0::new();
        assert_eq!(
            independent.apply(dependent.clone()),
            Err(LedgerError::Check {
                source: CheckError::UnknownProofReference {
                    step: 0,
                    proof_id: source.proof_id(),
                },
            })
        );
        assert!(!independent.contains_proof(source.proof_id()));

        let applied = selected.apply(dependent).unwrap();
        assert_eq!(applied.statement_novelty(), StatementNoveltyV0::New);
        assert!(selected.contains_proof(applied.proof_id()));
        assert!(!independent.contains_proof(applied.proof_id()));
    }

    #[test]
    fn one_proof_can_use_five_members_of_the_pre_transition_state() {
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

                let accepted = incomplete
                    .apply(certificate(vec![ProofStepV0::ZfcAxiom(axiom)]))
                    .unwrap();
                assert_eq!(accepted.proof_id(), references[index].0);
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
