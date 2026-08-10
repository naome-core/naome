use std::collections::{BTreeMap, btree_map::Entry};
use std::error::Error;
use std::fmt;

use naome_foundation::Formula;
use naome_proof::{DerivationId, ProofId, ProofStep, StatementId};

use crate::{CheckError, CheckedProof};

/// The checked proof conclusions available to resolve external references.
///
/// This in-memory state can only be extended with [`CheckedProof`] values.
/// It stores each closed conclusion once per [`StatementId`] while retaining
/// one concrete [`ProofId`] for every distinct checked derivation that may be
/// cited. Blocks, persistence, reorgs, and network synchronization are
/// deliberately outside this type.
#[derive(Default)]
#[must_use]
pub struct ProofState {
    proofs: BTreeMap<ProofId, DerivationId>,
    derivations: BTreeMap<DerivationId, StatementId>,
    statements: BTreeMap<StatementId, StoredStatement>,
}

impl ProofState {
    /// Constructs an empty checked-proof state.
    pub const fn new() -> Self {
        Self {
            proofs: BTreeMap::new(),
            derivations: BTreeMap::new(),
            statements: BTreeMap::new(),
        }
    }

    /// Returns whether the state already contains the selected concrete proof.
    pub fn contains_proof(&self, proof_id: ProofId) -> bool {
        self.proofs.contains_key(&proof_id)
    }

    /// Returns whether the state already contains the selected derivation.
    pub fn contains_derivation(&self, derivation_id: DerivationId) -> bool {
        self.derivations.contains_key(&derivation_id)
    }

    /// Returns whether the state already contains the selected statement.
    pub fn contains_statement(&self, statement_id: StatementId) -> bool {
        self.statements.contains_key(&statement_id)
    }

    /// Registers one checked proof without replacing existing state.
    ///
    /// Every external proof cited by the checked normal form must already be
    /// present. This keeps the registry dependency-closed even when a checked
    /// proof is moved from a different state. On success, the canonical proof
    /// bytes not retained by this resolver state are returned to the caller.
    pub fn register(&mut self, proof: CheckedProof) -> Result<Box<[u8]>, ProofStateError> {
        let empty = Self::new();
        ProofStateBatch {
            base: &empty,
            staged: self,
        }
        .register(proof)
    }

    /// Runs one synchronous checked-proof transaction against this state.
    ///
    /// Registrations made through `operation` resolve earlier registrations in
    /// the same transaction but remain invisible in this state until the
    /// operation succeeds. An error drops the complete staged transaction.
    pub fn apply_batch<T, E>(
        &mut self,
        operation: impl FnOnce(&mut ProofStateBatch<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut staged = Self::new();
        let result = {
            let mut batch = ProofStateBatch {
                base: self,
                staged: &mut staged,
            };
            operation(&mut batch)?
        };
        for (statement_id, statement) in staged.statements {
            match self.statements.entry(statement_id) {
                Entry::Vacant(entry) => {
                    entry.insert(statement);
                }
                Entry::Occupied(_) => unreachable!("validated batch statements are new"),
            }
        }
        for (derivation_id, statement_id) in staged.derivations {
            match self.derivations.entry(derivation_id) {
                Entry::Vacant(entry) => {
                    entry.insert(statement_id);
                }
                Entry::Occupied(_) => unreachable!("validated batch derivations are new"),
            }
        }
        for (proof_id, derivation_id) in staged.proofs {
            match self.proofs.entry(proof_id) {
                Entry::Vacant(entry) => {
                    entry.insert(derivation_id);
                }
                Entry::Occupied(_) => unreachable!("validated batch proofs are new"),
            }
        }
        Ok(result)
    }

    fn resolve(&self, proof_id: ProofId) -> Option<ResolvedProof<'_>> {
        let derivation_id = *self.proofs.get(&proof_id)?;
        let statement_id = self
            .derivations
            .get(&derivation_id)
            .expect("every registered proof has a registered derivation");
        let statement = self
            .statements
            .get(statement_id)
            .expect("every registered proof has a stored statement");
        Some(ResolvedProof {
            conclusion: &statement.conclusion,
            canonical_length: statement.canonical_length,
            derivation_id,
        })
    }
}

/// A non-escapable checked-proof transaction over one immutable base state.
///
/// Values of this type are created only by [`ProofState::apply_batch`]. The
/// transaction has no independent commit operation: returning success from
/// the enclosing callback commits it, while returning an error drops it.
pub struct ProofStateBatch<'a> {
    base: &'a ProofState,
    staged: &'a mut ProofState,
}

impl ProofStateBatch<'_> {
    /// Checks one canonical proof against the base plus earlier staged proofs.
    pub fn check_normal_form(
        &self,
        normal_form: naome_proof::ProofNormalForm,
    ) -> Result<CheckedProof, CheckError> {
        crate::check_normal_form_with_resolver(normal_form, self)
    }

    /// Stages one checked proof without replacing existing transaction state.
    pub fn register(&mut self, proof: CheckedProof) -> Result<Box<[u8]>, ProofStateError> {
        if let Some(existing_derivation_id) = self.proof_derivation(proof.proof_id) {
            let existing_statement_id = self
                .derivation_statement(existing_derivation_id)
                .expect("every registered proof has a registered derivation");
            if existing_derivation_id != proof.derivation_id
                || existing_statement_id != proof.statement_id
            {
                return Err(ProofStateError::ProofIdentityCollision {
                    proof_id: proof.proof_id,
                });
            }
            let existing_statement = self
                .statement(existing_statement_id)
                .expect("every registered proof has a stored statement");
            return if existing_statement.conclusion == proof.conclusion {
                Err(ProofStateError::DuplicateProof {
                    proof_id: proof.proof_id,
                })
            } else {
                Err(ProofStateError::StatementIdentityCollision {
                    statement_id: proof.statement_id,
                })
            };
        }

        for step in proof.normal_form.certificate().steps() {
            if let ProofStep::ProofReference { proof_id } = step
                && self.proof_derivation(*proof_id).is_none()
            {
                return Err(ProofStateError::MissingProofDependency {
                    proof_id: *proof_id,
                });
            }
        }

        if let Some(existing_statement_id) = self.derivation_statement(proof.derivation_id) {
            if existing_statement_id != proof.statement_id {
                return Err(ProofStateError::DerivationIdentityCollision {
                    derivation_id: proof.derivation_id,
                });
            }
            let existing_statement = self
                .statement(existing_statement_id)
                .expect("every registered derivation has a stored statement");
            return if existing_statement.conclusion == proof.conclusion {
                Err(ProofStateError::DuplicateDerivation {
                    derivation_id: proof.derivation_id,
                })
            } else {
                Err(ProofStateError::StatementIdentityCollision {
                    statement_id: proof.statement_id,
                })
            };
        }

        let CheckedProof {
            normal_form,
            conclusion,
            statement_id,
            derivation_id,
            proof_id,
            canonical_conclusion_length,
        } = proof;

        if let Some(existing_statement) = self.statement(statement_id) {
            if existing_statement.conclusion != conclusion {
                return Err(ProofStateError::StatementIdentityCollision { statement_id });
            }
        } else {
            self.staged.statements.insert(
                statement_id,
                StoredStatement {
                    conclusion,
                    canonical_length: canonical_conclusion_length,
                },
            );
        }
        self.staged.derivations.insert(derivation_id, statement_id);
        self.staged.proofs.insert(proof_id, derivation_id);

        Ok(normal_form.into_canonical_bytes())
    }

    fn proof_derivation(&self, proof_id: ProofId) -> Option<DerivationId> {
        self.staged
            .proofs
            .get(&proof_id)
            .or_else(|| self.base.proofs.get(&proof_id))
            .copied()
    }

    fn derivation_statement(&self, derivation_id: DerivationId) -> Option<StatementId> {
        self.staged
            .derivations
            .get(&derivation_id)
            .or_else(|| self.base.derivations.get(&derivation_id))
            .copied()
    }

    fn statement(&self, statement_id: StatementId) -> Option<&StoredStatement> {
        self.staged
            .statements
            .get(&statement_id)
            .or_else(|| self.base.statements.get(&statement_id))
    }
}

struct StoredStatement {
    conclusion: Formula,
    canonical_length: usize,
}

pub(crate) struct ResolvedProof<'a> {
    pub(crate) conclusion: &'a Formula,
    pub(crate) canonical_length: usize,
    pub(crate) derivation_id: DerivationId,
}

pub(crate) trait ProofResolver {
    fn resolve(&self, proof_id: ProofId) -> Option<ResolvedProof<'_>>;
}

impl ProofResolver for ProofState {
    fn resolve(&self, proof_id: ProofId) -> Option<ResolvedProof<'_>> {
        self.resolve(proof_id)
    }
}

impl ProofResolver for ProofStateBatch<'_> {
    fn resolve(&self, proof_id: ProofId) -> Option<ResolvedProof<'_>> {
        let derivation_id = self.proof_derivation(proof_id)?;
        let statement_id = self
            .derivation_statement(derivation_id)
            .expect("every registered proof has a registered derivation");
        let statement = self
            .statement(statement_id)
            .expect("every registered proof has a stored statement");
        Some(ResolvedProof {
            conclusion: &statement.conclusion,
            canonical_length: statement.canonical_length,
            derivation_id,
        })
    }
}

/// A fail-closed checked-proof state registration failure.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofStateError {
    /// The selected concrete proof is already registered.
    DuplicateProof { proof_id: ProofId },
    /// The selected inference DAG is already registered under another proof.
    DuplicateDerivation { derivation_id: DerivationId },
    /// One proof digest would identify conflicting checked derivations or statements.
    ProofIdentityCollision { proof_id: ProofId },
    /// One derivation digest would identify checked records for different statements.
    DerivationIdentityCollision { derivation_id: DerivationId },
    /// One digest would identify two structurally different conclusions.
    StatementIdentityCollision { statement_id: StatementId },
    /// A cited proof is absent from this state.
    MissingProofDependency { proof_id: ProofId },
}

impl fmt::Display for ProofStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateProof { .. } => {
                formatter.write_str("checked proof is already registered")
            }
            Self::DuplicateDerivation { .. } => {
                formatter.write_str("checked derivation is already registered")
            }
            Self::ProofIdentityCollision { .. } => {
                formatter.write_str("proof identity resolves to conflicting checked records")
            }
            Self::DerivationIdentityCollision { .. } => {
                formatter.write_str("derivation identity resolves to conflicting checked records")
            }
            Self::StatementIdentityCollision { .. } => {
                formatter.write_str("statement identity resolves to conflicting conclusions")
            }
            Self::MissingProofDependency { .. } => {
                formatter.write_str("checked proof cites a proof absent from this state")
            }
        }
    }
}

impl Error for ProofStateError {}

#[cfg(test)]
mod tests {
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

        let mut conflicting_statement =
            normalize_and_check(certificate(vec![ProofStep::ZfcAxiom(
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
}
