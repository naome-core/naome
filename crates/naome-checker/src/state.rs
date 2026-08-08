use std::collections::{BTreeMap, btree_map::Entry};
use std::error::Error;
use std::fmt;

use naome_foundation::Formula;
use naome_proof::{ProofId, ProofStepV0, StatementId};

use crate::CheckedProofV0;

/// The checked proof conclusions available to resolve external references.
///
/// This in-memory state can only be extended with [`CheckedProofV0`] values.
/// It stores each closed conclusion once per [`StatementId`] while retaining
/// every distinct [`ProofId`] that may be cited. Blocks, persistence, reorgs,
/// and network synchronization are deliberately outside this type.
#[derive(Default)]
#[must_use]
pub struct ProofStateV0 {
    proofs: BTreeMap<ProofId, StatementId>,
    statements: BTreeMap<StatementId, StoredStatementV0>,
}

impl ProofStateV0 {
    /// Constructs an empty checked-proof state.
    pub const fn new() -> Self {
        Self {
            proofs: BTreeMap::new(),
            statements: BTreeMap::new(),
        }
    }

    /// Returns whether the state already contains the selected concrete proof.
    pub fn contains_proof(&self, proof_id: ProofId) -> bool {
        self.proofs.contains_key(&proof_id)
    }

    /// Registers one checked proof without replacing existing state.
    ///
    /// Every external proof cited by the checked normal form must already be
    /// present. This keeps the registry dependency-closed even when a checked
    /// proof is moved from a different state.
    pub fn register(&mut self, proof: CheckedProofV0) -> Result<(), ProofStateError> {
        if let Some(existing_statement_id) = self.proofs.get(&proof.proof_id) {
            return if *existing_statement_id == proof.statement_id {
                Err(ProofStateError::DuplicateProof {
                    proof_id: proof.proof_id,
                })
            } else {
                Err(ProofStateError::ProofIdentityCollision {
                    proof_id: proof.proof_id,
                })
            };
        }

        for step in proof.normal_form.certificate().steps() {
            if let ProofStepV0::ProofReference { proof_id } = step
                && !self.proofs.contains_key(proof_id)
            {
                return Err(ProofStateError::MissingProofDependency {
                    proof_id: *proof_id,
                });
            }
        }

        let CheckedProofV0 {
            normal_form: _,
            conclusion,
            statement_id,
            proof_id,
            canonical_conclusion_length,
        } = proof;

        match self.statements.entry(statement_id) {
            Entry::Occupied(entry) if entry.get().conclusion != conclusion => {
                return Err(ProofStateError::StatementIdentityCollision { statement_id });
            }
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                entry.insert(StoredStatementV0 {
                    conclusion,
                    canonical_length: canonical_conclusion_length,
                });
            }
        }
        self.proofs.insert(proof_id, statement_id);

        Ok(())
    }

    pub(crate) fn resolve(&self, proof_id: ProofId) -> Option<ResolvedProofV0<'_>> {
        let statement_id = self.proofs.get(&proof_id)?;
        let statement = self
            .statements
            .get(statement_id)
            .expect("every registered proof has a stored statement");
        Some(ResolvedProofV0 {
            conclusion: &statement.conclusion,
            canonical_length: statement.canonical_length,
        })
    }
}

struct StoredStatementV0 {
    conclusion: Formula,
    canonical_length: usize,
}

pub(crate) struct ResolvedProofV0<'a> {
    pub(crate) conclusion: &'a Formula,
    pub(crate) canonical_length: usize,
}

/// A fail-closed checked-proof state registration failure.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofStateError {
    /// The selected concrete proof is already registered.
    DuplicateProof { proof_id: ProofId },
    /// One proof digest would identify checked records for different statements.
    ProofIdentityCollision { proof_id: ProofId },
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
            Self::ProofIdentityCollision { .. } => {
                formatter.write_str("proof identity resolves to conflicting checked records")
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
    use naome_foundation::{Formula, FreeVariable};
    use naome_proof::{ProofCertificateV0, ProofStepV0};

    use super::{ProofStateError, ProofStateV0};
    use crate::normalize_and_check;

    fn certificate(steps: Vec<ProofStepV0>) -> ProofCertificateV0 {
        ProofCertificateV0::new(steps).unwrap()
    }

    fn direct_identity(variable: FreeVariable) -> crate::CheckedProofV0 {
        normalize_and_check(certificate(vec![
            ProofStepV0::EqualityReflexivity { variable },
            ProofStepV0::Generalization {
                premise: 0,
                variable,
            },
        ]))
        .unwrap()
    }

    #[test]
    fn alternative_proofs_share_one_stored_conclusion() {
        let x = FreeVariable::new(7);
        let direct = direct_identity(x);
        let formula = Formula::equal(x, x);
        let detour = normalize_and_check(certificate(vec![
            ProofStepV0::EqualityReflexivity { variable: x },
            ProofStepV0::Simplification {
                antecedent: formula.clone(),
                consequent: formula,
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
                variable: x,
            },
        ]))
        .unwrap();
        assert_eq!(direct.statement_id, detour.statement_id);
        assert_ne!(direct.proof_id, detour.proof_id);

        let mut state = ProofStateV0::new();
        state.register(direct).unwrap();
        state.register(detour).unwrap();

        assert_eq!(state.proofs.len(), 2);
        assert_eq!(state.statements.len(), 1);
    }

    #[test]
    fn identity_collisions_fail_closed_without_mutating_state() {
        let x = FreeVariable::new(1);
        let original = direct_identity(x);
        let original_proof_id = original.proof_id;
        let original_statement_id = original.statement_id;
        let mut state = ProofStateV0::new();
        state.register(original).unwrap();

        let mut conflicting_proof = normalize_and_check(certificate(vec![
            ProofStepV0::EqualityReflexivity { variable: x },
            ProofStepV0::Generalization {
                premise: 0,
                variable: x,
            },
            ProofStepV0::Generalization {
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

        let mut conflicting_statement =
            normalize_and_check(certificate(vec![ProofStepV0::ZfcAxiom(
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
        assert_eq!(state.statements.len(), 1);
        assert!(!state.contains_proof(conflicting_proof_id));
    }
}
