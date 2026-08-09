use std::collections::{BTreeMap, btree_map::Entry};
use std::error::Error;
use std::fmt;

use naome_foundation::Formula;
use naome_proof::{DerivationId, ProofId, ProofStepV0, StatementId};

use crate::CheckedProofV0;

/// The checked proof conclusions available to resolve external references.
///
/// This in-memory state can only be extended with [`CheckedProofV0`] values.
/// It stores each closed conclusion once per [`StatementId`] while retaining
/// one concrete [`ProofId`] for every distinct checked derivation that may be
/// cited. Blocks, persistence, reorgs, and network synchronization are
/// deliberately outside this type.
#[derive(Default)]
#[must_use]
pub struct ProofStateV0 {
    proofs: BTreeMap<ProofId, DerivationId>,
    derivations: BTreeMap<DerivationId, StatementId>,
    statements: BTreeMap<StatementId, StoredStatementV0>,
}

impl ProofStateV0 {
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
    pub fn register(&mut self, proof: CheckedProofV0) -> Result<Box<[u8]>, ProofStateError> {
        if let Some(existing_derivation_id) = self.proofs.get(&proof.proof_id) {
            let existing_statement_id = self
                .derivations
                .get(existing_derivation_id)
                .expect("every registered proof has a registered derivation");
            if *existing_derivation_id != proof.derivation_id
                || *existing_statement_id != proof.statement_id
            {
                return Err(ProofStateError::ProofIdentityCollision {
                    proof_id: proof.proof_id,
                });
            }
            let existing_statement = self
                .statements
                .get(existing_statement_id)
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
            if let ProofStepV0::ProofReference { proof_id } = step
                && !self.proofs.contains_key(proof_id)
            {
                return Err(ProofStateError::MissingProofDependency {
                    proof_id: *proof_id,
                });
            }
        }

        if let Some(existing_statement_id) = self.derivations.get(&proof.derivation_id) {
            if *existing_statement_id != proof.statement_id {
                return Err(ProofStateError::DerivationIdentityCollision {
                    derivation_id: proof.derivation_id,
                });
            }
            let existing_statement = self
                .statements
                .get(existing_statement_id)
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

        let CheckedProofV0 {
            normal_form,
            conclusion,
            statement_id,
            derivation_id,
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
        self.derivations.insert(derivation_id, statement_id);
        self.proofs.insert(proof_id, derivation_id);

        Ok(normal_form.into_canonical_bytes())
    }

    pub(crate) fn resolve(&self, proof_id: ProofId) -> Option<ResolvedProofV0<'_>> {
        let derivation_id = *self.proofs.get(&proof_id)?;
        let statement_id = self
            .derivations
            .get(&derivation_id)
            .expect("every registered proof has a registered derivation");
        let statement = self
            .statements
            .get(statement_id)
            .expect("every registered proof has a stored statement");
        Some(ResolvedProofV0 {
            conclusion: &statement.conclusion,
            canonical_length: statement.canonical_length,
            derivation_id,
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
    pub(crate) derivation_id: DerivationId,
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
        assert_ne!(direct.derivation_id, detour.derivation_id);
        assert_ne!(direct.proof_id, detour.proof_id);
        let direct_derivation_id = direct.derivation_id;
        let detour_derivation_id = detour.derivation_id;

        let mut state = ProofStateV0::new();
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
        let mut state = ProofStateV0::new();
        state.register(original).unwrap();
        let different_conclusion = || {
            normalize_and_check(certificate(vec![ProofStepV0::ZfcAxiom(
                naome_foundation::ZfcAxiom::Pairing,
            )]))
            .unwrap()
        };

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
            ProofStepV0::EqualityReflexivity { variable: x },
            ProofStepV0::Simplification {
                antecedent: Formula::equal(x, x),
                consequent: Formula::equal(x, x),
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
        assert_eq!(state.derivations.len(), 1);
        assert_eq!(state.statements.len(), 1);
        assert!(!state.contains_proof(conflicting_proof_id));
        assert!(!state.contains_proof(duplicate_derivation_proof_id));
        assert!(!state.contains_proof(forged_derivation_proof_id));
        assert!(!state.contains_proof(conflicting_derivation_proof_id));
    }
}
