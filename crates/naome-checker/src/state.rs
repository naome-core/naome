use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use naome_foundation::Formula;
use naome_proof::{DerivationId, ProofId, ProofStep, StatementId};

use crate::CheckedProof;

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
        self.validate_registration(&proof)?;

        let CheckedProof {
            normal_form,
            conclusion,
            statement_id,
            derivation_id,
            proof_id,
            canonical_conclusion_length,
        } = proof;

        self.statements
            .entry(statement_id)
            .or_insert(StoredStatement {
                conclusion,
                canonical_length: canonical_conclusion_length,
            });
        self.derivations.insert(derivation_id, statement_id);
        self.proofs.insert(proof_id, derivation_id);

        Ok(normal_form.into_canonical_bytes())
    }

    /// Validates whether one checked proof could be registered without
    /// mutating this state.
    ///
    /// This applies the exact duplicate, collision, and dependency checks used
    /// by [`Self::register`] without allocating temporary registry entries.
    pub fn validate_registration(&self, proof: &CheckedProof) -> Result<(), ProofStateError> {
        if let Some(existing_derivation_id) = self.proofs.get(&proof.proof_id).copied() {
            let existing_statement_id = self
                .derivations
                .get(&existing_derivation_id)
                .expect("every registered proof has a registered derivation");
            if existing_derivation_id != proof.derivation_id
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
            if let ProofStep::ProofReference { proof_id } = step
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

        if let Some(existing_statement) = self.statements.get(&proof.statement_id)
            && existing_statement.conclusion != proof.conclusion
        {
            return Err(ProofStateError::StatementIdentityCollision {
                statement_id: proof.statement_id,
            });
        }
        Ok(())
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
mod tests;
