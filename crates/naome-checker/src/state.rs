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

    /// Runs one synchronous checked-proof transaction without committing it.
    ///
    /// Registrations made through `operation` resolve earlier registrations in
    /// the same transaction exactly as in [`Self::apply_batch`], but the staged
    /// state is discarded on both success and failure.
    pub fn validate_batch<E>(
        &self,
        operation: impl FnOnce(&mut ProofStateBatch<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut staged = Self::new();
        operation(&mut ProofStateBatch {
            base: self,
            staged: &mut staged,
        })
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
/// Values of this type are created only by [`ProofState::apply_batch`] and
/// [`ProofState::validate_batch`]. The transaction has no independent commit
/// operation: its enclosing method alone decides whether successful staged
/// registrations are committed or discarded.
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
mod tests;
