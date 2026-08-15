use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use naome_foundation::Formula;
use naome_proof::{
    DefinitionCertificate, DefinitionId, DefinitionKind, DefinitionResolution, DefinitionResolver,
    DerivationId, ProofId, ProofStep, StatementId,
};

use crate::{CheckedDefinition, CheckedProof};

/// The already checked proofs and definitions selected by one chain state.
///
/// Resolution is deliberately limited to this in-memory selected set. Candidate,
/// archived, locally authored, and network-visible artifacts cannot be used by
/// mathematical checking until their blocks are selected by the caller.
#[derive(Default)]
#[must_use]
pub struct ArtifactState {
    proofs: BTreeMap<ProofId, DerivationId>,
    derivations: BTreeMap<DerivationId, StatementId>,
    statements: BTreeMap<StatementId, StoredStatement>,
    definitions: BTreeMap<DefinitionId, StoredDefinition>,
}

impl ArtifactState {
    /// Constructs an empty selected-artifact state.
    pub const fn new() -> Self {
        Self {
            proofs: BTreeMap::new(),
            derivations: BTreeMap::new(),
            statements: BTreeMap::new(),
            definitions: BTreeMap::new(),
        }
    }

    /// Returns whether the selected set contains this exact concrete proof.
    pub fn contains_proof(&self, proof_id: ProofId) -> bool {
        self.proofs.contains_key(&proof_id)
    }

    /// Returns whether the selected set contains this derivation.
    pub fn contains_derivation(&self, derivation_id: DerivationId) -> bool {
        self.derivations.contains_key(&derivation_id)
    }

    /// Returns whether the selected set contains this statement.
    pub fn contains_statement(&self, statement_id: StatementId) -> bool {
        self.statements.contains_key(&statement_id)
    }

    /// Returns whether the selected set contains this exact definition.
    pub fn contains_definition(&self, definition_id: DefinitionId) -> bool {
        self.definitions.contains_key(&definition_id)
    }

    /// Returns the kind and proof obligation from the exact selected certificate.
    pub fn definition_kind(&self, definition_id: DefinitionId) -> Option<DefinitionKind> {
        self.definitions
            .get(&definition_id)
            .map(|definition| definition.certificate.kind())
    }

    /// Registers one checked proof without replacing selected state.
    ///
    /// All direct proof and definition dependencies are revalidated so a
    /// checked value cannot be moved from a different selected state unsafely.
    /// Canonical proof bytes not retained by the resolver are returned.
    pub fn register_proof(&mut self, proof: CheckedProof) -> Result<Box<[u8]>, ArtifactStateError> {
        self.validate_proof_registration(&proof)?;

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

    /// Applies the exact proof registration checks without mutating state.
    pub fn validate_proof_registration(
        &self,
        proof: &CheckedProof,
    ) -> Result<(), ArtifactStateError> {
        if let Some(existing_derivation_id) = self.proofs.get(&proof.proof_id).copied() {
            let existing_statement_id = self
                .derivations
                .get(&existing_derivation_id)
                .expect("every registered proof has a registered derivation");
            if existing_derivation_id != proof.derivation_id
                || *existing_statement_id != proof.statement_id
            {
                return Err(ArtifactStateError::ProofIdentityCollision {
                    proof_id: proof.proof_id,
                });
            }
            let existing_statement = self
                .statements
                .get(existing_statement_id)
                .expect("every registered proof has a stored statement");
            return if existing_statement.conclusion == proof.conclusion {
                Err(ArtifactStateError::DuplicateProof {
                    proof_id: proof.proof_id,
                })
            } else {
                Err(ArtifactStateError::StatementIdentityCollision {
                    statement_id: proof.statement_id,
                })
            };
        }

        for step in proof.normal_form.certificate().steps() {
            if let ProofStep::ProofReference { proof_id } = step
                && !self.proofs.contains_key(proof_id)
            {
                return Err(ArtifactStateError::MissingProofDependency {
                    proof_id: *proof_id,
                });
            }
            for definition_id in step.definition_references() {
                if !self.definitions.contains_key(&definition_id) {
                    return Err(ArtifactStateError::MissingDefinitionDependency { definition_id });
                }
            }
        }

        if let Some(existing_statement_id) = self.derivations.get(&proof.derivation_id) {
            if *existing_statement_id != proof.statement_id {
                return Err(ArtifactStateError::DerivationIdentityCollision {
                    derivation_id: proof.derivation_id,
                });
            }
            let existing_statement = self
                .statements
                .get(existing_statement_id)
                .expect("every registered derivation has a stored statement");
            return if existing_statement.conclusion == proof.conclusion {
                Err(ArtifactStateError::DuplicateDerivation {
                    derivation_id: proof.derivation_id,
                })
            } else {
                Err(ArtifactStateError::StatementIdentityCollision {
                    statement_id: proof.statement_id,
                })
            };
        }

        if let Some(existing_statement) = self.statements.get(&proof.statement_id)
            && existing_statement.conclusion != proof.conclusion
        {
            return Err(ArtifactStateError::StatementIdentityCollision {
                statement_id: proof.statement_id,
            });
        }
        Ok(())
    }

    /// Registers one checked definition without replacing selected state.
    ///
    /// The resolver retains a definition-free expansion cache, preventing
    /// repeated transitive expansion during every later proof step.
    pub fn register_definition(
        &mut self,
        definition: CheckedDefinition,
    ) -> Result<(), ArtifactStateError> {
        self.validate_definition_registration(&definition)?;
        let CheckedDefinition {
            certificate,
            definition_id,
            expansion_cache,
        } = definition;
        self.definitions.insert(
            definition_id,
            StoredDefinition {
                certificate,
                expansion_cache,
            },
        );
        Ok(())
    }

    /// Applies the exact definition registration checks without mutating state.
    ///
    /// Duplicate/collision checks precede dependency checks. Direct definition
    /// references are checked in canonical prefix order, followed by the exact
    /// selected proof obligation for constants and functions.
    pub fn validate_definition_registration(
        &self,
        definition: &CheckedDefinition,
    ) -> Result<(), ArtifactStateError> {
        if let Some(existing) = self.definitions.get(&definition.definition_id) {
            return if existing.certificate == definition.certificate {
                Err(ArtifactStateError::DuplicateDefinition {
                    definition_id: definition.definition_id,
                })
            } else {
                Err(ArtifactStateError::DefinitionIdentityCollision {
                    definition_id: definition.definition_id,
                })
            };
        }
        for dependency_id in definition.certificate.body().definition_references() {
            if !self.definitions.contains_key(&dependency_id) {
                return Err(ArtifactStateError::MissingDefinitionDependency {
                    definition_id: dependency_id,
                });
            }
        }
        if let Some(proof_id) = definition.certificate.obligation_proof_id()
            && !self.proofs.contains_key(&proof_id)
        {
            return Err(ArtifactStateError::MissingDefinitionObligation { proof_id });
        }
        Ok(())
    }

    pub(crate) fn resolve_proof(&self, proof_id: ProofId) -> Option<ResolvedProof<'_>> {
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

struct StoredDefinition {
    certificate: DefinitionCertificate,
    expansion_cache: DefinitionCertificate,
}

pub(crate) struct ResolvedProof<'a> {
    pub(crate) conclusion: &'a Formula,
    pub(crate) canonical_length: usize,
    pub(crate) derivation_id: DerivationId,
}

impl DefinitionResolver for ArtifactState {
    fn resolve_definition(&self, definition_id: DefinitionId) -> Option<DefinitionResolution<'_>> {
        self.definitions.get(&definition_id).map(|definition| {
            DefinitionResolution::new(
                definition.expansion_cache.relation_arity(),
                definition.expansion_cache.body(),
            )
        })
    }
}

/// A fail-closed selected-artifact registration failure.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactStateError {
    /// The selected concrete proof is already registered.
    DuplicateProof { proof_id: ProofId },
    /// The selected inference DAG is already registered under another proof.
    DuplicateDerivation { derivation_id: DerivationId },
    /// One proof digest would identify conflicting checked records.
    ProofIdentityCollision { proof_id: ProofId },
    /// One derivation digest would identify conflicting checked statements.
    DerivationIdentityCollision { derivation_id: DerivationId },
    /// One statement digest would identify structurally different conclusions.
    StatementIdentityCollision { statement_id: StatementId },
    /// The selected definition is already registered.
    DuplicateDefinition { definition_id: DefinitionId },
    /// One definition digest would identify conflicting certificates.
    DefinitionIdentityCollision { definition_id: DefinitionId },
    /// A cited proof is absent from selected state.
    MissingProofDependency { proof_id: ProofId },
    /// A cited definition is absent from selected state.
    MissingDefinitionDependency { definition_id: DefinitionId },
    /// A definition's exact proof obligation is absent from selected state.
    MissingDefinitionObligation { proof_id: ProofId },
}

impl fmt::Display for ArtifactStateError {
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
            Self::DuplicateDefinition { .. } => {
                formatter.write_str("checked definition is already registered")
            }
            Self::DefinitionIdentityCollision { .. } => {
                formatter.write_str("definition identity resolves to conflicting certificates")
            }
            Self::MissingProofDependency { .. } => {
                formatter.write_str("checked proof cites a proof absent from selected state")
            }
            Self::MissingDefinitionDependency { .. } => formatter
                .write_str("checked artifact cites a definition absent from selected state"),
            Self::MissingDefinitionObligation { .. } => formatter
                .write_str("checked definition requires a proof absent from selected state"),
        }
    }
}

impl Error for ArtifactStateError {}

#[cfg(test)]
mod tests;
