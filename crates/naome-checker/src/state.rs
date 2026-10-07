use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;

use naome_foundation::Formula;
use naome_proof::{
    DefinitionCertificate, DefinitionId, DefinitionKind, DefinitionResolution, DefinitionResolver,
    DerivationId, ProofId, ProofStep, StatementId,
};

use crate::{CheckedDefinition, CheckedProof, question::index::KnowledgeIndex};

pub(crate) mod persistent_map;

use persistent_map::{Key256, PersistentMap};

macro_rules! impl_key256 {
    ($($key:ty),+ $(,)?) => {
        $(
            impl Key256 for $key {
                fn as_key_bytes(&self) -> &[u8; 32] {
                    self.as_bytes()
                }
            }
        )+
    };
}

impl_key256!(
    ProofId,
    DerivationId,
    StatementId,
    DefinitionId,
    naome_proof::ArtifactId
);

impl Key256 for [u8; 32] {
    fn as_key_bytes(&self) -> &[u8; 32] {
        self
    }
}

/// The already checked proofs and definitions selected by one chain state.
///
/// Resolution is deliberately limited to this in-memory selected set. Candidate,
/// archived, locally authored, and network-visible artifacts require explicit
/// checked registration before mathematical dependency resolution. Chain callers
/// register only artifacts from their selected blocks. An economy-free replicated
/// graph may instead use [`Self::register_proof_for_replication`]; that mathematical
/// context establishes no chain selection, finality, provenance, or rewards.
/// Cloning is constant-time: immutable resolver nodes remain shared, and every
/// later successful registration copies only the changed Patricia paths.
/// An explicitly temporary original-group verification branch may use
/// [`Self::register_proof_for_verification`] to resolve checked but unselected
/// aliases. Such a branch must never become the selected publication state.
#[derive(Clone, Default)]
#[must_use]
pub struct ArtifactState {
    proofs: PersistentMap<ProofId, DerivationId>,
    derivations: PersistentMap<DerivationId, StatementId>,
    statements: PersistentMap<StatementId, StoredStatement>,
    definitions: PersistentMap<DefinitionId, StoredDefinition>,
    pub(crate) question_index: KnowledgeIndex,
}

impl ArtifactState {
    /// Constructs an empty selected-artifact state.
    pub const fn new() -> Self {
        Self {
            proofs: PersistentMap::new(),
            derivations: PersistentMap::new(),
            statements: PersistentMap::new(),
            definitions: PersistentMap::new(),
            question_index: KnowledgeIndex::new(),
        }
    }

    /// Identifies the complete registered checked artifact set in constant time.
    /// The cached Patricia roots bind all proof/definition content identities,
    /// independently of arrival order. No selected-history authority is implied.
    pub fn snapshot_id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"naome:checked-artifact-snapshot:v1\0");
        hash.update(self.proofs.fingerprint());
        hash.update(self.definitions.fingerprint());
        hash.finalize().into()
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

    /// Borrows every registered concrete proof's checker-owned conclusion.
    ///
    /// Iteration is ascending by ProofId and performs no proof checking or
    /// mutation. Consumers must bound and exhaust their declared comparison
    /// scope; an unfinished iteration cannot establish absence of knowledge.
    pub fn proof_conclusions(
        &self,
    ) -> impl Iterator<Item = (ProofId, StatementId, &Formula, usize)> {
        self.proofs.entries().map(|(proof_id, derivation_id)| {
            let statement_id = *self
                .derivations
                .get(derivation_id)
                .expect("registered derivation");
            let statement = self
                .statements
                .get(&statement_id)
                .expect("registered statement");
            (
                *proof_id,
                statement_id,
                &statement.conclusion,
                statement.canonical_length,
            )
        })
    }

    /// Borrows the identities of all registered conservative definitions.
    pub fn definition_ids(&self) -> impl Iterator<Item = DefinitionId> + '_ {
        self.definitions.entries().map(|(id, _)| *id)
    }

    /// Returns the graph kind from the exact selected certificate.
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

        self.question_index
            .register_proof(proof_id, statement_id, &conclusion);
        self.statements.insert(
            statement_id,
            StoredStatement {
                conclusion,
                canonical_length: canonical_conclusion_length,
            },
        );
        let inserted = self.derivations.insert(derivation_id, statement_id);
        debug_assert!(inserted);
        let inserted = self.proofs.insert(proof_id, derivation_id);
        debug_assert!(inserted);

        Ok(normal_form.into_canonical_bytes())
    }

    /// Registers a checked reference in a temporary verification context.
    ///
    /// An original proof group may cite two different certificates of the same
    /// derivation before its admission policy replaces one with an older proof.
    /// This method permits that alias only after the ordinary registration
    /// checks establish identical derivation, statement, and actual conclusion,
    /// and verify every required proof and definition dependency. It adds only
    /// the new concrete ProofId; existing conclusions and identities stay intact.
    ///
    /// This is mathematical verification, not selection or publication. Use a
    /// temporary resolver and discard it after checking the original group.
    /// Selected-state admission must continue to use [`Self::register_proof`],
    /// which still rejects duplicate derivations. Do not publish this resolver.
    pub fn register_proof_for_verification(
        &mut self,
        proof: CheckedProof,
    ) -> Result<Box<[u8]>, ArtifactStateError> {
        self.register_proof_for_replication(proof)
    }

    /// Registers a checked concrete proof in an economy-free mathematical graph.
    ///
    /// Distinct certificates for the same derivation coexist without replacing
    /// immutable references. Every identity, conclusion and dependency check is
    /// preserved. This API grants dependency resolution only; ledger callers must
    /// retain [`Self::register_proof`] and its duplicate-derivation policy.
    pub fn register_proof_for_replication(
        &mut self,
        proof: CheckedProof,
    ) -> Result<Box<[u8]>, ArtifactStateError> {
        match self.validate_proof_registration(&proof) {
            Err(ArtifactStateError::DuplicateDerivation { .. }) => {
                self.question_index.register_proof(
                    proof.proof_id,
                    proof.statement_id,
                    &proof.conclusion,
                );
                let inserted = self.proofs.insert(proof.proof_id, proof.derivation_id);
                debug_assert!(inserted);
                Ok(proof.normal_form.into_canonical_bytes())
            }
            Err(error) => Err(error),
            Ok(()) => self.register_proof(proof),
        }
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
    /// The retained canonical certificate already contains a definition-free body.
    pub fn register_definition(
        &mut self,
        definition: CheckedDefinition,
    ) -> Result<(), ArtifactStateError> {
        self.validate_definition_registration(&definition)?;
        let CheckedDefinition {
            certificate,
            definition_id,
            obligation: _,
        } = definition;
        self.question_index.register_definition(definition_id);
        let inserted = self
            .definitions
            .insert(definition_id, StoredDefinition { certificate });
        debug_assert!(inserted);
        Ok(())
    }

    /// Applies the exact definition registration checks without mutating state.
    ///
    /// Duplicate/collision checks precede the exact computed function-obligation
    /// statement check.
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
        if let Some(obligation) = &definition.obligation {
            let Some(selected) = self.statements.get(&obligation.statement_id) else {
                return Err(ArtifactStateError::MissingDefinitionObligation {
                    statement_id: obligation.statement_id,
                });
            };
            if selected.conclusion != obligation.conclusion {
                return Err(ArtifactStateError::StatementIdentityCollision {
                    statement_id: obligation.statement_id,
                });
            }
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

    pub(crate) fn known_statement(
        &self,
        statement_id: StatementId,
    ) -> Option<(ProofId, &Formula, usize)> {
        let stored = self.statements.get(&statement_id)?;
        let witness = *self.question_index.witness(statement_id)?;
        Some((witness, &stored.conclusion, stored.canonical_length))
    }

    pub(crate) fn resolve_statement(&self, statement_id: StatementId) -> Option<&Formula> {
        self.statements
            .get(&statement_id)
            .map(|statement| &statement.conclusion)
    }
}

struct StoredStatement {
    conclusion: Formula,
    canonical_length: usize,
}

struct StoredDefinition {
    certificate: DefinitionCertificate,
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
                definition.certificate.relation_arity(),
                definition.certificate.body(),
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
    /// A function's computed obligation statement is absent from selected state.
    MissingDefinitionObligation { statement_id: StatementId },
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
                .write_str("checked definition requires a statement absent from selected state"),
        }
    }
}

impl Error for ArtifactStateError {}

#[cfg(test)]
mod tests;
