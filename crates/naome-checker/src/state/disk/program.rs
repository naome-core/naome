//! Bounded registration of a complete checked program into the common context.
use super::*;
use crate::program::CheckedProgram;
use naome_proof::program::Manifest;

/// Unpublished checked successor. The node cursor never retains the formula
/// graph in memory and cannot finish before every required record is copied.
pub struct ProgramRegistration {
    next: DiskArtifactState,
    manifest: Manifest,
    after: u64,
    nodes_complete: bool,
    after_dependency: Option<ProofId>,
    dependencies_complete: bool,
    definitions_complete: bool,
    after_definition: Option<naome_proof::DefinitionId>,
    depth: usize,
    complete: bool,
}
impl DiskArtifactState {
    pub fn begin_program_registration(
        &self,
        proof: &CheckedProgram,
    ) -> Result<ProgramRegistration, ArtifactStateError> {
        let manifest = proof.manifest();
        if self
            .contains_proof(manifest.proof_id())
            .map_err(ArtifactStateError::Context)?
        {
            return Err(ArtifactStateError::DuplicateProof {
                proof_id: manifest.proof_id(),
            });
        }
        Ok(ProgramRegistration {
            next: self.clone(),
            manifest: manifest.clone(),
            after: 0,
            nodes_complete: proof.conclusion().is_some(),
            after_dependency: None,
            dependencies_complete: false,
            definitions_complete: false,
            after_definition: None,
            depth: 1,
            complete: false,
        })
    }

    /// Common checked fact/index publication for both maintained proof formats.
    pub(super) fn register_fact(
        &mut self,
        proof: ProofId,
        derivation: DerivationId,
        statement: StatementId,
        depth: usize,
        record: &[u8],
        formula: Option<&Formula>,
    ) -> Result<(), ArtifactStateError> {
        let context = ArtifactStateError::Context;
        if let Some(previous) = self.statements.get(statement.as_bytes()).map_err(context)?
            && previous != record
        {
            return Err(ArtifactStateError::StatementIdentityCollision {
                statement_id: statement,
            });
        }
        if let Some(previous) = self
            .derivations
            .get(derivation.as_bytes())
            .map_err(context)?
            && previous != statement.as_bytes()
        {
            return Err(ArtifactStateError::DerivationIdentityCollision {
                derivation_id: derivation,
            });
        }
        self.statements
            .insert(*statement.as_bytes(), record)
            .map_err(context)?;
        self.derivations
            .insert(*derivation.as_bytes(), statement.as_bytes())
            .map_err(context)?;
        let mut proof_record = derivation.as_bytes().to_vec();
        proof_record.extend_from_slice(&(depth as u64).to_be_bytes());
        self.proofs
            .insert(*proof.as_bytes(), &proof_record)
            .map_err(context)?;
        let mut identity = vec![0];
        identity.extend_from_slice(proof.as_bytes());
        self.artifacts
            .insert(*ArtifactId::from_proof_id(proof).as_bytes(), &identity)
            .map_err(context)?;
        let previous = self.witnesses.get(statement.as_bytes()).map_err(context)?;
        match previous {
            Some(previous) => {
                if proof.as_bytes() < &fixed(&previous).map_err(context)? {
                    self.witnesses
                        .set(*statement.as_bytes(), proof.as_bytes())
                        .map_err(context)?;
                }
            }
            None => {
                self.witnesses
                    .insert(*statement.as_bytes(), proof.as_bytes())
                    .map_err(context)?;
                if let Some(formula) = formula {
                    for (kind, target) in projections(proof, formula) {
                        let index = self.index_mut(kind);
                        let root = index.get(target.as_bytes()).map_err(context)?;
                        let mut bucket = DiskMap::from_root(
                            index.storage(),
                            decode_root(root.as_deref()).map_err(context)?,
                        );
                        bucket.insert(*statement.as_bytes(), &[]).map_err(context)?;
                        index
                            .set(*target.as_bytes(), &encode_root(bucket.root()))
                            .map_err(context)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
impl ProgramRegistration {
    pub fn complete(&self) -> bool {
        self.complete
    }
    pub fn advance(
        &mut self,
        proof: &CheckedProgram,
        records: usize,
    ) -> Result<(), ArtifactStateError> {
        if records == 0 {
            return Err(ArtifactStateError::Context(ContextError::Limit));
        }
        if proof.manifest() != &self.manifest {
            return Err(ArtifactStateError::Context(ContextError::Corrupt));
        }
        if self.complete {
            return Ok(());
        }
        if !self.dependencies_complete {
            let limit = records.min(4096);
            let dependencies = proof
                .dependencies_after(self.after_dependency, limit)
                .map_err(|error| {
                    ArtifactStateError::Context(if error.resource_shortage() {
                        ContextError::Limit
                    } else {
                        ContextError::Storage(error.to_string())
                    })
                })?;
            for dependency in &dependencies {
                let header = self
                    .next
                    .proof_header(dependency.proof)
                    .map_err(ArtifactStateError::Context)?
                    .ok_or(ArtifactStateError::MissingProofDependency {
                        proof_id: dependency.proof,
                    })?;
                if header.statement != dependency.statement
                    || header.derivation != dependency.derivation
                {
                    return Err(ArtifactStateError::ProofIdentityCollision {
                        proof_id: dependency.proof,
                    });
                }
                let depth = self
                    .next
                    .proof_dependency_depth(dependency.proof)
                    .map_err(ArtifactStateError::Context)?
                    .ok_or(ArtifactStateError::MissingProofDependency {
                        proof_id: dependency.proof,
                    })?;
                self.depth = self.depth.max(
                    depth
                        .checked_add(1)
                        .ok_or(ArtifactStateError::Context(ContextError::Limit))?,
                );
                self.after_dependency = Some(dependency.proof);
            }
            self.dependencies_complete = dependencies.len() < limit;
            if !dependencies.is_empty() || !self.dependencies_complete {
                return Ok(());
            }
        }
        if !self.definitions_complete {
            let limit = records.min(4096);
            let definitions = proof
                .definition_dependencies_after(self.after_definition, limit)
                .map_err(|error| {
                    ArtifactStateError::Context(if error.resource_shortage() {
                        ContextError::Limit
                    } else {
                        ContextError::Storage(error.to_string())
                    })
                })?;
            for definition_id in &definitions {
                if self
                    .next
                    .definition_kind(*definition_id)
                    .map_err(ArtifactStateError::Context)?
                    .is_none()
                {
                    return Err(ArtifactStateError::MissingDefinitionDependency {
                        definition_id: *definition_id,
                    });
                }
                self.after_definition = Some(*definition_id);
            }
            self.definitions_complete = definitions.len() < limit;
            if !definitions.is_empty() || !self.definitions_complete {
                return Ok(());
            }
        }
        if !self.nodes_complete {
            let mut nodes = proof.nodes_after(self.after);
            for _ in 0..records {
                let Some(node) = nodes.next() else {
                    self.nodes_complete = true;
                    break;
                };
                let (ordinal, address, bytes) = node.map_err(|e| {
                    ArtifactStateError::Context(if e.resource_shortage() {
                        ContextError::Limit
                    } else {
                        ContextError::Storage(e.to_string())
                    })
                })?;
                self.next
                    .program_nodes
                    .insert(address, &bytes)
                    .map_err(ArtifactStateError::Context)?;
                self.after = ordinal;
            }
            if !self.nodes_complete {
                return Ok(());
            }
        }
        let mut record = Vec::with_capacity(40);
        if let Some(formula) = proof.conclusion() {
            let bytes = formula
                .encode_canonical()
                .map_err(|_| ArtifactStateError::Context(ContextError::Corrupt))?;
            let address = formula_address(&bytes);
            self.next
                .statements
                .storage()
                .write(address, &bytes)
                .map_err(ArtifactStateError::Context)?;
            record.extend_from_slice(&address);
            record.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        } else {
            if !self
                .next
                .program_nodes
                .contains_key(&self.manifest.conclusion)
                .map_err(ArtifactStateError::Context)?
            {
                return Err(ArtifactStateError::Context(ContextError::Corrupt));
            }
            record.extend_from_slice(&self.manifest.conclusion);
            record.extend_from_slice(&0u64.to_be_bytes());
        }
        self.next.register_fact(
            self.manifest.proof_id(),
            self.manifest.derivation_id(),
            self.manifest.statement_id(),
            self.depth,
            &record,
            proof.conclusion(),
        )?;
        self.complete = true;
        Ok(())
    }
    pub fn finish(self) -> Result<DiskArtifactState, ContextError> {
        if !self.complete {
            return Err(ContextError::Limit);
        }
        Ok(self.next)
    }
}
