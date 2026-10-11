use super::disk_map::{DiskMap, Root};
use crate::context::{BucketKind, ProofHeader, StatementCursor, StatementHeader, sealed};
use crate::question::index::projections;
use crate::{
    ArtifactStateError, CHECKER_MAX_FORMULA_WORK_BYTES, CheckedProof, ContextError, ContextStorage,
    ContextView, statement_id,
};
use naome_foundation::Formula;
use naome_proof::{
    ArtifactId, DefinitionId, DefinitionKind, DefinitionResolution, DefinitionResolver,
    DerivationId, ProofId, ProofStep, StatementId,
};
use sha2::{Digest, Sha256};
use std::{borrow::Cow, sync::Arc};

/// Complete proof-only checked context with authenticated cold records.
/// Construction is empty; only mathematical registration can create roots.
/// Restart must replay every canonical proof. No persisted root is trusted.
#[derive(Clone)]
#[must_use]
pub struct DiskArtifactState {
    proofs: DiskMap,
    derivations: DiskMap,
    statements: DiskMap,
    artifacts: DiskMap,
    witnesses: DiskMap,
    outgoing: DiskMap,
    deductions: DiskMap,
    instances: DiskMap,
}

impl DiskArtifactState {
    pub fn new(storage: Arc<dyn ContextStorage>) -> Self {
        Self {
            proofs: DiskMap::new(storage.clone()),
            derivations: DiskMap::new(storage.clone()),
            statements: DiskMap::new(storage.clone()),
            artifacts: DiskMap::new(storage.clone()),
            witnesses: DiskMap::new(storage.clone()),
            outgoing: DiskMap::new(storage.clone()),
            deductions: DiskMap::new(storage.clone()),
            instances: DiskMap::new(storage),
        }
    }

    pub fn contains_proof(&self, id: ProofId) -> Result<bool, ContextError> {
        self.proofs.contains_key(id.as_bytes())
    }
    pub fn contains_statement(&self, id: StatementId) -> Result<bool, ContextError> {
        self.statements.contains_key(id.as_bytes())
    }
    pub fn proof_ids(&self) -> impl Iterator<Item = Result<ProofId, ContextError>> {
        self.proofs
            .entries()
            .map(|entry| entry.map(|(id, _)| ProofId::from_bytes(id)))
    }

    /// Aliases coexist only after exact checked identity/conclusion/dependency
    /// validation. Failed storage writes publish no successor root.
    pub fn register_proof_for_replication(
        &mut self,
        proof: CheckedProof,
    ) -> Result<Box<[u8]>, ArtifactStateError> {
        self.validate_registration(&proof)?;
        let mut next = self.clone();
        let bytes = proof
            .conclusion
            .encode_canonical()
            .map_err(|_| ArtifactStateError::Context(ContextError::Corrupt))?;
        if bytes.len() != proof.canonical_conclusion_length
            || bytes.len() > CHECKER_MAX_FORMULA_WORK_BYTES
        {
            return Err(ArtifactStateError::Context(ContextError::Limit));
        }
        let address = formula_address(&bytes);
        next.statements
            .storage()
            .write(address, &bytes)
            .map_err(ArtifactStateError::Context)?;
        let mut statement_record = address.to_vec();
        statement_record.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        next.statements
            .insert(*proof.statement_id.as_bytes(), &statement_record)
            .map_err(ArtifactStateError::Context)?;
        next.derivations
            .insert(
                *proof.derivation_id.as_bytes(),
                proof.statement_id.as_bytes(),
            )
            .map_err(ArtifactStateError::Context)?;
        next.proofs
            .insert(*proof.proof_id.as_bytes(), proof.derivation_id.as_bytes())
            .map_err(ArtifactStateError::Context)?;
        next.artifacts
            .insert(*ArtifactId::from_proof_id(proof.proof_id).as_bytes(), &[])
            .map_err(ArtifactStateError::Context)?;
        let previous = next
            .witnesses
            .get(proof.statement_id.as_bytes())
            .map_err(ArtifactStateError::Context)?;
        match previous {
            Some(previous) => {
                if proof.proof_id.as_bytes()
                    < &fixed(&previous).map_err(ArtifactStateError::Context)?
                {
                    next.witnesses
                        .set(*proof.statement_id.as_bytes(), proof.proof_id.as_bytes())
                        .map_err(ArtifactStateError::Context)?;
                }
            }
            None => {
                next.witnesses
                    .insert(*proof.statement_id.as_bytes(), proof.proof_id.as_bytes())
                    .map_err(ArtifactStateError::Context)?;
                for (kind, target) in projections(proof.proof_id, &proof.conclusion) {
                    let index = next.index_mut(kind);
                    let root = index
                        .get(target.as_bytes())
                        .map_err(ArtifactStateError::Context)?;
                    let mut bucket = DiskMap::from_root(
                        index.storage(),
                        decode_root(root.as_deref()).map_err(ArtifactStateError::Context)?,
                    );
                    bucket
                        .insert(*proof.statement_id.as_bytes(), &[])
                        .map_err(ArtifactStateError::Context)?;
                    index
                        .set(*target.as_bytes(), &encode_root(bucket.root()))
                        .map_err(ArtifactStateError::Context)?;
                }
            }
        }
        *self = next;
        Ok(proof.normal_form.into_canonical_bytes())
    }

    fn validate_registration(&self, proof: &CheckedProof) -> Result<(), ArtifactStateError> {
        if let Some(header) = self
            .proof_header(proof.proof_id)
            .map_err(ArtifactStateError::Context)?
        {
            if header.derivation != proof.derivation_id || header.statement != proof.statement_id {
                return Err(ArtifactStateError::ProofIdentityCollision {
                    proof_id: proof.proof_id,
                });
            }
            self.require_same_statement(proof)?;
            return Err(ArtifactStateError::DuplicateProof {
                proof_id: proof.proof_id,
            });
        }
        for step in proof.normal_form.certificate().steps() {
            if let ProofStep::ProofReference { proof_id } = step
                && !self
                    .contains_proof(*proof_id)
                    .map_err(ArtifactStateError::Context)?
            {
                return Err(ArtifactStateError::MissingProofDependency {
                    proof_id: *proof_id,
                });
            }
            if let Some(definition_id) = step.definition_references().into_iter().next() {
                return Err(ArtifactStateError::MissingDefinitionDependency { definition_id });
            }
        }
        if let Some(statement) = self
            .derivations
            .get(proof.derivation_id.as_bytes())
            .map_err(ArtifactStateError::Context)?
            && fixed(&statement).map_err(ArtifactStateError::Context)?
                != *proof.statement_id.as_bytes()
        {
            return Err(ArtifactStateError::DerivationIdentityCollision {
                derivation_id: proof.derivation_id,
            });
        }
        self.require_same_statement(proof)
    }

    fn require_same_statement(&self, proof: &CheckedProof) -> Result<(), ArtifactStateError> {
        if let Some(formula) = self
            .statement_formula(proof.statement_id, CHECKER_MAX_FORMULA_WORK_BYTES)
            .map_err(ArtifactStateError::Context)?
            && *formula != proof.conclusion
        {
            return Err(ArtifactStateError::StatementIdentityCollision {
                statement_id: proof.statement_id,
            });
        }
        Ok(())
    }
    fn index(&self, kind: BucketKind) -> &DiskMap {
        match kind {
            BucketKind::Outgoing => &self.outgoing,
            BucketKind::Deductions => &self.deductions,
            BucketKind::Instances => &self.instances,
        }
    }
    fn index_mut(&mut self, kind: BucketKind) -> &mut DiskMap {
        match kind {
            BucketKind::Outgoing => &mut self.outgoing,
            BucketKind::Deductions => &mut self.deductions,
            BucketKind::Instances => &mut self.instances,
        }
    }
    fn statement_record(&self, id: StatementId) -> Result<Option<([u8; 32], usize)>, ContextError> {
        let Some(record) = self.statements.get(id.as_bytes())? else {
            return Ok(None);
        };
        if record.len() != 40 {
            return Err(ContextError::Corrupt);
        }
        let length = usize::try_from(u64::from_be_bytes(
            record[32..].try_into().map_err(|_| ContextError::Corrupt)?,
        ))
        .map_err(|_| ContextError::Limit)?;
        if length == 0 || length > CHECKER_MAX_FORMULA_WORK_BYTES {
            return Err(ContextError::Limit);
        }
        Ok(Some((fixed(&record[..32])?, length)))
    }
}

impl sealed::Sealed for DiskArtifactState {}
impl ContextView for DiskArtifactState {
    fn snapshot_id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"naome:checked-artifact-snapshot:v1\0");
        hash.update(self.proofs.fingerprint());
        hash.update([0; 32]); // This context has no conservative definitions.
        hash.finalize().into()
    }
    fn contains_artifact(&self, id: ArtifactId) -> Result<bool, ContextError> {
        self.artifacts.contains_key(id.as_bytes())
    }
    fn proof_header(&self, id: ProofId) -> Result<Option<ProofHeader>, ContextError> {
        let Some(derivation) = self.proofs.get(id.as_bytes())? else {
            return Ok(None);
        };
        let derivation = DerivationId::from_bytes(fixed(&derivation)?);
        let statement = self
            .derivations
            .get(derivation.as_bytes())?
            .ok_or(ContextError::Corrupt)?;
        let statement = StatementId::from_bytes(fixed(&statement)?);
        let (_, length) = self
            .statement_record(statement)?
            .ok_or(ContextError::Corrupt)?;
        Ok(Some(ProofHeader {
            derivation,
            statement,
            length,
        }))
    }
    fn statement_header(&self, id: StatementId) -> Result<Option<StatementHeader>, ContextError> {
        let Some((_, length)) = self.statement_record(id)? else {
            return Ok(None);
        };
        let proof = self
            .witnesses
            .get(id.as_bytes())?
            .ok_or(ContextError::Corrupt)?;
        Ok(Some(StatementHeader {
            proof: ProofId::from_bytes(fixed(&proof)?),
            length,
        }))
    }
    fn statement_formula(
        &self,
        id: StatementId,
        maximum: usize,
    ) -> Result<Option<Cow<'_, Formula>>, ContextError> {
        let Some((address, length)) = self.statement_record(id)? else {
            return Ok(None);
        };
        if length > maximum {
            return Err(ContextError::Limit);
        }
        let bytes = self.statements.storage().read(address, length)?;
        if bytes.len() != length || formula_address(&bytes) != address || statement_id(&bytes) != id
        {
            return Err(ContextError::Corrupt);
        }
        let formula = Formula::decode_canonical(&bytes).map_err(|_| ContextError::Corrupt)?;
        if !formula.is_closed() {
            return Err(ContextError::Corrupt);
        }
        Ok(Some(Cow::Owned(formula)))
    }
    fn bucket(
        &self,
        kind: BucketKind,
        target: StatementId,
    ) -> Result<StatementCursor<'_>, ContextError> {
        let index = self.index(kind);
        let root = index.get(target.as_bytes())?;
        let bucket = DiskMap::from_root(index.storage(), decode_root(root.as_deref())?);
        Ok(Box::new(bucket.entries().map(|entry| {
            entry.and_then(|(key, value)| {
                if !value.is_empty() {
                    return Err(ContextError::Corrupt);
                }
                Ok(StatementId::from_bytes(key))
            })
        })))
    }
    fn definition_kind(&self, _: DefinitionId) -> Option<DefinitionKind> {
        None
    }
}
impl DefinitionResolver for DiskArtifactState {
    fn resolve_definition(&self, _: DefinitionId) -> Option<DefinitionResolution<'_>> {
        None
    }
}

fn fixed(bytes: &[u8]) -> Result<[u8; 32], ContextError> {
    bytes.try_into().map_err(|_| ContextError::Corrupt)
}
fn formula_address(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naome:checked-formula-storage:v1\0");
    hash.update(bytes);
    hash.finalize().into()
}
fn encode_root(root: Option<Root>) -> Vec<u8> {
    match root {
        None => vec![0],
        Some(root) => {
            let mut bytes = vec![1];
            bytes.extend_from_slice(&root.address);
            bytes.extend_from_slice(&root.fingerprint);
            bytes
        }
    }
}
fn decode_root(bytes: Option<&[u8]>) -> Result<Option<Root>, ContextError> {
    match bytes {
        None | Some([0]) => Ok(None),
        Some(bytes) if bytes.len() == 65 && bytes[0] == 1 => Ok(Some(Root {
            address: fixed(&bytes[1..33])?,
            fingerprint: fixed(&bytes[33..])?,
        })),
        _ => Err(ContextError::Corrupt),
    }
}
