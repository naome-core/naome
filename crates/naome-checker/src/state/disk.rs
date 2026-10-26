use super::disk_map::{DiskMap, Root};
use crate::context::{
    BucketKind, FormulaLocation, ProofHeader, StatementCursor, StatementHeader, sealed,
};
use crate::question::index::projections;
use crate::{
    ArtifactStateError, CHECKER_MAX_FORMULA_WORK_BYTES, CheckedDefinition, CheckedProof,
    ContextError, ContextStorage, ContextView, statement_id,
};
use naome_foundation::Formula;
use naome_proof::{
    ArtifactId, DefinitionCertificate, DefinitionId, DefinitionKind, DefinitionResolution,
    DefinitionResolver, DerivationId, ProofId, ProofStep, StatementId,
};
use sha2::{Digest, Sha256};
use std::{borrow::Cow, sync::Arc};

mod copy;
mod pending;
mod program;
pub use copy::{DiskArtifactCopy, DiskCopyBudget, DiskCopyProgress};
pub use program::ProgramRegistration;

/// Complete checked artifact context with authenticated cold records.
/// Construction is empty; only mathematical registration can create roots.
/// Restart must replay every canonical proof. No persisted root is trusted.
#[derive(Clone)]
#[must_use]
pub struct DiskArtifactState {
    proofs: DiskMap,
    definitions: DiskMap,
    derivations: DiskMap,
    statements: DiskMap,
    artifacts: DiskMap,
    witnesses: DiskMap,
    outgoing: DiskMap,
    deductions: DiskMap,
    instances: DiskMap,
    program_nodes: DiskMap,
    read_cache: crate::ReadCacheLimits,
}

struct ProgramNodes(DiskMap);
impl crate::context::ProgramNodes for ProgramNodes {
    fn read(
        &self,
        address: [u8; 32],
    ) -> Result<
        (
            naome_foundation::graph::Node<[u8; 32]>,
            naome_foundation::graph::Properties,
        ),
        ContextError,
    > {
        let result = (|| {
            let bytes = self.0.get(&address)?.ok_or(ContextError::Corrupt)?;
            let (node, properties) = naome_proof::program::decode_graph_node(&bytes)
                .map_err(|_| ContextError::Corrupt)?;
            if naome_proof::program::graph_node_hash(node, properties) != address {
                return Err(ContextError::Corrupt);
            }
            Ok((node, properties))
        })();
        if let Err(error @ (ContextError::Corrupt | ContextError::Storage(_))) = &result {
            self.0.storage().record_failure(error);
        }
        result
    }
}

// This one inventory names every authenticated map for complete copies and
// selected startup frontiers. Map-specific record semantics stay typed below.
macro_rules! checked_maps {
    ($($kind:ident => $field:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum MapKind { $($kind),+ }
        impl MapKind {
            const ALL: &'static [Self] = &[$(Self::$kind),+];
            fn map(self, state: &DiskArtifactState) -> &DiskMap {
                match self { $(Self::$kind => &state.$field),+ }
            }
            fn next(self) -> Option<Self> {
                let position = Self::ALL.iter().position(|kind| *kind == self)
                    .expect("complete checked map inventory");
                Self::ALL.get(position + 1).copied()
            }
        }
        fn maps(state: &DiskArtifactState) -> [&DiskMap; MapKind::ALL.len()] {
            [$(&state.$field),+]
        }
    };
}
checked_maps! {
    Proofs => proofs,
    Definitions => definitions,
    Derivations => derivations,
    Statements => statements,
    Artifacts => artifacts,
    Witnesses => witnesses,
    Outgoing => outgoing,
    Deductions => deductions,
    Instances => instances,
    ProgramNodes => program_nodes,
}

impl DiskArtifactState {
    fn report<T>(&self, result: Result<T, ContextError>) -> Result<T, ContextError> {
        if let Err(error @ (ContextError::Corrupt | ContextError::Storage(_))) = &result {
            self.proofs.storage().record_failure(error);
        }
        result
    }
    pub fn new(storage: Arc<dyn ContextStorage>) -> Self {
        Self {
            proofs: DiskMap::new(storage.clone()),
            definitions: DiskMap::new(storage.clone()),
            derivations: DiskMap::new(storage.clone()),
            statements: DiskMap::new(storage.clone()),
            artifacts: DiskMap::new(storage.clone()),
            witnesses: DiskMap::new(storage.clone()),
            outgoing: DiskMap::new(storage.clone()),
            deductions: DiskMap::new(storage.clone()),
            instances: DiskMap::new(storage.clone()),
            program_nodes: DiskMap::new(storage),
            read_cache: crate::ReadCacheLimits::DEFAULT,
        }
    }

    pub fn with_read_cache_limits(
        mut self,
        limits: crate::ReadCacheLimits,
    ) -> Result<Self, ContextError> {
        self.read_cache = crate::ReadCacheLimits::new(limits.entries, limits.bytes)?;
        Ok(self)
    }

    /// Fingerprint of the complete checked concrete-proof set. This exposes
    /// no persisted roots and cannot restore mathematical validity.
    pub fn proof_set_fingerprint(&self) -> [u8; 32] {
        self.proofs.fingerprint()
    }

    /// Fingerprint of every checked proof and definition address.
    pub fn artifact_set_fingerprint(&self) -> [u8; 32] {
        self.artifacts.fingerprint()
    }

    pub fn artifact_ids_after(
        &self,
        after: Option<ArtifactId>,
    ) -> impl Iterator<Item = Result<ArtifactId, ContextError>> {
        self.artifacts
            .entries_after(after.map(|id| *id.as_bytes()))
            .map(|entry| {
                entry.and_then(|(id, value)| {
                    artifact_proof_id(ArtifactId::from_bytes(id), &value)?;
                    Ok(ArtifactId::from_bytes(id))
                })
            })
    }

    /// Resolve a node address to its concrete proof citation identity.
    /// Definitions return None; a malformed record is never absence.
    pub fn artifact_proof_id(&self, id: ArtifactId) -> Result<Option<ProofId>, ContextError> {
        self.report(self.artifacts.get(id.as_bytes()).and_then(|record| {
            record
                .map(|record| artifact_proof_id(id, &record))
                .transpose()
                .map(Option::flatten)
        }))
    }
    pub fn artifact_definition_id(
        &self,
        id: ArtifactId,
    ) -> Result<Option<DefinitionId>, ContextError> {
        self.report((|| {
            let Some(record) = self.artifacts.get(id.as_bytes())? else {
                return Ok(None);
            };
            artifact_proof_id(id, &record)?;
            Ok((record[0] == 1).then(|| {
                DefinitionId::from_bytes(fixed(&record[1..]).expect("validated identity width"))
            }))
        })())
    }
    pub fn artifact_proof_header(
        &self,
        id: ArtifactId,
    ) -> Result<Option<ProofHeader>, ContextError> {
        self.artifact_proof_id(id)?
            .map(|proof| self.proof_header(proof))
            .transpose()
            .map(Option::flatten)
    }
    pub fn artifact_proof_dependency_depth(
        &self,
        id: ArtifactId,
    ) -> Result<Option<usize>, ContextError> {
        self.artifact_proof_id(id)?
            .map(|proof| self.proof_dependency_depth(proof))
            .transpose()
            .map(Option::flatten)
    }

    /// Register a checked conservative definition in the same authenticated set.
    /// No stored certificate or root can substitute for the current obligation.
    pub fn register_definition(
        &mut self,
        definition: CheckedDefinition,
    ) -> Result<(), ArtifactStateError> {
        super::registration::validate_definition(self, &definition)?;
        let bytes = definition.certificate().to_canonical_bytes();
        let address = definition_address(&bytes);
        let mut next = self.clone();
        next.definitions
            .storage()
            .write(address, &bytes)
            .map_err(ArtifactStateError::Context)?;
        let mut record = address.to_vec();
        record.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        next.definitions
            .insert(*definition.definition_id().as_bytes(), &record)
            .map_err(ArtifactStateError::Context)?;
        let mut identity = vec![1];
        identity.extend_from_slice(definition.definition_id().as_bytes());
        next.artifacts
            .insert(
                *ArtifactId::from_definition_id(definition.definition_id()).as_bytes(),
                &identity,
            )
            .map_err(ArtifactStateError::Context)?;
        *self = next;
        Ok(())
    }

    fn definition(&self, id: DefinitionId) -> Result<Option<DefinitionCertificate>, ContextError> {
        self.report((|| {
            let Some(record) = self.definitions.get(id.as_bytes())? else {
                return Ok(None);
            };
            let (address, length) = definition_record(&record)?;
            let bytes = self.definitions.storage().read(address, length)?;
            if bytes.len() != length
                || definition_address(&bytes) != address
                || definition_identity(&bytes)? != *id.as_bytes()
            {
                return Err(ContextError::Corrupt);
            }
            DefinitionCertificate::from_canonical_bytes(&bytes)
                .map(Some)
                .map_err(|_| ContextError::Corrupt)
        })())
    }

    pub fn contains_proof(&self, id: ProofId) -> Result<bool, ContextError> {
        self.proofs.contains_key(id.as_bytes())
    }
    pub fn contains_statement(&self, id: StatementId) -> Result<bool, ContextError> {
        self.statements.contains_key(id.as_bytes())
    }
    /// Exact cited-proof DAG depth, authenticated by the live checked roots.
    /// This is a derived metric; the operating graph owns its depth policy.
    pub fn proof_dependency_depth(&self, id: ProofId) -> Result<Option<usize>, ContextError> {
        self.report((|| {
            self.proofs
                .get(id.as_bytes())?
                .map(|record| proof_record(&record).map(|(_, depth)| depth))
                .transpose()
        })())
    }
    pub fn proof_ids(&self) -> impl Iterator<Item = Result<ProofId, ContextError>> {
        self.proof_ids_after(None)
    }
    /// Complete ascending proof cursor, seeking through authenticated ranges.
    pub fn proof_ids_after(
        &self,
        after: Option<ProofId>,
    ) -> impl Iterator<Item = Result<ProofId, ContextError>> {
        self.proofs
            .entries_after(after.map(|id| *id.as_bytes()))
            .map(|entry| entry.map(|(id, _)| ProofId::from_bytes(id)))
    }

    /// Clone a live checked view into fresh byte storage, preserving its exact
    /// authenticated roots and snapshot. This cannot restore a persisted root
    /// or grant validity to new records. Old handles retain their own storage.
    pub fn copy_to(&self, storage: Arc<dyn ContextStorage>) -> Result<Self, ContextError> {
        let mut copy = self.begin_copy(storage);
        while !copy.complete() {
            copy.advance(DiskCopyBudget {
                records: usize::MAX,
                bytes: CHECKER_MAX_FORMULA_WORK_BYTES,
            })?;
        }
        copy.finish(self)
    }

    /// Aliases coexist only after exact checked identity/conclusion/dependency
    /// validation. Failed storage writes publish no successor root.
    pub fn register_proof_for_replication(
        &mut self,
        proof: CheckedProof,
    ) -> Result<Box<[u8]>, ArtifactStateError> {
        self.validate_registration(&proof)?;
        let mut next = self.clone();
        let mut depth = 0usize;
        for step in proof.normal_form.certificate().steps() {
            if let ProofStep::ProofReference { proof_id } = step {
                depth = depth.max(
                    self.proof_dependency_depth(*proof_id)
                        .map_err(ArtifactStateError::Context)?
                        .ok_or(ArtifactStateError::MissingProofDependency {
                            proof_id: *proof_id,
                        })?,
                );
            }
        }
        let depth = depth
            .checked_add(1)
            .ok_or(ArtifactStateError::Context(ContextError::Limit))?;
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
        next.register_fact(
            proof.proof_id,
            proof.derivation_id,
            proof.statement_id,
            depth,
            &statement_record,
            Some(&proof.conclusion),
        )?;
        *self = next;
        Ok(proof.normal_form.into_canonical_bytes())
    }

    fn validate_registration(&self, proof: &CheckedProof) -> Result<(), ArtifactStateError> {
        super::registration::validate(self, proof, true)
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
    fn formula_at(
        &self,
        id: StatementId,
        location: Option<FormulaLocation>,
        length: usize,
        maximum: usize,
    ) -> Result<Cow<'_, Formula>, ContextError> {
        self.report((|| {
            let location = location.ok_or(ContextError::Corrupt)?;
            if location.snapshot != self.snapshot_id() {
                return Err(ContextError::Corrupt);
            }
            if length == usize::MAX || length > maximum {
                return Err(ContextError::Limit);
            }
            let bytes = self.statements.storage().read(location.address, length)?;
            if bytes.len() != length
                || formula_address(&bytes) != location.address
                || statement_id(&bytes) != id
            {
                return Err(ContextError::Corrupt);
            }
            let formula = Formula::decode_canonical(&bytes).map_err(|_| ContextError::Corrupt)?;
            if !formula.is_closed() {
                return Err(ContextError::Corrupt);
            }
            Ok(Cow::Owned(formula))
        })())
    }
    fn statement_record(&self, id: StatementId) -> Result<Option<([u8; 32], usize)>, ContextError> {
        self.report((|| {
            let Some(record) = self.statements.get(id.as_bytes())? else {
                return Ok(None);
            };
            let (address, length) = decode_statement_record(&record)?;
            if length == 0
                && (naome_proof::program::graph_statement_id(address) != id
                    || !self.program_nodes.contains_key(&address)?)
            {
                return Err(ContextError::Corrupt);
            }
            Ok(Some((address, length)))
        })())
    }
}

impl super::registration::RegistrationView for DiskArtifactState {
    fn has_proof(&self, id: ProofId) -> Result<bool, ContextError> {
        self.contains_proof(id)
    }
    fn derivation_statement(&self, id: DerivationId) -> Result<Option<StatementId>, ContextError> {
        self.report(
            self.derivations
                .get(id.as_bytes())?
                .map(|bytes| fixed(&bytes).map(StatementId::from_bytes))
                .transpose(),
        )
    }
}

impl sealed::Sealed for DiskArtifactState {}
impl ContextView for DiskArtifactState {
    fn program_source(
        &self,
        id: ProofId,
    ) -> Result<Option<crate::context::ProgramSource>, ContextError> {
        self.report((|| {
            let Some(header) = self.proof_header(id)? else {
                return Ok(None);
            };
            if header.length == usize::MAX {
                let root = header.location.ok_or(ContextError::Corrupt)?.address;
                if naome_proof::program::graph_statement_id(root) != header.statement
                    || !self.program_nodes.contains_key(&root)?
                {
                    return Err(ContextError::Corrupt);
                }
                Ok(Some(crate::context::ProgramSource::graph(
                    id,
                    header,
                    root,
                    Arc::new(ProgramNodes(self.program_nodes.clone())),
                )))
            } else {
                let formula = self
                    .proof_formula(header, header.length)?
                    .ok_or(ContextError::Corrupt)?;
                Ok(Some(crate::context::ProgramSource::formula(
                    id,
                    header,
                    formula.into_owned(),
                )))
            }
        })())
    }
    fn read_cache_limits(&self) -> crate::ReadCacheLimits {
        self.read_cache
    }
    fn snapshot_id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"naome:checked-artifact-snapshot:v1\0");
        hash.update(self.proofs.fingerprint());
        hash.update(self.definitions.fingerprint());
        hash.finalize().into()
    }
    fn contains_artifact(&self, id: ArtifactId) -> Result<bool, ContextError> {
        self.artifacts.contains_key(id.as_bytes())
    }
    fn proof_header(&self, id: ProofId) -> Result<Option<ProofHeader>, ContextError> {
        self.report((|| {
            let Some(derivation) = self.proofs.get(id.as_bytes())? else {
                return Ok(None);
            };
            let (derivation, _) = proof_record(&derivation)?;
            let statement = self
                .derivations
                .get(derivation.as_bytes())?
                .ok_or(ContextError::Corrupt)?;
            let statement = StatementId::from_bytes(fixed(&statement)?);
            let (address, length) = self
                .statement_record(statement)?
                .ok_or(ContextError::Corrupt)?;
            Ok(Some(ProofHeader {
                location: Some(FormulaLocation {
                    address,
                    snapshot: self.snapshot_id(),
                }),
                derivation,
                statement,
                length: if length == 0 { usize::MAX } else { length },
            }))
        })())
    }
    fn statement_header(&self, id: StatementId) -> Result<Option<StatementHeader>, ContextError> {
        self.report((|| {
            let Some((address, length)) = self.statement_record(id)? else {
                return Ok(None);
            };
            let proof = self
                .witnesses
                .get(id.as_bytes())?
                .ok_or(ContextError::Corrupt)?;
            Ok(Some(StatementHeader {
                location: Some(FormulaLocation {
                    address,
                    snapshot: self.snapshot_id(),
                }),
                proof: ProofId::from_bytes(fixed(&proof)?),
                length: if length == 0 { usize::MAX } else { length },
            }))
        })())
    }
    fn statement_formula(
        &self,
        id: StatementId,
        maximum: usize,
    ) -> Result<Option<Cow<'_, Formula>>, ContextError> {
        self.report((|| {
            let Some((address, length)) = self.statement_record(id)? else {
                return Ok(None);
            };
            if length == 0 || length > maximum {
                return Err(ContextError::Limit);
            }
            let bytes = self.statements.storage().read(address, length)?;
            if bytes.len() != length
                || formula_address(&bytes) != address
                || statement_id(&bytes) != id
            {
                return Err(ContextError::Corrupt);
            }
            let formula = Formula::decode_canonical(&bytes).map_err(|_| ContextError::Corrupt)?;
            if !formula.is_closed() {
                return Err(ContextError::Corrupt);
            }
            Ok(Some(Cow::Owned(formula)))
        })())
    }
    fn proof_formula(
        &self,
        header: ProofHeader,
        maximum: usize,
    ) -> Result<Option<Cow<'_, Formula>>, ContextError> {
        self.formula_at(header.statement, header.location, header.length, maximum)
            .map(Some)
    }
    fn statement_formula_from_header(
        &self,
        id: StatementId,
        header: StatementHeader,
        maximum: usize,
    ) -> Result<Option<Cow<'_, Formula>>, ContextError> {
        self.formula_at(id, header.location, header.length, maximum)
            .map(Some)
    }
    fn bucket(
        &self,
        kind: BucketKind,
        target: StatementId,
    ) -> Result<StatementCursor<'_>, ContextError> {
        self.report((|| {
            let index = self.index(kind);
            let root = index.get(target.as_bytes())?;
            let bucket = DiskMap::from_root(index.storage(), decode_root(root.as_deref())?);
            let storage = index.storage();
            Ok::<StatementCursor<'_>, ContextError>(Box::new(bucket.entries().map(move |entry| {
                let result = entry.and_then(|(key, value)| {
                    if !value.is_empty() {
                        return Err(ContextError::Corrupt);
                    }
                    Ok(StatementId::from_bytes(key))
                });
                if let Err(error) = &result {
                    storage.record_failure(error);
                }
                result
            })))
        })())
    }
    fn definition_kind(&self, id: DefinitionId) -> Result<Option<DefinitionKind>, ContextError> {
        self.definition(id)
            .map(|definition| definition.map(|definition| definition.kind()))
    }
}
impl DefinitionResolver for DiskArtifactState {
    fn resolve_definition(
        &self,
        id: DefinitionId,
    ) -> Result<Option<DefinitionResolution<'_>>, naome_proof::DefinitionAccessError> {
        self.definition(id)
            .map(|definition| {
                definition.map(|definition| {
                    DefinitionResolution::owned(
                        definition.relation_arity(),
                        definition.body().clone(),
                    )
                })
            })
            .map_err(Into::into)
    }
}

fn definition_record(record: &[u8]) -> Result<([u8; 32], usize), ContextError> {
    let (address, length) = decode_statement_record(record)?;
    if length == 0
        || length > naome_proof::DEFINITION_MAX_BYTES
        || length > CHECKER_MAX_FORMULA_WORK_BYTES
    {
        return Err(ContextError::Corrupt);
    }
    Ok((address, length))
}
fn artifact_proof_id(id: ArtifactId, record: &[u8]) -> Result<Option<ProofId>, ContextError> {
    if record.len() != 33 {
        return Err(ContextError::Corrupt);
    }
    let raw = fixed(&record[1..])?;
    match record[0] {
        0 if ArtifactId::from_proof_id(ProofId::from_bytes(raw)) == id => {
            Ok(Some(ProofId::from_bytes(raw)))
        }
        1 if ArtifactId::from_definition_id(DefinitionId::from_bytes(raw)) == id => Ok(None),
        _ => Err(ContextError::Corrupt),
    }
}
fn definition_address(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naome:checked-definition\0");
    hash.update(bytes);
    hash.finalize().into()
}
fn definition_identity(bytes: &[u8]) -> Result<[u8; 32], ContextError> {
    DefinitionCertificate::from_canonical_bytes(bytes)
        .map(|certificate| *certificate.definition_id().as_bytes())
        .map_err(|_| ContextError::Corrupt)
}

fn fixed(bytes: &[u8]) -> Result<[u8; 32], ContextError> {
    bytes.try_into().map_err(|_| ContextError::Corrupt)
}
fn decode_statement_record(record: &[u8]) -> Result<([u8; 32], usize), ContextError> {
    if record.len() != 40 {
        return Err(ContextError::Corrupt);
    }
    let length = usize::try_from(u64::from_be_bytes(
        record[32..].try_into().map_err(|_| ContextError::Corrupt)?,
    ))
    .map_err(|_| ContextError::Limit)?;
    if length > CHECKER_MAX_FORMULA_WORK_BYTES {
        return Err(ContextError::Corrupt);
    }
    Ok((fixed(&record[..32])?, length))
}
fn proof_record(bytes: &[u8]) -> Result<(DerivationId, usize), ContextError> {
    if bytes.len() != 40 {
        return Err(ContextError::Corrupt);
    }
    let depth = usize::try_from(u64::from_be_bytes(fixed_u64(&bytes[32..])?))
        .map_err(|_| ContextError::Limit)?;
    if depth == 0 {
        return Err(ContextError::Corrupt);
    }
    Ok((DerivationId::from_bytes(fixed(&bytes[..32])?), depth))
}
fn fixed_u64(bytes: &[u8]) -> Result<[u8; 8], ContextError> {
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

#[cfg(test)]
mod tests;
