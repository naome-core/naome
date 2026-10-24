use super::disk_map::{DiskMap, Root};
use crate::context::{
    BucketKind, FormulaLocation, ProofHeader, StatementCursor, StatementHeader, sealed,
};
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

mod copy;
mod program;
pub use copy::{DiskArtifactCopy, DiskCopyBudget, DiskCopyProgress};
pub use program::ProgramRegistration;

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
    program_nodes: DiskMap,
    read_cache: crate::ReadCacheLimits,
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
        self.report((|| {
            let next = Self {
                read_cache: self.read_cache,
                proofs: self.proofs.copy_to(storage.clone())?,
                derivations: self.derivations.copy_to(storage.clone())?,
                statements: self.statements.copy_to(storage.clone())?,
                artifacts: self.artifacts.copy_to(storage.clone())?,
                witnesses: self.witnesses.copy_to(storage.clone())?,
                outgoing: self.outgoing.copy_to(storage.clone())?,
                deductions: self.deductions.copy_to(storage.clone())?,
                instances: self.instances.copy_to(storage.clone())?,
                program_nodes: self.program_nodes.copy_to(storage.clone())?,
            };
            for entry in self.statements.entries() {
                let (id, record) = entry?;
                let id = StatementId::from_bytes(id);
                let (address, length) = decode_statement_record(&record)?;
                if length == 0 {
                    continue;
                }
                let bytes = self.statements.storage().read(address, length)?;
                if bytes.len() != length
                    || formula_address(&bytes) != address
                    || statement_id(&bytes) != id
                {
                    return Err(ContextError::Corrupt);
                }
                storage.write(address, &bytes)?;
            }
            for index in [&self.outgoing, &self.deductions, &self.instances] {
                for entry in index.entries() {
                    let (_, record) = entry?;
                    let bucket = DiskMap::from_root(index.storage(), decode_root(Some(&record))?);
                    let _ = bucket.copy_to(storage.clone())?;
                }
            }
            Ok(next)
        })())
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
    fn read_cache_limits(&self) -> crate::ReadCacheLimits {
        self.read_cache
    }
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
mod tests {
    use super::*;
    use naome_foundation::ZfcAxiom;
    use naome_proof::ProofCertificate;
    use std::{collections::BTreeMap, sync::Mutex};

    #[derive(Default)]
    pub(super) struct MemoryStorage {
        pub(super) bytes: Mutex<BTreeMap<[u8; 32], Vec<u8>>>,
        pub(super) reads: Mutex<BTreeMap<[u8; 32], usize>>,
        pub(super) failures: Mutex<Vec<ContextError>>,
    }
    impl ContextStorage for MemoryStorage {
        fn read(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
            *self.reads.lock().unwrap().entry(address).or_default() += 1;
            let records = self.bytes.lock().unwrap();
            let bytes = records.get(&address).ok_or(ContextError::Corrupt)?;
            if bytes.len() > maximum {
                return Err(ContextError::Limit);
            }
            Ok(bytes.clone())
        }
        fn write(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError> {
            let mut records = self.bytes.lock().unwrap();
            if let Some(previous) = records.get(&address) {
                if previous != bytes {
                    return Err(ContextError::Corrupt);
                }
            } else {
                records.insert(address, bytes.to_vec());
            }
            Ok(())
        }
        fn record_failure(&self, error: &ContextError) {
            self.failures.lock().unwrap().push(error.clone());
        }
    }

    pub(super) fn register_axiom(
        state: &mut DiskArtifactState,
        axiom: ZfcAxiom,
    ) -> (ProofId, StatementId, Vec<u8>) {
        let proof = crate::normalize_and_check(
            ProofCertificate::new(vec![ProofStep::ZfcAxiom(axiom)]).unwrap(),
        )
        .unwrap();
        let expected = (
            proof.proof_id(),
            proof.statement_id(),
            proof.conclusion().encode_canonical().unwrap(),
        );
        state.register_proof_for_replication(proof).unwrap();
        expected
    }

    #[test]
    fn copy_reuses_authenticated_statement_records_and_keeps_cold_formulas() {
        let source = Arc::new(MemoryStorage::default());
        let mut state = DiskArtifactState::new(source.clone());
        let expected = [
            register_axiom(&mut state, ZfcAxiom::Pairing),
            register_axiom(&mut state, ZfcAxiom::Union),
        ];
        let statement_root = state.statements.root().unwrap().address;
        let snapshot = state.snapshot_id();
        let ids = state.proof_ids().collect::<Result<Vec<_>, _>>().unwrap();
        source.reads.lock().unwrap().clear();
        let copied = state.copy_to(Arc::new(MemoryStorage::default())).unwrap();
        assert_eq!(
            source.reads.lock().unwrap().get(&statement_root),
            Some(&2),
            "one reachable-node copy and one statement cursor, without per-record lookups"
        );
        drop(state);
        source.bytes.lock().unwrap().clear();
        assert_eq!(copied.snapshot_id(), snapshot);
        assert_eq!(
            copied.proof_ids().collect::<Result<Vec<_>, _>>().unwrap(),
            ids
        );
        for (id, statement, bytes) in expected {
            assert_eq!(
                copied.proof_header(id).unwrap().unwrap().statement_id(),
                statement
            );
            assert_eq!(
                copied
                    .statement_formula(statement, CHECKER_MAX_FORMULA_WORK_BYTES)
                    .unwrap()
                    .unwrap()
                    .encode_canonical()
                    .unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn copy_rejects_malformed_statement_records_and_formula_identity_corruption() {
        let mut oversized = vec![0; 32];
        oversized.extend_from_slice(&((CHECKER_MAX_FORMULA_WORK_BYTES as u64) + 1).to_be_bytes());
        for record in [vec![0; 39], vec![0; 41], vec![0; 40], oversized] {
            let source = Arc::new(MemoryStorage::default());
            let mut state = DiskArtifactState::new(source.clone());
            state.statements.insert([1; 32], &record).unwrap();
            assert!(matches!(
                state.copy_to(Arc::new(MemoryStorage::default())),
                Err(ContextError::Corrupt)
            ));
            assert!(
                source
                    .failures
                    .lock()
                    .unwrap()
                    .contains(&ContextError::Corrupt)
            );
        }

        for wrong_statement in [false, true] {
            let source = Arc::new(MemoryStorage::default());
            let mut state = DiskArtifactState::new(source.clone());
            let (_, statement, _) = register_axiom(&mut state, ZfcAxiom::Pairing);
            if wrong_statement {
                let record = state.statements.get(statement.as_bytes()).unwrap().unwrap();
                let mut other = *statement.as_bytes();
                other[0] ^= 1;
                state.statements.insert(other, &record).unwrap();
            } else {
                let (address, _) = state.statement_record(statement).unwrap().unwrap();
                source.bytes.lock().unwrap().get_mut(&address).unwrap()[0] ^= 1;
            }
            assert!(matches!(
                state.copy_to(Arc::new(MemoryStorage::default())),
                Err(ContextError::Corrupt)
            ));
            assert!(
                source
                    .failures
                    .lock()
                    .unwrap()
                    .contains(&ContextError::Corrupt)
            );
        }
    }
}
