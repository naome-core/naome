use super::{
    DiskArtifactState, StatementId, decode_root, decode_statement_record, formula_address,
    statement_id,
};
use crate::context::{ContextError, ContextStorage};
use crate::state::disk_map::{DiskMap, MAX_NODE_BYTES, Walk};
use std::sync::Arc;

/// Limits actual authenticated record visits and raw bytes read in one step.
/// A node visit reserves its fixed maximum before reading; formulas reserve
/// their authenticated length. A formula is one atomic record, at most the
/// existing CHECKER_MAX_FORMULA_WORK_BYTES. The budget must accommodate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskCopyBudget {
    pub records: usize,
    pub bytes: usize,
}

/// Work performed by this step, including branch-only and repeated index
/// visits. Formula records contribute to records/bytes, but not node_visits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiskCopyProgress {
    pub records: usize,
    pub node_visits: usize,
    pub bytes: usize,
    pub complete: bool,
}

impl DiskCopyProgress {
    fn fits(&self, budget: DiskCopyBudget, bytes: usize) -> bool {
        self.records < budget.records && bytes <= budget.bytes.saturating_sub(self.bytes)
    }

    fn node(&mut self, bytes: usize) {
        self.records += 1;
        self.node_visits += 1;
        self.bytes += bytes;
    }
}

/// A live checked context's authenticated, resumable copy. The cursor holds
/// two depth-bounded DFS stacks at most, and one pending formula descriptor.
/// No persisted root or caller-supplied address set can complete this cursor.
#[must_use]
pub struct DiskArtifactCopy {
    source: DiskArtifactState,
    target: Arc<dyn ContextStorage>,
    phase: usize,
    walk: Option<Walk>,
    nested: Option<Walk>,
    formula: Option<(StatementId, [u8; 32], usize)>,
    failed: bool,
}

impl DiskArtifactState {
    /// Start copying the exact live roots. Callers that later finish against
    /// newer roots must mirror every subsequent successful immutable write to
    /// the target and exclude deltas prepared before that mirror was attached.
    /// Byte storage still grants no mathematical validity.
    pub fn begin_copy(&self, target: Arc<dyn ContextStorage>) -> DiskArtifactCopy {
        DiskArtifactCopy {
            source: self.clone(),
            target,
            phase: 0,
            walk: None,
            nested: None,
            formula: None,
            failed: false,
        }
    }
}

impl DiskArtifactCopy {
    pub fn complete(&self) -> bool {
        !self.failed && self.phase == 12 && self.nested.is_none() && self.formula.is_none()
    }

    /// Yield after a bounded number of actual reads, including all eight maps,
    /// statement formulas and all three nested bucket families. A too-small
    /// fresh budget fails rather than silently skipping an oversized record.
    pub fn advance(&mut self, budget: DiskCopyBudget) -> Result<DiskCopyProgress, ContextError> {
        let result = self.advance_inner(budget);
        if result.is_err() {
            self.failed = true;
        }
        self.source.report(result)
    }

    fn advance_inner(&mut self, budget: DiskCopyBudget) -> Result<DiskCopyProgress, ContextError> {
        if self.failed {
            return Err(ContextError::Corrupt);
        }
        if budget.records == 0 || budget.bytes < MAX_NODE_BYTES {
            return Err(ContextError::Limit);
        }
        let mut work = DiskCopyProgress::default();
        loop {
            if let Some((id, address, length)) = self.formula {
                if length > budget.bytes {
                    return Err(ContextError::Limit);
                }
                if !work.fits(budget, length) {
                    break;
                }
                let bytes = self.source.statements.storage().read(address, length)?;
                if bytes.len() != length
                    || formula_address(&bytes) != address
                    || statement_id(&bytes) != id
                {
                    return Err(ContextError::Corrupt);
                }
                self.target.write(address, &bytes)?;
                work.records += 1;
                work.bytes += bytes.len();
                self.formula = None;
                continue;
            }
            if let Some(nested) = &mut self.nested {
                if nested.complete() {
                    self.nested = None;
                    continue;
                }
                if !work.fits(budget, MAX_NODE_BYTES) {
                    break;
                }
                let visit = nested.step()?.ok_or(ContextError::Corrupt)?;
                self.target.write(visit.address, &visit.bytes)?;
                work.node(visit.bytes.len());
                continue;
            }
            if self.phase == 12 {
                break;
            }
            if self.walk.is_none() {
                self.walk = Some(self.phase_map().walk());
            }
            let walk = self.walk.as_mut().expect("active copy phase");
            if walk.complete() {
                self.walk = None;
                self.phase += 1;
                continue;
            }
            if !work.fits(budget, MAX_NODE_BYTES) {
                break;
            }
            let visit = walk.step()?.ok_or(ContextError::Corrupt)?;
            if self.phase < 8 {
                self.target.write(visit.address, &visit.bytes)?;
            }
            work.node(visit.bytes.len());
            if let Some((key, record)) = visit.entry {
                if self.phase == 8 {
                    let (address, length) = decode_statement_record(&record)?;
                    self.formula = Some((StatementId::from_bytes(key), address, length));
                } else if self.phase > 8 {
                    let root = decode_root(Some(&record))?;
                    self.nested = Some(DiskMap::from_root(self.phase_map().storage(), root).walk());
                }
            }
        }
        work.complete = self.complete();
        Ok(work)
    }

    fn phase_map(&self) -> &DiskMap {
        match self.phase {
            0..=7 => maps(&self.source)[self.phase],
            8 => &self.source.statements,
            9 => &self.source.outgoing,
            10 => &self.source.deductions,
            11 => &self.source.instances,
            _ => unreachable!("completed copy has no next map"),
        }
    }

    /// Consume a fully exhausted cursor and bind only roots of an already
    /// checked, live context from the same source storage. The owner must hold
    /// its write gate through target COMMIT and publication. This constant-size
    /// rebind does not read records, reconstruct roots, or restore persisted
    /// validity. Later mirrored writes are an availability obligation of that
    /// owner, just as successful writes are for synchronous copy_to.
    pub fn finish(self, current: &DiskArtifactState) -> Result<DiskArtifactState, ContextError> {
        let result = (|| {
            if !self.complete() {
                return Err(ContextError::Storage("checked copy is incomplete".into()));
            }
            for (source, current) in maps(&self.source).into_iter().zip(maps(current)) {
                if !Arc::ptr_eq(&source.storage(), &current.storage()) {
                    return Err(ContextError::Corrupt);
                }
            }
            let [
                proofs,
                derivations,
                statements,
                artifacts,
                witnesses,
                outgoing,
                deductions,
                instances,
            ] = maps(current).map(|map| DiskMap::from_root(self.target.clone(), map.root()));
            Ok(DiskArtifactState {
                proofs,
                derivations,
                statements,
                artifacts,
                witnesses,
                outgoing,
                deductions,
                instances,
            })
        })();
        self.source.report(result)
    }
}

fn maps(state: &DiskArtifactState) -> [&DiskMap; 8] {
    [
        &state.proofs,
        &state.derivations,
        &state.statements,
        &state.artifacts,
        &state.witnesses,
        &state.outgoing,
        &state.deductions,
        &state.instances,
    ]
}

#[cfg(test)]
mod tests {
    use super::super::tests::{MemoryStorage, register_axiom};
    use super::*;
    use crate::{CHECKER_MAX_FORMULA_WORK_BYTES, ContextView};
    use naome_foundation::ZfcAxiom;
    use naome_proof::{ProofCertificate, ProofStep};

    fn populated() -> (DiskArtifactState, Arc<MemoryStorage>) {
        let storage = Arc::new(MemoryStorage::default());
        let mut state = DiskArtifactState::new(storage.clone());
        register_axiom(&mut state, ZfcAxiom::Pairing);
        register_axiom(&mut state, ZfcAxiom::Union);
        let implication = crate::normalize_and_check(
            ProofCertificate::new(vec![ProofStep::Simplification {
                antecedent: ZfcAxiom::Pairing.formula().into(),
                consequent: ZfcAxiom::Union.formula().into(),
            }])
            .unwrap(),
        )
        .unwrap();
        state.register_proof_for_replication(implication).unwrap();
        assert!(maps(&state).iter().all(|map| map.root().is_some()));
        (state, storage)
    }

    fn observed(storage: &MemoryStorage) -> (usize, usize) {
        let reads = storage.reads.lock().unwrap();
        let bytes = storage.bytes.lock().unwrap();
        (
            reads.values().sum(),
            reads
                .iter()
                .map(|(address, count)| count * bytes[address].len())
                .sum(),
        )
    }

    #[test]
    fn each_quantum_counts_every_map_formula_and_nested_bucket_read() {
        let (state, source) = populated();
        let baseline = Arc::new(MemoryStorage::default());
        let synchronous = state.copy_to(baseline.clone()).unwrap();
        let ids = synchronous
            .proof_ids()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut copies = Vec::new();
        for budget in [
            DiskCopyBudget {
                records: 1,
                bytes: CHECKER_MAX_FORMULA_WORK_BYTES,
            },
            DiskCopyBudget {
                records: 64,
                bytes: MAX_NODE_BYTES,
            },
        ] {
            let target = Arc::new(MemoryStorage::default());
            let mut cursor = state.begin_copy(target.clone());
            let mut nodes = 0;
            let mut records = 0;
            for _ in 0..4096 {
                let before = observed(&source);
                let work = cursor.advance(budget).unwrap();
                let after = observed(&source);
                assert_eq!(
                    (after.0 - before.0, after.1 - before.1),
                    (work.records, work.bytes)
                );
                assert!(work.records <= budget.records && work.bytes <= budget.bytes);
                assert!(work.records > 0 || work.complete);
                nodes += work.node_visits;
                records += work.records;
                if work.complete {
                    break;
                }
            }
            assert!(cursor.complete());
            assert!(
                nodes > 8 && records > nodes,
                "formula reads are separate work"
            );
            let before_finish = observed(&source);
            let copied = cursor.finish(&state).unwrap();
            assert_eq!(
                observed(&source),
                before_finish,
                "finish has no hidden walk"
            );
            assert_eq!(
                *target.bytes.lock().unwrap(),
                *baseline.bytes.lock().unwrap()
            );
            assert_eq!(copied.snapshot_id(), synchronous.snapshot_id());
            copies.push(copied);
        }
        // No target can fall back to the original context or hot bytes.
        source.bytes.lock().unwrap().clear();
        for copied in copies {
            assert_eq!(
                copied.proof_ids().collect::<Result<Vec<_>, _>>().unwrap(),
                ids
            );
            for id in &ids {
                let header = copied.proof_header(*id).unwrap().unwrap();
                assert!(
                    copied
                        .statement_formula(header.statement_id(), CHECKER_MAX_FORMULA_WORK_BYTES)
                        .unwrap()
                        .is_some()
                );
            }
        }
    }

    #[test]
    fn maximum_atomic_formula_progresses_and_insufficient_fresh_budget_fails() {
        // A byte-storage boundary fixture, not a registered mathematical proof.
        // It exercises the existing maximum without inventing a smaller limit.
        let source = Arc::new(MemoryStorage::default());
        let mut state = DiskArtifactState::new(source.clone());
        let bytes = vec![42; CHECKER_MAX_FORMULA_WORK_BYTES];
        let address = formula_address(&bytes);
        let id = statement_id(&bytes);
        source.write(address, &bytes).unwrap();
        let mut record = address.to_vec();
        record.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        state.statements.insert(*id.as_bytes(), &record).unwrap();
        let target = Arc::new(MemoryStorage::default());
        let mut cursor = state.begin_copy(target.clone());
        let mut largest = 0;
        for _ in 0..32 {
            let work = cursor
                .advance(DiskCopyBudget {
                    records: 1,
                    bytes: CHECKER_MAX_FORMULA_WORK_BYTES,
                })
                .unwrap();
            largest = largest.max(work.bytes);
            if work.complete {
                break;
            }
        }
        assert!(cursor.complete());
        assert_eq!(largest, CHECKER_MAX_FORMULA_WORK_BYTES);
        drop(cursor.finish(&state).unwrap());
        assert_eq!(target.read(address, bytes.len()).unwrap(), bytes);
        let mut too_small = state.begin_copy(Arc::new(MemoryStorage::default()));
        let mut failed = false;
        for _ in 0..32 {
            match too_small.advance(DiskCopyBudget {
                records: 1,
                bytes: MAX_NODE_BYTES,
            }) {
                Ok(work) => assert!(!work.complete),
                Err(ContextError::Limit) => {
                    failed = true;
                    break;
                }
                Err(error) => panic!("unexpected error: {error}"),
            }
        }
        assert!(failed && !too_small.complete());
        assert!(too_small.finish(&state).is_err());
    }

    #[test]
    fn partial_failed_and_unrelated_copies_cannot_supply_roots() {
        let budget = DiskCopyBudget {
            records: 1,
            bytes: CHECKER_MAX_FORMULA_WORK_BYTES,
        };
        let (state, _) = populated();
        assert!(
            state
                .begin_copy(Arc::new(MemoryStorage::default()))
                .finish(&state)
                .is_err()
        );
        for damage in 0..3 {
            let (state, source) = populated();
            let mut cursor = state.begin_copy(Arc::new(MemoryStorage::default()));
            let address = match damage {
                0 => state.proofs.root().unwrap().address,
                1 => {
                    let (_, record) = state.statements.entries().next().unwrap().unwrap();
                    decode_statement_record(&record).unwrap().0
                }
                _ => {
                    // Damage a nested row only after the top-level maps were
                    // authenticated, so this specifically tests bucket work.
                    while cursor.phase < 9 {
                        cursor.advance(budget).unwrap();
                    }
                    let (_, record) = state.outgoing.entries().next().unwrap().unwrap();
                    decode_root(Some(&record)).unwrap().unwrap().address
                }
            };
            source.bytes.lock().unwrap().get_mut(&address).unwrap()[0] ^= 1;
            let mut failed = false;
            for _ in 0..4096 {
                match cursor.advance(budget) {
                    Ok(work) => assert!(!work.complete),
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            assert!(failed && !cursor.complete());
            assert!(cursor.finish(&state).is_err());
            assert!(!source.failures.lock().unwrap().is_empty());
        }
        let (state, _) = populated();
        let mut cursor = state.begin_copy(Arc::new(MemoryStorage::default()));
        while !cursor.complete() {
            cursor.advance(budget).unwrap();
        }
        let other = DiskArtifactState::new(Arc::new(MemoryStorage::default()));
        assert!(cursor.finish(&other).is_err());
    }
}
