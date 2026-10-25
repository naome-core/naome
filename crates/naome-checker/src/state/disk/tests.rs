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
