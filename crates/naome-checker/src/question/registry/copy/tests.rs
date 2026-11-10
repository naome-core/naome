use super::*;
use naome_foundation::ZfcAxiom;
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
struct Storage {
    bytes: Mutex<BTreeMap<Identity, Vec<u8>>>,
    reads: Mutex<(usize, usize)>,
    failures: Mutex<Vec<ContextError>>,
    fail_writes: Mutex<bool>,
}
impl ContextStorage for Storage {
    fn read(&self, address: Identity, maximum: usize) -> Result<Vec<u8>, ContextError> {
        let records = self.bytes.lock().unwrap();
        let bytes = records.get(&address).ok_or(ContextError::Corrupt)?;
        if bytes.len() > maximum {
            return Err(ContextError::Limit);
        }
        let mut reads = self.reads.lock().unwrap();
        reads.0 += 1;
        reads.1 += bytes.len();
        Ok(bytes.clone())
    }
    fn write(&self, address: Identity, bytes: &[u8]) -> Result<(), ContextError> {
        if *self.fail_writes.lock().unwrap() {
            return Err(ContextError::Storage(
                naome_proof::ContextStorageFailure::Injected,
            ));
        }
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
fn registry() -> (QuestionRegistry, Arc<Storage>, QuestionRegistry) {
    let storage = Arc::new(Storage::default());
    let mut disk = QuestionRegistry::with_storage(storage.clone());
    let mut oracle = QuestionRegistry::new();
    for (record, formula) in [
        ([1; 32], ZfcAxiom::Pairing.formula()),
        ([2; 32], ZfcAxiom::Union.formula()),
        ([3; 32], ZfcAxiom::Pairing.formula()),
    ] {
        let entry = RegisteredQuestion::new(record, &formula).unwrap();
        disk.insert(entry).unwrap();
        oracle
            .insert(RegisteredQuestion::new(record, &formula).unwrap())
            .unwrap();
    }
    (disk, storage, oracle)
}

#[test]
fn duplicate_cold_record_preserves_registry_and_storage() {
    let (mut disk, storage, _) = registry();
    let identity = disk.identity();
    let bytes = storage.bytes.lock().unwrap().clone();
    let other = ZfcAxiom::Union.formula();
    let entry = RegisteredQuestion::new([1; 32], &other).unwrap();
    assert_eq!(
        disk.insert(entry),
        Err(crate::question::RejectionReason::InvalidRegistry)
    );
    assert_eq!(disk.identity(), identity);
    assert_eq!(*storage.bytes.lock().unwrap(), bytes);
    assert!(storage.failures.lock().unwrap().is_empty());
}

#[test]
fn cold_formula_membership_authenticates_the_matching_bytes() {
    let (disk, storage, _) = registry();
    let formula = ZfcAxiom::Pairing.formula();
    assert_eq!(disk.contains(&formula), Ok(true));
    assert_eq!(disk.contains(&ZfcAxiom::Infinity.formula()), Ok(false));

    let address = cold::formula_address(&formula.encode_canonical().unwrap());
    storage.bytes.lock().unwrap().get_mut(&address).unwrap()[0] ^= 1;
    assert_eq!(disk.contains(&formula), Err(ContextError::Corrupt));
    assert_eq!(*storage.failures.lock().unwrap(), [ContextError::Corrupt]);
}

#[test]
fn cold_formula_matching_rejects_authenticated_invalid_formulas() {
    use naome_foundation::{FreeVariable, graph::Node};

    let variable = FreeVariable::new(0);
    let quantified = Formula::for_all(variable, Formula::equal(variable, variable));
    let Node::ForAll(body) = quantified.view().graph_node() else {
        panic!("expected a quantifier");
    };
    let dangling = body.to_owned();
    let open = Formula::equal(variable, variable);
    let valid = ZfcAxiom::Pairing.formula();
    for formula in [dangling, open] {
        let storage = Arc::new(Storage::default());
        let mut cold = cold::DiskRegistry::new(storage.clone());
        let bytes = formula.encode_canonical().unwrap();
        let address = cold::formula_address(&bytes);
        storage.write(address, &bytes).unwrap();
        let mut metadata = [0; 72];
        metadata[..32].copy_from_slice(statement_id(&bytes).as_bytes());
        metadata[32..64].copy_from_slice(&address);
        metadata[64..].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
        let record = [9; 32];
        cold.records.insert(record, &metadata).unwrap();

        assert_eq!(cold.get(&record), Err(ContextError::Corrupt));
        assert_eq!(
            cold.matches_formula(&record, &formula, &bytes),
            Err(ContextError::Corrupt)
        );
        assert_eq!(
            cold.matches_formula(&record, &valid, &valid.encode_canonical().unwrap()),
            Err(ContextError::Corrupt)
        );
        assert_eq!(
            *storage.failures.lock().unwrap(),
            vec![ContextError::Corrupt; 3]
        );
    }
}

#[test]
fn registry_copy_accounts_every_read_and_survives_loss_of_source_storage() {
    for budget in [
        DiskCopyBudget {
            records: 1,
            bytes: 1024 * 1024,
        },
        DiskCopyBudget {
            records: 64,
            bytes: 4096,
        },
    ] {
        let (registry, source, oracle) = registry();
        source.write([99; 32], b"unreachable bytes").unwrap();
        let target = Arc::new(Storage::default());
        let mut copy = registry.begin_copy(target.clone()).unwrap();
        loop {
            let before = *source.reads.lock().unwrap();
            let progress = copy.advance(budget).unwrap();
            let after = *source.reads.lock().unwrap();
            assert_eq!(
                (after.0 - before.0, after.1 - before.1),
                (progress.records, progress.bytes)
            );
            assert!(progress.records <= budget.records && progress.bytes <= budget.bytes);
            assert!(progress.records > 0 || progress.complete);
            if progress.complete {
                break;
            }
        }
        let before = *source.reads.lock().unwrap();
        let copied = copy.finish(&registry).unwrap();
        assert_eq!(
            *source.reads.lock().unwrap(),
            before,
            "root publication performs no hidden reads"
        );
        assert!(!target.bytes.lock().unwrap().contains_key(&[99; 32]));
        source.bytes.lock().unwrap().clear();
        assert_eq!(copied.identity(), oracle.identity());
        assert_eq!(copied.len(), 3);
        for record in [[1; 32], [2; 32], [3; 32]] {
            let formula = oracle.get(&record).unwrap().unwrap();
            assert_eq!(
                copied.get(&record).unwrap().as_deref(),
                Some(formula.as_ref())
            );
            let statement = statement_id(&formula.encode_canonical().unwrap());
            assert_eq!(
                copied
                    .records_for(statement)
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                oracle
                    .records_for(statement)
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
            );
        }
    }
}

#[test]
fn partial_corrupt_and_failed_registry_copies_cannot_publish_roots() {
    let budget = DiskCopyBudget {
        records: 1,
        bytes: 1024 * 1024,
    };
    let (registry, _, _) = registry();
    assert!(
        registry
            .begin_copy(Arc::new(Storage::default()))
            .unwrap()
            .finish(&registry)
            .is_err()
    );
    for damage in 0..2 {
        let (registry, source, _) = self::registry();
        let target = Arc::new(Storage::default());
        if damage == 0 {
            let cold = registry.cold.as_ref().unwrap();
            let (_, record) = cold.records.entries().next().unwrap().unwrap();
            let address: Identity = record[32..64].try_into().unwrap();
            source.bytes.lock().unwrap().get_mut(&address).unwrap()[0] ^= 1;
        } else {
            *target.fail_writes.lock().unwrap() = true;
        }
        let mut copy = registry.begin_copy(target.clone()).unwrap();
        let error = loop {
            match copy.advance(budget) {
                Ok(progress) => assert!(!progress.complete),
                Err(error) => break error,
            }
        };
        assert!(source.failures.lock().unwrap().contains(&error));
        *target.fail_writes.lock().unwrap() = false;
        assert!(
            copy.advance(budget).is_err(),
            "a failed cursor cannot resume"
        );
        assert!(copy.finish(&registry).is_err());
    }
    let mut copy = registry.begin_copy(Arc::new(Storage::default())).unwrap();
    while !copy.advance(budget).unwrap().complete {}
    let unrelated = QuestionRegistry::with_storage(Arc::new(Storage::default()));
    assert!(copy.finish(&unrelated).is_err());
}

#[test]
fn registry_cursor_reports_corrupted_bucket_and_stops() {
    let (disk, storage, _) = registry();
    let formula = ZfcAxiom::Pairing.formula();
    let statement = statement_id(&formula.encode_canonical().unwrap());
    let cold = disk.cold.as_ref().unwrap();
    let encoded_root = cold.statements.get(statement.as_bytes()).unwrap().unwrap();
    let address: Identity = encoded_root[..32].try_into().unwrap();
    storage.bytes.lock().unwrap().get_mut(&address).unwrap()[0] ^= 1;

    let mut entries = disk.records_for(statement).unwrap();
    assert_eq!(entries.next(), Some(Err(ContextError::Corrupt)));
    assert_eq!(entries.next(), None);
    assert_eq!(
        *storage.failures.lock().unwrap(),
        [ContextError::Corrupt, ContextError::Corrupt]
    );
}
