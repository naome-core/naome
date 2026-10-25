use super::super::tests::{MemoryStorage, register_axiom};
use super::*;
use crate::{CHECKER_MAX_FORMULA_WORK_BYTES, ContextView};
use naome_foundation::ZfcAxiom;
use naome_proof::{ProofCertificate, ProofStep};

fn populated() -> (DiskArtifactState, Arc<MemoryStorage>) {
    let storage = Arc::new(MemoryStorage::default());
    let mut state = DiskArtifactState::new(storage.clone());
    let _ = register_axiom(&mut state, ZfcAxiom::Pairing);
    let _ = register_axiom(&mut state, ZfcAxiom::Union);
    let implication = crate::normalize_and_check(
        ProofCertificate::new(vec![ProofStep::Simplification {
            antecedent: ZfcAxiom::Pairing.formula().into(),
            consequent: ZfcAxiom::Union.formula().into(),
        }])
        .unwrap(),
    )
    .unwrap();
    state.register_proof_for_replication(implication).unwrap();
    assert!(maps(&state)[..8].iter().all(|map| map.root().is_some()));
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
                while matches!(cursor.phase, Phase::Map(_)) {
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

#[test]
fn graph_statement_membership_reads_are_part_of_each_copy_quantum() {
    let (state, source) = populated();
    let program = super::super::tests::checked_program(true);
    let mut registration = state.begin_program_registration(&program).unwrap();
    while !registration.complete() {
        registration.advance(&program, 17).unwrap();
    }
    let state = registration.finish().unwrap();
    assert!(maps(&state).iter().all(|map| map.root().is_some()));
    // Entries and public bucket queries are independent of the copy cursor.
    let expected = maps(&state).map(|map| map.entries().collect::<Result<Vec<_>, _>>().unwrap());
    let mut buckets = Vec::new();
    for kind in [
        crate::context::BucketKind::Outgoing,
        crate::context::BucketKind::Deductions,
        crate::context::BucketKind::Instances,
    ] {
        for entry in state.index(kind).entries() {
            let (target, _) = entry.unwrap();
            let target = StatementId::from_bytes(target);
            let expected = state
                .bucket(kind, target)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            buckets.push((kind, target, expected));
        }
    }
    let mut copy = state.begin_copy(Arc::new(MemoryStorage::default()));
    let budget = DiskCopyBudget {
        records: 1,
        bytes: CHECKER_MAX_FORMULA_WORK_BYTES,
    };
    while !copy.complete() {
        let before = observed(&source);
        let work = copy.advance(budget).unwrap();
        let after = observed(&source);
        assert_eq!(
            (after.0 - before.0, after.1 - before.1),
            (work.records, work.bytes)
        );
        assert!(work.records <= budget.records && work.bytes <= budget.bytes);
    }
    let copied = copy.finish(&state).unwrap();
    source.bytes.lock().unwrap().clear();
    assert_eq!(
        maps(&copied).map(|map| map.entries().collect::<Result<Vec<_>, _>>().unwrap()),
        expected
    );
    for (kind, target, expected) in buckets {
        assert_eq!(
            copied
                .bucket(kind, target)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            expected
        );
    }
    assert!(
        copied
            .contains_proof(program.manifest().proof_id())
            .unwrap()
    );
}
