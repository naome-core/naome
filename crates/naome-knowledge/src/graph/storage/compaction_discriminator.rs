use super::*;
use crate::Graph;
use naome_checker::{CHECKER_MAX_FORMULA_WORK_BYTES as WORK_BYTES, ContextView, DiskCopyBudget};
use naome_proof::{DerivationId, ProofId, StatementId};
use std::fmt::Write;
type Expected = (ProofId, StatementId, DerivationId, Vec<u8>);
fn fixture(index: usize) -> (String, Vec<u8>, Vec<u8>) {
    assert!((8100..130712).contains(&index));
    let mut source = String::from("let:\n    large0 = not(not(not(all(x,eq(x,x)))))\n");
    let mut formula = vec![2, 2, 2, 4, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    for level in 1..10 {
        writeln!(
            source,
            "    large{level} = imp(large{},large{})",
            level - 1,
            level - 1
        )
        .unwrap();
        formula = [vec![3], formula.clone(), formula].concat();
    }
    let mut last = "large9".to_owned();
    for (position, bit) in format!("{index:017b}").bytes().enumerate() {
        let name = format!("index{position}");
        let body = if bit == b'1' {
            format!("not({last})")
        } else {
            format!("all(z,{last})")
        };
        writeln!(source, "    {name} = {body}").unwrap();
        formula.insert(0, if bit == b'1' { 2 } else { 4 });
        last = name;
    }
    write!(source, "goal = imp({last},imp({last},{last}))\nproof:\n    p0 = simp({last},{last})\n    return p0\n").unwrap();
    let length = u32::try_from(formula.len()).unwrap().to_be_bytes().to_vec();
    let proof = [
        vec![0, 0, 0, 1, 0],
        length.clone(),
        formula.clone(),
        length,
        formula.clone(),
    ]
    .concat();
    let goal = [vec![3], formula.clone(), vec![3], formula.clone(), formula].concat();
    assert_eq!((proof.len(), goal.len()), (16429, 24626));
    (source, proof, goal)
}
fn admit(g: &mut Graph, index: usize) -> Expected {
    let (source, proof, goal) = fixture(index);
    let envelope = g.author(&source).unwrap();
    let candidate = envelope.clone().prepare().unwrap();
    assert_eq!(candidate.normal.canonical_bytes(), proof);
    let (id, statement) = (candidate.id, candidate.statement);
    g.admit(candidate).unwrap();
    assert_eq!(g.object(id).unwrap(), Some(envelope));
    let header = g.context.proof_header(id).unwrap().unwrap();
    (id, statement, header.derivation_id(), goal)
}
fn verify(context: &DiskArtifactState, proofs: &[Expected]) {
    let mut ids: Vec<_> = proofs.iter().map(|row| row.0).collect();
    ids.sort();
    assert_eq!(
        context.proof_ids().collect::<Result<Vec<_>, _>>().unwrap(),
        ids
    );
    for (id, statement, derivation, bytes) in proofs {
        let header = context.proof_header(*id).unwrap().unwrap();
        assert_eq!(header.statement_id(), *statement);
        assert_eq!(header.derivation_id(), *derivation);
        assert_eq!(header.canonical_length(), bytes.len());
        let formula = context
            .statement_formula(*statement, WORK_BYTES)
            .unwrap()
            .unwrap();
        assert_eq!(formula.encode_canonical().unwrap(), *bytes);
    }
}
fn rows(storage: &CheckedStorage) -> usize {
    let rows: i64 = storage
        .connection
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM nodes", [], |row| row.get(0))
        .unwrap();
    usize::try_from(rows).unwrap()
}
fn drain(g: &mut Graph, limit: usize) -> usize {
    for step in 1..=limit {
        g.maintain_checked_storage_step(
            usize::MAX,
            DiskCopyBudget {
                records: 64,
                bytes: WORK_BYTES,
            },
        )
        .unwrap();
        if g.compaction.is_none() {
            return step;
        }
    }
    panic!("copy step bound");
}
fn oracle(g: &Graph) -> (DiskArtifactState, Arc<CheckedStorage>, usize, usize, usize) {
    let target = g.checked_storage.successor().unwrap();
    let mut cursor = g.context.begin_copy(target.clone());
    let budget = DiskCopyBudget {
        records: 7,
        bytes: WORK_BYTES,
    };
    let (mut records, mut bytes) = (0, 0);
    for step in 1..=g.accepted_count() * 128 {
        target.begin_write_phase().unwrap();
        let work = cursor.advance(budget).unwrap();
        target.finish_write_phase().unwrap();
        assert!(work.records <= budget.records && work.bytes <= budget.bytes);
        assert!(work.node_visits <= work.records && (work.records > 0 || work.complete));
        records += work.records;
        bytes += work.bytes;
        if work.complete {
            assert!(cursor.complete() && step > 1 && records >= g.accepted_count());
            let context = cursor.finish(&g.context).unwrap();
            return (context, target, step, records, bytes);
        }
    }
    panic!("bounded current oracle did not finish");
}
#[test]
#[ignore = "Bounded structural diagnosis"]
fn r10_compaction_reachable_history_and_last_snapshot_lifetime() {
    for size in [32, 128] {
        let mut states = Vec::new();
        for mode in 0..3 {
            let mut g = Graph {
                next_compaction: usize::MAX,
                ..Graph::default()
            };
            let mut proofs: Vec<_> = (8100..8100 + size / 2)
                .map(|index| admit(&mut g, index))
                .collect();
            let old = g.context.clone();
            let old_snapshot = old.snapshot_id();
            let old_owner = Arc::downgrade(&g.checked_storage);
            let old_path = g.checked_storage.path.clone();
            let base_rows = rows(&g.checked_storage);
            let base_bytes = g.checked_storage.allocated_bytes().unwrap();
            let mut quanta = 0;
            if mode != 0 {
                assert!(g.test_compaction_step(1).unwrap());
                quanta += 1;
                if mode == 2 {
                    quanta += drain(&mut g, size * 128);
                }
            }
            for index in 8100 + size / 2..8100 + size {
                proofs.push(admit(&mut g, index));
                if mode == 1 {
                    assert!(g.test_compaction_step(1).unwrap());
                    quanta += 1;
                }
            }
            let old_rows = rows(&old_owner.upgrade().unwrap());
            let old_bytes = old_owner.upgrade().unwrap().allocated_bytes().unwrap();
            if mode == 2 {
                assert_eq!(old_rows, base_rows);
            } else {
                assert!(old_rows > base_rows && old_bytes >= base_bytes);
            }
            let active_target = g
                .compaction
                .as_ref()
                .map(|copy| (rows(&copy.target), copy.target.allocated_bytes().unwrap()));
            if mode == 1 {
                quanta += drain(&mut g, size * 128);
            }
            assert!(g.compaction.is_none());
            g.checked_storage.evict_cache();
            verify(&old, &proofs[..size / 2]);
            assert_eq!(old.snapshot_id(), old_snapshot);
            g.checked_storage.evict_cache();
            verify(&g.context, &proofs);
            g.checked_storage.evict_cache();
            let (fresh, storage, steps, records, bytes) = oracle(&g);
            storage.evict_cache();
            verify(&fresh, &proofs);
            assert_eq!(fresh.snapshot_id(), g.context.snapshot_id());
            let reachable = rows(&storage);
            let retained = rows(&g.checked_storage);
            assert!(retained >= reachable);
            assert_eq!(g.accepted_count(), size);
            assert_eq!(g.store.summary().unwrap().count, size);
            assert!(g.storage_error().is_none());
            states.push((g.content_root(), g.context.snapshot_id()));
            let observation = serde_json::json!({"size":size,"mode":(["no_copy","copy_active","copy_completed"][mode]),
                "base_rows":base_rows,"base_allocated":base_bytes,"old_rows":old_rows,"old_allocated":old_bytes,"active_target":active_target,
                "retained_rows":retained,"allocated":g.checked_storage.allocated_bytes().unwrap(),
                "reachable_rows":reachable,"obsolete_rows":retained-reachable,"oracle_allocated":storage.allocated_bytes().unwrap(),
                "quanta":quanta,"oracle_steps":steps,"oracle_records":records,"oracle_raw_bytes":bytes});
            drop(fresh);
            drop(storage);
            assert!(old_path.exists());
            drop(old);
            if mode == 0 {
                assert!(old_owner.upgrade().is_some() && old_path.exists());
            } else {
                assert!(old_owner.upgrade().is_none() && !old_path.exists());
            }
            drop(g);
            assert!(old_owner.upgrade().is_none() && !old_path.exists());
            println!("{observation}");
        }
        assert!(states.windows(2).all(|pair| pair[0] == pair[1]));
    }
}
