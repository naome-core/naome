use super::*;
use crate::{Envelope, Graph, hex};
use naome_checker::{ContextStorage, ContextView};
use naome_proof::{ProofCertificate, ProofId, ProofStep, StatementId};
use std::{
    cell::RefCell,
    sync::{Arc, Barrier, mpsc},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Fault {
    #[default]
    None,
    SourceBegin,
    TargetBegin,
    SourceInsert,
    TargetInsert,
    SourceCommit,
    TargetCommit,
    Epoch,
    Poison,
    TargetPoison,
    Panic,
}

#[derive(Default)]
struct Probe {
    enabled: bool,
    fault: Fault,
    inserts: Vec<(u64, bool)>,
    boundaries: Vec<(bool, Option<bool>, usize)>,
}
thread_local! {
    static PROBE: RefCell<Probe> = RefCell::new(Probe::default());
}
struct Reset;
fn probe(fault: Fault) -> Reset {
    PROBE.with(|slot| {
        *slot.borrow_mut() = Probe {
            enabled: true,
            fault,
            ..Probe::default()
        }
    });
    Reset
}
impl Drop for Reset {
    fn drop(&mut self) {
        PROBE.with(|slot| *slot.borrow_mut() = Probe::default());
    }
}
pub(super) fn insert_state(generation: u64, autocommit: bool) {
    PROBE.with(|slot| {
        let mut probe = slot.borrow_mut();
        if probe.enabled {
            probe.inserts.push((generation, autocommit));
        }
    });
}
fn autocommit(storage: &CheckedStorage) -> bool {
    storage
        .connection
        .lock()
        .unwrap()
        .open()
        .unwrap()
        .is_autocommit()
}
pub(super) fn before_canonical(source: &CheckedStorage, target: Option<&CheckedStorage>) {
    PROBE.with(|slot| {
        let mut probe = slot.borrow_mut();
        if probe.enabled {
            probe.boundaries.push((
                autocommit(source),
                target.map(autocommit),
                source.owner.lease.summary().unwrap().count,
            ));
        }
        assert!(
            probe.fault != Fault::Panic,
            "injected checked admission panic"
        );
    });
}
pub(super) fn prepare_failure(source: &CheckedStorage, target: Option<&CheckedStorage>) {
    let fault = PROBE.with(|slot| slot.borrow().fault);
    if fault == Fault::Epoch {
        source.write_gate().unwrap().epoch += 1;
        return;
    }
    if matches!(fault, Fault::Poison | Fault::TargetPoison) {
        let storage = if fault == Fault::Poison {
            source
        } else {
            target.unwrap()
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = storage.write_gate().unwrap();
            panic!("injected checked write gate poison");
        }));
        return;
    }
    let storage = match fault {
        Fault::SourceBegin | Fault::SourceInsert | Fault::SourceCommit => source,
        Fault::TargetBegin | Fault::TargetInsert | Fault::TargetCommit => target.unwrap(),
        _ => return,
    };
    let guard = storage.connection.lock().unwrap();
    let connection = guard.open().unwrap();
    match fault {
        Fault::SourceBegin | Fault::TargetBegin => connection.execute_batch("BEGIN").unwrap(),
        Fault::SourceInsert | Fault::TargetInsert => connection
            .execute_batch(
                "CREATE TRIGGER refuse_admission BEFORE INSERT ON nodes BEGIN
                SELECT RAISE(ABORT,'injected checked admission INSERT'); END;",
            )
            .unwrap(),
        Fault::SourceCommit | Fault::TargetCommit => connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
             CREATE TABLE admission_parent(id INTEGER PRIMARY KEY);
             CREATE TABLE admission_child(id INTEGER REFERENCES admission_parent(id)
                 DEFERRABLE INITIALLY DEFERRED);
             CREATE TRIGGER refuse_admission_commit AFTER INSERT ON nodes BEGIN
                 INSERT INTO admission_child(id) VALUES(1); END;",
            )
            .unwrap(),
        _ => unreachable!(),
    }
}

// The same large simplification family as the accepted public process case.
// Sixteen live statements keep the forced copy active through ingest's default step.
fn object(graph: &Graph, index: usize) -> Envelope {
    let mut source = String::from("let:\n    large0 = not(not(not(all(x,eq(x,x)))))\n");
    for level in 1..10 {
        source.push_str(&format!(
            "    large{level} = imp(large{},large{})\n",
            level - 1,
            level - 1
        ));
    }
    let mut previous = "large9".to_owned();
    for (position, bit) in format!("{index:017b}").bytes().enumerate() {
        let name = format!("index{position}");
        let body = if bit == b'1' {
            format!("not({previous})")
        } else {
            format!("all(z,{previous})")
        };
        source.push_str(&format!("    {name} = {body}\n"));
        previous = name;
    }
    source.push_str(&format!("goal = imp({previous},imp({previous},{previous}))\nproof:\n    p0 = simp({previous},{previous})\n    return p0\n"));
    graph.author(&source).unwrap()
}
fn graph(copy: bool) -> Graph {
    let mut graph = Graph::default();
    for index in 8100..8116 {
        let envelope = object(&graph, index);
        graph.ingest(envelope, Instant::now()).unwrap();
    }
    if copy {
        assert!(graph.test_compaction_step(1).unwrap());
    }
    graph
}
fn closed(graph: &Graph, source: &CheckedStorage, target: Option<&CheckedStorage>) {
    assert!(
        source
            .connection
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .0
            .is_none()
    );
    if let Some(target) = target {
        assert!(
            target
                .connection
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .0
                .is_none()
        );
        assert!(
            target
                .write_gate
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .phase_owner
                .is_none()
        );
    }
    assert!(
        source
            .write_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .phase_owner
            .is_none()
    );
    assert!(
        source
            .connection
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .1
            .is_none(),
        "native close must actually succeed"
    );
    if let Some(target) = target {
        assert!(
            target
                .connection
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .1
                .is_none()
        );
    }
    assert!(
        source
            .cache
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed
    );
    assert_eq!(
        source
            .cache
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .charged,
        0
    );
    {
        let mut cache = source
            .cache
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // A reader may have obtained old bytes before the abort and try to
        // cache them afterwards. It must not reopen the shared cache.
        cache.insert([203; 32], b"late cold read".to_vec(), source.generation);
        assert!(cache.closed);
        assert_eq!(cache.charged, 0);
    }
    assert!(graph.storage_error().is_some());
    assert!(source.read([0; 32], 4096).is_err());
    assert!(
        source
            .write([200; 32], b"must not reuse provisional cache tags")
            .is_err()
    );
}

#[test]
fn public_ingest_batches_real_source_and_mirror_inserts_before_canonical_commit() {
    for copy in [false, true] {
        let mut graph = graph(copy);
        let source = graph.checked_storage.clone();
        let target = graph.compaction.as_ref().map(|copy| copy.target.clone());
        let old = graph.context.clone();
        let snapshot = old.snapshot_id();
        let before = graph.store.summary().unwrap();
        let envelope = object(&graph, 8116);
        let id = ProofId::from_bytes(crate::object::id_bytes(&envelope.proof_id).unwrap());
        let _reset = probe(Fault::None);
        assert_eq!(
            graph
                .ingest(envelope.clone(), Instant::now())
                .unwrap()
                .status,
            "accepted"
        );
        PROBE.with(|slot| {
            let probe = slot.borrow();
            assert!(
                probe
                    .inserts
                    .iter()
                    .any(|(generation, _)| *generation == source.generation)
            );
            assert!(
                probe.inserts.iter().all(|(_, autocommit)| !autocommit),
                "a7 per-row autocommit must fail this assertion"
            );
            if let Some(target) = &target {
                assert!(
                    probe
                        .inserts
                        .iter()
                        .any(|(generation, _)| *generation == target.generation)
                );
            }
            assert_eq!(
                probe.boundaries,
                vec![(true, target.as_ref().map(|_| true), before.count)]
            );
        });
        assert!(autocommit(&source));
        if let Some(target) = &target {
            assert!(autocommit(target));
        }
        source.evict_cache();
        assert_eq!(old.snapshot_id(), snapshot);
        assert_eq!(
            old.proof_ids()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .len(),
            16
        );
        assert_eq!(graph.object(id).unwrap(), Some(envelope));
        assert_eq!(graph.accepted_count(), 17);
        assert_eq!(
            graph.describe(id).unwrap_err(),
            "question limit exceeded: question source bytes"
        );
    }
}

#[test]
fn mathematically_invalid_public_ingest_rejects_before_opening_or_halting_a_phase() {
    let mut graph = graph(false);
    let source = graph.checked_storage.clone();
    let root = graph.content_root();
    let bytes = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity {
            variable: naome_foundation::FreeVariable::new(0),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 0,
        },
    ])
    .unwrap()
    .into_unchecked_normal_form()
    .into_canonical_bytes();
    let statement = StatementId::from_bytes([0; 32]);
    let envelope = Envelope {
        compatibility: hex(&crate::compatibility()),
        proof_id: hex(crate::object::content_id(statement, &bytes).as_bytes()),
        statement_id: hex(statement.as_bytes()),
        proof: hex(&bytes),
    };
    let _reset = probe(Fault::None);
    assert!(
        graph
            .ingest(envelope, Instant::now())
            .unwrap_err()
            .contains("mathematically invalid")
    );
    PROBE.with(|slot| {
        assert!(slot.borrow().inserts.is_empty());
        assert!(slot.borrow().boundaries.is_empty());
    });
    assert_eq!(graph.content_root(), root);
    assert!(graph.storage_error().is_none());
    assert!(autocommit(&source));
    let valid = object(&graph, 8116);
    graph.ingest(valid, Instant::now()).unwrap();
}

#[test]
fn begin_insert_commit_epoch_and_poison_failures_close_both_indexes_without_canonical_publication()
{
    for fault in [
        Fault::SourceBegin,
        Fault::TargetBegin,
        Fault::SourceInsert,
        Fault::TargetInsert,
        Fault::SourceCommit,
        Fault::TargetCommit,
        Fault::Epoch,
        Fault::Poison,
        Fault::TargetPoison,
    ] {
        let mut graph = graph(true);
        let source = graph.checked_storage.clone();
        let target = graph.compaction.as_ref().unwrap().target.clone();
        let old = graph.context.clone();
        let root = graph.content_root();
        let snapshot = old.snapshot_id();
        let envelope = object(&graph, 8116);
        let _reset = probe(fault);
        assert!(graph.ingest(envelope, Instant::now()).is_err());
        assert_eq!(graph.content_root(), root);
        assert_eq!(graph.context.snapshot_id(), snapshot);
        assert_eq!(graph.accepted_count(), 16);
        assert_eq!(graph.store.summary().unwrap().count, 16);
        closed(&graph, &source, Some(&target));
        assert!(old.proof_ids().next().unwrap().is_err());
    }
}

#[test]
fn panic_after_checked_commits_discards_connections_and_keeps_canonical_roots() {
    let mut graph = graph(true);
    let source = graph.checked_storage.clone();
    let target = graph.compaction.as_ref().unwrap().target.clone();
    let root = graph.content_root();
    let envelope = object(&graph, 8116);
    let _reset = probe(Fault::Panic);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || graph.ingest(envelope, Instant::now())
        ))
        .is_err()
    );
    assert_eq!(graph.content_root(), root);
    assert_eq!(graph.store.summary().unwrap().count, 16);
    closed(&graph, &source, Some(&target));
}

#[test]
fn canonical_failures_keep_existing_after_commit_ambiguity_and_close_disposable_indexes() {
    use crate::store::BatchCut;
    for cut in [
        BatchCut::BeforeWrite,
        BatchCut::DuringWrite,
        BatchCut::BeforeCommit,
        BatchCut::AfterCommit,
    ] {
        let mut graph = graph(true);
        let source = graph.checked_storage.clone();
        let target = graph.compaction.as_ref().unwrap().target.clone();
        let root = graph.content_root();
        let envelope = object(&graph, 8116);
        graph.test_batch_cut(cut);
        assert!(graph.ingest(envelope, Instant::now()).is_err());
        assert_eq!(graph.content_root(), root);
        assert_eq!(graph.accepted_count(), 16);
        assert_eq!(
            graph.store.summary().unwrap().count,
            if cut == BatchCut::AfterCommit { 17 } else { 16 }
        );
        closed(&graph, &source, Some(&target));
    }
}

#[test]
fn foreign_writer_waits_while_cold_old_reader_succeeds_and_abort_wakes_it_closed() {
    for abort in [false, true] {
        let graph = graph(true);
        let source = graph.checked_storage.clone();
        let target = graph.compaction.as_ref().unwrap().target.clone();
        let old = graph.context.clone();
        let phase = source.admission_phase().unwrap();
        source
            .write([201; 32], b"provisional same-owner row")
            .unwrap();
        source.evict_cache();
        assert_eq!(
            old.proof_ids()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .len(),
            16
        );
        let start = Arc::new(Barrier::new(2));
        let (sent, received) = mpsc::channel();
        let writer_source = source.clone();
        let writer_start = start.clone();
        let writer = std::thread::spawn(move || {
            writer_start.wait();
            sent.send(writer_source.write([202; 32], b"foreign bounded row"))
                .unwrap();
        });
        start.wait();
        assert!(matches!(
            received.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        if abort {
            drop(phase);
            assert!(
                received
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .is_err()
            );
            closed(&graph, &source, Some(&target));
        } else {
            let mut gates = phase.finish(source.as_ref()).unwrap();
            phase.published(&mut gates);
            drop(gates);
            drop(phase);
            received
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
            source.evict_cache();
            assert_eq!(
                source.read([202; 32], 4096).unwrap(),
                b"foreign bounded row"
            );
            target.evict_cache();
            assert_eq!(
                target.read([202; 32], 4096).unwrap(),
                b"foreign bounded row"
            );
        }
        writer.join().unwrap();
    }
}

#[test]
fn prepared_batch_staleness_deadline_and_last_snapshot_generation_lifetime_survive_admission() {
    const SOURCE: &str = "goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1";
    let mut graph = graph(false);
    let source = graph.checked_storage.clone();
    let path = source.path.clone();
    let weak = Arc::downgrade(&source);
    let old = graph.context.clone();
    let snapshot = old.snapshot_id();
    let question = naome_authoring::CompiledQuestion::compile("goal = all(x,eq(x,x))").unwrap();
    let (id, batch) = graph.prepare_generated(SOURCE, &[], &question).unwrap();
    let envelope = object(&graph, 8116);
    graph.ingest(envelope, Instant::now()).unwrap();
    assert!(
        graph
            .commit_batch(id, batch, Instant::now() + Duration::from_secs(1))
            .unwrap_err()
            .contains("stale")
    );
    let (id, batch) = graph.prepare_generated(SOURCE, &[], &question).unwrap();
    assert_eq!(
        graph.commit_batch(id, batch, Instant::now() - Duration::from_secs(1)),
        Err(crate::store::COMMIT_DEADLINE_ERROR.into())
    );
    assert!(graph.storage_error().is_none());
    assert!(autocommit(&source));
    assert!(graph.test_compaction_step(1).unwrap());
    for _ in 0..4096 {
        graph.maintain_checked_storage().unwrap();
        if graph.compaction.is_none() {
            break;
        }
    }
    assert!(graph.compaction.is_none());
    source.evict_cache();
    assert_eq!(old.snapshot_id(), snapshot);
    assert_eq!(
        old.proof_ids()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len(),
        16
    );
    assert!(path.exists());
    drop(source);
    assert!(weak.upgrade().is_some());
    drop(old);
    assert!(weak.upgrade().is_none());
    assert!(!path.exists());
}
