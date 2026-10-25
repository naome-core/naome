mod compaction;
use super::*;
use crate::Graph;
use naome_checker::ContextView;

#[test]
fn hot_reads_keep_owned_bytes_and_cached_allocation_generation_and_charge() {
    let graph = Graph::default();
    let storage = &graph.checked_storage;
    let address = [47; 32];
    let bytes = vec![7; 4096];
    storage.write(address, &bytes).unwrap();
    let (pointer, capacity, charged) = {
        let mut cache = storage.cache.lock().unwrap();
        let mut cached = Vec::with_capacity(bytes.len() + 4096);
        cached.extend_from_slice(&bytes);
        cache.insert(address, cached, storage.generation);
        let entry = &cache.entries[&address];
        (entry.bytes.as_ptr(), entry.bytes.capacity(), cache.charged)
    };
    let successor = storage.successor().unwrap();
    let mut owned = successor.read(address, bytes.len()).unwrap();
    assert_eq!(owned, bytes);
    owned[0] ^= 1;
    assert_eq!(successor.read(address, bytes.len()).unwrap(), bytes);
    let clock = {
        let cache = storage.cache.lock().unwrap();
        let entry = &cache.entries[&address];
        assert_eq!(entry.bytes.as_ptr(), pointer);
        assert_eq!(entry.bytes.capacity(), capacity);
        assert_eq!(entry.state, EntryState::Persisted(storage.generation));
        assert_eq!(cache.charged, charged);
        assert!(cache.charged <= crate::resources::limits().checked_cache_bytes);
        cache.clock
    };
    assert!(matches!(
        successor.read(address, bytes.len() - 1),
        Err(ContextError::Limit)
    ));
    assert_eq!(storage.cache.lock().unwrap().clock, clock);
    assert!(graph.storage_error().is_some());
}

#[test]
fn hot_read_and_write_rollover_preserves_generation_charge_and_successor_persistence() {
    for write_hit in [false, true] {
        let graph = Graph::default();
        let storage = &graph.checked_storage;
        let address = [48; 32];
        let bytes = vec![8; 4096];
        storage.write(address, &bytes).unwrap();
        storage.write([49; 32], &bytes).unwrap();
        let successor = storage.successor().unwrap();
        let (pointer, capacity, charged) = {
            let mut cache = storage.cache.lock().unwrap();
            let mut cached = Vec::with_capacity(bytes.len() + 4096);
            cached.extend_from_slice(&bytes);
            cache.insert(address, cached, storage.generation);
            cache.clock = u64::MAX - 1;
            let entry = &cache.entries[&address];
            (entry.bytes.as_ptr(), entry.bytes.capacity(), cache.charged)
        };
        let hit = || {
            if write_hit {
                storage.write(address, &bytes).unwrap();
            } else {
                assert_eq!(successor.read(address, bytes.len()).unwrap(), bytes);
            }
        };
        hit();
        {
            let cache = storage.cache.lock().unwrap();
            assert_eq!(cache.clock, u64::MAX);
            assert_eq!(cache.entries.len(), 2);
            assert_eq!(cache.recency.len(), 2);
            assert_eq!(cache.recency.get(&u64::MAX), Some(&address));
            assert_eq!(cache.charged, charged);
        }
        hit();
        {
            let cache = storage.cache.lock().unwrap();
            let entry = &cache.entries[&address];
            assert_eq!(cache.clock, 1);
            assert_eq!(cache.entries.len(), 1);
            assert_eq!(cache.recency.len(), 1);
            assert_eq!(cache.recency.get(&1), Some(&address));
            assert_eq!(entry.clock, 1);
            assert_eq!(entry.bytes.as_ptr(), pointer);
            assert_eq!(entry.bytes.capacity(), capacity);
            assert_eq!(entry.state, EntryState::Persisted(storage.generation));
            assert_eq!(cache.charged, capacity + CACHE_ENTRY_BYTES);
            assert!(cache.charged <= crate::resources::limits().checked_cache_bytes);
        }
        successor.write(address, &bytes).unwrap();
        successor.evict_cache();
        assert_eq!(successor.read(address, bytes.len()).unwrap(), bytes);
        storage.evict_cache();
        assert_eq!(storage.read(address, bytes.len()).unwrap(), bytes);
        assert!(graph.storage_error().is_none());
    }
}

#[test]
fn cold_records_decode_with_raw_cache_charges_and_caller_bounds() {
    let graph = Graph::default();
    let storage = &graph.checked_storage;
    let bytes = vec![0; 16 * 1024];
    let address = [41; 32];
    storage.write(address, &bytes).unwrap();
    storage.write(address, &bytes).unwrap();
    let (count, stored): (i64, i64) = storage
        .connection
        .lock()
        .unwrap()
        .open()
        .unwrap()
        .query_row(
            "SELECT count(*),sum(length(payload)) FROM nodes",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(count, 1);
    assert!(stored < bytes.len() as i64 / 10);
    assert_eq!(
        storage.cache.lock().unwrap().charged,
        bytes.len() + CACHE_ENTRY_BYTES
    );
    storage.evict_cache();
    assert_eq!(storage.read(address, bytes.len()).unwrap(), bytes);
    assert_eq!(
        storage.cache.lock().unwrap().charged,
        bytes.len() + CACHE_ENTRY_BYTES
    );
    storage.evict_cache();
    assert!(matches!(
        storage.read(address, bytes.len() - 1),
        Err(ContextError::Limit)
    ));
    assert!(graph.storage_error().is_some());
}

#[test]
fn conflicting_raw_bytes_do_not_replace_a_compressed_record() {
    let graph = Graph::default();
    let storage = &graph.checked_storage;
    let bytes = vec![0; 4096];
    let address = [42; 32];
    storage.write(address, &bytes).unwrap();
    let mut conflict = bytes.clone();
    conflict[2000] = 1;
    assert!(matches!(
        storage.write(address, &conflict),
        Err(ContextError::Corrupt)
    ));
    storage.evict_cache();
    assert_eq!(storage.read_inner(address, bytes.len()).unwrap(), bytes);
    assert!(graph.storage_error().is_some());
}

#[test]
fn cold_identical_and_conflicting_writes_preserve_the_original_payload() {
    let graph = Graph::default();
    let storage = &graph.checked_storage;
    let bytes = vec![0; 4096];
    let address = [46; 32];
    storage.write(address, &bytes).unwrap();
    let stored = || -> Vec<u8> {
        storage
            .connection
            .lock()
            .unwrap()
            .open()
            .unwrap()
            .query_row(
                "SELECT payload FROM nodes WHERE address=?1",
                params![address.as_slice()],
                |row| row.get(0),
            )
            .unwrap()
    };
    let original = stored();
    storage.evict_cache();
    storage.write(address, &bytes).unwrap();
    assert_eq!(stored(), original);
    assert!(graph.storage_error().is_none());
    storage.evict_cache();
    let mut conflict = bytes.clone();
    conflict[2000] = 1;
    assert!(matches!(
        storage.write(address, &conflict),
        Err(ContextError::Corrupt)
    ));
    assert_eq!(stored(), original);
    storage.evict_cache();
    assert_eq!(storage.read_inner(address, bytes.len()).unwrap(), bytes);
    assert!(graph.storage_error().is_some());
}

#[test]
fn cached_old_bytes_still_persist_in_a_successor_generation() {
    let graph = Graph::default();
    let old = &graph.checked_storage;
    let bytes = vec![0; 4096];
    let address = [45; 32];
    old.write(address, &bytes).unwrap();
    let successor = old.successor().unwrap();
    // This shared-cache read must not claim a row in the empty successor.
    assert_eq!(successor.read(address, bytes.len()).unwrap(), bytes);
    successor.write(address, &bytes).unwrap();
    successor.evict_cache();
    assert_eq!(successor.read(address, bytes.len()).unwrap(), bytes);
    old.evict_cache();
    assert_eq!(old.read(address, bytes.len()).unwrap(), bytes);
    assert!(graph.storage_error().is_none());
}

fn rows(storage: &CheckedStorage, address: [u8; 32]) -> i64 {
    storage
        .connection
        .lock()
        .unwrap()
        .open()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM nodes WHERE address=?1",
            [address.as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

fn checked_graph() -> Graph {
    let mut graph = Graph::default();
    let object = graph
        .author("goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1")
        .unwrap();
    graph.ingest(object, std::time::Instant::now()).unwrap();
    graph
}

#[test]
fn every_cached_existing_and_unreferenced_write_reaches_the_mirror() {
    for cached in [false, true] {
        for target_existing in [false, true] {
            let graph = Graph::default();
            let source = &graph.checked_storage;
            let target = source.successor().unwrap();
            let address = [67; 32];
            let bytes = vec![5; 8192];
            source.write(address, &bytes).unwrap();
            if target_existing {
                target.write(address, &bytes).unwrap();
            }
            if cached {
                source
                    .cache
                    .lock()
                    .unwrap()
                    .insert(address, bytes.clone(), source.generation);
            } else {
                source.evict_cache();
            }
            assert_eq!(rows(&target, address), if target_existing { 1 } else { 0 });
            let epoch = source
                .write_gate()
                .unwrap()
                .attach(source, target.clone())
                .unwrap();
            source.write(address, &bytes).unwrap();
            source.write_gate().unwrap().detach(epoch, &target).unwrap();
            // Reads alone could use another generation's shared hot bytes.
            // Evict the entire cache before establishing either SQL row.
            target.evict_cache();
            assert_eq!(target.read(address, bytes.len()).unwrap(), bytes);
            source.evict_cache();
            assert_eq!(source.read(address, bytes.len()).unwrap(), bytes);
            assert_eq!(rows(&target, address), 1);
            assert!(Arc::ptr_eq(&source.cache, &target.cache));
            assert!(
                source.cache.lock().unwrap().charged
                    <= crate::resources::limits().checked_cache_bytes
            );
            assert!(graph.storage_error().is_none());
        }
    }
}

#[test]
fn conflicting_mirror_row_is_not_repaired_or_hidden_by_a_source_cache_hit() {
    let graph = Graph::default();
    let source = &graph.checked_storage;
    let target = source.successor().unwrap();
    let address = [71; 32];
    source.write(address, b"original source").unwrap();
    target.write(address, b"different target").unwrap();
    source
        .cache
        .lock()
        .unwrap()
        .insert(address, b"original source".to_vec(), source.generation);
    let epoch = source
        .write_gate()
        .unwrap()
        .attach(source, target.clone())
        .unwrap();
    assert!(matches!(
        source.write(address, b"original source"),
        Err(ContextError::Corrupt)
    ));
    source.abort_copy(epoch, &target);
    assert!(source.write_gate().unwrap().mirror.is_none());
    target.evict_cache();
    assert_eq!(
        target.read_uncached(address, 64).unwrap(),
        b"different target"
    );
    source.evict_cache();
    assert_eq!(
        source.read_uncached(address, 64).unwrap(),
        b"original source"
    );
    assert!(graph.storage_error().is_some());
}

#[test]
fn source_gate_orders_real_writes_before_attach_and_current_root_handoff() {
    use std::sync::Barrier;
    for finishing in [false, true] {
        let mut graph = checked_graph();
        if finishing {
            assert!(graph.test_compaction_step(1).unwrap());
        }
        let source = graph.checked_storage.clone();
        let paused = Arc::new(Barrier::new(2));
        let writer_pause = paused.clone();
        let writer_source = source.clone();
        let writer = std::thread::spawn(move || {
            WRITE_TEST_PAUSE.with(|slot| *slot.borrow_mut() = Some(writer_pause));
            writer_source
                .write([68; 32], b"inflight immutable bytes")
                .unwrap();
        });
        paused.wait(); // writer owns the actual source gate
        let started = Arc::new(Barrier::new(2));
        let operation_started = started.clone();
        let operation = std::thread::spawn(move || {
            operation_started.wait();
            if finishing {
                for _ in 0..4096 {
                    let _ = graph
                        .maintain_checked_storage_step(
                            usize::MAX,
                            naome_checker::DiskCopyBudget {
                                records: 1,
                                bytes: naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES,
                            },
                        )
                        .unwrap();
                    if graph.compaction.is_none() {
                        return graph;
                    }
                }
                panic!("small copy did not complete");
            }
            assert!(graph.test_compaction_step(1).unwrap());
            graph
        });
        started.wait();
        paused.wait(); // allow write, then queued attach/finish
        writer.join().unwrap();
        let graph = operation.join().unwrap();
        let target = if finishing {
            assert!(!Arc::ptr_eq(&source, &graph.checked_storage));
            graph.checked_storage.clone()
        } else {
            assert!(Arc::ptr_eq(&source, &graph.checked_storage));
            graph.compaction.as_ref().unwrap().target.clone()
        };
        assert_eq!(rows(&target, [68; 32]), if finishing { 1 } else { 0 });
        source.write([69; 32], b"after boundary").unwrap();
        assert_eq!(rows(&target, [69; 32]), if finishing { 0 } else { 1 });
        if finishing {
            target.evict_cache();
            assert_eq!(
                target.read([68; 32], 64).unwrap(),
                b"inflight immutable bytes"
            );
            assert!(source.write_gate().unwrap().mirror.is_none());
        }
        assert!(graph.storage_error().is_none());
    }
}

#[test]
fn copy_read_mirror_and_real_sql_commit_failures_halt_without_handoff() {
    for failure in 0..3 {
        let mut graph = checked_graph();
        let source = graph.checked_storage.clone();
        let snapshot = graph.context.snapshot_id();
        let corpus = graph.content_root();
        assert!(graph.test_compaction_step(1).unwrap());
        let target = graph.compaction.as_ref().unwrap().target.clone();
        match failure {
            0 => {
                source
                    .connection
                    .lock()
                    .unwrap()
                    .open()
                    .unwrap()
                    .execute("DELETE FROM nodes", [])
                    .unwrap();
                source.evict_cache();
            }
            1 => {
                target
                    .connection
                    .lock()
                    .unwrap()
                    .open()
                    .unwrap()
                    .execute_batch(
                        "CREATE TRIGGER reject_mirror BEFORE INSERT ON nodes BEGIN
                         SELECT RAISE(ABORT,'injected mirror I/O refusal'); END;",
                    )
                    .unwrap();
                assert!(source.write([70; 32], b"unpublished staged write").is_err());
            }
            _ => {
                // A real deferred constraint lets node writes succeed and
                // makes the bounded transaction's COMMIT fail separately.
                target
                    .connection
                    .lock()
                    .unwrap()
                    .open()
                    .unwrap()
                    .execute_batch(
                        "PRAGMA foreign_keys=ON;
                         CREATE TABLE copy_parent(id INTEGER PRIMARY KEY);
                         CREATE TABLE copy_child(id INTEGER REFERENCES copy_parent(id)
                             DEFERRABLE INITIALLY DEFERRED);
                         CREATE TRIGGER reject_copy_commit AFTER INSERT ON nodes BEGIN
                             INSERT INTO copy_child(id) VALUES(1); END;",
                    )
                    .unwrap();
            }
        }
        let error = graph.test_compaction_step(1).unwrap_err();
        if failure == 2 {
            assert!(error.contains("FOREIGN KEY"), "{error}");
        }
        assert!(graph.compaction.is_none());
        assert!(graph.storage_error().is_some());
        assert!(source.write_gate().unwrap().mirror.is_none());
        assert!(Arc::ptr_eq(&source, &graph.checked_storage));
        assert_eq!(graph.context.snapshot_id(), snapshot);
        assert_eq!(graph.content_root(), corpus);
        assert_eq!(graph.store.summary().unwrap().count, 1);
        assert!(
            graph
                .author("goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1")
                .is_err()
        );
    }
}

#[test]
fn setup_failure_and_cancelled_copy_never_publish_or_retain_a_mirror() {
    let mut graph = checked_graph();
    let source = graph.checked_storage.clone();
    let snapshot = graph.context.snapshot_id();
    let corpus = graph.content_root();
    assert!(graph.test_compaction_step(1).unwrap());
    let target = Arc::downgrade(&graph.compaction.as_ref().unwrap().target);
    drop(graph.compaction.take());
    assert!(
        target.upgrade().is_none(),
        "abort guard releases the unfinished target"
    );
    assert!(source.write_gate().unwrap().mirror.is_none());
    assert!(Arc::ptr_eq(&source, &graph.checked_storage));
    assert_eq!(graph.context.snapshot_id(), snapshot);
    assert_eq!(graph.content_root(), corpus);
    source.evict_cache();
    assert_eq!(graph.ids().len(), 1);
    assert!(graph.storage_error().is_none());
    // Overflow is rejected before attach; the newly created empty target
    // must be dropped without changing the live context or route.
    source.write_gate().unwrap().epoch = u64::MAX;
    assert!(
        graph
            .test_compaction_step(1)
            .unwrap_err()
            .contains("epoch overflow")
    );
    assert!(graph.compaction.is_none());
    assert!(source.write_gate().unwrap().mirror.is_none());
    assert!(graph.storage_error().is_some());
    assert_eq!(graph.context.snapshot_id(), snapshot);
    assert_eq!(graph.content_root(), corpus);
}

#[test]
fn malicious_decoded_length_is_refused_from_the_sql_header() {
    let graph = Graph::default();
    let storage = &graph.checked_storage;
    let address = [43; 32];
    let mut encoded = codec::encode(&vec![0; 4096]).unwrap();
    encoded[5..13].copy_from_slice(&u64::MAX.to_be_bytes());
    storage
        .connection
        .lock()
        .unwrap()
        .open()
        .unwrap()
        .execute(
            "INSERT INTO nodes(address,payload) VALUES(?1,?2)",
            params![address.as_slice(), encoded],
        )
        .unwrap();
    assert!(matches!(
        storage.read(address, 4096),
        Err(ContextError::Limit)
    ));
    assert!(graph.storage_error().is_some());
}

#[test]
fn oversized_sql_blob_is_refused_before_parsing_its_header() {
    let graph = Graph::default();
    let storage = &graph.checked_storage;
    let address = [44; 32];
    storage
        .connection
        .lock()
        .unwrap()
        .open()
        .unwrap()
        .execute(
            "INSERT INTO nodes(address,payload) VALUES(?1,zeroblob(8192))",
            params![address.as_slice()],
        )
        .unwrap();
    assert!(matches!(
        storage.read(address, 64),
        Err(ContextError::Limit)
    ));
    assert!(graph.storage_error().is_some());
}

fn startup_prune_graph() -> (Graph, crate::Envelope, naome_proof::ProofId) {
    let mut graph = Graph::default();
    let envelope = graph
        .author("goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1")
        .unwrap();
    let id = naome_proof::ProofId::from_bytes(
        crate::unhex(&envelope.proof_id)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        graph
            .ingest(envelope.clone(), std::time::Instant::now())
            .unwrap()
            .status,
        "accepted"
    );
    (graph, envelope, id)
}

#[test]
fn startup_prune_checks_actual_map_formula_and_nested_bucket_rows_despite_hot_cache() {
    use naome_checker::ContextView;
    use sha2::{Digest, Sha256};
    for target in ["proof-map", "formula", "nested-bucket"] {
        for damage in ["missing", "corrupt", "oversized", "different"] {
            let (mut graph, _, id) = startup_prune_graph();
            let storage = graph.checked_storage.clone();
            let header = graph.context.proof_header(id).unwrap().unwrap();
            let formula = graph
                .context
                .statement_formula(
                    header.statement_id(),
                    naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES,
                )
                .unwrap()
                .unwrap()
                .encode_canonical()
                .unwrap();
            let mut raw = Vec::new();
            let domain: &[u8] = if target == "formula" {
                raw = formula;
                b"naome:checked-formula-storage:v1\0"
            } else {
                // Identify a real live authenticated leaf; none is inserted by this fixture.
                raw.extend_from_slice(&[1, 0]);
                if target == "proof-map" {
                    raw.extend_from_slice(id.as_bytes());
                    raw.extend_from_slice(&40u16.to_be_bytes());
                    raw.extend_from_slice(header.derivation_id().as_bytes());
                    raw.extend_from_slice(
                        &(graph.context.proof_dependency_depth(id).unwrap().unwrap() as u64)
                            .to_be_bytes(),
                    );
                } else {
                    raw.extend_from_slice(header.statement_id().as_bytes());
                    raw.extend_from_slice(&0u16.to_be_bytes());
                }
                b"naome:checked-map:storage:v1\0"
            };
            let mut hash = Sha256::new();
            hash.update(domain);
            hash.update(&raw);
            let address: [u8; 32] = hash.finalize().into();
            assert_eq!(storage.read(address, raw.len()).unwrap(), raw, "{target}");
            {
                let guard = storage.connection.lock().unwrap();
                let connection = guard.open().unwrap();
                let changed = match damage {
                    "missing" => connection
                        .execute("DELETE FROM nodes WHERE address=?1", [address.as_slice()]),
                    "corrupt" => connection.execute(
                        "UPDATE nodes SET payload=zeroblob(length(payload)) WHERE address=?1",
                        [address.as_slice()],
                    ),
                    "oversized" => connection.execute(
                        "UPDATE nodes SET payload=zeroblob(?2) WHERE address=?1",
                        params![
                            address.as_slice(),
                            i64::try_from(raw.len().checked_add(codec::HEADER_BYTES + 1).unwrap())
                                .unwrap()
                        ],
                    ),
                    "different" => {
                        let mut different = raw.clone();
                        *different.last_mut().unwrap() ^= 1;
                        connection.execute(
                            "UPDATE nodes SET payload=?2 WHERE address=?1",
                            params![address.as_slice(), codec::encode(&different).unwrap()],
                        )
                    }
                    _ => unreachable!(),
                }
                .unwrap();
                assert_eq!(changed, 1, "{target}/{damage}");
            }
            // This proves that the ordinary source read still has the correct hot value.
            assert_eq!(storage.read(address, raw.len()).unwrap(), raw);
            let persistent = || {
                let guard = storage.connection.lock().unwrap();
                let connection = guard.open().unwrap();
                let count: i64 = connection
                    .query_row("SELECT count(*) FROM nodes", [], |row| row.get(0))
                    .unwrap();
                let bytes: Option<Vec<u8>> = connection
                    .query_row(
                        "SELECT payload FROM nodes WHERE address=?1",
                        [address.as_slice()],
                        |row| row.get(0),
                    )
                    .optional()
                    .unwrap();
                (count, bytes)
            };
            let before = persistent();
            let root = graph.content_root();
            let snapshot = graph.context.snapshot_id();
            assert!(
                graph.prune_startup_checked_storage_at(0).is_err(),
                "{target}/{damage}"
            );
            assert!(graph.storage_error().is_some());
            assert_eq!(
                persistent(),
                before,
                "marking must neither insert nor repair {target}/{damage}"
            );
            assert_eq!(graph.content_root(), root);
            assert_eq!(graph.context.snapshot_id(), snapshot);
            assert_eq!(graph.accepted_count(), 1);
        }
    }
}

#[test]
fn startup_prune_clears_same_generation_tags_and_drains_the_physical_freelist() {
    use naome_checker::ContextView;
    let (mut graph, envelope, id) = startup_prune_graph();
    let storage = graph.checked_storage.clone();
    let generation = storage.generation;
    let root = graph.content_root();
    let snapshot = graph.context.snapshot_id();
    let mut last = ([0; 32], Vec::new());
    storage.begin_write_phase().unwrap();
    for index in 0u64..64 {
        let mut address = [0xa5; 32];
        address[..8].copy_from_slice(&index.to_be_bytes());
        let mut state = index + 1;
        let bytes: Vec<_> = (0..8192)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        storage.write(address, &bytes).unwrap();
        last = (address, bytes);
    }
    storage.finish_write_phase().unwrap();
    assert_eq!(storage.read(last.0, last.1.len()).unwrap(), last.1);
    let before = storage.allocated_bytes().unwrap();
    let before_file = fs::metadata(&storage.path).unwrap();
    assert!(storage.cache.lock().unwrap().charged > 0);
    let live = graph.prune_startup_checked_storage_at(0).unwrap().unwrap();
    assert!(Arc::ptr_eq(&storage, &graph.checked_storage));
    assert_eq!(storage.generation, generation);
    {
        let cache = storage.cache.lock().unwrap();
        assert!(cache.entries.is_empty() && cache.recency.is_empty());
        assert_eq!(cache.charged, 0);
        assert_eq!(cache.clock, 0);
    }
    let after_file = fs::metadata(&storage.path).unwrap();
    assert!(live < before, "unused pages must actually be reclaimed");
    assert_eq!(live, storage.allocated_bytes().unwrap());
    assert!(after_file.len() < before_file.len());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(after_file.ino(), before_file.ino());
        assert!(after_file.blocks() < before_file.blocks());
    }
    {
        let guard = storage.connection.lock().unwrap();
        let connection = guard.open().unwrap();
        assert!(connection.is_autocommit());
        assert_eq!(
            connection
                .pragma_query_value(None, "auto_vacuum", |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .pragma_query_value(None, "freelist_count", |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM startup_keep", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM nodes WHERE address=?1",
                    [last.0.as_slice()],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
    // A stale same-generation cache tag would wrongly skip this SQL insertion.
    storage.write(last.0, &last.1).unwrap();
    storage.evict_cache();
    assert_eq!(storage.read(last.0, last.1.len()).unwrap(), last.1);
    assert_eq!(graph.context.snapshot_id(), snapshot);
    assert_eq!(graph.content_root(), root);
    assert_eq!(graph.object(id).unwrap(), Some(envelope));
    assert!(graph.storage_error().is_none());
}

#[test]
fn startup_prune_requires_a_finished_page_and_leaves_runtime_successors_unchanged() {
    let (graph, _, _) = startup_prune_graph();
    let storage = graph.checked_storage.clone();
    assert_eq!(
        storage
            .connection
            .lock()
            .unwrap()
            .open()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='startup_keep'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0,
        "the keep table must remain lazy for small graphs"
    );
    let successor = storage.successor().unwrap();
    assert_eq!(
        successor
            .connection
            .lock()
            .unwrap()
            .open()
            .unwrap()
            .pragma_query_value(None, "auto_vacuum", |row| row.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(
        successor
            .prune_startup(&DiskArtifactState::new(successor.clone()))
            .unwrap_err()
            .contains("incremental vacuum")
    );
    assert!(
        successor
            .connection
            .lock()
            .unwrap()
            .open()
            .unwrap()
            .is_autocommit()
    );
    drop(graph);
    drop(storage);
    drop(successor);

    let (graph, _, _) = startup_prune_graph();
    graph.checked_storage.begin_write_phase().unwrap();
    assert!(
        graph
            .checked_storage
            .prune_startup(&graph.context)
            .unwrap_err()
            .contains("finished replay page")
    );
    assert!(graph.storage_error().is_some());
    // The failed owner is discarded; journal_mode=OFF is never rolled back for reuse.
}
