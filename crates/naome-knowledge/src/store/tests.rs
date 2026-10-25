use super::*;
mod lock_files;
mod replay_validation;
mod resource_calibration;
use crate::Graph;
use naome_proof::{ProofCertificate, ProofStep, StatementId};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

const SOURCE: &str = "goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1";
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-catalog-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn fixtures() -> (Envelope, Envelope) {
    let mut graph = Graph::default();
    let parent = graph.author(SOURCE).unwrap();
    graph.ingest(parent.clone(), Instant::now()).unwrap();
    let child = graph
        .author(&format!(
            "goal = all(x,eq(x,x)) proof: p0 = cite(\"{}\") return p0",
            parent.proof_id
        ))
        .unwrap();
    (parent, child)
}

#[test]
fn directory_ownership_ends_with_its_last_owner_despite_inherited_descriptors() {
    let directory = Directory::new();
    let owner = std::sync::Arc::new(Store::open(&directory.0).unwrap());
    // A duplicate shares the open-file description, as a descriptor inherited
    // by a concurrently spawning child does before close-on-exec takes effect.
    let inherited = owner._lock.0.file().try_clone().unwrap();
    let retained = owner.clone();
    drop(owner);
    assert!(Store::open(&directory.0).is_err());
    drop(retained);
    let reopened = Store::open(&directory.0).unwrap();
    drop(inherited);
    assert!(Store::open(&directory.0).is_err());
    drop(reopened);
    drop(Store::open(&directory.0).unwrap());
}

#[cfg(unix)]
#[test]
fn canonical_leaf_aliases_and_nonregular_files_cannot_publish_or_replace_data() {
    use std::os::unix::fs::{MetadataExt, symlink};
    for name in [FORMAT_FILE, DATABASE_FILE] {
        for kind in 0..4 {
            for initialized in [false, true] {
                let directory = Directory::new();
                if initialized {
                    drop(Store::open(&directory.0).unwrap());
                    fs::remove_file(directory.0.join(name)).unwrap();
                }
                let path = directory.0.join(name);
                let target = directory.0.join("unrelated");
                match kind {
                    0 => symlink(&target, &path).unwrap(),
                    1 => {
                        fs::write(&target, b"unrelated bytes").unwrap();
                        symlink(&target, &path).unwrap();
                    }
                    2 => {
                        fs::write(&target, b"unrelated bytes").unwrap();
                        fs::hard_link(&target, &path).unwrap();
                    }
                    _ => fs::create_dir(&path).unwrap(),
                }
                let before = fs::symlink_metadata(&path).unwrap();
                let link_before = fs::read_link(&path).ok();
                let target_before = fs::read(&target).ok();
                let other = if name == FORMAT_FILE {
                    DATABASE_FILE
                } else {
                    FORMAT_FILE
                };
                let other_before = fs::read(directory.0.join(other)).ok();
                assert!(Store::open(&directory.0).is_err());
                let after = fs::symlink_metadata(&path).unwrap();
                assert_eq!(
                    (after.dev(), after.ino(), after.nlink()),
                    (before.dev(), before.ino(), before.nlink())
                );
                assert_eq!(fs::read_link(&path).ok(), link_before);
                assert_eq!(fs::read(&target).ok(), target_before);
                assert_eq!(fs::read(directory.0.join(other)).ok(), other_before);
                assert!(!directory.0.join(INITIAL_DATABASE).exists());
                assert!(!directory.0.join(".proof-corpus-format-incoming").exists());
            }
        }
    }
}

#[test]
fn unknown_normal_schema_objects_are_refused_without_changing_data() {
    for sql in [
        "CREATE TABLE unexpected_schema(value INTEGER)",
        "CREATE VIEW unexpected_schema AS SELECT id FROM proofs",
        "CREATE TRIGGER unexpected_schema AFTER INSERT ON proofs BEGIN SELECT 1; END",
        "CREATE INDEX unexpected_schema ON proofs(statement)",
    ] {
        let directory = Directory::new();
        let (parent, _) = fixtures();
        let mut graph = Graph::open(&directory.0).unwrap();
        graph.ingest(parent, Instant::now()).unwrap();
        drop(graph);
        let path = directory.0.join(DATABASE_FILE);
        let database = rusqlite::Connection::open(&path).unwrap();
        let implicit: i64 = database
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE sql IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(implicit > 0);
        database.execute_batch(sql).unwrap();
        drop(database);
        let before = fs::read(&path).unwrap();
        assert!(
            Graph::open(&directory.0)
                .unwrap_err_string()
                .contains("unexpected catalog schema object")
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn namespace_metadata_errors_are_not_treated_as_absence() {
    let directory = Directory::new();
    let blocked = directory.0.join("not-a-directory");
    fs::write(&blocked, b"unrelated bytes").unwrap();
    assert!(
        catalog_leaf_exists(&blocked.join(DATABASE_FILE))
            .unwrap_err()
            .contains("cannot inspect")
    );
    assert!(!catalog_leaf_exists(&directory.0.join(DATABASE_FILE)).unwrap());
    assert_eq!(fs::read(&blocked).unwrap(), b"unrelated bytes");
}

#[cfg(unix)]
#[test]
fn directory_aliases_resolve_without_allowing_catalog_leaf_aliases() {
    let directory = Directory::new();
    let alias = directory.0.join("directory-alias");
    let target = directory.0.join("target");
    fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let graph = Graph::open(&alias).unwrap();
    drop(graph);
    Graph::open(&target).unwrap();
    let catalog = target.join(DATABASE_FILE);
    let foreign = target.join("foreign-database");
    fs::rename(&catalog, &foreign).unwrap();
    std::os::unix::fs::symlink(&foreign, &catalog).unwrap();
    let before = fs::read(&foreign).unwrap();
    assert!(Graph::open(&alias).is_err());
    assert_eq!(fs::read(&foreign).unwrap(), before);
}

#[test]
fn binary_single_and_dependency_batch_preserve_exact_bytes_ids_root_and_membership() {
    for batched in [false, true] {
        let directory = Directory::new();
        let (parent, child) = fixtures();
        let mut baseline = Graph::default();
        baseline.ingest(parent.clone(), Instant::now()).unwrap();
        baseline.ingest(child.clone(), Instant::now()).unwrap();
        let store = Store::open(&directory.0).unwrap();
        store
            .finish_replay(Graph::default().content_root())
            .unwrap();
        if batched {
            let root = ProofId::from_bytes(crate::object::id_bytes(&child.proof_id).unwrap());
            store
                .persist_batch(root, [&parent, &child].into_iter())
                .unwrap();
        } else {
            store.persist(&parent).unwrap();
            store.persist(&child).unwrap();
        }
        drop(store);
        let graph = Graph::open(&directory.0).unwrap();
        assert_eq!(graph.ids(), baseline.ids());
        assert_eq!(graph.content_root(), baseline.content_root());
        assert_eq!(graph.get(&parent.proof_id).unwrap(), Some(parent.clone()));
        assert_eq!(graph.get(&child.proof_id).unwrap(), Some(child.clone()));
        let database = rusqlite::Connection::open(directory.0.join(DATABASE_FILE)).unwrap();
        for object in [&parent, &child] {
            let payload: Vec<u8> = database
                .query_row(
                    "SELECT payload FROM proofs WHERE id=?1",
                    [crate::unhex(&object.proof_id).unwrap()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(payload, crate::unhex(&object.proof).unwrap());
        }
        assert!(!directory.0.join("objects").exists());
        drop(graph);
        let reopened = Graph::open(&directory.0).unwrap();
        assert_eq!(reopened.content_root(), baseline.content_root());
    }
}

#[test]
fn deferred_parent_inserts_resolve_foreign_keys_with_indexed_child_lookups() {
    let directory = Directory::new();
    drop(Graph::open(&directory.0).unwrap());
    let database = rusqlite::Connection::open_with_flags(
        directory.0.join(DATABASE_FILE),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    database.pragma_update(None, "foreign_keys", true).unwrap();
    let statements: [(&str, &[&str]); 2] = [
        (
            "EXPLAIN QUERY PLAN INSERT INTO commits(id,root,member_count)
             VALUES(zeroblob(32),zeroblob(32),1)",
            &["proofs_by_origin_commit"],
        ),
        (
            "EXPLAIN QUERY PLAN INSERT INTO proofs(id,replay_order,statement,compatibility,
             payload,payload_length,payload_digest,origin_commit)
             VALUES(zeroblob(32),1,zeroblob(32),zeroblob(32),x'00',1,zeroblob(32),zeroblob(32))",
            &["commits_by_root", "dependencies_by_target"],
        ),
    ];
    for (sql, required) in statements {
        let mut statement = database.prepare(sql).unwrap();
        let details: Vec<String> = statement
            .query_map([], |row| row.get(3))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            details.iter().all(|detail| !detail.starts_with("SCAN ")),
            "{details:?}"
        );
        for index in required {
            assert!(
                details.iter().any(|detail| detail.contains(index)),
                "{index}: {details:?}"
            );
        }
    }
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM proofs", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn missing_or_changed_foreign_key_indexes_refuse_startup() {
    for (name, table) in [
        ("proofs_by_origin_commit", "proofs"),
        ("commits_by_root", "commits"),
        ("dependencies_by_target", "dependencies"),
    ] {
        for changed in [false, true] {
            let directory = Directory::new();
            drop(Graph::open(&directory.0).unwrap());
            let database = rusqlite::Connection::open(directory.0.join(DATABASE_FILE)).unwrap();
            database
                .execute_batch(&format!("DROP INDEX {name}"))
                .unwrap();
            if changed {
                database
                    .execute_batch(&format!(
                        "CREATE INDEX {name} ON {table}({})",
                        if table == "dependencies" {
                            "proof_id"
                        } else {
                            "id"
                        }
                    ))
                    .unwrap();
            }
            drop(database);
            let before = fs::read(directory.0.join(DATABASE_FILE)).unwrap();
            assert!(Graph::open(&directory.0).is_err());
            assert_eq!(fs::read(directory.0.join(DATABASE_FILE)).unwrap(), before);
        }
    }
}

#[test]
fn first_activation_cuts_resume_with_an_empty_checked_corpus() {
    for cut in [ReplayCut::BeforeActivation, ReplayCut::AfterActivation] {
        let directory = Directory::new();
        let store = Store::open(&directory.0).unwrap();
        assert!(store.load().unwrap().is_empty());
        store.set_replay_cut(cut);
        assert!(
            store
                .finish_replay(Graph::default().content_root())
                .is_err()
        );
        assert_eq!(
            store.catalog.lock().unwrap().active().unwrap(),
            cut == ReplayCut::AfterActivation
        );
        drop(store);
        let graph = Graph::open(&directory.0).unwrap();
        assert!(graph.ids().is_empty());
        assert_eq!(graph.content_root(), Graph::default().content_root());
    }
}

#[test]
fn repeated_commit_preserves_totals_and_full_replay_root() {
    let directory = Directory::new();
    let (parent, child) = fixtures();
    let store = Store::open(&directory.0).unwrap();
    store
        .finish_replay(Graph::default().content_root())
        .unwrap();
    let root = ProofId::from_bytes(crate::object::id_bytes(&child.proof_id).unwrap());
    let first = store
        .persist_batch(root, [&parent, &child].into_iter())
        .unwrap();
    assert_eq!(first.count, 2);
    assert_eq!(
        first.bytes,
        crate::unhex(&parent.proof).unwrap().len() + crate::unhex(&child.proof).unwrap().len()
    );
    let repeated = store
        .persist_batch_checked(root, [&parent, &child].into_iter(), first, None)
        .unwrap();
    assert_eq!(repeated, first);
    assert_eq!(store.summary().unwrap(), first);
    drop(store);
    let graph = Graph::open(&directory.0).unwrap();
    assert_eq!(graph.accepted_count(), first.count);
    assert_eq!(graph.content_root(), first.root);
    assert_eq!(graph.get(&parent.proof_id).unwrap(), Some(parent));
    assert_eq!(graph.get(&child.proof_id).unwrap(), Some(child));
}

#[test]
fn forward_dependency_batch_rolls_back_before_publishing_incremental_totals() {
    let directory = Directory::new();
    let (parent, child) = fixtures();
    let store = Store::open(&directory.0).unwrap();
    store
        .finish_replay(Graph::default().content_root())
        .unwrap();
    let empty = store.summary().unwrap();
    let root = ProofId::from_bytes(crate::object::id_bytes(&child.proof_id).unwrap());
    let error = store
        .persist_batch_checked(root, [&child, &parent].into_iter(), empty, None)
        .unwrap_err();
    assert!(error.contains("dependency replay order"), "{error}");
    assert_eq!(store.summary().unwrap(), empty);
    assert!(store.load().unwrap().is_empty());
    drop(store);
    assert_eq!(Graph::open(&directory.0).unwrap().accepted_count(), 0);
}

#[test]
fn external_commit_invalidates_reads_replay_activation_and_new_writes() {
    for operation in 0..6 {
        let directory = Directory::new();
        let (parent, child) = fixtures();
        let store = Store::open(&directory.0).unwrap();
        store
            .finish_replay(Graph::default().content_root())
            .unwrap();
        let summary = store.persist(&parent).unwrap();
        let database = rusqlite::Connection::open(directory.0.join(DATABASE_FILE)).unwrap();
        assert_eq!(
            database
                .execute(
                    "UPDATE proofs SET payload_digest=zeroblob(32) WHERE id=?1",
                    [crate::unhex(&parent.proof_id).unwrap()],
                )
                .unwrap(),
            1
        );
        drop(database);
        let absent = ProofId::from_bytes(crate::object::id_bytes(&child.proof_id).unwrap());
        let refused = match operation {
            0 => store.get(absent, summary).is_err(),
            1 => store.ids_page(None, 64, summary).is_err(),
            2 => store.replay_page(0, 64).is_err(),
            3 => store.finish_replay(summary.root).is_err(),
            4 => store.persist_checked(&child, summary).is_err(),
            _ => store.summary().is_err(),
        };
        assert!(
            refused,
            "operation {operation} accepted an externally changed generation"
        );
        let database = rusqlite::Connection::open(directory.0.join(DATABASE_FILE)).unwrap();
        let count: i64 = database
            .query_row("SELECT count(*) FROM proofs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "no new commit after invalidation");
    }
}

#[test]
fn hash_consistent_invalid_proofs_cannot_bypass_mathematical_restart_replay() {
    let directory = Directory::new();
    let (parent, _) = fixtures();
    let certificate = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity {
            variable: naome_foundation::FreeVariable::new(0),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 0,
        },
    ])
    .unwrap();
    let bytes = certificate
        .into_unchecked_normal_form()
        .canonical_bytes()
        .to_vec();
    let statement = StatementId::from_bytes(crate::object::id_bytes(&parent.statement_id).unwrap());
    let object = Envelope {
        compatibility: crate::hex(&crate::compatibility()),
        proof_id: crate::hex(crate::object::content_id(statement, &bytes).as_bytes()),
        statement_id: parent.statement_id,
        proof: crate::hex(&bytes),
    };
    assert!(
        object.clone().prepare().is_ok(),
        "content hashes alone do not prove mathematics"
    );
    let store = Store::open(&directory.0).unwrap();
    store
        .finish_replay(Graph::default().content_root())
        .unwrap();
    // Test-only corruption injection supplies hash-consistent canonical syntax;
    // production Graph admission never calls persistence before checking it.
    store.persist(&object).unwrap();
    drop(store);
    assert!(
        Graph::open(&directory.0)
            .unwrap_err_string()
            .contains("mathematically invalid")
    );
}

#[test]
fn active_catalog_refuses_missing_database_or_lineage() {
    let directory = Directory::new();
    let (parent, child) = fixtures();
    let mut graph = Graph::open(&directory.0).unwrap();
    graph.ingest(parent, Instant::now()).unwrap();
    graph.ingest(child, Instant::now()).unwrap();
    drop(graph);
    let receipt = fs::read(directory.0.join(FORMAT_FILE)).unwrap();
    fs::remove_file(directory.0.join(FORMAT_FILE)).unwrap();
    assert!(
        Graph::open(&directory.0)
            .unwrap_err_string()
            .contains("receipt missing")
    );
    fs::write(directory.0.join(FORMAT_FILE), receipt).unwrap();
    fs::remove_file(directory.0.join(DATABASE_FILE)).unwrap();
    assert!(
        Graph::open(&directory.0)
            .unwrap_err_string()
            .contains("activated proof catalog missing")
    );
}

#[test]
fn inactive_initial_receipt_interruptions_resume_but_conflicts_fail_closed() {
    let directory = Directory::new();
    let store = Store::open(&directory.0).unwrap();
    drop(store);
    fs::rename(
        directory.0.join(FORMAT_FILE),
        directory.0.join(".proof-corpus-format-incoming"),
    )
    .unwrap();
    assert!(Graph::open(&directory.0).is_ok());
    assert!(directory.0.join(FORMAT_FILE).is_file());
    let conflicting = Directory::new();
    let store = Store::open(&conflicting.0).unwrap();
    drop(store);
    fs::remove_file(conflicting.0.join(FORMAT_FILE)).unwrap();
    fs::write(
        conflicting.0.join(".proof-corpus-format-incoming"),
        b"invalid pending receipt",
    )
    .unwrap();
    assert!(Graph::open(&conflicting.0).is_err());
}

#[test]
fn database_identity_and_payload_corruption_refuse_startup() {
    for mode in 0..3 {
        let directory = Directory::new();
        let (parent, _) = fixtures();
        let mut graph = Graph::open(&directory.0).unwrap();
        graph.ingest(parent.clone(), Instant::now()).unwrap();
        drop(graph);
        match mode {
            0 => {
                let mut receipt = fs::read(directory.0.join(FORMAT_FILE)).unwrap();
                receipt[71] ^= 1;
                fs::write(directory.0.join(FORMAT_FILE), receipt).unwrap();
            }
            1 => corrupt_payload(&directory.0, &parent.proof_id),
            _ => {
                fs::write(directory.0.join(DATABASE_FILE), b"truncated database").unwrap();
            }
        }
        assert!(Graph::open(&directory.0).is_err());
    }
}

#[test]
fn genuine_sqlite_full_preserves_live_state_and_halts_admission() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    graph.test_database_full();
    let object = large_fixture();
    let before = graph.content_root();
    let error = graph.ingest(object, Instant::now()).unwrap_err();
    assert!(
        error.contains("full"),
        "actual SQLite failure required: {error}"
    );
    assert!(graph.storage_error().is_some());
    assert_eq!(graph.content_root(), before);
    drop(graph);
    assert!(Graph::open(&directory.0).unwrap().ids().is_empty());
}

fn large_fixture() -> Envelope {
    let variable = naome_foundation::FreeVariable::new(0);
    let mut pattern = naome_foundation::Formula::for_all(
        variable,
        naome_foundation::Formula::equal(variable, variable),
    );
    for _ in 0..9 {
        pattern = naome_foundation::Formula::implies(pattern.clone(), pattern);
    }
    let checked = naome_checker::normalize_and_check(
        ProofCertificate::new(vec![ProofStep::Simplification {
            antecedent: pattern.clone().into(),
            consequent: pattern.into(),
        }])
        .unwrap(),
    )
    .unwrap();
    let object = Envelope {
        compatibility: crate::hex(&crate::compatibility()),
        proof_id: crate::hex(checked.proof_id().as_bytes()),
        statement_id: crate::hex(checked.statement_id().as_bytes()),
        proof: crate::hex(checked.normal_form().canonical_bytes()),
    };
    assert!(object.proof.len() / 2 <= crate::resources::limits().proof_bytes);
    object
}

#[test]
fn graph_keeps_the_supported_thread_transfer_and_shared_read_traits() {
    fn require<T: Send + Sync>() {}
    require::<Graph>();
}

#[test]
fn unpublished_empty_or_initialized_database_stages_resume_first_start() {
    for initialized in [false, true] {
        let directory = Directory::new();
        let incoming = directory.0.join(INITIAL_DATABASE);
        if initialized {
            let catalog = Catalog::initialize_stage(&incoming, [11; 32]).unwrap();
            drop(catalog);
        } else {
            // An interrupted schema transaction recovers to the same empty
            // unpublished database; the final canonical name does not exist.
            let database = rusqlite::Connection::open(&incoming).unwrap();
            database
                .execute_batch("BEGIN IMMEDIATE; CREATE TABLE interrupted(value BLOB); ROLLBACK")
                .unwrap();
            drop(database);
        }
        assert!(!directory.0.join(DATABASE_FILE).exists());
        let graph = Graph::open(&directory.0).unwrap();
        assert!(graph.ids().is_empty());
        assert!(!incoming.exists());
    }
}

#[cfg(unix)]
#[test]
fn unpublished_database_aliases_cannot_initialize_or_activate_an_unrelated_file() {
    for initialized in [false, true] {
        let directory = Directory::new();
        let foreign = directory.0.join("unrelated-database");
        if initialized {
            drop(Catalog::initialize_stage(&foreign, [21; 32]).unwrap());
        } else {
            fs::write(&foreign, b"").unwrap();
        }
        let bytes = fs::read(&foreign).unwrap();
        fs::hard_link(&foreign, directory.0.join(INITIAL_DATABASE)).unwrap();
        assert!(Store::open(&directory.0).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), bytes);
        assert!(!directory.0.join(DATABASE_FILE).exists());
    }
}

#[test]
fn partial_temporary_format_receipts_resume_only_for_a_verified_inactive_catalog() {
    for length in [0, 5, 39, 71] {
        let directory = Directory::new();
        let store = Store::open(&directory.0).unwrap();
        drop(store);
        let complete = fs::read(directory.0.join(FORMAT_FILE)).unwrap();
        fs::remove_file(directory.0.join(FORMAT_FILE)).unwrap();
        fs::write(
            directory.0.join(".proof-corpus-format-incoming"),
            &complete[..length],
        )
        .unwrap();
        let graph = Graph::open(&directory.0).unwrap();
        assert!(graph.ids().is_empty());
        assert_eq!(fs::read(directory.0.join(FORMAT_FILE)).unwrap(), complete);
    }
}

#[test]
fn complete_pending_receipt_retries_cannot_skip_synchronization_before_activation() {
    let directory = Directory::new();
    let store = Store::open(&directory.0).unwrap();
    drop(store);
    fs::rename(
        directory.0.join(FORMAT_FILE),
        directory.0.join(".proof-corpus-format-incoming"),
    )
    .unwrap();
    FORMAT_SYNC_FAILURE.set(true);
    let failed = Store::open(&directory.0);
    FORMAT_SYNC_FAILURE.set(false);
    assert!(matches!(failed,Err(error) if error.contains("receipt sync failure")));
    assert!(!directory.0.join(FORMAT_FILE).exists());
    let graph = Graph::open(&directory.0).unwrap();
    assert!(graph.ids().is_empty());
}

#[cfg(unix)]
#[test]
fn partial_receipt_aliases_cannot_overwrite_an_unrelated_file() {
    for (hardlink, length) in [(false, 0), (false, 5), (true, 0), (true, 5)] {
        let directory = Directory::new();
        let store = Store::open(&directory.0).unwrap();
        drop(store);
        let complete = fs::read(directory.0.join(FORMAT_FILE)).unwrap();
        fs::remove_file(directory.0.join(FORMAT_FILE)).unwrap();
        let foreign = directory.0.join("unrelated-config");
        let prefix = &complete[..length];
        fs::write(&foreign, prefix).unwrap();
        let pending = directory.0.join(".proof-corpus-format-incoming");
        if hardlink {
            fs::hard_link(&foreign, &pending).unwrap();
        } else {
            std::os::unix::fs::symlink(&foreign, &pending).unwrap();
        }
        assert!(Store::open(&directory.0).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), prefix);
        assert!(!directory.0.join(FORMAT_FILE).exists());
    }
}

#[test]
fn an_existing_proof_cannot_acquire_a_second_originating_commit() {
    let directory = Directory::new();
    let (parent, child) = fixtures();
    let store = Store::open(&directory.0).unwrap();
    store.load().unwrap();
    store
        .finish_replay(Graph::default().content_root())
        .unwrap();
    store.persist(&parent).unwrap();
    let root = ProofId::from_bytes(crate::object::id_bytes(&child.proof_id).unwrap());
    let error = store
        .persist_batch(root, [&parent, &child].into_iter())
        .unwrap_err();
    assert!(error.contains("another commit"), "{error}");
    assert_eq!(store.load().unwrap(), vec![parent]);
}

#[test]
fn bundled_engine_refuses_regular_file_replacement_under_the_owned_connection() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let before = graph.content_root();
    let (object, _) = fixtures();
    fs::rename(
        directory.0.join(DATABASE_FILE),
        directory.0.join("retained-original.sqlite3"),
    )
    .unwrap();
    fs::write(directory.0.join(DATABASE_FILE), b"").unwrap();
    assert!(graph.ingest(object, Instant::now()).is_err());
    assert!(graph.storage_error().is_some());
    assert_eq!(graph.content_root(), before);
}

#[test]
fn canonical_statement_compatibility_and_dependency_metadata_faults_fail_startup() {
    for mode in 0..5 {
        let directory = Directory::new();
        let (parent, child) = fixtures();
        let mut graph = Graph::open(&directory.0).unwrap();
        graph.ingest(parent, Instant::now()).unwrap();
        graph.ingest(child.clone(), Instant::now()).unwrap();
        drop(graph);
        let database = rusqlite::Connection::open(directory.0.join(DATABASE_FILE)).unwrap();
        database.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        let id = crate::unhex(&child.proof_id).unwrap();
        let sql = match mode {
            0 => "UPDATE proofs SET statement=zeroblob(32) WHERE id=?1",
            1 => "UPDATE proofs SET compatibility=zeroblob(32) WHERE id=?1",
            2 => "UPDATE dependencies SET target=zeroblob(32) WHERE proof_id=?1",
            3 => "DELETE FROM dependencies WHERE proof_id=?1",
            _ => "UPDATE proofs SET payload_digest=zeroblob(32) WHERE id=?1",
        };
        assert_eq!(database.execute(sql, [id]).unwrap(), 1);
        drop(database);
        assert!(Graph::open(&directory.0).is_err());
    }
}

trait ErrText {
    fn unwrap_err_string(self) -> String;
}
impl<E: std::fmt::Display> ErrText for Result<Graph, E> {
    fn unwrap_err_string(self) -> String {
        match self {
            Err(error) => error.to_string(),
            Ok(_) => panic!("expected fail-closed startup"),
        }
    }
}

#[test]
fn non_root_batch_members_receive_full_catalog_validation_before_acceptance() {
    let (parent, child) = fixtures();
    let mut baseline = Graph::default();
    baseline.ingest(parent.clone(), Instant::now()).unwrap();
    baseline.ingest(child.clone(), Instant::now()).unwrap();
    let root = baseline
        .author(&format!(
            "goal = all(x,eq(x,x)) proof: p0 = cite(\"{}\") return p0",
            child.proof_id
        ))
        .unwrap();
    baseline.ingest(root.clone(), Instant::now()).unwrap();
    let root_id = ProofId::from_bytes(crate::object::id_bytes(&root.proof_id).unwrap());
    let child_id = crate::unhex(&child.proof_id).unwrap();
    assert_ne!(child.proof_id, root.proof_id);
    for mode in 0..3 {
        let directory = Directory::new();
        let store = Store::open(&directory.0).unwrap();
        store
            .finish_replay(Graph::default().content_root())
            .unwrap();
        let summary = store
            .persist_batch(root_id, [&parent, &child, &root].into_iter())
            .unwrap();
        assert_eq!(summary.count, 3);
        assert_eq!(summary.root, baseline.content_root());
        assert_eq!(store.summary().unwrap(), summary);
        drop(store);
        let database = rusqlite::Connection::open(directory.0.join(DATABASE_FILE)).unwrap();
        database.pragma_update(None, "foreign_keys", true).unwrap();
        let totals = || {
            database
                .query_row(
                    "SELECT corpus_root,corpus_count,payload_bytes,
                     (SELECT count(*) FROM proofs),(SELECT count(*) FROM members),
                     (SELECT count(*) FROM commits),(SELECT min(replay_order) FROM proofs),
                     (SELECT max(replay_order) FROM proofs) FROM meta WHERE singleton=1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, i64>(7)?,
                        ))
                    },
                )
                .unwrap()
        };
        let membership = || {
            database
                .prepare(
                    "SELECT m.commit_id,m.proof_id,p.origin_commit,c.root,c.member_count
                     FROM members m JOIN proofs p ON p.id=m.proof_id
                     JOIN commits c ON c.id=m.commit_id ORDER BY m.proof_id",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let before_totals = totals();
        let before_membership = membership();
        assert_eq!(
            before_totals,
            (
                summary.root.to_vec(),
                3,
                i64::try_from(summary.bytes).unwrap(),
                3,
                3,
                1,
                1,
                3,
            )
        );
        assert_eq!(before_membership.len(), 3);
        assert!(before_membership.iter().all(|member| {
            member.0 == member.2
                && member.3.as_slice() == root_id.as_bytes().as_slice()
                && member.4 == 3
        }));
        let sql = match mode {
            // Preserve the stored digest and commit digest to require payload validation.
            0 => "UPDATE proofs SET payload=zeroblob(length(payload)) WHERE id=?1",
            1 => "UPDATE proofs SET statement=zeroblob(32) WHERE id=?1",
            _ => "DELETE FROM dependencies WHERE proof_id=?1",
        };
        assert_eq!(database.execute(sql, [&child_id]).unwrap(), 1);
        assert_eq!(totals(), before_totals);
        assert_eq!(membership(), before_membership);
        drop(database);
        let before = fs::read(directory.0.join(DATABASE_FILE)).unwrap();
        let store = Store::open(&directory.0).unwrap();
        assert!(store.summary().is_err(), "summary accepted mode {mode}");
        assert!(
            store.finish_replay(summary.root).is_err(),
            "activation accepted mode {mode}"
        );
        drop(store);
        assert_eq!(fs::read(directory.0.join(DATABASE_FILE)).unwrap(), before);
    }
}

#[test]
fn dependency_batch_rollback_then_same_connection_retry_reads_current_exact_records() {
    let directory = Directory::new();
    let (parent, child) = fixtures();
    let parent_id = ProofId::from_bytes(crate::object::id_bytes(&parent.proof_id).unwrap());
    let child_id = ProofId::from_bytes(crate::object::id_bytes(&child.proof_id).unwrap());
    let absent = ProofId::from_bytes([0; 32]);
    assert_ne!(absent, parent_id);
    assert_ne!(absent, child_id);
    let mut baseline = Graph::default();
    baseline.ingest(parent.clone(), Instant::now()).unwrap();
    baseline.ingest(child.clone(), Instant::now()).unwrap();
    let store = Store::open(&directory.0).unwrap();
    store
        .finish_replay(Graph::default().content_root())
        .unwrap();
    let empty = store.summary().unwrap();
    let error = store
        .persist_batch_checked(child_id, [&child, &parent].into_iter(), empty, None)
        .unwrap_err();
    assert!(error.contains("dependency replay order"), "{error}");
    assert_eq!(store.summary().unwrap(), empty);
    for id in [parent_id, absent, child_id] {
        assert_eq!(store.get(id, empty).unwrap(), None);
    }
    let summary = store
        .persist_batch_checked(child_id, [&parent, &child].into_iter(), empty, None)
        .unwrap();
    assert_eq!(summary.count, 2);
    assert_eq!(
        summary.bytes,
        crate::unhex(&parent.proof).unwrap().len() + crate::unhex(&child.proof).unwrap().len()
    );
    assert_eq!(summary.root, baseline.content_root());
    assert_eq!(store.summary().unwrap(), summary);
    for expected in [
        Some(&parent),
        None,
        Some(&child),
        None,
        Some(&parent),
        Some(&child),
    ] {
        let (id, wanted) = match expected {
            Some(object) => (
                ProofId::from_bytes(crate::object::id_bytes(&object.proof_id).unwrap()),
                Some(object.clone()),
            ),
            None => (absent, None),
        };
        assert_eq!(store.get(id, summary).unwrap(), wanted);
    }
    drop(store);
    let reopened = Graph::open(&directory.0).unwrap();
    assert_eq!(reopened.ids(), baseline.ids());
    assert_eq!(reopened.accepted_count(), summary.count);
    assert_eq!(reopened.content_root(), summary.root);
    assert_eq!(reopened.get(&parent.proof_id).unwrap(), Some(parent));
    assert_eq!(reopened.get(&child.proof_id).unwrap(), Some(child));
}

#[test]
fn inventory_pages_seek_past_the_cursor_without_rescanning_prior_ids() {
    use naome_foundation::{Formula, FreeVariable};
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let variable = FreeVariable::new(0);
    let mut pattern = Formula::equal(variable, variable);
    let mut expected = Vec::new();
    for _ in 0..65 {
        pattern = Formula::for_all(variable, pattern);
        let checked = naome_checker::normalize_and_check(
            ProofCertificate::new(vec![ProofStep::Simplification {
                antecedent: pattern.clone().into(),
                consequent: pattern.clone().into(),
            }])
            .unwrap(),
        )
        .unwrap();
        let id = checked.proof_id();
        let object = Envelope {
            compatibility: crate::hex(&crate::compatibility()),
            proof_id: crate::hex(id.as_bytes()),
            statement_id: crate::hex(checked.statement_id().as_bytes()),
            proof: crate::hex(checked.normal_form().canonical_bytes()),
        };
        assert_eq!(
            graph.ingest(object, Instant::now()).unwrap().status,
            "accepted"
        );
        expected.push(id);
    }
    expected.sort_unstable();
    assert_eq!(graph.accepted_count(), expected.len());
    let root = graph.content_root();
    drop(graph);
    let store = Store::open(&directory.0).unwrap();
    let summary = store.summary().unwrap();
    let mut observed = Vec::new();
    let mut after = None;
    loop {
        let page = store.ids_page(after, 7, summary).unwrap();
        assert_eq!(
            store.catalog.lock().unwrap().inventory_fullscan_steps(),
            0,
            "a page must seek its lower bound, including an exhausted cursor"
        );
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 7);
        after = page.last().copied();
        observed.extend(page);
    }
    assert_eq!(observed, expected);
    assert_eq!(
        store
            .ids_page(Some(ProofId::from_bytes([0; 32])), 7, summary)
            .unwrap(),
        expected[..7]
    );
    assert!(
        store
            .ids_page(Some(ProofId::from_bytes([255; 32])), 7, summary)
            .unwrap()
            .is_empty()
    );
    assert!(store.ids_page(None, 0, summary).is_err());
    assert!(store.ids_page(None, 129, summary).is_err());
    // The old optional-cursor predicate visits the complete earlier prefix.
    let database = rusqlite::Connection::open_with_flags(
        directory.0.join(DATABASE_FILE),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut old_query = database
        .prepare(
            "SELECT substr(id,1,33) FROM proofs WHERE (?1 IS NULL OR id > ?1) ORDER BY id LIMIT ?2",
        )
        .unwrap();
    let old_page = old_query
        .query_map(
            rusqlite::params![after.unwrap().as_bytes().as_slice(), 7],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(old_page.is_empty());
    assert!(old_query.get_status(rusqlite::StatementStatus::FullscanStep) >= 64);
    drop(old_query);
    drop(database);
    drop(store);
    let reopened = Graph::open(&directory.0).unwrap();
    assert_eq!(reopened.ids(), expected);
    assert_eq!(reopened.content_root(), root);
}

#[test]
fn growing_live_commits_never_rescan_the_corpus_set() {
    use naome_foundation::{Formula, FreeVariable};
    let mut graph = Graph::default();
    let scans = catalog::set_scan_count();
    let variable = FreeVariable::new(0);
    let mut pattern = Formula::equal(variable, variable);
    for _ in 0..65 {
        pattern = Formula::for_all(variable, pattern);
        let checked = naome_checker::normalize_and_check(
            ProofCertificate::new(vec![ProofStep::Simplification {
                antecedent: pattern.clone().into(),
                consequent: pattern.clone().into(),
            }])
            .unwrap(),
        )
        .unwrap();
        let object = crate::object::BinaryProof::from_checked(&checked)
            .unwrap()
            .envelope();
        graph.ingest(object, Instant::now()).unwrap();
        assert_eq!(
            catalog::set_scan_count(),
            scans,
            "a live commit may touch only its delta"
        );
    }
    assert_eq!(graph.accepted_count(), 65);
    assert_eq!(
        graph.content_root(),
        crate::corpus::root(65, graph.checked_context().proof_set_fingerprint()).unwrap()
    );
}

#[test]
fn generation_bound_membership_and_inventory_do_not_fetch_certificate_payloads() {
    let mut graph = Graph::default();
    let (_, result) = graph
        .produce("goal=all(x,eq(x,x)) proof: a=refl(x) b=gen(a,x) return b")
        .unwrap();
    let before = super::catalog::payload_reads();
    assert!(graph.contains(result.id).unwrap());
    assert_eq!(graph.ids_page(None, 1).unwrap(), [result.id]);
    assert_eq!(super::catalog::payload_reads(), before);
    assert!(graph.object(result.id).unwrap().is_some());
    assert_eq!(super::catalog::payload_reads(), before + 1);
}
