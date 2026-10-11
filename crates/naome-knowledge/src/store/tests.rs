use super::*;
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
        assert_eq!(graph.get(&parent.proof_id).unwrap(), Some(&parent));
        assert_eq!(graph.get(&child.proof_id).unwrap(), Some(&child));
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
    assert!(object.proof.len() / 2 <= crate::MAX_PROOF_BYTES);
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
impl ErrText for Result<Graph, String> {
    fn unwrap_err_string(self) -> String {
        match self {
            Err(error) => error,
            Ok(_) => panic!("expected fail-closed startup"),
        }
    }
}
