use super::*;
use crate::{Envelope, hex, object::content_id};
use naome_foundation::FreeVariable;
use naome_proof::{ProofCertificate, ProofStep, StatementId};
use sha2::Digest;
use std::sync::atomic::{AtomicU64, Ordering};

const SOURCE: &str = "goal = all(x, eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1";

#[test]
fn generated_root_and_actual_helpers_stay_staged_until_native_batch_commit() {
    let producer = Graph::default();
    let helper = producer.author(SOURCE).unwrap();
    let root_source = format!(
        "goal = all(x,eq(x,x)) proof: p0 = cite(\"{}\") return p0",
        helper.proof_id
    );
    let question = naome_authoring::CompiledQuestion::compile("goal = all(x,eq(x,x))").unwrap();
    let mut receiver = Graph::default();
    let (root, batch) = receiver
        .prepare_generated(&root_source, &[SOURCE.into()], &question)
        .unwrap();
    assert_eq!(
        receiver.checker_calls(),
        (2, 0),
        "one compiler check per helper/root, no rechecking"
    );
    assert!(
        receiver.ids().is_empty(),
        "native preparation grants no store effect"
    );
    let admitted = receiver
        .commit_batch(root, batch, Instant::now() + Duration::from_secs(60))
        .unwrap();
    assert_eq!(admitted.len(), 2);
    assert_eq!(
        receiver.checker_calls(),
        (2, 0),
        "commit reuses sealed checked results"
    );
    assert!(receiver.contains(root).unwrap());
    assert!(
        receiver
            .contains(ProofId::from_bytes(id_bytes(&helper.proof_id).unwrap()))
            .unwrap()
    );
}

#[test]
fn generated_missing_invalid_unused_and_wrong_target_helpers_never_publish() {
    let receiver = Graph::default();
    let helper = receiver.author(SOURCE).unwrap();
    let root_source = format!(
        "goal = all(x,eq(x,x)) proof: p0 = cite(\"{}\") return p0",
        helper.proof_id
    );
    let question =
        naome_authoring::CompiledQuestion::compile(&crate::mocks::create_question(0)).unwrap();
    assert!(
        receiver
            .prepare_generated(&root_source, &[], &question)
            .is_err()
    );
    assert!(
        receiver
            .prepare_generated(&root_source, &["invalid helper".into()], &question)
            .is_err()
    );
    let unrelated =
        naome_authoring::CompiledQuestion::compile(&crate::mocks::create_question(1)).unwrap();
    assert!(
        receiver
            .prepare_generated(&root_source, &[SOURCE.into()], &unrelated)
            .is_err()
    );
    assert!(
        receiver
            .prepare_generated(
                &root_source,
                &[
                    SOURCE.into(),
                    crate::mocks::create_proof(&unrelated).unwrap()
                ],
                &question
            )
            .is_err()
    );
    assert!(receiver.ids().is_empty());
}

fn introduce(graph: &mut Graph) -> Envelope {
    let proof = graph.author(SOURCE).unwrap();
    graph.ingest(proof.clone(), Instant::now()).unwrap();
    proof
}
fn citation(graph: &Graph, parent: &Envelope) -> Envelope {
    graph
        .author(&format!(
            "goal = all(x, eq(x,x)) proof: p0 = cite(\"{}\") return p0",
            parent.proof_id
        ))
        .unwrap()
}

#[test]
fn aliases_and_alternative_derivations_coexist_without_ledger_selection() {
    let mut graph = Graph::default();
    let parent = introduce(&mut graph);
    let child = citation(&graph, &parent);
    assert_ne!(parent.proof_id, child.proof_id);
    assert_eq!(parent.statement_id, child.statement_id);
    // Keep the strict selected-state rejection as an independent small oracle.
    let mut strict = naome_checker::ArtifactState::new();
    strict
        .register_proof(
            check_normal_form_with_state(parent.clone().prepare().unwrap().normal, &strict)
                .unwrap(),
        )
        .unwrap();
    let checked =
        check_normal_form_with_state(child.clone().prepare().unwrap().normal, &strict).unwrap();
    assert!(matches!(
        strict.validate_proof_registration(&checked),
        Err(naome_checker::ArtifactStateError::DuplicateDerivation { .. })
    ));
    let outcome = graph.ingest(child.clone(), Instant::now()).unwrap();
    assert_eq!(outcome.status, "accepted");
    assert_eq!(graph.ids().len(), 2);
    assert_eq!(
        graph.ingest(child, Instant::now()).unwrap().status,
        "duplicate"
    );
    assert_eq!(graph.ids().len(), 2);
    let alternate = graph.author("goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = simp(eq(x,x),eq(x,x)) p2 = mp(p0,p1) p3 = mp(p0,p2) p4 = gen(p3,x) return p4").unwrap();
    assert_eq!(alternate.statement_id, parent.statement_id);
    assert_ne!(alternate.proof_id, parent.proof_id);
    let alternate_checked =
        check_normal_form_with_state(alternate.clone().prepare().unwrap().normal, &graph.context)
            .unwrap();
    assert!(
        strict
            .validate_proof_registration(&alternate_checked)
            .is_ok()
    );
    graph.ingest(alternate, Instant::now()).unwrap();
    assert_eq!(graph.ids().len(), 3);
}

#[test]
fn dependent_waits_for_exact_immutable_parent_then_union_converges() {
    let mut first = Graph::default();
    let parent = introduce(&mut first);
    let child = citation(&first, &parent);
    first.ingest(child.clone(), Instant::now()).unwrap();
    let mut second = Graph::default();
    assert_eq!(
        second.ingest(child, Instant::now()).unwrap().status,
        "waiting"
    );
    assert!(second.ids().is_empty());
    assert_eq!(second.missing().unwrap().len(), 1);
    assert_eq!(
        second
            .ingest(parent, Instant::now())
            .unwrap()
            .admitted
            .len(),
        2
    );
    assert_eq!(first.content_root(), second.content_root());
}

#[test]
fn waiting_proofs_survive_retry_deadlines_without_extending_or_resetting_history() {
    let mut producer = Graph::default();
    let parent = introduce(&mut producer);
    let child = citation(&producer, &parent);
    let mut graph = Graph::default();
    let now = Instant::now();
    graph.ingest(child.clone(), now).unwrap();
    graph
        .ingest(
            child.clone(),
            now + crate::resources::limits().pending_retry - Duration::from_secs(1),
        )
        .unwrap();
    graph
        .ingest(parent, now + crate::resources::limits().pending_retry)
        .unwrap();
    assert_eq!(
        graph
            .ingest(child, now + crate::resources::limits().pending_retry)
            .unwrap()
            .status,
        "duplicate"
    );
}

#[test]
fn malformed_mismatched_open_and_non_normal_bytes_have_no_accepted_effects() {
    let mut graph = Graph::default();
    let original = introduce(&mut graph);
    let root = graph.content_root();
    let mut invalid = original.clone();
    invalid.proof = "ff".into();
    assert!(
        graph
            .ingest(invalid, Instant::now())
            .unwrap_err()
            .contains("malformed")
    );
    let mut invalid = original.clone();
    invalid.proof_id = "00".repeat(32);
    assert!(
        graph
            .ingest(invalid, Instant::now())
            .unwrap_err()
            .contains("claimed")
    );
    let mut invalid = original.clone();
    invalid.compatibility = "00".repeat(32);
    assert!(
        graph
            .ingest(invalid, Instant::now())
            .unwrap_err()
            .contains("compatibility")
    );
    let bytes = ProofCertificate::new(vec![ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(0),
    }])
    .unwrap()
    .to_canonical_bytes();
    let statement = StatementId::from_bytes([0; 32]);
    let invalid = Envelope {
        compatibility: hex(&crate::compatibility()),
        proof_id: hex(content_id(statement, &bytes).as_bytes()),
        statement_id: hex(statement.as_bytes()),
        proof: hex(&bytes),
    };
    assert!(
        graph
            .ingest(invalid, Instant::now())
            .unwrap_err()
            .contains("mathematically invalid")
    );
    let bytes = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity {
            variable: FreeVariable::new(0),
        },
        ProofStep::EqualityReflexivity {
            variable: FreeVariable::new(1),
        },
        ProofStep::Generalization {
            premise: 1,
            variable: FreeVariable::new(1),
        },
    ])
    .unwrap()
    .to_canonical_bytes();
    let invalid = Envelope {
        compatibility: hex(&crate::compatibility()),
        proof_id: hex(content_id(statement, &bytes).as_bytes()),
        statement_id: hex(statement.as_bytes()),
        proof: hex(&bytes),
    };
    assert!(
        graph
            .ingest(invalid, Instant::now())
            .unwrap_err()
            .contains("non-normal")
    );
    assert_eq!(graph.content_root(), root);
    assert!(graph.pending_ids().unwrap().is_empty());
}

#[test]
fn durable_restart_rechecks_dependencies_aliases_and_detects_corruption() {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "naome-knowledge-test-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    let mut graph = Graph::open(&directory).unwrap();
    let parent = introduce(&mut graph);
    let child = citation(&graph, &parent);
    graph.ingest(child, Instant::now()).unwrap();
    let root = graph.content_root();
    assert!(Graph::open(&directory).is_err());
    drop(graph);
    let graph = Graph::open(&directory).unwrap();
    assert_eq!(graph.content_root(), root);
    drop(graph);
    crate::store::corrupt_payload(&directory, &parent.proof_id);
    assert!(Graph::open(&directory).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn pending_history_outlives_working_pages_and_restart_without_affecting_accepted_state() {
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let root = graph.content_root();
    let total = 4 * crate::resources::limits().pending_page;
    for index in 0..total {
        let mut parent = [0; 32];
        parent[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let bytes = ProofCertificate::new(vec![ProofStep::ProofReference {
            proof_id: ProofId::from_bytes(parent),
        }])
        .unwrap()
        .to_canonical_bytes();
        let statement = StatementId::from_bytes([0; 32]);
        assert_eq!(
            graph
                .ingest(
                    Envelope {
                        compatibility: hex(&crate::compatibility()),
                        proof_id: hex(content_id(statement, &bytes).as_bytes()),
                        statement_id: hex(statement.as_bytes()),
                        proof: hex(&bytes)
                    },
                    Instant::now()
                )
                .unwrap()
                .status,
            "waiting"
        );
        assert!(graph.pending.len() <= crate::resources::limits().pending_page);
    }
    assert_eq!(graph.pending_count().unwrap(), total);
    assert_eq!(graph.content_root(), root);
    drop(graph);
    let mut graph = Graph::open(&directory.0).unwrap();
    assert_eq!(graph.pending_count().unwrap(), total);
    let mut cursor = None;
    let mut observed = BTreeSet::new();
    loop {
        let page = graph.pending_ids_after(cursor, 31).unwrap();
        if page.is_empty() {
            break;
        }
        cursor = page.last().copied();
        for id in page {
            assert!(observed.insert(id));
            assert!(graph.waiting(id));
        }
    }
    assert_eq!(observed.len(), total);
    for _ in 0..4 {
        graph.resolve_pending().unwrap();
        assert!(graph.pending.len() <= crate::resources::limits().pending_page);
    }
    assert_eq!(graph.pending_count().unwrap(), total);
    assert_eq!(graph.content_root(), root);
}

#[test]
fn dependency_depth_is_a_derived_metric_without_a_lifetime_ceiling() {
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let mut parent = introduce(&mut graph);
    for _ in 1..160 {
        let child = citation(&graph, &parent);
        graph.ingest(child.clone(), Instant::now()).unwrap();
        parent = child;
    }
    let root = graph.content_root();
    let id = ProofId::from_bytes(id_bytes(&parent.proof_id).unwrap());
    assert_eq!(
        graph.checked_context().proof_dependency_depth(id).unwrap(),
        Some(160)
    );
    drop(graph);
    let mut graph = Graph::open(&directory.0).unwrap();
    assert_eq!(graph.content_root(), root);
    let child = citation(&graph, &parent);
    graph.ingest(child, Instant::now()).unwrap();
}

#[test]
fn storage_failure_does_not_publish_memory_state_and_halts_further_admission() {
    let directory = std::env::temp_dir().join(format!(
        "naome-knowledge-storage-failure-{}",
        std::process::id()
    ));
    let mut graph = Graph::open(&directory).unwrap();
    let object = graph.author(SOURCE).unwrap();
    let root = graph.content_root();
    std::fs::remove_file(directory.join(crate::store::DATABASE_FILE)).unwrap();
    assert!(
        graph
            .ingest(object.clone(), Instant::now())
            .unwrap_err()
            .contains("storage halted")
    );
    assert!(graph.storage_error().is_some());
    assert_eq!(graph.content_root(), root);
    assert!(graph.ingest(object, Instant::now()).is_err());
    drop(graph);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn expired_commit_rolls_back_without_publishing_or_halting_the_graph() {
    let mut graph = Graph::default();
    let question = naome_authoring::CompiledQuestion::compile("goal = all(x,eq(x,x))").unwrap();
    let (root, batch) = graph.prepare_generated(SOURCE, &[], &question).unwrap();
    let before = graph.content_root();
    assert_eq!(
        graph.commit_batch(root, batch, Instant::now() - Duration::from_secs(1)),
        Err(crate::store::COMMIT_DEADLINE_ERROR)
    );
    assert_eq!(graph.accepted_count(), 0);
    assert_eq!(graph.content_root(), before);
    assert!(graph.ids_page(None, 64).unwrap().is_empty());
    assert!(graph.storage_error().is_none());
    let (root, batch) = graph.prepare_generated(SOURCE, &[], &question).unwrap();
    assert_eq!(
        graph
            .commit_batch(root, batch, Instant::now() + Duration::from_secs(60))
            .unwrap(),
        vec![root]
    );
}

#[test]
fn generation_compaction_preserves_cold_snapshots_and_rejects_old_prepared_batches() {
    let mut graph = Graph::default();
    let parent = introduce(&mut graph);
    let parent_id = ProofId::from_bytes(id_bytes(&parent.proof_id).unwrap());
    let old = graph.context.clone();
    let old_storage = Arc::downgrade(&graph.checked_storage);
    let before = old.snapshot_id();
    let source = format!(
        "goal = all(x,eq(x,x)) proof: p0 = cite(\"{}\") return p0",
        parent.proof_id
    );
    let question = naome_authoring::CompiledQuestion::compile("goal = all(x,eq(x,x))").unwrap();
    let (root, batch) = graph.prepare_generated(&source, &[], &question).unwrap();
    graph.next_compaction = 0;
    graph.maintain_checked_storage().unwrap();
    graph.checked_storage.evict_cache();
    assert!(old.contains_proof(parent_id).unwrap());
    assert_eq!(graph.context.snapshot_id(), before);
    assert_eq!(graph.object(parent_id).unwrap(), Some(parent));
    assert!(
        graph
            .commit_batch(root, batch, Instant::now() + Duration::from_secs(60))
            .unwrap_err()
            .contains("generation changed")
    );
    assert_eq!(graph.accepted_count(), 1);
    assert!(graph.storage_error().is_none());
    assert!(old_storage.upgrade().is_some());
    drop(old);
    assert!(
        old_storage.upgrade().is_none(),
        "last snapshot releases its old generation"
    );
    let (root, batch) = graph.prepare_generated(&source, &[], &question).unwrap();
    graph
        .commit_batch(root, batch, Instant::now() + Duration::from_secs(60))
        .unwrap();
    assert_eq!(graph.accepted_count(), 2);
}

fn drain_current_copy(graph: &mut Graph) {
    assert!(graph.compaction.is_some());
    for _ in 0..4096 {
        let _ = graph
            .maintain_checked_storage_step(
                usize::MAX,
                DiskCopyBudget {
                    records: 1,
                    bytes: naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES,
                },
            )
            .unwrap();
        if graph.compaction.is_none() {
            return;
        }
    }
    panic!("small test copy did not complete");
}

#[test]
fn pre_attach_batch_is_stale_before_canonical_write_while_generation_is_unchanged() {
    let mut graph = Graph::default();
    let parent = introduce(&mut graph);
    let source = format!(
        "goal = all(x,eq(x,x)) proof: p0 = cite(\"{}\") return p0",
        parent.proof_id
    );
    let question = naome_authoring::CompiledQuestion::compile("goal = all(x,eq(x,x))").unwrap();
    let (root, batch) = graph.prepare_generated(&source, &[], &question).unwrap();
    let storage = graph.checked_storage.clone();
    let epoch = storage.copy_epoch().unwrap();
    let snapshot = graph.context.snapshot_id();
    let corpus = graph.content_root();
    // A persistence attempt would fail and halt this owner. Epoch rejection
    // must happen before that call, even though snapshot and Arc still match.
    graph.test_batch_cut(crate::store::BatchCut::BeforeWrite);
    assert!(graph.test_compaction_step(1).unwrap());
    assert!(Arc::ptr_eq(&storage, &graph.checked_storage));
    assert_eq!(graph.context.snapshot_id(), snapshot);
    assert_ne!(storage.copy_epoch().unwrap(), epoch);
    assert!(
        graph
            .commit_batch(root, batch, Instant::now() + Duration::from_secs(60))
            .unwrap_err()
            .contains("generation changed")
    );
    assert_eq!(graph.accepted_count(), 1);
    assert_eq!(graph.content_root(), corpus);
    assert_eq!(graph.store.summary().unwrap().count, 1);
    assert!(!graph.contains(root).unwrap());
    assert!(graph.storage_error().is_none());
}

#[test]
fn post_attach_batch_and_new_formula_survive_current_root_handoff_with_cold_reads() {
    let mut graph = Graph::default();
    let parent = introduce(&mut graph);
    let parent_id = ProofId::from_bytes(id_bytes(&parent.proof_id).unwrap());
    let old = graph.context.clone();
    let old_storage = Arc::downgrade(&graph.checked_storage);
    let old_snapshot = old.snapshot_id();
    assert!(graph.test_compaction_step(1).unwrap());
    let source = "goal = imp(all(x,eq(x,x)),imp(all(y,eq(y,y)),all(x,eq(x,x)))) proof: p0 = simp(all(x,eq(x,x)),all(y,eq(y,y))) return p0";
    let question = naome_authoring::CompiledQuestion::compile(
        "goal = imp(all(x,eq(x,x)),imp(all(y,eq(y,y)),all(x,eq(x,x))))",
    )
    .unwrap();
    let expected = graph.author(source).unwrap();
    let (root, batch) = graph.prepare_generated(source, &[], &question).unwrap();
    graph
        .commit_batch(root, batch, Instant::now() + Duration::from_secs(60))
        .unwrap();
    assert!(graph.compaction.is_some(), "commit occurs during the copy");
    assert!(old_storage.ptr_eq(&Arc::downgrade(&graph.checked_storage)));
    let current_snapshot = graph.context.snapshot_id();
    let current_corpus = graph.content_root();
    assert_ne!(current_snapshot, old_snapshot);
    drain_current_copy(&mut graph);
    assert!(!old_storage.ptr_eq(&Arc::downgrade(&graph.checked_storage)));
    assert_eq!(graph.context.snapshot_id(), current_snapshot);
    assert_eq!(graph.content_root(), current_corpus);
    graph.checked_storage.evict_cache();
    assert_eq!(graph.object(root).unwrap(), Some(expected));
    let header = graph.context.proof_header(root).unwrap().unwrap();
    assert!(
        graph
            .context
            .statement_formula(
                header.statement_id(),
                naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES
            )
            .unwrap()
            .is_some()
    );
    assert!(graph.context.contains_proof(parent_id).unwrap());
    graph.checked_storage.evict_cache();
    assert!(old.contains_proof(parent_id).unwrap());
    assert!(!old.contains_proof(root).unwrap());
    assert!(old_storage.upgrade().is_some());
    drop(old);
    assert!(
        old_storage.upgrade().is_none(),
        "the cursor retains no hidden source Arc"
    );
    assert!(graph.storage_error().is_none());
}

#[test]
fn an_expired_post_attach_batch_preserves_deadline_and_partial_copy_state() {
    let mut graph = Graph::default();
    let parent = introduce(&mut graph);
    assert!(graph.test_compaction_step(1).unwrap());
    let source = format!(
        "goal = all(x,eq(x,x)) proof: p0 = cite(\"{}\") return p0",
        parent.proof_id
    );
    let question = naome_authoring::CompiledQuestion::compile("goal = all(x,eq(x,x))").unwrap();
    let (root, batch) = graph.prepare_generated(&source, &[], &question).unwrap();
    let before = graph.content_root();
    assert_eq!(
        graph.commit_batch(root, batch, Instant::now() - Duration::from_secs(1)),
        Err(crate::store::COMMIT_DEADLINE_ERROR)
    );
    assert!(graph.compaction.is_some());
    assert_eq!(graph.accepted_count(), 1);
    assert_eq!(graph.content_root(), before);
    assert!(graph.storage_error().is_none());
    drain_current_copy(&mut graph);
    graph.checked_storage.evict_cache();
    assert!(!graph.contains(root).unwrap());
    assert_eq!(graph.content_root(), before);
}

#[test]
fn four_retained_old_generations_bound_copy_admission_without_changing_snapshots() {
    let mut graph = Graph::default();
    let parent = introduce(&mut graph);
    let id = ProofId::from_bytes(id_bytes(&parent.proof_id).unwrap());
    let snapshot = graph.context.snapshot_id();
    let mut retained = Vec::new();
    for _ in 0..4 {
        retained.push(graph.context.clone());
        assert!(graph.test_compaction_step(1).unwrap());
        drain_current_copy(&mut graph);
        assert_eq!(graph.context.snapshot_id(), snapshot);
    }
    let current = Arc::downgrade(&graph.checked_storage);
    assert_eq!(
        graph.test_compaction_step(1).unwrap_err(),
        crate::Error::ExecutionLimit
    );
    assert!(graph.compaction.is_none());
    assert!(current.ptr_eq(&Arc::downgrade(&graph.checked_storage)));
    assert!(graph.storage_error().is_none());
    drop(retained.pop());
    assert!(graph.test_compaction_step(1).unwrap());
    drain_current_copy(&mut graph);
    graph.checked_storage.evict_cache();
    assert!(graph.context.contains_proof(id).unwrap());
    for old in retained {
        graph.checked_storage.evict_cache();
        assert_eq!(old.snapshot_id(), snapshot);
        assert!(old.contains_proof(id).unwrap());
    }
}

#[test]
fn direct_cold_formula_integrity_failure_halts_the_owner() {
    let mut graph = Graph::default();
    let parent = introduce(&mut graph);
    let id = ProofId::from_bytes(id_bytes(&parent.proof_id).unwrap());
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
    let mut hash = sha2::Sha256::new();
    hash.update(b"naome:checked-formula-storage:v1\0");
    hash.update(&formula);
    let address: [u8; 32] = hash.finalize().into();
    let index = std::fs::read_dir(graph.store.directory())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".checked-context-")
        })
        .unwrap();
    let database = rusqlite::Connection::open(index).unwrap();
    assert_eq!(
        database
            .execute(
                "UPDATE nodes SET payload=zeroblob(length(payload)) WHERE address=?1",
                [address.as_slice()]
            )
            .unwrap(),
        1
    );
    graph.checked_storage.evict_cache();
    assert!(matches!(
        graph.context.statement_formula(
            header.statement_id(),
            naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES
        ),
        Err(naome_checker::ContextError::Corrupt)
    ));
    assert!(
        graph.storage_error().is_some(),
        "direct ContextView caller reports integrity failure"
    );
    assert!(graph.author(SOURCE).unwrap_err().contains("storage halted"));
}

#[test]
fn metadata_drift_and_missing_inventory_members_cannot_look_like_absence() {
    for drift in [true, false] {
        let mut graph = Graph::default();
        let parent = introduce(&mut graph);
        let id = ProofId::from_bytes(id_bytes(&parent.proof_id).unwrap());
        let before = graph.content_root();
        let database =
            rusqlite::Connection::open(graph.store.directory().join(crate::store::DATABASE_FILE))
                .unwrap();
        if drift {
            database
                .execute(
                    "UPDATE meta SET corpus_root=zeroblob(32) WHERE singleton=1",
                    [],
                )
                .unwrap();
        } else {
            // Simulate external corruption without changing the live owner's protections.
            database
                .execute_batch("PRAGMA foreign_keys = OFF;")
                .unwrap();
            database
                .execute("DELETE FROM proofs WHERE id=?1", [id.as_bytes().as_slice()])
                .unwrap();
        }
        assert!(graph.ids_page(None, 64).is_err());
        assert!(graph.storage_error().is_some());
        assert_eq!(graph.content_root(), before);
        assert!(graph.object(id).is_err());
    }
}

#[test]
fn unrelated_external_payload_change_halts_admission_without_advancing_checked_state() {
    let mut graph = Graph::default();
    let parent = introduce(&mut graph);
    let child = graph
        .author(&format!(
            "goal = all(x,eq(x,x)) proof: p0 = cite(\"{}\") return p0",
            parent.proof_id
        ))
        .unwrap();
    let before = graph.content_root();
    let count = graph.accepted_count();
    let database =
        rusqlite::Connection::open(graph.store.directory().join(crate::store::DATABASE_FILE))
            .unwrap();
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
    let error = graph.ingest(child, Instant::now()).unwrap_err();
    assert!(error.contains("outside its owned connection"), "{error}");
    assert!(graph.storage_error().is_some());
    assert_eq!(graph.content_root(), before);
    assert_eq!(graph.accepted_count(), count);
}

#[test]
fn replay_compaction_keeps_ingest_scheduling_and_cold_snapshots() {
    const MIB: usize = 1024 * 1024;
    for (live, expected) in [
        (0, 32 * MIB),
        (32 * MIB, 64 * MIB),
        (64 * MIB, 96 * MIB),
        (64 * MIB + 2, 96 * MIB + 3),
        (usize::MAX - 1, usize::MAX),
        (usize::MAX, usize::MAX),
    ] {
        assert_eq!(Graph::replay_compaction_threshold(live), expected);
    }

    let mut graph = Graph::default();
    let envelope = introduce(&mut graph);
    let id = ProofId::from_bytes(id_bytes(&envelope.proof_id).unwrap());
    let old = graph.context.clone();
    let old_storage = Arc::downgrade(&graph.checked_storage);
    let snapshot = old.snapshot_id();
    let root = graph.content_root();

    graph.next_compaction = usize::MAX;
    graph.maintain_checked_storage().unwrap();
    assert!(old_storage.ptr_eq(&Arc::downgrade(&graph.checked_storage)));

    let live = graph.maintain_checked_storage_at(0).unwrap().unwrap();
    assert!(!old_storage.ptr_eq(&Arc::downgrade(&graph.checked_storage)));
    let ingest_threshold = live
        .saturating_mul(2)
        .max(live.saturating_add(crate::resources::limits().checked_cache_bytes));
    assert_eq!(graph.next_compaction, ingest_threshold);
    graph.checked_storage.evict_cache();
    assert_eq!(graph.context.snapshot_id(), snapshot);
    assert!(old.contains_proof(id).unwrap());
    assert_eq!(graph.object(id).unwrap(), Some(envelope.clone()));

    let current = Arc::downgrade(&graph.checked_storage);
    graph.next_compaction = 0;
    assert_eq!(graph.maintain_checked_storage_at(usize::MAX).unwrap(), None);
    assert_eq!(
        graph.next_compaction, 0,
        "a skipped page cannot rebase ingest"
    );
    assert!(current.ptr_eq(&Arc::downgrade(&graph.checked_storage)));
    graph.ingest(envelope.clone(), Instant::now()).unwrap();
    assert!(!current.ptr_eq(&Arc::downgrade(&graph.checked_storage)));
    graph.checked_storage.evict_cache();
    assert_eq!(graph.context.snapshot_id(), snapshot);
    assert_eq!(graph.content_root(), root);
    assert_eq!(graph.accepted_count(), 1);
    assert_eq!(graph.object(id).unwrap(), Some(envelope));
    assert!(graph.storage_error().is_none());
    drop(old);
    assert!(old_storage.upgrade().is_none());
}

fn startup_prune_directory(name: &str) -> std::path::PathBuf {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "naome-startup-prune-{}-{}-{name}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ))
}

fn startup_prune_fixture(directory: &Path) -> (Graph, Vec<Envelope>, StatementId) {
    let mut graph = Graph::open(directory).unwrap();
    let parent = introduce(&mut graph);
    let target = StatementId::from_bytes(id_bytes(&parent.statement_id).unwrap());
    let mut envelopes = vec![parent.clone(), citation(&graph, &parent)];
    graph.ingest(envelopes[1].clone(), Instant::now()).unwrap();
    for source in [
        "let: a = all(x,eq(x,x)) goal = imp(a,imp(a,a)) proof: p0 = simp(a,a) return p0",
        "let: a = all(x,eq(x,x)) b = all(x,all(y,eq(x,x))) goal = imp(a,imp(b,a)) proof: p0 = simp(a,b) return p0",
    ] {
        let envelope = graph.author(source).unwrap();
        assert_eq!(
            graph
                .ingest(envelope.clone(), Instant::now())
                .unwrap()
                .status,
            "accepted"
        );
        envelopes.push(envelope);
    }
    (graph, envelopes, target)
}

fn startup_prune_buckets(graph: &Graph, target: StatementId) -> Vec<Vec<StatementId>> {
    use naome_checker::context::BucketKind;
    [
        BucketKind::Outgoing,
        BucketKind::Deductions,
        BucketKind::Instances,
    ]
    .into_iter()
    .map(|kind| {
        graph
            .context
            .bucket(kind, target)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    })
    .collect()
}

#[test]
fn startup_prune_replays_aliases_dependencies_and_nested_buckets_after_cache_eviction() {
    let directory = startup_prune_directory("cold-buckets");
    let (graph, envelopes, target) = startup_prune_fixture(&directory);
    assert_eq!(envelopes[0].statement_id, envelopes[1].statement_id);
    assert_ne!(envelopes[0].proof_id, envelopes[1].proof_id);
    let root = graph.content_root();
    let snapshot = graph.context.snapshot_id();
    let buckets = startup_prune_buckets(&graph, target);
    assert!(buckets[0].len() >= 2 && buckets[1].len() >= 2 && !buckets[2].is_empty());
    drop(graph);

    let graph = storage::with_startup_prune_test(None, || Graph::open(&directory)).unwrap();
    graph.checked_storage.evict_cache();
    assert_eq!(graph.content_root(), root);
    assert_eq!(graph.context.snapshot_id(), snapshot);
    assert_eq!(graph.accepted_count(), envelopes.len());
    assert_eq!(startup_prune_buckets(&graph, target), buckets);
    assert_eq!(
        graph
            .context
            .proof_dependency_depth(ProofId::from_bytes(
                id_bytes(&envelopes[1].proof_id).unwrap()
            ))
            .unwrap(),
        Some(2)
    );
    for envelope in envelopes {
        assert_eq!(graph.get(&envelope.proof_id).unwrap(), Some(envelope));
    }
    assert!(graph.storage_error().is_none());
    drop(graph);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn startup_prune_failures_discard_the_generation_and_rebuild_from_canonical_history() {
    for stage in [
        storage::StartupPruneStage::Mark,
        storage::StartupPruneStage::Sweep,
        storage::StartupPruneStage::Reclaim,
    ] {
        let directory = startup_prune_directory(&format!("failure-{stage:?}"));
        let (graph, envelopes, target) = startup_prune_fixture(&directory);
        let root = graph.content_root();
        let snapshot = graph.context.snapshot_id();
        let buckets = startup_prune_buckets(&graph, target);
        drop(graph);
        let error = storage::with_startup_prune_test(Some(stage), || Graph::open(&directory))
            .err()
            .expect("no live graph may escape a partial prune");
        assert!(
            error.contains(&format!("test-controlled startup prune {stage:?} failure")),
            "{error}"
        );
        assert!(
            std::fs::read_dir(&directory).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".checked-context-")
            }),
            "the failed generation must be unlinked, not recovered by rollback"
        );

        let graph = Graph::open(&directory).unwrap();
        graph.checked_storage.evict_cache();
        assert_eq!(graph.content_root(), root);
        assert_eq!(graph.context.snapshot_id(), snapshot);
        assert_eq!(graph.accepted_count(), envelopes.len());
        assert_eq!(startup_prune_buckets(&graph, target), buckets);
        for envelope in envelopes {
            assert_eq!(graph.get(&envelope.proof_id).unwrap(), Some(envelope));
        }
        assert!(graph.storage_error().is_none());
        drop(graph);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn local_source_production_reuses_one_sealed_check_with_identical_transport_bytes() {
    let producer = Graph::default();
    let expected = producer.author(SOURCE).unwrap();
    let mut graph = Graph::default();
    let (object, result) = graph.produce(SOURCE).unwrap();
    assert_eq!(object, expected);
    assert_eq!(result.status, "accepted");
    assert_eq!(graph.checker_calls(), (1, 0));
    assert_eq!(graph.object(result.id).unwrap(), Some(expected));
}

#[test]
fn disk_pressure_rejects_every_preparation_and_batch_commit_without_integrity_halt() {
    let mut graph = Graph::default();
    let envelope = graph.author(SOURCE).unwrap();
    let question = naome_authoring::CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let (root, batch) = graph.prepare_generated(SOURCE, &[], &question).unwrap();
    crate::resources::with_disk_available(
        u128::from(crate::resources::limits().disk_reserve_bytes),
        || {
            assert!(matches!(
                graph.ingest(envelope.clone(), Instant::now()),
                Err(crate::Error::DiskOverload { .. })
            ));
            assert!(matches!(
                graph.produce(SOURCE),
                Err(crate::Error::DiskOverload { .. })
            ));
            assert!(matches!(
                graph.prepare_generated(SOURCE, &[], &question),
                Err(crate::Error::DiskOverload { .. })
            ));
            let candidate = envelope.prepare().unwrap();
            assert!(matches!(
                graph.prepare_batch(root, [(root, candidate)].into(), &question),
                Err(crate::Error::DiskOverload { .. })
            ));
            assert!(matches!(
                graph.commit_batch(root, batch, Instant::now() + Duration::from_secs(5)),
                Err(crate::Error::DiskOverload { .. })
            ));
        },
    );
    assert!(graph.storage_error().is_none());
    assert_eq!(graph.accepted_count(), 0);
}

#[test]
fn catalog_allocation_overload_is_retryable_and_never_sets_integrity_halt() {
    let mut graph = Graph::default();
    let (_, result) = graph.produce(SOURCE).unwrap();
    crate::resources::fail_next_memory_allocation();
    let error = graph.object(result.id).unwrap_err();
    assert!(error.retryable(), "{error:?}");
    assert!(graph.storage_error().is_none());
    assert!(graph.object(result.id).unwrap().is_some());
}

#[test]
fn unchanged_blocked_backlog_performs_no_sql_writes_and_wakes_on_exact_dependency() {
    let mut producer = Graph::default();
    let parent = introduce(&mut producer);
    let child = citation(&producer, &parent);
    let mut graph = Graph::default();
    graph.ingest(child, Instant::now()).unwrap();
    graph.resolve_pending().unwrap();
    let changes = graph.backlog().unwrap().changes();
    for _ in 0..8 {
        assert!(graph.resolve_pending().unwrap().0.is_empty());
    }
    assert_eq!(graph.backlog().unwrap().changes(), changes);
    assert_eq!(
        graph.ingest(parent, Instant::now()).unwrap().admitted.len(),
        2
    );
    assert_eq!(graph.pending_count().unwrap(), 0);
}

#[test]
fn a_peer_root_grant_revokes_only_its_publication() {
    for revoked in [false, true] {
        let mut graph = Graph::default();
        let question = naome_authoring::CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
        let (root, batch) = graph.prepare_generated(SOURCE, &[], &question).unwrap();
        let related = PeerGrant::new();
        let unrelated = PeerGrant::new();
        unrelated.0.store(false, Ordering::Release);
        if revoked {
            related.0.store(false, Ordering::Release);
        }
        let result = graph.commit_batch_granted(
            root,
            batch,
            Instant::now() + Duration::from_secs(5),
            Some(related),
        );
        if revoked {
            assert_eq!(result.unwrap_err(), crate::Error::StaleAuthority);
        } else {
            assert_eq!(result.unwrap(), [root]);
        }
        assert!(graph.storage_error().is_none());
    }
}

#[test]
fn narrowed_intake_limits_replay_current_proofs_without_changing_their_identity() {
    const TEST: &str = "graph::tests::narrowed_intake_limits_replay_current_proofs_without_changing_their_identity";
    if let Some(path) = std::env::var_os("NAOME_NARROW_INTAKE_TEST") {
        let profile: crate::resources::ResourceProfile = serde_json::from_value(
            serde_json::json!({"tuning":{"proof_bytes":64,"inventory_page":1}}),
        )
        .unwrap();
        crate::resources::configure(profile).unwrap();
        let mut graph = Graph::open(Path::new(&path)).unwrap();
        assert_eq!(graph.accepted_count(), 1);
        let id = graph.ids_page(None, 1).unwrap()[0];
        let object = graph.object(id).unwrap().unwrap();
        assert!(object.proof.len() > 128);
        assert!(matches!(
            graph.ingest(object, Instant::now()),
            Err(crate::Error::InputLimit(_))
        ));
        assert!(graph.storage_error().is_none());
        return;
    }
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let mut steps = vec![ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(0),
    }];
    for index in 0..32 {
        steps.push(ProofStep::Generalization {
            premise: index,
            variable: FreeVariable::new(index),
        });
    }
    let checked =
        naome_checker::normalize_and_check(ProofCertificate::new(steps).unwrap()).unwrap();
    let object = crate::object::BinaryProof::from_checked(&checked)
        .unwrap()
        .envelope();
    graph.ingest(object, Instant::now()).unwrap();
    drop(graph);
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture"])
        .env("NAOME_NARROW_INTAKE_TEST", &directory.0)
        .env_remove("NAOME_EFFECTIVE_RESOURCES")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_backlog_write_failure_halts_storage_instead_of_becoming_an_input_rejection() {
    let mut producer = Graph::default();
    let parent = introduce(&mut producer);
    let child = citation(&producer, &parent);
    let mut graph = Graph::default();
    crate::checkpoint::fail_next_commit();
    assert!(matches!(
        graph.ingest(child, Instant::now()),
        Err(crate::Error::UncertainDurability(_))
    ));
    assert!(graph.storage_error().is_some());
    assert_eq!(graph.accepted_count(), 0);
}
