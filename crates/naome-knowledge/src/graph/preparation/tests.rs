use super::*;
use crate::{graph::program::PreparedProgram, proof_work::Work, resources::adaptive::Budget};
use naome_proof::program::{CHUNK_BYTES, CHUNK_RECORDS, Command};

#[test]
fn a_valid_certificate_with_forged_claimed_identity_is_rejected_before_the_write_phase() {
    let mut graph = Graph::default();
    let valid = graph
        .author("goal=all(x,eq(x,x)) proof: p=refl(x) q=gen(p,x) return q")
        .unwrap();
    let mut forged = valid.clone();
    let statement = naome_proof::StatementId::from_bytes([7; 32]);
    forged.statement_id = crate::hex(statement.as_bytes());
    forged.proof_id = crate::hex(
        crate::object::content_id(statement, &crate::unhex(&forged.proof).unwrap()).as_bytes(),
    );
    let before = graph.content_root();
    let error = graph.ingest(forged, Instant::now()).unwrap_err();
    assert!(matches!(error, crate::Error::InvalidInput(_)));
    assert_eq!(graph.content_root(), before);
    assert_eq!(graph.accepted_count(), 0);
    assert!(
        graph.storage_error().is_none(),
        "untrusted identity claims cannot halt checked storage"
    );
    assert_eq!(
        graph.ingest(valid, Instant::now()).unwrap().admitted.len(),
        1
    );
}

#[test]
fn a_checked_program_rebinds_registration_after_graph_and_copy_changes_before_publication() {
    let mut graph = Graph::default();
    let path = graph.store.directory().join("session.sqlite3");
    let mut work = Work::open(&path).unwrap();
    for command in [
        Command::Reflexivity { variable: 0 },
        Command::Generalization {
            premise: 0,
            variable: 0,
        },
        Command::Seal { proof: 1 },
    ] {
        work.append(&command).unwrap();
    }
    let budget = Budget {
        memory_bytes: 64 * 1024 * 1024,
        concurrency: 1,
        cache_bytes: 4096,
        batch_steps: 32,
        network_requests: 1,
        yield_ms: 1,
        paused: None,
    };
    for _ in 0..128 {
        work.advance(&budget, graph.checked_context()).unwrap();
        if work.status().unwrap().fully_checked {
            break;
        }
    }
    for _ in 0..128 {
        if work.prepare_export(&budget).unwrap() {
            break;
        }
    }
    let proof = work.into_checked().unwrap();
    let manifest = proof.proof().unwrap().manifest().clone();
    let root = manifest.proof_id();
    graph.store.start_program(&manifest).unwrap();
    let chunk = proof
        .proof()
        .unwrap()
        .input_chunk(0, CHUNK_RECORDS, CHUNK_BYTES)
        .unwrap();
    graph.store.append_program(&manifest, &chunk).unwrap();
    let mut prepared = PreparedProgram::new(proof);
    assert!(!prepared.advance(&graph, 0).unwrap());
    let _ = graph
        .produce("goal=all(x,eq(x,x)) proof: p=refl(x) q=gen(p,x) return q")
        .unwrap();
    assert!(
        !prepared.advance(&graph, 1).unwrap(),
        "the old predecessor is discarded before registration advances"
    );
    for _ in 0..128 {
        if prepared.advance(&graph, 1).unwrap() {
            break;
        }
    }
    assert!(prepared.ready());
    assert_eq!(graph.accepted_count(), 1);
    assert!(!graph.contains(root).unwrap());
    assert!(
        Work::open(&path).is_err(),
        "the original checked work remains under custody"
    );
    assert!(graph.test_compaction_step(1).unwrap());
    for _ in 0..128 {
        if prepared.advance(&graph, 1).unwrap() {
            break;
        }
    }
    let batch = prepared.take_batch().expect("rebound checked delta");
    assert!(graph.batch_current(&batch).unwrap());
    assert_eq!(prepared.proof().unwrap().manifest(), &manifest);
    assert_eq!(
        graph
            .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
            .unwrap(),
        [root]
    );
    assert_eq!(graph.accepted_count(), 2);
    assert!(graph.contains(root).unwrap());
    assert!(graph.storage_error().is_none());
}
