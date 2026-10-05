use super::*;
use crate::{Envelope, hex, object::content_id};
use naome_foundation::FreeVariable;
use naome_proof::{ProofCertificate, ProofStep, StatementId};
use std::sync::atomic::{AtomicU64, Ordering};

const SOURCE: &str = "foundation = \"naome:zfc\" statement = forall(x, equal(x,x)) proof: p0 = equality_reflexivity(x) p1 = generalization(p0,x) return p1";

fn introduce(graph: &mut Graph) -> Envelope {
    let proof = graph.author(SOURCE).unwrap();
    graph.ingest(proof.clone(), Instant::now()).unwrap();
    proof
}
fn citation(graph: &Graph, parent: &Envelope) -> Envelope {
    graph.author(&format!("foundation = \"naome:zfc\" statement = forall(x, equal(x,x)) proof: p0 = cite(\"{}\") return p0",parent.proof_id)).unwrap()
}

#[test]
fn aliases_and_alternative_derivations_coexist_without_ledger_selection() {
    let mut graph = Graph::default();
    let parent = introduce(&mut graph);
    let child = citation(&graph, &parent);
    assert_ne!(parent.proof_id, child.proof_id);
    assert_eq!(parent.statement_id, child.statement_id);
    let checked =
        check_normal_form_with_state(child.clone().prepare().unwrap().normal, &graph.context)
            .unwrap();
    assert!(matches!(
        graph.context.validate_proof_registration(&checked),
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
    let alternate = graph.author("foundation = \"naome:zfc\" statement = forall(x,equal(x,x)) proof: p0 = equality_reflexivity(x) p1 = simplification(equal(x,x),equal(x,x)) p2 = modus_ponens(p0,p1) p3 = modus_ponens(p0,p2) p4 = generalization(p3,x) return p4").unwrap();
    assert_eq!(alternate.statement_id, parent.statement_id);
    assert_ne!(alternate.proof_id, parent.proof_id);
    let alternate_checked =
        check_normal_form_with_state(alternate.clone().prepare().unwrap().normal, &graph.context)
            .unwrap();
    assert!(
        graph
            .context
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
    assert_eq!(second.missing().len(), 1);
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
fn waiting_timeout_is_not_a_mathematical_rejection_and_duplicates_do_not_extend_it() {
    let mut producer = Graph::default();
    let parent = introduce(&mut producer);
    let child = citation(&producer, &parent);
    let mut graph = Graph::default();
    let now = Instant::now();
    graph.ingest(child.clone(), now).unwrap();
    graph
        .ingest(child.clone(), now + PENDING_TTL - Duration::from_secs(1))
        .unwrap();
    assert_eq!(graph.expire(now + PENDING_TTL).len(), 1);
    graph.ingest(parent, now + PENDING_TTL).unwrap();
    assert_eq!(
        graph.ingest(child, now + PENDING_TTL).unwrap().status,
        "accepted"
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
    assert!(graph.pending_ids().is_empty());
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
    std::fs::write(
        directory
            .join("objects")
            .join(format!("{}.json", parent.proof_id)),
        b"{}",
    )
    .unwrap();
    assert!(Graph::open(&directory).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn pending_capacity_is_bounded_and_does_not_change_accepted_state() {
    let mut graph = Graph::default();
    let root = graph.content_root();
    for index in 0..MAX_PENDING {
        let mut parent = [0; 32];
        parent[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let bytes = ProofCertificate::new(vec![ProofStep::ProofReference {
            proof_id: ProofId::from_bytes(parent),
        }])
        .unwrap()
        .to_canonical_bytes();
        let statement = StatementId::from_bytes([0; 32]);
        graph
            .ingest(
                Envelope {
                    compatibility: hex(&crate::compatibility()),
                    proof_id: hex(content_id(statement, &bytes).as_bytes()),
                    statement_id: hex(statement.as_bytes()),
                    proof: hex(&bytes),
                },
                Instant::now(),
            )
            .unwrap();
    }
    assert_eq!(graph.pending_ids().len(), MAX_PENDING);
    let bytes = ProofCertificate::new(vec![ProofStep::ProofReference {
        proof_id: ProofId::from_bytes([255; 32]),
    }])
    .unwrap()
    .to_canonical_bytes();
    let statement = StatementId::from_bytes([0; 32]);
    assert!(
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
            .unwrap_err()
            .contains("pending capacity")
    );
    assert_eq!(graph.content_root(), root);
}

#[test]
fn reference_depth_has_an_explicit_policy_boundary() {
    let mut graph = Graph::default();
    let mut parent = introduce(&mut graph);
    for _ in 1..MAX_DEPTH {
        let child = citation(&graph, &parent);
        graph.ingest(child.clone(), Instant::now()).unwrap();
        parent = child;
    }
    let root = graph.content_root();
    let child = citation(&graph, &parent);
    assert!(
        graph
            .ingest(child, Instant::now())
            .unwrap_err()
            .contains("depth limit")
    );
    assert_eq!(graph.content_root(), root);
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
    std::fs::remove_dir(directory.join("objects")).unwrap();
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
