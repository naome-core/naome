use super::*;

const RELATION: &str = "0100000000010000000b0000000000000000000000";

fn definition_source(definition: &Envelope) -> String {
    use naome_proof::{DefinedFormula, ProofFormula, ProofSeparation, ProofStep};
    let [element, source, result] = [0, 1, 2].map(crate::test_inputs::variable);
    let id = definition.definition_id().unwrap().unwrap();
    crate::test_inputs::proof(vec![ProofStep::Separation(ProofSeparation {
        predicate: ProofFormula::from_defined(DefinedFormula::defined_relation(id, [element]))
            .unwrap(),
        element,
        source,
        result,
        parameters: vec![],
    })])
}
fn identity_obligation() -> Envelope {
    let digits: String =
        include_str!("../../../../naome-checker/src/tests/fixtures/identity_unique.proof.hex")
            .split_whitespace()
            .collect();
    let certificate =
        ProofCertificate::from_canonical_bytes(&crate::unhex(&digits).unwrap()).unwrap();
    crate::object::BinaryArtifact::from_checked(
        &naome_checker::normalize_and_check(certificate).unwrap(),
    )
    .unwrap()
    .envelope()
}

#[test]
fn definition_memory_overload_preserves_the_graph_and_allows_retry() {
    let mut graph = Graph::default();
    let root = graph.content_root();
    crate::resources::fail_next_memory_allocation();
    assert!(matches!(
        graph.produce(RELATION),
        Err(crate::Error::MemoryOverload { .. })
    ));
    assert_eq!(graph.accepted_count(), 0);
    assert_eq!(graph.content_root(), root);
    assert!(graph.storage_error().is_none());
    assert_eq!(
        graph.produce(RELATION).unwrap().1.status,
        crate::IngestStatus::Accepted
    );
}

#[test]
fn definitions_are_durable_cited_dependencies_and_restart_rechecks_them() {
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let (definition, admission) = graph.produce(RELATION).unwrap();
    let definition_id = admission.id;
    assert_eq!(definition.statement_id, None);
    assert_eq!(definition.obligation_proof, None);
    assert!(
        graph.describe(definition_id).unwrap().is_none(),
        "definitions do not assert theorems"
    );
    let source = definition_source(&definition);
    let (proof, admission) = graph.produce(&source).unwrap();
    assert_eq!(
        proof.clone().prepare().unwrap().dependencies,
        BTreeSet::from([definition_id])
    );
    let root = graph.content_root();
    drop(graph);
    let mut graph = Graph::open(&directory.0).unwrap();
    assert_eq!(graph.content_root(), root);
    assert_eq!(
        graph.object(definition_id).unwrap(),
        Some(definition.clone())
    );
    assert_eq!(graph.object(admission.id).unwrap(), Some(proof));
    assert_eq!(
        graph.produce(&source).unwrap().1.status,
        crate::IngestStatus::Duplicate
    );
    drop(graph);
    crate::store::corrupt_payload(&directory.0, &definition.artifact_id);
    assert!(
        Graph::open(&directory.0).is_err(),
        "a saved checked flag cannot hide damaged definitions"
    );
}

#[test]
fn proof_waits_for_its_definition_without_publishing_unchecked_state() {
    let mut sender = Graph::default();
    let (definition, _) = sender.produce(RELATION).unwrap();
    let (proof, root) = sender.produce(&definition_source(&definition)).unwrap();
    let mut receiver = Graph::default();
    assert_eq!(
        receiver
            .ingest(proof.clone(), Instant::now())
            .unwrap()
            .status,
        crate::IngestStatus::Waiting
    );
    assert_eq!(receiver.accepted_count(), 0);
    assert_eq!(
        receiver
            .ingest(definition.clone(), Instant::now())
            .unwrap()
            .admitted
            .len(),
        2
    );
    assert!(receiver.contains(root.id).unwrap());
    assert_eq!(receiver.content_root(), sender.content_root());
    assert!(receiver.author(&definition_source(&definition)).is_ok());
}

#[test]
fn function_definitions_require_the_exact_obligation_proof_and_replay_it() {
    let directory = crate::checkpoint::tests::Directory::new();
    let mut sender = Graph::default();
    let witness = identity_obligation();
    let witness_id = witness.proof_id().unwrap().unwrap();
    assert!(
        sender
            .author(&crate::test_inputs::identity_function())
            .is_err()
    );
    sender.ingest(witness.clone(), Instant::now()).unwrap();
    let (definition, outcome) = sender
        .produce(&crate::test_inputs::identity_function())
        .unwrap();
    assert_eq!(
        definition.obligation_proof.as_deref(),
        Some(crate::hex(witness_id.as_bytes()).as_str())
    );
    let mut receiver = Graph::open(&directory.0).unwrap();
    assert_eq!(
        receiver
            .ingest(definition.clone(), Instant::now())
            .unwrap()
            .status,
        crate::IngestStatus::Waiting
    );
    assert_eq!(receiver.accepted_count(), 0);
    assert_eq!(
        receiver
            .ingest(witness, Instant::now())
            .unwrap()
            .admitted
            .len(),
        2
    );
    let mut forged = definition.clone();
    let (_, unrelated) = receiver.produce(SOURCE).unwrap();
    forged.obligation_proof = Some(crate::hex(
        receiver
            .context
            .artifact_proof_id(unrelated.id)
            .unwrap()
            .unwrap()
            .as_bytes(),
    ));
    let mut other = Graph::default();
    other.produce(SOURCE).unwrap();
    other.ingest(identity_obligation(), Instant::now()).unwrap();
    assert!(other.ingest(forged, Instant::now()).is_err());
    assert_eq!(other.accepted_count(), 2);
    drop(receiver);
    let replayed = Graph::open(&directory.0).unwrap();
    assert_eq!(replayed.object(outcome.id).unwrap(), Some(definition));
}

#[test]
fn selected_proof_and_definition_commit_atomically_as_one_checked_closure() {
    let mut sender = Graph::default();
    let (definition, _) = sender.produce(RELATION).unwrap();
    let (proof, _) = sender.produce(&definition_source(&definition)).unwrap();
    let root = proof.clone().prepare().unwrap().id;
    let candidates = [proof, definition]
        .into_iter()
        .map(|object| {
            let candidate = object.prepare().unwrap();
            (candidate.id, candidate)
        })
        .collect();
    let mut receiver = Graph::default();
    let question =
        naome_checker::question::ResearchQuestion::from_hex(&crate::mocks::create_question(0))
            .unwrap();
    let batch = receiver.prepare_batch(root, candidates, &question).unwrap();
    assert_eq!(receiver.accepted_count(), 0);
    assert_eq!(
        receiver
            .commit_batch(root, batch, Instant::now() + Duration::from_secs(30))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(receiver.content_root(), sender.content_root());
}
