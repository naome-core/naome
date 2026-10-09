//! Explicit fake-encoder contract tests. These establish no semantic accuracy
//! for a real local or hosted encoder and perform no model inference.
use super::*;
use crate::Graph;
use std::collections::BTreeMap;
use std::time::Instant;

const REFLEXIVITY: &str = "goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1";
const MEMBERSHIP: &str = "let: a = mem(x,x) b = imp(a,a) goal = all(x,b) proof: p0 = simp(a,a) p1 = simp(a,b) p2 = frege(a,b,a) p3 = mp(p1,p2) p4 = mp(p0,p3) p5 = gen(p4,x) return p5";

struct FakeEncoder {
    identity: EncoderIdentity,
    inputs: Vec<String>,
    proof_vectors: BTreeMap<String, Vec<f32>>,
    query_vector: Vec<f32>,
    fail_on: Option<usize>,
    change_on: Option<usize>,
}
impl FakeEncoder {
    fn new() -> Self {
        Self {
            identity: EncoderIdentity {
                name: "explicit-test-fake-only".into(),
                revision: "test-v1".into(),
                representation_version: SEMANTIC_REPRESENTATION_VERSION,
                dimensions: 2,
                maximum_input_bytes: MAX_REQUEST_BYTES,
            },
            inputs: Vec::new(),
            proof_vectors: BTreeMap::new(),
            query_vector: vec![1.0, 0.0],
            fail_on: None,
            change_on: None,
        }
    }
}
impl SemanticEncoder for FakeEncoder {
    fn identity(&self) -> EncoderIdentity {
        self.identity.clone()
    }
    fn encode(&mut self, input: &str) -> Result<Vec<f32>, String> {
        let call = self.inputs.len();
        self.inputs.push(input.into());
        if self.change_on == Some(call) {
            self.identity.revision = "changed-during-encode".into();
        }
        if self.fail_on == Some(call) {
            return Err("explicit injected fake failure".into());
        }
        if input.starts_with("naome:semantic-proof-content:v1\n") {
            for (proof, vector) in &self.proof_vectors {
                if input
                    .lines()
                    .any(|line| line == format!("proof_id: {proof}"))
                {
                    return Ok(vector.clone());
                }
            }
        }
        Ok(self.query_vector.clone())
    }
}

fn populate(graph: &mut Graph, source: &str) -> String {
    let envelope = graph.author(source).unwrap();
    let id = envelope.proof_id.clone();
    assert_eq!(
        graph.ingest(envelope, Instant::now()).unwrap().status,
        "accepted"
    );
    id
}
fn fixture() -> (Graph, CheckedContext, String, String) {
    let mut graph = Graph::default();
    let equality = populate(&mut graph, REFLEXIVITY);
    let membership = populate(&mut graph, MEMBERSHIP);
    let corpus = CheckedContext::capture(&graph).unwrap();
    (graph, corpus, equality, membership)
}

#[test]
fn encoder_receives_full_actual_proof_content_and_exact_text_query() {
    let (mut graph, _, equality, _) = fixture();
    let source = format!("goal = all(x,eq(x,x)) proof: p = cite(\"{equality}\") return p");
    let citing = populate(&mut graph, &source);
    let corpus = CheckedContext::capture(&graph).unwrap();
    let mut encoder = FakeEncoder::new();
    let index = SemanticIndex::build(&corpus, &mut encoder).unwrap();
    assert_eq!(encoder.inputs.len(), corpus.references.len());
    for reference in &corpus.references {
        let input = encoder
            .inputs
            .iter()
            .find(|input| {
                input
                    .lines()
                    .any(|line| line == format!("proof_id: {}", reference.proof.proof_id))
            })
            .unwrap();
        assert!(input.contains(&reference.native_conclusion));
        assert!(input.contains(&reference.proof.statement_id));
        assert!(input.contains(&reference.proof.compatibility));
        assert!(input.contains("original .nao source is not stored"));
        assert!(input.contains("normalized_certificate:\nProofCertificate"));
    }
    assert!(
        encoder
            .inputs
            .iter()
            .any(|input| input.contains("EqualityReflexivity"))
    );
    assert!(
        encoder
            .inputs
            .iter()
            .any(|input| input.contains("ModusPonens"))
    );
    let cited_content = encoder
        .inputs
        .iter()
        .find(|input| {
            input
                .lines()
                .any(|line| line == format!("proof_id: {citing}"))
        })
        .unwrap();
    assert!(cited_content.contains("ProofReference"));
    assert!(cited_content.contains(&format!("direct_dependencies: [\"{equality}\"]")));
    let query = "Find existing proofs involving addition, even if this is a new phrasing.";
    let page = index.search(&corpus, query, 2, &mut encoder).unwrap();
    assert_eq!(encoder.inputs.last().unwrap(), query);
    assert!(page.complete_corpus_scan);
    assert!(!page.original_source_available);
    assert_eq!(page.corpus_proofs, 3);
    assert_eq!(page.results.len(), 2);
}

#[test]
fn actual_top_k_uses_cosine_rank_not_magnitude_or_proof_order() {
    let (_, corpus, equality, membership) = fixture();
    let mut encoder = FakeEncoder::new();
    encoder
        .proof_vectors
        .insert(equality.clone(), vec![0.0, 500.0]);
    encoder
        .proof_vectors
        .insert(membership.clone(), vec![0.25, 0.0]);
    let index = SemanticIndex::build(&corpus, &mut encoder).unwrap();
    let page = index
        .search(&corpus, "unrestricted textual question", 1, &mut encoder)
        .unwrap();
    assert_eq!(page.results.len(), 1);
    assert_eq!(page.results[0].proof_id, membership);
    assert_eq!(page.results[0].score, 1.0);
    assert_eq!(page.corpus_proofs, 2);
    encoder.query_vector = vec![0.0, 42.0];
    let changed_query = index
        .search(&corpus, "different query", 2, &mut encoder)
        .unwrap();
    assert_eq!(changed_query.results[0].proof_id, equality);
    assert_eq!(changed_query.results[1].score, 0.0);
    assert_ne!(page.query_digest, changed_query.query_digest);
}

#[test]
fn deterministic_ties_negative_scores_and_empty_corpus_are_explicit() {
    let (_, corpus, _, _) = fixture();
    let mut encoder = FakeEncoder::new();
    let index = SemanticIndex::build(&corpus, &mut encoder).unwrap();
    encoder.query_vector = vec![-1.0, 0.0];
    let page = index.search(&corpus, "text", 16, &mut encoder).unwrap();
    assert_eq!(
        page.results
            .iter()
            .map(|hit| hit.proof_id.clone())
            .collect::<Vec<_>>(),
        corpus
            .references
            .iter()
            .map(|reference| reference.proof.proof_id.clone())
            .collect::<Vec<_>>()
    );
    assert!(page.results.iter().all(|hit| hit.score == -1.0));
    let empty = CheckedContext::capture(&Graph::default()).unwrap();
    let empty_index = SemanticIndex::build(&empty, &mut encoder).unwrap();
    let page = empty_index
        .search(&empty, "addition", 1, &mut encoder)
        .unwrap();
    assert!(page.results.is_empty());
    assert_eq!(page.corpus_proofs, 0);
    assert!(page.complete_corpus_scan);
}

#[test]
fn stale_corpus_encoder_and_changed_encoder_during_call_are_rejected() {
    let (mut graph, corpus, equality, _) = fixture();
    let mut encoder = FakeEncoder::new();
    let index = SemanticIndex::build(&corpus, &mut encoder).unwrap();
    let source = format!("goal = all(x,eq(x,x)) proof: p = cite(\"{equality}\") return p");
    populate(&mut graph, &source);
    let changed = CheckedContext::capture(&graph).unwrap();
    assert!(
        index
            .search(&changed, "text", 1, &mut encoder)
            .unwrap_err()
            .contains("corpus binding")
    );
    assert!(index.search(&corpus, "text", 1, &mut encoder).is_ok());
    encoder.identity.revision = "a different encoder".into();
    assert!(
        index
            .search(&corpus, "text", 1, &mut encoder)
            .unwrap_err()
            .contains("encoder identity")
    );
    let mut changing = FakeEncoder::new();
    changing.change_on = Some(0);
    assert!(
        SemanticIndex::build(&corpus, &mut changing)
            .unwrap_err()
            .contains("identity changed")
    );
    let mut changing = FakeEncoder::new();
    changing.change_on = Some(0);
    assert!(
        index
            .search(&corpus, "text", 1, &mut changing)
            .unwrap_err()
            .contains("identity changed")
    );
}

#[test]
fn every_missing_malformed_or_failed_vector_aborts_the_complete_index() {
    let (_, corpus, _, _) = fixture();
    for invalid in [
        vec![],
        vec![1.0],
        vec![1.0, 2.0, 3.0],
        vec![f32::NAN, 1.0],
        vec![f32::INFINITY, 1.0],
        vec![0.0, 0.0],
    ] {
        let mut encoder = FakeEncoder::new();
        encoder.query_vector = invalid;
        assert!(SemanticIndex::build(&corpus, &mut encoder).is_err());
    }
    let mut encoder = FakeEncoder::new();
    encoder.fail_on = Some(1);
    assert!(
        SemanticIndex::build(&corpus, &mut encoder)
            .unwrap_err()
            .contains("explicit injected fake failure")
    );
    assert_eq!(encoder.inputs.len(), 2);
    let mut encoder = FakeEncoder::new();
    encoder.identity.maximum_input_bytes = 1;
    assert!(
        SemanticIndex::build(&corpus, &mut encoder)
            .unwrap_err()
            .contains("complete content")
    );
    assert!(encoder.inputs.is_empty());
}

#[test]
fn queries_and_encoder_capacity_are_bounded_without_vocabulary_restrictions() {
    let (_, corpus, _, _) = fixture();
    let mut encoder = FakeEncoder::new();
    let index = SemanticIndex::build(&corpus, &mut encoder).unwrap();
    for query in ["", "  ", &"a".repeat(MAX_QUERY_BYTES + 1)] {
        assert!(index.search(&corpus, query, 1, &mut encoder).is_err());
    }
    for top_k in [0, MAX_TOP_K + 1] {
        assert!(index.search(&corpus, "text", top_k, &mut encoder).is_err());
    }
    let text = "Welche bestehenden Beweise behandeln Addition? 🔎";
    assert!(index.search(&corpus, text, 1, &mut encoder).is_ok());
    assert_eq!(encoder.inputs.last().unwrap(), text);
    for dimensions in [0, MAX_DIMENSIONS + 1] {
        let mut encoder = FakeEncoder::new();
        encoder.identity.dimensions = dimensions;
        assert!(SemanticIndex::build(&corpus, &mut encoder).is_err());
    }
    assert!(vector_budget(crate::MAX_OBJECTS, MAX_DIMENSIONS).is_err());
    assert!(
        vector_budget(
            MAX_VECTOR_ELEMENTS / usize::from(MAX_DIMENSIONS),
            MAX_DIMENSIONS
        )
        .is_ok()
    );
}

#[test]
fn query_output_failures_do_not_mutate_a_ready_index() {
    let (_, corpus, _, _) = fixture();
    let mut encoder = FakeEncoder::new();
    let index = SemanticIndex::build(&corpus, &mut encoder).unwrap();
    let before = serde_json::to_vec(&index).unwrap();
    encoder.query_vector = vec![f32::NAN, 1.0];
    assert!(index.search(&corpus, "text", 1, &mut encoder).is_err());
    encoder.query_vector = vec![1.0, 0.0];
    encoder.fail_on = Some(encoder.inputs.len());
    assert!(index.search(&corpus, "text", 1, &mut encoder).is_err());
    assert_eq!(serde_json::to_vec(&index).unwrap(), before);
    encoder.fail_on = None;
    assert!(index.search(&corpus, "text", 1, &mut encoder).is_ok());
}

#[test]
fn exported_cache_rechecks_all_source_and_vector_bindings_before_reuse() {
    let (_, corpus, _, _) = fixture();
    let mut encoder = FakeEncoder::new();
    let index = SemanticIndex::build(&corpus, &mut encoder).unwrap();
    let bytes = serde_json::to_vec(&index).unwrap();
    let restored = SemanticIndex::from_json(&corpus, &bytes).unwrap();
    assert_eq!(
        restored.search(&corpus, "text", 2, &mut encoder).unwrap(),
        index.search(&corpus, "text", 2, &mut encoder).unwrap()
    );
    assert_eq!(restored.identity(), index.identity());
    assert_eq!(restored.encoder_identity(), &encoder.identity);
    assert_eq!(restored.proof_count(), corpus.references.len());
    let mut changed = index.clone();
    changed.proofs.remove(0);
    assert!(changed.search(&corpus, "text", 1, &mut encoder).is_err());
    let mut changed = index.clone();
    changed.proofs[0].content_digest = "00".repeat(32);
    assert!(changed.search(&corpus, "text", 1, &mut encoder).is_err());
    let mut changed = index.clone();
    changed.proofs[0].vector = vec![0.0, 1.0];
    assert!(
        changed
            .search(&corpus, "text", 1, &mut encoder)
            .unwrap_err()
            .contains("checksum")
    );
    let mut changed = serde_json::to_value(index).unwrap();
    changed["invented"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SemanticIndex>(changed).is_err());
}

#[test]
fn cache_decoding_rejects_oversized_vector_arrays_and_malformed_identities() {
    let (_, corpus, _, _) = fixture();
    let mut encoder = FakeEncoder::new();
    let index = SemanticIndex::build(&corpus, &mut encoder).unwrap();
    let mut changed = serde_json::to_value(&index).unwrap();
    changed["proofs"][0]["vector"] =
        serde_json::json!(vec![1.0f32; usize::from(MAX_DIMENSIONS) + 1]);
    assert!(SemanticIndex::from_json(&corpus, &serde_json::to_vec(&changed).unwrap()).is_err());
    let mut changed = serde_json::to_value(index).unwrap();
    changed["proofs"][0]["proof_id"] = serde_json::json!("invented proof");
    assert!(SemanticIndex::from_json(&corpus, &serde_json::to_vec(&changed).unwrap()).is_err());
}
