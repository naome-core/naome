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
    document_vectors: BTreeMap<String, Vec<f32>>,
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
            document_vectors: BTreeMap::new(),
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
        if input.starts_with("naome:semantic-proof-content:v6\n") {
            for (line, vector) in &self.document_vectors {
                if input.lines().any(|candidate| candidate == line) {
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
fn encoder_receives_complete_math_once_with_canonical_records_bound_separately() {
    let (mut graph, _, equality, _) = fixture();
    let source = format!("goal = all(x,eq(x,x)) proof: p = cite(\"{equality}\") return p");
    let citing = populate(&mut graph, &source);
    let corpus = CheckedContext::capture(&graph).unwrap();
    let mut encoder = FakeEncoder::new();
    let index = SemanticIndex::build(&corpus, &mut encoder).unwrap();
    assert_eq!(encoder.inputs.len(), corpus.references.len());
    for (input, reference) in encoder.inputs.iter().zip(&corpus.references) {
        assert!(input.starts_with("naome:semantic-proof-content:v6\n"));
        assert_eq!(input.matches("Checked primitive conclusion:").count(), 1);
        assert_eq!(
            input
                .matches("Actual normalized certificate constructors and operands:")
                .count(),
            1
        );
        assert!(!input.contains("normalized_certificate:"));
        assert!(!input.contains("native_checked_conclusion:"));
        assert!(!input.contains(&reference.proof.proof_id));
        assert!(!input.contains(&reference.proof.statement_id));
        assert!(!input.contains(&reference.proof.compatibility));
        let indexed = index
            .proofs
            .iter()
            .find(|row| row.proof_id == reference.proof.proof_id)
            .unwrap();
        assert_eq!(indexed.statement_id, reference.proof.statement_id);
        assert_eq!(
            corpus.get_proof(&indexed.proof_id).unwrap().unwrap(),
            reference.proof
        );
        assert_eq!(
            indexed.content_digest,
            // The unchanged cache codec hashes the JSON-framed String,
            // including escaped line breaks, rather than raw UTF-8 bytes.
            crate::hex(&Sha256::digest(serde_json::to_vec(input).unwrap()))
        );
    }
    assert!(
        encoder
            .inputs
            .iter()
            .any(|input| input.contains("Equality reflexivity instance"))
    );
    assert!(
        encoder
            .inputs
            .iter()
            .any(|input| input.contains("Modus ponens using earlier normalized premise"))
    );
    let position = corpus
        .references
        .iter()
        .position(|reference| reference.proof.proof_id == citing)
        .unwrap();
    let cited_content = &encoder.inputs[position];
    assert!(cited_content.contains(&format!(
        "Citation of the concrete proof cite(\"{equality}\")"
    )));
    assert_eq!(corpus.references[position].dependencies, vec![equality]);
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
    encoder.document_vectors.insert(
        "Checked primitive conclusion: (for every set b0, (b0 equals b0)).".into(),
        vec![0.0, 500.0],
    );
    encoder
        .document_vectors
        .insert("Checked primitive conclusion: (for every set b0, (if (b0 is an element of b0), then (b0 is an element of b0))).".into(), vec![0.25, 0.0]);
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
    assert!(vector_budget(crate::MAX_OBJECTS, MAX_DIMENSIONS).is_ok());
    assert!(vector_budget(crate::MAX_OBJECTS + 1, MAX_DIMENSIONS).is_err());
    assert!(vector_budget(crate::MAX_OBJECTS, MAX_DIMENSIONS).is_ok());
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
    changed.proofs[0].chunks[0].vector = vec![0.0, 1.0];
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
    changed["proofs"][0]["chunks"][0]["vector"] =
        serde_json::json!(vec![1.0f32; usize::from(MAX_DIMENSIONS) + 1]);
    assert!(SemanticIndex::from_json(&corpus, &serde_json::to_vec(&changed).unwrap()).is_err());
    let mut changed = serde_json::to_value(index).unwrap();
    changed["proofs"][0]["proof_id"] = serde_json::json!("invented proof");
    assert!(SemanticIndex::from_json(&corpus, &serde_json::to_vec(&changed).unwrap()).is_err());
}

#[test]
fn complete_chunk_ranking_finds_later_content_and_rejects_incomplete_chunks() {
    struct MultiEncoder {
        base: FakeEncoder,
        chunks: Vec<Vec<f32>>,
    }
    impl SemanticEncoder for MultiEncoder {
        fn identity(&self) -> EncoderIdentity {
            self.base.identity()
        }
        fn encode(&mut self, input: &str) -> Result<Vec<f32>, String> {
            self.base.encode(input)
        }
        fn encode_document(&mut self, _: &str) -> Result<Vec<Vec<f32>>, String> {
            Ok(self.chunks.clone())
        }
    }
    let (_, corpus, _, _) = fixture();
    let mut encoder = MultiEncoder {
        base: FakeEncoder::new(),
        chunks: vec![vec![0.0, 3.0], vec![5.0, 0.0]],
    };
    let index = SemanticIndex::build(&corpus, &mut encoder).unwrap();
    let page = index
        .search(&corpus, "matching later chunk", 2, &mut encoder)
        .unwrap();
    assert!(page.complete_corpus_scan);
    assert!(
        page.results
            .iter()
            .all(|hit| hit.matched_chunk == 1 && hit.document_chunks == 2 && hit.score == 1.0)
    );
    assert!(
        page.results
            .windows(2)
            .all(|pair| pair[0].proof_id < pair[1].proof_id)
    );
    encoder.base.query_vector = vec![0.0, 1.0];
    let page = index
        .search(&corpus, "matching first chunk", 2, &mut encoder)
        .unwrap();
    assert!(page.results.iter().all(|hit| hit.matched_chunk == 0));
    let restored = SemanticIndex::from_json(&corpus, &serde_json::to_vec(&index).unwrap()).unwrap();
    assert_eq!(
        restored
            .search(&corpus, "matching first chunk", 2, &mut encoder)
            .unwrap(),
        page
    );
    for chunks in [
        vec![],
        vec![vec![]],
        vec![vec![1.0, 0.0]; MAX_DOCUMENT_CHUNKS + 1],
    ] {
        encoder.chunks = chunks;
        assert!(SemanticIndex::build(&corpus, &mut encoder).is_err());
    }
    let mut corrupted = index;
    corrupted.proofs[0].chunks[1].vector = vec![100.0, 0.0];
    corrupted.index_identity = corrupted.checksum();
    assert!(
        SemanticIndex::from_json(&corpus, &serde_json::to_vec(&corrupted).unwrap())
            .unwrap_err()
            .contains("not normalized")
    );
}

fn source_index_fixture() -> (super::super::snapshot::Frozen, SemanticIndex) {
    let (graph, _, _, _) = fixture();
    let source = super::super::snapshot::Frozen::capture(&graph, None, &"00".repeat(32)).unwrap();
    let identity = FakeEncoder::new().identity();
    let rows = source
        .corpus()
        .references
        .iter()
        .map(|reference| {
            let content = source.semantic_content(&reference.proof.proof_id).unwrap();
            let split = content.len() / 2;
            // Artificial spans/vectors test complete persisted coverage only.
            // They are not an observation of any real tokenizer or encoder.
            SourceVectorRow::new(
                identity.clone(),
                reference,
                &content,
                vec![
                    super::super::local::EmbeddedChunk {
                        token_start: 0,
                        token_end: 510,
                        total_tokens: 511,
                        byte_start: 0,
                        byte_end: split,
                        vector: vec![0., 1.],
                    },
                    super::super::local::EmbeddedChunk {
                        token_start: 510,
                        token_end: 511,
                        total_tokens: 511,
                        byte_start: split,
                        byte_end: content.len(),
                        vector: vec![1., 0.],
                    },
                ],
            )
            .unwrap()
        })
        .collect();
    let index = SemanticIndex::build_source(&source, identity, rows).unwrap();
    (source, index)
}

#[test]
fn source_index_import_rejects_missing_tail_even_with_recomputed_checksum() {
    let (source, index) = source_index_fixture();
    SemanticIndex::from_json_source(&source, &serde_json::to_vec(&index).unwrap()).unwrap();
    for missing in [0, 1] {
        let mut changed = index.clone();
        changed.proofs[0].chunks.remove(missing);
        changed.index_identity = changed.checksum();
        assert!(
            SemanticIndex::from_json_source(&source, &serde_json::to_vec(&changed).unwrap())
                .is_err()
        );
    }
    let mut changed = index;
    changed.proofs[0].chunks[0].coverage = None;
    changed.index_identity = changed.checksum();
    assert!(
        SemanticIndex::from_json_source(&source, &serde_json::to_vec(&changed).unwrap()).is_err()
    );
}

#[test]
fn saved_ranking_rejects_empty_duplicates_changed_bindings_and_invalid_chunks() {
    let (source, index) = source_index_fixture();
    let query = "actual saved ranked window contract";
    let page = index.search_vector(&source, query, 2, &[1., 0.]).unwrap();
    let saved: SemanticPage = serde_json::from_slice(&serde_json::to_vec(&page).unwrap()).unwrap();
    index.validate_ranking(&source, query, 2, &saved).unwrap();
    for change in 0..8 {
        let mut bad = saved.clone();
        match change {
            0 => bad.results.clear(),
            1 => bad.results[1] = bad.results[0].clone(),
            2 => bad.results.reverse(),
            3 => bad.results[0].score = f64::NAN,
            4 => bad.results[0].statement_id = "00".repeat(32),
            5 => bad.results[0].content_digest = "00".repeat(32),
            6 => bad.results[0].document_chunks = 3,
            _ => bad.results[0].matched_chunk = 2,
        }
        assert!(
            index.validate_ranking(&source, query, 2, &bad).is_err(),
            "mutation {change}"
        );
    }
    assert!(
        index
            .validate_ranking(&source, "changed query", 2, &saved)
            .is_err()
    );
    assert!(index.validate_ranking(&source, query, 1, &saved).is_err());
}
