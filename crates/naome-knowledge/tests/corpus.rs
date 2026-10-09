//! External consumer of the public proof-corpus adapter boundary.
//! The artificial encoder proves API compatibility, never semantic quality.
use naome_knowledge::{
    EncoderIdentity, Graph, ProofCorpus, SEMANTIC_REPRESENTATION_VERSION, SemanticEncoder,
    SemanticIndex,
};
use std::time::Instant;
struct FixtureEncoder;
impl SemanticEncoder for FixtureEncoder {
    fn identity(&self) -> EncoderIdentity {
        EncoderIdentity {
            name: "external-api-contract-fixture-only".into(),
            revision: "1".into(),
            representation_version: SEMANTIC_REPRESENTATION_VERSION,
            dimensions: 2,
            maximum_input_bytes: 256 * 1024,
        }
    }
    fn encode(&mut self, _input: &str) -> Result<Vec<f32>, String> {
        Ok(vec![1., 0.])
    }
}
#[test]
fn external_adapter_can_index_query_load_and_restore_actual_checked_content() {
    let mut graph = Graph::default();
    let proof = graph
        .author("goal=all(x,eq(x,x)) proof: p0=refl(x) p1=gen(p0,x) return p1")
        .unwrap();
    graph.ingest(proof.clone(), Instant::now()).unwrap();
    let corpus = ProofCorpus::capture(&graph).unwrap();
    let mut encoder = FixtureEncoder;
    let index = SemanticIndex::build(&corpus, &mut encoder).unwrap();
    let query = "existing proofs involving addition";
    let results = index.search(&corpus, query, 1, &mut encoder).unwrap();
    assert_eq!(results.results.len(), 1);
    assert_eq!(results.results[0].proof_id, proof.proof_id);
    assert!(results.complete_corpus_scan);
    assert!(!results.original_source_available);
    assert_eq!(
        corpus.get_proof(&results.results[0].proof_id).unwrap(),
        Some(proof)
    );
    let restored = ProofCorpus::from_json(&serde_json::to_vec(&corpus).unwrap()).unwrap();
    let restored_index =
        SemanticIndex::from_json(&restored, &serde_json::to_vec(&index).unwrap()).unwrap();
    assert_eq!(
        restored_index
            .search(&restored, query, 1, &mut encoder)
            .unwrap(),
        results
    );
}
