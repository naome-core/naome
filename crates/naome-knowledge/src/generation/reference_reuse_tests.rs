//! Genuine stored-proof reuse, independent of any model or semantic quality.
use super::*;
use crate::corpus::semantic::{
    EncoderIdentity, SEMANTIC_REPRESENTATION_VERSION, SemanticEncoder, SemanticIndex,
};
use crate::{mocks, question::LocalQuestions};
use serde_json::json;
use std::{
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "naome-proof-reference-reuse-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Artificial encoder only exercises the complete corpus/tool adapter contract.
/// One actual prior proof is available; no relevance accuracy is established.
struct ContractEncoder;
impl SemanticEncoder for ContractEncoder {
    fn identity(&self) -> EncoderIdentity {
        EncoderIdentity {
            name: "reference-reuse-contract-fixture-only".into(),
            revision: "1".into(),
            representation_version: SEMANTIC_REPRESENTATION_VERSION,
            dimensions: 2,
            maximum_input_bytes: MAX_REQUEST_BYTES,
        }
    }
    fn encode(&mut self, _input: &str) -> Result<Vec<f32>, String> {
        Ok(vec![1., 0.])
    }
}
const PRIOR: &str = "goal=all([x,y,z],imp(eq(x,y),imp(eq(x,z),eq(y,z)))) proof: p0=subst(x,y,eq(x,z)) p1=gen(p0,z) p2=gen(p1,y) p3=gen(p2,x) return p3";
const TARGET: &str = "goal=all([a,b],imp(eq(a,b),eq(b,a)))";

#[tokio::test]
async fn persisted_prior_proof_is_retrieved_and_cited_in_a_new_admissible_symmetry_proof() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let prior = graph.author(PRIOR).unwrap();
    let prior_id = prior.proof_id.clone();
    let prior_statement = prior.statement_id.clone();
    graph.ingest(prior.clone(), Instant::now()).unwrap();
    drop(graph);
    let mut graph = Graph::open(&directory.0).unwrap();
    assert_eq!(graph.get(&prior_id).unwrap(), Some(&prior));
    let mut questions = LocalQuestions::new(Some(mocks::assess_interest));
    let target = CompiledQuestion::compile(TARGET).unwrap();
    let (snapshot, policy) = questions.context_key(&graph);
    let binding = jobs::Binding::new(snapshot, policy);
    let input = jobs::Input::Solve {
        question: TARGET.into(),
    };
    let request = Request::build(
        &input,
        &binding,
        &graph,
        OwnerContext::Unavailable {
            reason: "controlled reference-reuse fixture has no owner configuration".into(),
        },
    )
    .unwrap();
    let mut encoder = ContractEncoder;
    let index = SemanticIndex::build(&request.checked_context, &mut encoder).unwrap();
    let ranked=request.invoke_tool_with_retrieval("semantic_search",&json!({"request_id":request.identity(),"query":"an existing proof that transports equality between values","top_k":1}),Some((&index,&mut encoder))).unwrap();
    assert_eq!(ranked.results.len(), 1);
    assert_eq!(ranked.results[0].proof_id, prior_id);
    assert_eq!(ranked.results[0].statement_id, prior_statement);
    assert_eq!(
        ranked.semantic_ranking.as_ref().unwrap().encoder.name,
        "reference-reuse-contract-fixture-only"
    );
    let loaded = request
        .invoke_tool(
            "fetch",
            &json!({"request_id":request.identity(),"proof_id":ranked.results[0].proof_id}),
        )
        .unwrap();
    let hit = &loaded.results[0];
    assert_eq!(hit.certificate.as_ref(), Some(&prior));
    assert!(hit.dependencies.is_empty());
    assert_eq!(hit.citation_expression, format!("cite(\"{prior_id}\")"));
    assert_ne!(
        prior_id, prior_statement,
        "ProofId addresses a certificate; StatementId addresses its conclusion"
    );
    let source = format!(
        "let: A=eq(a,b) B=eq(a,a) C=eq(b,a) L=all([y,z],imp(eq(x,y),imp(eq(x,z),eq(y,z)))) M=all(z,imp(eq(a,y),imp(eq(a,z),eq(y,z)))) N=imp(eq(a,b),imp(eq(a,z),eq(b,z))) goal=all([a,b],imp(A,C)) proof: p0={} p1=inst(x,a,L) p2=mp(p0,p1) p3=inst(y,b,M) p4=mp(p2,p3) p5=inst(z,a,N) p6=mp(p4,p5) p7=refl(a) p8=simp(B,A) p9=mp(p7,p8) p10=frege(A,B,C) p11=mp(p6,p10) p12=mp(p9,p11) p13=gen(p12,b) p14=gen(p13,a) return p14",
        hit.citation_expression
    );
    assert!(
        questions.generation_decision(&graph, &target).passed(),
        "new symmetry target must pass real local formal admission"
    );
    let (selected, reply) = questions.begin_exchange(
        &graph,
        target.clone(),
        Instant::now() + std::time::Duration::from_secs(5),
    );
    assert_eq!(selected, target);
    let completion = questions.completed().await;
    questions.finish(&graph, completion);
    let assessment = reply.await.unwrap();
    assert!(assessment.prefilter.passed());
    assert!(assessment.novelty().is_some());
    let (root, batch) = graph.prepare_generated(&source, &[], &target).unwrap();
    assert_ne!(crate::hex(root.as_bytes()), prior_id);
    let root_envelope = graph.author(&source).unwrap();
    assert_eq!(
        root_envelope
            .clone()
            .prepare()
            .unwrap()
            .dependencies
            .iter()
            .map(|p| crate::hex(p.as_bytes()))
            .collect::<Vec<_>>(),
        vec![prior_id.clone()]
    );
    let delta = questions
        .prepare_exchange(&graph, &target, &assessment)
        .unwrap();
    graph.persist_batch(root, &batch).unwrap();
    assert_eq!(graph.apply_batch(batch), vec![root]);
    questions.apply_exchange(delta);
    assert_eq!(graph.ids().len(), 2);
    assert!(
        !questions.generation_decision(&graph, &target).passed(),
        "newly checked answer now prevents re-admission"
    );
    let wrong = CompiledQuestion::compile("goal=all(a,mem(a,a))").unwrap();
    assert!(graph.prepare_generated(&source, &[], &wrong).is_err());
    let missing = source.replace(&prior_id, &"00".repeat(32));
    assert!(graph.author(&missing).is_err());
    let new_binding = {
        let (s, p) = questions.context_key(&graph);
        jobs::Binding::new(s, p)
    };
    let new_request = Request::build(
        &input,
        &new_binding,
        &graph,
        OwnerContext::Unavailable {
            reason: "same controlled fixture".into(),
        },
    )
    .unwrap();
    assert!(
        new_request
            .invoke_tool(
                "fetch",
                &json!({"request_id":request.identity(),"proof_id":prior_id})
            )
            .unwrap_err()
            .contains("stale")
    );
    drop(graph);
    let reopened = Graph::open(&directory.0).unwrap();
    assert_eq!(reopened.ids().len(), 2);
    assert_eq!(
        reopened.get(&root_envelope.proof_id).unwrap(),
        Some(&root_envelope)
    );
}
