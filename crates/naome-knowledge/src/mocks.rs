//! Three replaceable deterministic producers/selectors. Checking is never mocked.
use naome_authoring::CompiledQuestion;

const CATALOG: [(&str, &str); 3] = [
    (
        "goal = all(x,eq(x,x))",
        "goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1",
    ),
    (
        "goal = all(x,imp(mem(x,x),mem(x,x)))",
        "let: a = mem(x,x) b = imp(a,a) goal = all(x,b) proof: p0 = simp(a,a) p1 = simp(a,b) p2 = frege(a,b,a) p3 = mp(p1,p2) p4 = mp(p0,p3) p5 = gen(p4,x) return p5",
    ),
    (
        "goal = all(x,all(y,all(set,imp(eq(x,y),imp(mem(x,set),mem(y,set))))))",
        "goal = all(x,all(y,all(set,imp(eq(x,y),imp(mem(x,set),mem(y,set)))))) proof: p0 = subst(x,y,mem(x,set)) p1 = gen(p0,set) p2 = gen(p1,y) p3 = gen(p2,x) return p3",
    ),
];

/// Repeated calls cycle through a tiny fixed catalog; the cursor is runtime-owned.
pub fn create_question(cursor: u64) -> String {
    CATALOG[cursor as usize % CATALOG.len()].0.to_owned()
}

/// Unsupported questions have no candidate. This does not establish proof validity.
pub fn create_proof(question: &CompiledQuestion) -> Option<String> {
    CATALOG.iter().find_map(|(source, proof)| {
        let candidate = CompiledQuestion::compile(source).expect("fixed mock question source");
        (candidate == *question).then(|| (*proof).to_owned())
    })
}

/// The ordinary question provider consumes the completed future-model request.
/// Native context informs the envelope; the fixed catalog remains deterministic.
#[cfg(test)]
pub(crate) fn create_question_request(
    request: &crate::generation::Request,
) -> Result<String, String> {
    create_question_request_with_tools(request, |_, _| Ok(()))
}

/// The ordinary question mock invokes the advertised natural-query tool before
/// returning its fixed catalog entry. Missing semantic evidence stays explicit.
pub(crate) fn create_question_request_with_tools(
    request: &crate::generation::Request,
    mut observe: impl FnMut(&str, &crate::generation::ToolResult) -> Result<(), String>,
) -> Result<String, String> {
    let cursor = request.cursor()?;
    let semantic = request.invoke_tool(
        "semantic_search",
        &serde_json::json!({
            "request_id":request.identity(), "query":"proofs involving addition", "top_k":8,
        }),
    )?;
    observe("semantic_search", &semantic)?;
    Ok(create_question(cursor))
}

/// Mock inference receives the exact role-specific request before selecting its
/// deterministic candidate. Checking and target admission remain downstream.
#[cfg(test)]
pub(crate) fn create_proof_request(
    request: &crate::generation::Request,
) -> Result<Option<String>, String> {
    create_proof_request_with_tools(request, |_, _| Ok(()))
}

/// Exercise invocable tools in the ordinary provider process while keeping its
/// catalog output deterministic. Retrieval does not synthesize a mock proof.
pub(crate) fn create_proof_request_with_tools(
    request: &crate::generation::Request,
    mut observe: impl FnMut(&str, &crate::generation::ToolResult) -> Result<(), String>,
) -> Result<Option<String>, String> {
    let question = request.question()?;
    let request_id = request.identity();
    let semantic = request.invoke_tool(
        "semantic_search",
        &serde_json::json!({
            "request_id":request_id, "query":"proofs involving addition", "top_k":8,
        }),
    )?;
    observe("semantic_search", &semantic)?;
    let search = request.invoke_tool(
        "native_search",
        &serde_json::json!({
            "request_id":request_id, "question":question.source(), "after":null, "limit":16,
        }),
    )?;
    observe("native_search", &search)?;
    if let Some(proof_id) = request.checked_proof_ids().next() {
        let lookup = request.invoke_tool("lookup", &serde_json::json!({
            "request_id":request_id, "key":"proof_id", "value":proof_id, "after":null, "limit":16,
        }))?;
        observe("lookup", &lookup)?;
        let fetched = request.invoke_tool(
            "fetch",
            &serde_json::json!({
                "request_id":request_id, "proof_id":proof_id,
            }),
        )?;
        observe("fetch", &fetched)?;
        if lookup.results.len() != 1
            || fetched.results.len() != 1
            || fetched.results[0].proof_id != proof_id
            || fetched.results[0].certificate.is_none()
        {
            return Err("mock checked-context retrieval differs".into());
        }
    }
    Ok(create_proof(&question))
}

/// Placeholder interest selection, called only after the real formal prefilter.
pub fn assess_interest(_: CompiledQuestion) -> std::future::Ready<Result<bool, String>> {
    std::future::ready(Ok(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Graph, question};
    use std::time::{Duration, Instant};

    #[test]
    fn both_mock_roles_invoke_natural_query_tools_without_fabricated_rankings() {
        for populated in [false, true] {
            let mut graph = Graph::default();
            if populated {
                let question = CompiledQuestion::compile(&create_question(1)).unwrap();
                let proof = graph.author(&create_proof(&question).unwrap()).unwrap();
                graph.ingest(proof, Instant::now()).unwrap();
            }
            let binding = crate::jobs::Binding::new(
                [0; 32],
                naome_checker::question::PrefilterPolicy::default().identity(),
            );
            let selected = CompiledQuestion::compile(&create_question(0)).unwrap();
            for input in [
                crate::jobs::Input::Find { cursor: 0 },
                crate::jobs::Input::Solve {
                    question: selected.source().into(),
                },
            ] {
                let request = crate::generation::Request::build(
                    &input,
                    &binding,
                    &graph,
                    crate::generation::OwnerContext::Unavailable {
                        reason: "mock retrieval fixture has no owner control".into(),
                    },
                )
                .unwrap();
                let mut receipts = Vec::new();
                let observe = |operation: &str, result: &crate::generation::ToolResult| {
                    receipts.push((
                        operation.to_owned(),
                        result.status.clone(),
                        result.results.len(),
                    ));
                    Ok(())
                };
                match input {
                    crate::jobs::Input::Find { cursor } => {
                        assert_eq!(
                            create_question_request_with_tools(&request, observe).unwrap(),
                            create_question(cursor)
                        );
                    }
                    crate::jobs::Input::Solve { .. } => {
                        assert_eq!(
                            create_proof_request_with_tools(&request, observe).unwrap(),
                            create_proof(&selected)
                        );
                    }
                    _ => unreachable!(),
                }
                let semantic = receipts
                    .iter()
                    .filter(|(operation, _, _)| operation == "semantic_search")
                    .collect::<Vec<_>>();
                assert_eq!(semantic.len(), 1);
                assert_eq!(semantic[0].2, 0);
                assert_eq!(
                    semantic[0].1,
                    if populated {
                        crate::generation::ToolStatus::BackendUnavailable
                    } else {
                        crate::generation::ToolStatus::NoResult
                    }
                );
            }
        }
    }

    #[tokio::test]
    async fn every_catalog_pair_is_formally_admissible_and_really_checked() {
        for cursor in 0..CATALOG.len() {
            let question = CompiledQuestion::compile(&create_question(cursor as u64)).unwrap();
            let mut graph = Graph::default();
            let mut questions = question::LocalQuestions::new(Some(assess_interest));
            let (_, receiver) = questions.begin_exchange(
                &graph,
                question.clone(),
                Instant::now() + Duration::from_secs(5),
            );
            let interest = tokio::time::timeout(Duration::from_secs(5), questions.completed())
                .await
                .unwrap();
            questions.finish(&graph, interest);
            let assessment = receiver.await.unwrap();
            assert!(
                assessment.prefilter.passed(),
                "{:?}",
                assessment.prefilter.reason
            );
            assert!(assessment.novelty().is_some());
            let candidate = graph
                .author(&create_proof(&question).unwrap())
                .unwrap()
                .prepare()
                .unwrap();
            let root = candidate.id;
            let batch = graph
                .prepare_batch(root, [(root, candidate)].into(), &question)
                .unwrap();
            assert_eq!(graph.apply_batch(batch), vec![root]);
            assert_eq!(graph.ids().len(), 1);
        }
    }

    #[tokio::test]
    async fn catalog_remains_admissible_in_every_cyclic_order_as_knowledge_grows() {
        for offset in 0..CATALOG.len() {
            let mut graph = Graph::default();
            let mut questions = question::LocalQuestions::new(Some(assess_interest));
            for cursor in offset..offset + CATALOG.len() {
                let question = CompiledQuestion::compile(&create_question(cursor as u64)).unwrap();
                let (_, receiver) = questions.begin_exchange(
                    &graph,
                    question.clone(),
                    Instant::now() + Duration::from_secs(5),
                );
                if !questions.available() {
                    let interest =
                        tokio::time::timeout(Duration::from_secs(5), questions.completed())
                            .await
                            .unwrap();
                    questions.finish(&graph, interest);
                }
                let assessment = receiver.await.unwrap();
                assert!(
                    assessment.prefilter.passed(),
                    "offset {offset}, cursor {cursor}: {:?}",
                    assessment.prefilter.reason
                );
                let candidate = graph
                    .author(&create_proof(&question).unwrap())
                    .unwrap()
                    .prepare()
                    .unwrap();
                let root = candidate.id;
                let batch = graph
                    .prepare_batch(root, [(root, candidate)].into(), &question)
                    .unwrap();
                let delta = questions
                    .prepare_exchange(&graph, &question, &assessment)
                    .unwrap();
                graph.apply_batch(batch);
                questions.apply_exchange(delta);
            }
            assert_eq!(graph.ids().len(), CATALOG.len());
        }
    }
}
