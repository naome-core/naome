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
#[cfg(test)]
pub(crate) fn create_question_request_with_tools(
    request: &crate::generation::Request,
    mut observe: impl FnMut(&str, &crate::generation::ToolResult) -> Result<(), String>,
) -> Result<String, String> {
    create_question_request_using_tools(request, |name, arguments| {
        let result = request.invoke_tool(name, arguments)?;
        observe(name, &result)?;
        Ok(result)
    })
}

pub(crate) fn create_question_request_using_tools(
    request: &crate::generation::Request,
    mut invoke: impl FnMut(&str, &serde_json::Value) -> Result<crate::generation::ToolResult, String>,
) -> Result<String, String> {
    let cursor = request.cursor()?;
    let mut invoke = |name: &str, arguments: &serde_json::Value| {
        let reply = invoke(name, arguments)?;
        request.validate_tool_reply(name, arguments, &reply)?;
        Ok(reply)
    };
    let _semantic = semantic_window(request, &mut invoke)?;
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
#[cfg(test)]
pub(crate) fn create_proof_request_with_tools(
    request: &crate::generation::Request,
    mut observe: impl FnMut(&str, &crate::generation::ToolResult) -> Result<(), String>,
) -> Result<Option<String>, String> {
    create_proof_request_using_tools(request, |name, arguments| {
        let result = request.invoke_tool(name, arguments)?;
        observe(name, &result)?;
        Ok(result)
    })
}

pub(crate) fn create_proof_request_using_tools(
    request: &crate::generation::Request,
    mut invoke: impl FnMut(&str, &serde_json::Value) -> Result<crate::generation::ToolResult, String>,
) -> Result<Option<String>, String> {
    let question = request.question()?;
    let mut invoke = |name: &str, arguments: &serde_json::Value| {
        let reply = invoke(name, arguments)?;
        request.validate_tool_reply(name, arguments, &reply)?;
        Ok(reply)
    };
    let request_id = request.identity();
    let semantic = semantic_window(request, &mut invoke)?;

    let _search = invoke(
        "native_search",
        &serde_json::json!({
            "request_id":request_id, "question":question.source(), "after":null, "limit":16,
        }),
    )?;

    let browse = invoke(
        "browse",
        &serde_json::json!({"request_id":request_id,"after":null,"limit":1}),
    )?;
    // A configured semantic result chooses the fetched hint. Exact browsing
    // remains explicit when the optional encoder is absent or incomplete.
    if let Some(proof_id) = semantic
        .first()
        .or_else(|| browse.results.first().map(|hit| &hit.proof_id))
    {
        let lookup = invoke(
            "lookup",
            &serde_json::json!({
                "request_id":request_id, "key":"proof_id", "value":proof_id, "after":null, "limit":16,
            }),
        )?;

        let fetched = invoke(
            "fetch",
            &serde_json::json!({
                "request_id":request_id, "proof_id":proof_id,
            }),
        )?;

        if lookup.results.len() != 1
            || fetched.results.len() != 1
            || fetched.results[0].proof_id != *proof_id
            || fetched.results[0].certificate.is_none()
        {
            return Err("mock checked-context retrieval differs".into());
        }
        if !semantic.is_empty() || fetched.results[0].full_record.is_none() {
            consume_record(request, proof_id, &fetched, &mut invoke)?;
        }
    }
    Ok(create_proof(&question))
}

fn semantic_window(
    request: &crate::generation::Request,
    invoke: &mut impl FnMut(&str, &serde_json::Value) -> Result<crate::generation::ToolResult, String>,
) -> Result<Vec<String>, String> {
    let mut after = serde_json::Value::Null;
    let mut ids = Vec::new();
    let mut query_id = None;
    let mut window: Option<crate::SemanticPage> = None;
    for _ in 0..8 {
        let page = invoke(
            "semantic_search",
            &serde_json::json!({
                "request_id":request.identity(), "query":"proofs involving addition", "top_k":8,
                "after":after, "page_size":1, "max_bytes":4096,
            }),
        )?;
        if page.request_id != request.identity() || page.results.len() > 1 {
            return Err("mock semantic page identity or count differs".into());
        }
        if let Some(expected) = &query_id {
            if *expected != page.query_id {
                return Err("mock semantic continuation query changed".into());
            }
        } else {
            query_id = Some(page.query_id.clone());
        }
        if page.status != crate::generation::ToolStatus::Ok {
            if !ids.is_empty() || !page.results.is_empty() || page.next_after.is_some() {
                return Err("mock semantic continuation is incomplete".into());
            }
            if let Some(window) = &page.semantic_ranking {
                request.validate_received_window(
                    "proofs involving addition",
                    8,
                    &page.query_id,
                    window,
                )?;
            }
            return Ok(ids);
        }
        let hit = page
            .results
            .first()
            .ok_or("mock semantic page made no progress")?;
        if ids.contains(&hit.proof_id) {
            return Err("mock semantic continuation repeated a proof".into());
        }
        let ranking = page
            .semantic_ranking
            .as_ref()
            .ok_or("mock semantic ranking absent")?;
        let mut header = ranking.clone();
        header.results.clear();
        if let Some(window) = &window {
            let mut expected = window.clone();
            expected.results.clear();
            if header != expected {
                return Err("mock semantic source, encoder or index changed between pages".into());
            }
        } else {
            window = Some(header);
        }
        if ranking.results.len() != 1
            || hit.rank != Some(ids.len() + 1)
            || hit.proof_id != ranking.results[0].proof_id
            || hit.statement_id != ranking.results[0].statement_id
            || hit.score != Some(ranking.results[0].score)
        {
            return Err("mock semantic ranked hit correspondence differs".into());
        }
        window
            .as_mut()
            .expect("header captured")
            .results
            .extend(ranking.results.clone());
        ids.push(hit.proof_id.clone());
        if page.remaining_range_complete {
            if page.next_after.is_some() {
                return Err("mock completed semantic window has a cursor".into());
            }
            request.validate_received_window(
                "proofs involving addition",
                8,
                &page.query_id,
                window.as_ref().expect("ranked window"),
            )?;
            return Ok(ids);
        }
        let next = page
            .next_after
            .as_ref()
            .ok_or("mock semantic continuation cursor absent")?;
        after = serde_json::to_value(next).map_err(|e| e.to_string())?;
    }
    Err("mock semantic window exceeded its eight-result bound".into())
}

fn consume_record(
    request: &crate::generation::Request,
    proof_id: &str,
    fetched: &crate::generation::ToolResult,
    invoke: &mut impl FnMut(&str, &serde_json::Value) -> Result<crate::generation::ToolResult, String>,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let expected = fetched.results[0]
        .detail_reference
        .as_ref()
        .ok_or("mock full-record reference absent")?;
    // Mock consumption is finite independently of the node's larger record
    // capacity. A required oversized record is declined, never truncated.
    if expected.full_record_bytes > 4 * 1024 * 1024 {
        return Err("mock full-record byte capacity".into());
    }
    let mut after = serde_json::Value::Null;
    let mut bytes = Vec::new();
    for _ in 0..100 {
        let page = invoke(
            "read_record",
            &serde_json::json!({
                "request_id":request.identity(), "proof_id":proof_id, "after":after,
                "max_bytes":262144,
            }),
        )?;
        let chunk = page.detail.as_ref().ok_or("mock record chunk absent")?;
        if page.request_id != request.identity()
            || page.status != crate::generation::ToolStatus::Ok
            || chunk.proof_id != proof_id
            || chunk.encoding != "utf8_json"
            || chunk.byte_offset != bytes.len()
            || chunk.utf8_json.is_empty()
            || chunk.full_record_bytes != expected.full_record_bytes
            || chunk.full_record_sha256 != expected.full_record_sha256
            || bytes.len().saturating_add(chunk.utf8_json.len()) > expected.full_record_bytes
        {
            return Err("mock full-record chunk binding or progress differs".into());
        }
        bytes.extend_from_slice(chunk.utf8_json.as_bytes());
        match &chunk.next_after {
            Some(next) => after = serde_json::to_value(next).map_err(|e| e.to_string())?,
            None => {
                if bytes.len() != expected.full_record_bytes
                    || crate::hex(&Sha256::digest(&bytes)) != expected.full_record_sha256
                    || !page.remaining_range_complete
                {
                    return Err("mock complete record digest or length differs".into());
                }
                let record: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                let envelope: crate::Envelope = serde_json::from_value(record["envelope"].clone())
                    .map_err(|e| e.to_string())?;
                if envelope.proof_id != proof_id
                    || fetched.results[0].certificate.as_ref() != Some(&envelope)
                {
                    return Err("mock full record and fetched canonical certificate differ".into());
                }
                return Ok(());
            }
        }
    }
    Err("mock record pagination exhausted its finite allowance".into())
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

    struct TraversalFake;
    impl crate::SemanticEncoder for TraversalFake {
        fn identity(&self) -> crate::EncoderIdentity {
            crate::EncoderIdentity {
                name: "explicit-mock-traversal-fake-only".into(),
                revision: "test-v1".into(),
                representation_version: crate::corpus::semantic::SEMANTIC_REPRESENTATION_VERSION,
                dimensions: 2,
                maximum_input_bytes: crate::generation::MAX_REQUEST_BYTES,
            }
        }
        fn encode(&mut self, input: &str) -> Result<Vec<f32>, String> {
            // This is a caller-contract witness, never semantic quality.
            Ok(
                if input.starts_with("naome:semantic-proof-content:")
                    && !input.contains("Equality reflexivity instance")
                {
                    vec![0.0, 1.0]
                } else {
                    vec![1.0, 0.0]
                },
            )
        }
    }

    fn traversal_fixture() -> (crate::generation::Request, crate::SemanticIndex, String) {
        use std::{collections::BTreeMap, sync::Arc};
        let mut graph = Graph::default();
        for cursor in 0..2 {
            let question = CompiledQuestion::compile(&create_question(cursor)).unwrap();
            let envelope = graph.author(&create_proof(&question).unwrap()).unwrap();
            graph.ingest(envelope, Instant::now()).unwrap();
        }
        let selected = graph.author(CATALOG[0].1).unwrap().proof_id;
        let mut originals = BTreeMap::new();
        for n in 0..24 {
            let source = format!(
                "# retained original {n}: {}\ngoal=all(x,eq(x,x))",
                "x".repeat(15000)
            );
            let question = CompiledQuestion::compile(&source).unwrap();
            originals.insert(
                crate::hex(question.source_hash()),
                question::StoredQuestion {
                    source,
                    kind: question::StoredQuestionKind::Baseline,
                    first: None,
                },
            );
        }
        let policy = naome_checker::question::PrefilterPolicy::default();
        let binding = crate::jobs::Binding::new([0; 32], policy.identity());
        let frozen =
            crate::corpus::snapshot::Frozen::capture(&graph, Some(originals), &binding.snapshot)
                .unwrap();
        let index = crate::SemanticIndex::build(frozen.corpus(), &mut TraversalFake).unwrap();
        let request = crate::generation::Request::build_from_snapshot(
            &crate::jobs::Input::Solve {
                question: create_question(0),
            },
            &binding,
            Arc::new(frozen),
            crate::generation::OwnerContext::Unavailable {
                reason: "mock traversal fixture".into(),
            },
            policy,
        )
        .unwrap();
        assert_ne!(
            request.source().unwrap().corpus().references[0]
                .proof
                .proof_id,
            selected,
            "ranked hint must differ from exact browse-first to distinguish the paths"
        );
        (request, index, selected)
    }

    #[test]
    fn proof_mock_follows_ranked_pages_and_reads_actual_large_record_before_fixed_output() {
        let (request, index, selected) = traversal_fixture();
        let mut encoder = TraversalFake;
        let mut calls = Vec::new();
        let result = create_proof_request_using_tools(&request, |name, arguments| {
            let result = request.invoke_tool_with_retrieval(
                name,
                arguments,
                Some((&index, &mut encoder)),
            )?;
            calls.push((name.to_owned(), arguments.clone(), result.clone()));
            Ok(result)
        })
        .unwrap();
        assert_eq!(result, Some(CATALOG[0].1.into()));
        let semantic = calls
            .iter()
            .filter(|(name, _, _)| name == "semantic_search")
            .collect::<Vec<_>>();
        assert_eq!(semantic.len(), 2);
        assert!(
            semantic
                .iter()
                .all(|(_, _, page)| page.results.len() == 1 && page.byte_limit == 4096)
        );
        assert!(!semantic[0].2.remaining_range_complete && semantic[1].2.remaining_range_complete);
        assert_eq!(semantic[0].2.results[0].proof_id, selected);
        let lookup = calls.iter().find(|(name, _, _)| name == "lookup").unwrap();
        assert_eq!(lookup.1["value"], selected);
        let fetched = calls.iter().find(|(name, _, _)| name == "fetch").unwrap();
        assert!(fetched.2.results[0].full_record.is_none());
        let details = calls
            .iter()
            .filter(|(name, _, _)| name == "read_record")
            .collect::<Vec<_>>();
        assert!(details.len() > 1);
        let text = details
            .iter()
            .map(|(_, _, page)| page.detail.as_ref().unwrap().utf8_json.as_str())
            .collect::<String>();
        let record: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(record["envelope"]["proof_id"], selected);
        assert_eq!(
            record["original_question_records"]["matching_registered_questions"]
                .as_array()
                .unwrap()
                .len(),
            24
        );
    }

    #[test]
    fn mock_declines_duplicate_ranked_pages_and_modified_full_record_bytes() {
        for corrupt_record in [false, true] {
            let (request, index, selected) = traversal_fixture();
            let mut encoder = TraversalFake;
            let mut semantic_calls = 0;
            let mut changed = false;
            let error = create_proof_request_using_tools(&request, |name, arguments| {
                let mut result = request.invoke_tool_with_retrieval(
                    name,
                    arguments,
                    Some((&index, &mut encoder)),
                )?;
                if name == "semantic_search" {
                    semantic_calls += 1;
                    if !corrupt_record && semantic_calls == 2 {
                        result.results[0].proof_id = selected.clone();
                    }
                }
                if corrupt_record && name == "read_record" && !changed {
                    result
                        .detail
                        .as_mut()
                        .unwrap()
                        .utf8_json
                        .replace_range(0..1, "[");
                    changed = true;
                }
                Ok(result)
            })
            .unwrap_err();
            assert!(
                error.contains(if corrupt_record {
                    "complete record digest"
                } else {
                    "repeated a proof"
                }),
                "{error}"
            );
        }
    }

    #[test]
    fn serialized_mock_roles_validate_source_bound_pages_without_corpus_or_cursor_key() {
        use crate::corpus::{local::EmbeddedChunk, semantic::SourceVectorRow};
        let mut graph = Graph::default();
        for cursor in 0..2 {
            let question = CompiledQuestion::compile(&create_question(cursor)).unwrap();
            let envelope = graph.author(&create_proof(&question).unwrap()).unwrap();
            graph.ingest(envelope, Instant::now()).unwrap();
        }
        let original = create_question(0);
        let compiled = CompiledQuestion::compile(&original).unwrap();
        let source = std::sync::Arc::new(
            crate::corpus::snapshot::Frozen::capture(
                &graph,
                Some(
                    [(
                        crate::hex(compiled.source_hash()),
                        question::StoredQuestion {
                            source: original,
                            kind: question::StoredQuestionKind::Baseline,
                            first: None,
                        },
                    )]
                    .into(),
                ),
                &"00".repeat(32),
            )
            .unwrap(),
        );
        let identity = crate::SemanticEncoder::identity(&TraversalFake);
        let rows = source
            .corpus()
            .references
            .iter()
            .map(|reference| {
                let content = source.semantic_content(&reference.proof.proof_id).unwrap();
                // Explicit fake spans/vectors exercise wire custody only. They are
                // not observations of tokenizer coverage or semantic relevance.
                SourceVectorRow::new(
                    identity.clone(),
                    reference,
                    &content,
                    vec![EmbeddedChunk {
                        token_start: 0,
                        token_end: 1,
                        total_tokens: 1,
                        byte_start: 0,
                        byte_end: content.len(),
                        vector: vec![1., 0.],
                    }],
                )
                .unwrap()
            })
            .collect();
        let index = crate::SemanticIndex::build_source(&source, identity, rows).unwrap();
        for input in [
            crate::jobs::Input::Find { cursor: 0 },
            crate::jobs::Input::Solve {
                question: create_question(0),
            },
        ] {
            let owner = crate::generation::Request::build_from_snapshot(
                &input,
                &crate::jobs::Binding::new(
                    [0; 32],
                    naome_checker::question::PrefilterPolicy::default().identity(),
                ),
                source.clone(),
                crate::generation::OwnerContext::Unavailable {
                    reason: "serialized caller contract".into(),
                },
                naome_checker::question::PrefilterPolicy::default(),
            )
            .unwrap();
            let remote: crate::generation::Request =
                serde_json::from_slice(&serde_json::to_vec(&owner).unwrap()).unwrap();
            assert!(remote.source().is_err() && remote.context().is_err());
            let mut semantic_calls = 0;
            let mut invoke = |name: &str, arguments: &serde_json::Value| {
                if name == "semantic_search" {
                    semantic_calls += 1;
                    let ranking =
                        index.search_vector(&source, "proofs involving addition", 8, &[1., 0.])?;
                    owner.invoke_tool_with_ranking(name, arguments, ranking)
                } else {
                    owner.invoke_tool(name, arguments)
                }
            };
            match input {
                crate::jobs::Input::Find { .. } => assert_eq!(
                    create_question_request_using_tools(&remote, &mut invoke).unwrap(),
                    create_question(0)
                ),
                crate::jobs::Input::Solve { .. } => assert_eq!(
                    create_proof_request_using_tools(&remote, &mut invoke).unwrap(),
                    Some(CATALOG[0].1.into())
                ),
                _ => unreachable!(),
            }
            assert_eq!(semantic_calls, 2);
        }
    }

    #[test]
    fn mock_rejects_wrong_operation_source_and_ranked_window_replies() {
        for corruption in [
            "browse",
            "artifact",
            "graph",
            "snapshot",
            "query",
            "index",
            "encoder",
            "query_digest",
            "top_k",
            "count",
            "rank",
            "score",
            "early_complete",
        ] {
            let (request, index, _) = traversal_fixture();
            let mut encoder = TraversalFake;
            let mut calls = 0;
            // The ordinary proof role consumes the same helper through its
            // actual callback, including multiple result and detail pages.
            let result = create_proof_request_using_tools(&request, |name, arguments| {
                let mut reply = request.invoke_tool_with_retrieval(
                    name,
                    arguments,
                    Some((&index, &mut encoder)),
                )?;
                if name == "semantic_search" {
                    calls += 1;
                    if calls == 1 {
                        match corruption {
                            "browse" => reply = request.invoke_tool("browse", &serde_json::json!({"request_id":request.identity(),"after":null,"limit":1}))?,
                            "artifact" => reply.artifact_snapshot = "00".repeat(32),
                            "graph" => reply.graph_root = "00".repeat(32),
                            "snapshot" => reply.snapshot_id = Some("00".repeat(32)),
                            "query" => reply.query_id = "00".repeat(32),
                            "index" => reply.semantic_ranking.as_mut().unwrap().index_identity = "00".repeat(32),
                            "encoder" => reply.semantic_ranking.as_mut().unwrap().encoder.revision = "changed".into(),
                            "query_digest" => reply.semantic_ranking.as_mut().unwrap().query_digest = "00".repeat(32),
                            "top_k" => reply.semantic_ranking.as_mut().unwrap().top_k = 1,
                            "count" => reply.semantic_ranking.as_mut().unwrap().corpus_proofs = 1,
                            "rank" => reply.results[0].rank = Some(2),
                            "score" => reply.results[0].score = Some(0.5),
                            "early_complete" => { reply.remaining_range_complete = true; reply.next_after = None; },
                            _ => unreachable!(),
                        }
                    }
                }
                Ok(reply)
            });
            assert!(result.is_err(), "accepted {corruption}");
        }
    }

    #[test]
    fn mock_rejects_wrong_record_source_query_and_intermediate_completion() {
        for corruption in ["artifact", "graph", "snapshot", "query", "completion"] {
            let (request, index, _) = traversal_fixture();
            let mut encoder = TraversalFake;
            let mut changed = false;
            let result = create_proof_request_using_tools(&request, |name, arguments| {
                let mut reply = request.invoke_tool_with_retrieval(
                    name,
                    arguments,
                    Some((&index, &mut encoder)),
                )?;
                if name == "read_record" && !changed {
                    changed = true;
                    assert!(!reply.remaining_range_complete);
                    match corruption {
                        "artifact" => reply.artifact_snapshot = "00".repeat(32),
                        "graph" => reply.graph_root = "00".repeat(32),
                        "snapshot" => reply.snapshot_id = Some("00".repeat(32)),
                        "query" => reply.query_id = "00".repeat(32),
                        "completion" => reply.remaining_range_complete = true,
                        _ => unreachable!(),
                    }
                }
                Ok(reply)
            });
            assert!(changed && result.is_err(), "accepted {corruption}");
        }
    }

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
