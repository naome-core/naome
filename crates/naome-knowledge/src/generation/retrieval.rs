//! Read-only typed tools over one complete, checked generation snapshot.
//! Transport adapters can translate these JSON schemas into local or hosted
//! model tool calls; no protocol server or provider dependency is needed here.
use super::*;
use crate::Envelope;
use serde_json::{Value, json};

const MAX_CALL_BYTES: usize = naome_authoring::QUESTION_SOURCE_MAX_BYTES + 1024;
const MAX_PAGE: u16 = 16;
const MAX_TEXT_QUERY_BYTES: usize = 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Tool {
    name: String,
    description: String,
    input_schema: Value,
}

pub(super) fn tools() -> Vec<Tool> {
    let id = json!({"type":"string","pattern":"^[0-9a-f]{64}$"});
    let cursor = json!({"anyOf":[{"type":"object","additionalProperties":false,"properties":{"query_id":id.clone(),"proof_id":id.clone()},"required":["query_id","proof_id"]},{"type":"null"}]});
    let fields = [
        (
            "lookup",
            "Look up accepted local proofs by exact proof_id or statement_id. Paginate in ascending ProofId order.",
            json!({"key":{"enum":["proof_id","statement_id"]},"value":id.clone(),"after":cursor.clone(),"limit":{"type":"integer","minimum":1,"maximum":16}}),
            vec!["key", "value", "after", "limit"],
        ),
        (
            "native_search",
            "Find checked proofs resolving a closed native .nao question. Match canonical positive or negative target, including alpha-equivalent binders; label proved/refuted relative to the exact query orientation. This is mathematical target matching, not natural-language similarity or arbitrary theorem equivalence.",
            json!({"question":{"type":"string","maxLength":16384},"after":cursor.clone(),"limit":{"type":"integer","minimum":1,"maximum":16}}),
            vec!["question", "after", "limit"],
        ),
        (
            "fetch",
            "Retrieve one accepted proof's stored canonical certificate, exact identities, derived native conclusion and direct dependencies. Original .nao proof source is not stored.",
            json!({"proof_id":id.clone()}),
            vec!["proof_id"],
        ),
        (
            "semantic_search",
            "Search the actual accepted local proof corpus with a natural-language query and bounded top-K. Corpus content includes canonical certificates, derived native conclusions and dependencies, not syntax-guide or job labels. A separately identified compatible retrieval encoder/index is required for semantic ranking; the current mock-only runtime has none and returns explicit backend_unavailable. Selecting a generation model is independent. Exact lookup and certificate loading are available.",
            json!({"query":{"type":"string","maxLength":1024},"top_k":{"type":"integer","minimum":1,"maximum":16}}),
            vec!["query", "top_k"],
        ),
    ];
    fields.into_iter().map(|(name,description,properties,required)| {
        let mut properties = properties.as_object().expect("static tool properties").clone();
        properties.insert("request_id".into(),id.clone());
        let mut required = required;
        required.push("request_id");
        Tool {
            name: name.into(), description: description.into(),
            input_schema: json!({"type":"object","additionalProperties":false,"properties":properties,"required":required}),
        }
    }).collect()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Key {
    ProofId,
    StatementId,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Operation {
    Lookup {
        key: Key,
        value: String,
        after: Option<Cursor>,
        limit: u16,
    },
    NativeSearch {
        question: String,
        after: Option<Cursor>,
        limit: u16,
    },
    Fetch {
        proof_id: String,
    },
    SemanticSearch {
        query: String,
        top_k: u16,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Call {
    pub request_id: String,
    pub operation: Operation,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Ok,
    NoResult,
    BackendUnavailable,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hit {
    pub proof_id: String,
    pub statement_id: String,
    pub native_conclusion: String,
    pub dependencies: Vec<String>,
    pub resolution: Option<String>,
    pub certificate: Option<Envelope>,
    pub citation_expression: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResultPage {
    pub request_id: String,
    pub artifact_snapshot: String,
    pub graph_root: String,
    pub status: Status,
    pub results: Vec<Hit>,
    pub next_after: Option<Cursor>,
    pub query_id: String,
    pub remaining_range_complete: bool,
    pub original_source_available: bool,
    pub backend_unavailable_reason: Option<String>,
    pub native_query: Option<NativeQuery>,
    pub semantic_ranking: Option<semantic::SemanticPage>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cursor {
    query_id: String,
    proof_id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeQuery {
    source_hash: String,
    resolution_id: String,
    proved_statement_id: String,
    refuted_statement_id: String,
}

pub(super) fn parse_call(name: &str, arguments: &Value) -> Result<Call, String> {
    let tool = tools()
        .into_iter()
        .find(|tool| tool.name == name)
        .ok_or("unsupported generation retrieval tool")?;
    if serde_json::to_vec(arguments)
        .map_err(|e| e.to_string())?
        .len()
        > MAX_CALL_BYTES
    {
        return Err("retrieval request byte limit".into());
    }
    let mut fields = arguments
        .as_object()
        .ok_or("retrieval arguments must be an object")?
        .clone();
    for required in tool.input_schema["required"]
        .as_array()
        .expect("tool required fields")
    {
        if !fields.contains_key(required.as_str().expect("field name")) {
            return Err("retrieval required argument missing".into());
        }
    }
    let request_id = fields
        .remove("request_id")
        .ok_or("retrieval request identity missing")?;
    // The function name selects the operation; arguments cannot override it.
    if fields
        .insert("operation".into(), Value::String(name.into()))
        .is_some()
    {
        return Err("retrieval operation supplied in arguments".into());
    }
    serde_json::from_value(json!({"request_id":request_id,"operation":fields}))
        .map_err(|e| format!("retrieval arguments: {e}"))
}

fn page(
    limit: u16,
    after: &Option<Cursor>,
    request: &Request,
    query_id: &str,
) -> Result<(), String> {
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err("retrieval page limit".into());
    }
    if let Some(after) = after {
        crate::object::id_bytes(&after.proof_id)?;
        if after.query_id != query_id {
            return Err("retrieval cursor query or request binding differs".into());
        }
        if !request
            .checked_context
            .references
            .iter()
            .any(|r| r.proof.proof_id == after.proof_id)
        {
            return Err("retrieval cursor is absent from bound context".into());
        }
    }
    Ok(())
}
fn hit(reference: &Reference, resolution: Option<String>, fetch: bool) -> Hit {
    Hit {
        proof_id: reference.proof.proof_id.clone(),
        statement_id: reference.proof.statement_id.clone(),
        native_conclusion: reference.native_conclusion.clone(),
        dependencies: reference.dependencies.clone(),
        resolution,
        citation_expression: format!("cite(\"{}\")", reference.proof.proof_id),
        certificate: fetch.then(|| reference.proof.clone()),
    }
}
pub(super) fn invoke(
    request: &Request,
    call: &Call,
    backend: Option<(&semantic::SemanticIndex, &mut dyn semantic::SemanticEncoder)>,
) -> Result<ResultPage, String> {
    if serde_json::to_vec(call).map_err(|e| e.to_string())?.len() > MAX_CALL_BYTES {
        return Err("retrieval request byte limit".into());
    }
    if call.request_id != request.identity() {
        return Err("retrieval request identity is stale or differs".into());
    }
    let mut query_value = serde_json::to_value(&call.operation).map_err(|e| e.to_string())?;
    let query_fields = query_value.as_object_mut().expect("tagged operation");
    query_fields.remove("after");
    query_fields.remove("limit");
    let query_id = digest_value(&(&call.request_id, query_value));
    let mut result = ResultPage {
        request_id: call.request_id.clone(),
        artifact_snapshot: request.checked_context.artifact_snapshot.clone(),
        graph_root: request.checked_context.graph_root.clone(),
        status: Status::NoResult,
        results: Vec::new(),
        next_after: None,
        query_id: query_id.clone(),
        remaining_range_complete: true,
        original_source_available: false,
        backend_unavailable_reason: None,
        native_query: None,
        semantic_ranking: None,
    };
    let (after, limit) = match &call.operation {
        Operation::Lookup {
            value,
            after,
            limit,
            ..
        } => {
            crate::object::id_bytes(value)?;
            page(*limit, after, request, &query_id)?;
            (after, *limit)
        }
        Operation::NativeSearch { after, limit, .. } => {
            page(*limit, after, request, &query_id)?;
            (after, *limit)
        }
        Operation::SemanticSearch { query, top_k } => {
            if query.trim().is_empty()
                || query.len() > MAX_TEXT_QUERY_BYTES
                || !(1..=MAX_PAGE).contains(top_k)
            {
                return Err("retrieval semantic query or top-K limit".into());
            }
            if let Some((index, encoder)) = backend {
                let ranking = index.search(&request.checked_context, query, *top_k, encoder)?;
                for ranked in &ranking.results {
                    let reference = request
                        .checked_context
                        .references
                        .iter()
                        .find(|r| r.proof.proof_id == ranked.proof_id)
                        .ok_or("semantic result is absent from the checked corpus")?;
                    result.results.push(hit(reference, None, false));
                }
                result.status = if result.results.is_empty() {
                    Status::NoResult
                } else {
                    Status::Ok
                };
                result.semantic_ranking = Some(ranking);
            } else if !request.checked_context.references.is_empty() {
                result.status = Status::BackendUnavailable;
                result.backend_unavailable_reason=Some("No separately bound retrieval encoder/index is configured for the accepted local proof corpus; the future generation provider does not select this backend.".into());
                result.remaining_range_complete = false;
            }
            return bounded(result);
        }
        Operation::Fetch { proof_id } => {
            crate::object::id_bytes(proof_id)?;
            if let Some(reference) = request
                .checked_context
                .references
                .iter()
                .find(|r| &r.proof.proof_id == proof_id)
            {
                result.results.push(hit(reference, None, true));
                result.status = Status::Ok;
            }
            return bounded(result);
        }
    };
    let question = if let Operation::NativeSearch { question, .. } = &call.operation {
        {
            let q = CompiledQuestion::compile(question)
                .map_err(|e| format!("retrieval native question: {e}"))?;
            let proved = crate::hex(crate::object::target_id(q.proved_target())?.as_bytes());
            let refuted = crate::hex(crate::object::target_id(q.refuted_target())?.as_bytes());
            result.native_query = Some(NativeQuery {
                source_hash: crate::hex(q.source_hash()),
                resolution_id: crate::hex(q.resolution_id()),
                proved_statement_id: proved.clone(),
                refuted_statement_id: refuted.clone(),
            });
            Some((proved, refuted))
        }
    } else {
        None
    };
    for reference in &request.checked_context.references {
        if after
            .as_ref()
            .is_some_and(|after| reference.proof.proof_id <= after.proof_id)
        {
            continue;
        }
        let (matches, resolution) = match &call.operation {
            Operation::Lookup { key, value, .. } => (
                match key {
                    Key::ProofId => &reference.proof.proof_id == value,
                    Key::StatementId => &reference.proof.statement_id == value,
                },
                None,
            ),
            Operation::NativeSearch { .. } => {
                // Capture used the checker-owned closed conclusion; validate()
                // rechecks the complete certificate closure before provider entry.
                let (proved, refuted) = question.as_ref().expect("native query compiled");
                let statement = &reference.proof.statement_id;
                if statement == proved {
                    (true, Some("proved".into()))
                } else if statement == refuted {
                    (true, Some("refuted".into()))
                } else {
                    (false, None)
                }
            }
            _ => unreachable!("handled single-result operation"),
        };
        if matches {
            if result.results.len() == limit as usize {
                result.next_after = result.results.last().map(|h| Cursor {
                    query_id: query_id.clone(),
                    proof_id: h.proof_id.clone(),
                });
                result.remaining_range_complete = false;
                break;
            }
            result.results.push(hit(reference, resolution, false));
        }
    }
    if !result.results.is_empty() {
        result.status = Status::Ok;
    }
    bounded(result)
}
fn bounded(result: ResultPage) -> Result<ResultPage, String> {
    if serde_json::to_vec(&result)
        .map_err(|e| e.to_string())?
        .len()
        > MAX_REQUEST_BYTES
    {
        Err("retrieval complete result byte limit".into())
    } else {
        Ok(result)
    }
}
