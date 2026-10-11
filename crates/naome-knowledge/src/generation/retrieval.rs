//! Read-only typed tools over one complete, checked generation snapshot.
//! Transport adapters can translate these JSON schemas into local or hosted
//! model tool calls; no protocol server or provider dependency is needed here.
use super::*;
use crate::Envelope;
use serde_json::{Value, json};

const MAX_CALL_BYTES: usize = naome_authoring::QUESTION_SOURCE_MAX_BYTES + 1024;
const MAX_PAGE: u16 = 16;
const MAX_TEXT_QUERY_BYTES: usize = 1024;
const MIN_PAGE_BYTES: usize = 4096;
fn default_page_bytes() -> usize {
    MAX_REQUEST_BYTES
}
fn default_page_size() -> u16 {
    MAX_PAGE
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SearchType {
    Proof,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Tool {
    name: String,
    description: String,
    input_schema: Value,
}

pub(super) fn tools() -> Vec<Tool> {
    let id = json!({"type":"string","pattern":"^[0-9a-f]{64}$"});
    let cursor = json!({"anyOf":[{"type":"object","additionalProperties":false,"properties":{"query_id":id.clone(),"proof_id":id.clone(),"token":id.clone()},"required":["query_id","proof_id","token"]},{"type":"null"}]});
    let fields = [
        (
            "read_record",
            "Read every byte of the complete saved proof projection and actual matching original question records as UTF-8 JSON chunks. Concatenate chunks in byte-offset order and verify full_record_sha256; no original proof source is invented.",
            json!({"proof_id":id.clone(),"after":{"anyOf":[{"type":"object","additionalProperties":false,"properties":{"query_id":id.clone(),"proof_id":id.clone(),"offset":{"type":"integer","minimum":0},"token":id.clone()},"required":["query_id","proof_id","offset","token"]},{"type":"null"}]},"max_bytes":{"type":"integer","minimum":4096,"maximum":262144}}),
            vec!["proof_id", "after"],
        ),
        (
            "browse",
            "Browse summaries of all accepted proofs in the frozen snapshot, in ascending ProofId order. Full records are obtained with fetch.",
            json!({"after":cursor.clone(),"limit":{"type":"integer","minimum":1,"maximum":16}}),
            vec!["after", "limit"],
        ),
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
            "Search the actual accepted local proof corpus with a natural-language query and bounded top-K. Corpus content includes canonical certificates, derived native conclusions and dependencies, not syntax-guide or job labels. A separately identified compatible local retrieval encoder/index is required; missing or incomplete backends remain explicit. Supply query or key, with optional type=proof. top_k selects a stable ranked window; page_size and max_bytes bound each page. Follow authenticated after cursors to traverse that same window and read_record to obtain every byte of a large record. Selecting a generation model is independent. Exact lookup and certificate loading are available.",
            json!({"type":{"const":"proof"},"query":{"type":"string","maxLength":1024},"key":{"type":"string","maxLength":1024},"top_k":{"type":"integer","minimum":1,"maximum":1024},"after":cursor.clone(),"page_size":{"type":"integer","minimum":1,"maximum":16},"max_bytes":{"type":"integer","minimum":4096,"maximum":262144}}),
            vec!["top_k"],
        ),
    ];
    fields.into_iter().map(|(name,description,properties,required)| {
        let mut properties = properties.as_object().expect("static tool properties").clone();
        properties.insert("request_id".into(),id.clone());
        let mut required = required;
        required.push("request_id");
        Tool {
            name: name.into(), description: description.into(),
            input_schema: {
                let mut schema=json!({"type":"object","additionalProperties":false,"properties":properties,"required":required});
                if name=="semantic_search" { schema["oneOf"]=json!([{"required":["query"]},{"required":["key"]}]); }
                schema
            },
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
    Browse {
        after: Option<Cursor>,
        limit: u16,
    },
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
        #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
        kind: Option<SearchType>,
        #[serde(alias = "key")]
        query: String,
        top_k: u16,
        #[serde(default)]
        after: Option<Cursor>,
        #[serde(default = "default_page_size")]
        page_size: u16,
        #[serde(default = "default_page_bytes")]
        max_bytes: usize,
    },
    ReadRecord {
        proof_id: String,
        after: Option<RecordCursor>,
        #[serde(default = "default_page_bytes")]
        max_bytes: usize,
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
    IndexIncomplete,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hit {
    pub proof_id: String,
    pub statement_id: String,
    pub native_conclusion: String,
    pub dependencies: Vec<String>,
    pub resolution: Option<String>,
    pub certificate: Option<Envelope>,
    pub citation_expression: String,
    pub rank: Option<usize>,
    pub score: Option<f64>,
    pub full_record: Option<Value>,
    pub detail_reference: Option<DetailReference>,
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
    pub snapshot_id: Option<String>,
    pub byte_limit: usize,
    pub detail: Option<DetailChunk>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cursor {
    query_id: String,
    proof_id: String,
    token: String,
}
impl Cursor {
    fn new(request: &Request, query_id: &str, proof_id: &str) -> Result<Self, String> {
        Ok(Self {
            query_id: query_id.into(),
            proof_id: proof_id.into(),
            token: request.cursor_key()?.sign(&(
                "proof",
                request.identity(),
                query_id,
                proof_id,
            ))?,
        })
    }
    fn verify(&self, request: &Request, query_id: &str) -> Result<(), String> {
        if self.query_id != query_id {
            return Err("retrieval cursor query or request binding differs".into());
        }
        request.cursor_key()?.verify(
            &("proof", request.identity(), query_id, &self.proof_id),
            &self.token,
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordCursor {
    query_id: String,
    proof_id: String,
    offset: usize,
    token: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DetailReference {
    pub full_record_bytes: usize,
    pub full_record_sha256: String,
    pub inline_data_omitted: bool,
    pub read_tool: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DetailChunk {
    pub proof_id: String,
    pub encoding: String,
    pub full_record_sha256: String,
    pub full_record_bytes: usize,
    pub byte_offset: usize,
    pub utf8_json: String,
    pub next_after: Option<RecordCursor>,
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
        after.verify(request, query_id)?;
        if !request
            .context()?
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
        native_conclusion: reference.native_conclusion.to_string(),
        dependencies: reference.dependencies.clone(),
        resolution,
        citation_expression: format!("cite(\"{}\")", reference.proof.proof_id),
        certificate: fetch.then(|| reference.proof.clone()),
        rank: None,
        score: None,
        full_record: None,
        detail_reference: None,
    }
}
pub(super) fn invoke(
    request: &Request,
    call: &Call,
    backend: Option<(&semantic::SemanticIndex, &mut dyn semantic::SemanticEncoder)>,
) -> Result<ResultPage, String> {
    invoke_ranked(request, call, backend, None)
}
pub(super) fn invoke_ranked(
    request: &Request,
    call: &Call,
    backend: Option<(&semantic::SemanticIndex, &mut dyn semantic::SemanticEncoder)>,
    ranking: Option<semantic::SemanticPage>,
) -> Result<ResultPage, String> {
    if serde_json::to_vec(call).map_err(|e| e.to_string())?.len() > MAX_CALL_BYTES {
        return Err("retrieval request byte limit".into());
    }
    if call.request_id != request.identity() {
        return Err("retrieval request identity is stale or differs".into());
    }
    let mut query_id = operation_identity(call)?;
    let mut result = ResultPage {
        request_id: call.request_id.clone(),
        artifact_snapshot: request.context()?.artifact_snapshot.clone(),
        graph_root: request.context()?.graph_root.clone(),
        status: Status::NoResult,
        results: Vec::new(),
        next_after: None,
        query_id: query_id.clone(),
        remaining_range_complete: true,
        original_source_available: false,
        backend_unavailable_reason: None,
        native_query: None,
        semantic_ranking: None,
        snapshot_id: request
            .retrieval_snapshot
            .as_ref()
            .map(|s| s.snapshot_id.clone()),
        byte_limit: MAX_REQUEST_BYTES,
        detail: None,
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
        Operation::Browse { after, limit } | Operation::NativeSearch { after, limit, .. } => {
            page(*limit, after, request, &query_id)?;
            (after, *limit)
        }
        Operation::SemanticSearch {
            query,
            top_k,
            after,
            page_size,
            max_bytes,
            ..
        } => {
            if query.trim().is_empty()
                || query.len() > MAX_TEXT_QUERY_BYTES
                || !(1..=1024).contains(top_k)
            {
                return Err("retrieval semantic query or top-K limit".into());
            }
            byte_limit(*max_bytes)?;
            if !(1..=MAX_PAGE).contains(page_size) {
                return Err("retrieval semantic page size limit".into());
            }
            if after.is_some() && backend.is_none() && ranking.is_none() {
                return Err("semantic continuation backend is unavailable".into());
            }
            result.byte_limit = *max_bytes;
            let ranking = match (backend, ranking) {
                (_, Some(ranking)) => Some(ranking),
                (Some((index, encoder)), None) => {
                    Some(index.search(request.context()?, query, *top_k, encoder)?)
                }
                (None, None) => None,
            };
            if let Some(mut ranking) = ranking {
                ranking.validate_window(request.source()?, query, *top_k)?;
                query_id = digest_value(&(
                    &call.request_id,
                    &query_id,
                    &ranking.index_identity,
                    &ranking.encoder,
                    &ranking.query_digest,
                    &ranking.results,
                ));
                result.query_id = query_id.clone();
                page(*page_size, after, request, &query_id)?;
                let start = match after {
                    Some(cursor) => {
                        ranking
                            .results
                            .iter()
                            .position(|h| h.proof_id == cursor.proof_id)
                            .ok_or("semantic cursor is absent from the exact ranked window")?
                            + 1
                    }
                    None => 0,
                };
                let ranked = ranking.results.clone();
                ranking.results.clear();
                result.semantic_ranking = Some(ranking);
                for (offset, ranked) in ranked.iter().enumerate().skip(start) {
                    let reference = request
                        .source()?
                        .reference(&ranked.proof_id)
                        .ok_or("semantic result absent from frozen source")?;
                    if result.results.len() == usize::from(*page_size) {
                        result.remaining_range_complete = false;
                        break;
                    }
                    let mut candidate = full_hit(request, reference, None, false, *max_bytes)?;
                    candidate.rank = Some(offset + 1);
                    candidate.score = Some(ranked.score);
                    result.results.push(candidate);
                    result
                        .semantic_ranking
                        .as_mut()
                        .expect("ranking")
                        .results
                        .push(ranked.clone());
                    result.status = Status::Ok;
                    // Reserve a continuation cursor in the byte bound as well.
                    result.next_after = Some(Cursor::new(request, &query_id, &ranked.proof_id)?);
                    result.remaining_range_complete = false;
                    if encoded_size(&result)? > *max_bytes {
                        result.results.pop();
                        result
                            .semantic_ranking
                            .as_mut()
                            .expect("ranking")
                            .results
                            .pop();
                        if result.results.is_empty() {
                            return Err(
                                "semantic page metadata or one summary exceeds byte limit".into()
                            );
                        }
                        break;
                    }
                }
                let consumed = start + result.results.len();
                result.remaining_range_complete = consumed == ranked.len();
                result.next_after = if result.remaining_range_complete {
                    None
                } else {
                    Some(Cursor::new(
                        request,
                        &query_id,
                        &result
                            .results
                            .last()
                            .ok_or("semantic continuation has no result")?
                            .proof_id,
                    )?)
                };
                if result.results.is_empty() {
                    result.status = Status::NoResult;
                }
            } else if !request.context()?.references.is_empty() {
                if after.is_some() {
                    return Err("semantic continuation backend is unavailable".into());
                }
                result.status = Status::BackendUnavailable;
                result.backend_unavailable_reason=Some("No compatible local retrieval encoder/index is configured for this exact frozen source.".into());
                result.remaining_range_complete = false;
            }
            return bounded(result);
        }
        Operation::ReadRecord {
            proof_id,
            after,
            max_bytes,
        } => {
            byte_limit(*max_bytes)?;
            crate::object::id_bytes(proof_id)?;
            result.byte_limit = *max_bytes;
            if let Some(cursor) = after {
                if cursor.proof_id != *proof_id {
                    return Err("record continuation proof binding differs".into());
                }
                crate::object::id_bytes(&cursor.query_id)?;
                request.cursor_key()?.verify(
                    &(
                        "record",
                        request.identity(),
                        &cursor.query_id,
                        proof_id,
                        cursor.offset,
                    ),
                    &cursor.token,
                )?;
            }
            let Some(value) = request.source()?.full_record(proof_id)? else {
                if after.is_some() {
                    return Err("record continuation source is absent".into());
                }
                return bounded(result);
            };
            let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
            if bytes.len() > 64 * 1024 * 1024 {
                return Err("complete record representation capacity".into());
            }
            let digest = crate::hex(&Sha256::digest(&bytes));
            query_id = digest_value(&(&call.request_id, "read_record", proof_id, &digest));
            result.query_id = query_id.clone();
            let start = match after {
                None => 0,
                Some(cursor) => {
                    if cursor.query_id != query_id
                        || cursor.proof_id != *proof_id
                        || cursor.offset >= bytes.len()
                    {
                        return Err("record continuation source, proof or offset differs".into());
                    }
                    request.cursor_key()?.verify(
                        &(
                            "record",
                            request.identity(),
                            &query_id,
                            proof_id,
                            cursor.offset,
                        ),
                        &cursor.token,
                    )?;
                    cursor.offset
                }
            };
            let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
            if !text.is_char_boundary(start) {
                return Err("record cursor is not a UTF-8 boundary".into());
            }
            let mut end = (start + (*max_bytes - 2048) / 6).min(bytes.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            if end == start {
                return Err("record page cannot advance".into());
            }
            result.detail = Some(DetailChunk {
                proof_id: proof_id.clone(),
                encoding: "utf8_json".into(),
                full_record_sha256: digest,
                full_record_bytes: bytes.len(),
                byte_offset: start,
                utf8_json: text[start..end].into(),
                next_after: if end == bytes.len() {
                    None
                } else {
                    Some(RecordCursor {
                        query_id: query_id.clone(),
                        proof_id: proof_id.clone(),
                        offset: end,
                        token: request.cursor_key()?.sign(&(
                            "record",
                            request.identity(),
                            &query_id,
                            proof_id,
                            end,
                        ))?,
                    })
                },
            });
            result.status = Status::Ok;
            result.remaining_range_complete = end == bytes.len();
            return bounded(result);
        }
        Operation::Fetch { proof_id } => {
            crate::object::id_bytes(proof_id)?;
            if let Some(reference) = request
                .context()?
                .references
                .iter()
                .find(|r| &r.proof.proof_id == proof_id)
            {
                result
                    .results
                    .push(full_hit(request, reference, None, true, MAX_REQUEST_BYTES)?);
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
    for reference in &request.context()?.references {
        if after
            .as_ref()
            .is_some_and(|after| reference.proof.proof_id <= after.proof_id)
        {
            continue;
        }
        let (matches, resolution) = match &call.operation {
            Operation::Browse { .. } => (true, None),
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
                result.next_after = result
                    .results
                    .last()
                    .map(|h| Cursor::new(request, &query_id, &h.proof_id))
                    .transpose()?;
                result.remaining_range_complete = false;
                break;
            }
            result.results.push(full_hit(
                request,
                reference,
                resolution,
                false,
                MAX_REQUEST_BYTES,
            )?);
            result.status = Status::Ok;
            let continuation = Cursor::new(request, &query_id, &reference.proof.proof_id)?;
            result.next_after = Some(continuation);
            result.remaining_range_complete = false;
            if encoded_size(&result)? > MAX_REQUEST_BYTES {
                result.results.pop();
                result.next_after = result
                    .results
                    .last()
                    .map(|h| Cursor::new(request, &query_id, &h.proof_id))
                    .transpose()?;
                if result.results.is_empty() {
                    return Err("one retrieval summary exceeds page byte limit".into());
                }
                break;
            }
            result.next_after = None;
            result.remaining_range_complete = true;
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
        > result.byte_limit
    {
        Err("retrieval complete result byte limit".into())
    } else {
        Ok(result)
    }
}

fn byte_limit(maximum: usize) -> Result<(), String> {
    if !(MIN_PAGE_BYTES..=MAX_REQUEST_BYTES).contains(&maximum) {
        return Err("retrieval page byte limit must be 4096..=262144".into());
    }
    Ok(())
}
fn encoded_size(value: &impl Serialize) -> Result<usize, String> {
    serde_json::to_vec(value)
        .map(|v| v.len())
        .map_err(|e| e.to_string())
}
fn full_hit(
    request: &Request,
    reference: &Reference,
    resolution: Option<String>,
    fetch: bool,
    maximum: usize,
) -> Result<Hit, String> {
    let mut hit = hit(reference, resolution, fetch);
    let record = request
        .source()?
        .full_record(&reference.proof.proof_id)?
        .ok_or("frozen full record absent")?;
    let bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    let details = DetailReference {
        full_record_bytes: bytes.len(),
        full_record_sha256: crate::hex(&Sha256::digest(&bytes)),
        inline_data_omitted: false,
        read_tool: "read_record".into(),
    };
    hit.full_record = Some(record);
    hit.detail_reference = Some(details);
    if encoded_size(&hit)? > maximum.saturating_sub(3072) {
        hit.full_record = None;
        hit.native_conclusion.clear();
        hit.detail_reference
            .as_mut()
            .expect("details")
            .inline_data_omitted = true;
        // A legal node certificate is at most 128 KiB of hexadecimal bytes.
        // Fetch retains that bounded canonical object for the ordinary proof
        // consumer; all larger saved metadata remains available via read_record.
        if !fetch || encoded_size(&hit)? > maximum.saturating_sub(3072) {
            hit.certificate = None;
        }
    }
    Ok(hit)
}

fn operation_identity(call: &Call) -> Result<String, String> {
    let mut value = serde_json::to_value(&call.operation).map_err(|e| e.to_string())?;
    let fields = value.as_object_mut().expect("tagged operation");
    for key in ["after", "limit", "page_size", "max_bytes"] {
        fields.remove(key);
    }
    Ok(digest_value(&(&call.request_id, value)))
}

// Provider-side reply validation uses the serialized source handle, never the
// node's cursor signing key or a second copy of the complete proof corpus.
pub(super) fn validate_reply(
    request: &Request,
    name: &str,
    arguments: &Value,
    reply: &ResultPage,
) -> Result<(), String> {
    let call = parse_call(name, arguments)?;
    let source = request
        .retrieval_snapshot
        .as_ref()
        .ok_or("tool reply source handle absent")?;
    let maximum = match call.operation {
        Operation::SemanticSearch { max_bytes, .. } | Operation::ReadRecord { max_bytes, .. } => {
            max_bytes
        }
        _ => MAX_REQUEST_BYTES,
    };
    if call.request_id != request.identity()
        || reply.request_id != call.request_id
        || reply.artifact_snapshot != source.artifact_snapshot
        || reply.graph_root != source.graph_root
        || reply.snapshot_id.as_ref() != Some(&source.snapshot_id)
        || reply.original_source_available
        || reply.byte_limit != maximum
        || encoded_size(reply)? > maximum
    {
        return Err("tool reply request, source or byte binding differs".into());
    }
    let mut expected_query = operation_identity(&call)?;
    match &call.operation {
        Operation::SemanticSearch { after, .. } if reply.semantic_ranking.is_some() => {
            if reply.detail.is_some()
                || reply.native_query.is_some()
                || reply.backend_unavailable_reason.is_some()
            {
                return Err("semantic reply contains another operation's data".into());
            }
            if reply.status != Status::Ok
                && !(reply.status == Status::NoResult
                    && source.proof_count == 0
                    && reply.results.is_empty()
                    && reply.remaining_range_complete
                    && reply.next_after.is_none())
            {
                return Err("semantic ranked reply status differs".into());
            }
            crate::object::id_bytes(&reply.query_id)?;
            if let Some(after) = after
                && after.query_id != reply.query_id
            {
                return Err("semantic reply continuation query differs".into());
            }
            // Its query identity includes the complete ranked window. The
            // consumer verifies it once all bounded pages have been received.
            return Ok(());
        }
        Operation::SemanticSearch { after, .. } => {
            if after.is_some()
                || !reply.results.is_empty()
                || reply.next_after.is_some()
                || reply.detail.is_some()
                || reply.native_query.is_some()
                || match reply.status {
                    Status::NoResult => source.proof_count != 0 || !reply.remaining_range_complete,
                    Status::BackendUnavailable | Status::IndexIncomplete => {
                        reply.remaining_range_complete || reply.backend_unavailable_reason.is_none()
                    }
                    Status::Ok => true,
                }
            {
                return Err("semantic unavailable or empty reply differs".into());
            }
        }
        Operation::ReadRecord {
            proof_id, after, ..
        } => {
            let chunk = reply.detail.as_ref().ok_or("record reply chunk absent")?;
            expected_query = digest_value(&(
                &call.request_id,
                "read_record",
                proof_id,
                &chunk.full_record_sha256,
            ));
            let end = chunk
                .byte_offset
                .checked_add(chunk.utf8_json.len())
                .ok_or("record reply offset overflow")?;
            if reply.status != Status::Ok
                || !reply.results.is_empty()
                || reply.next_after.is_some()
                || reply.semantic_ranking.is_some()
                || reply.native_query.is_some()
                || reply.backend_unavailable_reason.is_some()
                || chunk.proof_id != *proof_id
                || chunk.encoding != "utf8_json"
                || chunk.utf8_json.is_empty()
                || chunk.byte_offset != after.as_ref().map_or(0, |cursor| cursor.offset)
                || end > chunk.full_record_bytes
                || reply.remaining_range_complete != (end == chunk.full_record_bytes)
                || chunk.next_after.is_none() != reply.remaining_range_complete
                || after.as_ref().is_some_and(|cursor| {
                    cursor.query_id != expected_query || cursor.proof_id != *proof_id
                })
                || chunk.next_after.as_ref().is_some_and(|cursor| {
                    cursor.query_id != expected_query
                        || cursor.proof_id != *proof_id
                        || cursor.offset != end
                })
            {
                return Err("record reply operation, offset or completion binding differs".into());
            }
        }
        _ => {
            if reply.semantic_ranking.is_some()
                || reply.detail.is_some()
                || reply.backend_unavailable_reason.is_some()
            {
                return Err("exact reply contains another operation's data".into());
            }
        }
    }
    if reply.query_id != expected_query {
        return Err("tool reply operation query binding differs".into());
    }
    Ok(())
}

pub(super) fn validate_received_window(
    request: &Request,
    query: &str,
    top_k: u16,
    query_id: &str,
    window: &semantic::SemanticPage,
) -> Result<(), String> {
    if let Some(source) = &request.frozen {
        window.validate_window(source, query, top_k)?;
    } else {
        let source = request
            .retrieval_snapshot
            .as_ref()
            .ok_or("semantic source handle absent")?;
        window.encoder.validate()?;
        crate::object::id_bytes(&window.index_identity)?;
        if window.artifact_snapshot != source.artifact_snapshot
            || window.graph_root != source.graph_root
            || window.source_snapshot.as_ref() != Some(&source.snapshot_id)
            || window.corpus_digest != digest_value(source)
            || window.query_digest != digest_value(&query)
            || window.top_k != top_k
            || window.corpus_proofs != source.proof_count
            || !window.complete_corpus_scan
            || window.original_source_available
            || window.results.len() != usize::from(top_k).min(source.proof_count)
        {
            return Err("semantic received window source or query binding differs".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut previous: Option<&semantic::SemanticHit> = None;
        for hit in &window.results {
            for id in [&hit.proof_id, &hit.statement_id, &hit.content_digest] {
                crate::object::id_bytes(id)?;
            }
            if !seen.insert(&hit.proof_id)
                || !hit.score.is_finite()
                || !(-1.0..=1.0).contains(&hit.score)
                || !(1..=semantic::MAX_DOCUMENT_CHUNKS).contains(&hit.document_chunks)
                || hit.matched_chunk >= hit.document_chunks
                || previous.is_some_and(|old| {
                    old.score.total_cmp(&hit.score).is_lt()
                        || (old.score.total_cmp(&hit.score).is_eq() && old.proof_id >= hit.proof_id)
                })
            {
                return Err("semantic received window order, score or chunks differ".into());
            }
            previous = Some(hit);
        }
    }
    let call = parse_call(
        "semantic_search",
        &json!({"request_id":request.identity(), "query":query, "top_k":top_k}),
    )?;
    let expected = digest_value(&(
        &call.request_id,
        &operation_identity(&call)?,
        &window.index_identity,
        &window.encoder,
        &window.query_digest,
        &window.results,
    ));
    if query_id != expected {
        return Err("semantic received complete window identity differs".into());
    }
    Ok(())
}
