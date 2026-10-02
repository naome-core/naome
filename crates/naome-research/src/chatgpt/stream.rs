//! One HTTP response, bounded SSE decoding and explicit terminal token evidence.

use super::{
    auth::Session,
    http::{diagnostic, network_error, read_json, request_id},
};
use crate::{
    node::{ProviderOutcome, budget::Usage},
    provider::{MAX_INPUT_BYTES, ProviderConfig, ProviderError, ProviderErrorKind, ProviderReply},
};
use serde_json::{Value, json};
use std::sync::{Arc, atomic::AtomicBool};

const MAX_EVENTS: usize = 4096;

pub(super) struct Stream {
    pending: Vec<u8>,
    maximum: usize,
    bytes: usize,
    events: usize,
    response_id: Option<String>,
    item_id: Option<String>,
    pub text: String,
    partial_usage: Option<Value>,
    terminal_usage: Option<Value>,
    terminal_digest: Option<[u8; 32]>,
    status: Option<String>,
    sequence: Option<(u64, [u8; 32])>,
    invalid: bool,
    failure: Option<ProviderError>,
    pub receipt: Value,
}
impl Stream {
    pub fn new(maximum: usize) -> Self {
        Self {
            pending: vec![],
            maximum,
            bytes: 0,
            events: 0,
            response_id: None,
            item_id: None,
            text: String::new(),
            partial_usage: None,
            terminal_usage: None,
            terminal_digest: None,
            status: None,
            sequence: None,
            invalid: false,
            failure: None,
            receipt: json!({"route":"public_responses_siwc","http_post_attempts":0,"automatic_post_retries":0}),
        }
    }
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), ProviderError> {
        let result = self.feed_inner(chunk);
        if result.is_err() {
            self.invalid = true;
        }
        result
    }
    fn feed_inner(&mut self, chunk: &[u8]) -> Result<(), ProviderError> {
        self.bytes = self
            .bytes
            .checked_add(chunk.len())
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| ProviderError::contract("Direct SSE stream exceeds its byte bound"))?;
        self.pending.extend_from_slice(chunk);
        loop {
            let delimiter = [
                self.pending
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|i| (i, 4)),
                self.pending
                    .windows(2)
                    .position(|w| w == b"\n\n")
                    .map(|i| (i, 2)),
            ]
            .into_iter()
            .flatten()
            .min_by_key(|(i, _)| *i);
            let Some((end, size)) = delimiter else {
                break;
            };
            let block = self.pending[..end].to_vec();
            self.pending.drain(..end + size);
            let text = std::str::from_utf8(&block)
                .map_err(|_| ProviderError::contract("Invalid direct SSE UTF-8"))?;
            let mut data = String::new();
            let mut kind: Option<&str> = None;
            for line in text.split('\n') {
                let line = line.trim_end_matches('\r');
                if line.starts_with(':') || line.is_empty() {
                    continue;
                }
                let (name, value) = line.split_once(':').unwrap_or((line, ""));
                let value = value.strip_prefix(' ').unwrap_or(value);
                match name {
                    "event" => {
                        if kind.replace(value).is_some() {
                            return self.reject("Conflicting SSE event labels");
                        }
                    }
                    "data" => {
                        if !data.is_empty() {
                            data.push('\n');
                        }
                        data.push_str(value);
                    }
                    "id" | "retry" => {}
                    _ => {}
                }
            }
            if data.is_empty() {
                continue;
            }
            self.events += 1;
            if self.events > MAX_EVENTS {
                return self.reject("Direct SSE event operation bound exceeded");
            }
            if data == "[DONE]" {
                if self.status.is_none() {
                    return self.reject("Direct stream ended without a terminal response");
                }
                continue;
            }
            let event: Value = serde_json::from_str(&data)
                .map_err(|_| ProviderError::contract("Invalid direct SSE JSON"))?;
            let event_kind = event["type"]
                .as_str()
                .ok_or_else(|| ProviderError::contract("Direct SSE event type missing"))?;
            if kind.is_some_and(|label| label != event_kind) {
                return self.reject("Direct SSE event label/value mismatch");
            }
            self.event(&event)?;
        }
        Ok(())
    }
    fn reject<T>(&mut self, message: &str) -> Result<T, ProviderError> {
        self.invalid = true;
        Err(ProviderError::contract(message))
    }
    fn bind(&mut self, id: &str) -> Result<(), ProviderError> {
        if id.is_empty() || id.len() > 256 {
            return self.reject("Invalid direct response identity");
        }
        match &self.response_id {
            Some(old) if old != id => {
                self.reject("Direct request returned conflicting response identities")
            }
            Some(_) => Ok(()),
            None => {
                self.response_id = Some(id.into());
                Ok(())
            }
        }
    }
    fn event(&mut self, event: &Value) -> Result<(), ProviderError> {
        let kind = event["type"]
            .as_str()
            .ok_or_else(|| ProviderError::contract("Direct SSE event type missing"))?;
        let sequence = event["sequence_number"].as_u64().ok_or_else(|| {
            ProviderError::contract("Direct SSE sequence number missing or invalid")
        })?;
        let digest = crate::state::hash(b"naome:siwc:event:v1\0", event);
        if let Some((previous, previous_digest)) = self.sequence {
            if sequence == previous && digest == previous_digest {
                return Ok(());
            }
            if sequence <= previous {
                return self.reject("Direct SSE event sequence regressed or conflicted");
            }
        }
        self.sequence = Some((sequence, digest));
        if let Some(value) = event.get("response_id") {
            let id = value
                .as_str()
                .ok_or_else(|| ProviderError::contract("Malformed direct response identity"))?;
            self.bind(id)?;
        }
        if self.status.is_some()
            && !matches!(
                kind,
                "response.completed" | "response.failed" | "response.incomplete"
            )
        {
            return self.reject("Direct stream continued after its terminal response");
        }
        if let Some(response) = event.get("response") {
            let id = response["id"]
                .as_str()
                .ok_or_else(|| ProviderError::contract("Direct response identity missing"))?;
            self.bind(id)?;
            if !response["usage"].is_null()
                && !matches!(
                    kind,
                    "response.completed" | "response.failed" | "response.incomplete"
                )
            {
                let usage = adapt_usage(&response["usage"], id, false, kind)?;
                if let Some(previous) = &self.partial_usage {
                    let old = Usage::from_provider(previous)
                        .map_err(|_| ProviderError::contract("Invalid partial usage ledger"))?;
                    let next = Usage::from_provider(&usage)
                        .map_err(|_| ProviderError::contract("Invalid partial direct usage"))?;
                    if !next.follows(&old) {
                        return self.reject("Direct partial usage regressed");
                    }
                }
                self.partial_usage = Some(usage);
            }
        }
        match kind {
            "response.output_item.added" => {
                if event["item"]["type"] == "message" {
                    let id = event["item"]["id"].as_str().ok_or_else(|| {
                        ProviderError::contract("Direct message item identity missing")
                    })?;
                    if self.item_id.as_ref().is_some_and(|old| old != id) {
                        self.failure = Some(ProviderError::contract(
                            "Multiple direct output messages are unsupported",
                        ));
                    } else {
                        self.item_id = Some(id.into());
                    }
                }
            }
            "response.output_text.delta" => {
                if let Some(id) = event["item_id"].as_str() {
                    if self.item_id.as_ref().is_some_and(|old| old != id) {
                        return self.reject("Direct text item identity mismatch");
                    }
                    self.item_id = Some(id.into());
                }
                let delta = event["delta"]
                    .as_str()
                    .ok_or_else(|| ProviderError::contract("Direct text delta missing"))?;
                if self.text.len() + delta.len() > self.maximum {
                    return self.reject("Direct model text exceeds its operation bound");
                }
                self.text.push_str(delta);
            }
            "response.completed" | "response.failed" | "response.incomplete" => {
                let response = &event["response"];
                let id = self.response_id.clone().ok_or_else(|| {
                    ProviderError::contract("Terminal direct response identity missing")
                })?;
                let expected = kind
                    .strip_prefix("response.")
                    .ok_or_else(|| ProviderError::contract("Invalid terminal response type"))?;
                if response["status"] != expected {
                    return self.reject("Terminal response status mismatch");
                }
                let digest = crate::state::hash(b"naome:siwc:terminal:v1\0", response);
                if let Some(previous) = self.terminal_digest {
                    if previous != digest {
                        return self.reject("Conflicting direct terminal response");
                    }
                    return Ok(());
                }
                self.terminal_digest = Some(digest);
                self.status = Some(expected.into());
                self.receipt["terminal_response"] = response.clone();
                self.receipt["terminal_digest"] = json!(crate::state::hex(&digest));
                if let Some(items) = response["output"].as_array() {
                    for item in items.iter().filter(|item| item["type"] == "message") {
                        if self
                            .item_id
                            .as_ref()
                            .is_some_and(|old| item["id"].as_str() != Some(old.as_str()))
                        {
                            return self.reject(
                                "Terminal output item identity differs from streamed item",
                            );
                        }
                    }
                }
                // Missing/null terminal usage is never replaced by a prefix,
                // estimated output size, response count or cached total.
                let usage = adapt_usage(&response["usage"], &id, true, kind);
                match usage {
                    Ok(usage) => {
                        if let Some(partial) = &self.partial_usage {
                            let before = Usage::from_provider(partial).map_err(|_| {
                                ProviderError::contract("Invalid partial usage ledger")
                            })?;
                            let after = Usage::from_complete_provider(&usage).map_err(|_| {
                                ProviderError::contract("Invalid direct terminal usage")
                            })?;
                            if !after.follows(&before) {
                                return self.reject("Direct terminal usage regressed");
                            }
                        }
                        self.terminal_usage = Some(usage);
                    }
                    Err(error) => {
                        self.invalid = true;
                        self.failure = Some(error);
                    }
                }
                if expected != "completed" {
                    self.receipt["terminal_error"] = diagnostic(200, response, Value::Null);
                    self.failure = Some(error_for(&response["error"]["code"]));
                }
                match model_text(response) {
                    Ok(text) => {
                        if !self.text.is_empty() && self.text != text {
                            return self.reject("Terminal model text differs from streamed text");
                        }
                        self.text = text;
                    }
                    Err(error) => {
                        self.failure = Some(error);
                    }
                }
            }
            "error" => {
                self.failure = Some(error_for(&event["code"]));
                self.receipt["stream_error"] = diagnostic(200, event, Value::Null);
            }
            _ => {}
        }
        Ok(())
    }
    pub fn usage(&self) -> Value {
        if !self.invalid
            && let Some(usage) = &self.terminal_usage
        {
            return usage.clone();
        }
        let mut value = self
            .terminal_usage
            .clone()
            .or_else(|| self.partial_usage.clone())
            .unwrap_or_else(|| json!({"complete":false}));
        value["complete"] = json!(false);
        value
    }
    pub fn finish(&mut self) -> Result<ProviderReply, ProviderError> {
        self.finish_terminal()?;
        let value = serde_json::from_str(&self.text)
            .map_err(|_| ProviderError::contract("Completed model text is not strict JSON"))?;
        Ok(ProviderReply {
            value,
            raw_response: self.text.clone(),
            usage: self.usage(),
            computation: vec![],
        })
    }
    pub(super) fn finish_terminal(&mut self) -> Result<(), ProviderError> {
        if !self.pending.iter().all(u8::is_ascii_whitespace) {
            return self.reject("Direct stream ended inside an SSE event");
        }
        if self.status.is_none() {
            return self.reject("Direct stream ended without terminal usage evidence");
        }
        self.receipt["response_id"] = json!(self.response_id);
        self.receipt["terminal_status"] = json!(self.status);
        self.receipt["stream_bytes"] = json!(self.bytes);
        self.receipt["stream_events"] = json!(self.events);
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if self.status.as_deref() != Some("completed") || self.invalid {
            return Err(ProviderError::contract(
                "Direct inference did not complete with valid explicit usage",
            ));
        }
        Ok(())
    }
    pub fn transport_failed(&mut self) {
        self.invalid = true;
    }
}
fn adapt_usage(
    raw: &Value,
    id: &str,
    complete: bool,
    source: &str,
) -> Result<Value, ProviderError> {
    let optional = |parent: &str, field: &str| -> Result<Value, ProviderError> {
        match raw.get(parent) {
            None | Some(Value::Null) => Ok(json!(0)),
            Some(Value::Object(object)) => Ok(object.get(field).cloned().unwrap_or(json!(0))),
            Some(_) => Err(ProviderError::contract(
                "Malformed direct usage detail object",
            )),
        }
    };
    let total = json!({"inputTokens":raw["input_tokens"],"outputTokens":raw["output_tokens"],"totalTokens":raw["total_tokens"],
        "cachedInputTokens":optional("input_tokens_details","cached_tokens")?,"reasoningOutputTokens":optional("output_tokens_details","reasoning_tokens")?});
    Usage::from_provider(&json!({"total":total})).map_err(|_| {
        ProviderError::contract("Direct response usage missing, malformed or inconsistent")
    })?;
    let mut response = total.clone();
    response["responseId"] = json!(id);
    let value = json!({"complete":complete,"total":total,"responseUsage":[response],"source":format!("{source}.usage"),"official_usage":raw});
    if complete {
        Usage::from_complete_provider(&value)
            .map_err(|_| ProviderError::contract("Direct terminal usage ledger inconsistent"))?;
    }
    Ok(value)
}
fn model_text(response: &Value) -> Result<String, ProviderError> {
    let output = response["output"]
        .as_array()
        .ok_or_else(|| ProviderError::contract("Direct response output missing"))?;
    let mut text = None;
    for item in output {
        if item["type"] == "reasoning" {
            continue;
        }
        if item["type"] != "message" || item["role"] != "assistant" {
            return Err(ProviderError::contract(
                "Unsupported direct output item; no tools are executed",
            ));
        }
        let content = item["content"]
            .as_array()
            .ok_or_else(|| ProviderError::contract("Direct message content missing"))?;
        for part in content {
            if part["type"] != "output_text" || text.is_some() {
                return Err(ProviderError::contract(
                    "Direct output refused or contained multiple text parts",
                ));
            }
            text = Some(
                part["text"]
                    .as_str()
                    .ok_or_else(|| ProviderError::contract("Direct output text missing"))?
                    .to_owned(),
            );
        }
    }
    text.ok_or_else(|| ProviderError::contract("Direct response contains no model text"))
}
fn error_for(code: &Value) -> ProviderError {
    match code.as_str() {
        Some("subscription_sharing_usage_limit_exceeded") => ProviderError::new(
            ProviderErrorKind::Quota,
            "ChatGPT usage limit reached; Manage usage at https://chatgpt.com/settings/usage",
        ),
        Some(
            "subscription_sharing_user_not_eligible"
            | "chatpass_v2_scope_not_authorized"
            | "chatpass_v2_invalid_authorization_context"
            | "subscription_sharing_invalid_user",
        ) => ProviderError::new(
            ProviderErrorKind::Auth,
            "Selected ChatGPT plan permission or account is unavailable",
        ),
        Some(
            "subscription_sharing_usage_unavailable" | "subscription_sharing_user_unavailable",
        ) => ProviderError::new(
            ProviderErrorKind::Transient,
            "ChatGPT usage availability could not be checked; preserve credentials and pause",
        ),
        _ => ProviderError::contract("Direct Responses reported failed or incomplete inference"),
    }
}

pub(super) fn body(
    provider: &ProviderConfig,
    prompt: &str,
    schema: Value,
) -> Result<Value, ProviderError> {
    if prompt.len() > MAX_INPUT_BYTES
        || serde_json::to_vec(&schema)
            .map_err(|_| ProviderError::contract("Invalid output schema"))?
            .len()
            > MAX_INPUT_BYTES
    {
        return Err(ProviderError::contract(
            "Direct request exceeds its input/schema bound",
        ));
    }
    Ok(
        json!({"model":provider.model,"instructions":"You are a mathematical research participant. Follow the task exactly. Return only the JSON required by its strict schema. No tools, subagents, additional questions or unverifiable claims.",
        "input":[{"role":"user","content":prompt}],"store":false,"stream":true,
        "text":{"format":{"type":"json_schema","name":"naome_research_phase","strict":true,"schema":schema}}}),
    )
}
pub(crate) fn request(
    provider: &ProviderConfig,
    prompt: &str,
    schema: Value,
    cancel: Arc<AtomicBool>,
) -> ProviderOutcome {
    let mut stream = Stream::new(provider.max_output_bytes);
    let result = (|| {
        let config = provider
            .responses
            .as_ref()
            .ok_or_else(|| ProviderError::contract("Direct route not selected"))?;
        let session = Session::open(config, cancel, provider.timeout_seconds).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Auth,
                "SIWC selected-session renewal failed; no inference fallback",
            )
        })?;
        request_with_session(provider, prompt, schema, &session, &mut stream)
    })();
    let raw = if stream.text.is_empty() {
        None
    } else {
        Some(stream.text.clone())
    };
    ProviderOutcome::from_provider_result(result, stream.usage(), stream.receipt, raw)
}
pub(super) fn request_with_session(
    provider: &ProviderConfig,
    prompt: &str,
    schema: Value,
    session: &Session,
    stream: &mut Stream,
) -> Result<ProviderReply, ProviderError> {
    let payload = body(provider, prompt, schema)?;
    let token = session.token().map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::Auth,
            "Selected SIWC account is not authorized for ChatGPT plan usage",
        )
    })?;
    session.require_model(&provider.model).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::Auth,
            "Selected SIWC account/model preflight failed",
        )
    })?;
    stream.receipt["account_id"] = json!(session.record.info.account_id);
    stream.receipt["client_id"] = json!(session.record.info.client_id);
    stream.receipt["model"] = json!(provider.model);
    stream.receipt["using_chatgpt_plan"] = json!(true);
    let result = session.http.run(async {
        stream.receipt["http_post_attempts"] = json!(1);
        let response = session
            .http
            .client
            .post(format!("{}/responses", session.http.endpoints.api))
            .bearer_auth(token)
            .json(&payload)
            .header("Accept", "text/event-stream")
            .send()
            .await
            .map_err(network_error)?;
        let status = response.status().as_u16();
        let id = request_id(&response);
        stream.receipt["http_status"] = json!(status);
        stream.receipt["request_id"] = id.clone();
        if status != 200 {
            let (_, value, _) = read_json(response, provider.max_output_bytes).await?;
            stream.receipt["http_error"] = diagnostic(status, &value, id);
            return Err(error_for(&value["error"]["code"]));
        }
        if response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_none_or(|s| s.split(';').next() != Some("text/event-stream"))
        {
            return Err(ProviderError::contract(
                "Direct response is not an SSE stream",
            ));
        }
        let mut response = response;
        while let Some(chunk) = response.chunk().await.map_err(network_error)? {
            stream.feed(&chunk)?;
        }
        Ok(())
    });
    if let Err(error) = result {
        stream.transport_failed();
        return Err(error);
    }
    stream.finish()
}
