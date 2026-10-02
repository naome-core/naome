//! Explicit nonresearch access diagnosis. Each invocation can make one POST;
//! the operator must persist its external one-attempt authorization before use.
//! This does not select a research model or create a profile or sample grant.

use super::{
    RESOURCE, ResponsesConfig,
    auth::Session,
    http::{diagnostic, network_error, read_json, request_id},
    stream::Stream,
};
use crate::provider::{ProviderError, ProviderErrorKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, atomic::AtomicBool};

const MAX_ACCESS_BYTES: usize = 16 * 1024;

fn validate_model(model: &str) -> Result<(), String> {
    if model.is_empty()
        || model.len() > 128
        || !model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("Invalid access-diagnostic model slug".into());
    }
    Ok(())
}

/// A separately authorized diagnostic, independent of the research catalog gate.
/// Normal management and transport share one 90-second Session deadline.
pub fn diagnose_model_access(
    config: &ResponsesConfig,
    model: &str,
    cancel: Arc<AtomicBool>,
) -> Result<Value, String> {
    validate_model(model)?;
    config.validate()?;
    match Session::open(config, cancel, 90) {
        Ok(session) => diagnose_with_session(&session, model),
        Err(_) => {
            let mut report = initial_report(model);
            report["failure"] = json!("Selected Session preparation failed; no Responses POST");
            Ok(report)
        }
    }
}

fn initial_report(model: &str) -> Value {
    json!({"version":1,"purpose":"nonresearch_model_access_diagnostic",
        "endpoint":format!("{RESOURCE}/responses"),"requested_model":model,
        "response_post_attempts":0,"catalog_get_attempts":0,"automatic_post_retries":0,
        "http_status":null,"request_id":null,"http_error":null,"failure":null,
        "access_qualified":false,"completed":false,"terminal_status":null,
        "returned_model":null,"returned_model_matches":false,
        "usage":{"complete":false,"total":null},"consumption":"not_contacted",
        "output_matches_ok":false,"output_bytes":0,"output_sha256":null,
        "limit":"Access diagnosis does not authorize research selection or create a research grant; retain the external one-attempt allowance"})
}

fn safe_request_id(value: Value) -> Value {
    let Some(text) = value.as_str() else {
        return Value::Null;
    };
    let request = text
        .strip_prefix("req_")
        .is_some_and(|tail| tail.len() == 32 && tail.bytes().all(|b| b.is_ascii_hexdigit()));
    let uuid = text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        });
    if request || uuid { value } else { Value::Null }
}

pub(super) fn diagnose_with_session(session: &Session, model: &str) -> Result<Value, String> {
    validate_model(model)?;
    let mut report = initial_report(model);
    let mut stream = Stream::new(MAX_ACCESS_BYTES);
    let result = (|| {
        let token = session.token().map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::Auth,
                "Selected account lacks direct plan permission",
            )
        })?;
        let transport = session.http.run(async {
            report["response_post_attempts"] = json!(1);
            report["consumption"] = json!("unknown");
            let response = session.http.client
                .post(format!("{}/responses", session.http.endpoints.api))
                .bearer_auth(token)
                .header("Accept", "text/event-stream")
                .json(&json!({"model":model,"input":[{"role":"user","content":"Reply with exactly OK."}],"store":false,"stream":true}))
                .send().await.map_err(network_error)?;
            let status = response.status().as_u16();
            let id = safe_request_id(request_id(&response));
            report["http_status"] = json!(status);
            report["request_id"] = id.clone();
            if status != 200 {
                let (_, body, _) = read_json(response, MAX_ACCESS_BYTES).await?;
                let mut error = diagnostic(status, &body, id);
                if body["error"]["code"] == "model_not_found" {
                    error["error_code"] = json!("model_not_found");
                }
                report["http_error"] = error;
                return Err(ProviderError::contract("Responses access diagnostic returned an HTTP error"));
            }
            if response.headers().get("content-type").and_then(|v| v.to_str().ok())
                .is_none_or(|s| s.split(';').next() != Some("text/event-stream"))
            {
                return Err(ProviderError::contract("Access diagnostic did not return SSE"));
            }
            let mut response = response;
            while let Some(chunk) = response.chunk().await.map_err(network_error)? {
                stream.feed(&chunk)?;
            }
            Ok(())
        });
        if transport.is_err() {
            stream.transport_failed();
        }
        transport?;
        stream.finish_terminal()
    })();
    if let Err(error) = result {
        report["failure"] = json!(error.to_string());
    } else {
        report["completed"] = json!(true);
        let returned = stream.receipt["terminal_response"]["model"]
            .as_str()
            .filter(|value| validate_model(value).is_ok());
        // Export only the already validated requested slug, never a foreign field.
        report["returned_model"] = json!(returned.filter(|value| *value == model));
        report["returned_model_matches"] = json!(returned == Some(model));
        report["access_qualified"] = json!(returned == Some(model));
        if returned != Some(model) {
            report["failure"] = json!("Completed response did not identify the requested model");
        }
    }
    let usage = stream.usage();
    report["usage"] = json!({"complete":usage["complete"],"total":usage["total"]});
    if usage["complete"] == true {
        report["consumption"] = json!("reported_terminal_usage");
    }
    report["terminal_status"] = stream.receipt["terminal_status"].clone();
    report["output_matches_ok"] = json!(stream.text == "OK");
    report["output_bytes"] = json!(stream.text.len());
    report["output_sha256"] = json!(crate::state::hex(&Sha256::digest(stream.text.as_bytes())));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_ids_are_public_identifiers_not_arbitrary_header_values() {
        for value in [
            "req_0123456789abcdef0123456789abcdef",
            "01234567-89ab-cdef-0123-456789abcdef",
        ] {
            assert_eq!(safe_request_id(json!(value)), value);
        }
        for value in [
            "sk-DO_NOT_EXPORT",
            "eyJ.DO_NOT_EXPORT",
            "Bearer secret",
            "unrecognized-id",
        ] {
            assert!(safe_request_id(json!(value)).is_null());
        }
    }
}
