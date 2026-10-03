use super::{
    auth::{Attempt, model_catalog, model_diagnostics},
    stream::Stream,
};
use crate::node::budget::Usage;
use serde_json::{Value, json};

fn usage() -> Value {
    json!({"input_tokens":20,"output_tokens":7,"total_tokens":27,"input_tokens_details":{"cached_tokens":3},"output_tokens_details":{"reasoning_tokens":2}})
}
fn terminal(status: &str, reported: Value, text: &str) -> Value {
    json!({"type":format!("response.{status}"),"sequence_number":1,"response":{"id":"resp_fixture","status":status,"usage":reported,
        "output":[{"type":"message","role":"assistant","id":"msg_fixture","content":[{"type":"output_text","text":text}]}]}})
}
fn frame(event: &Value) -> Vec<u8> {
    format!(
        "event: {}\ndata: {}\n\n",
        event["type"].as_str().unwrap(),
        event
    )
    .into_bytes()
}

#[test]
fn chunk_boundaries_and_identical_terminal_duplicate_charge_one_response() {
    let event = terminal("completed", usage(), "{\"question_id\":\"x\",\"yes\":true}");
    let bytes = frame(&event);
    let mut stream = Stream::new(4096);
    for byte in &bytes {
        stream.feed(&[*byte]).unwrap();
    }
    stream.feed(&bytes).unwrap();
    let reply = stream.finish().unwrap();
    assert_eq!(
        Usage::from_complete_provider(&reply.usage).unwrap().total,
        27
    );
    assert_eq!(reply.usage["responseUsage"].as_array().unwrap().len(), 1);
    assert_eq!(reply.value["yes"], true);
}
#[test]
fn malformed_or_conflicting_evidence_never_exposes_complete_usage() {
    for mutation in [
        "missing",
        "null",
        "negative",
        "fraction",
        "sum",
        "cached",
        "reasoning",
        "detail_type",
    ] {
        let mut reported = usage();
        match mutation {
            "missing" => {
                reported.as_object_mut().unwrap().remove("input_tokens");
            }
            "null" => reported = Value::Null,
            "negative" => reported["output_tokens"] = json!(-1),
            "fraction" => reported["input_tokens"] = json!(1.5),
            "sum" => reported["total_tokens"] = json!(26),
            "cached" => reported["input_tokens_details"]["cached_tokens"] = json!(21),
            "reasoning" => reported["output_tokens_details"]["reasoning_tokens"] = json!(8),
            "detail_type" => reported["input_tokens_details"] = json!("invalid"),
            _ => unreachable!(),
        }
        let mut stream = Stream::new(4096);
        stream
            .feed(&frame(&terminal("completed", reported, "{}")))
            .unwrap();
        assert!(stream.finish().is_err(), "{mutation}");
        assert_eq!(stream.usage()["complete"], false, "{mutation}");
    }
    for tail in [
        b"data: {invalid}\n\n".as_slice(),
        b"data: incomplete".as_slice(),
    ] {
        let mut stream = Stream::new(4096);
        stream
            .feed(&frame(&terminal("completed", usage(), "{}")))
            .unwrap();
        let _ = stream.feed(tail);
        assert!(stream.finish().is_err());
        assert_eq!(stream.usage()["complete"], false);
    }
    let mut stream = Stream::new(4096);
    stream
        .feed(&frame(&terminal("completed", usage(), "{}")))
        .unwrap();
    let mut conflict = terminal("completed", usage(), "{}");
    conflict["sequence_number"] = json!(2);
    conflict["response"]["usage"]["output_tokens"] = json!(8);
    assert!(stream.feed(&frame(&conflict)).is_err());
    assert_eq!(stream.usage()["complete"], false);
}
#[test]
fn unusable_model_text_and_failed_response_retain_valid_terminal_usage() {
    for (status, text) in [
        ("completed", "not json"),
        ("failed", "{}"),
        ("incomplete", "{}"),
    ] {
        let mut stream = Stream::new(4096);
        stream
            .feed(&frame(&terminal(status, usage(), text)))
            .unwrap();
        assert!(stream.finish().is_err());
        assert_eq!(
            Usage::from_complete_provider(&stream.usage())
                .unwrap()
                .total,
            27
        );
    }
}
#[test]
fn foreign_response_sequence_and_text_contradictions_halt_accounting() {
    for fault in ["foreign_id", "sequence", "text"] {
        let mut stream = Stream::new(4096);
        let start = json!({"type":"response.output_text.delta","sequence_number":0,"response_id":"resp_fixture","item_id":"msg_fixture","delta":"{}"});
        stream.feed(&frame(&start)).unwrap();
        let mut end = terminal("completed", usage(), "{}");
        match fault {
            "foreign_id" => end["response"]["id"] = json!("foreign"),
            "sequence" => end["sequence_number"] = json!(0),
            "text" => end["response"]["output"][0]["content"][0]["text"] = json!("{\"yes\":true}"),
            _ => unreachable!(),
        }
        assert!(stream.feed(&frame(&end)).is_err(), "{fault}");
        assert_eq!(stream.usage()["complete"], false);
    }
}
#[test]
fn registration_callback_binds_state_issued_client_and_returning_identity() {
    let first = Attempt::new(
        "http://127.0.0.1:9000/auth/callback".into(),
        "dynamic_agent_client".into(),
        "urn:uuid:00112233-4455-4677-8899-aabbccddeeff".into(),
        None,
        false,
    )
    .unwrap();
    let url = first
        .url("https://auth.openai.com/api/accounts/authorize")
        .unwrap();
    let q = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(q["agent_name_hint"], "NAOME");
    assert_eq!(q["code_challenge_method"], "S256");
    assert!(
        first
            .callback(&format!("/auth/callback?state={}&code=x", first.state))
            .is_err()
    );
    assert!(
        first
            .callback("/auth/callback?state=wrong&code=x&client_id=client_a")
            .is_err()
    );
    assert!(
        first
            .callback(&format!(
                "/auth/callback?state={}&state={}&code=x&client_id=client_a",
                first.state, first.state
            ))
            .is_err()
    );
    assert_eq!(
        first
            .callback(&format!(
                "/auth/callback?state={}&code=x&client_id=client_a",
                first.state
            ))
            .unwrap(),
        ("x".into(), "client_a".into())
    );
    let returning = Attempt::new(
        first.redirect.clone(),
        "client_a".into(),
        first.host.clone(),
        None,
        true,
    )
    .unwrap();
    assert!(
        !returning
            .url("https://auth.openai.com/api/accounts/authorize")
            .unwrap()
            .query_pairs()
            .any(|(k, _)| k == "agent_name_hint")
    );
    assert!(
        returning
            .callback(&format!(
                "/auth/callback?state={}&code=x&client_id=client_b",
                returning.state
            ))
            .is_err()
    );
}
#[test]
fn siwc_catalog_is_account_authoritative_and_uses_server_visibility() {
    let visible = json!({"slug":"gpt-6-luna","display_name":"GPT-6 Luna","visibility":"list"});
    assert_eq!(
        model_catalog(&json!({"models":[{"slug":"hidden","visibility":"hidden"},visible]}))
            .unwrap()[0]
            .slug,
        "gpt-6-luna"
    );
    assert!(model_catalog(&json!({"data":[{"id":"gpt-6-luna"}]})).is_err());
    assert!(model_catalog(&json!({"models":[visible.clone(),visible]})).is_err());
}

#[test]
fn catalog_diagnostic_distinguishes_membership_without_changing_the_picker() {
    for (visibility, presence) in [
        ("list", "present_visible"),
        ("hidden", "present_hidden"),
        ("deprecated", "present_not_listed"),
    ] {
        let body = json!({"private_auth_field":"DO_NOT_EXPORT_AUTH",
            "models":[{"slug":"gpt-6-luna","display_name":"GPT-6 Luna","visibility":visibility,
                "supports_verbosity":false,"supported_in_api":true,
                "arbitrary_private_metadata":"DO_NOT_EXPORT_MODEL"}]});
        let report = model_diagnostics(&body, "gpt-6-luna").unwrap();
        assert_eq!(report["presence"], presence);
        assert_eq!(report["row_count"], 1);
        assert_eq!(report["listed_count"], usize::from(visibility == "list"));
        assert_eq!(
            report["models"][0]["capabilities"],
            json!({"supports_verbosity":false,"supported_in_api":true})
        );
        assert!(!report.to_string().contains("DO_NOT_EXPORT"));
        assert_eq!(
            model_catalog(&body).unwrap().len(),
            usize::from(visibility == "list")
        );
        assert_eq!(
            model_diagnostics(&body, "absent-model").unwrap()["presence"],
            "absent"
        );
    }
    let hidden_without_name = json!({"models":[{"slug":"gpt-6-luna","visibility":"hidden"}]});
    let report = model_diagnostics(&hidden_without_name, "gpt-6-luna").unwrap();
    assert_eq!(report["presence"], "present_hidden");
    assert!(report["models"][0]["display_name"].is_null());
}

#[test]
fn catalog_diagnostic_rejects_malformed_and_oversized_public_fields_safely() {
    let row = json!({"slug":"gpt-6-luna","display_name":"GPT-6 Luna","visibility":"list"});
    for (key, value) in [
        ("slug", json!("")),
        ("slug", json!("s".repeat(129))),
        ("display_name", json!("n".repeat(257))),
        ("display_name", json!(false)),
        ("visibility", json!(null)),
        ("visibility", json!("v".repeat(65))),
        ("visibility", json!("list\n")),
        ("supports_verbosity", json!("DO_NOT_EXPORT")),
    ] {
        let mut invalid = row.clone();
        invalid[key] = value;
        let error = model_diagnostics(&json!({"models":[invalid]}), "gpt-6-luna").unwrap_err();
        assert!(!error.contains("DO_NOT_EXPORT"));
    }
    for body in [
        json!({"data":[{"id":"gpt-6-luna"}]}),
        json!({"models":null}),
        json!({"models":[row.clone(),row.clone()]}),
        json!({"models":vec![row;513]}),
    ] {
        assert!(model_diagnostics(&body, "gpt-6-luna").is_err());
    }
    for requested in ["".to_owned(), "s".repeat(129), "model\r\n".to_owned()] {
        assert!(model_diagnostics(&json!({"models":[]}), &requested).is_err());
    }
}

#[test]
fn catalog_cache_diagnostic_exports_only_recognized_flags_and_numeric_values() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("age", "42".parse().unwrap());
    headers.insert(
        "cache-control",
        "private, max-age=60, no-store, extension=DO_NOT_EXPORT"
            .parse()
            .unwrap(),
    );
    headers.insert("set-cookie", "DO_NOT_EXPORT_COOKIE".parse().unwrap());
    headers.insert("etag", "DO_NOT_EXPORT_ETAG".parse().unwrap());
    let report = super::http::catalog_cache_metadata(&headers);
    assert_eq!(report["age_seconds"], 42);
    assert_eq!(
        report["recognized_cache_control"],
        json!({"private":true,"max-age":60,"no-store":true})
    );
    assert!(!report.to_string().contains("DO_NOT_EXPORT"));
    headers.insert("age", "-1".parse().unwrap());
    headers.insert(
        "cache-control",
        "max-age=DO_NOT_EXPORT, no-cache=DO_NOT_EXPORT"
            .parse()
            .unwrap(),
    );
    let report = super::http::catalog_cache_metadata(&headers);
    assert!(report["age_seconds"].is_null());
    assert_eq!(report["recognized_cache_control"], json!({}));
}

mod http;

#[test]
fn crlf_comments_multiline_data_and_split_utf8_have_one_terminal_meaning() {
    let event = terminal("completed", usage(), "{\"text\":\"λ\"}");
    let pretty = serde_json::to_string_pretty(&event).unwrap();
    let mut wire = ": comment\r\nevent: response.completed\r\n".to_owned();
    for line in pretty.lines() {
        wire.push_str(&format!("data: {line}\r\n"));
    }
    wire.push_str("\r\n");
    let mut stream = Stream::new(4096);
    for byte in wire.as_bytes() {
        stream.feed(&[*byte]).unwrap();
    }
    assert_eq!(stream.finish().unwrap().value["text"], "λ");
    let mut early = Stream::new(4096);
    early.feed(&frame(&json!({"type":"response.output_text.done","sequence_number":0,"text":"{}","item_id":"msg_fixture"}))).unwrap();
    assert!(early.finish().is_err());
    assert_eq!(early.usage()["complete"], false);
}
#[test]
fn refused_output_retains_known_usage_and_stream_overrun_revokes_completeness() {
    let mut refused = terminal("completed", usage(), "{}");
    refused["response"]["output"][0]["content"] =
        json!([{"type":"refusal","refusal":"Fixture refusal"}]);
    let mut stream = Stream::new(4096);
    stream.feed(&frame(&refused)).unwrap();
    assert!(stream.finish().is_err());
    assert_eq!(
        Usage::from_complete_provider(&stream.usage())
            .unwrap()
            .total,
        27
    );
    assert_eq!(
        stream.receipt["terminal_response"]["output"][0]["content"][0]["refusal"],
        "Fixture refusal"
    );
    let mut stream = Stream::new(4096);
    stream
        .feed(&frame(&terminal("completed", usage(), "{}")))
        .unwrap();
    assert!(stream.feed(&vec![b' '; 4096]).is_err());
    assert_eq!(stream.usage()["complete"], false);
}

#[test]
fn diagnostic_identifier_fields_do_not_retain_secret_shaped_upstream_values() {
    let value = super::http::diagnostic(
        403,
        &json!({"error":{"code":"access-new","param":"never-log-this-upstream-body","message":"refresh-new"},"token_secret_example":"pkce-verifier-only"}),
        json!("fixture-request"),
    );
    let text = value.to_string();
    for secret in [
        "access-new",
        "never-log-this-upstream-body",
        "refresh-new",
        "pkce-verifier-only",
        "token_secret_example",
    ] {
        assert!(!text.contains(secret));
    }
    assert_eq!(value["error_code"], "unrecognized_error_code");
    assert_eq!(value["error_param"], "unrecognized_parameter");
    assert_eq!(value["body_fields"], json!(["error"]));
    assert_eq!(value["body_field_count"], 2);
    let known = super::http::diagnostic(
        400,
        &json!({"error":{"code":"subscription_sharing_unsupported_capability","param":"tools"}}),
        json!("fixture-request"),
    );
    assert_eq!(
        known["error_code"],
        "subscription_sharing_unsupported_capability"
    );
    assert_eq!(known["error_param"], "tools");
}
