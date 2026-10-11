//! Weightless per-job proxy; independently verifies the bound model decision.
use super::{Owner, host, ipc};
use crate::jobs::{Binding, Input, Record};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Session {
    pub client: String,
    pub generation: String,
    pub ready: Value,
}
impl Session {
    pub(crate) fn validate(&self) -> Result<(), String> {
        crate::object::id_bytes(&self.client)?;
        crate::object::id_bytes(&self.generation)?;
        validate_ready(&self.ready)
    }
}

pub(super) fn validate_ready(v: &Value) -> Result<(), String> {
    if v["schema"] != 1
        || v["kind"] != "ready"
        || v["model_revision"] != "1cfa9a7208912126459214e8b04321603b3df60c"
        || v["manifest_hash"] != "b7d4ab43f8cfc348ff7195e64a5e23fb65ceb0eec55a1761030ac1e9478b018b"
        || v["prompt_version"] != "naome:owner-interest:prompt:v1"
        || v["prompt_hash"] != "69afc1b7c184eeb83ed7faa55d7fdcfbc67949f0ed10b0c138eaaf0ff5403f98"
        || v["template_hash"] != "a55ee1b1660128b7098723e0abcd92caa0788061051c62d51cbe87d9cf1974d8"
        || v["device"] != "mps"
        || v["load_strategy"] != "cpu-staged-mps-v1"
        || v["parameter_bytes"] != 8_044_936_192u64
        || v["labels"] != json!({"true":1866,"false":3849})
        || v["model_instance"].as_u64().is_none_or(|x| x == 0)
    {
        return Err("resident model identity differs".into());
    }
    crate::object::id_bytes(
        v["inventory_hash"]
            .as_str()
            .ok_or("model inventory absent")?,
    )?;
    Ok(())
}
fn request(owner: &Owner, question: &str, binding: &Binding, id: String) -> Result<Value, String> {
    let question =
        naome_authoring::CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
    Ok(
        json!({"schema":1,"request_id":id,"profile":{"revision":owner.revision,"text":owner.interest,"hash":owner.profile_hash()},"question":{"source":question.source(),"source_hash":crate::hex(question.source_hash()),"resolution_id":crate::hex(question.resolution_id())},"snapshot":binding.snapshot,"policy":binding.policy}),
    )
}
#[derive(Debug)]
pub(crate) struct Scored {
    pub selected: bool,
    pub response: Value,
}

pub(crate) fn verify_record_decision(record: &Record, response: &Value) -> Result<bool, String> {
    let Input::Interest {
        question,
        owner: Some(owner),
        model: Some(session),
        ..
    } = &record.input
    else {
        return Err("model decision owner/session absent".into());
    };
    owner.validate()?;
    session.validate()?;
    let id = crate::jobs::identity(&(
        record.id,
        &record.binding,
        owner,
        &session.generation,
        &session.client,
    ));
    let envelope = json!({"owner":owner,"generation":session.generation,"transport_id":id,
        "request":request(owner, question, &record.binding, id.clone())?});
    decision(response, &envelope, &session.ready)
}

pub(crate) fn score(
    record: &Record,
    slot_fd: i32,
    remaining_ms: u64,
    deadline_ns: u64,
) -> Result<Scored, String> {
    let Input::Interest {
        question,
        owner: Some(owner),
        model: Some(session),
        ..
    } = &record.input
    else {
        return Err("model dispatch owner/session absent".into());
    };
    owner.validate()?;
    session.validate()?;
    let maximum = remaining_ms
        .min(
            record
                .model_allowance_ms
                .ok_or("durable model grant absent")?,
        )
        .min(20_000);
    let original = record
        .model_deadline_ns
        .ok_or("durable model deadline absent")?;
    if deadline_ns != original || original <= crate::jobs::monotonic_ns()? {
        return Err("model original deadline exhausted before connect".into());
    }
    let (mut channel, endpoint) = host::query_connection()?;
    if endpoint.nonce != session.generation || session.ready["contract"] != endpoint.contract {
        return Err("model generation changed before dispatch".into());
    }
    let remaining = maximum.min(original.saturating_sub(crate::jobs::monotonic_ns()?) / 1_000_000);
    if remaining == 0 {
        return Err("model original deadline exhausted during connect".into());
    }
    channel
        .set_read_timeout(Some(Duration::from_millis(remaining)))
        .map_err(|e| e.to_string())?;
    channel
        .set_write_timeout(Some(Duration::from_millis(remaining)))
        .map_err(|e| e.to_string())?;
    let id = crate::jobs::identity(&(
        record.id,
        &record.binding,
        owner,
        &session.generation,
        &session.client,
    ));
    let req = request(owner, question, &record.binding, id.clone())?;
    let envelope = json!({"kind":"query","nonce":endpoint.nonce,"contract":endpoint.contract,"client":session.client,"generation":session.generation,"transport_id":id,"remaining_ms":remaining,"deadline_ns":original,"owner":owner,"request":req});
    ipc::send(&mut channel, &envelope, Some(slot_fd))?;
    let (response, fds) = ipc::receive(&mut channel)?;
    if !fds.0.is_empty() || crate::jobs::monotonic_ns()? >= original {
        return Err("model response lease or original deadline differs".into());
    }
    let selected = decision(&response, &envelope, &session.ready)?;
    Ok(Scored { selected, response })
}
pub(super) fn decision(v: &Value, e: &Value, ready: &Value) -> Result<bool, String> {
    let allowed = [
        "kind",
        "schema",
        "transport_id",
        "request_id",
        "owner",
        "profile_revision",
        "profile_hash",
        "source_hash",
        "resolution_id",
        "snapshot",
        "policy",
        "generation",
        "selected",
        "reason",
        "input_tokens",
        "inference_ms",
        "restricted_true",
        "label_mass",
        "true_logit",
        "false_logit",
        "log_partition",
        "top_token",
        "device",
        "load_strategy",
        "inventory_hash",
        "model_instance",
    ];
    if v.as_object()
        .is_none_or(|o| o.keys().any(|k| !allowed.contains(&k.as_str())))
        || v["kind"] != "decision"
        || v["schema"] != 1
        || v["transport_id"] != e["transport_id"]
        || v["request_id"] != e["request"]["request_id"]
        || v["owner"] != e["owner"]
        || v["generation"] != e["generation"]
    {
        return Err("model response transport or owner binding differs".into());
    }
    for (field, section, source) in [
        ("profile_revision", "profile", "revision"),
        ("profile_hash", "profile", "hash"),
        ("source_hash", "question", "source_hash"),
        ("resolution_id", "question", "resolution_id"),
    ] {
        if v[field] != e["request"][section][source] {
            return Err("model response input binding differs".into());
        }
    }
    for field in ["snapshot", "policy"] {
        if v[field] != e["request"][field] {
            return Err("model response checked context differs".into());
        }
    }
    for field in [
        "device",
        "load_strategy",
        "inventory_hash",
        "model_instance",
    ] {
        if v[field] != ready[field] {
            return Err("model response resident instance differs".into());
        }
    }
    let selected = v["selected"]
        .as_bool()
        .ok_or("model typed Boolean absent")?;
    let tokens = v["input_tokens"]
        .as_u64()
        .filter(|x| *x <= 4096)
        .ok_or("model input token bound differs")?;
    if v["inference_ms"].as_u64().is_none_or(|x| x > 20_000) {
        return Err("model inference timing differs".into());
    }
    if e["owner"]["interest"]
        .as_str()
        .is_some_and(|x| x.trim().is_empty())
    {
        if selected || v["reason"] != "empty_profile" || tokens != 0 {
            return Err("empty profile result differs".into());
        }
        return Ok(false);
    }
    if tokens == 0 {
        return Err("model forward tokens absent".into());
    }
    let number = |k: &str| {
        v[k].as_f64()
            .filter(|x| x.is_finite())
            .ok_or_else(|| format!("model finite {k} absent"))
    };
    let t = number("true_logit")?;
    let f = number("false_logit")?;
    let partition = number("log_partition")?;
    let top = v["top_token"].as_u64().ok_or("model top token absent")?;
    let max = t.max(f);
    let labels = max + ((t - max).exp() + (f - max).exp()).ln();
    if partition + 1e-5 < labels {
        return Err("model vocabulary partition differs".into());
    }
    let ratio = (t - labels).exp();
    let mass = (labels - partition).exp().min(1.0);
    if (number("restricted_true")? - ratio).abs() > 1e-6
        || (number("label_mass")? - mass).abs() > 1e-6
    {
        return Err("model derived score differs".into());
    }
    if top >= 151936 || top == 1866 && t < f || top == 3849 && f < t {
        return Err("model vocabulary argmax label order differs".into());
    }
    if top != 1866
        && top != 3849
        && partition + 1e-5 < max + (1.0 + (t - max).exp() + (f - max).exp()).ln()
    {
        return Err("model non-label argmax contradicts partition".into());
    }
    let expected = top == 1866 && ratio >= 0.80 && mass >= 0.25;
    let reason = if top != 1866 && top != 3849 || mass < 0.25 {
        "unsupported_output"
    } else if top == 1866 && ratio < 0.80 {
        "ambiguous_output"
    } else if expected {
        "selected"
    } else {
        "not_selected"
    };
    if selected != expected || v["reason"] != reason {
        return Err("model score/Boolean rule differs".into());
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Value) {
        let rows: Vec<Value> =
            serde_json::from_str(include_str!("fixtures/v7-decisions.json")).unwrap();
        let mut response = rows[0].clone();
        let owner = json!({"version":1,"revision":1,"digest":crate::hex(&[1;32]),"interest":"Set theory","text_sha256":crate::hex(&[2;32])});
        response["transport_id"] = response["request_id"].clone();
        response["owner"] = owner.clone();
        response["generation"] = json!(crate::hex(&[3; 32]));
        let envelope = json!({"transport_id":response["transport_id"],"generation":response["generation"],"owner":owner,"request":{"request_id":response["request_id"],"profile":{"revision":response["profile_revision"],"hash":response["profile_hash"]},"question":{"source_hash":response["source_hash"],"resolution_id":response["resolution_id"]},"snapshot":response["snapshot"],"policy":response["policy"]}});
        let ready = json!({"device":response["device"],"load_strategy":response["load_strategy"],"inventory_hash":response["inventory_hash"],"model_instance":response["model_instance"]});
        (response, envelope, ready)
    }
    #[test]
    fn actual_retained_positive_logits_are_independently_verified() {
        let (v, e, r) = fixture();
        assert!(decision(&v, &e, &r).unwrap());
    }
    #[test]
    fn changed_native_owner_context_generation_and_model_instance_are_rejected() {
        let (v, e, r) = fixture();
        for key in [
            "owner",
            "profile_revision",
            "profile_hash",
            "source_hash",
            "resolution_id",
            "snapshot",
            "policy",
            "generation",
            "inventory_hash",
            "model_instance",
            "request_id",
            "transport_id",
        ] {
            let mut bad = v.clone();
            bad[key] = json!("changed");
            assert!(decision(&bad, &e, &r).is_err(), "{key}");
        }
    }
    #[test]
    fn typed_boolean_and_reported_scores_cannot_override_the_logit_rule() {
        let (v, e, r) = fixture();
        for (key, value) in [
            ("selected", json!("true")),
            ("selected", json!(false)),
            ("restricted_true", json!(0.5)),
            ("label_mass", json!(0.2)),
            ("log_partition", json!(1.0)),
            ("reason", json!("not_selected")),
            ("input_tokens", json!(4097)),
            ("inference_ms", json!(20001)),
            ("unknown", json!(true)),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(decision(&bad, &e, &r).is_err(), "{key}");
        }
    }
}

#[cfg(test)]
mod argmax_tests {
    use super::*;
    #[test]
    fn every_retained_v7_fixture_obeys_original_score_rule_and_mutated_argmax_is_rejected() {
        let rows: Vec<Value> =
            serde_json::from_str(include_str!("fixtures/v7-decisions.json")).unwrap();
        assert_eq!(rows.len(), 4);
        for mut v in rows {
            let owner = json!({"interest":"Set theory","version":1,"revision":1,"digest":crate::hex(&[1;32]),"text_sha256":crate::hex(&[2;32])});
            v["owner"] = owner.clone();
            v["generation"] = json!(crate::hex(&[3; 32]));
            v["transport_id"] = v["request_id"].clone();
            let e = json!({"owner":owner,"generation":v["generation"],"transport_id":v["transport_id"],"request":{"request_id":v["request_id"],"profile":{"revision":v["profile_revision"],"hash":v["profile_hash"]},"question":{"source_hash":v["source_hash"],"resolution_id":v["resolution_id"]},"snapshot":v["snapshot"],"policy":v["policy"]}});
            let r = json!({"device":v["device"],"load_strategy":v["load_strategy"],"inventory_hash":v["inventory_hash"],"model_instance":v["model_instance"]});
            assert_eq!(
                decision(&v, &e, &r).unwrap(),
                v["selected"].as_bool().unwrap()
            );
            let mut bad = v.clone();
            bad["top_token"] = json!(if v["top_token"] == 1866 { 3849 } else { 1866 });
            bad["selected"] = json!(false);
            bad["reason"] = json!("not_selected");
            assert!(decision(&bad, &e, &r).is_err());
            let mut bad = v.clone();
            bad["top_token"] = json!(0);
            bad["selected"] = json!(false);
            bad["reason"] = json!("unsupported_output");
            assert!(decision(&bad, &e, &r).is_err());
            let mut bad = v.clone();
            bad["top_token"] = json!(151936);
            assert!(decision(&bad, &e, &r).is_err());
        }
    }
}
