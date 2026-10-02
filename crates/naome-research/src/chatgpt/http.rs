//! Fixed public endpoints and cancellable, bounded HTTP with retries disabled.

use crate::provider::{ProviderError, ProviderErrorKind};
use reqwest::{Client, Response};
use serde_json::{Value, json};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) const MAX_MANAGEMENT_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub(super) struct Endpoints {
    pub discovery: String,
    pub authorize: String,
    pub token: String,
    pub jwks: String,
    pub revoke: Option<String>,
    pub api: String,
}
impl Default for Endpoints {
    fn default() -> Self {
        Self {
            discovery: format!("{}/.well-known/openid-configuration", super::ISSUER),
            authorize: format!("{}/api/accounts/authorize", super::ISSUER),
            token: format!("{}/api/accounts/oauth/token", super::ISSUER),
            jwks: format!("{}/.well-known/jwks.json", super::ISSUER),
            revoke: None,
            api: super::RESOURCE.into(),
        }
    }
}

pub(super) struct Http {
    pub client: Client,
    pub endpoints: Endpoints,
    pub cancel: Arc<AtomicBool>,
    pub timeout: Duration,
    deadline: Option<Instant>,
}
impl Http {
    pub fn new(cancel: Arc<AtomicBool>, seconds: u64) -> Result<Self, ProviderError> {
        Self::with_endpoints(cancel, seconds, Endpoints::default())
    }
    pub fn with_endpoints(
        cancel: Arc<AtomicBool>,
        seconds: u64,
        endpoints: Endpoints,
    ) -> Result<Self, ProviderError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(10))
            .user_agent("NAOME local research SIWC/1")
            .build()
            .map_err(|_| ProviderError::contract("Cannot prepare direct HTTPS transport"))?;
        Ok(Self {
            client,
            endpoints,
            cancel,
            timeout: Duration::from_secs(seconds),
            deadline: None,
        })
    }
    pub fn bound_total(&mut self) {
        self.deadline = Some(Instant::now() + self.timeout);
    }
    pub fn run<T>(
        &self,
        future: impl Future<Output = Result<T, ProviderError>>,
    ) -> Result<T, ProviderError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(ProviderError::new(
                ProviderErrorKind::TimeBudget,
                "Direct operation cancelled",
            ));
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(ProviderError::new(
                ProviderErrorKind::TimeBudget,
                "Direct operation exceeded its deadline",
            ));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ProviderError::contract("Cannot prepare direct transport runtime"))?;
        runtime.block_on(async {
            tokio::pin!(future);
            let remaining=self.deadline.map_or(self.timeout,|d|d.saturating_duration_since(Instant::now()));
            let deadline = tokio::time::sleep(remaining);
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut deadline => return Err(ProviderError::new(ProviderErrorKind::TimeBudget, "Direct operation exceeded its deadline")),
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {
                        if self.cancel.load(Ordering::Acquire) {
                            return Err(ProviderError::new(ProviderErrorKind::TimeBudget, "Direct operation cancelled"));
                        }
                    },
                    value = &mut future => return value,
                }
            }
        })
    }
    pub fn discovery(&self) -> Result<Value, ProviderError> {
        let value = self.run(async {
            let response = self
                .client
                .get(&self.endpoints.discovery)
                .send()
                .await
                .map_err(network_error)?;
            let (status, value, _) = read_json(response, MAX_MANAGEMENT_BYTES).await?;
            if status != 200 {
                return Err(ProviderError::new(
                    ProviderErrorKind::Auth,
                    "OpenID discovery unavailable",
                ));
            }
            Ok(value)
        })?;
        if value["issuer"] != super::ISSUER
            || value["authorization_endpoint"] != self.endpoints.authorize
            || value["token_endpoint"] != self.endpoints.token
            || value["jwks_uri"] != self.endpoints.jwks
        {
            return Err(ProviderError::new(
                ProviderErrorKind::Auth,
                "OpenID discovery endpoint or issuer mismatch",
            ));
        }
        Ok(value)
    }
    pub fn jwks(&self) -> Result<Value, ProviderError> {
        self.run(async {
            let response = self
                .client
                .get(&self.endpoints.jwks)
                .send()
                .await
                .map_err(network_error)?;
            let (status, value, _) = read_json(response, MAX_MANAGEMENT_BYTES).await?;
            if status != 200 {
                return Err(ProviderError::new(
                    ProviderErrorKind::Auth,
                    "OpenID signing keys unavailable",
                ));
            }
            Ok(value)
        })
    }
}

pub(super) fn network_error(_: reqwest::Error) -> ProviderError {
    // reqwest diagnostics can include URLs; OAuth authorization URLs may carry
    // a retained ID-token hint. Never propagate upstream error formatting.
    ProviderError::new(
        ProviderErrorKind::Transient,
        "Direct HTTPS transport failed",
    )
}
pub(super) async fn read_json(
    mut response: Response,
    maximum: usize,
) -> Result<(u16, Value, Value), ProviderError> {
    let status = response.status().as_u16();
    let id = request_id(&response);
    let mut body = Vec::new();
    while let Some(bytes) = response.chunk().await.map_err(network_error)? {
        if body
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > maximum)
        {
            return Err(ProviderError::contract(
                "Direct HTTP body exceeds its operation bound",
            ));
        }
        body.extend_from_slice(&bytes);
    }
    let value = serde_json::from_slice(&body)
        .map_err(|_| ProviderError::contract("Invalid direct HTTP JSON body"))?;
    Ok((status, value, id))
}
pub(super) fn request_id(response: &Response) -> Value {
    response
        .headers()
        .get("openai-request-id")
        .or_else(|| response.headers().get("x-request-id"))
        .and_then(|h| h.to_str().ok())
        .filter(|s| s.len() <= 256 && s.bytes().all(|b| b.is_ascii_graphic()))
        .map_or(Value::Null, |s| Value::String(s.into()))
}
pub(super) fn catalog_cache_metadata(headers: &reqwest::header::HeaderMap) -> Value {
    let age = headers
        .get("age")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 20)
        .and_then(|value| value.parse::<u64>().ok());
    let control = headers
        .get("cache-control")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 1024);
    let mut known = serde_json::Map::new();
    if let Some(value) = control {
        for directive in value.split(',').map(str::trim) {
            if [
                "no-cache",
                "no-store",
                "public",
                "private",
                "must-revalidate",
            ]
            .iter()
            .any(|allowed| directive.eq_ignore_ascii_case(allowed))
            {
                known.insert(directive.to_ascii_lowercase(), json!(true));
            } else if let Some((key, value)) = directive.split_once('=')
                && ["max-age", "s-maxage"]
                    .iter()
                    .any(|allowed| key.eq_ignore_ascii_case(allowed))
                && let Ok(seconds) = value.parse::<u64>()
            {
                known.insert(key.to_ascii_lowercase(), json!(seconds));
            }
        }
    }
    // Never return raw headers: unknown extensions can echo private strings.
    json!({"age_seconds":age,"cache_control_present":headers.contains_key("cache-control"),
        "recognized_cache_control":known,"raw_headers_retained":false})
}
pub(super) fn diagnostic(status: u16, body: &Value, request_id: Value) -> Value {
    let code = match body["error"]["code"].as_str() {
        Some(
            value @ ("subscription_sharing_user_not_eligible"
            | "subscription_sharing_usage_limit_exceeded"
            | "subscription_sharing_usage_unavailable"
            | "subscription_sharing_unsupported_capability"
            | "subscription_sharing_route_not_supported"
            | "subscription_sharing_invalid_user"
            | "subscription_sharing_user_unavailable"
            | "chatpass_v2_scope_not_authorized"
            | "chatpass_v2_invalid_authorization_context"),
        ) => json!(value),
        None => Value::Null,
        Some(_) => json!("unrecognized_error_code"),
    };
    let parameter = match body["error"]["param"].as_str() {
        Some(
            value @ ("model"
            | "input"
            | "tools"
            | "store"
            | "stream"
            | "text"
            | "text.format"
            | "service_tier"
            | "max_output_tokens"
            | "temperature"
            | "background"
            | "conversation"
            | "previous_response_id"),
        ) => json!(value),
        None => Value::Null,
        Some(_) => json!("unrecognized_parameter"),
    };
    let shape = [
        "error", "detail", "type", "response", "id", "status", "usage", "output",
    ]
    .into_iter()
    .filter(|name| body.get(name).is_some())
    .collect::<Vec<_>>();
    let field_count = body.as_object().map_or(0, |object| object.len());
    json!({"http_status":status,"error_code":code,"error_param":parameter,"body_fields":shape,"body_field_count":field_count,"request_id":request_id})
}
