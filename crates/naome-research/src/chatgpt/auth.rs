//! Loopback OAuth, validated registration identity and selected-session renewal.

use super::{
    ISSUER, REQUIRED_SCOPES, RESOURCE, ResponsesConfig, USAGE_SETTINGS,
    credentials::{AccountInfo, AccountRecord, Store, Tokens, valid_client},
    http::{Http, MAX_MANAGEMENT_BYTES, catalog_cache_metadata, network_error, read_json},
};
use crate::provider::{ProviderError, ProviderErrorKind};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Model {
    pub slug: String,
    pub display_name: String,
}

#[derive(Deserialize)]
pub(super) struct Identity {
    pub iss: String,
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub nonce: Option<String>,
    pub email: Option<String>,
}
pub(super) fn verify_identity(
    token: &str,
    client: &str,
    nonce: Option<&str>,
    keys: &Value,
) -> Result<Identity, String> {
    if token.len() > 64 * 1024 {
        return Err("ID token exceeds the identity bound".into());
    }
    let header = decode_header(token).map_err(|_| "Invalid ID token header")?;
    // The pinned issuer discovery supports RS256 for ID-token signatures.
    // Adding another algorithm requires a reviewed source/fixture transition.
    if header.alg != Algorithm::RS256 {
        return Err("Unsupported ID token signature algorithm".into());
    }
    let kid = header
        .kid
        .as_deref()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or("ID token signing key missing")?;
    let keys: JwkSet =
        serde_json::from_value(keys.clone()).map_err(|_| "Invalid OpenID signing keys")?;
    if keys.keys.len() > 128 {
        return Err("OpenID signing-key operation bound exceeded".into());
    }
    let matches = keys
        .keys
        .iter()
        .filter(|k| k.common.key_id.as_deref() == Some(kid))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err("OpenID signing key absent or ambiguous".into());
    }
    let common = &matches[0].common;
    if common
        .public_key_use
        .as_ref()
        .is_some_and(|u| *u != jsonwebtoken::jwk::PublicKeyUse::Signature)
        || common
            .key_operations
            .as_ref()
            .is_some_and(|ops| !ops.contains(&jsonwebtoken::jwk::KeyOperations::Verify))
        || common.key_algorithm.is_some_and(|alg| {
            serde_json::to_value(alg).ok() != serde_json::to_value(header.alg).ok()
        })
    {
        return Err("OpenID signing-key use or algorithm mismatch".into());
    }
    let key = DecodingKey::from_jwk(matches[0]).map_err(|_| "Unsupported OpenID signing key")?;
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[client]);
    validation.set_issuer(&[ISSUER]);
    validation.set_required_spec_claims(&["iss", "aud", "sub", "exp", "iat"]);
    validation.leeway = 5;
    validation.validate_nbf = true;
    let identity = decode::<Identity>(token, &key, &validation)
        .map_err(|_| "ID token signature, issuer, audience or lifetime rejected")?
        .claims;
    let now = now()? as u64;
    if identity.iss != ISSUER
        || identity.sub.is_empty()
        || identity.sub.len() > 512
        || identity.iat > now.saturating_add(5)
        || identity.exp <= now
        || identity.exp <= identity.iat
        || nonce.is_some_and(|n| identity.nonce.as_deref() != Some(n))
    {
        return Err("ID token identity or nonce rejected".into());
    }
    Ok(identity)
}

pub(super) struct Session {
    pub store: Store,
    pub record: AccountRecord,
    pub http: Http,
}
impl Session {
    pub fn open(
        config: &ResponsesConfig,
        cancel: Arc<AtomicBool>,
        seconds: u64,
    ) -> Result<Self, String> {
        let http = Http::new(cancel, seconds).map_err(|e| e.to_string())?;
        Self::with_http(config, http)
    }
    pub fn with_http(config: &ResponsesConfig, mut http: Http) -> Result<Self, String> {
        http.bound_total();
        config.validate()?;
        let store = Store::open(&config.credential_directory, false)?;
        let record = store.record(&config.account_id)?;
        let mut session = Self {
            store,
            record,
            http,
        };
        session.token()?;
        session.refresh_if_needed()?;
        Ok(session)
    }
    pub fn token(&self) -> Result<&str, String> {
        if !self.record.info.plan_enabled {
            return Err(
                "ChatGPT plan use is disabled; enable it through Continue with ChatGPT".into(),
            );
        }
        let tokens = self
            .record
            .tokens
            .as_ref()
            .ok_or("SIWC account is signed out; Continue with ChatGPT")?;
        if !["resource.invoke", "chatgpt.tokens.use.direct"]
            .iter()
            .all(|scope| tokens.scopes.iter().any(|s| s == scope))
        {
            return Err("SIWC grant lacks required inference scopes".into());
        }
        if tokens.access_token.is_empty() {
            return Err("SIWC plan access token is missing; Continue with ChatGPT".into());
        }
        Ok(&tokens.access_token)
    }
    fn refresh_if_needed(&mut self) -> Result<(), String> {
        let tokens = self
            .record
            .tokens
            .as_ref()
            .ok_or("SIWC account is signed out; Continue with ChatGPT")?;
        if tokens.expires_at > now()?.saturating_add(60) {
            return Ok(());
        }
        let refresh = tokens
            .refresh_token
            .as_deref()
            .ok_or("SIWC renewal unavailable; Continue with ChatGPT")?;
        if let Some(value) = &tokens.earliest_refresh_at {
            let not_before=value.as_i64().or_else(||value.as_str().and_then(|s|chrono::DateTime::parse_from_rfc3339(s).ok().map(|t|t.timestamp())))
                .ok_or("Unrecognized earliest_refresh_at; retain credentials and reauthorize before inference")?;
            if not_before > now()? {
                return Err(
                    "SIWC renewal is not yet available; retry before starting inference".into(),
                );
            }
        }
        let response = self
            .http
            .run(async {
                let response = self
                    .http
                    .client
                    .post(&self.http.endpoints.token)
                    .form(&[
                        ("grant_type", "refresh_token"),
                        ("client_id", self.record.info.client_id.as_str()),
                        ("refresh_token", refresh),
                        ("resource", RESOURCE),
                    ])
                    .send()
                    .await
                    .map_err(network_error)?;
                read_json(response, MAX_MANAGEMENT_BYTES).await
            })
            .map_err(|e| e.to_string())?;
        if response.0 != 200 {
            let code = oauth_code(&response.1);
            if terminal_refresh(code) {
                self.record.tokens = None;
                self.record.info.signed_in = false;
                self.record.info.plan_enabled = false;
                self.store.save(&self.record)?;
                return Err("SIWC renewable session is invalid; Continue with ChatGPT using the saved registration".into());
            }
            return Err(format!(
                "SIWC renewal failed (HTTP {}, {}); credentials preserved",
                response.0,
                safe_oauth_code(code)
            ));
        }
        self.http.discovery().map_err(|e| e.to_string())?;
        let keys = self.http.jwks().map_err(|e| e.to_string())?;
        let replacement = validated_record(
            &response.1,
            &self.record.info.client_id,
            None,
            &keys,
            Some(&self.record),
        )?;
        self.store.save(&replacement)?;
        self.record = replacement;
        Ok(())
    }
    pub fn models(&self) -> Result<Vec<Model>, String> {
        let token = self.token()?;
        let (_, body, _) = self
            .http
            .run(async {
                let response = self
                    .http
                    .client
                    .get(format!("{}/models", self.http.endpoints.api))
                    .bearer_auth(token)
                    .send()
                    .await
                    .map_err(network_error)?;
                let result = read_json(response, MAX_MANAGEMENT_BYTES).await?;
                if result.0 != 200 {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Auth,
                        "Selected ChatGPT account model catalog unavailable",
                    ));
                }
                Ok(result)
            })
            .map_err(|e| e.to_string())?;
        model_catalog(&body)
    }
    pub(super) fn model_diagnostics(&self, requested: &str) -> Result<Value, String> {
        catalog_text(requested, 128)?;
        let token = self.token()?;
        let (body, cache) = self
            .http
            .run(async {
                let response = self
                    .http
                    .client
                    .get(format!("{}/models", self.http.endpoints.api))
                    .bearer_auth(token)
                    .send()
                    .await
                    .map_err(network_error)?;
                let cache = catalog_cache_metadata(response.headers());
                let (status, body, _) = read_json(response, MAX_MANAGEMENT_BYTES).await?;
                if status != 200 {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Auth,
                        &format!(
                            "Selected ChatGPT account model diagnostic unavailable (HTTP {status})"
                        ),
                    ));
                }
                Ok((body, cache))
            })
            .map_err(|e| e.to_string())?;
        let mut report = model_diagnostics(&body, requested)?;
        report["http_status"] = json!(200);
        report["cache"] = cache;
        Ok(report)
    }
    pub fn require_model(&self, model: &str) -> Result<Model, String> {
        self.models()?.into_iter().find(|m| m.slug == model).ok_or(
            "Selected model is unavailable to this ChatGPT account; choose from chatgpt-models"
                .into(),
        )
    }
}
fn catalog_text(text: &str, maximum: usize) -> Result<&str, String> {
    if text.is_empty() || text.len() > maximum || text.chars().any(char::is_control) {
        return Err("Invalid or oversized public model metadata".into());
    }
    Ok(text)
}
pub(super) fn model_diagnostics(body: &Value, requested: &str) -> Result<Value, String> {
    catalog_text(requested, 128)?;
    let models = body["models"]
        .as_array()
        .filter(|rows| rows.len() <= 512)
        .ok_or("Invalid or oversized SIWC model catalog")?;
    let mut rows = Vec::with_capacity(models.len());
    let mut ids = std::collections::BTreeSet::new();
    let mut presence = "absent";
    let mut listed = 0;
    for model in models {
        let slug = catalog_text(model["slug"].as_str().ok_or("Missing model slug")?, 128)?;
        let visibility = catalog_text(
            model["visibility"]
                .as_str()
                .ok_or("Missing model visibility")?,
            64,
        )?;
        if !ids.insert(slug) {
            return Err("Duplicate SIWC model slug".into());
        }
        let name = match model.get("display_name") {
            None if visibility != "list" => Value::Null,
            Some(Value::String(name)) => json!(catalog_text(name, 256)?),
            _ => return Err("Invalid public model display name".into()),
        };
        let mut capabilities = serde_json::Map::new();
        for key in [
            "supports_reasoning_summaries",
            "supports_verbosity",
            "supports_parallel_tool_calls",
            "supported_in_api",
        ] {
            if let Some(value) = model.get(key) {
                capabilities.insert(
                    key.into(),
                    json!(
                        value
                            .as_bool()
                            .ok_or("Invalid public model capability flag")?
                    ),
                );
            }
        }
        listed += usize::from(visibility == "list");
        if slug == requested {
            presence = match visibility {
                "list" => "present_visible",
                "hidden" => "present_hidden",
                _ => "present_not_listed",
            };
        }
        rows.push(
            json!({"slug":slug,"display_name":name,"visibility":visibility,
            "capabilities":capabilities}),
        );
    }
    Ok(json!({"version":1,"endpoint":format!("{RESOURCE}/models"),
        "requested_model":requested,"presence":presence,"models":rows,
        "row_count":models.len(),"listed_count":listed,"model_requests":0,
        "catalog_get_attempts":1,"limit":"Catalog metadata does not prove inference entitlement; the advertised-model gate is unchanged"}))
}
pub(super) fn model_catalog(body: &Value) -> Result<Vec<Model>, String> {
    let models = body["models"]
        .as_array()
        .filter(|a| a.len() <= 512)
        .ok_or("Invalid or oversized SIWC model catalog")?;
    let mut result = vec![];
    let mut ids = std::collections::BTreeSet::new();
    for model in models {
        if model["visibility"] != "list" {
            continue;
        }
        let slug = model["slug"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .ok_or("Invalid SIWC model slug")?;
        let label = model["display_name"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or("Invalid SIWC model name")?;
        if !ids.insert(slug) {
            return Err("Duplicate SIWC model slug".into());
        }
        result.push(Model {
            slug: slug.into(),
            display_name: label.into(),
        });
    }
    Ok(result)
}
pub fn accounts(directory: &Path) -> Result<Value, String> {
    if !directory.exists() {
        return Ok(
            json!({"accounts":[],"signed_in":false,"next":"Continue with ChatGPT","manage_usage":USAGE_SETTINGS}),
        );
    }
    let store = Store::open(directory, false)?;
    Ok(
        json!({"accounts":store.accounts(),"pending_registration":store.pending_client().is_some(),"manage_usage":USAGE_SETTINGS}),
    )
}
pub fn models(config: &ResponsesConfig, cancel: Arc<AtomicBool>) -> Result<Value, String> {
    let session = Session::open(config, cancel, 30)?;
    Ok(
        json!({"account":session.record.info,"models":session.models()?,"using_chatgpt_plan":true,"manage_usage":USAGE_SETTINGS,"model_requests":0}),
    )
}
/// One bounded management request through the selected registration. No model
/// request, inference entitlement, or alternate serving route is introduced.
pub fn diagnose_model(
    config: &ResponsesConfig,
    model: &str,
    cancel: Arc<AtomicBool>,
) -> Result<Value, String> {
    catalog_text(model, 128)?;
    Session::open(config, cancel, 30)?.model_diagnostics(model)
}
pub fn preflight(
    config: &ResponsesConfig,
    model: &str,
    cancel: Arc<AtomicBool>,
) -> Result<Value, String> {
    let session = Session::open(config, cancel, 30)?;
    let model = session.require_model(model)?;
    Ok(
        json!({"account":session.record.info,"model":model,"using_chatgpt_plan":true,"manage_usage":USAGE_SETTINGS,"model_requests":0,"note":"Management preflight; no inference or token-usage estimate"}),
    )
}

pub(super) fn validated_record(
    body: &Value,
    client: &str,
    nonce: Option<&str>,
    keys: &Value,
    old: Option<&AccountRecord>,
) -> Result<AccountRecord, String> {
    if !valid_client(client) {
        return Err("Invalid SIWC token response client".into());
    }
    let token = |key| {
        body[key]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 64 * 1024)
            .map(str::to_owned)
            .ok_or("Required SIWC token response field missing")
    };
    let id_token = token("id_token")?;
    let identity = verify_identity(&id_token, client, nonce, keys)?;
    if old.is_some_and(|r| {
        r.info.subject != identity.sub
            || r.info.issuer != identity.iss
            || r.info.client_id != client
    }) {
        return Err("SIWC reauthorization identity differs from the selected registration".into());
    }
    let scope = body["scope"]
        .as_str()
        .filter(|s| s.len() <= 4096)
        .ok_or("SIWC granted scopes missing")?;
    let scopes = scope
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !scopes.iter().any(|s| s == "openid") || scopes.len() > 64 {
        return Err("SIWC identity scope missing or invalid".into());
    }
    let plan_enabled = ["resource.invoke", "chatgpt.tokens.use.direct"]
        .iter()
        .all(|scope| scopes.iter().any(|s| s == scope));
    let access_token = if plan_enabled {
        token("access_token")?
    } else {
        body["access_token"]
            .as_str()
            .filter(|s| s.len() <= 64 * 1024)
            .unwrap_or("")
            .into()
    };
    if !access_token.is_empty()
        && body["token_type"]
            .as_str()
            .is_none_or(|s| !s.eq_ignore_ascii_case("Bearer"))
    {
        return Err("Invalid SIWC access-token response type".into());
    }
    let refresh_token = if scopes.iter().any(|s| s == "offline_access") {
        Some(token("refresh_token")?)
    } else {
        None
    };
    let saved_at = now()?;
    let expires_at = if !access_token.is_empty() {
        let lifetime = body["expires_in"]
            .as_u64()
            .filter(|t| *t > 0 && *t <= 24 * 3600)
            .ok_or("SIWC access-token lifetime missing or invalid")?;
        saved_at
            .checked_add(lifetime as i64)
            .ok_or("SIWC lifetime overflow")?
    } else {
        identity
            .exp
            .try_into()
            .map_err(|_| "SIWC identity lifetime overflow")?
    };
    let account_id = AccountInfo::identity_id(&identity.iss, client, &identity.sub);
    let label = old.map(|r| r.info.label.clone()).unwrap_or_else(|| {
        format!(
            "{} [{}]",
            identity.email.as_deref().unwrap_or("ChatGPT account"),
            &account_id[..12]
        )
    });
    Ok(AccountRecord {
        info: AccountInfo {
            account_id,
            label,
            email: identity.email,
            issuer: identity.iss,
            subject: identity.sub,
            client_id: client.into(),
            plan_enabled,
            signed_in: true,
            welcome_shown: old.is_some_and(|r| r.info.welcome_shown),
        },
        tokens: Some(Tokens {
            access_token,
            refresh_token,
            id_token,
            scopes,
            saved_at,
            expires_at,
            earliest_refresh_at: body
                .get("earliest_refresh_at")
                .filter(|v| !v.is_null())
                .cloned(),
        }),
    })
}
fn oauth_code(value: &Value) -> &str {
    value["error"]
        .as_str()
        .or_else(|| value["error"]["code"].as_str())
        .unwrap_or("unknown_error")
}
fn safe_oauth_code(code: &str) -> &str {
    match code {
        "invalid_grant"
        | "invalid_refresh_token"
        | "token_expired"
        | "refresh_token_expired"
        | "refresh_token_invalidated"
        | "refresh_token_reused"
        | "invalid_client"
        | "invalid_request"
        | "access_denied"
        | "invalid_scope"
        | "unsupported_grant_type"
        | "server_error"
        | "temporarily_unavailable" => code,
        _ => "unknown_error",
    }
}
fn terminal_refresh(code: &str) -> bool {
    matches!(
        code,
        "invalid_grant"
            | "invalid_refresh_token"
            | "token_expired"
            | "refresh_token_expired"
            | "refresh_token_invalidated"
            | "refresh_token_reused"
    )
}
pub(super) fn now() -> Result<i64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System clock unavailable")?
        .as_secs()
        .try_into()
        .map_err(|_| "System clock exhausted".into())
}
fn random() -> Result<String, String> {
    let mut b = [0; 32];
    getrandom::fill(&mut b).map_err(|_| "OAuth randomness unavailable")?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}

pub(super) struct Attempt {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
    pub redirect: String,
    pub client: String,
    pub host: String,
    pub id_hint: Option<String>,
    pub email_hint: Option<String>,
    pub consent: bool,
}
impl Attempt {
    pub fn new(
        redirect: String,
        client: String,
        host: String,
        old: Option<&AccountRecord>,
        consent: bool,
    ) -> Result<Self, String> {
        Ok(Self {
            state: random()?,
            nonce: random()?,
            verifier: random()?,
            redirect,
            client,
            host,
            id_hint: old.and_then(|r| r.tokens.as_ref().map(|t| t.id_token.clone())),
            email_hint: old.and_then(|r| r.info.email.clone()),
            consent,
        })
    }
    pub fn url(&self, endpoint: &str) -> Result<Url, String> {
        let mut url = Url::parse(endpoint).map_err(|_| "Invalid authorization endpoint")?;
        let mut q = url.query_pairs_mut();
        q.extend_pairs([
            ("client_id", self.client.as_str()),
            ("ext_agent_host_id", self.host.as_str()),
            ("response_type", "code"),
            ("redirect_uri", self.redirect.as_str()),
            ("scope", REQUIRED_SCOPES),
            ("resource", RESOURCE),
            ("state", self.state.as_str()),
            ("nonce", self.nonce.as_str()),
            ("code_challenge_method", "S256"),
        ]);
        q.append_pair(
            "code_challenge",
            &URL_SAFE_NO_PAD.encode(Sha256::digest(self.verifier.as_bytes())),
        );
        if self.client == "dynamic_agent_client" {
            q.append_pair("agent_name_hint", "NAOME");
        }
        if let Some(token) = &self.id_hint {
            q.append_pair("id_token_hint", token);
        }
        if let Some(email) = &self.email_hint {
            q.append_pair("login_hint", email);
        }
        if self.consent {
            q.append_pair("prompt", "consent");
        }
        drop(q);
        Ok(url)
    }
    pub fn callback(&self, target: &str) -> Result<(String, String), String> {
        let url = Url::parse(&format!("http://127.0.0.1{target}"))
            .map_err(|_| "Invalid OAuth callback")?;
        if url.path() != "/auth/callback" {
            return Err("OAuth callback path mismatch".into());
        }
        let mut fields = BTreeMap::new();
        for (key, value) in url.query_pairs() {
            if fields
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return Err("Duplicate OAuth callback field".into());
            }
        }
        if fields.get("state") != Some(&self.state) {
            return Err("OAuth callback state mismatch".into());
        }
        if fields.contains_key("error") {
            return Err("ChatGPT sign-in was declined or could not be completed".into());
        }
        let code = fields
            .get("code")
            .filter(|s| !s.is_empty() && s.len() <= 8192)
            .ok_or("OAuth callback code missing")?;
        let client = if self.client == "dynamic_agent_client" {
            fields
                .get("client_id")
                .filter(|s| valid_client(s))
                .ok_or("Dynamic registration returned no issued client ID")?
        } else {
            if fields.get("client_id").is_some_and(|s| s != &self.client) {
                return Err("Returning OAuth callback changed the client registration".into());
            }
            &self.client
        };
        Ok((code.clone(), client.clone()))
    }
}

pub fn sign_in(
    directory: &Path,
    account: Option<&str>,
    enable_plan: bool,
    cancel: Arc<AtomicBool>,
) -> Result<Value, String> {
    let http = Http::new(cancel, 30).map_err(|e| e.to_string())?;
    sign_in_with_http(directory, account, enable_plan, http, open_browser)
}
pub(super) fn sign_in_with_http(
    directory: &Path,
    account: Option<&str>,
    enable_plan: bool,
    http: Http,
    open: impl FnOnce(&str) -> Result<(), String>,
) -> Result<Value, String> {
    let cancel = http.cancel.clone();
    let mut store = Store::open(directory, true)?;
    let old = account.map(|a| store.record(a)).transpose()?;
    http.discovery().map_err(|e| e.to_string())?;
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "Cannot start OAuth loopback listener")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "Cannot configure OAuth loopback listener")?;
    let port = listener
        .local_addr()
        .map_err(|_| "OAuth callback address unavailable")?
        .port();
    let client = old
        .as_ref()
        .map(|r| r.info.client_id.clone())
        .or_else(|| store.pending_client().map(str::to_owned))
        .unwrap_or_else(|| "dynamic_agent_client".into());
    let attempt = Attempt::new(
        format!("http://127.0.0.1:{port}/auth/callback"),
        client,
        store.host().into(),
        old.as_ref(),
        enable_plan,
    )?;
    let ticket = random()?;
    let start_path = format!("/start/{ticket}");
    let consent_path = format!("/auth/start/{ticket}");
    let local = format!("http://127.0.0.1:{port}{start_path}");
    eprintln!("Continue with ChatGPT: {local}");
    open(&local)?;
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut started = false;
    let mut connections = 0;
    loop {
        callback_active(&cancel, deadline)?;
        let (mut stream, peer) = match listener.accept() {
            Ok(value) => value,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(_) => return Err("OAuth loopback listener failed".into()),
        };
        connections += 1;
        if !peer.ip().is_loopback() || connections > 128 {
            return Err("OAuth listener operation bound exceeded".into());
        }
        let target = match local_request(&mut stream, port, &cancel, deadline) {
            Ok(target) => target,
            Err(_) => {
                callback_active(&cancel, deadline)?;
                local_reply(
                    &mut stream,
                    "400 Bad Request",
                    "Invalid local request",
                    None,
                )?;
                continue;
            }
        };
        if target == start_path && !started {
            let welcome = format!(
                "<!doctype html><meta charset=\"utf-8\"><title>NAOME</title><h1>Use your ChatGPT plan</h1><p>Eligible AI requests in NAOME use your ChatGPT plan. You can manage usage in ChatGPT settings.</p><a href=\"{consent_path}\">Continue with ChatGPT</a>"
            );
            local_reply(&mut stream, "200 OK", &welcome, None)?;
        } else if target == consent_path && !started {
            started = true;
            let url = attempt.url(&http.endpoints.authorize)?;
            local_reply(
                &mut stream,
                "302 Found",
                "Continue with ChatGPT",
                Some(url.as_str()),
            )?;
        } else if target.starts_with("/auth/callback?") && started {
            // The attempt is consumed here. Any success or failure closes this
            // listener; the code/state can never be redeemed a second time.
            let result = (|| {
                let (code, issued) = attempt.callback(&target)?;
                if old.is_none() {
                    store.remember_registration(&issued)?;
                }
                let (status, body, _) = http
                    .run(async {
                        let response = http
                            .client
                            .post(&http.endpoints.token)
                            .form(&[
                                ("grant_type", "authorization_code"),
                                ("client_id", issued.as_str()),
                                ("code", code.as_str()),
                                ("code_verifier", attempt.verifier.as_str()),
                                ("redirect_uri", attempt.redirect.as_str()),
                                ("resource", RESOURCE),
                            ])
                            .send()
                            .await
                            .map_err(network_error)?;
                        read_json(response, MAX_MANAGEMENT_BYTES).await
                    })
                    .map_err(|e| e.to_string())?;
                if status != 200 {
                    return Err(format!(
                        "ChatGPT code exchange failed (HTTP {}, {}); restart sign-in using the retained registration",
                        status,
                        safe_oauth_code(oauth_code(&body))
                    ));
                }
                let keys = http.jwks().map_err(|e| e.to_string())?;
                let mut record =
                    validated_record(&body, &issued, Some(&attempt.nonce), &keys, old.as_ref())?;
                let welcome = record.info.plan_enabled && !record.info.welcome_shown;
                if welcome {
                    record.info.welcome_shown = true;
                }
                store.save(&record)?;
                Ok((record.info, welcome))
            })();
            match result {
                Ok((info, welcome)) => {
                    let text = if welcome {
                        "<!doctype html><title>NAOME</title><h1>You're using your ChatGPT plan</h1><p>Eligible AI requests in NAOME use your ChatGPT plan.</p><p><a href=\"https://chatgpt.com/settings/usage\">Manage usage</a></p><button onclick=\"window.close()\">Got it</button>"
                    } else {
                        "<!doctype html><title>NAOME</title><h1>ChatGPT sign-in complete</h1><p>You can return to NAOME.</p><a href=\"https://chatgpt.com/settings/usage\">Manage usage</a>"
                    };
                    local_reply(&mut stream, "200 OK", text, None)?;
                    return Ok(
                        json!({"account":info,"model_requests":0,"manage_usage":USAGE_SETTINGS,"next":"Choose a model with chatgpt-models, then prepare-node. No inference was performed."}),
                    );
                }
                Err(reason) => {
                    let _ = local_reply(
                        &mut stream,
                        "400 Bad Request",
                        "ChatGPT sign-in could not be completed. Return to NAOME for the safe diagnostic.",
                        None,
                    );
                    return Err(reason);
                }
            }
        } else {
            local_reply(&mut stream, "404 Not Found", "No active local action", None)?;
        }
    }
}
fn callback_active(cancel: &AtomicBool, deadline: Instant) -> Result<(), String> {
    if cancel.load(Ordering::Acquire) {
        return Err("ChatGPT sign-in cancelled".into());
    }
    if Instant::now() >= deadline {
        return Err("ChatGPT sign-in timed out; start a fresh sign-in".into());
    }
    Ok(())
}
fn local_request(
    stream: &mut TcpStream,
    port: u16,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<String, String> {
    // Darwin inherits the listener's nonblocking mode on accept. Normalize it
    // before applying the bounded reads used by the browser callback parser.
    stream
        .set_nonblocking(false)
        .map_err(|_| "Cannot configure callback stream")?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|_| "Cannot bound callback read")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| "Cannot bound callback write")?;
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
        callback_active(cancel, deadline)?;
        stream
            .set_read_timeout(Some(
                Duration::from_millis(200).min(deadline.saturating_duration_since(Instant::now())),
            ))
            .map_err(|_| "Cannot bound callback read")?;
        let count = match stream.read(&mut chunk) {
            Ok(count) => count,
            Err(_) => {
                callback_active(cancel, deadline)?;
                return Err("Incomplete local callback".into());
            }
        };
        callback_active(cancel, deadline)?;
        if count == 0 || bytes.len() + count > 16 * 1024 {
            return Err("Local callback exceeds operation bound".into());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    callback_active(cancel, deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "Invalid local callback encoding")?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or("Local callback request missing")?;
    let parts = first.split_ascii_whitespace().collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != "GET" || parts[2] != "HTTP/1.1" || !parts[1].starts_with('/')
    {
        return Err("Invalid callback request method".into());
    }
    let hosts = lines
        .filter_map(|s| s.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.trim())
        .collect::<Vec<_>>();
    if hosts != [format!("127.0.0.1:{port}")] {
        return Err("Callback host mismatch".into());
    }
    Ok(parts[1].into())
}
fn local_reply(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
    location: Option<&str>,
) -> Result<(), String> {
    let location = location.map_or(String::new(), |url| format!("Location: {url}\r\n"));
    let message = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n{location}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(message.as_bytes())
        .map_err(|_| "Cannot return safe OAuth completion".into())
}
fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut command = Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let mut command = Command::new("xdg-open");
    let mut child = command.arg(url).spawn().map_err(
        |_| "Cannot open the system browser; open the displayed local Continue with ChatGPT link",
    )?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

pub fn sign_out(config: &ResponsesConfig, cancel: Arc<AtomicBool>) -> Result<Value, String> {
    let http = Http::new(cancel, 10).map_err(|e| e.to_string())?;
    sign_out_with_http(config, http)
}
pub(super) fn sign_out_with_http(config: &ResponsesConfig, http: Http) -> Result<Value, String> {
    config.validate()?;
    let mut store = Store::open(&config.credential_directory, false)?;
    let mut record = store.record(&config.account_id)?;
    let mut confirmed = record.tokens.is_none();
    if let Some(refresh) = record
        .tokens
        .as_ref()
        .and_then(|t| t.refresh_token.as_deref())
        && let Ok(discovery) = http.discovery()
        && let Some(endpoint) = discovery["revocation_endpoint"]
            .as_str()
            .filter(|s| trusted_revoke(s, &http))
    {
        for attempt in 0..3 {
            let result = http.run(async {
                let response = http
                    .client
                    .post(endpoint)
                    .form(&[
                        ("token", refresh),
                        ("token_type_hint", "refresh_token"),
                        ("client_id", record.info.client_id.as_str()),
                    ])
                    .send()
                    .await
                    .map_err(network_error)?;
                Ok(response.status().as_u16())
            });
            match result {
                Ok(200) => {
                    confirmed = true;
                    break;
                }
                Ok(status) if status < 500 => break,
                _ => {}
            }
            if http.cancel.load(Ordering::Acquire) {
                break;
            }
            if attempt < 2 {
                std::thread::sleep(Duration::from_millis(200u64 << attempt));
            }
        }
    }
    record.tokens = None;
    record.info.signed_in = false;
    record.info.plan_enabled = false;
    store.save(&record)?;
    Ok(
        json!({"account":record.info,"remote_revocation_confirmed":confirmed,"manage_usage":USAGE_SETTINGS,
        "note":if confirmed {"Signed out; account registration and host identity retained"} else {"Signed out locally; remote revocation was not confirmed. Disconnect NAOME in ChatGPT Settings if needed."}}),
    )
}
fn trusted_revoke(value: &str, http: &Http) -> bool {
    if let Some(expected) = &http.endpoints.revoke {
        return value == expected;
    }
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some("auth.openai.com")
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

#[cfg(test)]
mod socket_tests {
    use super::*;

    #[test]
    fn local_callback_reader_waits_for_delayed_fragments_on_a_nonblocking_accepted_socket() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut late_producers = Vec::new();
        for _ in 0..3 {
            if Instant::now() >= deadline {
                break;
            }
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let (ready, wait) = std::sync::mpsc::channel();
            let writer = std::thread::spawn(move || {
                let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
                stream.set_nodelay(true).unwrap();
                let started: Instant = wait.recv().unwrap();
                std::thread::sleep(Duration::from_millis(50));
                let request = format!(
                    "GET /auth/callback?state=fixture&code=fixture&client_id=fixture HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
                );
                let mut written = Duration::ZERO;
                for chunk in request.as_bytes().chunks(40) {
                    stream.write_all(chunk).unwrap();
                    written = started.elapsed();
                    std::thread::sleep(Duration::from_millis(20));
                }
                written
            });
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_nonblocking(true).unwrap();
            ready.send(Instant::now()).unwrap();
            let result = local_request(&mut stream, port, &AtomicBool::new(false), deadline);
            let written = writer.join().unwrap();
            // Sleep is only a lower bound. A producer descheduled past the idle
            // read limit does not supply the intended successful-fragment fixture.
            // Never replace a parser failure when every fragment was written in time.
            if written >= Duration::from_millis(200) {
                late_producers.push((written, result));
                continue;
            }
            assert_eq!(
                result.unwrap(),
                "/auth/callback?state=fixture&code=fixture&client_id=fixture"
            );
            return;
        }
        panic!("No timely fragmented callback fixture within its bound: {late_producers:?}");
    }

    #[test]
    fn local_callback_read_deadline_remains_bounded_after_socket_normalization() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let idle = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        let before = Instant::now();
        assert_eq!(
            local_request(
                &mut stream,
                port,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(3)
            )
            .unwrap_err(),
            "Incomplete local callback"
        );
        assert!(before.elapsed() >= Duration::from_millis(100));
        assert!(before.elapsed() < Duration::from_secs(3));
        drop(idle);
    }
    #[test]
    fn fragmented_callback_observes_cancellation_and_parent_deadline() {
        for cancellation in [true, false] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let cancel = Arc::new(AtomicBool::new(false));
            let done = Arc::new(AtomicBool::new(false));
            let (ready, wait) = std::sync::mpsc::channel();
            let writer_cancel = cancel.clone();
            let writer_done = done.clone();
            let writer = std::thread::spawn(move || {
                let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
                wait.recv().unwrap();
                for i in 0..20 {
                    if writer_done.load(Ordering::Acquire) {
                        break;
                    }
                    if cancellation && i == 2 {
                        writer_cancel.store(true, Ordering::Release);
                        break;
                    }
                    if stream.write_all(b"G").is_err() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(40));
                }
            });
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_nonblocking(true).unwrap();
            let before = Instant::now();
            let deadline = before
                + if cancellation {
                    Duration::from_secs(3)
                } else {
                    Duration::from_millis(150)
                };
            ready.send(()).unwrap();
            let result = local_request(&mut stream, port, &cancel, deadline);
            done.store(true, Ordering::Release);
            writer.join().unwrap();
            assert_eq!(
                result.unwrap_err(),
                if cancellation {
                    "ChatGPT sign-in cancelled"
                } else {
                    "ChatGPT sign-in timed out; start a fresh sign-in"
                }
            );
            assert!(before.elapsed() < Duration::from_secs(3));
        }
    }
}
