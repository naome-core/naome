//! Participant-owned SIWC credentials and a single direct Responses request.
//!
//! Credential management is independent of offline configuration validation and
//! replay. Inference has no tools, internal resampling, automatic POST retry,
//! native process, API-key fallback or alternate serving endpoint.

mod access;
mod auth;
mod credentials;
mod http;
mod stream;

pub use access::diagnose_model_access;
pub use auth::{accounts, diagnose_model, models, preflight, sign_in, sign_out};
pub use credentials::{AccountInfo, default_directory};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const USAGE_SETTINGS: &str = "https://chatgpt.com/settings/usage";
pub(super) const ISSUER: &str = "https://auth.openai.com";
pub(super) const RESOURCE: &str = "https://api.openai.com/v1";
pub(super) const REQUIRED_SCOPES: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";

/// An account registration is pinned at genesis; credentials may rotate without
/// changing that registration, the selected model, or the economic profile.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponsesConfig {
    pub version: u32,
    pub credential_directory: PathBuf,
    pub account_id: String,
}
impl ResponsesConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || !self.credential_directory.is_absolute()
            || self.account_id.len() != 64
            || !self
                .account_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid versioned SIWC account configuration".into());
        }
        Ok(())
    }
}

pub(crate) use stream::request;

#[cfg(test)]
mod tests;
