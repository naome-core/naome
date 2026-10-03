//! Protected per-registration records, stable host identity and one auth writer.

use super::ISSUER;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_FILE: u64 = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountInfo {
    pub account_id: String,
    pub label: String,
    pub email: Option<String>,
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub plan_enabled: bool,
    pub signed_in: bool,
    pub welcome_shown: bool,
}
impl AccountInfo {
    pub fn identity_id(issuer: &str, client: &str, subject: &str) -> String {
        crate::state::hex(&crate::state::hash(
            b"naome:siwc:account:v1\0",
            &(issuer, client, subject),
        ))
    }
    fn validate(&self) -> Result<(), String> {
        if self.issuer != ISSUER
            || self.subject.is_empty()
            || self.subject.len() > 512
            || !valid_client(&self.client_id)
            || self.label.len() > 512
            || self.email.as_ref().is_some_and(|s| s.len() > 320)
            || self.account_id != Self::identity_id(&self.issuer, &self.client_id, &self.subject)
        {
            return Err("invalid saved SIWC account identity".into());
        }
        Ok(())
    }
}
pub(super) fn valid_client(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value != "dynamic_agent_client"
        && value.bytes().all(|b| b.is_ascii_graphic())
}

// Intentionally no Debug implementation: neither diagnostics nor Node receipts
// may format credentials or complete OAuth token responses.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: String,
    pub scopes: Vec<String>,
    pub saved_at: i64,
    pub expires_at: i64,
    pub earliest_refresh_at: Option<serde_json::Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountRecord {
    pub info: AccountInfo,
    pub tokens: Option<Tokens>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    host_id: String,
    accounts: Vec<AccountInfo>,
    #[serde(default)]
    pending_client: Option<String>,
}

/// This store is separate from the node directory and never part of a journal.
/// Its lock serializes sign-in, selected-session refresh, inference and sign-out.
pub(super) struct Store {
    root: PathBuf,
    registry: Registry,
    _lock: File,
}
impl Store {
    pub fn open(root: &Path, create: bool) -> Result<Self, String> {
        if !root.is_absolute() {
            return Err("SIWC credential directory must be absolute".into());
        }
        if fs::symlink_metadata(root).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("SIWC credential directory cannot be a symlink".into());
        }
        if !root.exists() {
            if !create {
                return Err("Continue with ChatGPT before preparing an inference profile".into());
            }
            fs::create_dir_all(root).map_err(|_| "Cannot create SIWC credential directory")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                    .map_err(|_| "Cannot protect SIWC credential directory")?;
            }
        }
        let root =
            fs::canonicalize(root).map_err(|_| "Cannot resolve SIWC credential directory")?;
        if root.ancestors().any(|p| p.join(".git").exists()) {
            return Err("SIWC credentials must remain outside a Git checkout".into());
        }
        check_private(&root, true)?;
        let lock_path = root.join("auth.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if lock_path.exists() {
            check_private(&lock_path, false)?;
        }
        let lock = options
            .open(&lock_path)
            .map_err(|_| "Cannot open SIWC session lock")?;
        lock.try_lock().map_err(
            |_| "SIWC account is busy; stop its active operation before changing the session",
        )?;
        let index = root.join("accounts.json");
        let registry = if index.exists() {
            read_private(&index)?
        } else if create {
            let registry = Registry {
                version: 1,
                host_id: host_id()?,
                accounts: vec![],
                pending_client: None,
            };
            write_private(&index, &registry)?;
            registry
        } else {
            return Err("SIWC registration is missing; Continue with ChatGPT".into());
        };
        let value = Self {
            root,
            registry,
            _lock: lock,
        };
        value.validate_registry()?;
        Ok(value)
    }
    fn validate_registry(&self) -> Result<(), String> {
        if self.registry.version != 1
            || !valid_host(&self.registry.host_id)
            || self.registry.accounts.len() > 256
            || self
                .registry
                .pending_client
                .as_ref()
                .is_some_and(|s| !valid_client(s))
        {
            return Err("invalid or oversized SIWC account registry".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        for account in &self.registry.accounts {
            account.validate()?;
            if !ids.insert(&account.account_id) {
                return Err("duplicate SIWC registration".into());
            }
        }
        Ok(())
    }
    pub fn host(&self) -> &str {
        &self.registry.host_id
    }
    pub fn accounts(&self) -> &[AccountInfo] {
        &self.registry.accounts
    }
    pub fn pending_client(&self) -> Option<&str> {
        self.registry.pending_client.as_deref()
    }
    pub fn remember_registration(&mut self, client: &str) -> Result<(), String> {
        if !valid_client(client) {
            return Err("Invalid issued SIWC registration".into());
        }
        self.registry.pending_client = Some(client.into());
        write_private(&self.root.join("accounts.json"), &self.registry)
    }
    pub fn record(&self, id: &str) -> Result<AccountRecord, String> {
        let info = self
            .registry
            .accounts
            .iter()
            .find(|a| a.account_id == id)
            .ok_or("Unknown SIWC account registration")?;
        let path = self.root.join(format!("account-{id}.json"));
        #[cfg(not(windows))]
        let record: AccountRecord = read_private(&path)?;
        #[cfg(windows)]
        let record: AccountRecord = self.read_encrypted(&path, id)?;
        record.info.validate()?;
        if record.info.account_id != info.account_id
            || record.info.client_id != info.client_id
            || record.info.subject != info.subject
            || record.info.issuer != info.issuer
        {
            return Err("SIWC credential and registration identity mismatch".into());
        }
        if let Some(tokens) = &record.tokens {
            if (record.info.plan_enabled && tokens.access_token.is_empty())
                || tokens.id_token.is_empty()
                || tokens.access_token.len() > 64 * 1024
                || tokens.id_token.len() > 64 * 1024
                || tokens
                    .refresh_token
                    .as_ref()
                    .is_some_and(|s| s.is_empty() || s.len() > 64 * 1024)
                || tokens.scopes.len() > 64
                || tokens.expires_at <= tokens.saved_at
                || record.info.plan_enabled
                    != ["resource.invoke", "chatgpt.tokens.use.direct"]
                        .iter()
                        .all(|scope| tokens.scopes.iter().any(|s| s == scope))
                || !record.info.signed_in
            {
                return Err("invalid saved SIWC credential record".into());
            }
        } else if record.info.signed_in {
            return Err("SIWC registration has no renewable session".into());
        }
        Ok(record)
    }
    pub fn save(&mut self, record: &AccountRecord) -> Result<(), String> {
        record.info.validate()?;
        let id = &record.info.account_id;
        if !self.registry.accounts.iter().any(|a| a.account_id == *id)
            && self.registry.accounts.len() >= 256
        {
            return Err("SIWC registration registry operation bound reached".into());
        }
        let path = self.root.join(format!("account-{id}.json"));
        #[cfg(not(windows))]
        write_private(&path, record)?;
        #[cfg(windows)]
        self.write_encrypted(&path, id, record)?;
        if let Some(info) = self
            .registry
            .accounts
            .iter_mut()
            .find(|a| a.account_id == *id)
        {
            *info = record.info.clone();
        } else {
            if self.registry.accounts.len() >= 256 {
                return Err("SIWC registration registry operation bound reached".into());
            }
            self.registry.accounts.push(record.info.clone());
        }
        if self.registry.pending_client.as_ref() == Some(&record.info.client_id) {
            self.registry.pending_client = None;
        }
        write_private(&self.root.join("accounts.json"), &self.registry)
    }

    #[cfg(windows)]
    fn key(&self, create: bool) -> Result<[u8; 32], String> {
        let entry = keyring::Entry::new("NAOME SIWC credentials", self.host())
            .map_err(|_| "Windows credential store unavailable")?;
        let bytes = match entry.get_secret() {
            Ok(bytes) => bytes,
            Err(keyring::Error::NoEntry) if create => {
                let mut key = [0; 32];
                getrandom::fill(&mut key)
                    .map_err(|_| "Credential encryption randomness unavailable")?;
                entry.set_secret(&key).map_err(
                    |_| "Cannot protect the SIWC encryption key in the Windows credential store",
                )?;
                key.to_vec()
            }
            Err(_) => return Err("Protected Windows SIWC encryption key unavailable".into()),
        };
        bytes
            .try_into()
            .map_err(|_| "Invalid protected SIWC encryption key".into())
    }
    #[cfg(windows)]
    fn write_encrypted(&self, path: &Path, id: &str, record: &AccountRecord) -> Result<(), String> {
        use chacha20poly1305::{
            ChaCha20Poly1305, KeyInit,
            aead::{Aead, Payload},
        };
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| "Credential encryption randomness unavailable")?;
        let cipher = ChaCha20Poly1305::new((&self.key(true)?).into());
        let plain =
            serde_json::to_vec(record).map_err(|_| "Cannot encode SIWC credential record")?;
        let binding = format!("naome:siwc:credentials:v1:{}:{id}", self.host());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &plain,
                    aad: binding.as_bytes(),
                },
            )
            .map_err(|_| "Cannot protect SIWC credential record")?;
        write_private(
            path,
            &ProtectedRecord {
                version: 1,
                nonce: nonce.to_vec(),
                ciphertext,
            },
        )
    }
    #[cfg(windows)]
    fn read_encrypted(&self, path: &Path, id: &str) -> Result<AccountRecord, String> {
        use chacha20poly1305::{
            ChaCha20Poly1305, KeyInit,
            aead::{Aead, Payload},
        };
        let record: ProtectedRecord = read_private(path)?;
        if record.version != 1 || record.nonce.len() != 12 {
            return Err("Invalid protected SIWC credential envelope".into());
        }
        let cipher = ChaCha20Poly1305::new((&self.key(false)?).into());
        let binding = format!("naome:siwc:credentials:v1:{}:{id}", self.host());
        let bytes = cipher
            .decrypt(
                record.nonce.as_slice().into(),
                Payload {
                    msg: &record.ciphertext,
                    aad: binding.as_bytes(),
                },
            )
            .map_err(|_| "SIWC credential protection or identity check failed")?;
        serde_json::from_slice(&bytes)
            .map_err(|_| "Invalid protected SIWC credential record".into())
    }
}
#[cfg(windows)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedRecord {
    version: u32,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

pub fn default_directory() -> Result<PathBuf, String> {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or("LOCALAPPDATA unavailable")?;
    #[cfg(not(windows))]
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(value) => PathBuf::from(value),
        None => PathBuf::from(std::env::var_os("HOME").ok_or("Home directory unavailable")?)
            .join(".config"),
    };
    if !base.is_absolute() {
        return Err("Per-user configuration directory must be absolute".into());
    }
    Ok(base.join("naome").join("chatgpt"))
}
fn host_id() -> Result<String, String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| "Host identity randomness unavailable")?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = crate::state::hex(&bytes);
    Ok(format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
fn valid_host(value: &str) -> bool {
    let Some(uuid) = value.strip_prefix("urn:uuid:") else {
        return false;
    };
    uuid.len() == 36
        && uuid.as_bytes()[14] == b'4'
        && matches!(uuid.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
        && uuid.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn check_private(path: &Path, directory: bool) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "Cannot inspect SIWC protected storage")?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err("Invalid SIWC protected storage path".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(
                "SIWC storage must be owned by this user with owner-only permissions".into(),
            );
        }
    }
    Ok(())
}
fn read_private<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    check_private(path, false)?;
    let mut file = File::open(path).map_err(|_| "Cannot open SIWC protected record")?;
    if file
        .metadata()
        .map_err(|_| "Cannot inspect SIWC record")?
        .len()
        > MAX_FILE
    {
        return Err("SIWC protected record exceeds operation bound".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read SIWC protected record")?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("SIWC protected record exceeds operation bound".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid SIWC protected record".into())
}
fn write_private(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if path.exists() {
        check_private(path, false)?;
    }
    let bytes = serde_json::to_vec(value).map_err(|_| "Cannot encode SIWC protected record")?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("SIWC protected record exceeds operation bound".into());
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| "Storage randomness unavailable")?;
    let temporary = path.with_file_name(format!(".pending-{}", crate::state::hex(&random)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|_| "Cannot create protected SIWC replacement")?;
        file.write_all(&bytes)
            .map_err(|_| "Cannot write protected SIWC replacement")?;
        file.sync_all()
            .map_err(|_| "Cannot sync protected SIWC replacement")?;
        drop(file);
        fs::rename(&temporary, path)
            .map_err(|_| "Cannot atomically replace protected SIWC record")?;
        #[cfg(unix)]
        File::open(path.parent().ok_or("SIWC record parent missing")?)
            .and_then(|f| f.sync_all())
            .map_err(|_| "Cannot sync SIWC credential directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
