//! Bounded, participant-local access to the official Codex App Server.
//!
//! Authentication stays inside Codex. This client never reads credentials and never
//! supports API keys, externally injected tokens, or a hosted proxy. An explicit
//! participant option permits bounded pure JavaScript through an owned local host.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) const MAX_INPUT_BYTES: usize = 32 * 1024;
pub(crate) const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_EVENTS: usize = 4096;
const MAX_MODEL_PAGES: usize = 8;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub codex_binary: PathBuf,
    /// A participant-owned Codex home, authenticated through `codex login`.
    pub codex_home: PathBuf,
    /// An exact model name returned by the authenticated `model/list` endpoint.
    pub model: String,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
    /// Optional exact inherited names to disable on the initial process launch.
    #[serde(default, skip_serializing_if = "DisabledRegistries::is_empty")]
    pub disabled_registries: DisabledRegistries,
    /// Explicit local-mathematics exception; omission preserves the text-only path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pure_js: Option<PureJsConfig>,
}

/// Exact executable bytes for the audited Codex 0.159.2 host protocol.
/// `codex_binary` must be the direct native executable, rather than a launcher.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PureJsConfig {
    pub native_host_binary: PathBuf,
    pub host_proxy_binary: PathBuf,
    pub package_manifest: PathBuf,
    pub codex_binary_sha256: String,
    pub native_host_sha256: String,
    pub host_proxy_sha256: String,
    pub package_manifest_sha256: String,
    /// Preserve the signed desktop bundle when the native macOS CLI belongs to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_bundle: Option<MacosBundleConfig>,
}

/// Fixed public package support files; contents are copied without interpretation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosBundleConfig {
    pub info_plist_sha256: String,
    pub provision_profile_sha256: String,
    pub legacy_code_resources_sha256: String,
    pub code_signature_resources_sha256: String,
    pub launcher_sha256: String,
}

impl MacosBundleConfig {
    fn files(&self) -> [(&'static str, &str); 5] {
        [
            ("CodexCLI.app/Contents/Info.plist", &self.info_plist_sha256),
            (
                "CodexCLI.app/Contents/embedded.provisionprofile",
                &self.provision_profile_sha256,
            ),
            (
                "CodexCLI.app/Contents/CodeResources",
                &self.legacy_code_resources_sha256,
            ),
            (
                "CodexCLI.app/Contents/_CodeSignature/CodeResources",
                &self.code_signature_resources_sha256,
            ),
            ("bin/codex", &self.launcher_sha256),
        ]
    }
}

impl PureJsConfig {
    fn validate(&self, codex_binary: &std::path::Path) -> Result<(), ProviderError> {
        for (path, expected) in [
            (codex_binary, &self.codex_binary_sha256),
            (self.native_host_binary.as_path(), &self.native_host_sha256),
            (self.host_proxy_binary.as_path(), &self.host_proxy_sha256),
            (
                self.package_manifest.as_path(),
                &self.package_manifest_sha256,
            ),
        ] {
            if !path.is_absolute()
                || expected.len() != 64
                || !expected
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                || executable_digest(path)? != *expected
            {
                return Err(ProviderError::contract(
                    "Pure JavaScript executable identity mismatch",
                ));
            }
        }
        let mut manifest = Vec::new();
        fs::File::open(&self.package_manifest)
            .and_then(|file| file.take(4097).read_to_end(&mut manifest))
            .map_err(|_| ProviderError::contract("Cannot read pinned package manifest"))?;
        if manifest.len() > 4096 {
            return Err(ProviderError::contract("Package manifest exceeds bound"));
        }
        let metadata: Value = serde_json::from_slice(&manifest)
            .map_err(|_| ProviderError::contract("Invalid package manifest"))?;
        if metadata["layoutVersion"] != 1
            || metadata["version"] != "0.159.2"
            || metadata["entrypoint"]
                != if cfg!(windows) {
                    "bin/codex.exe"
                } else {
                    "bin/codex"
                }
        {
            return Err(ProviderError::contract(
                "Unsupported audited package manifest",
            ));
        }
        if let Some(bundle) = &self.macos_bundle {
            if !cfg!(target_os = "macos") {
                return Err(ProviderError::contract("macOS bundle requires macOS"));
            }
            let root = self
                .package_manifest
                .parent()
                .ok_or_else(|| ProviderError::contract("Invalid signed package root"))?;
            if codex_binary != root.join("CodexCLI.app/Contents/MacOS/codex") {
                return Err(ProviderError::contract(
                    "Native CLI is outside pinned bundle",
                ));
            }
            if fs::symlink_metadata(codex_binary)
                .map_err(|_| ProviderError::contract("Cannot inspect bundled native CLI"))?
                .file_type()
                .is_symlink()
            {
                return Err(ProviderError::contract(
                    "Bundled native CLI must be a regular file",
                ));
            }
            for relative in [
                "CodexCLI.app",
                "CodexCLI.app/Contents",
                "CodexCLI.app/Contents/MacOS",
                "CodexCLI.app/Contents/_CodeSignature",
                "bin",
            ] {
                let metadata = fs::symlink_metadata(root.join(relative)).map_err(|_| {
                    ProviderError::contract("Cannot inspect signed package directory")
                })?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(ProviderError::contract("Invalid signed package directory"));
                }
            }
            for (relative, expected) in bundle.files() {
                if !valid_digest(expected) || bundle_file_digest(&root.join(relative))? != expected
                {
                    return Err(ProviderError::contract("Signed package identity mismatch"));
                }
            }
        } else if cfg!(target_os = "macos")
            && codex_binary
                .ancestors()
                .any(|path| path.extension().is_some_and(|ext| ext == "app"))
        {
            return Err(ProviderError::contract(
                "Signed macOS CLI requires bundle metadata",
            ));
        }
        Ok(())
    }
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn bundle_file_digest(path: &std::path::Path) -> Result<String, ProviderError> {
    Ok(bytes_digest(&read_bundle_file(path)?))
}

fn bytes_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read_bundle_file(path: &std::path::Path) -> Result<Vec<u8>, ProviderError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ProviderError::contract("Cannot inspect signed package file"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > 1024 * 1024
    {
        return Err(ProviderError::contract(
            "Invalid bounded signed package file",
        ));
    }
    // Read at most one byte beyond the support-file bound, including a growth race.
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(1024 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|_| ProviderError::contract("Cannot hash signed package file"))?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(ProviderError::contract("Signed package file exceeds bound"));
    }
    Ok(bytes)
}

fn executable_digest(path: &std::path::Path) -> Result<String, ProviderError> {
    let mut file = fs::File::open(path)
        .map_err(|_| ProviderError::contract("Cannot read configured executable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| ProviderError::contract("Cannot inspect configured executable"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 256 * 1024 * 1024 {
        return Err(ProviderError::contract("Invalid bounded executable file"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| ProviderError::contract("Cannot hash configured executable"))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > 256 * 1024 * 1024 {
            return Err(ProviderError::contract(
                "Executable changed beyond bounded size",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisabledRegistries {
    #[serde(default)]
    pub mcp_servers: Vec<String>,
    #[serde(default)]
    pub plugins: Vec<String>,
}

impl DisabledRegistries {
    fn is_empty(&self) -> bool {
        self.mcp_servers.is_empty() && self.plugins.is_empty()
    }

    fn validate(&self) -> Result<(), ProviderError> {
        for names in [&self.mcp_servers, &self.plugins] {
            if names.len() > 64
                || names.iter().any(|name| {
                    name.is_empty() || name.len() > 256 || name.chars().any(char::is_control)
                })
                || names.iter().collect::<BTreeSet<_>>().len() != names.len()
            {
                return Err(ProviderError::contract(
                    "Invalid bounded initial registry names",
                ));
            }
        }
        Ok(())
    }

    fn overrides(&self) -> Vec<String> {
        [
            ("mcp_servers", &self.mcp_servers),
            ("plugins", &self.plugins),
        ]
        .into_iter()
        .filter(|(_, names)| !names.is_empty())
        .map(|(registry, names)| {
            let entries = names
                .iter()
                .map(|name| format!("{}={{enabled=false}}", json!(name)))
                .collect::<Vec<_>>();
            format!("{registry}={{{}}}", entries.join(","))
        })
        .collect()
    }
}

impl ProviderConfig {
    pub(crate) fn validate(&self) -> Result<(), ProviderError> {
        if !self.codex_binary.is_absolute()
            || !self.codex_home.is_absolute()
            || self.model.is_empty()
            || self.model.len() > 128
            || self.timeout_seconds == 0
            || self.timeout_seconds > 600
            || !(4096..=MAX_OUTPUT_BYTES).contains(&self.max_output_bytes)
        {
            return Err(ProviderError::contract(
                "Invalid bounded App Server configuration",
            ));
        }
        self.disabled_registries.validate()?;
        if let Some(config) = &self.pure_js {
            config.validate(&self.codex_binary)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Auth,
    Quota,
    Transient,
    Contract,
    TimeBudget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    /// Local, sanitized explanation; upstream messages and credentials are omitted.
    pub message: String,
}

impl ProviderError {
    fn new(kind: ProviderErrorKind, message: &str) -> Self {
        Self {
            kind,
            message: message.to_owned(),
        }
    }

    fn contract(message: &str) -> Self {
        Self::new(ProviderErrorKind::Contract, message)
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ProviderError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderReply {
    pub value: Value,
    pub raw_response: String,
    /// Official per-turn token usage, or null when the server did not report it.
    pub usage: Value,
    /// Bounded standard-v2 exec/wait output observations; these are not full
    /// JavaScript source traces or an execution authorization boundary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub computation: Vec<Value>,
}

struct Budget {
    deadline: Instant,
    bytes: usize,
    events: usize,
    maximum_bytes: usize,
}

impl Budget {
    fn new(config: &ProviderConfig) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(config.timeout_seconds),
            bytes: 0,
            events: 0,
            maximum_bytes: config.max_output_bytes,
        }
    }

    fn remaining(&self) -> Result<Duration, ProviderError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorKind::TimeBudget,
                    "App Server wall time exhausted",
                )
            })
    }

    fn charge(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.remaining()?;
        self.bytes = self.bytes.saturating_add(bytes);
        self.events = self.events.saturating_add(1);
        if self.bytes > self.maximum_bytes || self.events > MAX_EVENTS {
            return Err(ProviderError::contract(
                "App Server stream budget exhausted",
            ));
        }
        Ok(())
    }
}

/// A synchronous client with one outstanding turn and bounded pipe readers.
/// Any failed operation permanently closes the process; retry belongs to the caller.
pub struct AppServer {
    config: ProviderConfig,
    child: Option<Child>,
    sender: Option<SyncSender<Vec<u8>>>,
    receiver: Option<Receiver<Result<Vec<u8>, ProviderError>>>,
    workers: Vec<JoinHandle<()>>,
    cwd: PathBuf,
    runtime_dir: PathBuf,
    next_id: u64,
    active_turn: Option<(String, String)>,
    info: Value,
    rate_limits: Value,
    effort: String,
    deferred_events: VecDeque<Value>,
    lifecycle_deadline: Instant,
    required_disables: Vec<String>,
    host_status_seen: bool,
    observed_usage: Value,
    observed_response: Option<String>,
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    accounted_native: bool,
}

// Installed 0.153.4 accepts these keys under --strict-config. The official
// config schema documents them. Empty thread/turn `environments` is additionally
// required: source tools/spec_plan.rs gates shell, apply_patch and view_image on
// has_environment(), rather than treating sandbox=read-only as a tool deny list.
fn isolation_overrides() -> Vec<(&'static str, Value)> {
    let mut overrides = vec![
        ("model_provider", json!("openai")),
        ("model_providers", json!({})),
        ("web_search", json!("disabled")),
        ("mcp_servers", json!({})),
        ("plugins", json!({})),
        ("hooks", json!({})),
        ("apps._default.enabled", json!(false)),
        ("skills.include_instructions", json!(false)),
        ("skills.bundled.enabled", json!(false)),
        ("agents.enabled", json!(false)),
        ("tools.update_plan.enabled", json!(false)),
        (
            "tools.experimental_request_user_input.enabled",
            json!(false),
        ),
        ("project_doc_max_bytes", json!(0)),
        ("shell_environment_policy.inherit", json!("none")),
        ("allow_login_shell", json!(false)),
        ("include_apps_instructions", json!(false)),
        ("include_environment_context", json!(false)),
        ("analytics.enabled", json!(false)),
        ("notify", json!([])),
    ];
    for key in [
        "features.shell_tool",
        "features.unified_exec",
        "features.shell_snapshot",
        "features.apps",
        "features.plugins",
        "features.remote_plugin",
        "features.hooks",
        "features.browser_use",
        "features.browser_use_external",
        "features.browser_use_full_cdp_access",
        "features.computer_use",
        "features.code_mode",
        "features.code_mode_host",
        "features.code_mode_only",
        "features.code_mode_prewarm",
        "features.multi_agent",
        "features.multi_agent_v2",
        "features.artifact",
        "features.image_generation",
        "features.view_image",
        "features.memories",
        "features.skill_search",
        "features.skill_mcp_dependency_install",
        "features.skill_env_var_dependency_prompt",
        "features.workspace_dependencies",
        "features.standalone_web_search",
        "features.request_permissions_tool",
        "features.deferred_executor",
        "features.tool_suggest",
        "features.goals",
        "features.token_budget",
        "features.sleep_tool",
        "features.current_time_reminder",
        "features.unbounded_connection_retries",
    ] {
        overrides.push((key, json!(false)));
    }
    overrides.push(("features.skip_host_skill_discovery", json!(true)));
    overrides
}

fn provider_overrides(config: &ProviderConfig) -> Vec<(&'static str, Value)> {
    let mut overrides = isolation_overrides();
    if config.pure_js.is_some() {
        overrides
            .retain(|(key, _)| !["features.code_mode", "features.code_mode_host"].contains(key));
        overrides.extend([
            ("features.code_mode.enabled", json!(true)),
            (
                "features.code_mode.excluded_tool_namespaces",
                json!(["functions", "clock"]),
            ),
            ("features.code_mode.direct_only_tool_namespaces", json!([])),
            ("features.code_mode_host.enabled", json!(true)),
            (
                "features.code_mode_host.disable_in_process_fallback",
                json!(true),
            ),
            ("suppress_unstable_features_warning", json!(true)),
        ]);
    }
    overrides
}

fn is_pure_js_origin_key(key: &str) -> bool {
    key.starts_with("features.code_mode.") || key.starts_with("features.code_mode_host.")
}

fn staged_codex_path(pure: &PureJsConfig, runtime_dir: &std::path::Path) -> PathBuf {
    if pure.macos_bundle.is_some() {
        runtime_dir.join("CodexCLI.app/Contents/MacOS/codex")
    } else {
        runtime_dir
            .join("bin")
            .join(if cfg!(windows) { "codex.exe" } else { "codex" })
    }
}

fn stage_pure_js(
    config: &ProviderConfig,
    runtime_dir: &std::path::Path,
) -> Result<(PathBuf, Option<String>), ProviderError> {
    let Some(pure) = &config.pure_js else {
        return Ok((config.codex_binary.clone(), None));
    };
    // InstallContext::code_mode_host_program in audited ff6aec9 resolves an
    // executable-adjacent host. Copying exact bytes creates that supported layout
    // without changing an installed package or relying on an undocumented key.
    let bin = runtime_dir.join("bin");
    fs::create_dir(&bin)
        .map_err(|_| ProviderError::contract("Cannot stage package bin directory"))?;
    let cli = staged_codex_path(pure, runtime_dir);
    if let Some(bundle) = &pure.macos_bundle {
        pure.validate(&config.codex_binary)?;
        fs::create_dir_all(runtime_dir.join("CodexCLI.app/Contents/MacOS"))
            .and_then(|()| fs::create_dir(runtime_dir.join("CodexCLI.app/Contents/_CodeSignature")))
            .map_err(|_| ProviderError::contract("Cannot stage signed package directories"))?;
        let root = pure
            .package_manifest
            .parent()
            .ok_or_else(|| ProviderError::contract("Invalid signed package root"))?;
        for (relative, expected) in bundle.files() {
            let source = root.join(relative);
            let bytes = read_bundle_file(&source)?;
            if bytes_digest(&bytes) != expected {
                return Err(ProviderError::contract(
                    "Signed package changed before staging",
                ));
            }
            let target = runtime_dir.join(relative);
            fs::write(&target, bytes)
                .and_then(|()| fs::set_permissions(&target, fs::metadata(&source)?.permissions()))
                .map_err(|_| ProviderError::contract("Cannot stage signed package file"))?;
            if bundle_file_digest(&target)? != expected {
                return Err(ProviderError::contract(
                    "Staged signed package identity mismatch",
                ));
            }
        }
    }
    let proxy = bin.join(if cfg!(windows) {
        "codex-code-mode-host.exe"
    } else {
        "codex-code-mode-host"
    });
    let native = runtime_dir.join(if cfg!(windows) {
        "native-code-mode-host.exe"
    } else {
        "native-code-mode-host"
    });
    for (source, target, expected) in [
        (&config.codex_binary, &cli, &pure.codex_binary_sha256),
        (&pure.host_proxy_binary, &proxy, &pure.host_proxy_sha256),
        (&pure.native_host_binary, &native, &pure.native_host_sha256),
        (
            &pure.package_manifest,
            &runtime_dir.join("codex-package.json"),
            &pure.package_manifest_sha256,
        ),
    ] {
        fs::copy(source, target)
            .map_err(|_| ProviderError::contract("Cannot stage owned code host"))?;
        if executable_digest(target)? != *expected {
            return Err(ProviderError::contract(
                "Staged code host identity mismatch",
            ));
        }
    }
    let host = crate::host_proxy::HostProxyConfig {
        native_binary: native,
        status_file: runtime_dir.join("host-status.json"),
        timeout_millis: config.timeout_seconds * 1000,
        max_output_bytes: config.max_output_bytes,
    };
    host.validate()
        .map_err(|_| ProviderError::contract("Invalid owned host configuration"))?;
    let encoded = serde_json::to_string(&host)
        .map_err(|_| ProviderError::contract("Cannot encode owned host configuration"))?;
    Ok((cli, Some(encoded)))
}

fn toml_value(value: &Value) -> String {
    // Only static scalar values and empty tables occur in the overrides.
    if value.is_object() {
        "{}".to_owned()
    } else {
        value.to_string()
    }
}

fn read_lines(
    source: impl Read,
    maximum: usize,
    sender: SyncSender<Result<Vec<u8>, ProviderError>>,
) {
    let mut reader = BufReader::new(source);
    loop {
        let mut line = Vec::new();
        loop {
            let available = match reader.fill_buf() {
                Ok(bytes) => bytes,
                Err(_) => {
                    let _ = sender.send(Err(ProviderError::new(
                        ProviderErrorKind::Transient,
                        "App Server pipe read failed",
                    )));
                    return;
                }
            };
            if available.is_empty() {
                let _ = sender.send(Err(ProviderError::new(
                    ProviderErrorKind::Transient,
                    "App Server closed its output pipe",
                )));
                return;
            }
            let length = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            if line.len().saturating_add(length) > maximum {
                let _ = sender.send(Err(ProviderError::contract(
                    "App Server line exceeds the output budget",
                )));
                return;
            }
            let complete = available[length - 1] == b'\n';
            line.extend_from_slice(&available[..length]);
            reader.consume(length);
            if complete {
                break;
            }
        }
        if sender.send(Ok(line)).is_err() {
            return;
        }
    }
}

impl AppServer {
    pub fn start(config: &ProviderConfig) -> Result<Self, ProviderError> {
        config.validate()?;
        let deadline = Instant::now() + Duration::from_secs(config.timeout_seconds);
        let mut server = Self::launch(config, deadline, &[])?;
        let mut budget = Budget::new(config);
        budget.deadline = deadline;
        if let Err(error) = server.handshake(&mut budget) {
            let required = std::mem::take(&mut server.required_disables);
            server.stop();
            if required.is_empty() {
                return Err(error);
            }
            // The bootstrap has no research thread or turn. Restart once with
            // every inherited registry entry explicitly disabled; an empty CLI
            // table merges with participant configuration instead of clearing it.
            let mut isolated = Self::launch(config, deadline, &required)?;
            if let Err(error) = isolated.handshake(&mut budget) {
                isolated.stop();
                return Err(ProviderError::new(
                    error.kind,
                    &format!("Isolated restart: {}", error.message),
                ));
            }
            return Ok(isolated);
        }
        Ok(server)
    }

    fn launch(
        config: &ProviderConfig,
        deadline: Instant,
        disables: &[String],
    ) -> Result<Self, ProviderError> {
        let mut budget = Budget::new(config);
        budget.deadline = deadline;
        budget.remaining()?;
        let cwd = create_empty_directory()?;
        let runtime_dir = match create_empty_directory() {
            Ok(directory) => directory,
            Err(error) => {
                let _ = fs::remove_dir(&cwd);
                return Err(error);
            }
        };
        let (executable, host_config) = match stage_pure_js(config, &runtime_dir) {
            Ok(staged) => staged,
            Err(error) => {
                let _ = fs::remove_dir(&cwd);
                let _ = fs::remove_dir_all(&runtime_dir);
                return Err(error);
            }
        };
        let mut command = Command::new(executable);
        command
            .arg("app-server")
            .arg("--stdio")
            .arg("--strict-config")
            .env_clear()
            .env("CODEX_HOME", &config.codex_home)
            .env("PATH", minimal_path())
            .current_dir(&cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Diagnostics may contain private account or configuration details.
            .stderr(Stdio::null());
        if let Some(host_config) = host_config {
            command.env("NAOME_RESEARCH_HOST_CONFIG", host_config);
        }
        for key in [
            "HOME",
            "USERPROFILE",
            "SYSTEMROOT",
            "WINDIR",
            "APPDATA",
            "LOCALAPPDATA",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        for (key, value) in provider_overrides(config) {
            command
                .arg("-c")
                .arg(format!("{key}={}", toml_value(&value)));
        }
        for override_value in config
            .disabled_registries
            .overrides()
            .iter()
            .chain(disables)
        {
            command.arg("-c").arg(override_value);
        }
        // Keep native Codex state and logs separate from both credentials and the
        // empty research cwd. Ephemeral threads do not persist research history.
        for key in ["sqlite_home", "log_dir"] {
            command
                .arg("-c")
                .arg(format!("{key}={}", json!(runtime_dir)));
        }
        command.arg("-c").arg("approval_policy=\"never\"");
        command.arg("-c").arg("sandbox_mode=\"read-only\"");
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                let _ = fs::remove_dir(&cwd);
                let _ = fs::remove_dir_all(&runtime_dir);
                return Err(ProviderError::new(
                    ProviderErrorKind::Transient,
                    "Cannot start the configured Codex binary",
                ));
            }
        };
        Self::attach(config.clone(), cwd, runtime_dir, child, budget.deadline)
    }

    fn attach(
        config: ProviderConfig,
        cwd: PathBuf,
        runtime_dir: PathBuf,
        mut child: Child,
        lifecycle_deadline: Instant,
    ) -> Result<Self, ProviderError> {
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_dir(&cwd);
            let _ = fs::remove_dir_all(&runtime_dir);
            return Err(ProviderError::contract("Missing App Server input pipe"));
        };
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_dir(&cwd);
            let _ = fs::remove_dir_all(&runtime_dir);
            return Err(ProviderError::contract("Missing App Server output pipe"));
        };
        let (sender, writes) = mpsc::sync_channel::<Vec<u8>>(1);
        let (output_sender, receiver) = mpsc::sync_channel(16);
        let maximum = config.max_output_bytes;
        let reader = thread::spawn(move || read_lines(stdout, maximum, output_sender));
        let writer = thread::spawn(move || {
            while let Ok(bytes) = writes.recv() {
                if stdin
                    .write_all(&bytes)
                    .and_then(|()| stdin.flush())
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(Self {
            config,
            child: Some(child),
            sender: Some(sender),
            receiver: Some(receiver),
            workers: vec![reader, writer],
            cwd,
            runtime_dir,
            next_id: 1,
            active_turn: None,
            info: Value::Null,
            rate_limits: Value::Null,
            effort: String::new(),
            deferred_events: VecDeque::new(),
            lifecycle_deadline,
            required_disables: Vec::new(),
            host_status_seen: false,
            observed_usage: Value::Null,
            observed_response: None,
            cancel: None,
            accounted_native: false,
        })
    }

    fn handshake(&mut self, budget: &mut Budget) -> Result<(), ProviderError> {
        let initialized = self.rpc(
            "initialize",
            json!({
                "clientInfo": {"name":"naome_research", "version":env!("CARGO_PKG_VERSION")},
                "capabilities": {"experimentalApi":true}
            }),
            budget,
        )?;
        self.accounted_native = initialized["userAgent"].as_str().is_some_and(|agent| {
            agent
                .split_ascii_whitespace()
                .next()
                .is_some_and(|token| token.ends_with("/0.159.2"))
        });
        if self.config.pure_js.is_some()
            && !initialized["userAgent"].as_str().is_some_and(|agent| {
                agent
                    .split_ascii_whitespace()
                    .next()
                    .is_some_and(|token| token.ends_with("/0.159.2"))
            })
        {
            return Err(ProviderError::contract(
                "Owned host requires audited native Codex 0.159.2",
            ));
        }
        self.send(json!({"method":"initialized"}), budget)?;
        let account = self.rpc("account/read", json!({"refreshToken":false}), budget)?;
        if account.pointer("/account/type").and_then(Value::as_str) != Some("chatgpt") {
            return Err(ProviderError::new(
                ProviderErrorKind::Auth,
                "Managed ChatGPT login is required; run codex login for this participant",
            ));
        }
        let effective = self.rpc(
            "config/read",
            json!({"includeLayers":true,"cwd":self.cwd}),
            budget,
        )?;
        self.required_disables = registry_disables(&effective["config"])?;
        if !self.required_disables.is_empty() {
            return Err(ProviderError::contract(
                "Inherited registries require explicit isolated disables",
            ));
        }
        verify_provider_config(&effective, &self.config)?;
        let mut cursor = Value::Null;
        let mut selected = None;
        for _ in 0..MAX_MODEL_PAGES {
            let catalog = self.rpc(
                "model/list",
                json!({"cursor":cursor,"limit":100,"includeHidden":false}),
                budget,
            )?;
            let models = catalog["data"]
                .as_array()
                .ok_or_else(|| ProviderError::contract("Invalid model catalog"))?;
            if let Some(model) = models.iter().find(|entry| {
                entry["model"].as_str() == Some(self.config.model.as_str())
                    && entry["hidden"].as_bool() == Some(false)
            }) {
                selected = Some(model.clone());
                break;
            }
            cursor = catalog["nextCursor"].clone();
            if cursor.is_null() {
                break;
            }
        }
        let selected = selected.ok_or_else(|| {
            ProviderError::contract(
                "Requested model is absent from the authenticated visible catalog",
            )
        })?;
        self.effort = ["minimal", "low", "medium"]
            .into_iter()
            .find(|effort| {
                selected["supportedReasoningEfforts"]
                    .as_array()
                    .is_some_and(|options| {
                        options
                            .iter()
                            .any(|option| option["reasoningEffort"].as_str() == Some(effort))
                    })
            })
            .ok_or_else(|| ProviderError::contract("Model advertises no bounded reasoning effort"))?
            .to_owned();
        let limits = self.rpc("account/rateLimits/read", json!({}), budget)?;
        self.rate_limits = sanitize_limits(&limits)?;
        self.info = json!({
            "accountMode":"chatgpt", "planType":account.pointer("/account/planType"),
            "model":self.config.model, "reasoningEffort":self.effort,
            "transport":"stdio", "environmentAccess":false,
            "timeoutSeconds":self.config.timeout_seconds,
            "maxOutputBytes":self.config.max_output_bytes,
            "maxInputBytes":MAX_INPUT_BYTES, "maxEvents":MAX_EVENTS,
            "toolConfigVerification":"origin_bound_session_flags",
            "localComputation": if self.config.pure_js.is_some() { "bounded_pure_js" } else { "none" }
        });
        if let Some(pure) = &self.config.pure_js {
            self.info["hostRuntime"] = json!({
                "auditedCodexVersion":"0.159.2",
                "sourceRevision":"ff6aec96948b70d94983af2641a6b67c94faeff5",
                "codexSha256":pure.codex_binary_sha256,
                "nativeHostSha256":pure.native_host_sha256,
                "proxySha256":pure.host_proxy_sha256,
                "packageManifestSha256":pure.package_manifest_sha256,
                "nativeUserAgent":initialized["userAgent"],
                "resolvedCodexPath":staged_codex_path(pure, &self.runtime_dir),
                "resolvedProxyPath":self.runtime_dir.join("bin").join(if cfg!(windows) {"codex-code-mode-host.exe"} else {"codex-code-mode-host"}),
                "resolvedNativeHostPath":self.runtime_dir.join(if cfg!(windows) {"native-code-mode-host.exe"} else {"native-code-mode-host"}),
                "ownershipPolicy":if cfg!(unix) {"proxy_verifies_own_group_native_inherits"} else {"retained_child_tree_bounded_cleanup"},
                "executeEnabledTools":"required_empty_before_forward",
                "effectiveControls":pure_js_controls(&effective)?,
                "hardHeapLimit":false,
                "traceCoverage":"standard_v2_exec_wait_outputs"
            });
            if let Some(bundle) = &pure.macos_bundle {
                self.info["hostRuntime"]["macosBundleSha256"] = serde_json::to_value(bundle)
                    .map_err(|_| {
                        ProviderError::contract("Cannot record signed package identity")
                    })?;
            }
        }
        Ok(())
    }

    pub fn info(&self) -> Value {
        self.info.clone()
    }

    pub fn limits(&self) -> Value {
        self.rate_limits.clone()
    }

    /// Known partial counts survive an accounting failure; completeness is
    /// never inferred from this projection.
    pub fn observed_usage(&self) -> Value {
        self.observed_usage.clone()
    }
    pub fn observed_response(&self) -> Option<String> {
        self.observed_response.clone()
    }
    pub fn set_cancel(&mut self, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.cancel = Some(stop);
    }

    pub fn request(
        &mut self,
        prompt: &str,
        output_schema: Value,
    ) -> Result<ProviderReply, ProviderError> {
        if self.child.is_none() {
            return Err(ProviderError::contract(
                "App Server is closed; start a fresh client",
            ));
        }
        let mut budget = Budget::new(&self.config);
        budget.deadline = budget.deadline.min(self.lifecycle_deadline);
        let result = self.request_inner(prompt, output_schema, &mut budget, false);
        if result.is_err() {
            self.stop();
        }
        result
    }

    /// Version 2 requires exact usage on every observed upstream completion.
    /// This source-pinned experimental capability has no total-token cap.
    pub fn request_accounted(
        &mut self,
        prompt: &str,
        output_schema: Value,
    ) -> Result<ProviderReply, ProviderError> {
        if !self.accounted_native {
            return Err(ProviderError::contract(
                "Accounted requests require source-pinned native Codex 0.159.2",
            ));
        }
        if self.child.is_none() {
            return Err(ProviderError::contract("App Server is closed"));
        }
        let mut budget = Budget::new(&self.config);
        budget.deadline = budget.deadline.min(self.lifecycle_deadline);
        let result = self.request_inner(prompt, output_schema, &mut budget, true);
        if result.is_err() {
            self.stop();
        }
        result
    }

    fn request_inner(
        &mut self,
        prompt: &str,
        output_schema: Value,
        budget: &mut Budget,
        account_usage: bool,
    ) -> Result<ProviderReply, ProviderError> {
        if prompt.is_empty() || prompt.len() > MAX_INPUT_BYTES || !output_schema.is_object() {
            return Err(ProviderError::contract("Invalid bounded provider input"));
        }
        if quota_exhausted(&self.rate_limits) {
            return Err(ProviderError::new(
                ProviderErrorKind::Quota,
                "ChatGPT quota is exhausted",
            ));
        }
        let (base_instructions, developer_instructions) = if self.config.pure_js.is_some() {
            (
                "Return only the requested JSON. You may use exec/wait for bounded pure JavaScript mathematics and string computation. The local host exposes no external tools. Only the local formal checker decides proof validity.",
                "Use only supplied research context. Pure JavaScript may compute numbers and strings; never request filesystem, network, terminal, media, credentials, plugins, other agents, or user input. Finish with the exact JSON output schema.",
            )
        } else {
            (
                "Return only the requested JSON. You have no tools or environment access. A proposal is never proof validity; only the local formal checker decides validity.",
                "Use only the supplied research context. Never request tools, shell, files, web, credentials, plugins, or another agent. Return the exact output schema.",
            )
        };
        let started = self.rpc(
            "thread/start",
            json!({
                "model":self.config.model, "modelProvider":"openai",
                "cwd":self.cwd,"ephemeral":true,"approvalPolicy":"never","sandbox":"read-only",
                "environments":[],"dynamicTools":[],"selectedCapabilityRoots":[],
                "runtimeWorkspaceRoots":[],"allowProviderModelFallback":false,
                "experimentalRawEvents":account_usage,
                "baseInstructions":base_instructions,
                "developerInstructions":developer_instructions
            }),
            budget,
        )?;
        verify_thread(&started, &self.config.model)?;
        let thread_id = started
            .pointer("/thread/id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ProviderError::contract("Missing new thread id"))?
            .to_owned();
        let begun = self.rpc(
            "turn/start",
            json!({
                "threadId":thread_id,"input":[{"type":"text","text":prompt}],
                "outputSchema":output_schema,"model":self.config.model,"effort":self.effort,
                "environments":[],"approvalPolicy":"never"
            }),
            budget,
        )?;
        let turn_id = begun
            .pointer("/turn/id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ProviderError::contract("Missing new turn id"))?
            .to_owned();
        self.active_turn = Some((thread_id.clone(), turn_id.clone()));
        let mut final_text = None;
        let mut usage = Value::Null;
        let mut usage_trace = UsageTrace::default();
        if account_usage {
            self.observed_usage = Value::Null;
            self.observed_response = None;
        }
        let mut completed_code_items = BTreeSet::new();
        let mut computation = Vec::new();
        loop {
            let message = match self.deferred_events.pop_front() {
                Some(message) => message,
                None => self.receive(budget)?,
            };
            self.inspect_message(&message)?;
            let method = message["method"].as_str().unwrap_or("");
            let params = &message["params"];
            if matches!(
                method,
                "item/started"
                    | "item/completed"
                    | "thread/tokenUsage/updated"
                    | "turn/completed"
                    | "rawResponse/completed"
                    | "rawResponseItem/completed"
            ) {
                if params["threadId"].as_str() != Some(&thread_id) {
                    return Err(ProviderError::contract(
                        "Event belongs to a different thread",
                    ));
                }
                let event_turn = if method == "turn/completed" {
                    &params["turn"]["id"]
                } else {
                    &params["turnId"]
                };
                if event_turn.as_str() != Some(&turn_id) {
                    return Err(ProviderError::contract("Event belongs to a different turn"));
                }
            }
            match method {
                "item/completed" => {
                    let item = &params["item"];
                    if item["type"] == "functionCallOutput" {
                        let id = item["id"].as_str().unwrap_or("");
                        if completed_code_items.len() >= 48
                            || !completed_code_items.insert(id.to_owned())
                        {
                            return Err(ProviderError::contract(
                                "Duplicate or excessive code wrapper output",
                            ));
                        }
                        computation.push(item.clone());
                    }
                    if item["type"] == "agentMessage" && item["phase"] != "commentary" {
                        if final_text.is_some() {
                            return Err(ProviderError::contract(
                                "Multiple final provider messages",
                            ));
                        }
                        final_text = Some(
                            item["text"]
                                .as_str()
                                .ok_or_else(|| {
                                    ProviderError::contract("Invalid final provider message")
                                })?
                                .to_owned(),
                        );
                        if account_usage {
                            self.observed_response = final_text.clone();
                        }
                    }
                }
                "thread/tokenUsage/updated" => {
                    if account_usage {
                        self.observed_response = final_text.clone();
                    }
                    if account_usage {
                        usage_trace.cumulative(&params["tokenUsage"])?;
                    }
                    usage = sanitize_usage(&params["tokenUsage"]);
                    if account_usage {
                        self.observed_usage = usage_trace.partial();
                    }
                }
                "rawResponse/completed" if account_usage => {
                    usage_trace.response(params)?;
                    self.observed_usage = usage_trace.partial();
                }
                "turn/completed" => {
                    self.active_turn = None;
                    let turn = &params["turn"];
                    if account_usage {
                        usage = usage_trace.finish(usage)?;
                        self.observed_usage = usage.clone();
                    }
                    if turn["status"] != "completed" {
                        return Err(classify_error(&turn["error"]));
                    }
                    let text = final_text.ok_or_else(|| {
                        ProviderError::contract("Turn completed without a final response")
                    })?;
                    let value = serde_json::from_str(&text).map_err(|_| {
                        ProviderError::contract("Final response is not a single JSON value")
                    })?;
                    if self.config.pure_js.is_some() {
                        let path = self.runtime_dir.join("host-status.json");
                        let present = verify_host_status(&path, false)?.is_some();
                        if self.host_status_seen || !computation.is_empty() || present {
                            self.info["hostRuntime"]["observedStatus"] =
                                verify_host_status(&path, true)?.ok_or_else(|| {
                                    ProviderError::contract("Missing verified code host status")
                                })?;
                        }
                    }
                    return Ok(ProviderReply {
                        value,
                        raw_response: text,
                        usage,
                        computation,
                    });
                }
                _ => {}
            }
        }
    }

    fn send(&mut self, value: Value, budget: &Budget) -> Result<(), ProviderError> {
        budget.remaining()?;
        let mut bytes = serde_json::to_vec(&value)
            .map_err(|_| ProviderError::contract("Cannot encode provider request"))?;
        if bytes.len() > 2 * MAX_INPUT_BYTES {
            return Err(ProviderError::contract(
                "Provider request exceeds input budget",
            ));
        }
        bytes.push(b'\n');
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| ProviderError::contract("App Server is closed"))?;
        loop {
            match sender.try_send(bytes) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(returned)) => {
                    bytes = returned;
                    thread::sleep(budget.remaining()?.min(Duration::from_millis(1)));
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Transient,
                        "App Server input pipe is unavailable",
                    ));
                }
            }
        }
    }

    fn receive(&mut self, budget: &mut Budget) -> Result<Value, ProviderError> {
        let bytes = loop {
            if self
                .cancel
                .as_ref()
                .is_some_and(|stop| stop.load(Ordering::SeqCst))
            {
                return Err(ProviderError::new(
                    ProviderErrorKind::TimeBudget,
                    "Provider operation stopped by operator",
                ));
            }
            let remaining = budget.remaining()?;
            let timeout = if self.cancel.is_some() {
                remaining.min(Duration::from_millis(200))
            } else {
                remaining
            };
            match self
                .receiver
                .as_ref()
                .ok_or_else(|| ProviderError::contract("App Server is closed"))?
                .recv_timeout(timeout)
            {
                Ok(bytes) => break bytes?,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Transient,
                        "App Server reader stopped",
                    ));
                }
            }
        };
        budget.charge(bytes.len())?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| ProviderError::contract("Malformed App Server JSON line"))?;
        if !value.is_object() {
            return Err(ProviderError::contract("App Server frame is not an object"));
        }
        Ok(value)
    }

    fn rpc(
        &mut self,
        method: &str,
        params: Value,
        budget: &mut Budget,
    ) -> Result<Value, ProviderError> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"id":id,"method":method,"params":params}), budget)?;
        loop {
            let message = self.receive(budget).map_err(|mut error| {
                error.message.push_str(&format!(" while awaiting {method}"));
                error
            })?;
            self.inspect_message(&message)?;
            if message.get("id").is_some() && message.get("method").is_none() {
                if message["id"].as_u64() != Some(id) {
                    return Err(ProviderError::contract("Unexpected App Server response id"));
                }
                if let Some(error) = message.get("error") {
                    return Err(classify_error(error));
                }
                return message
                    .get("result")
                    .cloned()
                    .ok_or_else(|| ProviderError::contract("Missing App Server result"));
            }
            if matches!(
                message["method"].as_str(),
                Some(
                    "item/started"
                        | "item/completed"
                        | "thread/tokenUsage/updated"
                        | "turn/completed"
                        | "rawResponse/completed"
                        | "rawResponseItem/completed"
                )
            ) {
                // Notifications can precede the request's response. Retain them
                // within the existing byte/event budget and validate both ids once
                // turn/start returns the authoritative turn id.
                if method != "turn/start" || self.deferred_events.len() >= 16 {
                    return Err(ProviderError::contract(
                        "Unexpected or excessive early turn events",
                    ));
                }
                self.deferred_events.push_back(message);
            }
        }
    }

    fn inspect_message(&mut self, message: &Value) -> Result<(), ProviderError> {
        if self.config.pure_js.is_some() {
            match verify_host_status(&self.runtime_dir.join("host-status.json"), false)? {
                Some(status) => {
                    self.host_status_seen = true;
                    self.info["hostRuntime"]["observedStatus"] = status;
                }
                None if self.host_status_seen => {
                    return Err(ProviderError::contract(
                        "Owned code host status disappeared",
                    ));
                }
                None => {}
            }
        }
        if message.get("method").is_some() && message.get("id").is_some() {
            // No approvals, externally owned auth refresh, elicitation or tool calls.
            return Err(ProviderError::contract(
                "App Server requested an unsupported client action",
            ));
        }
        let params = &message["params"];
        match message["method"].as_str().unwrap_or("") {
            "account/updated" => {
                if params["authMode"] != "chatgpt" {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Auth,
                        "Managed ChatGPT authentication changed",
                    ));
                }
            }
            "account/rateLimits/updated" => {
                self.rate_limits = sanitize_limits(params)?;
                if quota_exhausted(&self.rate_limits) {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Quota,
                        "ChatGPT quota is exhausted",
                    ));
                }
            }
            "item/started" | "item/completed" => {
                let item = &params["item"];
                let kind = item["type"].as_str().unwrap_or("");
                if kind == "functionCallOutput" && self.config.pure_js.is_some() {
                    verify_host_status(&self.runtime_dir.join("host-status.json"), true)?;
                    verify_code_output(item)?;
                } else if !matches!(kind, "userMessage" | "agentMessage" | "reasoning") {
                    return Err(ProviderError::contract(
                        "Provider attempted an unsupported item or tool",
                    ));
                }
                // The native async question utility is catalog-gated separately
                // from the synchronous input setting. Its trace is an agent
                // message, so kind alone cannot establish an ordinary response.
                if kind == "agentMessage"
                    && (!item["delivery"].is_null() || !item["questions"].is_null())
                {
                    return Err(ProviderError::contract(
                        "Provider attempted asynchronous user input",
                    ));
                }
            }
            "error" => return Err(classify_error(&params["error"])),
            "configWarning" | "warning" => {
                return Err(ProviderError::contract(
                    "App Server reported a configuration or runtime warning",
                ));
            }
            "model/rerouted" => {
                return Err(ProviderError::contract(
                    "App Server rerouted the explicit model",
                ));
            }
            method if method.starts_with("hook/") || method.starts_with("mcpServer/") => {
                return Err(ProviderError::contract("Disabled capability became active"));
            }
            _ => {}
        }
        Ok(())
    }

    fn stop(&mut self) {
        if let Some((thread_id, turn_id)) = self.active_turn.take() {
            // Best-effort interrupt, immediately followed by termination. No cancellation
            // confirmation is assumed and no additional provider turn is started.
            if let Some(sender) = &self.sender
                && let Ok(mut bytes) = serde_json::to_vec(&json!({
                    "id":self.next_id,"method":"turn/interrupt",
                    "params":{"threadId":thread_id,"turnId":turn_id}
                }))
            {
                bytes.push(b'\n');
                let _ = sender.try_send(bytes);
            }
        }
        self.sender.take();
        // Disconnect the bounded reader channel before joining its sender thread.
        self.receiver.take();
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            {
                if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
            }
            #[cfg(windows)]
            {
                // The OS utility targets only this configured subprocess tree.
                if let Some(root) = std::env::var_os("SYSTEMROOT") {
                    let mut task = Command::new(PathBuf::from(root).join("System32/taskkill.exe"));
                    task.args(["/PID", &child.id().to_string(), "/T", "/F"])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());
                    if let Ok(mut killer) = task.spawn() {
                        let cutoff = Instant::now() + Duration::from_millis(100);
                        while Instant::now() < cutoff && killer.try_wait().ok().flatten().is_none()
                        {
                            thread::sleep(Duration::from_millis(1));
                        }
                        let _ = killer.kill();
                        let _ = killer.wait();
                    }
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        let cutoff = Instant::now() + Duration::from_millis(100);
        for worker in self.workers.drain(..) {
            while !worker.is_finished() && Instant::now() < cutoff {
                thread::sleep(Duration::from_millis(1));
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
            // A detached OS pipe owner cannot extend this client's deadline.
            // The finite run budget also bounds such exceptional detached workers.
        }
        let _ = fs::remove_dir_all(&self.cwd);
        let _ = fs::remove_dir_all(&self.runtime_dir);
    }
}

impl Drop for AppServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn minimal_path() -> &'static str {
    if cfg!(windows) {
        "C:\\Windows\\System32;C:\\Windows"
    } else {
        "/usr/bin:/bin:/usr/sbin:/sbin"
    }
}

fn create_empty_directory() -> Result<PathBuf, ProviderError> {
    for _ in 0..16 {
        let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let cwd = std::env::temp_dir().join(format!(
            "naome-research-provider-{}-{serial}",
            std::process::id()
        ));
        match fs::create_dir(&cwd) {
            Ok(()) => {
                return fs::canonicalize(&cwd).map_err(|_| {
                    ProviderError::contract("Cannot normalize isolated provider directory")
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err(ProviderError::contract(
                    "Cannot create isolated provider directory",
                ));
            }
        }
    }
    Err(ProviderError::contract(
        "Cannot allocate isolated provider directory",
    ))
}

#[cfg(test)]
fn verify_isolation_config(effective: &Value) -> Result<(), ProviderError> {
    verify_overrides(effective, isolation_overrides())
}

fn verify_provider_config(
    effective: &Value,
    provider: &ProviderConfig,
) -> Result<(), ProviderError> {
    verify_overrides(effective, provider_overrides(provider))
}

fn verify_overrides(effective: &Value, overrides: Vec<(&str, Value)>) -> Result<(), ProviderError> {
    let config = &effective["config"];
    for (key, expected) in overrides {
        let pointer = format!("/{}", key.replace('.', "/"));
        if ["mcp_servers", "plugins"].contains(&key)
            && registry_is_disabled(config.pointer(&pointer))
        {
            continue;
        }
        if key == "hooks" && hook_lists_are_empty(config.pointer(&pointer)) {
            continue;
        }
        // ApiConfig's typed ToolsV2 retains only web_search in 0.153.4.
        // Verify the two omitted booleans in the actual enabled CLI layer and
        // require their effective origin to match that layer's name/version.
        let actual = if is_code_array_key(key) {
            origin_bound_code_array_value(effective, key)
        } else if [
            "tools.update_plan.enabled",
            "tools.experimental_request_user_input.enabled",
        ]
        .contains(&key)
            || is_pure_js_origin_key(key)
        {
            origin_bound_tool_value(effective, key)
        } else {
            config.pointer(&pointer)
        };
        if actual != Some(&expected) {
            let shape = match actual {
                Some(Value::Object(values)) => format!("object with {} entries", values.len()),
                Some(Value::Array(values)) => format!("array with {} entries", values.len()),
                Some(Value::Null) => "null".into(),
                Some(Value::Bool(value)) => format!("boolean {value}"),
                Some(_) => "scalar".into(),
                None => "absent".into(),
            };
            return Err(ProviderError::contract(&format!(
                "Effective Codex configuration did not preserve isolation: {key} ({shape})"
            )));
        }
    }
    Ok(())
}

fn verify_code_output(item: &Value) -> Result<(), ProviderError> {
    let text_only = match item.get("output") {
        Some(Value::String(_)) => true,
        Some(Value::Array(items)) => items.iter().all(|content| {
            content["type"] == "inputText"
                && content["text"].is_string()
                && content.as_object().is_some_and(|fields| fields.len() == 2)
        }),
        _ => false,
    };
    if item["type"] != "functionCallOutput"
        || !item.as_object().is_some_and(|fields| {
            fields
                .keys()
                .all(|key| ["type", "id", "name", "namespace", "output"].contains(&key.as_str()))
        })
        || !item["id"]
            .as_str()
            .is_some_and(|id| !id.is_empty() && id.len() <= 256)
        || !matches!(item["name"].as_str(), Some("exec" | "wait"))
        || !item
            .get("namespace")
            .is_none_or(|value| value.is_null() || matches!(value.as_str(), Some("" | "functions")))
        || !text_only
    {
        return Err(ProviderError::contract("Unsupported code wrapper output"));
    }
    Ok(())
}

fn verify_host_status(
    path: &std::path::Path,
    required: bool,
) -> Result<Option<Value>, ProviderError> {
    let failed = || {
        crate::host_proxy::has_host_failed(path)
            .map_err(|_| ProviderError::contract("Cannot inspect owned code host failure latch"))
    };
    if failed()? {
        return Err(ProviderError::contract(
            "Owned code host failure is permanent",
        ));
    }
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(ProviderError::contract(
                "Owned code host status is unavailable",
            ));
        }
    };
    let mut bytes = Vec::new();
    file.take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderError::contract("Cannot read owned code host status"))?;
    if failed()? {
        return Err(ProviderError::contract(
            "Owned code host failure is permanent",
        ));
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| ProviderError::contract("Invalid owned code host status"))?;
    let fields = value
        .as_object()
        .ok_or_else(|| ProviderError::contract("Invalid owned code host status"))?;
    if bytes.len() > 1024
        || fields.len() != 4
        || !["state", "proxy_pid", "native_pid", "process_group"]
            .iter()
            .all(|key| fields.contains_key(*key))
        || !value["proxy_pid"]
            .as_u64()
            .is_some_and(|pid| pid > 0 && pid <= i32::MAX as u64)
    {
        return Err(ProviderError::contract("Invalid owned code host identity"));
    }
    if value["state"] == "starting" && !required && value["native_pid"].is_null() {
        return Ok(Some(value));
    }
    if value["state"] != "running"
        || !value["native_pid"].as_u64().is_some_and(|pid| {
            pid > 0 && pid <= i32::MAX as u64 && value["native_pid"] != value["proxy_pid"]
        })
    {
        return Err(ProviderError::contract(
            "Owned code host stopped or failed its guard",
        ));
    }
    #[cfg(unix)]
    {
        let proxy =
            rustix::process::Pid::from_raw(value["proxy_pid"].as_u64().unwrap() as i32).unwrap();
        let native =
            rustix::process::Pid::from_raw(value["native_pid"].as_u64().unwrap() as i32).unwrap();
        if value["process_group"].as_u64() != value["proxy_pid"].as_u64()
            || rustix::process::getpgid(Some(proxy)).ok() != Some(proxy)
            || rustix::process::getpgid(Some(native)).ok() != Some(proxy)
        {
            return Err(ProviderError::contract(
                "Owned code host process-group verification failed",
            ));
        }
    }
    #[cfg(windows)]
    if !value["process_group"].is_null() {
        return Err(ProviderError::contract(
            "Unexpected Windows process-group claim",
        ));
    }
    Ok(Some(value))
}

pub(crate) fn validate_computation(
    items: &[Value],
    config: &ProviderConfig,
) -> Result<(), ProviderError> {
    if items.len() > 48 || (config.pure_js.is_none() && !items.is_empty()) {
        return Err(ProviderError::contract(
            "Unexpected or excessive computation observations",
        ));
    }
    let bytes = serde_json::to_vec(items)
        .map_err(|_| ProviderError::contract("Cannot encode computation observations"))?;
    if bytes.len() > config.max_output_bytes {
        return Err(ProviderError::contract(
            "Computation observations exceed output budget",
        ));
    }
    let mut ids = BTreeSet::new();
    for item in items {
        verify_code_output(item)?;
        if !ids.insert(item["id"].as_str().unwrap_or("")) {
            return Err(ProviderError::contract("Duplicate computation observation"));
        }
    }
    Ok(())
}

fn origin_bound_tool_value<'a>(effective: &'a Value, key: &str) -> Option<&'a Value> {
    let origin = effective.get("origins")?.get(key)?;
    if origin.pointer("/name/type")?.as_str()? != "sessionFlags" {
        return None;
    }
    let version = origin.get("version")?.as_str()?;
    if version.is_empty() || version.len() > 256 {
        return None;
    }
    let layers = effective.get("layers")?.as_array()?;
    if layers.len() > 64 {
        return None;
    }
    let mut matches = layers.iter().filter(|layer| {
        layer.get("name") == origin.get("name") && layer.get("version") == origin.get("version")
    });
    let layer = matches.next()?;
    if matches.next().is_some() || !layer.get("disabledReason").is_none_or(Value::is_null) {
        return None;
    }
    layer
        .get("config")?
        .pointer(&format!("/{}", key.replace('.', "/")))
}

fn is_code_array_key(key: &str) -> bool {
    matches!(
        key,
        "features.code_mode.excluded_tool_namespaces"
            | "features.code_mode.direct_only_tool_namespaces"
    )
}

fn origin_bound_code_array_value<'a>(effective: &'a Value, key: &str) -> Option<&'a Value> {
    // Codex 0.159.2 records array origins per scalar element, and no leaf for [].
    // Bind the raw array to the unique enabled CLI layer through code_mode.enabled,
    // require the typed effective array to agree, and verify every element origin.
    if !is_code_array_key(key)
        || origin_bound_tool_value(effective, "features.code_mode.enabled")
            != Some(&Value::Bool(true))
    {
        return None;
    }
    let origin = effective
        .get("origins")?
        .get("features.code_mode.enabled")?;
    let layer = effective.get("layers")?.as_array()?.iter().find(|layer| {
        layer.get("name") == origin.get("name") && layer.get("version") == origin.get("version")
    })?;
    let pointer = format!("/{}", key.replace('.', "/"));
    let actual = effective.get("config")?.pointer(&pointer)?;
    let array = actual.as_array()?;
    if array.len() > 64 || layer.get("config")?.pointer(&pointer) != Some(actual) {
        return None;
    }
    for index in 0..array.len() {
        let element_origin = effective.get("origins")?.get(format!("{key}.{index}"))?;
        if element_origin.get("name") != origin.get("name")
            || element_origin.get("version") != origin.get("version")
        {
            return None;
        }
    }
    Some(actual)
}

fn pure_js_controls(effective: &Value) -> Result<Value, ProviderError> {
    let mut controls = serde_json::Map::new();
    for key in [
        "features.code_mode.enabled",
        "features.code_mode.excluded_tool_namespaces",
        "features.code_mode.direct_only_tool_namespaces",
        "features.code_mode_host.enabled",
        "features.code_mode_host.disable_in_process_fallback",
    ] {
        let is_array = is_code_array_key(key);
        let value = if is_array {
            origin_bound_code_array_value(effective, key)
        } else {
            origin_bound_tool_value(effective, key)
        }
        .ok_or_else(|| ProviderError::contract("Cannot record verified code controls"))?;
        let anchor = if is_array {
            "features.code_mode.enabled"
        } else {
            key
        };
        let origin = &effective["origins"][anchor];
        let mut observation = json!({
            "value":value,
            "cliLayer":{"type":"sessionFlags","version":origin["version"]},
            "provenance":if is_array {"effective_array_and_enabled_cli_layer"} else {"scalar_origin"}
        });
        if let Some(array) = value.as_array() {
            observation["elementOrigins"] = Value::Array(
                (0..array.len())
                    .map(|index| {
                        let origin = &effective["origins"][format!("{key}.{index}")];
                        json!({"index":index,"type":"sessionFlags","version":origin["version"]})
                    })
                    .collect(),
            );
        }
        controls.insert(key.into(), observation);
    }
    Ok(Value::Object(controls))
}

fn hook_lists_are_empty(value: Option<&Value>) -> bool {
    // HooksToml serializes empty event lists plus stored enabled/trusted-hash
    // metadata. State entries contain no executable hook; features.hooks=false
    // is independently required by verify_isolation_config.
    const EVENTS: [&str; 12] = [
        "Interrupt",
        "PermissionRequest",
        "PostCompact",
        "PostToolUse",
        "PreCompact",
        "PreToolUse",
        "SessionEnd",
        "SessionStart",
        "Stop",
        "SubagentStart",
        "SubagentStop",
        "UserPromptSubmit",
    ];
    value.and_then(Value::as_object).is_some_and(|fields| {
        fields.iter().all(|(key, value)| {
            if EVENTS.contains(&key.as_str()) {
                value.as_array().is_some_and(Vec::is_empty)
            } else if key == "state" {
                value.as_object().is_some_and(|entries| {
                    entries.len() <= 64
                        && entries.iter().all(|(name, entry)| {
                            name.len() <= 256
                                && entry.as_object().is_some_and(|fields| {
                                    fields.iter().all(|(key, value)| match key.as_str() {
                                        "enabled" => value.is_boolean(),
                                        "trusted_hash" => {
                                            value.as_str().is_some_and(|hash| hash.len() <= 128)
                                        }
                                        _ => false,
                                    })
                                })
                        })
                })
            } else {
                false
            }
        })
    })
}

fn registry_is_disabled(value: Option<&Value>) -> bool {
    value.and_then(Value::as_object).is_some_and(|entries| {
        entries
            .values()
            .all(|entry| entry.get("enabled") == Some(&Value::Bool(false)))
    })
}

fn registry_disables(config: &Value) -> Result<Vec<String>, ProviderError> {
    let mut keys = Vec::new();
    for registry in ["mcp_servers", "plugins"] {
        let entries = config
            .get(registry)
            .and_then(Value::as_object)
            .ok_or_else(|| ProviderError::contract("Invalid inherited capability registry"))?;
        if entries.len() > 64 {
            return Err(ProviderError::contract(
                "Inherited capability registry exceeds bound",
            ));
        }
        let mut disabled_entries = Vec::new();
        let mut needs_disable = false;
        for (name, entry) in entries {
            if name.len() > 256 || !entry.is_object() {
                return Err(ProviderError::contract(
                    "Invalid inherited capability entry",
                ));
            }
            needs_disable |= entry.get("enabled") != Some(&Value::Bool(false));
            disabled_entries.push(format!("{}={{enabled=false}}", json!(name)));
        }
        if needs_disable {
            // CLI paths are split on dots without TOML key unquoting. Use a
            // root inline table so quoted registry names remain exact keys.
            keys.push(format!("{registry}={{{}}}", disabled_entries.join(",")));
        }
    }
    Ok(keys)
}

fn verify_thread(started: &Value, model: &str) -> Result<(), ProviderError> {
    if started["model"].as_str() != Some(model)
        || started["modelProvider"] != "openai"
        || started["approvalPolicy"] != "never"
        || started.pointer("/sandbox/type").and_then(Value::as_str) != Some("readOnly")
    {
        return Err(ProviderError::contract(
            "New thread did not preserve the requested model and isolation",
        ));
    }
    // These two Vec fields default to empty in the pinned response contract.
    // Only omission has that meaning; null and malformed values still fail.
    for (field, message) in [
        (
            "instructionSources",
            "Thread instruction sources must be absent or empty; use a separate Codex home without AGENTS.md or AGENTS.override.md and complete its managed ChatGPT login",
        ),
        (
            "runtimeWorkspaceRoots",
            "New thread did not preserve empty runtime workspace roots",
        ),
    ] {
        if !started
            .get(field)
            .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
        {
            return Err(ProviderError::contract(message));
        }
    }
    Ok(())
}

fn classify_error(error: &Value) -> ProviderError {
    let code = &error["codexErrorInfo"];
    let code = if code.is_null() {
        &error["data"]["codexErrorInfo"]
    } else {
        code
    };
    let normalized = code.to_string().to_ascii_lowercase();
    let message = error["message"].as_str().unwrap_or("").to_ascii_lowercase();
    let http = code.as_object().and_then(|fields| {
        fields
            .values()
            .find_map(|value| value["httpStatusCode"].as_u64())
    });
    if normalized.contains("usagelimit")
        || message.contains("quota")
        || message.contains("usage limit")
        || http == Some(429)
    {
        ProviderError::new(ProviderErrorKind::Quota, "ChatGPT usage limit reached")
    } else if normalized.contains("unauthorized") || http == Some(401) || http == Some(403) {
        ProviderError::new(
            ProviderErrorKind::Auth,
            "Managed ChatGPT authentication failed",
        )
    } else if normalized.contains("connection")
        || normalized.contains("stream")
        || normalized.contains("internalserver")
        || http.is_some_and(|status| status >= 500)
    {
        ProviderError::new(
            ProviderErrorKind::Transient,
            "App Server transport or service failed",
        )
    } else {
        ProviderError::contract("App Server rejected the request or response contract")
    }
}

fn sanitize_limits(value: &Value) -> Result<Value, ProviderError> {
    fn snapshot(value: &Value) -> Value {
        let mut output = serde_json::Map::new();
        for key in ["planType", "rateLimitReachedType", "spendControlReached"] {
            if let Some(value) = value.get(key) {
                output.insert(key.to_owned(), value.clone());
            }
        }
        for key in ["primary", "secondary"] {
            if let Some(window) = value.get(key) {
                if window.is_null() {
                    output.insert(key.to_owned(), Value::Null);
                    continue;
                }
                let mut safe_window = serde_json::Map::new();
                for field in ["usedPercent", "resetsAt", "windowDurationMins"] {
                    if let Some(value) = window.get(field) {
                        safe_window.insert(field.to_owned(), value.clone());
                    }
                }
                output.insert(key.to_owned(), Value::Object(safe_window));
            }
        }
        Value::Object(output)
    }
    let mut output = serde_json::Map::new();
    if let Some(allowed) = value.get("ordinaryUsageAllowed") {
        if !allowed.is_null() && !allowed.is_boolean() {
            return Err(ProviderError::contract("Invalid ordinary usage permission"));
        }
        output.insert("ordinaryUsageAllowed".to_owned(), allowed.clone());
    }
    if let Some(limits) = value.get("rateLimits") {
        output.insert("rateLimits".to_owned(), snapshot(limits));
    }
    if let Some(buckets) = value["rateLimitsByLimitId"].as_object() {
        output.insert(
            "rateLimitsByLimitId".to_owned(),
            Value::Object(
                buckets
                    .iter()
                    .map(|(key, value)| (key.clone(), snapshot(value)))
                    .collect(),
            ),
        );
    }
    Ok(Value::Object(output))
}

fn quota_exhausted(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            (key == "usedPercent" && value.as_i64().is_some_and(|used| used >= 100))
                || (key == "rateLimitReachedType" && !value.is_null())
                || (key == "spendControlReached" && value == &Value::Bool(true))
                || (key == "ordinaryUsageAllowed" && value == &Value::Bool(false))
                || quota_exhausted(value)
        }),
        _ => false,
    }
}

#[derive(Default)]
struct UsageTrace {
    responses: std::collections::BTreeMap<String, crate::node::budget::Usage>,
    cumulative: Option<crate::node::budget::Usage>,
}
impl UsageTrace {
    fn partial(&self) -> Value {
        json!({"complete":false,"responses":self.responses.iter().map(|(id,usage)|json!({"responseId":id,"usage":usage})).collect::<Vec<_>>(),"cumulative":self.cumulative})
    }
    fn cumulative(&mut self, value: &Value) -> Result<(), ProviderError> {
        let next = crate::node::budget::Usage::from_provider(value)
            .map_err(|_| ProviderError::contract("Missing or invalid cumulative usage"))?;
        if self.cumulative.is_some_and(|before| !next.follows(&before)) {
            return Err(ProviderError::contract("Regressive cumulative usage"));
        }
        self.cumulative = Some(next);
        Ok(())
    }
    fn response(&mut self, params: &Value) -> Result<(), ProviderError> {
        let id = params["responseId"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 256)
            .ok_or_else(|| ProviderError::contract("Missing upstream response identity"))?;
        let usage = crate::node::budget::Usage::from_provider(&json!({"total":params["usage"]}))
            .map_err(|_| {
                ProviderError::contract("Upstream response has unknown or invalid usage")
            })?;
        if let Some(previous) = self.responses.get(id) {
            if *previous != usage {
                return Err(ProviderError::contract("Conflicting response usage"));
            }
        } else {
            if self.responses.len() >= MAX_EVENTS {
                return Err(ProviderError::contract(
                    "Per-operation response count bound",
                ));
            }
            self.responses.insert(id.to_owned(), usage);
        }
        Ok(())
    }
    fn finish(self, mut usage: Value) -> Result<Value, ProviderError> {
        let final_total = self
            .cumulative
            .ok_or_else(|| ProviderError::contract("Final cumulative usage unavailable"))?;
        if self.responses.is_empty() {
            return Err(ProviderError::contract(
                "Raw completion accounting unavailable",
            ));
        }
        let mut sum = crate::node::budget::Usage {
            input: 0,
            output: 0,
            total: 0,
            cached: 0,
            reasoning: 0,
        };
        for response in self.responses.values() {
            sum.input = sum
                .input
                .checked_add(response.input)
                .ok_or_else(|| ProviderError::contract("Usage overflow"))?;
            sum.output = sum
                .output
                .checked_add(response.output)
                .ok_or_else(|| ProviderError::contract("Usage overflow"))?;
            sum.total = sum
                .total
                .checked_add(response.total)
                .ok_or_else(|| ProviderError::contract("Usage overflow"))?;
            sum.cached = sum
                .cached
                .checked_add(response.cached)
                .ok_or_else(|| ProviderError::contract("Usage overflow"))?;
            sum.reasoning = sum
                .reasoning
                .checked_add(response.reasoning)
                .ok_or_else(|| ProviderError::contract("Usage overflow"))?;
        }
        if sum != final_total {
            return Err(ProviderError::contract(
                "Incomplete response usage accounting",
            ));
        }
        usage["complete"] = json!(true);
        usage["responses"] = json!(self.responses.len());
        usage["responseUsage"] = json!(self.responses.iter().map(|(id,usage)|json!({"responseId":id,"inputTokens":usage.input,"outputTokens":usage.output,"totalTokens":usage.total,"cachedInputTokens":usage.cached,"reasoningOutputTokens":usage.reasoning})).collect::<Vec<_>>());
        Ok(usage)
    }
}

fn sanitize_usage(value: &Value) -> Value {
    let mut output = serde_json::Map::new();
    for key in ["last", "total"] {
        if let Some(input) = value[key].as_object() {
            let mut safe = serde_json::Map::new();
            for field in [
                "inputTokens",
                "outputTokens",
                "totalTokens",
                "reasoningOutputTokens",
                "cachedInputTokens",
                "cacheWriteInputTokens",
            ] {
                if let Some(value) = input.get(field).filter(|value| value.as_u64().is_some()) {
                    safe.insert(field.to_owned(), value.clone());
                }
            }
            output.insert(key.to_owned(), Value::Object(safe));
        }
    }
    if output.is_empty() {
        Value::Null
    } else {
        Value::Object(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    // A real stdio child with no network or provider access. Compiling this fixture
    // uses the repository's selected Rust toolchain and only Rust's standard library.
    const MOCK_SOURCE: &str = r###"
use std::io::{self, BufRead, Write};
fn emit(message: &str) { println!("{message}"); io::stdout().flush().unwrap(); }
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--hold-pipes") {
        std::thread::sleep(std::time::Duration::from_secs(30));
        return;
    }
    let home = std::path::PathBuf::from(std::env::var_os("CODEX_HOME").unwrap());
    let mode = std::fs::read_to_string(home.join("mode")).unwrap();
    let mut config = std::fs::read_to_string(home.join("effective.json")).unwrap();
    assert!(std::env::var_os("OPENAI_API_KEY").is_none());
    assert!(std::env::var_os("CODEX_ACCESS_TOKEN").is_none());
    assert_eq!(std::fs::read_dir(std::env::current_dir().unwrap()).unwrap().count(), 0);
    let args: Vec<String> = std::env::args().collect();
    assert!(args.iter().any(|arg| arg == "--strict-config"));
    assert!(!args.iter().any(|arg| arg.starts_with("forced_login_method=")));
    if mode == "inherited" {
        let launches = home.join("launches");
        let count: usize = std::fs::read_to_string(&launches).unwrap_or_else(|_| "0".into()).parse().unwrap();
        std::fs::write(launches, (count + 1).to_string()).unwrap();
        for (registry, name) in [("mcp_servers", "fixture.server"), ("mcp_servers", "fixture.initial"), ("plugins", "fixture@vendor")] {
            let needle = format!("\"{name}\"={{enabled=false}}");
            if args.iter().any(|arg| arg.starts_with(&format!("{registry}={{")) && arg.contains(&needle)) {
                config = config.replace(&format!("\"{name}\":{{\"enabled\":true}}"), &format!("\"{name}\":{{\"enabled\":false}}"));
            }
        }
    }
    if mode == "descendant" {
        let _child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--hold-pipes")
            .stdin(std::process::Stdio::inherit()).stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::null()).spawn().unwrap();
        emit(r#"{"method":"configWarning","params":{}}"#);
        std::thread::sleep(std::time::Duration::from_secs(30));
        return;
    }
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        if !line.contains("\"id\":") { continue; }
        let id: u64 = line.split("\"id\":").nth(1).unwrap().split(',').next().unwrap().parse().unwrap();
        let result = if line.contains("\"method\":\"initialize\"") {
            if mode == "pure_old_version" { r#"{"userAgent":"naome_research/0.153.4"}"#.to_owned() }
            else if mode.starts_with("pure") || mode.starts_with("accounted") { r#"{"userAgent":"naome_research/0.159.2 (test)"}"#.to_owned() }
            else { "{}".to_owned() }
        }
        else if line.contains("\"method\":\"account/read\"") {
            assert!(line.contains("\"refreshToken\":false"));
            if mode == "api_key" { r#"{"account":{"type":"apiKey"}}"#.to_owned() }
            else { r#"{"account":{"type":"chatgpt","email":"private@example.test","planType":"pro"}}"#.to_owned() }
        }
        else if line.contains("\"method\":\"config/read\"") {
            assert!(line.contains("\"includeLayers\":true"));
            if mode.starts_with("pure") {
                emit(&format!(r#"{{"id":{id},"result":{}}}"#, std::fs::read_to_string(home.join("effective-response.json")).unwrap()));
                continue;
            }
            let projection = config.replace(r#""tools":{"experimental_request_user_input":{"enabled":false},"update_plan":{"enabled":false}}"#, r#""tools":{}"#);
            format!(r#"{{"config":{projection},"origins":{{"tools.update_plan.enabled":{{"name":{{"type":"sessionFlags"}},"version":"fixture-v1"}},"tools.experimental_request_user_input.enabled":{{"name":{{"type":"sessionFlags"}},"version":"fixture-v1"}}}},"layers":[{{"name":{{"type":"sessionFlags"}},"version":"fixture-v1","config":{config}}}]}}"#)
        }
        else if line.contains("\"method\":\"model/list\"") {
            if mode == "missing_model" { r#"{"data":[],"nextCursor":null}"#.to_owned() }
            else { r#"{"data":[{"model":"fixture-model","hidden":false,"supportedReasoningEfforts":[{"reasoningEffort":"low"}]}],"nextCursor":null}"#.to_owned() }
        }
        else if line.contains("\"method\":\"account/rateLimits/read\"") {
            if mode == "ordinary_denied" { emit(&format!(r#"{{"id":{id},"result":{{"ordinaryUsageAllowed":false,"rateLimits":{{"primary":{{"usedPercent":1}}}}}}}}"#)); continue; }
            let used = if mode == "quota" { 100 } else { 17 };
            format!("{{\"rateLimits\":{{\"primary\":{{\"usedPercent\":{used},\"resetsAt\":123}}}},\"accountId\":\"private-account\"}}")
        }
        else if line.contains("\"method\":\"thread/start\"") {
            assert!(line.contains("\"environments\":[]"));
            assert!(line.contains("\"dynamicTools\":[]"));
            assert!(line.contains("\"ephemeral\":true"));
            assert!(line.contains("\"allowProviderModelFallback\":false"));
            let lists = match mode.as_str() {
                "thread_defaults" => "",
                "thread_null" => r#", "instructionSources":null,"runtimeWorkspaceRoots":[]"#,
                "thread_source_nonempty" => r#", "instructionSources":["/private-source/AGENTS.md"],"runtimeWorkspaceRoots":[]"#,
                "thread_roots_nonempty" => r#", "instructionSources":[],"runtimeWorkspaceRoots":["/unexpected"]"#,
                _ => r#", "instructionSources":[],"runtimeWorkspaceRoots":[]"#,
            };
            format!(r#"{{"model":"fixture-model","modelProvider":"openai","approvalPolicy":"never","sandbox":{{"type":"readOnly"}}{lists},"thread":{{"id":"fixture-thread"}}}}"#)
        }
        else if line.contains("\"method\":\"turn/start\"") {
            std::fs::write(home.join("turn-started"), "true").unwrap();
            assert!(line.contains("\"outputSchema\":"));
            assert!(line.contains("\"environments\":[]"));
            if mode == "accounted_early" {
                emit(r#"{"method":"rawResponse/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","responseId":"response-1","usage":{"inputTokens":10,"outputTokens":4,"totalTokens":14}}}"#);
            }
            emit(&format!("{{\"id\":{id},\"result\":{{\"turn\":{{\"id\":\"fixture-turn\"}}}}}}"));
            if mode == "timeout" || mode == "accounted_timeout" { std::thread::sleep(std::time::Duration::from_secs(30)); }
            if mode == "oversized" { emit(&"x".repeat(80000)); continue; }
            if mode == "flood" { for _ in 0..4500 { emit(r#"{"method":"ignored"}"#); } continue; }
            if mode == "server_request" { emit(r#"{"id":22,"method":"item/commandExecution/requestApproval","params":{}}"#); continue; }
            if mode == "external_auth" { emit(r#"{"method":"account/updated","params":{"authMode":"chatgptAuthTokens"}}"#); continue; }
            if mode == "tool" { emit(r#"{"method":"item/started","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"type":"commandExecution","command":"touch forbidden"}}}"#); continue; }
            if mode == "async_delivery" { emit(r#"{"method":"item/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"type":"agentMessage","phase":"final_answer","delivery":"async","text":"{\"vote\":true}"}}}"#); continue; }
            if mode == "async_questions" { emit(r#"{"method":"item/started","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"type":"agentMessage","phase":"final_answer","questions":[],"text":"{\"vote\":true}"}}}"#); continue; }
            if mode == "wrong_turn" { emit(r#"{"method":"item/completed","params":{"threadId":"fixture-thread","turnId":"other-turn","item":{"type":"agentMessage","text":"{}"}}}"#); continue; }
            if mode.starts_with("pure") {
                let host = std::env::var("NAOME_RESEARCH_HOST_CONFIG").unwrap();
                let path = host.split("\"status_file\":\"").nth(1).unwrap().split('"').next().unwrap().replace("\\\\", "\\");
                let native = std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("--hold-pipes").stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
                let proxy = std::process::id();
                let group = if cfg!(unix) { proxy.to_string() } else { "null".to_owned() };
                let state = if mode == "pure_host_failed" { "failed" } else { "running" };
                std::fs::write(path, format!("{{\"state\":\"{state}\",\"proxy_pid\":{proxy},\"native_pid\":{},\"process_group\":{group}}}", native.id())).unwrap();
                let name = if mode == "pure_wrong_name" { "exec_command" } else { "exec" };
                let output = if mode == "pure_media" { r#"[{"type":"inputImage","imageUrl":"unused"}]"# } else { r#"[{"type":"inputText","text":"2"}]"# };
                let frame = format!(r#"{{"method":"item/completed","params":{{"threadId":"fixture-thread","turnId":"fixture-turn","item":{{"id":"cell-output","type":"functionCallOutput","name":"{name}","namespace":"functions","output":{output}}}}}}}"#);
                emit(&frame);
                if mode == "pure_duplicate" { emit(&frame); }
            }
            if mode == "accounted_payload" { emit(&std::fs::read_to_string(home.join("payload-frame.json")).unwrap()); }
            else if mode == "malformed" || mode == "accounted_malformed" { emit(r#"{"method":"item/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"type":"agentMessage","text":"not json"}}}"#); }
            else { emit(r#"{"method":"item/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"id":"answer","type":"agentMessage","phase":"final_answer","text":"{\"vote\":true}"}}}"#); }
            if mode.starts_with("accounted") {
                let raw=r#"{"method":"rawResponse/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","responseId":"response-1","usage":{"inputTokens":10,"outputTokens":4,"totalTokens":14}}}"#;
                if mode != "accounted_no_raw" && mode != "accounted_early" { emit(raw); }
                if mode == "accounted_duplicate" { emit(raw); }
                if mode == "accounted_conflict" { emit(&raw.replace("\"inputTokens\":10", "\"inputTokens\":11").replace("\"totalTokens\":14", "\"totalTokens\":15")); }
                if mode == "accounted_wrong_turn" { emit(&raw.replace("fixture-turn", "another-turn")); }
                if mode == "accounted_missing_later" { emit(r#"{"method":"rawResponse/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","responseId":"response-2","usage":null}}"#); }
                if mode == "accounted_multi" { emit(r#"{"method":"rawResponse/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","responseId":"response-2","usage":{"inputTokens":2,"outputTokens":3,"totalTokens":5}}}"#); }
                let cumulative=if mode == "accounted_multi" {
                    r#"{"method":"thread/tokenUsage/updated","params":{"threadId":"fixture-thread","turnId":"fixture-turn","tokenUsage":{"last":{"inputTokens":2,"outputTokens":3,"totalTokens":5},"total":{"inputTokens":12,"outputTokens":7,"totalTokens":19}}}}"#
                } else {
                    r#"{"method":"thread/tokenUsage/updated","params":{"threadId":"fixture-thread","turnId":"fixture-turn","tokenUsage":{"last":{"inputTokens":10,"outputTokens":4,"totalTokens":14},"total":{"inputTokens":10,"outputTokens":4,"totalTokens":14}}}}"#
                };
                emit(cumulative);
                if mode == "accounted_regressive" { emit(&cumulative.replace("\"inputTokens\":10","\"inputTokens\":9").replace("\"totalTokens\":14","\"totalTokens\":13")); }
            } else {
                emit(r#"{"method":"thread/tokenUsage/updated","params":{"threadId":"fixture-thread","turnId":"fixture-turn","tokenUsage":{"last":{"inputTokens":10,"outputTokens":4,"totalTokens":14},"private":"secret"}}}"#);
            }
            emit(r#"{"method":"turn/completed","params":{"threadId":"fixture-thread","turn":{"id":"fixture-turn","status":"completed"}}}"#);
            continue;
        }
        else { "{}".to_owned() };
        emit(&format!("{{\"id\":{id},\"result\":{result}}}"));
    }
}
"###;

    struct Fixture {
        home: PathBuf,
        config: ProviderConfig,
    }

    impl Fixture {
        fn new(mode: &str) -> Self {
            static BINARY: OnceLock<PathBuf> = OnceLock::new();
            let binary = BINARY
                .get_or_init(|| {
                    let directory = create_empty_directory().unwrap();
                    let source = directory.join("fixture.rs");
                    let binary = directory.join(if cfg!(windows) {
                        "fixture.exe"
                    } else {
                        "fixture"
                    });
                    fs::write(&source, MOCK_SOURCE).unwrap();
                    let status = Command::new("rustc")
                        .arg("--edition=2024")
                        .arg(&source)
                        .arg("-o")
                        .arg(&binary)
                        .status()
                        .unwrap();
                    assert!(status.success());
                    binary
                })
                .clone();
            let home = create_empty_directory().unwrap();
            fs::write(home.join("mode"), mode).unwrap();
            let mut effective = json!({});
            for (key, value) in isolation_overrides() {
                let parts = key.split('.').collect::<Vec<_>>();
                let mut parent = &mut effective;
                for part in &parts[..parts.len() - 1] {
                    if parent.get(part).is_none() {
                        parent[*part] = json!({});
                    }
                    parent = &mut parent[*part];
                }
                parent[parts[parts.len() - 1]] = value;
            }
            fs::write(home.join("effective.json"), effective.to_string()).unwrap();
            Self {
                config: ProviderConfig {
                    codex_binary: binary,
                    codex_home: home.clone(),
                    model: "fixture-model".to_owned(),
                    timeout_seconds: 3,
                    max_output_bytes: 64 * 1024,
                    disabled_registries: Default::default(),
                    pure_js: None,
                },
                home,
            }
        }

        fn enable_pure_js(&mut self) {
            let manifest = json!({"layoutVersion":1,"version":"0.159.2","entrypoint":if cfg!(windows) {"bin/codex.exe"} else {"bin/codex"}});
            fs::write(self.home.join("codex-package.json"), manifest.to_string()).unwrap();
            let digest = executable_digest(&self.config.codex_binary).unwrap();
            self.config.pure_js = Some(PureJsConfig {
                native_host_binary: self.config.codex_binary.clone(),
                host_proxy_binary: self.config.codex_binary.clone(),
                package_manifest: self.home.join("codex-package.json"),
                codex_binary_sha256: digest.clone(),
                native_host_sha256: digest.clone(),
                host_proxy_sha256: digest,
                package_manifest_sha256: executable_digest(&self.home.join("codex-package.json"))
                    .unwrap(),
                macos_bundle: None,
            });
            let mut effective = json!({"config":{},"origins":{},"layers":[{
                "name":{"type":"sessionFlags"},"version":"fixture-v1","config":{}}]});
            for (key, value) in provider_overrides(&self.config) {
                for root in ["/config", "/layers/0/config"] {
                    let mut parent = effective.pointer_mut(root).unwrap();
                    let parts = key.split('.').collect::<Vec<_>>();
                    for part in &parts[..parts.len() - 1] {
                        if parent.get(part).is_none() {
                            parent[*part] = json!({});
                        }
                        parent = &mut parent[*part];
                    }
                    parent[parts[parts.len() - 1]] = value.clone();
                }
                let origin = json!({"name":{"type":"sessionFlags"},"version":"fixture-v1"});
                if let Some(array) = value.as_array() {
                    for index in 0..array.len() {
                        effective["origins"][format!("{key}.{index}")] = origin.clone();
                    }
                } else {
                    effective["origins"][key] = origin;
                }
            }
            fs::write(
                self.home.join("effective-response.json"),
                effective.to_string(),
            )
            .unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.home);
        }
    }

    fn schema() -> Value {
        json!({"type":"object","properties":{"vote":{"type":"boolean"}},"required":["vote"],"additionalProperties":false})
    }

    #[test]
    fn accounted_raw_process_completions_sum_once_and_preserve_early_events() {
        for mode in [
            "accounted_success",
            "accounted_duplicate",
            "accounted_early",
            "accounted_multi",
        ] {
            let fixture = Fixture::new(mode);
            let mut server = AppServer::start(&fixture.config).unwrap();
            let reply = server
                .request_accounted("offline fixture", schema())
                .unwrap();
            let usage = crate::node::budget::Usage::from_complete_provider(&reply.usage).unwrap();
            assert_eq!(usage.total, if mode == "accounted_multi" { 19 } else { 14 });
            assert_eq!(
                reply.usage["responses"],
                if mode == "accounted_multi" { 2 } else { 1 }
            );
            assert_eq!(server.observed_usage(), reply.usage);
        }
    }

    #[test]
    fn accounted_process_rejects_missing_conflicting_regressive_or_foreign_usage() {
        for mode in [
            "accounted_no_raw",
            "accounted_missing_later",
            "accounted_conflict",
            "accounted_regressive",
            "accounted_wrong_turn",
        ] {
            let fixture = Fixture::new(mode);
            let mut server = AppServer::start(&fixture.config).unwrap();
            assert!(
                server
                    .request_accounted("offline fixture", schema())
                    .is_err(),
                "{mode}"
            );
            assert!(
                crate::node::budget::Usage::from_complete_provider(&server.observed_usage())
                    .is_err()
            );
            assert!(server.child.is_none());
        }
    }

    #[test]
    fn malformed_answer_keeps_complete_usage_and_raw_reply() {
        let fixture = Fixture::new("accounted_malformed");
        let mut server = AppServer::start(&fixture.config).unwrap();
        assert!(
            server
                .request_accounted("offline fixture", schema())
                .is_err()
        );
        assert_eq!(
            crate::node::budget::Usage::from_complete_provider(&server.observed_usage())
                .unwrap()
                .total,
            14
        );
        assert_eq!(server.observed_response().as_deref(), Some("not json"));
        let outcome = crate::node::ProviderOutcome::from_provider_result(
            Err(ProviderError::contract(
                "Final response is not a single JSON value",
            )),
            server.observed_usage(),
            server.info(),
            server.observed_response(),
        );
        assert_eq!(outcome.retained_raw_response.as_deref(), Some("not json"));
        assert_eq!(
            outcome.provenance["raw_reply"]["location"],
            "retained_raw_response"
        );
        assert_eq!(
            crate::node::budget::Usage::from_complete_provider(&outcome.known_usage)
                .unwrap()
                .total,
            14
        );
    }

    #[test]
    fn production_node_run_persists_large_offline_stdio_reply_and_restarts_without_unknown_usage() {
        use crate::{
            formal::FormulaInput,
            journal::write_new,
            node::{
                Action, Config, Control, Node,
                budget::{Allowance, Budgets, Period},
            },
            run::Interests,
            state::{PoolConfig, Question, hex},
        };
        let mut fixture = Fixture::new("accounted_payload");
        fixture.config.max_output_bytes = 256 * 1024;
        let root = fixture.home.join("node-fixture");
        fs::create_dir(&root).unwrap();
        let identity = root.join("key.json");
        write_new(&identity, &[57u8; 32]).unwrap();
        let config = Config {
            version: 2,
            directory: root.join("node"),
            identity_file: identity,
            run_label: "offline-large-production-record".into(),
            interests: Interests {
                topics: vec!["Formal logic".into()],
                context: "Offline stdio fixture".into(),
            },
            provider: fixture.config.clone(),
            budgets: Budgets {
                timezone: "Europe/Berlin".into(),
                research: Allowance {
                    amount: 1,
                    period: Period::Day,
                },
                discoveries: Allowance {
                    amount: 0,
                    period: Period::Hour,
                },
                evaluations: Allowance {
                    amount: 0,
                    period: Period::Hour,
                },
            },
            credit: 3,
            pool: PoolConfig::default(),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut node = Node::initialize(config.clone(), now).unwrap();
        let question = Question {
            title: "Large escaped production output".into(),
            context: String::new(),
            formula: FormulaInput::Forall {
                variable: 0,
                body: Box::new(FormulaInput::Equal { left: 0, right: 0 }),
            },
            definitions: vec![],
        };
        let id = question.id().unwrap();
        let action = node.sign(Action::Publish { question }).unwrap();
        node.submit(action).unwrap();
        let action = node
            .sign(Action::Evaluate {
                question: id,
                yes: true,
            })
            .unwrap();
        node.submit(action).unwrap();
        node.tick(now).unwrap();
        let value = json!({"question_id":hex(&id),"outcome":"proof","source":"a".repeat(200*1024),"dependencies":[]});
        let raw = value.to_string();
        let event = json!({"method":"item/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"id":"answer","type":"agentMessage","phase":"final_answer","text":raw}}});
        let wire = serde_json::to_vec(&event).unwrap();
        assert!(wire.len() + 8192 < config.provider.max_output_bytes);
        fs::write(fixture.home.join("payload-frame.json"), wire).unwrap();
        let control = Control::default();
        let stop = control.clone();
        let inspect_config = config.clone();
        let watcher = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Ok(snapshot) = Node::inspect(inspect_config.clone()) {
                    let state = &snapshot.checkpoint().state;
                    if state["research"]["used"] == 14 && state["received"].is_null() {
                        stop.stop();
                        return true;
                    }
                }
                if Instant::now() >= deadline {
                    stop.stop();
                    return false;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        // This is the production Node::run/AppServer/result-construction path
        // with an owned fake stdio child, not an authentic provider turn.
        let result = node.run(&control);
        assert!(watcher.join().unwrap());
        assert_eq!(result.unwrap()["lifecycle"], "stopped");
        let selected = node.checkpoint().clone();
        assert_eq!(selected.state["research"]["used"], 14);
        assert_eq!(selected.state["attempts"], 1);
        assert!(selected.state["usage_unknown"].is_null());
        drop(node);
        let mut node = Node::open(config.clone()).unwrap();
        assert!(node.recover_provider().unwrap());
        assert_eq!(node.checkpoint(), &selected);
        assert_eq!(node.status("fixture").unwrap()["local_credit"], 0);
        drop(node);
        let report = Node::replay(
            config,
            &root.join("replayed"),
            Some((selected.head, selected.count)),
        )
        .unwrap();
        assert_eq!(report["records_verified"], selected.count);
        assert_eq!(report["provider_turns"], 0);
    }

    #[test]
    fn accounted_operation_stop_bounds_owned_process_cleanup() {
        let mut fixture = Fixture::new("accounted_timeout");
        fixture.config.timeout_seconds = 10;
        let mut server = AppServer::start(&fixture.config).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        server.set_cancel(stop.clone());
        let trigger = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            stop.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        assert!(
            server
                .request_accounted("offline fixture", schema())
                .is_err()
        );
        trigger.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(server.child.is_none());
        assert!(
            crate::node::budget::Usage::from_complete_provider(&server.observed_usage()).is_err()
        );
    }

    #[test]
    fn ordinary_usage_permission_preserves_unknown_and_blocks_explicit_denial() {
        for source in [
            json!({}),
            json!({"ordinaryUsageAllowed":null}),
            json!({"ordinaryUsageAllowed":true}),
        ] {
            let safe = sanitize_limits(&source).unwrap();
            assert_eq!(
                safe.get("ordinaryUsageAllowed"),
                source.get("ordinaryUsageAllowed")
            );
            assert!(!quota_exhausted(&safe));
        }
        let fixture = Fixture::new("ordinary_denied");
        let mut server = AppServer::start(&fixture.config).unwrap();
        assert_eq!(server.limits()["ordinaryUsageAllowed"], false);
        assert_eq!(
            server
                .request("bounded question", schema())
                .unwrap_err()
                .kind,
            ProviderErrorKind::Quota
        );
        assert!(!fixture.home.join("turn-started").exists());
        for invalid in [json!(0), json!("false"), json!([]), json!({})] {
            assert!(sanitize_limits(&json!({"ordinaryUsageAllowed":invalid})).is_err());
        }
    }

    #[test]
    fn pure_js_staging_pins_bytes_and_origin_bound_configuration() {
        let mut fixture = Fixture::new("pure_success");
        fixture.enable_pure_js();
        fixture.config.validate().unwrap();
        let effective: Value = serde_json::from_slice(
            &fs::read(fixture.home.join("effective-response.json")).unwrap(),
        )
        .unwrap();
        verify_provider_config(&effective, &fixture.config).unwrap();
        for key in [
            "features.code_mode.excluded_tool_namespaces",
            "features.code_mode_host.disable_in_process_fallback",
        ] {
            let mut altered = effective.clone();
            let origin_key = if is_code_array_key(key) {
                format!("{key}.0")
            } else {
                key.to_owned()
            };
            altered["origins"][origin_key]["version"] = json!("other");
            assert!(verify_provider_config(&altered, &fixture.config).is_err());
        }
        let directory = create_empty_directory().unwrap();
        let (cli, encoded) = stage_pure_js(&fixture.config, &directory).unwrap();
        assert_eq!(cli.parent(), Some(directory.join("bin").as_path()));
        assert_eq!(
            executable_digest(&cli).unwrap(),
            fixture.config.pure_js.as_ref().unwrap().codex_binary_sha256
        );
        assert!(
            directory
                .join("bin")
                .join(if cfg!(windows) {
                    "codex-code-mode-host.exe"
                } else {
                    "codex-code-mode-host"
                })
                .is_file()
        );
        assert!(directory.join("codex-package.json").exists());
        assert!(!directory.join("codex-resources").exists());
        let host: crate::host_proxy::HostProxyConfig =
            serde_json::from_str(&encoded.unwrap()).unwrap();
        assert_eq!(host.native_binary.parent(), Some(directory.as_path()));
        assert_eq!(host.timeout_millis, fixture.config.timeout_seconds * 1000);
        fs::remove_dir_all(directory).unwrap();
        fixture.config.pure_js.as_mut().unwrap().native_host_sha256 = "0".repeat(64);
        assert!(fixture.config.validate().is_err());
    }

    #[test]
    fn code_arrays_require_effective_raw_cli_and_every_element_origin_agreement() {
        let mut fixture = Fixture::new("pure_success");
        fixture.enable_pure_js();
        let effective: Value = serde_json::from_slice(
            &fs::read(fixture.home.join("effective-response.json")).unwrap(),
        )
        .unwrap();
        let excluded = "features.code_mode.excluded_tool_namespaces";
        let direct = "features.code_mode.direct_only_tool_namespaces";
        assert!(effective["origins"].get(excluded).is_none());
        assert!(effective["origins"].get(direct).is_none());
        verify_provider_config(&effective, &fixture.config).unwrap();
        for index in 0..2 {
            let key = format!("{excluded}.{index}");
            for invalid in [
                Value::Null,
                json!({"name":{"type":"user"},"version":"fixture-v1"}),
                json!({"name":{"type":"sessionFlags"},"version":"different"}),
            ] {
                let mut altered = effective.clone();
                altered["origins"][&key] = invalid;
                assert!(verify_provider_config(&altered, &fixture.config).is_err());
            }
            let mut absent = effective.clone();
            absent["origins"].as_object_mut().unwrap().remove(&key);
            // A whole-array origin cannot substitute for any actual element origin.
            absent["origins"][excluded] = effective["origins"][format!("{excluded}.0")].clone();
            assert!(verify_provider_config(&absent, &fixture.config).is_err());
        }
        for key in ["excluded_tool_namespaces", "direct_only_tool_namespaces"] {
            for value in [Value::Null, json!({}), json!(["unexpected"])] {
                for pointer in [
                    "/config/features/code_mode",
                    "/layers/0/config/features/code_mode",
                ] {
                    let mut altered = effective.clone();
                    altered.pointer_mut(pointer).unwrap()[key] = value.clone();
                    assert!(verify_provider_config(&altered, &fixture.config).is_err());
                }
            }
            let mut missing = effective.clone();
            missing
                .pointer_mut("/layers/0/config/features/code_mode")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(verify_provider_config(&missing, &fixture.config).is_err());
        }
        let mut duplicate = effective.clone();
        duplicate["layers"]
            .as_array_mut()
            .unwrap()
            .push(effective["layers"][0].clone());
        assert!(verify_provider_config(&duplicate, &fixture.config).is_err());
        for origin in [
            json!({"name":{"type":"user"},"version":"fixture-v1"}),
            json!({"name":{"type":"sessionFlags"},"version":"different"}),
        ] {
            let mut altered = effective.clone();
            altered["origins"]["features.code_mode.enabled"] = origin;
            assert!(verify_provider_config(&altered, &fixture.config).is_err());
        }
        for disabled in [json!(""), json!(false)] {
            let mut altered = effective.clone();
            altered["layers"][0]["disabledReason"] = disabled;
            assert!(verify_provider_config(&altered, &fixture.config).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn signed_bundle_staging_preserves_fixed_support_bytes_and_rejects_tampering() {
        use std::os::unix::fs::symlink;
        let mut fixture = Fixture::new("pure_success");
        fixture.enable_pure_js();
        let original_cli = fixture.config.codex_binary.clone();
        let bundle_cli = fixture.home.join("CodexCLI.app/Contents/MacOS/codex");
        fs::create_dir_all(bundle_cli.parent().unwrap()).unwrap();
        fs::create_dir(fixture.home.join("CodexCLI.app/Contents/_CodeSignature")).unwrap();
        fs::create_dir(fixture.home.join("bin")).unwrap();
        fs::copy(original_cli, &bundle_cli).unwrap();
        fixture.config.codex_binary = bundle_cli;
        assert!(fixture.config.validate().is_err());
        let mut metadata = MacosBundleConfig {
            info_plist_sha256: String::new(),
            provision_profile_sha256: String::new(),
            legacy_code_resources_sha256: String::new(),
            code_signature_resources_sha256: String::new(),
            launcher_sha256: String::new(),
        };
        for (index, (relative, _)) in metadata.files().iter().enumerate() {
            // The two CodeResources files intentionally have different bytes.
            fs::write(
                fixture.home.join(relative),
                format!("public package file {index}"),
            )
            .unwrap();
        }
        let hashes = metadata
            .files()
            .map(|(relative, _)| bundle_file_digest(&fixture.home.join(relative)).unwrap());
        metadata.info_plist_sha256 = hashes[0].clone();
        metadata.provision_profile_sha256 = hashes[1].clone();
        metadata.legacy_code_resources_sha256 = hashes[2].clone();
        metadata.code_signature_resources_sha256 = hashes[3].clone();
        metadata.launcher_sha256 = hashes[4].clone();
        fixture.config.pure_js.as_mut().unwrap().macos_bundle = Some(metadata.clone());
        fixture.config.validate().unwrap();
        let staged = create_empty_directory().unwrap();
        let (actual_cli, _) = stage_pure_js(&fixture.config, &staged).unwrap();
        assert_eq!(actual_cli, staged.join("CodexCLI.app/Contents/MacOS/codex"));
        for (relative, expected) in metadata.files() {
            assert_eq!(
                bundle_file_digest(&staged.join(relative)).unwrap(),
                expected
            );
        }
        assert_eq!(
            executable_digest(&actual_cli).unwrap(),
            fixture.config.pure_js.as_ref().unwrap().codex_binary_sha256
        );
        assert!(!staged.join("codex-resources").exists());
        assert!(staged.join("bin/codex-code-mode-host").is_file());
        fs::remove_dir_all(staged).unwrap();
        let info = fixture.home.join("CodexCLI.app/Contents/Info.plist");
        fs::write(&info, "modified").unwrap();
        assert!(fixture.config.validate().is_err());
        fs::remove_file(&info).unwrap();
        symlink(fixture.home.join("bin/codex"), &info).unwrap();
        assert!(fixture.config.validate().is_err());
        fs::remove_file(&info).unwrap();
        fs::write(&info, vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert!(fixture.config.validate().is_err());
        fixture
            .config
            .pure_js
            .as_mut()
            .unwrap()
            .macos_bundle
            .as_mut()
            .unwrap()
            .info_plist_sha256 = "A".repeat(64);
        assert!(fixture.config.validate().is_err());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn signed_bundle_metadata_is_rejected_on_other_platforms() {
        let mut fixture = Fixture::new("pure_success");
        fixture.enable_pure_js();
        let hash = "0".repeat(64);
        fixture.config.pure_js.as_mut().unwrap().macos_bundle = Some(MacosBundleConfig {
            info_plist_sha256: hash.clone(),
            provision_profile_sha256: hash.clone(),
            legacy_code_resources_sha256: hash.clone(),
            code_signature_resources_sha256: hash.clone(),
            launcher_sha256: hash,
        });
        assert!(fixture.config.validate().is_err());
    }

    #[test]
    fn pure_js_stdio_path_preserves_bounded_outputs_and_rejects_contract_changes() {
        let mut fixture = Fixture::new("pure_success");
        fixture.enable_pure_js();
        let mut server = AppServer::start(&fixture.config).unwrap();
        let response = server.request("bounded mathematics", schema()).unwrap();
        assert_eq!(response.computation.len(), 1);
        assert_eq!(response.value, json!({"vote":true}));
        assert_eq!(
            server.info()["hostRuntime"]["auditedCodexVersion"],
            "0.159.2"
        );
        for mode in [
            "pure_wrong_name",
            "pure_media",
            "pure_duplicate",
            "pure_old_version",
            "pure_host_failed",
        ] {
            let mut fixture = Fixture::new(mode);
            fixture.enable_pure_js();
            let result = AppServer::start(&fixture.config)
                .and_then(|mut server| server.request("bounded mathematics", schema()));
            assert_eq!(
                result.unwrap_err().kind,
                ProviderErrorKind::Contract,
                "{mode}"
            );
            if mode == "pure_old_version" {
                assert!(!fixture.home.join("turn-started").exists());
            }
        }
    }

    #[test]
    fn production_request_boundary_returns_and_persists_verified_host_observation() {
        use crate::run::{Interests, ParticipantConfig, RunConfig, TickMode};
        let mut fixture = Fixture::new("pure_success");
        fixture.enable_pure_js();
        let coordinator = fixture.home.join("coordinator-key.json");
        fs::write(&coordinator, serde_json::to_vec(&[90u8; 32]).unwrap()).unwrap();
        let mut participants = Vec::new();
        for index in 0..2u8 {
            let signing_key_file = fixture.home.join(format!("participant-{index}-key.json"));
            let interests_file = fixture
                .home
                .join(format!("participant-{index}-interests.json"));
            fs::write(
                &signing_key_file,
                serde_json::to_vec(&[91u8 + index; 32]).unwrap(),
            )
            .unwrap();
            fs::write(
                &interests_file,
                serde_json::to_vec(&Interests {
                    topics: vec!["Elementary equality".into()],
                    context: String::new(),
                })
                .unwrap(),
            )
            .unwrap();
            participants.push(ParticipantConfig {
                label: format!("participant-{index}"),
                signing_key_file,
                interests_file,
                provider: fixture.config.clone(),
            });
        }
        let config = RunConfig {
            directory: fixture.home.join("research-run"),
            run_label: "observed-host-fixture".into(),
            coordinator_key_file: coordinator,
            participants,
            pool: crate::state::PoolConfig::default(),
            max_calls: 1,
            max_seconds: 10,
            shared_plan_sample: true,
            tick_mode: TickMode::SignedFixture,
        };
        let mut returned = None;
        let assert_controls = |controls: &Value| {
            let excluded = &controls["features.code_mode.excluded_tool_namespaces"];
            let direct = &controls["features.code_mode.direct_only_tool_namespaces"];
            assert_eq!(excluded["value"], json!(["functions", "clock"]));
            assert_eq!(direct["value"], json!([]));
            for array in [excluded, direct] {
                assert_eq!(
                    array["cliLayer"],
                    json!({"type":"sessionFlags","version":"fixture-v1"})
                );
                assert_eq!(array["provenance"], "effective_array_and_enabled_cli_layer");
            }
            assert_eq!(
                excluded["elementOrigins"],
                json!([
                    {"index":0,"type":"sessionFlags","version":"fixture-v1"},
                    {"index":1,"type":"sessionFlags","version":"fixture-v1"}
                ])
            );
            assert_eq!(direct["elementOrigins"], json!([]));
        };
        let report = crate::run::execute(&config, |provider, prompt, schema| {
            let (reply, info) = crate::run::request_once(provider, prompt, schema)?;
            assert_eq!(
                info["account"]["hostRuntime"]["observedStatus"]["state"],
                "running"
            );
            assert!(
                info["account"]["hostRuntime"]["observedStatus"]["native_pid"]
                    .as_u64()
                    .is_some()
            );
            assert_controls(&info["account"]["hostRuntime"]["effectiveControls"]);
            returned = Some(info.clone());
            Ok((reply, info))
        })
        .unwrap();
        assert_eq!(report["run"]["provider_calls_consumed"], 1);
        let receipt: Value = serde_json::from_slice(
            &fs::read(config.directory.join("provider_calls/receipt-0000.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["provider"], returned.unwrap());
        assert_controls(&receipt["provider"]["account"]["hostRuntime"]["effectiveControls"]);
        assert_eq!(
            receipt["provider"]["account"]["hostRuntime"]["observedStatus"]["state"],
            "running"
        );
    }

    #[test]
    fn code_wrapper_outputs_allow_only_exact_native_names_and_text() {
        let valid = json!({"type":"functionCallOutput","id":"cell-output","name":"exec","namespace":"functions","output":[{"type":"inputText","text":"1"}]});
        verify_code_output(&valid).unwrap();
        for (field, value) in [
            ("namespace", json!("clock")),
            ("name", json!("exec_command")),
            ("id", json!("")),
            ("output", json!([{"type":"inputImage","imageUrl":"x"}])),
            ("output", json!({"text":"1"})),
        ] {
            let mut altered = valid.clone();
            altered[field] = value;
            assert!(verify_code_output(&altered).is_err());
        }
        let fixture = Fixture::new("success");
        assert!(validate_computation(std::slice::from_ref(&valid), &fixture.config).is_err());
        let mut enabled = fixture.config.clone();
        enabled.pure_js = Some(PureJsConfig {
            native_host_binary: enabled.codex_binary.clone(),
            host_proxy_binary: enabled.codex_binary.clone(),
            package_manifest: enabled.codex_binary.clone(),
            package_manifest_sha256: String::new(),
            codex_binary_sha256: String::new(),
            native_host_sha256: String::new(),
            host_proxy_sha256: String::new(),
            macos_bundle: None,
        });
        validate_computation(std::slice::from_ref(&valid), &enabled).unwrap();
        assert!(validate_computation(&[valid.clone(), valid], &enabled).is_err());
    }

    #[test]
    fn permanent_host_failure_is_rejected_even_without_an_observation() {
        let directory = create_empty_directory().unwrap();
        let status = directory.join("host-status.json");
        assert!(verify_host_status(&status, false).unwrap().is_none());
        fs::write(directory.join("host-status.json.failed"), []).unwrap();
        assert!(verify_host_status(&status, false).is_err());
        fs::write(
            &status,
            r#"{"state":"starting","proxy_pid":1,"native_pid":null,"process_group":1}"#,
        )
        .unwrap();
        assert!(verify_host_status(&status, false).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn thread_response_defaults_accept_only_missing_or_empty_lists() {
        let complete = json!({"model":"fixture-model","modelProvider":"openai",
            "approvalPolicy":"never","sandbox":{"type":"readOnly"},
            "instructionSources":[],"runtimeWorkspaceRoots":[]});
        for omitted in [
            vec![],
            vec!["instructionSources"],
            vec!["runtimeWorkspaceRoots"],
            vec!["instructionSources", "runtimeWorkspaceRoots"],
        ] {
            let mut response = complete.clone();
            for field in omitted {
                response.as_object_mut().unwrap().remove(field);
            }
            verify_thread(&response, "fixture-model").unwrap();
        }
        for field in ["instructionSources", "runtimeWorkspaceRoots"] {
            for invalid in [
                Value::Null,
                json!(""),
                json!({}),
                json!(false),
                json!(0),
                json!([null]),
                json!(["/unexpected"]),
            ] {
                let mut response = complete.clone();
                response[field] = invalid;
                assert!(
                    verify_thread(&response, "fixture-model").is_err(),
                    "{field}: {response}"
                );
            }
        }
        for field in ["model", "modelProvider", "approvalPolicy", "sandbox"] {
            for invalid in [
                Value::Null,
                json!("changed"),
                json!([]),
                json!({"type":"workspaceWrite"}),
            ] {
                let mut response = complete.clone();
                response[field] = invalid;
                assert!(
                    verify_thread(&response, "fixture-model").is_err(),
                    "{field}: {response}"
                );
            }
            let mut response = complete.clone();
            response.as_object_mut().unwrap().remove(field);
            assert!(
                verify_thread(&response, "fixture-model").is_err(),
                "missing {field}"
            );
        }
    }

    #[test]
    fn stdio_thread_defaults_reach_turn_and_invalid_lists_stop_before_turn() {
        for mode in [
            "thread_defaults",
            "thread_null",
            "thread_source_nonempty",
            "thread_roots_nonempty",
        ] {
            let fixture = Fixture::new(mode);
            let mut server = AppServer::start(&fixture.config).unwrap();
            let reply = server.request("Vote.", schema());
            let accepted = mode == "thread_defaults";
            assert_eq!(reply.is_ok(), accepted, "{mode}");
            assert_eq!(
                fixture.home.join("turn-started").exists(),
                accepted,
                "{mode}"
            );
            if !accepted {
                let error = reply.unwrap_err();
                assert_eq!(error.kind, ProviderErrorKind::Contract);
                if mode == "thread_source_nonempty" {
                    assert!(error.message.contains("separate Codex home"));
                    assert!(!error.message.contains("private-source"));
                }
                assert!(server.child.is_none());
            }
        }
    }

    #[test]
    fn stdio_fixture_preserves_isolation_and_reports_sanitized_usage() {
        let fixture = Fixture::new("success");
        let mut server = AppServer::start(&fixture.config).unwrap();
        assert_eq!(server.info()["accountMode"], "chatgpt");
        assert!(!server.info().to_string().contains("private"));
        assert!(!server.limits().to_string().contains("private"));
        for _ in 0..2 {
            let reply = server.request("Return a Boolean vote.", schema()).unwrap();
            assert_eq!(reply.value, json!({"vote":true}));
            assert_eq!(reply.usage["last"]["totalTokens"], 14);
            assert!(!reply.usage.to_string().contains("secret"));
        }
        let cwd = server.cwd.clone();
        drop(server);
        assert!(!cwd.exists());
    }

    #[test]
    fn startup_rejects_api_auth_and_models_outside_the_catalog() {
        for (mode, kind) in [
            ("api_key", ProviderErrorKind::Auth),
            ("missing_model", ProviderErrorKind::Contract),
        ] {
            let fixture = Fixture::new(mode);
            let error = match AppServer::start(&fixture.config) {
                Ok(_) => panic!("fixture should fail startup"),
                Err(error) => error,
            };
            assert_eq!(error.kind, kind);
            assert!(!error.message.contains("private"));
        }
    }

    #[test]
    fn quota_stops_before_a_provider_turn() {
        let fixture = Fixture::new("quota");
        let mut server = AppServer::start(&fixture.config).unwrap();
        assert_eq!(
            server.request("Vote.", schema()).unwrap_err().kind,
            ProviderErrorKind::Quota
        );
        assert!(server.child.is_none());
    }

    #[test]
    fn tool_requests_wrong_turns_and_invalid_json_fail_closed() {
        for mode in [
            "tool",
            "server_request",
            "wrong_turn",
            "malformed",
            "oversized",
            "flood",
            "async_delivery",
            "async_questions",
        ] {
            let fixture = Fixture::new(mode);
            let mut server = AppServer::start(&fixture.config).unwrap();
            let error = server.request("Vote.", schema()).unwrap_err();
            assert_eq!(error.kind, ProviderErrorKind::Contract, "{mode}: {error}");
            assert!(server.child.is_none());
            assert_eq!(
                server.request("Vote again.", schema()).unwrap_err().kind,
                ProviderErrorKind::Contract
            );
        }
    }

    #[test]
    fn external_token_mode_is_rejected_without_refreshing_tokens() {
        let fixture = Fixture::new("external_auth");
        let mut server = AppServer::start(&fixture.config).unwrap();
        assert_eq!(
            server.request("Vote.", schema()).unwrap_err().kind,
            ProviderErrorKind::Auth
        );
        assert!(server.child.is_none());
    }

    #[test]
    fn timed_out_child_is_killed_reaped_and_cannot_be_reused() {
        let mut fixture = Fixture::new("timeout");
        fixture.config.timeout_seconds = 1;
        let mut server = AppServer::start(&fixture.config).unwrap();
        let cwd = server.cwd.clone();
        let started = Instant::now();
        assert_eq!(
            server.request("Vote.", schema()).unwrap_err().kind,
            ProviderErrorKind::TimeBudget
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(server.child.is_none());
        assert!(server.workers.is_empty());
        assert!(!cwd.exists());
    }

    #[test]
    fn changed_effective_capabilities_are_rejected() {
        let fixture = Fixture::new("success");
        let file = fixture.home.join("effective.json");
        let mut value: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        value["features"]["shell_tool"] = json!(true);
        fs::write(file, value.to_string()).unwrap();
        assert!(AppServer::start(&fixture.config).is_err());
    }

    #[test]
    fn inherited_registry_names_are_disabled_by_one_bounded_restart() {
        let fixture = Fixture::new("inherited");
        let file = fixture.home.join("effective.json");
        let mut value: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        value["mcp_servers"]["fixture.server"] = json!({"enabled":true});
        fs::write(file, value.to_string()).unwrap();
        let mut server = AppServer::start(&fixture.config).unwrap();
        assert_eq!(
            fs::read_to_string(fixture.home.join("launches")).unwrap(),
            "2"
        );
        assert_eq!(
            server.request("Vote.", schema()).unwrap().value,
            json!({"vote":true})
        );
    }

    #[test]
    fn initial_registry_names_avoid_restart_and_unknown_names_still_trigger_one() {
        for unknown_server in [false, true] {
            let mut fixture = Fixture::new("inherited");
            fixture.config.disabled_registries = DisabledRegistries {
                mcp_servers: vec!["fixture.initial".into()],
                plugins: vec!["fixture@vendor".into()],
            };
            let file = fixture.home.join("effective.json");
            let mut value: Value =
                serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
            value["mcp_servers"]["fixture.initial"] = json!({"enabled":true});
            value["plugins"]["fixture@vendor"] = json!({"enabled":true});
            if unknown_server {
                value["mcp_servers"]["fixture.server"] = json!({"enabled":true});
            }
            fs::write(file, value.to_string()).unwrap();
            let mut server = AppServer::start(&fixture.config).unwrap();
            assert_eq!(
                fs::read_to_string(fixture.home.join("launches")).unwrap(),
                if unknown_server { "2" } else { "1" }
            );
            assert_eq!(
                server.request("Vote.", schema()).unwrap().value,
                json!({"vote":true})
            );
        }
    }

    fn effective_layer(fixture: &Fixture) -> Value {
        let config: Value =
            serde_json::from_str(&fs::read_to_string(fixture.home.join("effective.json")).unwrap())
                .unwrap();
        let mut projection = config.clone();
        projection["tools"] = json!({});
        json!({
            "config":projection,
            "origins":{
                "tools.update_plan.enabled":{"name":{"type":"sessionFlags"},"version":"fixture-v1"},
                "tools.experimental_request_user_input.enabled":{"name":{"type":"sessionFlags"},"version":"fixture-v1"}
            },
            "layers":[{"name":{"type":"sessionFlags"},"version":"fixture-v1","config":config}]
        })
    }

    #[test]
    fn omitted_tool_settings_require_matching_enabled_effective_origins() {
        let fixture = Fixture::new("success");
        let effective = effective_layer(&fixture);
        assert!(
            effective["config"]
                .pointer("/tools/update_plan/enabled")
                .is_none()
        );
        verify_isolation_config(&effective).unwrap();
        for case in 0..9 {
            let mut value = effective.clone();
            match case {
                0 => {
                    value["origins"]
                        .as_object_mut()
                        .unwrap()
                        .remove("tools.update_plan.enabled");
                }
                1 => value["origins"]["tools.update_plan.enabled"]["name"]["type"] = json!("user"),
                2 => value["origins"]["tools.update_plan.enabled"]["version"] = json!("other"),
                3 => value["layers"][0]["disabledReason"] = json!(""),
                4 => value["layers"] = json!([]),
                5 => {
                    let layer = value["layers"][0].clone();
                    value["layers"].as_array_mut().unwrap().push(layer);
                }
                6 => value["layers"][0]["config"]["tools"]["update_plan"]["enabled"] = json!(true),
                7 => {
                    value["layers"][0]["config"]["tools"]["experimental_request_user_input"] =
                        Value::Null
                }
                8 => {
                    value["origins"]["tools.experimental_request_user_input.enabled"]["version"] =
                        json!("")
                }
                _ => unreachable!(),
            }
            assert!(verify_isolation_config(&value).is_err(), "case {case}");
        }
    }

    #[test]
    fn native_empty_hook_defaults_and_inert_state_require_no_executable_groups() {
        let fixture = Fixture::new("success");
        let mut effective = effective_layer(&fixture);
        effective["config"]["hooks"] = json!({
            "Interrupt":[], "PermissionRequest":[], "PostCompact":[], "PostToolUse":[],
            "PreCompact":[], "PreToolUse":[], "SessionEnd":[], "SessionStart":[], "Stop":[],
            "SubagentStart":[], "SubagentStop":[], "UserPromptSubmit":[],
            "state":{"stored-hook":{"enabled":true,"trusted_hash":"inert-hash"}}
        });
        verify_isolation_config(&effective).unwrap();
        for case in 0..5 {
            let mut value = effective.clone();
            match case {
                0 => value["config"]["hooks"]["Stop"] = json!([{}]),
                1 => value["config"]["hooks"]["UnknownEvent"] = json!([]),
                2 => {
                    value["config"]["hooks"]["state"]["stored-hook"]["command"] =
                        json!("unsupported")
                }
                3 => value["config"]["hooks"]["state"]["stored-hook"]["enabled"] = json!("false"),
                4 => value["config"]["features"]["hooks"] = json!(true),
                _ => unreachable!(),
            }
            assert!(verify_isolation_config(&value).is_err(), "case {case}");
        }
    }

    #[test]
    fn initial_registry_names_are_bounded_and_empty_configuration_preserves_old_bytes() {
        let fixture = Fixture::new("success");
        let serialized = serde_json::to_value(&fixture.config).unwrap();
        assert!(serialized.get("disabled_registries").is_none());
        let restored: ProviderConfig = serde_json::from_value(serialized.clone()).unwrap();
        assert_eq!(serde_json::to_value(restored).unwrap(), serialized);
        for names in [
            vec!["duplicate".into(), "duplicate".into()],
            vec!["".into()],
            vec!["x".repeat(257)],
            vec!["line\nbreak".into()],
            vec!["x".into(); 65],
        ] {
            let mut config = fixture.config.clone();
            config.disabled_registries.mcp_servers = names;
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn descendant_pipe_owner_cannot_extend_shutdown_deadline() {
        let mut fixture = Fixture::new("descendant");
        fixture.config.timeout_seconds = 1;
        let started = Instant::now();
        let error = match AppServer::start(&fixture.config) {
            Ok(_) => panic!("warning should stop startup"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ProviderErrorKind::Contract);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn oversized_unterminated_line_is_rejected_without_unbounded_allocation() {
        let (sender, receiver) = mpsc::sync_channel(1);
        read_lines(std::io::Cursor::new(vec![b'x'; 9000]), 4096, sender);
        assert_eq!(
            receiver.recv().unwrap().unwrap_err().kind,
            ProviderErrorKind::Contract
        );
    }

    #[test]
    fn errors_are_classified_without_echoing_backend_messages() {
        let quota = classify_error(
            &json!({"message":"private@example.test secret", "codexErrorInfo":"usageLimitExceeded"}),
        );
        assert_eq!(quota.kind, ProviderErrorKind::Quota);
        assert!(!quota.message.contains("private"));
        let auth = classify_error(&json!({"codexErrorInfo":"unauthorized"}));
        assert_eq!(auth.kind, ProviderErrorKind::Auth);
        let transient = classify_error(
            &json!({"codexErrorInfo":{"httpConnectionFailed":{"httpStatusCode":503}}}),
        );
        assert_eq!(transient.kind, ProviderErrorKind::Transient);
    }
}
