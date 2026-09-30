//! Bounded, participant-local access to the official Codex App Server.
//!
//! Authentication stays inside Codex. This client never reads credentials and never
//! supports API keys, externally injected tokens, a hosted proxy, or tool execution.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::VecDeque;
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
        let mut command = Command::new(&config.codex_binary);
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
        for (key, value) in isolation_overrides() {
            command
                .arg("-c")
                .arg(format!("{key}={}", toml_value(&value)));
        }
        for override_value in disables {
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
        })
    }

    fn handshake(&mut self, budget: &mut Budget) -> Result<(), ProviderError> {
        self.rpc(
            "initialize",
            json!({
                "clientInfo": {"name":"naome_research", "version":env!("CARGO_PKG_VERSION")},
                "capabilities": {"experimentalApi":true}
            }),
            budget,
        )?;
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
            json!({"includeLayers":false,"cwd":self.cwd}),
            budget,
        )?;
        self.required_disables = registry_disables(&effective["config"])?;
        if !self.required_disables.is_empty() {
            return Err(ProviderError::contract(
                "Inherited registries require explicit isolated disables",
            ));
        }
        verify_isolation_config(&effective["config"])?;
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
        self.rate_limits = sanitize_limits(&limits);
        self.info = json!({
            "accountMode":"chatgpt", "planType":account.pointer("/account/planType"),
            "model":self.config.model, "reasoningEffort":self.effort,
            "transport":"stdio", "environmentAccess":false,
            "timeoutSeconds":self.config.timeout_seconds,
            "maxOutputBytes":self.config.max_output_bytes,
            "maxInputBytes":MAX_INPUT_BYTES, "maxEvents":MAX_EVENTS
        });
        Ok(())
    }

    pub fn info(&self) -> Value {
        self.info.clone()
    }

    pub fn limits(&self) -> Value {
        self.rate_limits.clone()
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
        let result = self.request_inner(prompt, output_schema, &mut budget);
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
        let started = self.rpc(
            "thread/start",
            json!({
                "model":self.config.model, "modelProvider":"openai",
                "cwd":self.cwd,"ephemeral":true,"approvalPolicy":"never","sandbox":"read-only",
                "environments":[],"dynamicTools":[],"selectedCapabilityRoots":[],
                "runtimeWorkspaceRoots":[],"allowProviderModelFallback":false,
                "baseInstructions":"Return only the requested JSON. You have no tools or environment access. A proposal is never proof validity; only the local formal checker decides validity.",
                "developerInstructions":"Use only the supplied research context. Never request tools, shell, files, web, credentials, plugins, or another agent. Return the exact output schema."
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
                "item/started" | "item/completed" | "thread/tokenUsage/updated" | "turn/completed"
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
                    }
                }
                "thread/tokenUsage/updated" => usage = sanitize_usage(&params["tokenUsage"]),
                "turn/completed" => {
                    self.active_turn = None;
                    let turn = &params["turn"];
                    if turn["status"] != "completed" {
                        return Err(classify_error(&turn["error"]));
                    }
                    let text = final_text.ok_or_else(|| {
                        ProviderError::contract("Turn completed without a final response")
                    })?;
                    let value = serde_json::from_str(&text).map_err(|_| {
                        ProviderError::contract("Final response is not a single JSON value")
                    })?;
                    return Ok(ProviderReply {
                        value,
                        raw_response: text,
                        usage,
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
        let bytes = self
            .receiver
            .as_ref()
            .ok_or_else(|| ProviderError::contract("App Server is closed"))?
            .recv_timeout(budget.remaining()?)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => ProviderError::new(
                    ProviderErrorKind::TimeBudget,
                    "App Server wall time exhausted",
                ),
                mpsc::RecvTimeoutError::Disconnected => {
                    ProviderError::new(ProviderErrorKind::Transient, "App Server reader stopped")
                }
            })??;
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
                self.rate_limits = sanitize_limits(params);
                if quota_exhausted(&self.rate_limits) {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Quota,
                        "ChatGPT quota is exhausted",
                    ));
                }
            }
            "item/started" | "item/completed" => {
                let kind = params["item"]["type"].as_str().unwrap_or("");
                if !matches!(kind, "userMessage" | "agentMessage" | "reasoning") {
                    return Err(ProviderError::contract(
                        "Provider attempted an unsupported item or tool",
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

fn verify_isolation_config(config: &Value) -> Result<(), ProviderError> {
    for (key, expected) in isolation_overrides() {
        let pointer = format!("/{}", key.replace('.', "/"));
        if ["mcp_servers", "plugins"].contains(&key)
            && registry_is_disabled(config.pointer(&pointer))
        {
            continue;
        }
        if config.pointer(&pointer) != Some(&expected) {
            let shape = match config.pointer(&pointer) {
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
        for (name, entry) in entries {
            if name.len() > 256 || !entry.is_object() {
                return Err(ProviderError::contract(
                    "Invalid inherited capability entry",
                ));
            }
            if entry.get("enabled") != Some(&Value::Bool(false)) {
                disabled_entries.push(format!("{}={{enabled=false}}", json!(name)));
            }
        }
        if !disabled_entries.is_empty() {
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
        || !started["instructionSources"]
            .as_array()
            .is_some_and(Vec::is_empty)
        || !started["runtimeWorkspaceRoots"]
            .as_array()
            .is_some_and(Vec::is_empty)
    {
        return Err(ProviderError::contract(
            "New thread did not preserve the requested model and isolation",
        ));
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

fn sanitize_limits(value: &Value) -> Value {
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
    Value::Object(output)
}

fn quota_exhausted(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            (key == "usedPercent" && value.as_i64().is_some_and(|used| used >= 100))
                || (key == "rateLimitReachedType" && !value.is_null())
                || (key == "spendControlReached" && value == &Value::Bool(true))
                || quota_exhausted(value)
        }),
        _ => false,
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
        if args.iter().any(|arg| arg == r#"mcp_servers={"fixture.server"={enabled=false}}"#) {
            config = config.replace(r#""fixture.server":{"enabled":true}"#, r#""fixture.server":{"enabled":false}"#);
        } else {
            assert_eq!(count, 0);
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
        let result = if line.contains("\"method\":\"initialize\"") { "{}".to_owned() }
        else if line.contains("\"method\":\"account/read\"") {
            assert!(line.contains("\"refreshToken\":false"));
            if mode == "api_key" { r#"{"account":{"type":"apiKey"}}"#.to_owned() }
            else { r#"{"account":{"type":"chatgpt","email":"private@example.test","planType":"pro"}}"#.to_owned() }
        }
        else if line.contains("\"method\":\"config/read\"") { format!("{{\"config\":{config}}}") }
        else if line.contains("\"method\":\"model/list\"") {
            if mode == "missing_model" { r#"{"data":[],"nextCursor":null}"#.to_owned() }
            else { r#"{"data":[{"model":"fixture-model","hidden":false,"supportedReasoningEfforts":[{"reasoningEffort":"low"}]}],"nextCursor":null}"#.to_owned() }
        }
        else if line.contains("\"method\":\"account/rateLimits/read\"") {
            let used = if mode == "quota" { 100 } else { 17 };
            format!("{{\"rateLimits\":{{\"primary\":{{\"usedPercent\":{used},\"resetsAt\":123}}}},\"accountId\":\"private-account\"}}")
        }
        else if line.contains("\"method\":\"thread/start\"") {
            assert!(line.contains("\"environments\":[]"));
            assert!(line.contains("\"dynamicTools\":[]"));
            assert!(line.contains("\"ephemeral\":true"));
            assert!(line.contains("\"allowProviderModelFallback\":false"));
            r#"{"model":"fixture-model","modelProvider":"openai","approvalPolicy":"never","sandbox":{"type":"readOnly"},"instructionSources":[],"runtimeWorkspaceRoots":[],"thread":{"id":"fixture-thread"}}"#.to_owned()
        }
        else if line.contains("\"method\":\"turn/start\"") {
            assert!(line.contains("\"outputSchema\":"));
            assert!(line.contains("\"environments\":[]"));
            emit(&format!("{{\"id\":{id},\"result\":{{\"turn\":{{\"id\":\"fixture-turn\"}}}}}}"));
            if mode == "timeout" { std::thread::sleep(std::time::Duration::from_secs(30)); }
            if mode == "oversized" { emit(&"x".repeat(80000)); continue; }
            if mode == "flood" { for _ in 0..4500 { emit(r#"{"method":"ignored"}"#); } continue; }
            if mode == "server_request" { emit(r#"{"id":22,"method":"item/commandExecution/requestApproval","params":{}}"#); continue; }
            if mode == "external_auth" { emit(r#"{"method":"account/updated","params":{"authMode":"chatgptAuthTokens"}}"#); continue; }
            if mode == "tool" { emit(r#"{"method":"item/started","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"type":"commandExecution","command":"touch forbidden"}}}"#); continue; }
            if mode == "wrong_turn" { emit(r#"{"method":"item/completed","params":{"threadId":"fixture-thread","turnId":"other-turn","item":{"type":"agentMessage","text":"{}"}}}"#); continue; }
            if mode == "malformed" { emit(r#"{"method":"item/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"type":"agentMessage","text":"not json"}}}"#); }
            else { emit(r#"{"method":"item/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"id":"answer","type":"agentMessage","phase":"final_answer","text":"{\"vote\":true}"}}}"#); }
            emit(r#"{"method":"thread/tokenUsage/updated","params":{"threadId":"fixture-thread","turnId":"fixture-turn","tokenUsage":{"last":{"inputTokens":10,"outputTokens":4,"totalTokens":14},"private":"secret"}}}"#);
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
                },
                home,
            }
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
