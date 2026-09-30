//! Bounded, text-only proxy for the pinned native code-mode host protocol.
//!
//! The proxy bounds forwarded traffic and owns the host's lifetime. It does not
//! impose a V8 heap limit or provide an operating-system execution sandbox.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

const MAX_INPUT_BYTES: usize = 32 * 1024;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_MESSAGES: usize = 128;
const MAX_SESSIONS: usize = 4;
const MAX_EXECUTIONS: usize = 16;
const MAX_WAITS: usize = 32;
const MAX_TIMEOUT_MILLIS: u64 = 600_000;
const CAPABILITIES: [&str; 2] = [
    "session-cell-execution-resource-limits",
    "yield-observation",
];

/// Passed as JSON through `NAOME_RESEARCH_HOST_CONFIG` by the owning provider.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProxyConfig {
    pub native_binary: PathBuf,
    pub status_file: PathBuf,
    #[serde(default = "default_timeout")]
    pub timeout_millis: u64,
    #[serde(default = "default_output")]
    pub max_output_bytes: usize,
}

fn default_timeout() -> u64 {
    MAX_TIMEOUT_MILLIS
}

fn default_output() -> usize {
    262_144
}

impl HostProxyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.native_binary.is_absolute() || !self.native_binary.is_file() {
            return Err("Native code host must be an absolute file path".into());
        }
        if !self.status_file.is_absolute()
            || self.status_file.file_name().is_none()
            || self
                .status_file
                .parent()
                .is_none_or(|parent| !parent.is_dir())
            || fs::symlink_metadata(&self.status_file)
                .is_ok_and(|metadata| !metadata.file_type().is_file())
        {
            return Err("Code host status must be an absolute regular file path".into());
        }
        if !(1..=MAX_TIMEOUT_MILLIS).contains(&self.timeout_millis)
            || !(1..=MAX_OUTPUT_BYTES).contains(&self.max_output_bytes)
        {
            return Err("Code host proxy limits are outside their fixed bounds".into());
        }
        if std::env::current_exe()
            .ok()
            .and_then(|path| path.canonicalize().ok())
            == self.native_binary.canonicalize().ok()
        {
            return Err("The native code host must not be the proxy itself".into());
        }
        Ok(())
    }
}

/// Runs only in the independently owned process created by the native client.
/// Once the native child exists, every stop condition terminates that owned
/// process tree, including this proxy and its potentially blocked pipe workers.
pub fn run_from_env() -> Result<(), String> {
    let config_text = std::env::var("NAOME_RESEARCH_HOST_CONFIG")
        .map_err(|_| "Missing code host proxy configuration".to_string())?;
    if config_text.len() > 16 * 1024 {
        return Err("Code host proxy configuration exceeds its bound".into());
    }
    let config: HostProxyConfig = serde_json::from_str(&config_text)
        .map_err(|_| "Malformed code host proxy configuration".to_string())?;
    config.validate()?;
    let owner = Arc::new(Owner::new(&config.status_file)?);
    let deadline_owner = Arc::clone(&owner);
    if thread::Builder::new()
        .name("code-host-deadline".into())
        .spawn(move || {
            thread::sleep(Duration::from_millis(config.timeout_millis));
            deadline_owner.stop(Status::Failed);
        })
        .is_err()
    {
        owner.stop(Status::Failed);
        return Err("Could not start the code host deadline".into());
    }

    let result = forward(&config, &owner);
    // The Unix signal also terminates blocked readers and writers. On Windows,
    // cleanup targets the retained native child tree, then exits this process.
    // There is no unbounded join on a pipe controlled by another process.
    owner.stop(Status::Failed);
    result
}

struct Owner {
    stopping: AtomicBool,
    child: Mutex<Option<Child>>,
    native_pid: AtomicU32,
    status: Mutex<()>,
    status_file: PathBuf,
    #[cfg(unix)]
    group: rustix::process::Pid,
    #[cfg(windows)]
    taskkill: PathBuf,
}

impl Owner {
    fn new(status_file: &std::path::Path) -> Result<Self, String> {
        #[cfg(unix)]
        let group = {
            let pid = rustix::process::getpid();
            if rustix::process::getpgrp() != pid {
                return Err("Code host proxy does not own its process group".into());
            }
            pid
        };
        #[cfg(windows)]
        let taskkill = {
            let root = std::env::var_os("SYSTEMROOT")
                .ok_or_else(|| "Missing Windows process-tree cleanup utility".to_string())?;
            let path = PathBuf::from(root).join("System32/taskkill.exe");
            if !path.is_absolute() || !path.is_file() {
                return Err("Windows process-tree cleanup utility is unavailable".into());
            }
            path
        };
        #[cfg(not(any(unix, windows)))]
        return Err("Code host process ownership is unsupported on this platform".into());
        #[cfg(any(unix, windows))]
        match publish_status(
            status_file,
            &StatusRecord::new(Status::Starting, None),
            true,
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                // A failed/restarted or concurrent host must never erase the
                // first host's failure by resetting the same status to running.
                let _ =
                    publish_status(status_file, &StatusRecord::new(Status::Failed, None), false);
                return Err("Code host status was already used".into());
            }
            Err(_) => return Err("Could not create the code host status".into()),
        }
        #[cfg(any(unix, windows))]
        Ok(Self {
            stopping: AtomicBool::new(false),
            child: Mutex::new(None),
            native_pid: AtomicU32::new(0),
            status: Mutex::new(()),
            status_file: status_file.to_path_buf(),
            #[cfg(unix)]
            group,
            #[cfg(windows)]
            taskkill,
        })
    }

    fn stop(&self, status: Status) {
        self.stopping.store(true, Ordering::SeqCst);
        if self.status.lock().map_or(true, |_| {
            publish_status(&self.status_file, &self.status_record(status), false).is_err()
        }) {
            // Missing/malformed status is rejected by the owning provider.
            let _ = fs::remove_file(&self.status_file);
        }
        #[cfg(unix)]
        {
            let _ = rustix::process::kill_process_group(self.group, rustix::process::Signal::KILL);
        }
        #[cfg(windows)]
        {
            // A retained child handle prevents PID reuse before tree cleanup.
            // The native host is launched without a new group or detached flag.
            if let Ok(mut retained) = self.child.lock()
                && let Some(child) = retained.as_mut()
            {
                let pid = child.id().to_string();
                if let Ok(mut killer) = Command::new(&self.taskkill)
                    .args(["/PID", &pid, "/T", "/F"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    let cutoff = Instant::now() + Duration::from_millis(500);
                    while Instant::now() < cutoff {
                        match killer.try_wait() {
                            Ok(Some(_)) | Err(_) => break,
                            Ok(None) => thread::sleep(Duration::from_millis(1)),
                        }
                    }
                    let _ = killer.kill();
                    let _ = killer.wait();
                }
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        std::process::exit(1);
    }

    fn status_record(&self, status: Status) -> StatusRecord {
        let pid = self.native_pid.load(Ordering::SeqCst);
        StatusRecord::new(status, (pid != 0).then_some(pid))
    }

    fn running(&self) -> Result<(), String> {
        let _status = self
            .status
            .lock()
            .map_err(|_| "Code host status handle is unavailable".to_string())?;
        if self.stopping.load(Ordering::SeqCst)
            || has_host_failed(&self.status_file)
                .map_err(|_| "Cannot inspect code host failure latch")?
        {
            return Err("Code host stopped before ownership publication".into());
        }
        let mut bytes = Vec::new();
        File::open(&self.status_file)
            .and_then(|file| file.take(513).read_to_end(&mut bytes))
            .map_err(|_| "Code host starting status is unavailable".to_string())?;
        let previous: StatusRecord = serde_json::from_slice(&bytes)
            .map_err(|_| "Malformed code host starting status".to_string())?;
        if bytes.len() > 512
            || previous.proxy_pid != std::process::id()
            || previous.state != Status::Starting
        {
            return Err("Code host starting status changed ownership".into());
        }
        publish_status(
            &self.status_file,
            &self.status_record(Status::Running),
            false,
        )
        .map_err(|_| "Could not publish code host ownership".to_string())?;
        if self.stopping.load(Ordering::SeqCst)
            || has_host_failed(&self.status_file)
                .map_err(|_| "Cannot inspect code host failure latch")?
        {
            return Err("Code host stopped during ownership publication".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Starting,
    Running,
    Failed,
    Stopped,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRecord {
    state: Status,
    proxy_pid: u32,
    native_pid: Option<u32>,
    process_group: Option<u32>,
}

impl StatusRecord {
    fn new(state: Status, native_pid: Option<u32>) -> Self {
        Self {
            state,
            proxy_pid: std::process::id(),
            native_pid,
            process_group: if cfg!(unix) {
                Some(std::process::id())
            } else {
                None
            },
        }
    }
}

fn failure_path(path: &std::path::Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".failed");
    PathBuf::from(name)
}

pub(crate) fn has_host_failed(path: &std::path::Path) -> io::Result<bool> {
    match fs::symlink_metadata(failure_path(path)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn publish_status(path: &std::path::Path, status: &StatusRecord, initial: bool) -> io::Result<()> {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    // The permanent latch is independent of replaceable observations. Once
    // created, concurrent EOF or another host cannot conceal a guard failure.
    if status.state == Status::Failed {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(failure_path(path))
        {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    let failed = has_host_failed(path)?;
    if initial && failed {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    let mut record = *status;
    if failed {
        record.state = Status::Failed;
    }
    let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
    let mut filename = path
        .file_name()
        .ok_or_else(|| io::Error::other("Missing status filename"))?
        .to_os_string();
    filename.push(format!(
        ".{}-{}.tmp",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    let temporary = path.with_file_name(filename);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.flush()?;
        drop(file);
        if initial {
            // Atomic initial publication refuses an already claimed status
            // path without exposing an empty placeholder to observers.
            fs::hard_link(&temporary, path)
        } else {
            fs::rename(&temporary, path)
        }
    })();
    let _ = fs::remove_file(&temporary);
    result?;
    if failed && matches!(status.state, Status::Starting | Status::Running) {
        return Err(io::Error::other("Code host failure is permanent"));
    }
    Ok(())
}

fn register_owned_child<'a, T>(
    slot: &'a Mutex<Option<T>>,
    stopping: &AtomicBool,
    spawn: impl FnOnce() -> Result<T, String>,
) -> Result<std::sync::MutexGuard<'a, Option<T>>, String> {
    let mut retained = slot
        .lock()
        .map_err(|_| "Code host ownership state is unavailable".to_string())?;
    if stopping.load(Ordering::SeqCst) || retained.is_some() {
        return Err("Code host stopped or was already launched".into());
    }
    *retained = Some(spawn()?);
    Ok(retained)
}

fn forward(config: &HostProxyConfig, owner: &Arc<Owner>) -> Result<(), String> {
    // Stdio::piped replaces the child's stdin; the app-server-facing stdin is
    // never supplied to it. No process_group or detachment changes are applied.
    // The cleanup thread cannot observe the gap between process creation and
    // retained-handle registration, including on Windows where it kills a tree.
    let mut retained = register_owned_child(&owner.child, &owner.stopping, || {
        Command::new(&config.native_binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "Could not start the native code host".to_string())
    })?;
    let child = retained.as_mut().unwrap();
    let native_pid = child.id();
    owner.native_pid.store(native_pid, Ordering::SeqCst);
    let mut native_input = child
        .stdin
        .take()
        .ok_or_else(|| "Missing native input pipe".to_string())?;
    let native_output = child
        .stdout
        .take()
        .ok_or_else(|| "Missing native output pipe".to_string())?;
    let native_error = child
        .stderr
        .take()
        .ok_or_else(|| "Missing native error pipe".to_string())?;
    drop(retained);
    #[cfg(unix)]
    {
        let pid = rustix::process::Pid::from_raw(native_pid as i32)
            .ok_or_else(|| "Invalid native code host PID".to_string())?;
        if rustix::process::getpgid(Some(pid)).ok() != Some(owner.group) {
            return Err("Native code host did not inherit the owned group".into());
        }
    }
    owner.running()?;
    let input_budget = Arc::new(Mutex::new(Budget::new(MAX_INPUT_BYTES)));
    let output_budget = Arc::new(Mutex::new(Budget::new(config.max_output_bytes)));
    // This finite queue can hold every admitted frame in both directions. In
    // particular, an input reader never waits for the writer before detecting
    // parent EOF. Total payload memory remains bounded by the byte budgets.
    let (sender, receiver) = mpsc::sync_channel(MAX_MESSAGES * 2);
    spawn_reader(
        io::stdin(),
        Direction::Client,
        input_budget,
        sender.clone(),
        Arc::clone(owner),
    )?;
    spawn_reader(
        native_output,
        Direction::Host,
        Arc::clone(&output_budget),
        sender,
        Arc::clone(owner),
    )?;
    let stderr_owner = Arc::clone(owner);
    thread::Builder::new()
        .name("code-host-stderr".into())
        .spawn(move || {
            let mut reader = native_error;
            let mut bytes = [0; 4096];
            loop {
                match reader.read(&mut bytes) {
                    Ok(0) => return,
                    Ok(length) => {
                        if claim_bytes(&output_budget, length).is_err() {
                            stderr_owner.stop(Status::Failed);
                            return;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        stderr_owner.stop(Status::Failed);
                        return;
                    }
                }
            }
        })
        .map_err(|_| "Could not start the native error reader".to_string())?;
    let mut state = Protocol::default();
    let mut client_output = io::stdout();
    loop {
        let (direction, bytes) = receiver
            .recv()
            .map_err(|_| "Code host frame reader stopped".to_string())?;
        match direction {
            Direction::Client => {
                state.client(&bytes)?;
                write_frame(&mut native_input, &bytes)?;
            }
            Direction::Host => {
                state.host(&bytes)?;
                write_frame(&mut client_output, &bytes)?;
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Client,
    Host,
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    direction: Direction,
    budget: Arc<Mutex<Budget>>,
    sender: mpsc::SyncSender<(Direction, Vec<u8>)>,
    owner: Arc<Owner>,
) -> Result<(), String> {
    thread::Builder::new()
        .name("code-host-frames".into())
        .spawn(move || {
            loop {
                match read_frame(&mut reader, &budget) {
                    Ok(Some(bytes)) => {
                        if frame_shape(direction, &bytes).is_err() {
                            owner.stop(Status::Failed);
                            return;
                        }
                        if sender.send((direction, bytes)).is_err() {
                            owner.stop(Status::Failed);
                            return;
                        }
                    }
                    Ok(None) => {
                        // In particular, app-server EOF does not wait for the
                        // forwarding loop or a native child holding a pipe open.
                        owner.stop(match direction {
                            Direction::Client => Status::Stopped,
                            Direction::Host => Status::Failed,
                        });
                        return;
                    }
                    Err(_) => {
                        owner.stop(Status::Failed);
                        return;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|_| "Could not start a code host frame reader".to_string())
}

fn frame_shape(direction: Direction, bytes: &[u8]) -> Result<(), String> {
    match direction {
        Direction::Client => {
            let frame: ClientFrame = serde_json::from_slice(bytes)
                .map_err(|_| "Malformed or forbidden client code host frame".to_string())?;
            match frame {
                ClientFrame::Cancel { id } => {
                    let _ = id;
                    return Err("Code host cancellation stops its owned lifetime".into());
                }
                ClientFrame::Request {
                    request: Request::Execute { request, .. },
                    ..
                } if !request.enabled_tools.is_empty() => {
                    return Err("Code host nested tools are forbidden".into());
                }
                _ => {}
            }
        }
        Direction::Host => {
            let _: HostFrame = serde_json::from_slice(bytes)
                .map_err(|_| "Malformed, delegated or nontext code host frame".to_string())?;
        }
    }
    Ok(())
}

struct Budget {
    remaining: usize,
    frames: usize,
}

impl Budget {
    fn new(remaining: usize) -> Self {
        Self {
            remaining,
            frames: 0,
        }
    }
}

fn claim_bytes(budget: &Mutex<Budget>, count: usize) -> Result<(), String> {
    let mut budget = budget
        .lock()
        .map_err(|_| "Code host byte budget is unavailable".to_string())?;
    budget.remaining = budget
        .remaining
        .checked_sub(count)
        .ok_or_else(|| "Code host byte budget exceeded".to_string())?;
    Ok(())
}

fn read_frame<R: Read>(reader: &mut R, budget: &Mutex<Budget>) -> Result<Option<Vec<u8>>, String> {
    let mut prefix = [0; 4];
    loop {
        match reader.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err("Could not read code host frame prefix".into()),
        }
    }
    reader
        .read_exact(&mut prefix[1..])
        .map_err(|_| "Truncated code host frame prefix".to_string())?;
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 {
        return Err("Empty code host frame".into());
    }
    {
        let mut budget = budget
            .lock()
            .map_err(|_| "Code host frame budget is unavailable".to_string())?;
        if budget.frames >= MAX_MESSAGES {
            return Err("Code host message budget exceeded".into());
        }
        budget.remaining = budget
            .remaining
            .checked_sub(length.saturating_add(4))
            .ok_or_else(|| "Code host frame exceeds its byte budget".to_string())?;
        budget.frames += 1;
    }
    // The complete length is charged before allocating the payload.
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| "Truncated code host frame payload".to_string())?;
    Ok(Some(bytes))
}

fn write_frame<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), String> {
    let length = u32::try_from(bytes.len()).map_err(|_| "Invalid code host frame length")?;
    writer
        .write_all(&length.to_le_bytes())
        .and_then(|()| writer.write_all(bytes))
        .and_then(|()| writer.flush())
        .map_err(|_| "Could not forward code host frame".to_string())
}

// These deliberately narrow types follow native protocol V1 at Codex release
// ff6aec96948b70d94983af2641a6b67c94faeff5. Delegates and media have no variant.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all_fields = "camelCase")]
enum ClientFrame {
    #[serde(rename = "connection/hello")]
    Hello {
        supported_versions: Vec<u32>,
        required_capabilities: Vec<String>,
        optional_capabilities: Vec<String>,
    },
    #[serde(rename = "operation/request")]
    Request { id: i64, request: Request },
    #[serde(rename = "operation/cancel")]
    Cancel { id: i64 },
    #[serde(rename = "operation/yield")]
    Yield { id: i64 },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "method", rename_all_fields = "camelCase")]
enum Request {
    #[serde(rename = "session/open")]
    Open {
        session_id: String,
        cell_execution_limits: Option<Limits>,
    },
    #[serde(rename = "session/execute")]
    Execute {
        session_id: String,
        request: Execute,
    },
    #[serde(rename = "session/wait")]
    Wait { session_id: String, request: Wait },
    #[serde(rename = "session/terminate")]
    Terminate { session_id: String, cell_id: String },
    #[serde(rename = "session/shutdown")]
    Shutdown { session_id: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Limits {
    max_yield_time_ms: Option<u64>,
    max_heap_size_bytes: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Execute {
    tool_call_id: String,
    enabled_tools: Vec<Value>,
    source: String,
    yield_time_ms: Option<u64>,
    max_output_tokens: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wait {
    cell_id: String,
    yield_time_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all_fields = "camelCase")]
enum HostFrame {
    #[serde(rename = "connection/ready")]
    Ready {
        selected_version: u32,
        capabilities: Vec<String>,
    },
    #[serde(rename = "operation/response")]
    Response {
        id: i64,
        result: WireResult<Response>,
    },
    #[serde(rename = "execute/initialResponse")]
    Initial {
        id: i64,
        result: WireResult<Runtime>,
    },
    #[serde(rename = "cell/closed")]
    Closed { session_id: String, cell_id: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "status")]
enum WireResult<T> {
    #[serde(rename = "ok")]
    Ok { value: T },
    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all_fields = "camelCase")]
enum Response {
    #[serde(rename = "session/ready")]
    Ready { session_id: String },
    #[serde(rename = "execution/started")]
    Started { cell_id: String },
    #[serde(rename = "wait/completed")]
    Wait { outcome: Outcome },
    #[serde(rename = "session/closed")]
    Closed { session_id: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Outcome {
    LiveCell(Runtime),
    MissingCell(Runtime),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Runtime {
    Yielded(RuntimeBody),
    Terminated(RuntimeBody),
    Result(ResultBody),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeBody {
    cell_id: String,
    content_items: Vec<TextItem>,
    code_mode_host_duration_ns: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultBody {
    cell_id: String,
    content_items: Vec<TextItem>,
    error_text: Option<String>,
    code_mode_host_duration_ns: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type")]
enum TextItem {
    #[serde(rename = "input_text")]
    Text { text: String },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionStatus {
    Opening,
    Ready,
    Closing,
    Closed,
}

enum Operation {
    Open(String),
    Execute {
        session: String,
        cell: Option<String>,
    },
    Wait {
        session: String,
        cell: String,
    },
    Shutdown(String),
}

struct Cell {
    session: String,
    initial: bool,
    terminal: bool,
    closed: bool,
}

#[derive(Default)]
struct Protocol {
    hello: bool,
    ready: bool,
    offered: BTreeSet<String>,
    required: BTreeSet<String>,
    sessions: BTreeMap<String, SessionStatus>,
    seen_requests: BTreeSet<i64>,
    pending: BTreeMap<i64, Operation>,
    seen_calls: BTreeSet<String>,
    cells: BTreeMap<String, Cell>,
    executions: usize,
    waits: usize,
    source_bytes: usize,
}

impl Protocol {
    fn client(&mut self, bytes: &[u8]) -> Result<(), String> {
        let frame: ClientFrame = serde_json::from_slice(bytes)
            .map_err(|_| "Malformed or forbidden client code host frame".to_string())?;
        match frame {
            ClientFrame::Hello {
                supported_versions,
                required_capabilities,
                optional_capabilities,
            } => {
                if self.hello || supported_versions != [1] {
                    return Err("Invalid code host handshake".into());
                }
                self.required = capabilities(&required_capabilities)?;
                self.offered = capabilities(&optional_capabilities)?;
                if !self.required.is_disjoint(&self.offered) {
                    return Err("Overlapping code host capabilities".into());
                }
                self.offered.extend(self.required.iter().cloned());
                self.hello = true;
            }
            ClientFrame::Cancel { .. } => {
                return Err("Code host cancellation stops its owned lifetime".into());
            }
            ClientFrame::Yield { id } => {
                if !self.ready || !self.pending.contains_key(&id) {
                    return Err("Code host control refers to an unknown request".into());
                }
            }
            ClientFrame::Request { id, request } => {
                if !self.ready || !self.seen_requests.insert(id) {
                    return Err("Code host request is unready or duplicated".into());
                }
                let operation = self.request(request)?;
                self.pending.insert(id, operation);
            }
        }
        Ok(())
    }

    fn request(&mut self, request: Request) -> Result<Operation, String> {
        match request {
            Request::Open {
                session_id,
                cell_execution_limits,
            } => {
                identifier(&session_id)?;
                if self.sessions.len() >= MAX_SESSIONS || self.sessions.contains_key(&session_id) {
                    return Err("Code host session is duplicated or exceeds its bound".into());
                }
                if let Some(limits) = cell_execution_limits {
                    yield_limit(limits.max_yield_time_ms)?;
                    // The pinned host ignores this value; do not accept a heap
                    // setting that might be mistaken for an enforced ceiling.
                    if limits.max_heap_size_bytes.is_some() {
                        return Err("Native code host heap limits are not enforced".into());
                    }
                }
                self.sessions
                    .insert(session_id.clone(), SessionStatus::Opening);
                Ok(Operation::Open(session_id))
            }
            Request::Execute {
                session_id,
                request,
            } => {
                self.session_ready(&session_id)?;
                identifier(&request.tool_call_id)?;
                yield_limit(request.yield_time_ms)?;
                if !request.enabled_tools.is_empty()
                    || self.executions >= MAX_EXECUTIONS
                    || request.source.len() > MAX_INPUT_BYTES
                    || request.max_output_tokens.is_some_and(|count| count < 0)
                    || !self.seen_calls.insert(request.tool_call_id)
                {
                    return Err("Code host execute violates its capability or count bound".into());
                }
                self.source_bytes = self
                    .source_bytes
                    .checked_add(request.source.len())
                    .filter(|total| *total <= MAX_INPUT_BYTES)
                    .ok_or_else(|| "Code host source budget exceeded".to_string())?;
                self.executions += 1;
                Ok(Operation::Execute {
                    session: session_id,
                    cell: None,
                })
            }
            Request::Wait {
                session_id,
                request,
            } => {
                yield_limit(Some(request.yield_time_ms))?;
                self.wait(session_id, request.cell_id)
            }
            Request::Terminate {
                session_id,
                cell_id,
            } => self.wait(session_id, cell_id),
            Request::Shutdown { session_id } => {
                self.session_ready(&session_id)?;
                self.sessions
                    .insert(session_id.clone(), SessionStatus::Closing);
                Ok(Operation::Shutdown(session_id))
            }
        }
    }

    fn session_ready(&self, session: &str) -> Result<(), String> {
        if self.sessions.get(session) != Some(&SessionStatus::Ready) {
            return Err("Code host session is not ready".into());
        }
        Ok(())
    }

    fn wait(&mut self, session: String, cell: String) -> Result<Operation, String> {
        self.session_ready(&session)?;
        if self.waits >= MAX_WAITS
            || self
                .cells
                .get(&cell)
                .is_none_or(|record| record.session != session || !record.initial)
        {
            return Err("Code host wait is uncorrelated or exceeds its bound".into());
        }
        self.waits += 1;
        Ok(Operation::Wait { session, cell })
    }

    fn host(&mut self, bytes: &[u8]) -> Result<(), String> {
        let frame: HostFrame = serde_json::from_slice(bytes)
            .map_err(|_| "Malformed, delegated or nontext code host frame".to_string())?;
        match frame {
            HostFrame::Ready {
                selected_version,
                capabilities: selected,
            } => {
                let selected = capabilities(&selected)?;
                if !self.hello
                    || self.ready
                    || selected_version != 1
                    || !selected.is_subset(&self.offered)
                    || !self.required.is_subset(&selected)
                {
                    return Err("Uncorrelated code host handshake response".into());
                }
                self.ready = true;
            }
            HostFrame::Response { id, result } => self.response(id, result)?,
            HostFrame::Initial { id, result } => {
                let Some(Operation::Execute {
                    session,
                    cell: Some(cell),
                }) = self.pending.remove(&id)
                else {
                    return Err("Uncorrelated initial code host response".into());
                };
                let WireResult::Ok { value } = result else {
                    return Err("Failed initial code host response".into());
                };
                self.runtime(&session, &cell, value)?;
                self.cells.get_mut(&cell).unwrap().initial = true;
            }
            HostFrame::Closed {
                session_id,
                cell_id,
            } => {
                let cell = self
                    .cells
                    .get_mut(&cell_id)
                    .ok_or_else(|| "Unknown closed code host cell".to_string())?;
                if cell.session != session_id || !cell.initial || cell.closed {
                    return Err("Uncorrelated or duplicate code host cell closure".into());
                }
                cell.terminal = true;
                cell.closed = true;
            }
        }
        Ok(())
    }

    fn response(&mut self, id: i64, result: WireResult<Response>) -> Result<(), String> {
        let operation = self
            .pending
            .remove(&id)
            .ok_or_else(|| "Unknown code host response request ID".to_string())?;
        let value = match result {
            WireResult::Ok { value } => value,
            WireResult::Error { message } => {
                // Errors are correlated, bounded text but invalidate the run;
                // forwarding them cannot establish a completed research result.
                let _ = message;
                return Err("Native code host operation failed".into());
            }
        };
        match (operation, value) {
            (Operation::Open(session), Response::Ready { session_id }) if session == session_id => {
                self.sessions.insert(session, SessionStatus::Ready);
            }
            (
                Operation::Execute {
                    session,
                    cell: None,
                },
                Response::Started { cell_id },
            ) => {
                identifier(&cell_id)?;
                if self.cells.contains_key(&cell_id) {
                    return Err("Duplicate code host cell ID".into());
                }
                self.cells.insert(
                    cell_id.clone(),
                    Cell {
                        session: session.clone(),
                        initial: false,
                        terminal: false,
                        closed: false,
                    },
                );
                self.pending.insert(
                    id,
                    Operation::Execute {
                        session,
                        cell: Some(cell_id),
                    },
                );
            }
            (Operation::Wait { session, cell }, Response::Wait { outcome }) => {
                let runtime = match outcome {
                    Outcome::LiveCell(runtime) | Outcome::MissingCell(runtime) => runtime,
                };
                self.runtime(&session, &cell, runtime)?;
            }
            (Operation::Shutdown(session), Response::Closed { session_id })
                if session == session_id =>
            {
                if self
                    .cells
                    .values()
                    .any(|cell| cell.session == session && !cell.closed)
                {
                    return Err("Code host session closed with unclosed cells".into());
                }
                self.sessions.insert(session, SessionStatus::Closed);
            }
            _ => return Err("Code host response does not match its request".into()),
        }
        Ok(())
    }

    fn runtime(&mut self, session: &str, cell_id: &str, value: Runtime) -> Result<(), String> {
        let (body_cell, items, duration, terminal, error) = match value {
            Runtime::Yielded(body) => (
                body.cell_id,
                body.content_items,
                body.code_mode_host_duration_ns,
                false,
                None,
            ),
            Runtime::Terminated(body) => (
                body.cell_id,
                body.content_items,
                body.code_mode_host_duration_ns,
                true,
                None,
            ),
            Runtime::Result(body) => (
                body.cell_id,
                body.content_items,
                body.code_mode_host_duration_ns,
                true,
                body.error_text,
            ),
        };
        let cell = self
            .cells
            .get_mut(cell_id)
            .ok_or_else(|| "Unknown code host runtime cell".to_string())?;
        if body_cell != cell_id || cell.session != session || (!terminal && cell.terminal) {
            return Err("Uncorrelated code host runtime response".into());
        }
        // Deserialization restricts content to text; the frame budget already
        // bounds these strings, the error text and timing field together.
        for TextItem::Text { text } in items {
            let _ = text;
        }
        let _ = (duration, error);
        cell.terminal |= terminal;
        Ok(())
    }
}

fn identifier(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err("Invalid code host identifier".into());
    }
    Ok(())
}

fn yield_limit(value: Option<u64>) -> Result<(), String> {
    if value.is_some_and(|value| value > MAX_TIMEOUT_MILLIS) {
        return Err("Code host observation exceeds its time bound".into());
    }
    Ok(())
}

fn capabilities(values: &[String]) -> Result<BTreeSet<String>, String> {
    let mut selected = BTreeSet::new();
    for value in values {
        if !CAPABILITIES.contains(&value.as_str()) || !selected.insert(value.clone()) {
            return Err("Unknown or duplicate code host capability".into());
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deadline_cannot_observe_the_spawn_registration_gap() {
        let slot = Arc::new(Mutex::new(None::<u8>));
        let stopping = Arc::new(AtomicBool::new(false));
        let (entered, entered_rx) = mpsc::channel();
        let (resume, resume_rx) = mpsc::channel();
        let launch_slot = Arc::clone(&slot);
        let launch_stop = Arc::clone(&stopping);
        let launcher = thread::spawn(move || {
            let registered = register_owned_child(&launch_slot, &launch_stop, || {
                entered.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                Ok(7)
            })
            .unwrap();
            assert_eq!(*registered, Some(7));
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        stopping.store(true, Ordering::SeqCst);
        assert!(matches!(
            slot.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        resume.send(()).unwrap();
        launcher.join().unwrap();
        assert_eq!(*slot.lock().unwrap(), Some(7));
        let empty = Mutex::new(None::<u8>);
        assert!(
            register_owned_child(&empty, &stopping, || panic!("stopped owner must not spawn"))
                .is_err()
        );
    }

    #[test]
    fn starting_and_running_status_are_atomically_complete() {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-atomic-host-status-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let status_file = path.join("status.json");
        publish_status(
            &status_file,
            &StatusRecord::new(Status::Starting, None),
            true,
        )
        .unwrap();
        assert!(
            publish_status(
                &status_file,
                &StatusRecord::new(Status::Starting, None),
                true
            )
            .is_err()
        );
        let done = Arc::new(AtomicBool::new(false));
        let observer_done = Arc::clone(&done);
        let observer_path = status_file.clone();
        let observer = thread::spawn(move || {
            while !observer_done.load(Ordering::SeqCst) {
                let record: StatusRecord =
                    serde_json::from_slice(&fs::read(&observer_path).unwrap()).unwrap();
                match record.state {
                    Status::Starting => assert!(record.native_pid.is_none()),
                    Status::Running => assert_eq!(record.native_pid, Some(42)),
                    _ => panic!("unexpected status transition"),
                }
            }
        });
        for _ in 0..16 {
            publish_status(
                &status_file,
                &StatusRecord::new(Status::Running, Some(42)),
                false,
            )
            .unwrap();
            publish_status(
                &status_file,
                &StatusRecord::new(Status::Starting, None),
                false,
            )
            .unwrap();
        }
        done.store(true, Ordering::SeqCst);
        observer.join().unwrap();
        publish_status(
            &status_file,
            &StatusRecord::new(Status::Failed, Some(42)),
            false,
        )
        .unwrap();
        assert!(has_host_failed(&status_file).unwrap());
        assert!(
            publish_status(
                &status_file,
                &StatusRecord::new(Status::Running, Some(42)),
                false
            )
            .is_err()
        );
        publish_status(
            &status_file,
            &StatusRecord::new(Status::Stopped, Some(42)),
            false,
        )
        .unwrap();
        let final_status: StatusRecord =
            serde_json::from_slice(&fs::read(&status_file).unwrap()).unwrap();
        assert!(final_status.state == Status::Failed);
        // Even a concurrently replaced observation cannot reset the latch.
        fs::write(
            &status_file,
            serde_json::to_vec(&StatusRecord::new(Status::Running, Some(42))).unwrap(),
        )
        .unwrap();
        assert!(has_host_failed(&status_file).unwrap());
        fs::remove_dir_all(path).unwrap();
    }

    fn ready() -> Protocol {
        let mut state = Protocol::default();
        state
            .client(
                &serde_json::to_vec(&json!({
                    "type":"connection/hello", "supportedVersions":[1],
                    "requiredCapabilities":[], "optionalCapabilities":[]
                }))
                .unwrap(),
            )
            .unwrap();
        state
            .host(br#"{"type":"connection/ready","selectedVersion":1,"capabilities":[]}"#)
            .unwrap();
        state.client(br#"{"type":"operation/request","id":1,"request":{"method":"session/open","sessionId":"s1"}}"#).unwrap();
        state.host(br#"{"type":"operation/response","id":1,"result":{"status":"ok","value":{"type":"session/ready","sessionId":"s1"}}}"#).unwrap();
        state
    }

    fn execute(id: i64, tools: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"type":"operation/request","id":id,"request":{
            "method":"session/execute","sessionId":"s1","request":{
                "tool_call_id":format!("call-{id}"),"enabled_tools":tools,
                "source":"text(6 * 7)","yield_time_ms":1000,"max_output_tokens":100
            }
        }}))
        .unwrap()
    }

    #[test]
    fn every_execute_requires_an_explicit_empty_tool_array() {
        for tools in [Value::Null, json!([{}]), json!({})] {
            assert!(ready().client(&execute(2, tools)).is_err());
        }
        let mut missing: Value = serde_json::from_slice(&execute(2, json!([]))).unwrap();
        missing["request"]["request"]
            .as_object_mut()
            .unwrap()
            .remove("enabled_tools");
        assert!(
            ready()
                .client(&serde_json::to_vec(&missing).unwrap())
                .is_err()
        );
        let mut state = ready();
        assert!(state.client(&execute(2, json!([]))).is_ok());
        assert!(state.client(&execute(3, json!([{}]))).is_err());
    }

    #[test]
    fn unknown_methods_delegate_and_media_fail_closed() {
        let mut state = ready();
        assert!(state.client(br#"{"type":"delegate/response","id":2,"result":{"status":"ok","value":{"type":"notification/delivered"}}}"#).is_err());
        assert!(state.host(br#"{"type":"delegate/request","id":2,"sessionId":"s1","request":{"type":"notification/send","callId":"c","cellId":"x","text":"42"}}"#).is_err());
        assert!(state.client(br#"{"type":"operation/request","id":2,"request":{"method":"session/other","sessionId":"s1"}}"#).is_err());
        assert!(state.host(br#"{"type":"execute/initialResponse","id":2,"result":{"status":"ok","value":{"Result":{"cell_id":"x","content_items":[{"type":"input_image","image_url":"data:image/png;base64,AA=="}],"error_text":null,"code_mode_host_duration_ns":0}}}}"#).is_err());
    }

    #[test]
    fn framing_is_preserved_and_charged_before_allocation() {
        let bytes = br#"{ "type": "connection/hello" }"#;
        let mut framed = Vec::new();
        write_frame(&mut framed, bytes).unwrap();
        let budget = Mutex::new(Budget::new(framed.len()));
        let recovered = read_frame(&mut framed.as_slice(), &budget)
            .unwrap()
            .unwrap();
        let mut forwarded = Vec::new();
        write_frame(&mut forwarded, &recovered).unwrap();
        assert_eq!(forwarded, framed);
        assert_eq!(budget.lock().unwrap().remaining, 0);
        let prefix = u32::MAX.to_le_bytes();
        assert!(read_frame(&mut prefix.as_slice(), &Mutex::new(Budget::new(256))).is_err());
        assert!(read_frame(&mut &prefix[..2], &Mutex::new(Budget::new(256))).is_err());
    }

    #[test]
    fn frame_count_and_duplicate_request_bounds_are_enforced() {
        let one = [1, 0, 0, 0, b'0'];
        let bytes = one.repeat(MAX_MESSAGES + 1);
        let mut reader = bytes.as_slice();
        let budget = Mutex::new(Budget::new(bytes.len()));
        for _ in 0..MAX_MESSAGES {
            assert!(read_frame(&mut reader, &budget).unwrap().is_some());
        }
        assert!(read_frame(&mut reader, &budget).is_err());
        let mut state = ready();
        state.client(&execute(2, json!([]))).unwrap();
        assert!(state.client(&execute(2, json!([]))).is_err());
    }
}
