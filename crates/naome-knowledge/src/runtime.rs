//! Independent lifecycle and a bounded, instance-bound local control channel.
use crate::{Graph, autonomous::Intervals, network};
use libp2p::identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::time::Duration;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    time::Instant,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

pub use crate::autonomous::Intervals as RuntimeIntervals;
pub use crate::jobs::{Limits as JobLimits, RecoveryPolicy, RoleSettings, Settings as RuntimeJobs};
mod cli;
mod owner;
mod replay_guard;
mod startup;
pub(crate) use owner::Profile as OwnerProfile;
pub(crate) use startup::Startup;

fn control_limit() -> usize {
    // Resource reports carry a bounded 4 KiB snapshot, independently of the
    // configured owner-text capacity. They never duplicate owner text.
    (6 * crate::resources::limits().owner_text_bytes + 512).max(4096 + 512)
}
const DAEMON_NONCE: &str = "NAOME_DAEMON_NONCE";
static LOG: OnceLock<Mutex<Log>> = OnceLock::new();

struct Log {
    file: File,
    path: PathBuf,
    error: Option<String>,
}

impl Log {
    fn open(directory: &Path) -> Result<Self, String> {
        let path = directory.join("node.log");
        cap_log(&path)?;
        cap_log(&directory.join("node.log.previous"))?;
        let file = open_log(&path)?;
        Ok(Self {
            file,
            path,
            error: None,
        })
    }

    fn write(&mut self, value: &serde_json::Value) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        if bytes.len() as u64 > crate::resources::limits().log_segment_bytes {
            return Err("runtime event exceeds log capacity".into());
        }
        if self
            .file
            .metadata()
            .map_err(|error| error.to_string())?
            .len()
            + bytes.len() as u64
            > crate::resources::limits().log_segment_bytes
        {
            cap_log(&self.path)?;
            let previous = self.path.with_file_name("node.log.previous");
            let source = open_log(&self.path)?;
            let mut target = open_log(&previous)?;
            target.set_len(0).map_err(|error| error.to_string())?;
            std::io::copy(
                &mut source.take(crate::resources::limits().log_segment_bytes),
                &mut target,
            )
            .map_err(|error| error.to_string())?;
            self.file.set_len(0).map_err(|error| error.to_string())?;
        }
        self.file
            .write_all(&bytes)
            .map_err(|error| error.to_string())
    }
}

fn open_log(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err("runtime log must be one owned regular file".into());
    }
    Ok(file)
}

fn cap_log(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
        Ok(metadata) if !metadata.is_file() => {
            return Err("runtime log path must be a regular file".into());
        }
        Ok(_) => {}
    }
    let mut file = open_log(path)?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("runtime log must be a regular file".into());
    }
    if metadata.len() <= crate::resources::limits().log_segment_bytes {
        return Ok(());
    }
    file.seek(SeekFrom::End(
        -(crate::resources::limits().log_segment_bytes as i64),
    ))
    .map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(crate::resources::limits().log_segment_bytes)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let retained = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| &bytes[offset + 1..])
        .unwrap_or(&[]);
    file.set_len(0).map_err(|error| error.to_string())?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    file.write_all(retained)
        .and_then(|_| file.sync_all())
        .map_err(|error| error.to_string())
}

pub(crate) fn emit_log(value: &serde_json::Value) -> bool {
    let Some(log) = LOG.get() else {
        return false;
    };
    let mut log = log.lock().expect("runtime log owner");
    if log.error.is_some() {
        return true;
    }
    let result = log.write(value);
    if let Err(error) = result {
        log.error = Some(error);
    }
    true
}

pub(crate) fn log_error() -> Option<String> {
    LOG.get()
        .and_then(|log| log.lock().expect("runtime log owner").error.clone())
}

/// Fatal daemon diagnostics use the same bounded owner as ordinary events.
pub fn report_error(error: &str) {
    let bounded = error
        .chars()
        .take(crate::resources::limits().diagnostic_bytes)
        .collect::<String>();
    if !emit_log(&serde_json::json!({"event":"fatal_error","error":bounded})) {
        eprintln!("naome: {error}");
    }
}

/// The complete ordinary status surface. Count only unique checked accepted IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub running: bool,
    pub computation: crate::resources::ComputationState,
    pub accepted_proofs: usize,
    pub interest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    version: u8,
    token: String,
    pid: u32,
    socket: PathBuf,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct IdentityReceipt {
    version: u8,
    peer_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Status,
    Resources,
    Stop,
    Pause,
    Resume,
    Interest(String),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    token: String,
    operation: Operation,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    token: String,
    report: Report,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Report {
    Status {
        status: Status,
    },
    Resources {
        snapshot: Option<crate::resources::adaptive::Snapshot>,
    },
}

pub(crate) struct Control {
    listener: UnixListener,
    directory: PathBuf,
    endpoint: Endpoint,
    stopping: tokio::sync::watch::Sender<bool>,
    pub(crate) computation: std::sync::Arc<crate::resources::Computation>,
    owner: std::sync::Arc<Mutex<OwnerState>>,
    selection_dirty: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ownership: Option<std::sync::Arc<crate::store::Store>>,
    startup: Option<Startup>,
}

impl crate::publication::LocalAuthority for Control {
    fn check_selection(&self, expected: Option<[u8; 32]>) -> Result<(), crate::Error> {
        if self.stopping() {
            return Err(crate::Error::StaleAuthority);
        }
        let selection = self.selection().map_err(|_| crate::Error::StaleAuthority)?;
        if Some(selection) != expected {
            return Err(crate::Error::StaleAuthority);
        }
        Ok(())
    }
}

struct OwnerState {
    text: String,
    recovery_error: Option<String>,
}

fn socket_path(directory: &Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    // Keep the socket below macOS's path limit even for a long node directory.
    PathBuf::from("/tmp").join(format!(
        "naome-{}.sock",
        crate::hex(&Sha256::digest(directory.as_os_str().as_bytes()))
    ))
}

fn endpoint(directory: &Path) -> Result<Option<Endpoint>, String> {
    let path = directory.join("control.json");
    if !path.exists() {
        return Ok(None);
    }
    let endpoint: Endpoint =
        serde_json::from_slice(&crate::store::read_bounded(&path, control_limit())?)
            .map_err(|error| error.to_string())?;
    if endpoint.version != 1
        || endpoint.socket != socket_path(directory)
        || endpoint.pid <= 1
        || endpoint.pid > i32::MAX as u32
        || endpoint.token.len() != 64
        || crate::unhex(&endpoint.token)?.len() != 32
    {
        return Err("invalid local control endpoint".into());
    }
    Ok(Some(endpoint))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| error.to_string())
}

impl Control {
    #[cfg(test)]
    pub(crate) fn bind_test(
        directory: &Path,
        ownership: std::sync::Arc<crate::store::Store>,
    ) -> Result<Self, String> {
        let mut control = Self::bind_token(directory, "01".repeat(32))?;
        control.ownership = Some(ownership);
        Ok(control)
    }

    /// Called only after Graph::open owns and revalidates this directory.
    pub(crate) fn bind(directory: &Path, startup: Option<Startup>) -> Result<Self, String> {
        let token = std::env::var(DAEMON_NONCE).map_err(|_| "missing internal launch nonce")?;
        let mut control = Self::bind_token(directory, token)?;
        control.startup = startup;
        Ok(control)
    }

    pub(crate) fn bind_owned(
        directory: &Path,
        startup: Option<Startup>,
        ownership: std::sync::Arc<crate::store::Store>,
    ) -> Result<Self, String> {
        let mut control = Self::bind(directory, startup)?;
        control.ownership = Some(ownership);
        Ok(control)
    }

    pub(crate) async fn accept(&self) -> Result<UnixStream, String> {
        self.listener
            .accept()
            .await
            .map(|(stream, _)| stream)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn stopping(&self) -> bool {
        *self.stopping.borrow()
    }

    pub(crate) fn startup_ready(&self) {
        if let Some(startup) = &self.startup {
            startup.ready();
        }
    }

    fn bind_token(directory: &Path, token: String) -> Result<Self, String> {
        if token.len() != 64 || crate::unhex(&token)?.len() != 32 {
            return Err("invalid internal launch nonce".into());
        }
        let directory = fs::canonicalize(directory).map_err(|error| error.to_string())?;
        let text = owner::load(&directory)?;
        let socket = socket_path(&directory);
        match fs::symlink_metadata(&socket) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                fs::remove_file(&socket).map_err(|error| error.to_string())?
            }
            Ok(_) => return Err("local control path is not a socket".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        let listener = UnixListener::bind(&socket).map_err(|error| error.to_string())?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        let endpoint = Endpoint {
            version: 1,
            token,
            pid: std::process::id(),
            socket,
        };
        let temporary = directory.join(".control-incoming");
        if temporary.exists() {
            fs::remove_file(&temporary).map_err(|error| error.to_string())?;
        }
        write_new(
            &temporary,
            &serde_json::to_vec(&endpoint).map_err(|error| error.to_string())?,
        )?;
        fs::rename(temporary, directory.join("control.json")).map_err(|error| error.to_string())?;
        File::open(&directory)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(Self {
            listener,
            directory,
            endpoint,
            stopping: tokio::sync::watch::channel(false).0,
            computation: std::sync::Arc::default(),
            owner: std::sync::Arc::new(Mutex::new(OwnerState {
                text,
                recovery_error: None,
            })),
            selection_dirty: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            ownership: None,
            startup: None,
        })
    }

    /// A profile snapshot for same-owner consumers, with validated format,
    /// revision and digest. Recovery uncertainty never yields a usable profile.
    pub(crate) fn owner_profile(&self) -> Result<OwnerProfile, String> {
        let mut owner = self
            .owner
            .lock()
            .map_err(|_| "owner configuration lock poisoned")?;
        if let Some(error) = &owner.recovery_error {
            return Err(error.clone());
        }
        let profile = owner::profile(&self.directory).inspect_err(|_error| {
            self.selection_dirty
                .store(true, std::sync::atomic::Ordering::Release);
        })?;
        owner.text = profile.interest.clone();
        Ok(profile)
    }

    pub(crate) fn selection(&self) -> Result<[u8; 32], String> {
        let profile = self.owner_profile()?;
        let bytes = serde_json::to_vec(&(
            "naome-deterministic-mocks-v1",
            profile.version,
            profile.revision,
            profile.digest,
            crate::hex(&Sha256::digest(profile.interest.as_bytes())),
        ))
        .map_err(|e| e.to_string())?;
        Ok(Sha256::digest(bytes).into())
    }

    pub(crate) fn selection_changed(&self) -> bool {
        self.selection_dirty
            .swap(false, std::sync::atomic::Ordering::AcqRel)
    }

    pub(crate) async fn respond(
        &self,
        mut stream: UnixStream,
        count: usize,
        ready: bool,
    ) -> Result<bool, String> {
        let request: Request = tokio::time::timeout(
            crate::resources::limits().control_request_timeout,
            read_frame(&mut stream),
        )
        .await
        .map_err(|_| "local control request timeout")??;
        if request.version != 1 || request.token != self.endpoint.token {
            return Err("local control instance mismatch".into());
        }
        #[cfg(feature = "developer-tools")]
        if std::env::var("NAOME_DEV_CONTROL_SENDBUF_BYTES").as_deref() == Ok("1024") {
            socket2::SockRef::from(&stream)
                .set_send_buffer_size(1024)
                .map_err(|e| e.to_string())?;
        }
        let stopping = matches!(request.operation, Operation::Stop);
        let resources = matches!(request.operation, Operation::Resources);
        if stopping {
            self.stopping.send_replace(true);
        }
        if ready && !self.stopping() {
            match request.operation {
                Operation::Pause => self.computation.set_paused(true),
                Operation::Resume => self.computation.set_paused(false),
                _ => {}
            }
        }
        let directory = self.directory.clone();
        let state = self.owner.clone();
        let dirty = self.selection_dirty.clone();
        let ownership = self.ownership.clone();
        let interest = tokio::task::spawn_blocking(move || -> Result<String, String> {
            // Keep the canonical directory locked until any in-flight owner
            // transition finishes, including after a disconnected control client.
            let _ownership = ownership;
            match request.operation {
                Operation::Resources => Ok(String::new()),
                Operation::Status | Operation::Pause | Operation::Resume => {
                    let mut owner = state
                        .lock()
                        .map_err(|_| "owner configuration lock poisoned")?;
                    if let Some(error) = &owner.recovery_error {
                        return Err(error.clone());
                    }
                    let profile = owner::profile(&directory).inspect_err(|_| {
                        dirty.store(true, std::sync::atomic::Ordering::Release);
                    })?;
                    owner.text = profile.interest.clone();
                    Ok(profile.interest)
                }
                Operation::Stop => Ok(state
                    .lock()
                    .map_err(|_| "owner configuration lock poisoned")?
                    .text
                    .clone()),
                Operation::Interest(text) => {
                    dirty.store(true, std::sync::atomic::Ordering::Release);
                    let mut owner = state
                        .lock()
                        .map_err(|_| "owner configuration lock poisoned")?;
                    if let Some(error) = &owner.recovery_error {
                        return Err(error.clone());
                    }
                    match owner::update(&directory, &text) {
                        Ok(text) => {
                            owner.text = text.clone();
                            Ok(text)
                        }
                        Err(error) => {
                            if error.recovery_required {
                                owner.recovery_error = Some(error.message.clone());
                            }
                            Err(error.message)
                        }
                    }
                }
            }
        })
        .await
        .map_err(|error| format!("owner control worker failed: {error}"))??;
        let running = ready && !self.stopping();
        let response = Response {
            token: self.endpoint.token.clone(),
            report: if resources {
                Report::Resources {
                    snapshot: crate::resources::adaptive::current(),
                }
            } else {
                Report::Status {
                    status: Status {
                        running,
                        computation: if running {
                            self.computation.state()
                        } else {
                            crate::resources::ComputationState::Stopped
                        },
                        accepted_proofs: count,
                        interest,
                    },
                }
            },
        };
        // Leave time for a response timeout to settle before the node's stop
        // drain expires, while provider teardown has already been requested.
        tokio::time::timeout(
            crate::resources::limits().control_request_timeout,
            write_frame(&mut stream, &response),
        )
        .await
        .map_err(|_| "local control write timeout")??;
        Ok(stopping)
    }

    pub(crate) fn stop_watch(&self) -> tokio::sync::watch::Receiver<bool> {
        self.stopping.subscribe()
    }
}

#[cfg(test)]
mod tests;

impl Drop for Control {
    fn drop(&mut self) {
        if endpoint(&self.directory)
            .ok()
            .flatten()
            .is_some_and(|endpoint| endpoint.token == self.endpoint.token)
        {
            let _ = fs::remove_file(self.directory.join("control.json"));
            let _ = fs::remove_file(&self.endpoint.socket);
        }
    }
}

pub(crate) async fn requested_stop(watch: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    if let Some(watch) = watch {
        loop {
            if *watch.borrow_and_update() {
                return;
            }
            if watch.changed().await.is_err() {
                return;
            }
        }
    } else {
        std::future::pending().await
    }
}

async fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T, String> {
    tokio::time::timeout(crate::resources::limits().control_timeout, async {
        let mut bytes = Vec::new();
        BufReader::new(stream)
            .take(control_limit() as u64 + 1)
            .read_until(b'\n', &mut bytes)
            .await
            .map_err(|error| error.to_string())?;
        if bytes.len() > control_limit() || bytes.last() != Some(&b'\n') {
            return Err("local control frame limit or incomplete request".into());
        }
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())
    })
    .await
    .map_err(|_| "local control read timeout")?
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > control_limit() {
        return Err("local control response limit".into());
    }
    tokio::time::timeout(
        crate::resources::limits().control_timeout,
        stream.write_all(&bytes),
    )
    .await
    .map_err(|_| "local control write timeout")?
    .map_err(|error| error.to_string())
}

async fn request_response(
    directory: &Path,
    operation: Operation,
    launch: Option<&str>,
) -> Result<Option<Response>, String> {
    let Some(endpoint) = endpoint(directory)? else {
        return Ok(None);
    };
    if launch.is_some_and(|nonce| nonce != endpoint.token) {
        return Ok(None);
    }
    let connected = tokio::time::timeout(
        crate::resources::limits().control_timeout,
        UnixStream::connect(&endpoint.socket),
    )
    .await
    .map_err(|_| "local control connect timeout")?;
    let mut stream = match connected {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.to_string()),
    };
    write_frame(
        &mut stream,
        &Request {
            version: 1,
            token: endpoint.token.clone(),
            operation,
        },
    )
    .await?;
    let response: Response = read_frame(&mut stream).await?;
    if response.token != endpoint.token {
        return Err("local control response instance mismatch".into());
    }
    Ok(Some(response))
}

async fn request(
    directory: &Path,
    operation: Operation,
    launch: Option<&str>,
) -> Result<Option<Status>, String> {
    request_response(directory, operation, launch)
        .await
        .and_then(|response| {
            response
                .map(|r| match r.report {
                    Report::Status { status } => Ok(status),
                    _ => Err("unexpected control response type".into()),
                })
                .transpose()
        })
}

fn directory() -> Result<PathBuf, String> {
    let path = if let Some(path) = std::env::var_os("NAOME_NODE_DIR") {
        PathBuf::from(path)
    } else if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(path).join("naome")
    } else {
        PathBuf::from(std::env::var_os("HOME").ok_or("set NAOME_NODE_DIR or HOME")?)
            .join(".local/share/naome")
    };
    if path.as_os_str().is_empty() {
        return Err("empty node directory".into());
    }
    Ok(if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(path)
    })
}

async fn operation_lock(directory: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(directory.join("lifecycle.lock"))
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + crate::resources::limits().lifecycle_timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                tokio::time::sleep(crate::resources::limits().lifecycle_poll_interval).await
            }
            Err(error) => return Err(format!("lifecycle operation unavailable: {error}")),
        }
    }
}

fn initialize(directory: &Path) -> Result<(), String> {
    let key_path = directory.join("identity.key");
    let receipt_path = directory.join("identity.json");
    let previously_started = directory.join("node.log").exists()
        || directory.join("node.log.previous").exists()
        || directory.join("control.json").exists();
    if !key_path.exists() {
        if receipt_path.exists() || previously_started {
            return Err("existing node identity is missing; refusing to replace it".into());
        }
        let key = identity::Keypair::generate_ed25519();
        write_new(
            &key_path,
            &key.to_protobuf_encoding()
                .map_err(|error| error.to_string())?,
        )?;
    }
    let key =
        identity::Keypair::from_protobuf_encoding(&crate::store::read_bounded(&key_path, 1024)?)
            .map_err(|error| error.to_string())?;
    let expected = IdentityReceipt {
        version: 1,
        peer_id: key.public().to_peer_id().to_string(),
    };
    if receipt_path.exists() {
        let receipt: IdentityReceipt =
            serde_json::from_slice(&crate::store::read_bounded(&receipt_path, 1024)?)
                .map_err(|error| error.to_string())?;
        if receipt != expected {
            return Err("existing node identity does not match its initialized identity".into());
        }
    } else {
        if previously_started {
            return Err("existing node identity receipt is missing".into());
        }
        write_new(
            &receipt_path,
            &serde_json::to_vec(&expected).map_err(|error| error.to_string())?,
        )?;
    }
    let config = directory.join("config.json");
    if !config.exists() {
        write_new(
            &config,
            &serde_json::to_vec_pretty(
                &serde_json::json!({"directory":directory,"listen":"/ip4/0.0.0.0/tcp/0","peers":[],
            "discovery":network::DiscoveryConfig::default(),"runtime":Intervals::default()}),
            )
            .map_err(|error| error.to_string())?,
        )?;
    }
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn configuration(directory: &Path) -> Result<(network::Config, Intervals), String> {
    let mut value: serde_json::Value = serde_json::from_slice(&crate::store::read_bounded(
        &directory.join("config.json"),
        crate::resources::limits().network_config_bytes,
    )?)
    .map_err(|error| error.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or("node configuration must be an object")?;
    let intervals = object
        .remove("runtime")
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or_default();
    let intervals: Intervals = intervals;
    let configured = object
        .entry("directory")
        .or_insert_with(|| serde_json::json!(directory));
    let configured_path = PathBuf::from(
        configured
            .as_str()
            .ok_or("configuration directory must be a path")?,
    );
    let configured_path = if configured_path.is_absolute() {
        configured_path
    } else {
        directory.join(configured_path)
    };
    if fs::canonicalize(configured_path).map_err(|error| error.to_string())? != directory {
        return Err("configuration belongs to another node directory".into());
    }
    *configured = serde_json::json!(directory);
    let config: network::Config =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    if !config.producer_sources.is_empty() {
        return Err("producer_sources is a developer-only operation; ordinary runtime uses the three mock functions".into());
    }
    Ok((config, intervals.validate()?))
}

async fn stopped_status(directory: &Path) -> Result<Status, String> {
    let graph = Graph::open(directory)?;
    Ok(Status {
        running: false,
        computation: crate::resources::ComputationState::Stopped,
        accepted_proofs: graph.accepted_count(),
        interest: owner::load(directory)?,
    })
}

async fn interest(directory: &Path, text: &str) -> Result<Status, String> {
    owner::validate(text)?;
    if let Some(status) = request(directory, Operation::Interest(text.into()), None).await? {
        return Ok(status);
    }
    // Keep the graph's kernel lock through persistence and status construction.
    // A daemon or embedding racing this command cannot become another writer.
    let graph = Graph::open(directory)?;
    Ok(Status {
        running: false,
        computation: crate::resources::ComputationState::Stopped,
        accepted_proofs: graph.accepted_count(),
        interest: owner::update(directory, text).map_err(|error| error.message)?,
    })
}

async fn status(directory: &Path) -> Result<Status, String> {
    if let Some(status) = request(directory, Operation::Status, None).await? {
        return Ok(status);
    }
    stopped_status(directory).await
}

async fn computation(directory: &Path, paused: bool) -> Result<Status, String> {
    let operation = if paused {
        Operation::Pause
    } else {
        Operation::Resume
    };
    request(directory, operation, None)
        .await?
        .filter(|status| status.running)
        .ok_or_else(|| "node is not running; start it before pause or resume".into())
}

async fn start(directory: &Path) -> Result<Status, String> {
    start_with_handoff(directory, None).await
}

async fn start_with_handoff(
    directory: &Path,
    mut handoff: Option<startup::Handoff>,
) -> Result<Status, String> {
    let deadline = match &handoff {
        Some(owner) => owner.deadline()?,
        None => tokio::time::Instant::now() + crate::resources::limits().startup_timeout,
    };
    // Keep startup cancellation alive while the child performs synchronous
    // replay. SIGKILL/parent disappearance instead closes the stdin lifeline.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("startup termination signal: {e}"))?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| format!("startup interrupt signal: {e}"))?;
    if let Some(status) =
        tokio::time::timeout_at(deadline, request(directory, Operation::Status, None))
            .await
            .map_err(|_| "node startup deadline")??
    {
        if handoff.is_some() {
            return Err("startup handoff requires a new owned daemon".into());
        }
        return Ok(status);
    }
    // Prove there is no existing owner before launching. The daemon takes the
    // same kernel lock itself; an external embedding racing this probe wins or fails.
    // Catalog shape establishes no mathematical proof validity. The daemon
    // alone rebuilds checked roots by complete mathematical corpus replay.
    drop(crate::store::Store::open(directory)?);
    initialize(directory)?;
    configuration(directory)?;
    let nonce = crate::hex(&Sha256::digest(
        identity::Keypair::generate_ed25519()
            .to_protobuf_encoding()
            .map_err(|error| error.to_string())?,
    ));
    // Compact retained diagnostics before opening the child's inherited handles.
    cap_log(&directory.join("node.log"))?;
    cap_log(&directory.join("node.log.previous"))?;
    let log = open_log(&directory.join("node.log"))?;
    if tokio::time::Instant::now() >= deadline {
        return Err("node startup deadline before launch".into());
    }
    let mut command = Command::new(std::env::current_exe().map_err(|error| error.to_string())?);
    command
        .arg("start")
        .env("NAOME_NODE_DIR", directory)
        .env(DAEMON_NONCE, &nonce)
        .env(
            "NAOME_EFFECTIVE_RESOURCES",
            crate::resources::child_snapshot()?,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::from(
            log.try_clone().map_err(|error| error.to_string())?,
        ))
        .stderr(Stdio::from(log))
        .env_remove(startup::HANDOFF_ACTIVE)
        .env_remove(startup::HANDOFF_CLEANUP)
        .env_remove(startup::CUSTODY_ACTIVE);
    if let Some(owner) = &mut handoff {
        owner.before_offer()?;
        command.env(startup::CUSTODY_ACTIVE, owner.active_ns.to_string());
    }
    let inherited_session = if handoff.is_some() {
        Some((
            nix::unistd::getpgrp(),
            nix::unistd::getsid(None).map_err(|e| e.to_string())?,
        ))
    } else {
        None
    };
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let launch = async {
        child
            .stdin
            .as_mut()
            .ok_or("startup parent lifeline missing")?
            .write_all(&startup::begin(&nonce))
            .map_err(|e| e.to_string())?;
        let status = if let Some(owner) = &mut handoff {
            // The existing owner lifeline is checked concurrently with RPC,
            // so a slow readiness exchange cannot delay owned EOF cancellation.
            tokio::select! {
                value = startup::wait(directory, &nonce, deadline, || Ok(None)) => value?,
                lost = owner.wait_for_loss() => { lost?; return Err("startup owner lost".into()); }
            }
        } else {
            startup::wait(directory, &nonce, deadline, || {
                child.try_wait().map_err(|e| e.to_string())
            })
            .await?
        };
        if tokio::time::Instant::now() >= deadline {
            return Err("node startup deadline before acknowledgement".into());
        }
        if let Some(owner) = &mut handoff {
            owner.transfer(child.id(), &nonce).await?;
        }
        child
            .stdin
            .as_mut()
            .ok_or("startup parent lifeline missing")?
            .write_all(&startup::acknowledge(&nonce))
            .map_err(|e| e.to_string())?;
        drop(child.stdin.take());
        Ok(status)
    };
    let result: Result<Status, String> = tokio::select! {
        result = launch => result,
        _ = terminate.recv() => Err("node startup cancelled".into()),
        _ = interrupt.recv() => Err("node startup cancelled".into()),
    };
    match result {
        Ok(status) => Ok(status),
        Err(error) => {
            let cleanup = match &handoff {
                Some(owner) => {
                    let (until, clock_error) = match owner.abort_deadline() {
                        Ok(until) => (until, None),
                        Err(error) => (Instant::now(), Some(error)),
                    };
                    let mut report =
                        abort_owned_handoff(&mut child, until, inherited_session).await?;
                    if let Some(error) = clock_error {
                        report["clock_error"] = serde_json::json!(error);
                        report["complete"] = serde_json::json!(false);
                    }
                    owner.report_abort(child.id(), &nonce, &report)?;
                    if report["complete"] == true {
                        Ok(())
                    } else {
                        Err(format!("owned startup abort incomplete: {report}"))
                    }
                }
                None => abort_start(&mut child).await,
            };
            cleanup.map_err(|cleanup| format!("{error}; {cleanup}"))?;
            Err(format!("{error}; owned startup child reaped"))
        }
    }
}

async fn abort_owned_handoff(
    child: &mut Child,
    deadline: Instant,
    inherited: Option<(nix::unistd::Pid, nix::unistd::Pid)>,
) -> Result<serde_json::Value, String> {
    use nix::sys::{
        signal::{Signal, kill, killpg},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    };
    // The opt-in caller never polled/reaped this original Child. Stop it before
    // interpreting a pre-setsid snapshot; a successful SIGSTOP alone is not proof.
    drop(child.stdin.take());
    let pid = nix::unistd::Pid::from_raw(
        i32::try_from(child.id()).map_err(|_| "invalid original handoff Child PID")?,
    );
    let mut errors = Vec::<String>::new();
    if let Err(error) = kill(pid, Signal::SIGSTOP) {
        errors.push(format!("original Child stop: {error}"));
    }
    let stable_end =
        deadline.min(Instant::now() + crate::resources::limits().detach_confirm_timeout);
    let mut stopped = false;
    let mut reaped = false;
    let mut authority_lost = false;
    let mut reaper = "NONE";
    loop {
        match waitpid(pid, Some(WaitPidFlag::WUNTRACED | WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Stopped(actual, Signal::SIGSTOP)) if actual == pid => {
                stopped = true;
                break;
            }
            Ok(WaitStatus::Exited(actual, _)) | Ok(WaitStatus::Signaled(actual, _, _))
                if actual == pid =>
            {
                // waitpid really reaped it. No group or PID signal follows.
                reaped = true;
                reaper = "waitpid";
                errors.push(
                    "original Child exited before stable session confirmation; group unknown"
                        .into(),
                );
                break;
            }
            Ok(WaitStatus::StillAlive) => {}
            Ok(other) => {
                errors.push(format!("unconfirmed original Child stop: {other:?}"));
                break;
            }
            Err(error) => {
                authority_lost = true;
                errors.push(format!("original Child wait authority: {error}"));
                break;
            }
        }
        if Instant::now() >= stable_end {
            errors.push("original Child stop confirmation deadline".into());
            break;
        }
        tokio::time::sleep(
            crate::resources::limits()
                .detach_poll_interval
                .min(stable_end.saturating_duration_since(Instant::now())),
        )
        .await;
    }
    let mut state = "UNKNOWN";
    let mut group_empty: Option<bool> = None;
    if stopped {
        match (
            nix::unistd::getpgid(Some(pid)),
            nix::unistd::getsid(Some(pid)),
        ) {
            (Ok(group), Ok(session)) if group == pid && session == pid => {
                state = "CONFIRMED_STOPPED_DETACHED_SESSION";
                group_empty = Some(false);
            }
            (Ok(group), Ok(session)) if inherited == Some((group, session)) => {
                // The actually stopped child cannot race setsid after this
                // observation. First-party daemon code calls setsid before work.
                state = "CONFIRMED_STOPPED_BEFORE_DETACH";
            }
            observed => errors.push(format!(
                "stopped original Child session unproved: {observed:?}"
            )),
        }
    }
    if !reaped && !authority_lost {
        let signalled = if group_empty.is_some() {
            // Actual stopped/unreaped session leader pins this original group.
            killpg(pid, Signal::SIGKILL).map_err(|e| e.to_string())
        } else {
            child.kill().map_err(|e| e.to_string())
        };
        if let Err(error) = signalled {
            errors.push(format!("original Child/group kill: {error}"));
        }
    }
    loop {
        if !reaped && !authority_lost {
            match child.try_wait() {
                Ok(Some(_)) => {
                    reaped = true;
                    reaper = "std_Child_try_wait";
                }
                Ok(None) => {}
                Err(error) => {
                    authority_lost = true;
                    errors.push(format!("original Child reap: {error}"));
                }
            }
        }
        if group_empty.is_some() {
            // Query only after the sole group signal; never signal after reap.
            group_empty = Some(matches!(killpg(pid, None), Err(nix::errno::Errno::ESRCH)));
        }
        let closure_known = group_empty == Some(true) || state == "CONFIRMED_STOPPED_BEFORE_DETACH";
        if reaped && closure_known {
            break;
        }
        if authority_lost || Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(
            crate::resources::limits()
                .detach_poll_interval
                .min(deadline.saturating_duration_since(Instant::now())),
        )
        .await;
    }
    let closure_known = group_empty == Some(true) || state == "CONFIRMED_STOPPED_BEFORE_DETACH";
    Ok(
        serde_json::json!({"complete":errors.is_empty() && reaped && closure_known && Instant::now() <= deadline,
        "original_child_pid":child.id(),"original_child_reaped":reaped,"reaper":reaper,
        "session_state":state,"owned_group_empty":group_empty,"errors":errors,
        "authority_lost":authority_lost}),
    )
}

async fn abort_start(child: &mut Child) -> Result<(), String> {
    // EOF reaches the independent reader even while Graph::open is synchronous.
    drop(child.stdin.take());
    let deadline = Instant::now() + crate::resources::limits().lifecycle_abort_timeout;
    let fallback = Instant::now() + crate::resources::limits().supervisor_cleanup_timeout;
    let mut signalled = false;
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Ok(());
        }
        if !signalled && Instant::now() >= fallback {
            let pid = nix::unistd::Pid::from_raw(
                i32::try_from(child.id()).map_err(|_| "invalid owned startup PID")?,
            );
            // The still-unreaped direct Child is the launch authority. Group
            // fallback additionally requires its actual current self-session.
            if nix::unistd::getpgid(Some(pid)).ok() == Some(pid)
                && nix::unistd::getsid(Some(pid)).ok() == Some(pid)
            {
                nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL)
                    .map_err(|e| format!("owned startup group cleanup: {e}"))?;
            } else {
                child
                    .kill()
                    .map_err(|e| format!("owned startup child cleanup: {e}"))?;
            }
            signalled = true;
        }
        if Instant::now() >= deadline {
            return Err("owned startup exit and reap remain unconfirmed".into());
        }
        tokio::time::sleep(crate::resources::limits().cleanup_poll_interval).await;
    }
}

async fn stop(directory: &Path) -> Result<Status, String> {
    let owned = endpoint(directory)?;
    if request(directory, Operation::Stop, None).await?.is_none() {
        return stopped_status(directory).await;
    }
    let pid = nix::unistd::Pid::from_raw(
        i32::try_from(owned.expect("successful control request has endpoint").pid)
            .map_err(|_| "invalid daemon process identity")?,
    );
    // Stop is nonce-authenticated; this callback only queries group liveness.
    wait_for_stop(
        directory,
        Instant::now() + crate::resources::limits().lifecycle_timeout,
        || nix::sys::signal::killpg(pid, None),
    )
    .await
}

async fn wait_for_stop(
    directory: &Path,
    deadline: Instant,
    mut observe_group: impl FnMut() -> nix::Result<()>,
) -> Result<Status, String> {
    loop {
        let exited = match observe_group() {
            Err(nix::errno::Errno::ESRCH) => true,
            // A denied query is inconclusive; only a later ESRCH proves exit.
            Err(nix::errno::Errno::EPERM) => false,
            Ok(()) => false,
            Err(error) => return Err(format!("observe daemon process group: {error}")),
        };
        match stopped_status(directory).await {
            Ok(status) if exited => return Ok(status),
            Ok(_) if Instant::now() >= deadline => {
                return Err(
                    "node directory released but daemon process group exit is unconfirmed".into(),
                );
            }
            Ok(_) => tokio::time::sleep(crate::resources::limits().lifecycle_poll_interval).await,
            Err(error) if Instant::now() >= deadline => {
                return Err(format!("node did not release its directory: {error}"));
            }
            Err(_) => tokio::time::sleep(crate::resources::limits().lifecycle_poll_interval).await,
        }
    }
}

/// Ordinary CLI exposes lifecycle, computation control and local owner interest.
pub async fn execute() -> Result<(), String> {
    crate::resources::initialize_from_environment()?;
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let plain = if arguments.first().is_some_and(|a| a == "--json") {
        &arguments[1..]
    } else {
        &arguments[..]
    };
    if plain.first().is_some_and(|a| a == "resources") {
        return resources_command(&plain[1..]).await;
    }
    if let Some(result) = crate::jobs::internal(&arguments) {
        return result;
    }
    let cli::Arguments {
        command,
        text,
        json,
        startup_handoff,
    } = cli::Arguments::parse(&arguments)?;
    let _replay_guard = replay_guard::optional(command)?;
    let directory = directory()?;
    if std::env::var_os(DAEMON_NONCE).is_some() {
        if command != "start" || startup_handoff {
            return Err("invalid internal lifecycle invocation".into());
        }
        nix::unistd::setsid().map_err(|error| format!("detach node session: {error}"))?;
        let nonce = std::env::var(DAEMON_NONCE).map_err(|_| "missing internal launch nonce")?;
        let startup = Startup::arm(&nonce)?;
        let directory = fs::canonicalize(directory).map_err(|error| error.to_string())?;
        LOG.set(Mutex::new(Log::open(&directory)?))
            .map_err(|_| "runtime log already owned")?;
        let (config, intervals) = configuration(&directory)?;
        return network::run_autonomous(config, intervals, startup).await;
    }
    if matches!(command, "stop" | "status") && !directory.exists() {
        cli::print(
            command,
            json,
            &Status {
                running: false,
                computation: crate::resources::ComputationState::Stopped,
                accepted_proofs: 0,
                interest: String::new(),
            },
        )?;
        return Ok(());
    }
    if matches!(command, "pause" | "resume") && !directory.exists() {
        return Err("node is not running; start it before pause or resume".into());
    }
    crate::storage::private_directory(&directory)?;
    let directory = fs::canonicalize(directory).map_err(|error| error.to_string())?;
    let _lock = operation_lock(&directory).await?;
    let status = match command {
        "start" if startup_handoff => {
            start_with_handoff(&directory, Some(startup::Handoff::open()?)).await?
        }
        "start" => start(&directory).await?,
        "stop" => stop(&directory).await?,
        "pause" => computation(&directory, true).await?,
        "resume" => computation(&directory, false).await?,
        "status" => status(&directory).await?,
        "interest" => interest(&directory, text.expect("parsed interest text")).await?,
        _ => unreachable!(),
    };
    cli::print(command, json, &status)
}

async fn resources_command(arguments: &[std::ffi::OsString]) -> Result<(), String> {
    use crate::resources::adaptive::{self, Snapshot};
    let directory = directory()?;
    if arguments.first().is_some_and(|v| v == "history") {
        if arguments.len() > 2 {
            return Err("usage: naome resources history [after]".into());
        }
        let after = arguments
            .get(1)
            .map(|s| {
                s.to_str()
                    .ok_or("invalid history cursor")?
                    .parse::<u64>()
                    .map_err(|e| e.to_string())
            })
            .transpose()?
            .unwrap_or(0);
        println!(
            "{}",
            serde_json::to_string_pretty(&adaptive::history::page(&directory, after)?)
                .map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if !arguments.is_empty() {
        return Err(
            "usage: naome resources [history [after]]; resource budgets adapt automatically".into(),
        );
    }
    let configured = adaptive::load(&directory)?;
    let active = if directory.exists() {
        match request_response(&directory, Operation::Resources, None).await? {
            Some(Response {
                report: Report::Resources { snapshot },
                ..
            }) => snapshot,
            None => None,
            _ => return Err("unexpected resource response type".into()),
        }
    } else {
        None
    };
    let location = if directory.exists() {
        directory.as_path()
    } else {
        std::path::Path::new("/tmp")
    };
    let proposed = Snapshot::derive(
        configured.clone(),
        adaptive::sample(location)?,
        crate::resources::limits().memory_bytes as u64,
    )?;
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({"version":crate::resources::PROFILE_VERSION,"limits":crate::resources::limits(),"configured":configured,"active":active,"caller_observation":proposed,"memory_charge":crate::resources::memory_usage()})).map_err(|e|e.to_string())?);
    Ok(())
}
