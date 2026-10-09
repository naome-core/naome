//! Independent lifecycle and a bounded, instance-bound local control channel.
use crate::{Graph, autonomous::Intervals, network};
use libp2p::identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

pub use crate::autonomous::Intervals as RuntimeIntervals;
mod cli;
mod owner;
pub(crate) use owner::Profile as OwnerProfile;

const CONTROL_LIMIT: usize = 6 * owner::MAX_TEXT_BYTES + 512;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(15);
const DAEMON_NONCE: &str = "NAOME_DAEMON_NONCE";
const MAX_LOG_BYTES: u64 = 1024 * 1024;
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
        if bytes.len() as u64 > MAX_LOG_BYTES {
            return Err("runtime event exceeds log capacity".into());
        }
        if self
            .file
            .metadata()
            .map_err(|error| error.to_string())?
            .len()
            + bytes.len() as u64
            > MAX_LOG_BYTES
        {
            cap_log(&self.path)?;
            let previous = self.path.with_file_name("node.log.previous");
            let source = open_log(&self.path)?;
            let mut target = open_log(&previous)?;
            target.set_len(0).map_err(|error| error.to_string())?;
            std::io::copy(&mut source.take(MAX_LOG_BYTES), &mut target)
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
    if metadata.len() <= MAX_LOG_BYTES {
        return Ok(());
    }
    file.seek(SeekFrom::End(-(MAX_LOG_BYTES as i64)))
        .map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_LOG_BYTES)
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
    let bounded = error.chars().take(4096).collect::<String>();
    if !emit_log(&serde_json::json!({"event":"fatal_error","error":bounded})) {
        eprintln!("naome: {error}");
    }
}

/// The complete ordinary status surface. Count only unique checked accepted IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub running: bool,
    pub accepted_proofs: usize,
    #[serde(default)]
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
    Stop,
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
    status: Status,
}

pub(crate) struct Control {
    listener: UnixListener,
    directory: PathBuf,
    endpoint: Endpoint,
    owner: Mutex<OwnerState>,
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
        serde_json::from_slice(&crate::store::read_bounded(&path, CONTROL_LIMIT)?)
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
    /// Called only after Graph::open owns and revalidates this directory.
    pub(crate) fn bind(directory: &Path) -> Result<Self, String> {
        let token = std::env::var(DAEMON_NONCE).map_err(|_| "missing internal launch nonce")?;
        Self::bind_token(directory, token)
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
            owner: Mutex::new(OwnerState {
                text,
                recovery_error: None,
            }),
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
        let profile = owner::profile(&self.directory)?;
        owner.text = profile.interest.clone();
        Ok(profile)
    }

    pub(crate) async fn respond(
        &self,
        mut stream: UnixStream,
        count: usize,
        ready: bool,
    ) -> Result<bool, String> {
        let request: Request = read_frame(&mut stream).await?;
        if request.version != 1 || request.token != self.endpoint.token {
            return Err("local control instance mismatch".into());
        }
        let stopping = matches!(request.operation, Operation::Stop);
        let interest = match request.operation {
            Operation::Status => self.owner_profile()?.interest,
            Operation::Stop => self
                .owner
                .lock()
                .map_err(|_| "owner configuration lock poisoned")?
                .text
                .clone(),
            Operation::Interest(text) => {
                // Serialize transitions even if the consumer serves concurrent
                // clients. Never retain this guard across the response await.
                let mut owner = self
                    .owner
                    .lock()
                    .map_err(|_| "owner configuration lock poisoned")?;
                if let Some(error) = &owner.recovery_error {
                    return Err(error.clone());
                }
                match owner::update(&self.directory, &text) {
                    Ok(text) => {
                        owner.text = text.clone();
                        text
                    }
                    Err(error) => {
                        if error.recovery_required {
                            owner.recovery_error = Some(error.message.clone());
                        }
                        return Err(error.message);
                    }
                }
            }
        };
        let response = Response {
            token: self.endpoint.token.clone(),
            status: Status {
                running: ready && !stopping,
                accepted_proofs: count,
                interest,
            },
        };
        write_frame(&mut stream, &response).await?;
        Ok(stopping)
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

pub(crate) async fn accept(control: &Option<Control>) -> Result<UnixStream, String> {
    match control {
        Some(control) => control
            .listener
            .accept()
            .await
            .map(|(stream, _)| stream)
            .map_err(|error| error.to_string()),
        None => std::future::pending().await,
    }
}

async fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T, String> {
    tokio::time::timeout(CONTROL_TIMEOUT, async {
        let mut bytes = Vec::new();
        BufReader::new(stream)
            .take(CONTROL_LIMIT as u64 + 1)
            .read_until(b'\n', &mut bytes)
            .await
            .map_err(|error| error.to_string())?;
        if bytes.len() > CONTROL_LIMIT || bytes.last() != Some(&b'\n') {
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
    if bytes.len() > CONTROL_LIMIT {
        return Err("local control response limit".into());
    }
    tokio::time::timeout(CONTROL_TIMEOUT, stream.write_all(&bytes))
        .await
        .map_err(|_| "local control write timeout")?
        .map_err(|error| error.to_string())
}

async fn request(
    directory: &Path,
    operation: Operation,
    launch: Option<&str>,
) -> Result<Option<Status>, String> {
    let Some(endpoint) = endpoint(directory)? else {
        return Ok(None);
    };
    if launch.is_some_and(|nonce| nonce != endpoint.token) {
        return Ok(None);
    }
    let connected = tokio::time::timeout(CONTROL_TIMEOUT, UnixStream::connect(&endpoint.socket))
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
    Ok(Some(response.status))
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
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await
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
        network::MAX_CONFIG_BYTES,
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
        accepted_proofs: graph.ids().len(),
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
        accepted_proofs: graph.ids().len(),
        interest: owner::update(directory, text).map_err(|error| error.message)?,
    })
}

async fn status(directory: &Path) -> Result<Status, String> {
    if let Some(status) = request(directory, Operation::Status, None).await? {
        return Ok(status);
    }
    stopped_status(directory).await
}

async fn start(directory: &Path) -> Result<Status, String> {
    if let Some(status) = request(directory, Operation::Status, None).await? {
        return Ok(status);
    }
    // Prove there is no existing owner before launching. The daemon takes the
    // same kernel lock itself; an external embedding racing this probe wins or fails.
    drop(Graph::open(directory)?);
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
    let mut child = Command::new(std::env::current_exe().map_err(|error| error.to_string())?)
        .arg("start")
        .env("NAOME_NODE_DIR", directory)
        .env(DAEMON_NONCE, &nonce)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            log.try_clone().map_err(|error| error.to_string())?,
        ))
        .stderr(Stdio::from(log))
        .spawn()
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        if let Some(exit) = child.try_wait().map_err(|error| error.to_string())? {
            return Err(format!(
                "node failed to start ({exit}); inspect {}",
                directory.join("node.log").display()
            ));
        }
        match request(directory, Operation::Status, Some(&nonce)).await {
            Ok(Some(status)) if status.running => return Ok(status),
            Ok(Some(_)) => {}
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("node startup deadline; owned launch was terminated".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
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
    wait_for_stop(directory, Instant::now() + LIFECYCLE_TIMEOUT, || {
        nix::sys::signal::killpg(pid, None)
    })
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
            Ok(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(error) if Instant::now() >= deadline => {
                return Err(format!("node did not release its directory: {error}"));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// Ordinary CLI exposes lifecycle, status and exact local owner interest text.
pub async fn execute() -> Result<(), String> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let cli::Arguments {
        command,
        text,
        json,
    } = cli::Arguments::parse(&arguments)?;
    let directory = directory()?;
    if std::env::var_os(DAEMON_NONCE).is_some() {
        if command != "start" {
            return Err("invalid internal lifecycle invocation".into());
        }
        nix::unistd::setsid().map_err(|error| format!("detach node session: {error}"))?;
        let directory = fs::canonicalize(directory).map_err(|error| error.to_string())?;
        LOG.set(Mutex::new(Log::open(&directory)?))
            .map_err(|_| "runtime log already owned")?;
        let (config, intervals) = configuration(&directory)?;
        return network::run_autonomous(config, intervals).await;
    }
    if matches!(command, "stop" | "status") && !directory.exists() {
        cli::print(
            command,
            json,
            &Status {
                running: false,
                accepted_proofs: 0,
                interest: String::new(),
            },
        )?;
        return Ok(());
    }
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let directory = fs::canonicalize(directory).map_err(|error| error.to_string())?;
    let _lock = operation_lock(&directory).await?;
    let status = match command {
        "start" => start(&directory).await?,
        "stop" => stop(&directory).await?,
        "status" => status(&directory).await?,
        "interest" => interest(&directory, text.expect("parsed interest text")).await?,
        _ => unreachable!(),
    };
    cli::print(command, json, &status)
}
