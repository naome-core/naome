//! Independent lifecycle and a bounded, instance-bound local control channel.
#[cfg(test)]
use crate::Graph;
use crate::{autonomous::Intervals, network};
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
mod replay_guard;
mod startup;
pub(crate) use startup::Startup;

fn control_limit() -> usize {
    4096
}
const DAEMON_NONCE: &str = "NAOME_DAEMON_NONCE";
static LOG: OnceLock<Mutex<Log>> = OnceLock::new();

struct Log {
    file: File,
    path: PathBuf,
    error: Option<crate::Error>,
}

fn log_io(operation: crate::StorageIoOperation, error: std::io::Error) -> crate::Error {
    crate::error::storage_io_error(operation, error)
}

impl Log {
    fn open(directory: &Path) -> Result<Self, crate::Error> {
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

    fn write(&mut self, value: &serde_json::Value) -> Result<(), crate::Error> {
        use crate::StorageIoOperation as Op;
        let mut bytes =
            serde_json::to_vec(value).map_err(|_| crate::InputFault::LogRecordEncoding)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > crate::resources::limits().log_segment_bytes {
            return Err(crate::InputFault::LogRecordCapacity.into());
        }
        if self
            .file
            .metadata()
            .map_err(|error| log_io(Op::InspectLog, error))?
            .len()
            + bytes.len() as u64
            > crate::resources::limits().log_segment_bytes
        {
            cap_log(&self.path)?;
            let previous = self.path.with_file_name("node.log.previous");
            let source = open_log(&self.path)?;
            let mut target = open_log(&previous)?;
            target
                .set_len(0)
                .map_err(|error| log_io(Op::TruncateLog, error))?;
            std::io::copy(
                &mut source.take(crate::resources::limits().log_segment_bytes),
                &mut target,
            )
            .map_err(|error| log_io(Op::CopyLog, error))?;
            self.file
                .set_len(0)
                .map_err(|error| log_io(Op::TruncateLog, error))?;
        }
        self.file
            .write_all(&bytes)
            .map_err(|error| log_io(Op::WriteLog, error))
    }
}

fn open_log(path: &Path) -> Result<File, crate::Error> {
    use crate::StorageIoOperation as Op;
    let file = OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(|error| log_io(Op::OpenLog, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| log_io(Op::InspectLog, error))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(crate::InputFault::LogFileInvalid.into());
    }
    Ok(file)
}

fn cap_log(path: &Path) -> Result<(), crate::Error> {
    use crate::StorageIoOperation as Op;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(log_io(Op::InspectLog, error)),
        Ok(metadata) if !metadata.is_file() => return Err(crate::InputFault::LogPathInvalid.into()),
        Ok(_) => {}
    }
    let mut file = open_log(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| log_io(Op::InspectLog, error))?;
    if !metadata.is_file() {
        return Err(crate::InputFault::LogFileInvalid.into());
    }
    if metadata.len() <= crate::resources::limits().log_segment_bytes {
        return Ok(());
    }
    file.seek(SeekFrom::End(
        -(crate::resources::limits().log_segment_bytes as i64),
    ))
    .map_err(|error| log_io(Op::SeekLog, error))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(crate::resources::limits().log_segment_bytes)
        .read_to_end(&mut bytes)
        .map_err(|error| log_io(Op::ReadLog, error))?;
    let retained = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| &bytes[offset + 1..])
        .unwrap_or(&[]);
    file.set_len(0)
        .map_err(|error| log_io(Op::TruncateLog, error))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| log_io(Op::SeekLog, error))?;
    file.write_all(retained)
        .map_err(|error| log_io(Op::WriteLog, error))?;
    file.sync_all().map_err(|error| log_io(Op::SyncLog, error))
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

pub(crate) fn log_error() -> Option<crate::Error> {
    LOG.get()
        .and_then(|log| log.lock().expect("runtime log owner").error.clone())
}

/// Fatal daemon diagnostics use the same bounded owner as ordinary events.
pub fn report_error(error: &crate::Error) {
    let event = serde_json::json!({"event":crate::outcome::NodeEvent::FatalError,"error":error});
    if !emit_log(&event) || log_error().is_some() {
        use std::io::Write;
        let mut stderr = std::io::stderr().lock();
        if serde_json::to_writer(&mut stderr, &event).is_ok() {
            let _ = stderr.write_all(b"\n");
        }
    }
}

/// Whether this process reconstructed mathematical validity for the reported set.
pub use crate::outcome::ArtifactVerification;

/// The ordinary status surface. Offline counts describe recorded admissions;
/// only a live checked graph can report `ArtifactVerification::Checked`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub running: bool,
    pub computation: crate::resources::ComputationState,
    pub computation_reason: Option<crate::PauseReason>,
    pub accepted_artifacts: usize,
    pub artifact_verification: ArtifactVerification,
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

fn identity_receipt(directory: &Path) -> Result<Option<IdentityReceipt>, crate::Error> {
    crate::storage::read_owned(&directory.join("identity.json"), 1024)?
        .map(|bytes| {
            let receipt: IdentityReceipt =
                serde_json::from_slice(&bytes).map_err(crate::error::record_decode)?;
            if receipt.version != 1 {
                return Err(crate::InputFault::IdentityReceiptVersion.into());
            }
            Ok(receipt)
        })
        .transpose()
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Status,
    Stop,
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
    Status { status: Status },
}

pub(crate) struct Control {
    listener: UnixListener,
    directory: PathBuf,
    endpoint: Endpoint,
    socket_identity: (u64, u64),
    stopping: tokio::sync::watch::Sender<bool>,
    pub(crate) computation: std::sync::Arc<crate::resources::Computation>,
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

fn socket_path(directory: &Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    // Keep the socket below macOS's path limit even for a long node directory.
    PathBuf::from("/tmp").join(format!(
        "naome-{}.sock",
        crate::hex(&Sha256::digest(directory.as_os_str().as_bytes()))
    ))
}

fn endpoint(directory: &Path) -> Result<Option<Endpoint>, crate::Error> {
    let path = directory.join("control.json");
    if !path.exists() {
        return Ok(None);
    }
    let endpoint: Endpoint =
        serde_json::from_slice(&crate::store::read_bounded(&path, control_limit())?)
            .map_err(control_json)?;
    if endpoint.version != 1
        || endpoint.socket != socket_path(directory)
        || endpoint.pid <= 1
        || endpoint.pid > i32::MAX as u32
        || endpoint.token.len() != 64
        || crate::unhex(&endpoint.token)
            .map_err(|_| crate::InputFault::ControlEndpointInvalid)?
            .len()
            != 32
    {
        return Err(crate::InputFault::ControlEndpointInvalid.into());
    }
    Ok(Some(endpoint))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), crate::Error> {
    use crate::StorageIoOperation as Op;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| crate::error::storage_io_error(Op::CreateRuntimeFile, error))?;
    file.write_all(bytes)
        .map_err(|error| crate::error::storage_io_error(Op::WriteRuntimeFile, error))?;
    file.sync_all()
        .map_err(|error| crate::error::storage_io_error(Op::SyncRuntimeFile, error))
}

impl Control {
    #[cfg(test)]
    pub(crate) fn bind_test(
        directory: &Path,
        ownership: std::sync::Arc<crate::store::Store>,
    ) -> Result<Self, crate::Error> {
        let mut control = Self::bind_token(directory, "01".repeat(32))?;
        control.ownership = Some(ownership);
        Ok(control)
    }

    /// Called only after Graph::open owns and revalidates this directory.
    pub(crate) fn bind(directory: &Path, startup: Option<Startup>) -> Result<Self, crate::Error> {
        let token =
            std::env::var(DAEMON_NONCE).map_err(|_| crate::InputFault::ControlNonceMissing)?;
        let mut control = Self::prepare(directory, token)?;
        control.startup = startup;
        Ok(control)
    }

    pub(crate) fn bind_owned(
        directory: &Path,
        startup: Option<Startup>,
        ownership: std::sync::Arc<crate::store::Store>,
    ) -> Result<Self, crate::Error> {
        let mut control = Self::bind(directory, startup)?;
        control.ownership = Some(ownership);
        Ok(control)
    }

    pub(crate) async fn accept(&self) -> Result<UnixStream, crate::Error> {
        self.listener
            .accept()
            .await
            .map(|(stream, _)| stream)
            .map_err(crate::Error::from)
    }

    pub(crate) fn stopping(&self) -> bool {
        *self.stopping.borrow()
    }

    pub(crate) fn startup_ready(&self) {
        if let Some(startup) = &self.startup {
            startup.ready();
        }
    }

    #[cfg(test)]
    fn bind_token(directory: &Path, token: String) -> Result<Self, crate::Error> {
        let control = Self::prepare(directory, token)?;
        control.publish()?;
        Ok(control)
    }

    fn prepare(directory: &Path, token: String) -> Result<Self, crate::Error> {
        if token.len() != 64
            || crate::unhex(&token)
                .map_err(|_| crate::InputFault::ControlNonceInvalid)?
                .len()
                != 32
        {
            return Err(crate::InputFault::ControlNonceInvalid.into());
        }
        let directory = fs::canonicalize(directory)?;
        let socket = socket_path(&directory);
        match fs::symlink_metadata(&socket) {
            Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(&socket)?,
            Ok(_) => return Err(crate::InputFault::ControlSocketPath.into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&socket)?;
        let socket_identity = (metadata.dev(), metadata.ino());
        let endpoint = Endpoint {
            version: 1,
            token,
            pid: std::process::id(),
            socket,
        };
        Ok(Self {
            listener,
            directory,
            endpoint,
            socket_identity,
            stopping: tokio::sync::watch::channel(false).0,
            computation: std::sync::Arc::default(),
            ownership: None,
            startup: None,
        })
    }

    /// Advertise the listener only after fallible startup state validation. A
    /// failed initializer must report its error before the parent aborts it on
    /// a control connection that closed without a response.
    pub(crate) fn publish(&self) -> Result<(), crate::Error> {
        let temporary = self.directory.join(".control-incoming");
        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        write_new(
            &temporary,
            &serde_json::to_vec(&self.endpoint)
                .map_err(|_| crate::InputFault::ControlEndpointEncode)?,
        )?;
        fs::rename(temporary, self.directory.join("control.json"))?;
        File::open(&self.directory)
            .and_then(|file| file.sync_all())
            .map_err(crate::Error::from)
    }

    pub(crate) fn selection(&self) -> Result<[u8; 32], String> {
        // The active instance and fixed research policy own publication authority.
        // Knowledge and attempt statistics only order work, never revoke grants.
        let mut hash = Sha256::new();
        hash.update(b"naome:research-selection");
        hash.update(self.endpoint.token.as_bytes());
        Ok(hash.finalize().into())
    }

    #[cfg(test)]
    pub(crate) async fn respond(
        &self,
        stream: UnixStream,
        count: usize,
        ready: bool,
    ) -> Result<bool, crate::outcome::ControlFailure> {
        self.respond_tracked(
            stream,
            count,
            ready,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .await
    }

    pub(crate) async fn respond_tracked(
        &self,
        mut stream: UnixStream,
        count: usize,
        ready: bool,
        authenticated: &std::sync::atomic::AtomicBool,
    ) -> Result<bool, crate::outcome::ControlFailure> {
        use crate::outcome::ControlFailure;
        let request: Request = tokio::time::timeout(
            crate::resources::limits().control_request_timeout,
            read_frame(&mut stream),
        )
        .await
        .map_err(|_| ControlFailure::ReadDeadline)?
        .map_err(|_| ControlFailure::Frame)?;
        if request.version != 1 || request.token != self.endpoint.token {
            return Err(ControlFailure::InstanceMismatch);
        }
        authenticated.store(true, std::sync::atomic::Ordering::Release);
        #[cfg(feature = "developer-tools")]
        if std::env::var("NAOME_DEV_CONTROL_SENDBUF_BYTES").as_deref() == Ok("1024") {
            socket2::SockRef::from(&stream)
                .set_send_buffer_size(1024)
                .map_err(|_| ControlFailure::Socket)?;
        }
        let stopping = matches!(request.operation, Operation::Stop);
        if stopping {
            self.stopping.send_replace(true);
        }
        let running = ready && !self.stopping();
        let (computation, computation_reason) = if running {
            self.computation.status()
        } else {
            (crate::resources::ComputationState::Stopped, None)
        };
        let response = Response {
            token: self.endpoint.token.clone(),
            report: Report::Status {
                status: Status {
                    running,
                    computation,
                    computation_reason,
                    accepted_artifacts: count,
                    artifact_verification: ArtifactVerification::Checked,
                },
            },
        };
        #[cfg(feature = "developer-tools")]
        let response = if stopping
            && std::env::var("NAOME_DEV_CONTROL_SENDBUF_BYTES").as_deref() == Ok("1024")
        {
            let mut value = serde_json::to_value(&response).map_err(|_| ControlFailure::Write)?;
            value["padding"] = serde_json::Value::String("x".repeat(3000));
            value
        } else {
            serde_json::to_value(&response).map_err(|_| ControlFailure::Write)?
        };
        // Leave time for a response timeout to settle before the node's stop
        // drain expires, while provider teardown has already been requested.
        tokio::time::timeout(
            crate::resources::limits().control_request_timeout,
            write_frame(&mut stream, &response),
        )
        .await
        .map_err(|_| ControlFailure::WriteDeadline)?
        .map_err(|_| ControlFailure::Write)?;
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
        }
        if fs::symlink_metadata(&self.endpoint.socket)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == self.socket_identity)
        {
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

fn control_json(error: serde_json::Error) -> crate::Error {
    let reason = match crate::error::json_fault(&error) {
        crate::JsonFault::Io => crate::InputFault::ControlJsonIo,
        crate::JsonFault::Syntax => crate::InputFault::ControlJsonSyntax,
        crate::JsonFault::Data => crate::InputFault::ControlJsonData,
        crate::JsonFault::Eof => crate::InputFault::ControlJsonEof,
    };
    reason.into()
}

async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
) -> Result<T, crate::Error> {
    let limit = control_limit();
    tokio::time::timeout(crate::resources::limits().control_timeout, async {
        let mut bytes = Vec::new();
        BufReader::new(stream)
            .take(limit as u64 + 1)
            .read_until(b'\n', &mut bytes)
            .await?;
        if bytes.len() > limit {
            return Err(crate::InputFault::ControlFrameLimit.into());
        }
        if bytes.last() != Some(&b'\n') {
            return Err(crate::InputFault::ControlFrameIncomplete.into());
        }
        serde_json::from_slice(&bytes).map_err(control_json)
    })
    .await
    .map_err(|_| crate::InputFault::ControlReadTimeout)?
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), crate::Error> {
    let limit = control_limit();
    let mut bytes = serde_json::to_vec(value).map_err(control_json)?;
    bytes.push(b'\n');
    if bytes.len() > limit {
        return Err(crate::InputFault::ControlFrameLimit.into());
    }
    tokio::time::timeout(crate::resources::limits().control_timeout, async {
        // Unix sockets may round a requested small send buffer up beyond
        // the entire control frame (Linux does). Separate small writes
        // consume buffer space per packet and keep the unread-client
        // developer fixture exercising backpressure on both platforms.
        #[cfg(feature = "developer-tools")]
        if std::env::var("NAOME_DEV_CONTROL_SENDBUF_BYTES").as_deref() == Ok("1024") {
            for chunk in bytes.chunks(512) {
                stream.write_all(chunk).await?;
            }
            return Ok(());
        }
        stream.write_all(&bytes).await
    })
    .await
    .map_err(|_| crate::InputFault::ControlWriteTimeout)?
    .map_err(crate::Error::from)
}

async fn request(
    directory: &Path,
    operation: Operation,
    launch: Option<&str>,
) -> Result<Option<Status>, crate::Error> {
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
    .map_err(|_| crate::InputFault::ControlConnectTimeout)?;
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
        Err(error) => return Err(error.into()),
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
        return Err(crate::InputFault::ControlResponseMismatch.into());
    }
    let Report::Status { status } = response.report;
    Ok(Some(status))
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

async fn operation_lock(directory: &Path) -> Result<crate::storage::LockFile, String> {
    let file = crate::storage::LockFile::open(&directory.join("lifecycle.lock"))
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

fn initialize(directory: &Path) -> Result<(), crate::Error> {
    let key_path = directory.join("identity.key");
    let receipt_path = directory.join("identity.json");
    let previously_started = directory.join("node.log").exists()
        || directory.join("node.log.previous").exists()
        || directory.join("control.json").exists();
    if !key_path.exists() {
        if receipt_path.exists() || previously_started {
            return Err(crate::InputFault::IdentityKeyMissing.into());
        }
        let key = identity::Keypair::generate_ed25519();
        write_new(
            &key_path,
            &key.to_protobuf_encoding()
                .map_err(|_| crate::InputFault::IdentityKeyEncode)?,
        )?;
    }
    let key =
        identity::Keypair::from_protobuf_encoding(&crate::store::read_bounded(&key_path, 1024)?)
            .map_err(|_| crate::InputFault::IdentityKeyDecode)?;
    let peer_id = key.public().to_peer_id().to_string();
    let receipt = identity_receipt(directory)?;
    if receipt
        .as_ref()
        .is_some_and(|receipt| receipt.peer_id != peer_id)
    {
        return Err(crate::InputFault::IdentityReceiptMismatch.into());
    }
    if receipt.is_none() && previously_started {
        return Err(crate::InputFault::IdentityReceiptMissing.into());
    }
    if receipt.is_none() {
        let incoming = directory.join(".identity-receipt-incoming");
        if crate::storage::read_owned(&incoming, 1024)?.is_some() {
            fs::remove_file(&incoming).map_err(|error| {
                crate::error::storage_io_error(
                    crate::StorageIoOperation::RemoveIdentityStage,
                    error,
                )
            })?;
        }
        write_new(
            &incoming,
            &serde_json::to_vec(&IdentityReceipt {
                version: 1,
                peer_id,
            })
            .map_err(|_| crate::InputFault::IdentityReceiptEncode)?,
        )?;
        fs::rename(&incoming, &receipt_path).map_err(|error| {
            crate::error::storage_io_error(crate::StorageIoOperation::PublishIdentityReceipt, error)
        })?;
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|error| {
                crate::error::storage_io_error(
                    crate::StorageIoOperation::SyncIdentityDirectory,
                    error,
                )
            })?;
    }
    let config = directory.join("config.json");
    if !config.exists() {
        write_new(
            &config,
            &serde_json::to_vec_pretty(
                &serde_json::json!({"directory":directory,"listen":"/ip4/0.0.0.0/tcp/0","peers":[],
            "discovery":network::DiscoveryConfig::default(),"runtime":Intervals::default()}),
            )
            .map_err(|_| crate::InputFault::RuntimeConfigEncode)?,
        )?;
    }
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            crate::error::storage_io_error(crate::StorageIoOperation::SyncIdentityDirectory, error)
        })?;
    Ok(())
}

fn configuration(directory: &Path) -> Result<(network::Config, Intervals), crate::Error> {
    let mut value: serde_json::Value = serde_json::from_slice(&crate::store::read_bounded(
        &directory.join("config.json"),
        crate::resources::limits().network_config_bytes,
    )?)
    .map_err(crate::error::config_decode)?;
    let object = value
        .as_object_mut()
        .ok_or(crate::InputFault::RuntimeConfigObject)?;
    let intervals = object
        .remove("runtime")
        .map(serde_json::from_value)
        .transpose()
        .map_err(crate::error::config_decode)?
        .unwrap_or_default();
    let intervals: Intervals = intervals;
    let configured = object
        .entry("directory")
        .or_insert_with(|| serde_json::json!(directory));
    let configured_path = PathBuf::from(
        configured
            .as_str()
            .ok_or(crate::InputFault::RuntimeConfigDirectory)?,
    );
    let configured_path = if configured_path.is_absolute() {
        configured_path
    } else {
        directory.join(configured_path)
    };
    if fs::canonicalize(configured_path)? != directory {
        return Err(crate::InputFault::RuntimeConfigOwner.into());
    }
    *configured = serde_json::json!(directory);
    let config: network::Config =
        serde_json::from_value(value).map_err(crate::error::config_decode)?;
    if !config.producer_artifacts.is_empty() {
        return Err(crate::InputFault::RuntimeConfigProducer.into());
    }
    Ok((config, intervals.validate()?))
}

async fn stopped_status(directory: &Path) -> Result<Status, crate::Error> {
    let store = crate::store::Store::open(directory)?;
    Ok(Status {
        running: false,
        computation: crate::resources::ComputationState::Stopped,
        computation_reason: None,
        accepted_artifacts: store.stored_count()?,
        artifact_verification: ArtifactVerification::NotRun,
    })
}

async fn status(directory: &Path) -> Result<Status, crate::Error> {
    if let Some(status) = request(directory, Operation::Status, None).await? {
        return Ok(status);
    }
    stopped_status(directory).await
}

async fn start(directory: &Path) -> Result<Status, crate::Error> {
    start_with_handoff(directory, None).await
}

async fn start_with_handoff(
    directory: &Path,
    mut handoff: Option<startup::Handoff>,
) -> Result<Status, crate::Error> {
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
    let result: Result<Status, crate::Error> = tokio::select! {
        result = launch => result,
        _ = terminate.recv() => Err(crate::StartupFailure::Cancelled.into()),
        _ = interrupt.recv() => Err(crate::StartupFailure::Cancelled.into()),
    };
    match result {
        Ok(status) => Ok(status),
        Err(error) => {
            let cleanup = match &handoff {
                Some(owner) => {
                    let until = owner.abort_deadline();
                    let clock_failed = until.is_err();
                    let until = until.unwrap_or_else(|_| Instant::now());
                    let mut report =
                        abort_owned_handoff(&mut child, until, inherited_session).await?;
                    if clock_failed {
                        report.errors.push(crate::outcome::AbortFailure::Clock);
                        report.complete = false;
                    }
                    owner.report_abort(child.id(), &nonce, &report)?;
                    if report.complete {
                        Ok(())
                    } else {
                        Err("owned startup abort incomplete".into())
                    }
                }
                None => abort_start(&mut child).await,
            };
            cleanup.map_err(|_| crate::RuntimeFailure::Cleanup)?;
            let code = match error {
                crate::Error::Startup { code, .. } => code,
                _ => crate::StartupFailure::Launch,
            };
            Err(crate::Error::Startup { code, reaped: true })
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct AbortReport {
    complete: bool,
    original_child_pid: u32,
    original_child_reaped: bool,
    reaper: crate::outcome::AbortReaper,
    session_state: crate::outcome::AbortSession,
    owned_group_empty: Option<bool>,
    errors: Vec<crate::outcome::AbortFailure>,
    authority_lost: bool,
}

async fn abort_owned_handoff(
    child: &mut Child,
    deadline: Instant,
    inherited: Option<(nix::unistd::Pid, nix::unistd::Pid)>,
) -> Result<AbortReport, String> {
    use crate::outcome::{AbortFailure, AbortReaper, AbortSession};
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
    let mut errors = Vec::new();
    if kill(pid, Signal::SIGSTOP).is_err() {
        errors.push(AbortFailure::SignalStop);
    }
    let stable_end =
        deadline.min(Instant::now() + crate::resources::limits().detach_confirm_timeout);
    let mut stopped = false;
    let mut reaped = false;
    let mut authority_lost = false;
    let mut reaper = AbortReaper::None;
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
                reaper = AbortReaper::WaitPid;
                errors.push(AbortFailure::ChildExitedBeforeConfirmation);
                break;
            }
            Ok(WaitStatus::StillAlive) => {}
            Ok(_) => {
                errors.push(AbortFailure::StopUnconfirmed);
                break;
            }
            Err(_) => {
                authority_lost = true;
                errors.push(AbortFailure::WaitAuthorityLost);
                break;
            }
        }
        if Instant::now() >= stable_end {
            errors.push(AbortFailure::StopDeadline);
            break;
        }
        tokio::time::sleep(
            crate::resources::limits()
                .detach_poll_interval
                .min(stable_end.saturating_duration_since(Instant::now())),
        )
        .await;
    }
    let mut state = AbortSession::Unknown;
    let mut group_empty: Option<bool> = None;
    if stopped {
        match (
            nix::unistd::getpgid(Some(pid)),
            nix::unistd::getsid(Some(pid)),
        ) {
            (Ok(group), Ok(session)) if group == pid && session == pid => {
                state = AbortSession::Detached;
                group_empty = Some(false);
            }
            (Ok(group), Ok(session)) if inherited == Some((group, session)) => {
                // The actually stopped child cannot race setsid after this
                // observation. First-party daemon code calls setsid before work.
                state = AbortSession::Inherited;
            }
            _ => errors.push(AbortFailure::SessionUnconfirmed),
        }
    }
    if !reaped && !authority_lost {
        let signalled = if group_empty.is_some() {
            // Actual stopped/unreaped session leader pins this original group.
            killpg(pid, Signal::SIGKILL).is_ok()
        } else {
            child.kill().is_ok()
        };
        if !signalled {
            errors.push(AbortFailure::Kill);
        }
    }
    loop {
        if !reaped && !authority_lost {
            match child.try_wait() {
                Ok(Some(_)) => {
                    reaped = true;
                    reaper = AbortReaper::OwnedChild;
                }
                Ok(None) => {}
                Err(_) => {
                    authority_lost = true;
                    errors.push(AbortFailure::Reap);
                }
            }
        }
        if group_empty.is_some() {
            // Query only after the sole group signal; never signal after reap.
            group_empty = Some(matches!(killpg(pid, None), Err(nix::errno::Errno::ESRCH)));
        }
        let closure_known = group_empty == Some(true) || state == AbortSession::Inherited;
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
    let closure_known = group_empty == Some(true) || state == AbortSession::Inherited;
    Ok(AbortReport {
        complete: errors.is_empty() && reaped && closure_known && Instant::now() <= deadline,
        original_child_pid: child.id(),
        original_child_reaped: reaped,
        reaper,
        session_state: state,
        owned_group_empty: group_empty,
        errors,
        authority_lost,
    })
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

async fn stop(directory: &Path) -> Result<Status, crate::Error> {
    let owned = endpoint(directory)?;
    if request(directory, Operation::Stop, None).await?.is_none() {
        return stopped_status(directory).await;
    }
    let pid = nix::unistd::Pid::from_raw(
        i32::try_from(owned.expect("successful control request has endpoint").pid)
            .map_err(|_| crate::InputFault::StopProcessIdentity)?,
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
) -> Result<Status, crate::Error> {
    loop {
        let exited = match observe_group() {
            Err(nix::errno::Errno::ESRCH) => true,
            // A denied query is inconclusive; only a later ESRCH proves exit.
            Err(nix::errno::Errno::EPERM) => false,
            Ok(()) => false,
            Err(error) => return Err(std::io::Error::from_raw_os_error(error as i32).into()),
        };
        match stopped_status(directory).await {
            Ok(status) if exited => return Ok(status),
            Ok(_) if Instant::now() >= deadline => {
                return Err(crate::InputFault::StopProcessGroupUnconfirmed.into());
            }
            Ok(_) => tokio::time::sleep(crate::resources::limits().lifecycle_poll_interval).await,
            Err(error) if Instant::now() >= deadline => {
                return Err(crate::Error::RuntimeContext {
                    code: crate::RuntimeFailure::StopReleaseUnconfirmed,
                    cause: Box::new(error),
                });
            }
            Err(_) => tokio::time::sleep(crate::resources::limits().lifecycle_poll_interval).await,
        }
    }
}

/// Ordinary CLI exposes lifecycle and passive observation.
pub async fn execute() -> Result<(), crate::Error> {
    use crate::RuntimeFailure as Failure;
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(output) = cli::information(&arguments) {
        println!("{output}");
        return Ok(());
    }
    if std::env::var_os("NAOME_EFFECTIVE_RESOURCES").is_none()
        && std::env::var_os("NAOME_RESOURCE_CONFIG").is_none()
    {
        crate::resources::initialize_for(&directory().map_err(|_| Failure::Directory)?).map_err(
            |cause| crate::Error::RuntimeContext {
                code: Failure::Resources,
                cause: Box::new(cause),
            },
        )?;
    } else {
        crate::resources::initialize_from_environment().map_err(|cause| {
            crate::Error::RuntimeContext {
                code: Failure::Resources,
                cause: Box::new(cause),
            }
        })?;
    }
    if let Some(result) = crate::jobs::internal(&arguments) {
        return result.map_err(|cause| crate::Error::RuntimeContext {
            code: Failure::Worker,
            cause: Box::new(cause),
        });
    }
    let cli::Arguments {
        command,
        json,
        startup_handoff,
    } = cli::Arguments::parse(&arguments).map_err(|_| Failure::Arguments)?;
    let _replay_guard = replay_guard::optional(command).map_err(|_| Failure::ReplayGuard)?;
    let directory = directory().map_err(|_| Failure::Directory)?;
    if std::env::var_os(DAEMON_NONCE).is_some() {
        if command != "start" || startup_handoff {
            return Err(Failure::DaemonSetup.into());
        }
        nix::unistd::setsid().map_err(|_| Failure::DaemonSetup)?;
        let nonce = std::env::var(DAEMON_NONCE).map_err(|_| Failure::DaemonSetup)?;
        let startup = Startup::arm(&nonce).map_err(|_| Failure::DaemonSetup)?;
        let directory = fs::canonicalize(directory).map_err(|_| Failure::Directory)?;
        LOG.set(Mutex::new(Log::open(&directory).map_err(|cause| {
            crate::Error::RuntimeContext {
                code: Failure::Log,
                cause: Box::new(cause),
            }
        })?))
        .map_err(|_| Failure::Log)?;
        let (config, intervals) =
            configuration(&directory).map_err(|cause| crate::Error::RuntimeContext {
                code: Failure::DaemonSetup,
                cause: Box::new(cause),
            })?;
        return network::run_autonomous(config, intervals, startup).await;
    }
    if matches!(command, "stop" | "status") && !directory.exists() {
        cli::print(
            command,
            json,
            &Status {
                running: false,
                computation: crate::resources::ComputationState::Stopped,
                computation_reason: None,
                accepted_artifacts: 0,
                artifact_verification: ArtifactVerification::NotRun,
            },
        )
        .map_err(|_| Failure::Output)?;
        return Ok(());
    }
    crate::storage::private_directory(&directory).map_err(|cause| {
        crate::Error::RuntimeContext {
            code: Failure::Directory,
            cause: Box::new(cause),
        }
    })?;
    let directory = fs::canonicalize(directory).map_err(|_| Failure::Directory)?;
    let _lock = operation_lock(&directory)
        .await
        .map_err(|_| Failure::Directory)?;
    let status = match command {
        "start" if startup_handoff => {
            start_with_handoff(
                &directory,
                Some(startup::Handoff::open().map_err(|_| Failure::Start)?),
            )
            .await?
        }
        "start" => start(&directory).await?,
        "stop" => stop(&directory)
            .await
            .map_err(|cause| crate::Error::RuntimeContext {
                code: Failure::Stop,
                cause: Box::new(cause),
            })?,
        "status" => status(&directory)
            .await
            .map_err(|cause| crate::Error::RuntimeContext {
                code: Failure::Status,
                cause: Box::new(cause),
            })?,
        _ => unreachable!(),
    };
    cli::print(command, json, &status).map_err(|_| Failure::Output.into())
}
