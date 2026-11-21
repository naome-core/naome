//! Local operator control. Each connection requests one operation by its socket name.
use crate::{identity, initialize, node, read_bounded};
use anyhow::{Context, Result, bail, ensure};
use naome_protocol::{store::Archive, wire::Id};
use serde::{Deserialize, Serialize};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions, TryLockError},
    io::{ErrorKind, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt},
        net::UnixStream,
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, net::UnixListener};

const RUNTIME: &str = ".runtime";
const STATUS: &str = ".runtime/status.sock";
const STOP: &str = ".runtime/stop.sock";
const DEADLINE: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(40);

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SyncStatus {
    pub state: String,
    pub available_heads: BTreeSet<Id>,
    pub queued_heads: usize,
    pub active_head: Option<Id>,
    pub pending_requests: usize,
    pub peers_with_catalog: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Status {
    pub running: bool,
    pub pid: Option<u32>,
    pub peer_id: Option<String>,
    pub listen_addresses: Vec<String>,
    pub configured_peers: Vec<String>,
    pub connected_peers: Vec<String>,
    pub connections: BTreeMap<String, String>,
    pub discovered_addresses: BTreeMap<String, Vec<String>>,
    pub sync: Option<SyncStatus>,
}

impl Status {
    pub fn print(&self, json: bool) -> Result<()> {
        if json {
            println!("{}", serde_json::to_string(self)?);
        } else if let (Some(pid), Some(peer), Some(sync)) = (self.pid, &self.peer_id, &self.sync) {
            println!("Running (PID {pid})  {peer}");
            println!("Listening on {}", self.listen_addresses.join(", "));
            println!(
                "Archive peers: {} connected of {} configured",
                self.connected_peers.len(),
                self.configured_peers.len()
            );
            for (peer, route) in &self.connections {
                println!("Connected to {peer} via {route}");
            }
            println!(
                "Replication: {} ({} available inventories)",
                sync.state,
                sync.available_heads.len()
            );
        } else {
            println!("Stopped");
        }
        Ok(())
    }
}

fn private_file(path: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?)
}

// These commands own the whole CLI process. Relative socket names also work in
// node directories whose absolute paths exceed the Unix socket address limit.
fn enter(dir: &Path) -> Result<()> {
    std::env::set_current_dir(dir)?;
    match fs::DirBuilder::new().mode(0o700).create(RUNTIME) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let metadata = fs::symlink_metadata(RUNTIME)?;
    ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
        "the runtime directory must be private to its owner"
    );
    Ok(())
}

fn command_lock() -> Result<File> {
    let file = private_file(".runtime/command.lock")?;
    file.lock()?;
    Ok(file)
}

fn owned() -> Result<bool> {
    match private_file(".runtime/node.lock")?.try_lock() {
        Ok(()) => Ok(false),
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(e)) => Err(e.into()),
    }
}

fn request(socket: &str, timeout: Duration) -> Result<Status> {
    // Darwin rejects SO_RCVTIMEO after the peer has closed its end, even
    // while its complete reply is still buffered. Configure before connecting.
    let client = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    client
        .set_read_timeout(Some(timeout))
        .context("set node reply timeout")?;
    client
        .connect(&SockAddr::unix(socket)?)
        .with_context(|| format!("connect {socket}"))?;
    let stream = UnixStream::from(client);
    let mut bytes = Vec::new();
    stream
        .take(32 * 1024 + 1)
        .read_to_end(&mut bytes)
        .context("read node reply")?;
    ensure!(bytes.len() <= 32 * 1024, "oversized node status");
    Ok(serde_json::from_slice(&bytes)?)
}

fn live_status() -> Result<Status> {
    if owned()? {
        request(STATUS, DEADLINE).context("node owns the directory but did not answer status")
    } else {
        Ok(Status::default())
    }
}

pub fn status(dir: &Path) -> Result<Status> {
    if !dir.join(RUNTIME).try_exists()? {
        return Ok(Status::default());
    }
    enter(dir)?;
    let _command = command_lock()?;
    live_status()
}

pub fn start(dir: &Path) -> Result<Status> {
    fs::create_dir_all(dir)?;
    enter(dir)?;
    let _command = command_lock()?;
    if owned()? {
        return request(STATUS, DEADLINE).context("existing node did not answer status");
    }
    initialize(Path::new("."))?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--directory", ".", "serve"])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(private_file("events.jsonl")?)
        .stderr(private_file("node.log")?)
        .spawn()?;
    let deadline = Instant::now() + DEADLINE;
    loop {
        if let Some(code) = child.try_wait()? {
            bail!(
                "node exited during startup ({code}). See {}/node.log",
                std::env::current_dir()?.display()
            );
        }
        if let Ok(status) = request(STATUS, Duration::from_millis(500))
            && status.running
            && status.pid == Some(child.id())
            && !status.listen_addresses.is_empty()
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            bail!("node listener did not become ready before the startup deadline");
        }
        thread::sleep(POLL);
    }
}

pub fn stop(dir: &Path) -> Result<Status> {
    if !dir.join(RUNTIME).try_exists()? {
        return Ok(Status::default());
    }
    enter(dir)?;
    let _command = command_lock()?;
    if !owned()? {
        return Ok(Status::default());
    }
    let deadline = Instant::now() + DEADLINE;
    let stopped = request(STOP, DEADLINE).context("node did not confirm clean shutdown")?;
    ensure!(!stopped.running, "node still running");
    while owned()? {
        ensure!(
            Instant::now() < deadline,
            "node still owns the directory after stop"
        );
        thread::sleep(POLL);
    }
    Ok(stopped)
}

pub struct Control {
    pub status: UnixListener,
    pub stop: UnixListener,
}

impl Control {
    fn bind() -> Result<Self> {
        // Only the current node owner may replace sockets left by a crash.
        for path in [STATUS, STOP] {
            match fs::symlink_metadata(path) {
                Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path)?,
                Ok(_) => bail!("unexpected file at {path}"),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Self {
            status: UnixListener::bind(STATUS)?,
            stop: UnixListener::bind(STOP)?,
        })
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        let _ = fs::remove_file(STATUS);
        let _ = fs::remove_file(STOP);
    }
}

pub async fn reply(mut stream: tokio::net::UnixStream, status: &Status) {
    // One bounded reply. A disappearing status client cannot stop the node.
    if let Ok(bytes) = serde_json::to_vec(status) {
        let _ = tokio::time::timeout(Duration::from_millis(500), stream.write_all(&bytes)).await;
    }
}

pub fn serve(dir: &Path) -> Result<()> {
    enter(dir)?;
    let owner = private_file(".runtime/node.lock")?;
    owner.try_lock().context("node directory already in use")?;
    let key = identity(Path::new("."), false)?;
    let config = serde_json::from_slice(&read_bounded(Path::new("node.json"), 16_384)?)
        .context("invalid peer configuration")?;
    let path = std::env::current_dir()?.join("archive.sqlite");
    let archive = Archive::open(&path)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let stopped = runtime.block_on(async {
        let control = Control::bind()?;
        node::run(archive, path, key, config, control).await
    })?;
    drop(runtime);
    let mut client = stopped;
    client.set_nonblocking(false)?;
    client.set_write_timeout(Some(Duration::from_secs(1)))?;
    client.write_all(&serde_json::to_vec(&Status::default())?)?;
    // The OS releases this descriptor on process exit. The stop client waits
    // for that release before it reports success or allows the next start.
    std::mem::forget(owner);
    Ok(())
}
