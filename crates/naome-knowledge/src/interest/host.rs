//! A purpose-specific, UID-private resident model broker; no admission authority.
use super::{Owner, ipc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

const INTERNAL: &str = "--interest-host-v1";
pub(super) const STARTUP: Duration = Duration::from_secs(180);
const MAX_CLIENTS: usize = 16;
const MAX_QUEUE: usize = 8;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Support {
    python: PathBuf,
    model: PathBuf,
}
impl Support {
    pub(super) fn validate(&self) -> Result<(), String> {
        if !self.python.is_absolute() || !self.model.is_absolute() {
            return Err("interest artifact paths must be absolute".into());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Endpoint {
    version: u8,
    pub nonce: String,
    pub contract: String,
}
#[derive(Clone)]
pub(crate) struct State {
    pub generation: String,
    pub ready: Value,
}

pub(super) fn namespace() -> PathBuf {
    PathBuf::from("/tmp").join(format!("naome-interest-uid-{}", nix::unistd::geteuid()))
}
pub(super) fn private_root(root: &Path) -> Result<(), String> {
    match fs::DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.to_string()),
    }
    let m = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != nix::unistd::geteuid().as_raw()
        || m.mode() & 0o777 != 0o700
    {
        return Err("interest namespace ownership or mode differs".into());
    }
    Ok(())
}
fn owned(path: &Path, bytes: Option<&[u8]>) -> Result<File, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(bytes.is_some())
        .truncate(false)
        .mode(0o600)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(|e| e.to_string())?;
    let m = file.metadata().map_err(|e| e.to_string())?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != nix::unistd::geteuid().as_raw()
        || m.mode() & 0o777 != 0o600
    {
        return Err("interest file ownership or mode differs".into());
    }
    if let Some(bytes) = bytes {
        if m.len() == 0 {
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
        } else {
            let mut old = Vec::new();
            (&mut file)
                .take(ipc::LIMIT as u64 + 1)
                .read_to_end(&mut old)
                .map_err(|e| e.to_string())?;
            if old != bytes {
                return Err("installed interest source differs".into());
            }
        }
    }
    Ok(file)
}
pub(super) fn support() -> Result<Support, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = exe
        .parent()
        .ok_or("executable parent absent")?
        .join(".naome-interest.json");
    let value = if path.exists() {
        serde_json::from_slice(&crate::store::read_bounded(&path, 4096)?)
            .map_err(|e| e.to_string())?
    } else {
        let home = std::env::var_os("HOME").ok_or("HOME absent")?;
        let cache = PathBuf::from(home).join(".cache/naome/qwen3-4b");
        Support {
            python: cache.join("backend/bin/python"),
            model: cache.join("model"),
        }
    };
    value.validate()?;
    Ok(value)
}
fn source(root: &Path) -> Result<PathBuf, String> {
    let qwen = include_bytes!("qwen.py");
    let worker = include_bytes!("worker.py");
    let manifest = include_bytes!("model.lock.json");
    let hash = crate::hex(&Sha256::digest(
        [qwen.as_slice(), worker.as_slice(), manifest.as_slice()].concat(),
    ));
    let path = root.join(hash);
    private_root(&path)?;
    for (name, bytes) in [
        ("qwen.py", qwen.as_slice()),
        ("worker.py", worker.as_slice()),
        ("model.lock.json", manifest.as_slice()),
    ] {
        owned(&path.join(name), Some(bytes))?;
    }
    Ok(path)
}
pub(super) fn contract(support: &Support) -> Result<String, String> {
    let value = serde_json::to_vec(&(
        super::QWEN_PROVIDER,
        support,
        crate::hex(&Sha256::digest(include_bytes!("qwen.py"))),
        crate::hex(&Sha256::digest(include_bytes!("worker.py"))),
    ))
    .map_err(|e| e.to_string())?;
    Ok(crate::hex(&Sha256::digest(value)))
}
fn endpoint(root: &Path) -> Result<Endpoint, String> {
    let file = owned(&root.join("endpoint.json"), None)?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 4096 {
        return Err("interest endpoint byte limit".into());
    }
    let e: Endpoint = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    crate::object::id_bytes(&e.nonce)?;
    crate::object::id_bytes(&e.contract)?;
    if e.version != 1 {
        return Err("interest endpoint version differs".into());
    }
    Ok(e)
}
pub(super) fn nonce() -> String {
    crate::hex(&Sha256::digest(
        libp2p::identity::Keypair::generate_ed25519()
            .to_protobuf_encoding()
            .expect("generated key encoding"),
    ))
}
pub(super) fn connect(root: &Path, expected: &str) -> Result<(UnixStream, Endpoint), String> {
    let e = endpoint(root)?;
    if e.contract != expected {
        return Err("live interest model contract differs".into());
    }
    let stream = UnixStream::connect(root.join("host.sock")).map_err(|e| e.to_string())?;
    ipc::peer(&stream)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| e.to_string())?;
    Ok((stream, e))
}
pub(super) fn bootstrap(root: &Path, support: &Support, expected: &str) -> Result<(), String> {
    private_root(root)?;
    let lease = owned(
        &root.join("model.lock"),
        Some(b"naome-interest-host-lease-v1\n"),
    )?;
    match lease.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(()),
        Err(e) => return Err(e.to_string()),
    }
    if connect(root, expected).is_ok() {
        return Err("interest host responded without its global lease".into());
    }
    for path in [root.join("host.sock"), root.join("endpoint.json")] {
        match fs::symlink_metadata(&path) {
            Ok(m) if m.uid() == nix::unistd::geteuid().as_raw() && !m.file_type().is_symlink() => {
                fs::remove_file(path).map_err(|e| e.to_string())?
            }
            Ok(_) => return Err("stale interest endpoint ownership differs".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    let mut cmd = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    cmd.arg(INTERNAL)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = {
        let _guard = crate::jobs::process::SPAWN
            .lock()
            .map_err(|_| "spawn owner poisoned")?;
        nix::fcntl::fcntl(
            &lease,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .map_err(|e| e.to_string())?;
        let result = cmd.spawn();
        let restore = nix::fcntl::fcntl(
            &lease,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        );
        let mut child = result.map_err(|e| e.to_string())?;
        if let Err(e) = restore {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e.to_string());
        }
        child
    };
    let initial = json!({"lease_fd":lease.as_raw_fd(),"support":support,"contract":expected});
    if let Err(e) = serde_json::to_writer(
        child.stdin.as_mut().ok_or("host bootstrap pipe absent")?,
        &initial,
    )
    .and_then(|_| {
        child
            .stdin
            .as_mut()
            .expect("owned pipe")
            .write_all(b"\n")
            .map_err(serde_json::Error::io)
    }) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e.to_string());
    }
    // The helper's global lease remains inherited. Reap its actual Child in a
    // dedicated owner thread, independently of the first node's lifetime.
    drop(child.stdin.take());
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

pub(crate) fn internal(args: &[std::ffi::OsString]) -> Option<Result<(), String>> {
    (args.first().is_some_and(|a| a == INTERNAL)).then(run)
}
struct Query {
    socket: UnixStream,
    client: String,
    value: Value,
    fds: ipc::Fds,
    deadline_ns: u64,
    held: bool,
}
enum Event {
    Attach(String, UnixStream, mpsc::SyncSender<bool>),
    Lost(String),
    Query(Query),
    Model(Value),
    Fault(String),
}
struct Model {
    child: Option<Child>,
    channel: UnixStream,
}
impl Drop for Model {
    fn drop(&mut self) {
        let _ = self.channel.shutdown(std::net::Shutdown::Both);
        let Some(child) = self.child.as_mut() else {
            return;
        };
        drop(child.stdin.take());
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                _ if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
            }
        }
    }
}
fn model(
    support: &Support,
    root: &Path,
    lease_fd: i32,
    events: mpsc::SyncSender<Event>,
) -> Result<Model, String> {
    let path = source(root)?;
    let (channel, child_socket) = UnixStream::pair().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&support.python);
    cmd.arg("-I")
        .arg("-B")
        .arg(path.join("worker.py"))
        .arg("--keeper")
        .arg("--channel-fd")
        .arg(child_socket.as_raw_fd().to_string())
        .arg("--lease-fd")
        .arg(lease_fd.to_string())
        .arg("--model")
        .arg(&support.model)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PYTORCH_ENABLE_MPS_FALLBACK", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = {
        let _guard = crate::jobs::process::SPAWN
            .lock()
            .map_err(|_| "spawn owner poisoned")?;
        nix::fcntl::fcntl(
            &child_socket,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .map_err(|e| e.to_string())?;
        let result = cmd.spawn();
        let restore = nix::fcntl::fcntl(
            &child_socket,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        );
        let mut child = result.map_err(|e| e.to_string())?;
        if let Err(e) = restore {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e.to_string());
        }
        child
    };
    drop(child_socket);
    let mut output = channel.try_clone().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        loop {
            match ipc::receive(&mut output) {
                Ok((v, f)) if f.0.is_empty() => {
                    if events.send(Event::Model(v)).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    let _ = events.send(Event::Fault(e));
                    return;
                }
                _ => {
                    let _ = events.send(Event::Fault("model ancillary response differs".into()));
                    return;
                }
            }
        }
    });
    Ok(Model {
        child: Some(child),
        channel,
    })
}
fn run() -> Result<(), String> {
    nix::unistd::setsid().map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 4096 {
        return Err("host bootstrap limit".into());
    }
    let initial: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let support: Support =
        serde_json::from_value(initial["support"].clone()).map_err(|e| e.to_string())?;
    let lease_fd = initial["lease_fd"]
        .as_i64()
        .and_then(|x| i32::try_from(x).ok())
        .ok_or("host lease descriptor absent")?;
    let expected = contract(&support)?;
    if initial["contract"] != expected {
        return Err("host contract differs".into());
    }
    let root = namespace();
    private_root(&root)?;
    let listener = UnixListener::bind(root.join("host.sock")).map_err(|e| e.to_string())?;
    fs::set_permissions(root.join("host.sock"), fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    let generation = nonce();
    let endpoint = Endpoint {
        version: 1,
        nonce: generation.clone(),
        contract: expected.clone(),
    };
    let encoded = serde_json::to_vec(&endpoint).map_err(|e| e.to_string())?;
    owned(&root.join("endpoint.json"), Some(&encoded))?;
    let (sender, receiver) = mpsc::sync_channel(64);
    let accept = sender.clone();
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let nonce = generation.clone();
    let contract = expected.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut socket) = incoming else {
                return;
            };
            if connections.fetch_add(1, std::sync::atomic::Ordering::AcqRel) >= 48 {
                connections.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                continue;
            }
            let connections = connections.clone();
            let sender = accept.clone();
            let nonce = nonce.clone();
            let contract = contract.clone();
            std::thread::spawn(move || {
                let result = (|| {
                    ipc::peer(&socket)?;
                    socket
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .map_err(|e| e.to_string())?;
                    socket
                        .set_write_timeout(Some(Duration::from_secs(1)))
                        .map_err(|e| e.to_string())?;
                    let (value, fds) = ipc::receive(&mut socket)?;
                    if value["nonce"] != nonce || value["contract"] != contract {
                        return Err("interest authentication differs".into());
                    }
                    let client = value["client"]
                        .as_str()
                        .ok_or("interest client absent")?
                        .to_owned();
                    crate::object::id_bytes(&client)?;
                    if value["kind"] == "attach" && fds.0.is_empty() {
                        let (accepted, confirmation) = mpsc::sync_channel(1);
                        sender
                            .send(Event::Attach(
                                client.clone(),
                                socket.try_clone().map_err(|e| e.to_string())?,
                                accepted,
                            ))
                            .map_err(|e| e.to_string())?;
                        if !confirmation
                            .recv_timeout(Duration::from_secs(2))
                            .unwrap_or(false)
                        {
                            return Ok(());
                        }
                        socket.set_read_timeout(None).map_err(|e| e.to_string())?;
                        let mut byte = [0];
                        let _ = socket.read(&mut byte);
                        let _ = sender.send(Event::Lost(client));
                    } else if value["kind"] == "query" && fds.0.len() == 1 {
                        let now = crate::jobs::monotonic_ns()?;
                        let deadline_ns = value["deadline_ns"]
                            .as_u64()
                            .filter(|end| *end > now && end.saturating_sub(now) <= 20_000_000_000)
                            .ok_or("interest original deadline differs")?;
                        sender
                            .try_send(Event::Query(Query {
                                socket,
                                client,
                                value,
                                fds,
                                deadline_ns,
                                held: false,
                            }))
                            .map_err(|e| e.to_string())?;
                    } else {
                        return Err("interest connection role or lease differs".into());
                    }
                    Ok::<_, String>(())
                })();
                connections.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                if let Err(e) = result {
                    crate::network::emit(json!({"event":"interest_connection_rejected","error":e}));
                }
            });
        }
    });
    let model = model(&support, &root, lease_fd, sender)?;
    serve(model, receiver, generation, expected)
}

fn serve(
    mut model: Model,
    receiver: mpsc::Receiver<Event>,
    generation: String,
    expected: String,
) -> Result<(), String> {
    let start = Instant::now();
    let mut clients = BTreeMap::<String, UnixStream>::new();
    let mut queues = BTreeMap::<String, VecDeque<Query>>::new();
    let mut ready = None;
    let mut active: Option<Query> = None;
    let mut last = None;
    let mut ever_attached = false;
    loop {
        if !ever_attached && start.elapsed() > Duration::from_secs(5) {
            break;
        }
        if ready.is_none() && start.elapsed() > STARTUP {
            return Err("resident model startup deadline".into());
        }
        let now_ns = crate::jobs::monotonic_ns()?;
        if active.as_ref().is_some_and(|q| now_ns >= q.deadline_ns) {
            return Err("resident model query deadline; terminate before replacement".into());
        }
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok(Event::Attach(client, mut socket, accepted)) => {
                if clients.len() >= MAX_CLIENTS || clients.contains_key(&client) {
                    let _ = accepted.send(false);
                    continue;
                }
                if ipc::send(&mut socket, &json!({"kind":"attached"}), None).is_err()
                    || ready
                        .as_ref()
                        .is_some_and(|value| ipc::send(&mut socket, value, None).is_err())
                {
                    let _ = accepted.send(false);
                    continue;
                }
                clients.insert(client.clone(), socket);
                queues.insert(client, VecDeque::new());
                ever_attached = true;
                let _ = accepted.send(true);
            }
            Ok(Event::Lost(client)) => {
                clients.remove(&client);
                queues.remove(&client);
                if let Some(q) = &active
                    && q.client == client
                {
                    let _ = q.socket.shutdown(std::net::Shutdown::Both);
                }
                if clients.is_empty() && ever_attached {
                    break;
                }
            }
            Ok(Event::Query(query)) => {
                if ready.is_none() || !clients.contains_key(&query.client) {
                    continue;
                }
                let queue = queues.get_mut(&query.client).expect("live queue");
                if queue.len() < MAX_QUEUE {
                    queue.push_back(query);
                }
            }
            Ok(Event::Model(value)) => match value["kind"].as_str() {
                Some("ready") => {
                    super::proxy::validate_ready(&value)?;
                    let mut value = value;
                    value["generation"] = json!(generation);
                    value["contract"] = json!(expected);
                    for socket in clients.values_mut() {
                        let _ = ipc::send(socket, &value, None);
                    }
                    ready = Some(value);
                }
                Some("decision") | Some("declined") => {
                    let Some(mut query) = active.take() else {
                        return Err("unsolicited model decision".into());
                    };
                    if !query.held || value["transport_id"] != query.value["transport_id"] {
                        return Err("model transport identity differs".into());
                    }
                    if clients.contains_key(&query.client)
                        && crate::jobs::monotonic_ns()? < query.deadline_ns
                    {
                        let mut response = value;
                        response["generation"] = json!(generation);
                        // A cancelled proxy cannot tear down another node's resident model.
                        let _ = ipc::send(&mut query.socket, &response, None);
                    }
                }
                Some("lease_held") => {
                    let query = active
                        .as_mut()
                        .ok_or("unsolicited model lease acknowledgement")?;
                    if query.held || query.value["transport_id"] != value["transport_id"] {
                        return Err("model lease acknowledgement differs".into());
                    }
                    query.held = true;
                }
                Some("failed") => {
                    for socket in clients.values_mut() {
                        let _ = ipc::send(socket, &value, None);
                    }
                    return Err(format!("resident model failed: {value}"));
                }
                Some("stage") | Some("telemetry") => {
                    let mut metric = value;
                    metric["generation"] = json!(generation);
                    clients.retain(|_, socket| ipc::send(socket, &metric, None).is_ok());
                    queues.retain(|client, _| clients.contains_key(client));
                    if clients.is_empty() && ever_attached {
                        break;
                    }
                }
                _ => return Err("resident model failure or unsupported frame".into()),
            },
            Ok(Event::Fault(error)) => return Err(error),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(e) => return Err(e.to_string()),
        }
        if ready.is_some() && active.is_none() {
            let keys = queues.keys().cloned().collect::<Vec<_>>();
            let offset = last
                .as_ref()
                .and_then(|last| keys.iter().position(|x| x == last))
                .map_or(0, |x| (x + 1) % keys.len().max(1));
            for n in 0..keys.len() {
                let key = &keys[(offset + n) % keys.len()];
                let queue = queues.get_mut(key).expect("queue owner");
                while queue.front().is_some_and(|q| now_ns >= q.deadline_ns) {
                    queue.pop_front();
                }
                if let Some(mut query) = queue.pop_front() {
                    let mut peek = [0u8; 1];
                    match nix::sys::socket::recv(
                        query.socket.as_raw_fd(),
                        &mut peek,
                        nix::sys::socket::MsgFlags::MSG_PEEK
                            | nix::sys::socket::MsgFlags::MSG_DONTWAIT,
                    ) {
                        Ok(_) => continue,
                        Err(nix::errno::Errno::EAGAIN) => {}
                        Err(_) => continue,
                    }
                    query.value["remaining_ms"] = json!(
                        query
                            .deadline_ns
                            .saturating_sub(crate::jobs::monotonic_ns()?)
                            / 1_000_000
                    );
                    ipc::send(
                        &mut model.channel,
                        &query.value,
                        Some(query.fds.0[0].as_raw_fd()),
                    )?;
                    last = Some(key.clone());
                    active = Some(query);
                    break;
                }
            }
        }
    }
    drop(model);
    Ok(())
}

pub(super) fn query_connection() -> Result<(UnixStream, Endpoint), String> {
    let s = support()?;
    connect(&namespace(), &contract(&s)?)
}
pub(crate) fn selection(owner: &Owner, state: &State) -> Result<[u8; 32], String> {
    let bytes = serde_json::to_vec(&(super::QWEN_PROVIDER, owner, &state.generation, &state.ready))
        .map_err(|e| e.to_string())?;
    Ok(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use super::super::client::receive_live;
    use super::*;
    use std::{os::unix::fs::OpenOptionsExt, thread::JoinHandle};
    fn ready() -> Value {
        json!({"kind":"ready","schema":1,"model_revision":"1cfa9a7208912126459214e8b04321603b3df60c","manifest_hash":"b7d4ab43f8cfc348ff7195e64a5e23fb65ceb0eec55a1761030ac1e9478b018b","prompt_version":"naome:owner-interest:prompt:v1","prompt_hash":"69afc1b7c184eeb83ed7faa55d7fdcfbc67949f0ed10b0c138eaaf0ff5403f98","template_hash":"a55ee1b1660128b7098723e0abcd92caa0788061051c62d51cbe87d9cf1974d8","device":"mps","load_strategy":"cpu-staged-mps-v1","parameter_bytes":8044936192u64,"labels":{"true":1866,"false":3849},"inventory_hash":crate::hex(&[4;32]),"model_instance":1})
    }
    fn broker() -> (
        mpsc::SyncSender<Event>,
        UnixStream,
        JoinHandle<Result<(), String>>,
    ) {
        let (sender, receiver) = mpsc::sync_channel(64);
        let (channel, worker) = UnixStream::pair().unwrap();
        worker
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let handle = std::thread::spawn(move || {
            serve(
                Model {
                    child: None,
                    channel,
                },
                receiver,
                crate::hex(&[5; 32]),
                crate::hex(&[6; 32]),
            )
        });
        sender.send(Event::Model(ready())).unwrap();
        (sender, worker, handle)
    }
    fn attach(sender: &mpsc::SyncSender<Event>, id: u8) -> UnixStream {
        let (socket, mut client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (accepted, confirmation) = mpsc::sync_channel(1);
        sender
            .send(Event::Attach(crate::hex(&[id; 32]), socket, accepted))
            .unwrap();
        assert!(confirmation.recv_timeout(Duration::from_secs(2)).unwrap());
        assert_eq!(
            receive_live(&mut client).unwrap().unwrap()["kind"],
            "attached"
        );
        assert_eq!(receive_live(&mut client).unwrap().unwrap()["kind"], "ready");
        client
    }
    fn query(
        sender: &mpsc::SyncSender<Event>,
        id: u8,
        request: u8,
        deadline_ns: u64,
    ) -> (UnixStream, PathBuf) {
        let path = PathBuf::from("/tmp").join(format!(
            "naome-host-test-{}-{}-{request}",
            std::process::id(),
            crate::jobs::monotonic_ns().unwrap()
        ));
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        lease.try_lock().unwrap();
        let (mut borrowed, mut server) = UnixStream::pair().unwrap();
        let value = json!({"kind":"query","client":crate::hex(&[id;32]),"transport_id":crate::hex(&[request;32]),"deadline_ns":deadline_ns,"remaining_ms":20000});
        ipc::send(&mut borrowed, &value, Some(lease.as_raw_fd())).unwrap();
        let (value, fds) = ipc::receive(&mut server).unwrap();
        drop(lease);
        let (socket, client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        sender
            .send(Event::Query(Query {
                socket,
                client: crate::hex(&[id; 32]),
                value,
                fds,
                deadline_ns,
                held: false,
            }))
            .unwrap();
        (client, path)
    }
    fn finish(sender: &mpsc::SyncSender<Event>, value: &Value) {
        sender
            .send(Event::Model(
                json!({"kind":"lease_held","transport_id":value["transport_id"]}),
            ))
            .unwrap();
        sender
            .send(Event::Model(
                json!({"kind":"decision","transport_id":value["transport_id"],"selected":false}),
            ))
            .unwrap();
    }
    #[test]
    fn closed_query_and_closed_new_attachment_do_not_stop_another_client() {
        let (sender, mut worker, handle) = broker();
        let _a = attach(&sender, 1);
        let (socket, b) = UnixStream::pair().unwrap();
        drop(b);
        let (accepted, confirmation) = mpsc::sync_channel(1);
        sender
            .send(Event::Attach(crate::hex(&[2; 32]), socket, accepted))
            .unwrap();
        assert!(!confirmation.recv_timeout(Duration::from_secs(2)).unwrap());
        let (query_a, path_a) = query(
            &sender,
            1,
            10,
            crate::jobs::monotonic_ns().unwrap() + 20_000_000_000,
        );
        let (value, held) = ipc::receive(&mut worker).unwrap();
        assert_eq!(held.0.len(), 1);
        drop(query_a);
        drop(held);
        finish(&sender, &value);
        let _c = attach(&sender, 3);
        let (mut query_c, path_c) = query(
            &sender,
            3,
            11,
            crate::jobs::monotonic_ns().unwrap() + 20_000_000_000,
        );
        let (value, held) = ipc::receive(&mut worker).unwrap();
        assert_eq!(held.0.len(), 1);
        drop(held);
        finish(&sender, &value);
        assert_eq!(
            receive_live(&mut query_c).unwrap().unwrap()["kind"],
            "decision"
        );
        sender.send(Event::Lost(crate::hex(&[1; 32]))).unwrap();
        sender.send(Event::Lost(crate::hex(&[3; 32]))).unwrap();
        handle.join().unwrap().unwrap();
        for path in [path_a, path_c] {
            let probe = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            probe.try_lock().unwrap();
            drop(probe);
            std::fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn expired_queued_deadline_never_receives_fresh_forward_window() {
        let (sender, mut worker, handle) = broker();
        let _a = attach(&sender, 1);
        let _b = attach(&sender, 2);
        let (_first, path_a) = query(
            &sender,
            1,
            10,
            crate::jobs::monotonic_ns().unwrap() + 20_000_000_000,
        );
        let (value, held) = ipc::receive(&mut worker).unwrap();
        let (expired, path_b) = query(
            &sender,
            2,
            11,
            crate::jobs::monotonic_ns().unwrap() + 10_000_000,
        );
        std::thread::sleep(Duration::from_millis(20));
        drop(held);
        finish(&sender, &value);
        worker
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        assert!(ipc::receive(&mut worker).is_err());
        drop(expired);
        sender.send(Event::Lost(crate::hex(&[1; 32]))).unwrap();
        sender.send(Event::Lost(crate::hex(&[2; 32]))).unwrap();
        handle.join().unwrap().unwrap();
        for path in [path_a, path_b] {
            let probe = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            probe.try_lock().unwrap();
            drop(probe);
            std::fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn live_channel_discards_ancillary_without_installing_node_fds() {
        use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
        use std::io::IoSlice;
        let path = PathBuf::from("/tmp").join(format!(
            "naome-live-nofd-{}-{}",
            std::process::id(),
            crate::jobs::monotonic_ns().unwrap()
        ));
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        lease.try_lock().unwrap();
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        let data = [0u8, 0, 0, 2, b'{', b'}'];
        let fds = vec![lease.as_raw_fd(); 32];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(&data)],
            &[ControlMessage::ScmRights(&fds)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(lease);
        assert_eq!(receive_live(&mut receiver).unwrap(), Some(json!({})));
        probe.try_lock().unwrap();
        drop(probe);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn partial_live_frame_is_rejected_without_reinterpreting_remaining_bytes() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        assert_eq!(receive_live(&mut receiver).unwrap(), None);
        sender.write_all(&[0]).unwrap();
        assert!(receive_live(&mut receiver).is_err());
    }
}
