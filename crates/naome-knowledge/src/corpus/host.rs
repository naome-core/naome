//! One killable CPU encoder, with an inherited physical lease and EOF watchdog.
use super::{
    cache::Settings,
    local::{ChunkCoverage, EmbeddedChunk, LocalEncoder, PreparedDocument},
    semantic::EncoderIdentity,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, Read, Write},
    os::{
        fd::{AsFd, AsRawFd},
        unix::{fs::MetadataExt, process::CommandExt},
    },
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const ARG: &str = "--retrieval-worker-v1";
const INTERNAL: &str = "NAOME_INTERNAL_RETRIEVAL";
const MAX_FRAME: usize = 2 * 1024 * 1024;

pub(super) struct StartFailure {
    pub message: String,
    pub cleanup_uncertain: bool,
}
impl From<String> for StartFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            cleanup_uncertain: false,
        }
    }
}
impl From<&str> for StartFailure {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Load {
        settings: Settings,
        lease_fd: i32,
        lease_dev: u64,
        lease_ino: u64,
    },
    Prepare {
        job: u64,
        input: String,
    },
    Chunk {
        job: u64,
        position: usize,
    },
    Query {
        query: String,
    },
    Forget {
        job: u64,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    sequence: u32,
    quantum_ms: u64,
    expires_monotonic_ns: u64,
    operation: Operation,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    sequence: u32,
    result: Result<Value, String>,
    encoder: EncoderIdentity,
    working_bytes: u64,
}

pub(super) struct Host {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
    lease: File,
    sequence: u32,
    buffer: Vec<u8>,
    settings: Settings,
    finished: bool,
    observation_uncertain: Option<String>,
}
impl Host {
    pub fn start(
        settings: Settings,
        lease: File,
        stopped: &dyn Fn() -> bool,
        scope_deadline: Instant,
    ) -> Result<Self, StartFailure> {
        settings.validate()?;
        if stopped() {
            return Err("retrieval cancelled before model host spawn".into());
        }
        let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
        command
            .arg(ARG)
            .env_clear()
            .env(INTERNAL, "worker-v1")
            .env("RAYON_NUM_THREADS", "1")
            .env("TOKENIZERS_PARALLELISM", "false")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        let metadata = lease.metadata().map_err(|e| e.to_string())?;
        let (spawned, restored) = {
            let _guard = crate::jobs::SPAWN
                .lock()
                .map_err(|_| "retrieval spawn owner poisoned")?;
            nix::fcntl::fcntl(
                &lease,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
            )
            .map_err(|e| e.to_string())?;
            let child = command.spawn();
            let restored = nix::fcntl::fcntl(
                &lease,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
            );
            (child, restored)
        };
        let mut child = spawned.map_err(|e| format!("retrieval host spawn: {e}"))?;
        let input = child
            .stdin
            .take()
            .expect("spawned piped retrieval lifeline");
        let output = child.stdout.take().expect("spawned piped retrieval output");
        let mut host = Self {
            child,
            input: Some(input),
            output,
            lease,
            sequence: 0,
            buffer: Vec::new(),
            settings: settings.clone(),
            finished: false,
            observation_uncertain: None,
        };
        let initialize = (|| {
            restored
                .map_err(|error| format!("retrieval lease inheritance restoration: {error}"))?;
            for fd in [
                host.input.as_ref().expect("owned lifeline").as_fd(),
                host.output.as_fd(),
            ] {
                let old = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL)
                    .map_err(|e| e.to_string())?;
                nix::fcntl::fcntl(
                    fd,
                    nix::fcntl::FcntlArg::F_SETFL(
                        nix::fcntl::OFlag::from_bits_truncate(old) | nix::fcntl::OFlag::O_NONBLOCK,
                    ),
                )
                .map_err(|e| e.to_string())?;
            }
            crate::network::emit(
                json!({"event":"retrieval_host_started","pid":host.child.id(),"encoder":LocalEncoder::identity_specification(),"quantum_ms":settings.quantum_ms,"memory_bytes":settings.memory_bytes}),
            );
            let value = host.call(
                Operation::Load {
                    settings,
                    lease_fd: host.lease.as_raw_fd(),
                    lease_dev: metadata.dev(),
                    lease_ino: metadata.ino(),
                },
                stopped,
                scope_deadline,
            )?;
            if value["loaded"] != true {
                return Err("retrieval host readiness differs".into());
            }
            Ok::<(), String>(())
        })();
        if let Err(message) = initialize {
            return Err(match host.finish() {
                Ok(()) => StartFailure {
                    message,
                    cleanup_uncertain: false,
                },
                Err(cleanup) => StartFailure {
                    message: format!("{message}; retrieval initialization cleanup: {cleanup}"),
                    cleanup_uncertain: true,
                },
            });
        }
        Ok(host)
    }
    pub fn call(
        &mut self,
        operation: Operation,
        stopped: &dyn Fn() -> bool,
        scope_deadline: Instant,
    ) -> Result<Value, String> {
        if self.finished || stopped() {
            return Err("retrieval host cancelled or closed".into());
        }
        // Capture the shared clock before measuring the original remaining
        // scope. Serialization, pipe delay or wall-clock changes cannot renew it.
        let origin_ns = monotonic_ns()?;
        let quantum_ms = u64::try_from(
            scope_deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
        .min(self.settings.quantum_ms);
        if quantum_ms < 100 {
            return Err("retrieval original scope has no complete quantum remaining".into());
        }
        let deadline = Instant::now() + Duration::from_millis(quantum_ms);
        let packet = Packet {
            sequence: self.sequence,
            quantum_ms,
            expires_monotonic_ns: origin_ns
                .checked_add(quantum_ms * 1_000_000)
                .ok_or("retrieval scope clock overflow")?,
            operation,
        };
        let mut bytes = serde_json::to_vec(&packet).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        if bytes.len() > MAX_FRAME {
            return Err("retrieval host input frame capacity".into());
        }
        let mut offset = 0;
        while offset < bytes.len() {
            self.alive(stopped, deadline)?;
            match self
                .input
                .as_mut()
                .ok_or("retrieval lifeline closed")?
                .write(&bytes[offset..])
            {
                Ok(0) => return Err("retrieval lifeline write closed".into()),
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        let mut last_observation = Instant::now();
        loop {
            self.alive(stopped, deadline)?;
            if last_observation.elapsed() >= Duration::from_millis(250) {
                let rss = resident_bytes(self.child.id()).map_err(|failure| {
                    if failure.cleanup_uncertain {
                        self.observation_uncertain = Some(failure.message.clone());
                    }
                    failure.message
                })?;
                if rss > self.settings.memory_bytes {
                    return Err("retrieval host working memory limit exceeded".into());
                }
                last_observation = Instant::now();
            }
            let mut chunk = [0u8; 8192];
            match self.output.read(&mut chunk) {
                Ok(0) => return Err("retrieval host ended before reply".into()),
                Ok(count) => self.buffer.extend_from_slice(&chunk[..count]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(e) => return Err(e.to_string()),
            }
            if self.buffer.len() > MAX_FRAME {
                return Err("retrieval host output frame capacity".into());
            }
            if let Some(end) = self.buffer.iter().position(|b| *b == b'\n') {
                let frame: Vec<_> = self.buffer.drain(..=end).collect();
                let reply: Reply = serde_json::from_slice(&frame)
                    .map_err(|_| "retrieval host reply corruption")?;
                if reply.sequence != self.sequence
                    || reply.encoder != LocalEncoder::identity_specification()
                    || reply.working_bytes > self.settings.memory_bytes
                {
                    return Err("retrieval host reply identity or memory differs".into());
                }
                self.sequence = self
                    .sequence
                    .checked_add(1)
                    .ok_or("retrieval host sequence overflow")?;
                crate::network::emit(
                    json!({"event":"retrieval_quantum_finished","pid":self.child.id(),"sequence":reply.sequence,"working_bytes":reply.working_bytes,"encoder":reply.encoder}),
                );
                return reply.result;
            }
        }
    }
    fn alive(&self, stopped: &dyn Fn() -> bool, deadline: Instant) -> Result<(), String> {
        if stopped() {
            return Err("retrieval computation cancelled".into());
        }
        if Instant::now() >= deadline {
            return Err("retrieval computation deadline expired".into());
        }
        Ok(())
    }
    pub fn prepare(
        &mut self,
        job: u64,
        input: String,
        stopped: &dyn Fn() -> bool,
        deadline: Instant,
    ) -> Result<Vec<ChunkCoverage>, String> {
        serde_json::from_value(self.call(Operation::Prepare { job, input }, stopped, deadline)?)
            .map_err(|e| e.to_string())
    }
    pub fn chunk(
        &mut self,
        job: u64,
        position: usize,
        stopped: &dyn Fn() -> bool,
        deadline: Instant,
    ) -> Result<EmbeddedChunk, String> {
        serde_json::from_value(self.call(Operation::Chunk { job, position }, stopped, deadline)?)
            .map_err(|e| e.to_string())
    }
    pub fn query(
        &mut self,
        query: String,
        stopped: &dyn Fn() -> bool,
        deadline: Instant,
    ) -> Result<Vec<f32>, String> {
        serde_json::from_value(self.call(Operation::Query { query }, stopped, deadline)?)
            .map_err(|e| e.to_string())
    }
    pub fn finish(&mut self) -> Result<(), String> {
        if self.finished {
            return self.observation_uncertain.clone().map_or(Ok(()), Err);
        }
        drop(self.input.take());
        // Retain the unreaped positive Child identity through group termination.
        let pid = nix::unistd::Pid::from_raw(
            i32::try_from(self.child.id()).map_err(|_| "retrieval pid capacity")?,
        );
        match nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH | nix::errno::Errno::EPERM) => {}
            Err(e) => return Err(format!("retrieval group cleanup: {e}")),
        }
        // No further signal uses this numeric group after the owned leader is
        // reaped. A denied or persistent group query never confirms cleanup.
        let deadline = Instant::now() + Duration::from_secs(2);
        let status = loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|e| format!("retrieval reap: {e}"))?
            {
                break status;
            }
            if Instant::now() >= deadline {
                return Err("retrieval owned leader reap deadline".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        // The leader has been reaped. Mark this before querying descendants so
        // Drop never signals a reused leader identity on an uncertain result.
        self.finished = true;
        loop {
            match nix::sys::signal::killpg(pid, None) {
                Err(nix::errno::Errno::ESRCH) => break,
                Ok(()) | Err(nix::errno::Errno::EPERM) => {}
                Err(error) => return Err(format!("retrieval group absence query: {error}")),
            }
            if Instant::now() >= deadline {
                return Err("retrieval group absence is unconfirmed".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        crate::network::emit(
            json!({"event":"retrieval_host_reaped","pid":pid.as_raw(),"status":status.code(),"group_absent":true,"encoder":LocalEncoder::identity_specification()}),
        );
        self.observation_uncertain.clone().map_or(Ok(()), Err)
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            crate::network::emit(json!({"event":"retrieval_cleanup_failed","error":error}));
        }
    }
}

/// RSS is an observation, not an inference about free system memory.
fn resident_bytes(pid: u32) -> Result<u64, StartFailure> {
    #[cfg(target_os = "linux")]
    {
        let data =
            std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| e.to_string())?;
        let kb = data
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .ok_or("retrieval RSS is unavailable")?
            .split_whitespace()
            .next()
            .ok_or("retrieval RSS value is unavailable")?
            .parse::<u64>()
            .map_err(|e| e.to_string())?;
        kb.checked_mul(1024)
            .ok_or_else(|| "retrieval RSS overflow".into())
    }
    #[cfg(target_os = "macos")]
    {
        let mut child = Command::new("/bin/ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_millis(200);
        loop {
            let status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    return Err(finish_rss_helper(
                        &mut child,
                        &format!("retrieval RSS observation poll failed: {error}"),
                    ));
                }
            };
            if let Some(status) = status {
                if !status.success() {
                    return Err("retrieval RSS observation failed".into());
                }
                let mut bytes = String::new();
                child
                    .stdout
                    .take()
                    .ok_or("retrieval RSS output missing")?
                    .take(128)
                    .read_to_string(&mut bytes)
                    .map_err(|e| e.to_string())?;
                let kb = bytes
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| "retrieval RSS value differs")?;
                return kb
                    .checked_mul(1024)
                    .ok_or_else(|| "retrieval RSS overflow".into());
            }
            if Instant::now() >= deadline {
                return Err(finish_rss_helper(
                    &mut child,
                    "retrieval RSS observation deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        Err("retrieval memory observation platform is unsupported".into())
    }
}

#[cfg(target_os = "macos")]
fn finish_rss_helper(child: &mut Child, reason: &str) -> StartFailure {
    // One owned ps child has no model work or descendants. Retain its unreaped
    // identity through the last kill on both timeout and observation failure.
    let kill = child.kill();
    let reap_deadline = Instant::now() + Duration::from_millis(200);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return format!("{reason}; owned helper reaped").into(),
            Ok(None) if Instant::now() < reap_deadline => {
                std::thread::sleep(Duration::from_millis(2))
            }
            result => {
                return StartFailure {
                    message: format!(
                        "{reason}; retrieval RSS helper cleanup is unconfirmed: kill={kill:?}, reap={result:?}"
                    ),
                    cleanup_uncertain: true,
                };
            }
        }
    }
}

pub(crate) fn internal(arguments: &[std::ffi::OsString]) -> Option<Result<(), String>> {
    if arguments.first().is_none_or(|arg| arg != ARG) {
        return None;
    }
    Some(
        if arguments.len() == 1 && std::env::var(INTERNAL).as_deref() == Ok("worker-v1") {
            worker()
        } else {
            Err("internal retrieval invocation required".into())
        },
    )
}
fn worker() -> Result<(), String> {
    if nix::unistd::getpgrp() != nix::unistd::getpid() {
        return Err("retrieval worker must own its positive process group".into());
    }
    let initial_deadline = monotonic_ns()?
        .checked_add(2_000_000_000)
        .ok_or("retrieval startup clock overflow")?;
    let deadline = Arc::new(AtomicU64::new(initial_deadline));
    let watchdog = deadline.clone();
    std::thread::spawn(move || {
        loop {
            match monotonic_ns() {
                Ok(now) if now < watchdog.load(Ordering::Acquire) => {}
                _ => abort_owned_group(),
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut input = std::io::BufReader::new(std::io::stdin());
        loop {
            let mut bytes = Vec::new();
            let count = Read::by_ref(&mut input)
                .take((MAX_FRAME + 1) as u64)
                .read_until(b'\n', &mut bytes);
            let packet: Packet = match count {
                Ok(n) if n > 0 && n <= MAX_FRAME && bytes.last() == Some(&b'\n') => {
                    match serde_json::from_slice(&bytes) {
                        Ok(packet) => packet,
                        Err(_) => abort_owned_group(),
                    }
                }
                _ => abort_owned_group(),
            };
            if !(100..=30_000).contains(&packet.quantum_ms) {
                abort_owned_group();
            }
            // EOF/overflow remains observable while work or stdout blocks.
            // An arriving packet cannot extend another operation's deadline.
            if sender.try_send(packet).is_err() {
                abort_owned_group();
            }
        }
    });
    let mut model = None;
    let mut documents: BTreeMap<u64, PreparedDocument> = BTreeMap::new();
    let mut sequence = 0;
    for packet in receiver {
        if packet.sequence != sequence {
            return Err("retrieval input sequence differs".into());
        }
        let now = monotonic_ns()?;
        let end = packet.expires_monotonic_ns.min(
            now.checked_add(packet.quantum_ms * 1_000_000)
                .ok_or("retrieval quantum clock overflow")?,
        );
        if now >= end {
            return Err("retrieval received expired original quantum".into());
        }
        deadline.store(end, Ordering::Release);
        let result = (|| match packet.operation {
            Operation::Load {
                settings,
                lease_fd,
                lease_dev,
                lease_ino,
            } => {
                if model.is_some() {
                    return Err("retrieval model is already loaded".into());
                }
                settings.validate()?;
                let metadata =
                    std::fs::metadata(format!("/dev/fd/{lease_fd}")).map_err(|e| e.to_string())?;
                if !metadata.is_file()
                    || metadata.dev() != lease_dev
                    || metadata.ino() != lease_ino
                    || metadata.nlink() != 1
                    || metadata.uid() != nix::unistd::geteuid().as_raw()
                {
                    return Err("retrieval inherited physical lease differs".into());
                }
                model = Some(LocalEncoder::load(&settings.model_directory)?);
                Ok(json!({"loaded":true}))
            }
            Operation::Prepare { job, input } => {
                if job == 0 || (!documents.contains_key(&job) && documents.len() >= 8) {
                    return Err("retrieval prepared document capacity".into());
                }
                let prepared = model
                    .as_ref()
                    .ok_or("retrieval model not loaded")?
                    .prepare_document(&input)?;
                let layout = serde_json::to_value(&prepared.coverage).map_err(|e| e.to_string())?;
                documents.insert(job, prepared);
                Ok(layout)
            }
            Operation::Chunk { job, position } => {
                let prepared = documents
                    .get(&job)
                    .ok_or("retrieval prepared document is absent")?;
                serde_json::to_value(
                    model
                        .as_ref()
                        .ok_or("retrieval model not loaded")?
                        .encode_prepared(prepared, position)?,
                )
                .map_err(|e| e.to_string())
            }
            Operation::Query { query } => serde_json::to_value(
                model
                    .as_mut()
                    .ok_or("retrieval model not loaded")?
                    .query(&query)?,
            )
            .map_err(|e| e.to_string()),
            Operation::Forget { job } => {
                documents.remove(&job);
                Ok(json!({"forgotten":true}))
            }
        })();
        let working_bytes = resident_bytes(std::process::id()).map_err(|failure| {
            if failure.cleanup_uncertain {
                abort_owned_group();
            }
            failure.message
        })?;
        let bytes = serde_json::to_vec(&Reply {
            sequence,
            result,
            encoder: LocalEncoder::identity_specification(),
            working_bytes,
        })
        .map_err(|e| e.to_string())?;
        if bytes.len() > MAX_FRAME {
            return Err("retrieval reply byte limit".into());
        }
        // The reader remains independent while model execution or output blocks.
        // Only a complete response retires this operation's hard deadline.
        std::io::stdout()
            .write_all(&bytes)
            .and_then(|_| std::io::stdout().write_all(b"\n"))
            .and_then(|_| std::io::stdout().flush())
            .map_err(|e| e.to_string())?;
        deadline.store(u64::MAX, Ordering::Release);
        sequence = sequence
            .checked_add(1)
            .ok_or("retrieval sequence overflow")?;
    }
    Ok(())
}

/// Same-host process deadlines share this kernel clock and never use UTC.
fn monotonic_ns() -> Result<u64, String> {
    let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .map_err(|e| format!("retrieval monotonic clock: {e}"))?;
    let seconds = u64::try_from(time.tv_sec()).map_err(|_| "retrieval negative clock")?;
    let nanos = u64::try_from(time.tv_nsec()).map_err(|_| "retrieval negative nanoseconds")?;
    if nanos >= 1_000_000_000 {
        return Err("retrieval clock nanoseconds differ".into());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos))
        .ok_or_else(|| "retrieval monotonic clock overflow".into())
}

fn abort_owned_group() -> ! {
    // This executing process is still the unreaped, positive group leader.
    let _ = nix::sys::signal::killpg(nix::unistd::getpid(), nix::sys::signal::Signal::SIGKILL);
    std::process::exit(2)
}
