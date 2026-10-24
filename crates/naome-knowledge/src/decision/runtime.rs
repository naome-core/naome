//! One explicitly owned, reusable model process. Scheduling stays with its caller.
use super::{Distribution, Request};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufRead, Write},
    os::fd::AsRawFd,
    process::{Command, Stdio},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::{Mutex, oneshot},
};

const INTERNAL: &str = "--decision-supervisor-v1";
const WORKER: &str = "--decision-worker-v1";
const CAPACITY: usize = 256 * 1024;

/// A concrete adapter prepares one process speaking this module's bounded
/// protocol. The shared access owns custody, not model-specific loading code.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Backend {
    pub identity: String,
    pub executable: std::path::PathBuf,
    pub arguments: Vec<String>,
    pub environment: std::collections::BTreeMap<String, String>,
    pub initialization: serde_json::Value,
    pub memory_bytes: u64,
    pub threads: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    backend: Backend,
    slot_fd: i32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    sequence: u64,
    request: String,
    input: Request,
    deadline_ns: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Frame {
    Started {
        pid: u32,
    },
    Ready {
        model: String,
        pid: u32,
        runtime: std::collections::BTreeMap<String, String>,
    },
    Answer {
        sequence: u64,
        distribution: Distribution,
    },
    Error {
        sequence: u64,
        code: ErrorCode,
        error: String,
    },
    Cleanup {
        error: Option<String>,
    },
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrorCode {
    Failed,
    TimedOut,
}

/// Clones share this exact runtime, with no additional queue or model instance.
/// Admission, deadlines and durable allowances remain with the job owner.
#[derive(Clone)]
pub(crate) struct Access(Arc<Mutex<Model>>);

#[derive(Debug)]
pub(crate) enum Failure {
    Failed(String),
    Cancelled,
    TimedOut,
    Uncertain(String),
}
impl From<String> for Failure {
    fn from(value: String) -> Self {
        Self::Failed(value)
    }
}
impl From<&str> for Failure {
    fn from(value: &str) -> Self {
        Self::Failed(value.into())
    }
}

struct Model {
    backend: Option<Backend>,
    session: Option<Session>,
}

struct Session {
    child: tokio::process::Child,
    input: Option<tokio::process::ChildStdin>,
    output: BufReader<tokio::process::ChildStdout>,
    sequence: u64,
    ready: bool,
    backend_pid: Option<u32>,
    cleanup: Option<Result<(), String>>,
    initial: Option<Start>,
    slot: Option<File>,
}

/// Drop closes the inherited lifeline. The native supervisor, independently of
/// inference and the Tokio runtime, terminates/reaps the model's process group.
impl Drop for Session {
    fn drop(&mut self) {
        self.input.take();
    }
}

impl Access {
    pub(crate) fn new(backend: Option<Backend>) -> Self {
        Self(Arc::new(Mutex::new(Model {
            backend,
            session: None,
        })))
    }

    pub(crate) fn has_session(&self) -> bool {
        self.0
            .try_lock()
            .map_or(true, |model| model.session.is_some())
    }

    pub(crate) async fn infer(
        &self,
        request: Request,
        model_id: &str,
        mut slot: Option<File>,
        mut cancel: oneshot::Receiver<()>,
        deadline: tokio::time::Instant,
    ) -> Result<Distribution, Failure> {
        request.validate()?;
        if deadline <= tokio::time::Instant::now() {
            return Err(Failure::TimedOut);
        }
        if !matches!(cancel.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
            return Err(Failure::Cancelled);
        }
        let mut model = self.0.try_lock().map_err(|_| "decision runtime is busy")?;
        if model
            .session
            .as_ref()
            .is_some_and(|session| session.input.is_none())
        {
            let closed = model.session.take().expect("closed owned session");
            let lease = closed.shutdown().await.map_err(Failure::Uncertain)?;
            if slot.is_none() {
                slot = Some(lease);
            }
        }
        let backend = model
            .backend
            .as_ref()
            .ok_or("decision model is not configured")?;
        let identity = backend.identity.clone();
        if backend.identity != model_id {
            return Err("decision model context differs; restart required".into());
        }
        if backend.memory_bytes > crate::resources::limits().decision_memory_bytes {
            return Err("decision model exceeds installed memory capacity".into());
        }
        if backend.threads
            > std::thread::available_parallelism()
                .map_err(|e| e.to_string())?
                .get()
        {
            return Err("decision thread budget exceeds available CPUs".into());
        }
        if model.session.is_none() {
            if !crate::resources::adaptive::model_memory_available(backend.memory_bytes) {
                return Err(
                    "decision model capacity is unavailable under current resource pressure".into(),
                );
            }
            model.session = Some(
                Session::spawn(
                    backend.clone(),
                    slot.ok_or("decision physical lease unavailable")?,
                )
                .await?,
            );
        }
        let session = model.session.as_mut().expect("owned decision session");
        let duration = deadline.saturating_duration_since(tokio::time::Instant::now());
        let deadline_ns = crate::process_custody::monotonic_ns()?
            .checked_add(
                u64::try_from(duration.as_nanos()).map_err(|_| "decision horizon overflow")?,
            )
            .ok_or("decision horizon overflow")?;
        let execution = async { session.evaluate(&request, &identity, deadline_ns).await };
        let result = tokio::select! {
            result = execution => result,
            _ = &mut cancel => Err(Failure::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(Failure::TimedOut),
        };
        if result.is_err()
            && let Some(session) = model.session.take()
        {
            session.shutdown().await.map_err(Failure::Uncertain)?;
        }
        result
    }

    pub(crate) async fn shutdown(&self) -> Result<(), String> {
        let mut model = self.0.lock().await;
        if let Some(session) = model.session.take() {
            session.shutdown().await?;
        }
        Ok(())
    }
}

impl Session {
    async fn spawn(backend: Backend, slot: File) -> Result<Self, Failure> {
        let mut command =
            tokio::process::Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
        command
            .arg(INTERNAL)
            .env_clear()
            .env("NAOME_INTERNAL_DECISION", "v1")
            .env(
                "NAOME_EFFECTIVE_RESOURCES",
                crate::resources::child_snapshot()?,
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let start = Start {
            backend,
            slot_fd: slot.as_raw_fd(),
        };
        let (spawned, restored) =
            crate::process_custody::spawn_with_slot(&slot, || command.spawn())?;
        let mut child = spawned.map_err(|e| format!("decision supervisor spawn: {e}"))?;
        let input = child.stdin.take().ok_or("decision lifeline absent")?;
        let output = child.stdout.take().ok_or("decision output absent")?;
        let session = Self {
            child,
            input: Some(input),
            output: BufReader::new(output),
            sequence: 0,
            ready: false,
            backend_pid: None,
            cleanup: None,
            initial: Some(start),
            slot: Some(slot),
        };
        if let Err(error) = restored {
            session.shutdown().await.map_err(Failure::Uncertain)?;
            return Err(Failure::Failed(format!(
                "decision slot inheritance restoration: {error}"
            )));
        }
        crate::network::emit(
            serde_json::json!({"event":"decision_started", "supervisor_pid":session.child.id()}),
        );
        Ok(session)
    }

    async fn write(&mut self, value: &impl Serialize) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        if bytes.len() > CAPACITY {
            return Err("decision frame capacity".into());
        }
        self.input
            .as_mut()
            .ok_or("decision lifeline closed")?
            .write_all(&bytes)
            .await
            .map_err(|e| e.to_string())
    }

    async fn frame(&mut self) -> Result<Frame, String> {
        let mut bytes = Vec::new();
        loop {
            let buffer = self.output.fill_buf().await.map_err(|e| e.to_string())?;
            if buffer.is_empty() {
                return Err("decision process ended before response".into());
            }
            let length = buffer
                .iter()
                .position(|b| *b == b'\n')
                .map_or(buffer.len(), |n| n + 1);
            if bytes.len().saturating_add(length) > CAPACITY {
                return Err("decision response frame capacity".into());
            }
            let end = buffer[length - 1] == b'\n';
            bytes.extend_from_slice(&buffer[..length]);
            self.output.consume(length);
            if end {
                let frame: Frame = serde_json::from_slice(&bytes)
                    .map_err(|_| "invalid decision response frame")?;
                if let Frame::Cleanup { error } = &frame {
                    self.cleanup = Some(error.clone().map_or(Ok(()), Err));
                }
                return Ok(frame);
            }
        }
    }

    async fn evaluate(
        &mut self,
        request: &Request,
        model: &str,
        deadline_ns: u64,
    ) -> Result<Distribution, Failure> {
        let mut flight = Flight {
            session: self,
            completed: false,
        };
        let result = flight
            .session
            .evaluate_inner(request, model, deadline_ns)
            .await;
        flight.completed = true;
        result
    }

    async fn evaluate_inner(
        &mut self,
        request: &Request,
        model: &str,
        deadline_ns: u64,
    ) -> Result<Distribution, Failure> {
        if let Some(start) = self.initial.take() {
            self.write(&start).await?;
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("decision sequence exhausted")?;
        let sequence = self.sequence;
        self.write(&Invocation {
            sequence,
            request: request.identity(),
            input: request.clone(),
            deadline_ns,
        })
        .await?;
        loop {
            match self.frame().await? {
                Frame::Started { pid } if self.backend_pid.is_none() => {
                    self.backend_pid = Some(pid);
                    crate::network::emit(
                        serde_json::json!({"event":"decision_backend_started","model":model,"pid":pid}),
                    );
                }
                Frame::Ready {
                    model: identity,
                    pid,
                    runtime,
                } if !self.ready && identity == model && self.backend_pid == Some(pid) => {
                    self.ready = true;
                    crate::network::emit(
                        serde_json::json!({"event":"decision_model_loaded", "model":identity,"pid":pid,"runtime":runtime}),
                    );
                }
                Frame::Answer {
                    sequence: response,
                    distribution,
                } if self.ready && response == sequence => {
                    distribution.validate(request, model)?;
                    return Ok(distribution);
                }
                Frame::Error {
                    sequence: response,
                    code,
                    error,
                } if response == sequence => {
                    return Err(match code {
                        ErrorCode::TimedOut => Failure::TimedOut,
                        ErrorCode::Failed => {
                            Failure::Failed(format!("decision inference: {error}"))
                        }
                    });
                }
                _ => return Err("decision response identity or lifecycle differs".into()),
            }
        }
    }

    async fn shutdown(mut self) -> Result<File, String> {
        self.input.take();
        let until = tokio::time::Instant::now() + crate::resources::limits().provider_drain_timeout;
        let cleanup = async {
            if let Some(result) = &self.cleanup {
                return result.clone();
            }
            loop {
                if let Frame::Cleanup { error } = self.frame().await? {
                    return error.map_or(Ok(()), Err);
                }
            }
        };
        let receipt = tokio::time::timeout_at(until, cleanup)
            .await
            .map_err(|_| {
                "decision cleanup receipt deadline; physical custody is unconfirmed".to_owned()
            })
            .and_then(|value| value);
        let reaped = tokio::time::timeout_at(until, self.child.wait())
            .await
            .map_err(|_| "decision supervisor reaping deadline".to_owned())
            .and_then(|value| value.map_err(|e| e.to_string()));
        receipt?;
        reaped?;
        Ok(self.slot.take().expect("owned physical lease"))
    }
}

struct Flight<'a> {
    session: &'a mut Session,
    completed: bool,
}
impl Drop for Flight<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.session.input.take();
        }
    }
}

pub(crate) fn internal(arguments: &[std::ffi::OsString]) -> Option<Result<(), String>> {
    if arguments
        .first()
        .is_none_or(|arg| arg != INTERNAL && arg != WORKER)
    {
        return None;
    }
    Some(
        if arguments.len() != 1 || std::env::var("NAOME_INTERNAL_DECISION").as_deref() != Ok("v1") {
            Err("internal decision invocation required".into())
        } else {
            if arguments[0] == WORKER {
                work()
            } else {
                supervise()
            }
        },
    )
}

fn line(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, String> {
    let mut bytes = Vec::new();
    loop {
        let buffer = reader.fill_buf().map_err(|e| e.to_string())?;
        if buffer.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err("decision ended inside frame".into())
            };
        }
        let length = buffer
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buffer.len(), |n| n + 1);
        if bytes.len().saturating_add(length) > CAPACITY {
            return Err("decision transport capacity".into());
        }
        let end = buffer[length - 1] == b'\n';
        bytes.extend_from_slice(&buffer[..length]);
        reader.consume(length);
        if end {
            return Ok(Some(bytes));
        }
    }
}

enum Message {
    Parent(Vec<u8>),
    ParentClosed,
    Model(Vec<u8>),
    ModelClosed,
}

fn supervise() -> Result<(), String> {
    nix::unistd::setsid().map_err(|e| e.to_string())?;
    let mut reader = std::io::BufReader::new(std::io::stdin());
    let initial = (|| {
        let Some(bytes) = line(&mut reader)? else {
            return Ok(None);
        };
        let start: Start = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        crate::object::id_bytes(&start.backend.identity)?;
        if !start.backend.executable.is_absolute()
            || start.backend.memory_bytes == 0
            || start.backend.threads == 0
        {
            return Err("invalid decision backend descriptor".into());
        }
        Ok::<_, String>(Some(start))
    })();
    let start = match initial {
        Ok(Some(start)) => start,
        // Cancellation may close the lifeline before Start is delivered. No
        // worker exists, so acknowledge actual absence instead of uncertainty.
        Ok(None) => {
            emit_frame(&Frame::Cleanup { error: None })?;
            return Ok(());
        }
        Err(error) => {
            emit_frame(&Frame::Cleanup { error: None })?;
            return Err(error);
        }
    };
    let backend = &start.backend;
    let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg(WORKER)
        .env_clear()
        .env("NAOME_INTERNAL_DECISION", "v1")
        .env(
            "NAOME_EFFECTIVE_RESOURCES",
            crate::resources::child_snapshot()?,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            emit_frame(&Frame::Cleanup { error: None })?;
            return Err(format!("decision backend spawn: {error}"));
        }
    };
    let mut sequence = None;
    let mut timed_out = false;
    let mut lifeline = None;
    let mut peak_rss = 0;
    let result: Result<(), String> = (|| {
        let mut input = child.stdin.take().ok_or("decision model input absent")?;
        let output = child.stdout.take().ok_or("decision model output absent")?;
        let mut initial = serde_json::to_vec(&start).map_err(|e| e.to_string())?;
        initial.push(b'\n');
        let (send, receive) = mpsc::sync_channel(4);
        let parent = send.clone();
        std::thread::spawn(move || {
            while let Ok(Some(bytes)) = line(&mut reader) {
                if parent.send(Message::Parent(bytes)).is_err() {
                    return;
                }
            }
            let _ = parent.send(Message::ParentClosed);
        });
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(output);
            while let Ok(Some(bytes)) = line(&mut reader) {
                if send.send(Message::Model(bytes)).is_err() {
                    return;
                }
            }
            let _ = send.send(Message::ModelClosed);
        });
        // Pipe backpressure must not block the independent custody loop.
        let (write, writes) = mpsc::sync_channel::<Vec<u8>>(1);
        lifeline = Some(write.clone());
        std::thread::spawn(move || {
            if input.write_all(&initial).is_err() {
                return;
            }
            while let Ok(bytes) = writes.recv() {
                if input.write_all(&bytes).is_err() {
                    break;
                }
            }
        });
        let mut deadline = None;
        let mut started = false;
        let mut ready = false;
        let mut next_memory = Instant::now();
        loop {
            if deadline.is_some_and(|end| {
                crate::process_custody::monotonic_ns().map_or(true, |now| now >= end)
            }) {
                timed_out = true;
                return Err("decision original deadline expired".into());
            }
            if Instant::now() >= next_memory {
                next_memory = Instant::now() + Duration::from_millis(250);
                let rss = process_group_rss(child.id())?;
                peak_rss = peak_rss.max(rss);
                if rss > backend.memory_bytes {
                    return Err(format!(
                        "decision resident memory limit ({rss} > {} bytes)",
                        backend.memory_bytes
                    ));
                }
            }
            match receive.recv_timeout(Duration::from_millis(20)) {
                Ok(Message::Parent(bytes)) => {
                    let request: Invocation = serde_json::from_slice(&bytes)
                        .map_err(|_| "invalid decision invocation")?;
                    request.input.validate()?;
                    if deadline.is_some() || request.request != request.input.identity() {
                        return Err("decision concurrent invocation or binding differs".into());
                    }
                    deadline = Some(request.deadline_ns);
                    sequence = Some(request.sequence);
                    write
                        .try_send(bytes)
                        .map_err(|_| "decision transport busy")?;
                }
                Ok(Message::ParentClosed) => return Ok(()),
                Ok(Message::Model(bytes)) => {
                    // A bounded ready/answer fits the parent pipe even if its
                    // consumer is cancelled. Bulk output must never block the
                    // independent custody loop on stdout backpressure.
                    if bytes.len() > 4096 {
                        return Err("decision response metadata capacity".into());
                    }
                    let mut frame: Frame = serde_json::from_slice(&bytes)
                        .map_err(|_| "invalid decision model frame")?;
                    match &mut frame {
                        Frame::Started { .. } if !started => {
                            started = true;
                        }
                        Frame::Ready { .. } if started && !ready => {
                            ready = true;
                        }
                        Frame::Answer { distribution, .. } if ready && deadline.is_some() => {
                            distribution.peak_rss_bytes = distribution.peak_rss_bytes.max(peak_rss);
                            deadline = None;
                            sequence = None;
                        }
                        Frame::Error { .. } if deadline.is_some() => {
                            deadline = None;
                            sequence = None;
                        }
                        _ => return Err("unsolicited decision response".into()),
                    }
                    emit_frame(&frame)?;
                }
                Ok(Message::ModelClosed) => return Err("decision model ended".into()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return Err("decision custody channels stopped".into()),
            }
        }
    })();
    if let (Err(error), Some(sequence)) = (&result, sequence) {
        let _ = emit_frame(&Frame::Error {
            sequence,
            code: if timed_out {
                ErrorCode::TimedOut
            } else {
                ErrorCode::Failed
            },
            error: error.chars().take(256).collect(),
        });
    }
    let cleanup = crate::process_custody::stop_worker(&mut child);
    drop(lifeline);
    emit_frame(&Frame::Cleanup {
        error: cleanup.as_ref().err().cloned(),
    })?;
    cleanup.and(result)
}

fn emit_frame(frame: &Frame) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(frame).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    std::io::stdout()
        .write_all(&bytes)
        .and_then(|_| std::io::stdout().flush())
        .map_err(|e| e.to_string())
}

fn work() -> Result<(), String> {
    nix::unistd::setsid().map_err(|e| e.to_string())?;
    let mut reader = std::io::BufReader::new(std::io::stdin());
    let start: Start =
        serde_json::from_slice(&line(&mut reader)?.ok_or("decision worker start missing")?)
            .map_err(|e| e.to_string())?;
    let backend = start.backend;
    let mut child = Command::new(&backend.executable)
        .args(&backend.arguments)
        .env_clear()
        .envs(&backend.environment)
        .env("NAOME_DECISION_SLOT_FD", start.slot_fd.to_string())
        .env(
            "NAOME_DECISION_GUARDIAN_PID",
            nix::unistd::getppid().as_raw().to_string(),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("decision backend spawn: {e}"))?;
    emit_frame(&Frame::Started { pid: child.id() })?;
    let mut input = child.stdin.take().ok_or("decision backend stdin absent")?;
    let output = child
        .stdout
        .take()
        .ok_or("decision backend stdout absent")?;
    let (write, writes) = mpsc::sync_channel::<Vec<u8>>(1);
    // Parent loss stops blocked native inference independently of its API.
    std::thread::spawn(move || {
        while let Ok(Some(bytes)) = line(&mut reader) {
            if write.try_send(bytes).is_err() {
                break;
            }
        }
        let _ = nix::sys::signal::killpg(nix::unistd::getpgrp(), nix::sys::signal::Signal::SIGKILL);
        std::process::exit(125);
    });
    let mut initial = serde_json::to_vec(&backend.initialization).map_err(|e| e.to_string())?;
    initial.push(b'\n');
    std::thread::spawn(move || {
        if input.write_all(&initial).is_err() {
            return;
        }
        while let Ok(bytes) = writes.recv() {
            if input.write_all(&bytes).is_err() {
                return;
            }
        }
    });
    let mut output = std::io::BufReader::new(output);
    while let Ok(Some(bytes)) = line(&mut output) {
        if std::io::stdout()
            .write_all(&bytes)
            .and_then(|_| std::io::stdout().flush())
            .is_err()
        {
            break;
        }
    }
    let _ = child.kill();
    child.wait().map_err(|e| e.to_string())?;
    Err("decision backend ended".into())
}

fn process_group_rss(group: u32) -> Result<u64, String> {
    #[cfg(target_os = "linux")]
    {
        let mut rss = 0u64;
        for entry in std::fs::read_dir("/proc").map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let pgrp = stat
                .rsplit_once(')')
                .and_then(|(_, tail)| tail.split_whitespace().nth(2))
                .and_then(|s| s.parse::<u32>().ok());
            if pgrp != Some(group) {
                continue;
            }
            let status = match std::fs::read_to_string(entry.path().join("status")) {
                Ok(status) => status,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("decision member RSS unavailable: {error}")),
            };
            let kib = status
                .lines()
                .find_map(|line| line.strip_prefix("VmRSS:"))
                .and_then(|s| s.split_whitespace().next()?.parse::<u64>().ok());
            let zombie = status
                .lines()
                .any(|line| line.starts_with("State:") && line.contains("Z (zombie)"));
            let kib = kib
                .or_else(|| zombie.then_some(0))
                .ok_or("decision member RSS malformed")?;
            rss = rss.saturating_add(kib.saturating_mul(1024));
        }
        Ok(rss)
    }
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/bin/ps")
            .args(["-A", "-o", "pgid=,rss="])
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() || output.stdout.len() > CAPACITY {
            return Err("decision RSS unavailable".into());
        }
        let text = std::str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
        let mut rss = 0u64;
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let pgrp = fields
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or("decision group observation malformed")?;
            let bytes = fields
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or("decision group RSS malformed")?
                .saturating_mul(1024);
            if pgrp == group {
                rss = rss.saturating_add(bytes);
            }
        }
        Ok(rss)
    }
}
