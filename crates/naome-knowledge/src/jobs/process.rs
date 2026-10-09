//! The production parent lifeline is independent of synchronous provider work.
use super::*;
use std::{
    io::{BufRead, Write},
    os::fd::AsRawFd,
    process::{Child, Command as ProcessCommand, Stdio},
    sync::mpsc as sync_channel,
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const INTERNAL: &str = "NAOME_INTERNAL_RESEARCH_PROVIDER";
const SUPERVISOR: &str = "--research-supervisor-v1";
const WORKER: &str = "--research-worker-v1";
const DESCENDANT: &str = "--research-descendant-v1";
const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    version: u8,
    record: Record,
    remaining_ms: u64,
    slot_fd: i32,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Frame {
    Ready {
        id: u64,
        binding: String,
        pid: u32,
    },
    Descendant {
        id: u64,
        pid: u32,
    },
    CpuActive {
        id: u64,
        next: u32,
    },
    CpuDone {
        id: u64,
        next: u32,
    },
    ResultReady {
        id: u64,
    },
    GenerationTool {
        id: u64,
        request_id: String,
        operation: String,
        status: crate::generation::ToolStatus,
        count: usize,
        artifact_snapshot: String,
        graph_root: String,
        query_id: String,
        remaining_range_complete: bool,
        backend_category: Option<String>,
    },
    Reserve {
        id: u64,
        next: u32,
    },
    Progress {
        id: u64,
        checkpoint: u32,
    },
    Result {
        id: u64,
        output: Output,
    },
    Failed {
        id: u64,
    },
    CleanupComplete {
        id: u64,
    },
    CleanupFailed {
        id: u64,
        error: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    id: u64,
    next: u32,
}

pub(super) enum Event {
    Reserve {
        id: u64,
        next: u32,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Progress {
        id: u64,
        checkpoint: u32,
        reply: oneshot::Sender<Result<(), String>>,
    },
}

pub(super) struct Outcome {
    pub state: State,
    pub result: Result<Output, String>,
}

pub(super) async fn run(
    record: Record,
    remaining_ms: u64,
    events: mpsc::Sender<Event>,
    cancel: oneshot::Receiver<()>,
    slot: std::fs::File,
) -> Outcome {
    let state = std::sync::Arc::new(std::sync::Mutex::new(None));
    let result = run_owned(record, remaining_ms, events, cancel, slot, state.clone()).await;
    let state = state
        .lock()
        .expect("provider disposition owner")
        .unwrap_or(if result.is_ok() {
            State::Complete
        } else {
            State::Failed
        });
    Outcome { state, result }
}

async fn run_owned(
    record: Record,
    remaining_ms: u64,
    events: mpsc::Sender<Event>,
    mut cancel: oneshot::Receiver<()>,
    slot: std::fs::File,
    disposition: std::sync::Arc<std::sync::Mutex<Option<State>>>,
) -> Result<Output, String> {
    let remaining_ms = remaining_ms.min(record.expires_ms.saturating_sub(wall_ms()?));
    if remaining_ms == 0 {
        *disposition.lock().expect("provider disposition owner") = Some(State::Expired);
        return Err("research deadline expired before launch".into());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_millis(remaining_ms);
    // This is the only deliberately inherited descriptor besides stdio. It is
    // a resource lease, never accepted-store or identity custody. Keeping it in
    // every descendant prevents a restarted node from reusing a live slot.
    let mut command =
        tokio::process::Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg(SUPERVISOR)
        .env_clear()
        .env(INTERNAL, "supervisor-v1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut start = serde_json::to_vec(&Start {
        version: 1,
        record: record.clone(),
        remaining_ms,
        slot_fd: slot.as_raw_fd(),
    })
    .map_err(|e| e.to_string())?;
    start.push(b'\n');
    let (spawned, restored) = {
        let _spawn = SPAWN.lock().map_err(|_| "provider spawn owner poisoned")?;
        nix::fcntl::fcntl(
            &slot,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .map_err(|e| e.to_string())?;
        let spawned = command.spawn();
        let restored = nix::fcntl::fcntl(
            &slot,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        );
        (spawned, restored)
    };
    let mut child = spawned.map_err(|e| format!("provider supervisor spawn: {e}"))?;
    *disposition.lock().expect("provider disposition owner") = Some(State::InDoubt);
    if let Err(error) = restored {
        // Start has not been written: close the lifeline, retain this Child
        // through termination, and preserve uncertain ownership on any error.
        drop(child.stdin.take());
        if tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .is_err()
        {
            child
                .start_kill()
                .map_err(|e| format!("slot inheritance restoration: {error}; {e}"))?;
            child
                .wait()
                .await
                .map_err(|e| format!("slot inheritance restoration: {error}; {e}"))?;
        }
        return Err(format!("slot inheritance restoration: {error}"));
    }
    let pid = child
        .id()
        .ok_or("provider supervisor has no process identity")?;
    crate::network::emit(
        serde_json::json!({"event":"research_started","job":record.id,
        "provider":record.provider,"pid":pid,"lane":record.input.lane(),"remaining_ms":remaining_ms}),
    );
    let mut input = child.stdin.take().ok_or("provider lifeline absent")?;
    let output = child.stdout.take().ok_or("provider output absent")?;
    let mut reader = FrameReader::new(output);
    let mut cleaned = false;
    let mut start_delivered = false;
    let execution = async {
        input.write_all(&start).await.map_err(|e| e.to_string())?;
        start_delivered = true;
        let mut ready = false;
        let mut checkpoint = record.checkpoint;
        let mut outstanding = None;
        let mut tool_receipts = 0u8;
        loop {
            let bytes = reader
                .next()
                .await?
                .ok_or("provider ended before a complete result")?;
            let frame: Frame =
                serde_json::from_slice(&bytes).map_err(|_| "provider frame corruption")?;
            match frame {
                Frame::Ready { id, binding, pid }
                    if !ready && id == record.id && binding == identity(&record) =>
                {
                    ready = true;
                    crate::network::emit(
                        serde_json::json!({"event":"research_worker","job":id,"pid":pid}),
                    );
                }
                Frame::Descendant { id, pid }
                    if ready && id == record.id && record.settings.mock.descendant =>
                {
                    crate::network::emit(
                        serde_json::json!({"event":"research_descendant","job":id,"pid":pid}),
                    );
                }
                Frame::CpuActive { id, next }
                    if ready && id == record.id && outstanding == Some(next) =>
                {
                    crate::network::emit(
                        serde_json::json!({"event":"research_working","job":id,"phase":"cpu_active","next":next}),
                    );
                }
                Frame::CpuDone { id, next }
                    if ready && id == record.id && outstanding == Some(next) =>
                {
                    crate::network::emit(
                        serde_json::json!({"event":"research_working","job":id,"phase":"cpu_done","next":next}),
                    );
                }
                Frame::ResultReady { id } if ready && id == record.id && outstanding.is_none() => {
                    crate::network::emit(
                        serde_json::json!({"event":"research_working","job":id,"phase":"result_ready"}),
                    );
                }
                Frame::GenerationTool {
                    id,
                    request_id,
                    operation,
                    status,
                    count,
                    artifact_snapshot,
                    graph_root,
                    query_id,
                    remaining_range_complete,
                    backend_category,
                } if ready
                    && id == record.id
                    && outstanding.is_none()
                    && matches!(record.input, Input::Find { .. } | Input::Solve { .. })
                    && tool_receipts < 4
                    && (tool_receipts == 0 || matches!(record.input, Input::Solve { .. }))
                    && count <= 16 =>
                {
                    let request = record
                        .generation
                        .as_ref()
                        .ok_or("generation request absent")?;
                    let (expected_snapshot, expected_root) = request.context_identity();
                    crate::object::id_bytes(&query_id)?;
                    let semantic_state_valid = match (
                        &status,
                        count,
                        remaining_range_complete,
                        backend_category.as_deref(),
                    ) {
                        (
                            crate::generation::ToolStatus::BackendUnavailable,
                            0,
                            false,
                            Some("retrieval_encoder_not_configured"),
                        ) => operation == "semantic_search",
                        (crate::generation::ToolStatus::NoResult, 0, true, None) => true,
                        (crate::generation::ToolStatus::Ok, 1..=16, _, None) => {
                            operation != "semantic_search"
                        }
                        _ => false,
                    };
                    if request_id != request.identity()
                        || artifact_snapshot != expected_snapshot
                        || graph_root != expected_root
                        || !["native_search", "lookup", "fetch", "semantic_search"]
                            .contains(&operation.as_str())
                        || !semantic_state_valid
                    {
                        return Err("generation retrieval receipt differs from request".into());
                    }
                    tool_receipts += 1;
                    crate::network::emit(serde_json::json!({
                        "event":"generation_tool_invoked","job":id,"request_id":request_id,
                        "operation":operation,"status":status,"count":count,
                        "artifact_snapshot":artifact_snapshot,"graph_root":graph_root,
                        "query_id":query_id,"remaining_range_complete":remaining_range_complete,
                        "backend_category":backend_category,
                    }));
                }
                Frame::Reserve { id, next }
                    if ready
                        && outstanding.is_none()
                        && id == record.id
                        && next
                            == checkpoint
                                .checked_add(1)
                                .ok_or("provider checkpoint overflow")? =>
                {
                    let (reply, receipt) = oneshot::channel();
                    events
                        .send(Event::Reserve { id, next, reply })
                        .await
                        .map_err(|_| "research owner stopped")?;
                    receipt
                        .await
                        .map_err(|_| "research reservation owner stopped")??;
                    let mut bytes =
                        serde_json::to_vec(&Grant { id, next }).map_err(|e| e.to_string())?;
                    bytes.push(b'\n');
                    input.write_all(&bytes).await.map_err(|e| e.to_string())?;
                    outstanding = Some(next);
                }
                Frame::Progress {
                    id,
                    checkpoint: next,
                } if ready
                    && outstanding == Some(next)
                    && id == record.id
                    && next == checkpoint + 1 =>
                {
                    checkpoint = next;
                    let (reply, receipt) = oneshot::channel();
                    events
                        .send(Event::Progress {
                            id,
                            checkpoint,
                            reply,
                        })
                        .await
                        .map_err(|_| "research owner stopped")?;
                    receipt
                        .await
                        .map_err(|_| "research checkpoint owner stopped")??;
                    let mut bytes = serde_json::to_vec(&Grant {
                        id,
                        next: checkpoint,
                    })
                    .map_err(|e| e.to_string())?;
                    bytes.push(b'\n');
                    input.write_all(&bytes).await.map_err(|e| e.to_string())?;
                    outstanding = None;
                }
                Frame::CleanupComplete { id } if id == record.id => cleaned = true,
                Frame::Result { id, output }
                    if ready
                        && cleaned
                        && outstanding.is_none()
                        && id == record.id
                        && record.settings.mock.steps > 0
                        && checkpoint == record.settings.mock.steps =>
                {
                    output.validate(&record.input)?;
                    return Ok(output);
                }
                Frame::Failed { id } if ready && id == record.id => {
                    return Err("deterministic provider failed".into());
                }
                Frame::CleanupFailed { id, error } if id == record.id => {
                    *disposition.lock().expect("provider disposition owner") = Some(State::InDoubt);
                    return Err(format!(
                        "provider group termination is unconfirmed: {error}"
                    ));
                }
                _ => return Err("provider frame identity or lifecycle differs".into()),
            }
        }
    };
    let result = tokio::select! {
        value=execution=>value,
        _=&mut cancel=>{*disposition.lock().expect("provider disposition owner")=Some(State::Cancelled);Err("research cancelled".into())},
        _=tokio::time::sleep_until(deadline)=>{*disposition.lock().expect("provider disposition owner")=Some(State::Expired);Err("research deadline expired".into())},
    };
    let completion_state = disposition
        .lock()
        .expect("provider disposition owner")
        .take();
    *disposition.lock().expect("provider disposition owner") = Some(State::InDoubt);
    // EOF asks the supervisor to terminate and reap its provider even while the
    // provider is CPU-blocked. Keep the live Child until teardown is observed.
    drop(input);
    // Cancellation can arrive before Ready or while a checkpoint is pending.
    // Keep the partial frame across cancellation and drain through EOF even
    // after the cleanup receipt, so a large result cannot block child.wait.
    let drain = async {
        loop {
            let Some(frame) = reader.next().await? else {
                return Ok::<(), String>(());
            };
            match serde_json::from_slice::<Frame>(&frame)
                .map_err(|_| "provider cleanup frame corruption")?
            {
                Frame::CleanupComplete { id } if id == record.id => cleaned = true,
                Frame::CleanupFailed { id, error } if id == record.id => {
                    cleaned = false;
                    return Err(format!(
                        "provider group termination is unconfirmed: {error}"
                    ));
                }
                Frame::Ready { id, .. }
                | Frame::Descendant { id, .. }
                | Frame::CpuActive { id, .. }
                | Frame::CpuDone { id, .. }
                | Frame::ResultReady { id }
                | Frame::GenerationTool { id, .. }
                | Frame::Reserve { id, .. }
                | Frame::Progress { id, .. }
                | Frame::Result { id, .. }
                | Frame::Failed { id }
                    if id == record.id => {}
                _ => return Err("provider cleanup identity differs".to_owned()),
            }
        }
    };
    let drain_error = match tokio::time::timeout(Duration::from_secs(3), drain).await {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some("provider output drain deadline".to_owned()),
    };
    let status = match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
        Ok(status) => status.map_err(|e| e.to_string())?,
        Err(_) => {
            child.start_kill().map_err(|e| e.to_string())?;
            child.wait().await.map_err(|e| e.to_string())?;
            *disposition.lock().expect("provider disposition owner") = Some(State::InDoubt);
            return Err("provider supervisor cleanup deadline; recovery is uncertain".into());
        }
    };
    crate::network::emit(
        serde_json::json!({"event":"research_reaped","job":record.id,"pid":pid,"exit":status.code()}),
    );
    // An incomplete Start cannot create a worker. When cancellation closed its
    // lifeline before any complete Start or output frame, reaped supervisor
    // exit is sufficient: no provider group was ever created.
    if !start_delivered && reader.total == 0 && drain_error.is_none() {
        cleaned = true;
    }
    if !cleaned {
        *disposition.lock().expect("provider disposition owner") = Some(State::InDoubt);
        return Err("provider cleanup receipt is absent; recovery is uncertain".into());
    }
    *disposition.lock().expect("provider disposition owner") =
        completion_state.filter(|state| *state != State::InDoubt);
    if let Some(error) = drain_error {
        return Err(match result {
            Err(primary) => format!("{primary}; {error}"),
            Ok(_) => error,
        });
    }
    if result.is_ok() && !status.success() {
        return Err("provider exited without clean completion".into());
    }
    result
}

struct FrameReader<R> {
    reader: BufReader<R>,
    partial: Vec<u8>,
    total: usize,
}

impl<R: tokio::io::AsyncRead + Unpin> FrameReader<R> {
    fn new(output: R) -> Self {
        Self {
            reader: BufReader::new(output),
            partial: Vec::new(),
            total: 0,
        }
    }

    async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        loop {
            let buffer = self.reader.fill_buf().await.map_err(|e| e.to_string())?;
            if buffer.is_empty() {
                return if self.partial.is_empty() {
                    Ok(None)
                } else {
                    Err("provider ended inside a frame".into())
                };
            }
            let end = buffer
                .iter()
                .position(|b| *b == b'\n')
                .map(|n| n + 1)
                .unwrap_or(buffer.len());
            if self.partial.len() + end > MAX_FRAME_BYTES {
                return Err("provider frame capacity".into());
            }
            let complete = buffer[end - 1] == b'\n';
            self.partial.extend_from_slice(&buffer[..end]);
            self.reader.consume(end);
            if complete {
                self.total = self
                    .total
                    .checked_add(self.partial.len())
                    .ok_or("provider stream overflow")?;
                if self.total > MAX_STREAM_BYTES {
                    return Err("provider stream capacity".into());
                }
                return Ok(Some(std::mem::take(&mut self.partial)));
            }
        }
    }
}

pub(super) fn internal(arguments: &[std::ffi::OsString]) -> Option<Result<(), String>> {
    let [argument] = arguments else {
        return None;
    };
    match argument.to_str()? {
        SUPERVISOR => Some(
            if std::env::var(INTERNAL).as_deref() == Ok("supervisor-v1") {
                supervise()
            } else {
                Err("internal provider invocation required".into())
            },
        ),
        WORKER => Some(if std::env::var(INTERNAL).as_deref() == Ok("worker-v1") {
            work()
        } else {
            Err("internal provider invocation required".into())
        }),
        DESCENDANT => Some(
            if std::env::var(INTERNAL).as_deref() == Ok("descendant-v1") {
                descendant()
            } else {
                Err("internal provider invocation required".into())
            },
        ),
        _ => None,
    }
}

fn line(reader: &mut impl BufRead, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    loop {
        let buffer = reader.fill_buf().map_err(|e| e.to_string())?;
        if buffer.is_empty() {
            return Err("provider lifeline closed".into());
        }
        let end = buffer
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(buffer.len());
        if bytes.len() + end > limit {
            return Err("provider pipe capacity".into());
        }
        let complete = buffer[end - 1] == b'\n';
        bytes.extend_from_slice(&buffer[..end]);
        reader.consume(end);
        if complete {
            return Ok(bytes);
        }
    }
}

fn emit_generation_tool(
    id: u64,
    operation: &str,
    result: &crate::generation::ToolResult,
) -> Result<(), String> {
    emit(&Frame::GenerationTool {
        id,
        request_id: result.request_id.clone(),
        operation: operation.into(),
        status: result.status.clone(),
        count: result.results.len(),
        artifact_snapshot: result.artifact_snapshot.clone(),
        graph_root: result.graph_root.clone(),
        query_id: result.query_id.clone(),
        remaining_range_complete: result.remaining_range_complete,
        backend_category: (result.status == crate::generation::ToolStatus::BackendUnavailable)
            .then(|| "retrieval_encoder_not_configured".into()),
    })
}

fn emit(frame: &Frame) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(frame).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME_BYTES {
        return Err("provider output capacity".into());
    }
    std::io::stdout()
        .write_all(&bytes)
        .and_then(|_| std::io::stdout().flush())
        .map_err(|e| e.to_string())
}

enum Message {
    Parent(Vec<u8>),
    ParentClosed,
    Provider(Vec<u8>),
    ProviderClosed,
}

struct Worker {
    child: Child,
    teardown_started: bool,
}
impl Worker {
    fn finish(&mut self) -> Result<(), String> {
        self.teardown_started = true;
        stop_worker(&mut self.child)
    }
}

struct Descendant(Child);
impl Drop for Descendant {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if !self.teardown_started {
            let _ = self.finish();
        }
    }
}

fn supervise() -> Result<(), String> {
    // The supervisor is the session/group leader. It stays alive during normal
    // cancellation so the group cannot be confused with a recycled PID.
    nix::unistd::setsid().map_err(|e| e.to_string())?;
    let mut reader = std::io::BufReader::new(std::io::stdin());
    let bytes = line(&mut reader, MAX_FRAME_BYTES)?;
    let start: Start = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if start.version != 1 || !(1..=MAX_HORIZON_MS).contains(&start.remaining_ms) {
        return Err("provider start version or horizon differs".into());
    }
    start.record.input.validate()?;
    start.record.binding.validate()?;
    let child = ProcessCommand::new(std::env::current_exe().map_err(|e| e.to_string())?)
        .arg(WORKER)
        .env(INTERNAL, "worker-v1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut child = Worker {
        child,
        teardown_started: false,
    };
    let mut input = child
        .child
        .stdin
        .take()
        .ok_or("provider worker lifeline absent")?;
    input.write_all(&bytes).map_err(|e| e.to_string())?;
    let output = child
        .child
        .stdout
        .take()
        .ok_or("provider worker output absent")?;
    let (sender, receiver) = sync_channel::sync_channel(8);
    let parent = sender.clone();
    std::thread::spawn(move || {
        loop {
            match line(&mut reader, 256) {
                Ok(bytes) => {
                    if parent.send(Message::Parent(bytes)).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = parent.send(Message::ParentClosed);
                    break;
                }
            }
        }
    });
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(output);
        let mut total = 0usize;
        while let Ok(bytes) = line(&mut reader, MAX_FRAME_BYTES) {
            total = total.saturating_add(bytes.len());
            if total > MAX_STREAM_BYTES || sender.send(Message::Provider(bytes)).is_err() {
                break;
            }
        }
        let _ = sender.send(Message::ProviderClosed);
    });
    let deadline = Instant::now() + Duration::from_millis(start.remaining_ms);
    let mut result = None;
    loop {
        if Instant::now() >= deadline {
            break;
        }
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(Message::Parent(bytes)) => {
                if input.write_all(&bytes).is_err() {
                    break;
                }
            }
            Ok(Message::ParentClosed) => break,
            Ok(Message::Provider(bytes)) => {
                if matches!(
                    serde_json::from_slice::<Frame>(&bytes),
                    Ok(Frame::Result { .. })
                ) {
                    result = Some(bytes);
                } else if std::io::stdout()
                    .write_all(&bytes)
                    .and_then(|_| std::io::stdout().flush())
                    .is_err()
                {
                    break;
                }
            }
            Ok(Message::ProviderClosed) => break,
            Err(sync_channel::RecvTimeoutError::Disconnected) => break,
            Err(sync_channel::RecvTimeoutError::Timeout) => {}
        }
    }
    if let Err(error) = child.finish() {
        let _ = emit(&Frame::CleanupFailed {
            id: start.record.id,
            error: error.chars().take(256).collect(),
        });
        return Err(error);
    }
    emit(&Frame::CleanupComplete {
        id: start.record.id,
    })?;
    drop(input);
    if let Some(result) = result {
        std::io::stdout()
            .write_all(&result)
            .and_then(|_| std::io::stdout().flush())
            .map_err(|e| e.to_string())
    } else {
        Err("provider stopped or failed".into())
    }
}

fn stop_worker(child: &mut Child) -> Result<(), String> {
    // Hold the live unreaped Child while signalling its separate provider group.
    // A pre-start cancellation may precede setsid; direct Child.kill covers it.
    let group =
        nix::unistd::Pid::from_raw(i32::try_from(child.id()).map_err(|_| "provider PID overflow")?);
    let mut signal_errors = Vec::new();
    match nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGTERM) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
        // Darwin skips zombies when signalling a group and can return EPERM
        // for a zombie-only group. Retain the denial until actual absence is
        // observed after reaping; a denial alone never confirms cleanup.
        Err(error) => signal_errors.push(format!("provider TERM group: {error}")),
    }
    // Rust's portable Child API reaps on try_wait. Keep the leader unreaped
    // through both signals instead, including when it exits during this grace.
    std::thread::sleep(Duration::from_millis(300));
    // Stop the original leader before the last group signal. This also covers
    // early cancellation while the worker is still creating its own group.
    if let Err(error) = child.kill() {
        signal_errors.push(format!("provider direct Child kill: {error}"));
    }
    // Retain the unreaped leader through the final group signal. Its PID
    // cannot be recycled while we own this Child, even after its exit.
    match nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
        Err(error) => signal_errors.push(format!("provider KILL group: {error}")),
    }
    // All signals are finished before any reaping can release the leader PID.
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        if child
            .try_wait()
            .map_err(|e| format!("provider wait: {e}"))?
            .is_some()
        {
            break;
        }
        if Instant::now() >= until {
            return Err(format!(
                "provider Child reaping deadline; {}",
                signal_errors.join("; ")
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        match nix::sys::signal::killpg(group, None) {
            Err(nix::errno::Errno::ESRCH) => return Ok(()),
            Ok(()) | Err(nix::errno::Errno::EPERM) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                return Err(format!(
                    "provider group termination is unconfirmed{}",
                    if signal_errors.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", signal_errors.join("; "))
                    }
                ));
            }
        }
    }
}

fn work() -> Result<(), String> {
    nix::unistd::setsid().map_err(|e| e.to_string())?;
    let mut reader = std::io::BufReader::new(std::io::stdin());
    let start: Start =
        serde_json::from_slice(&line(&mut reader, MAX_FRAME_BYTES)?).map_err(|e| e.to_string())?;
    let record = start.record;
    record.input.validate()?;
    record.binding.validate()?;
    validate_generation(&record.input, &record.binding, record.generation.as_ref())?;
    if let Some(request) = &record.generation {
        request.recheck(&record.input, &record.binding)?;
    }
    let (sender, receiver) = sync_channel::sync_channel(1);
    // A lost supervisor closes this pipe. This dedicated lifeline reader can
    // still stop the group while the provider main thread is doing CPU work.
    std::thread::spawn(move || {
        loop {
            match line(&mut reader, 256) {
                Ok(bytes) => {
                    if sender.send(bytes).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = nix::sys::signal::killpg(
                        nix::unistd::getpgrp(),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    std::process::exit(125);
                }
            }
        }
    });
    emit(&Frame::Ready {
        id: record.id,
        binding: identity(&record),
        pid: std::process::id(),
    })?;
    let mut checkpoint = record.checkpoint;
    let mock = record.settings.mock;
    let _descendant = if mock.descendant {
        let mut child = ProcessCommand::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg(DESCENDANT)
            .env(INTERNAL, "descendant-v1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        let output = child.stdout.take().ok_or("descendant readiness absent")?;
        let child = Descendant(child);
        if line(&mut std::io::BufReader::new(output), 64)? != b"naome descendant ready v1\n" {
            return Err("descendant readiness differs".into());
        }
        emit(&Frame::Descendant {
            id: record.id,
            pid: child.0.id(),
        })?;
        Some(child)
    } else {
        None
    };
    while mock.steps == 0 || checkpoint < mock.steps {
        let next = checkpoint
            .checked_add(1)
            .ok_or("provider checkpoint overflow")?;
        emit(&Frame::Reserve {
            id: record.id,
            next,
        })?;
        let grant: Grant =
            serde_json::from_slice(&receiver.recv().map_err(|_| "provider permission closed")?)
                .map_err(|e| e.to_string())?;
        if grant.id != record.id || grant.next != next {
            return Err("provider reservation identity differs".into());
        }
        if mock.step_ms > 0 {
            std::thread::sleep(Duration::from_millis(mock.step_ms));
        }
        if mock.cpu_ms > 0 {
            emit(&Frame::CpuActive {
                id: record.id,
                next,
            })?;
            let until = Instant::now() + Duration::from_millis(mock.cpu_ms);
            let mut value = 0u64;
            while Instant::now() < until {
                value = std::hint::black_box(value.wrapping_mul(1664525).wrapping_add(1013904223));
            }
            std::hint::black_box(value);
            emit(&Frame::CpuDone {
                id: record.id,
                next,
            })?;
        }
        if mock.steps == 0 {
            // A true pending stand-in holds one charged reservation. Its
            // lifeline reader and supervisor enforce cancellation/deadline.
            loop {
                std::thread::park();
            }
        }
        checkpoint = next;
        emit(&Frame::Progress {
            id: record.id,
            checkpoint,
        })?;
        let grant: Grant = serde_json::from_slice(
            &receiver
                .recv()
                .map_err(|_| "provider checkpoint acknowledgement closed")?,
        )
        .map_err(|e| e.to_string())?;
        if grant.id != record.id || grant.next != checkpoint {
            return Err("provider durable checkpoint acknowledgement differs".into());
        }
    }
    if mock.outcome == MockOutcome::Failed {
        return emit(&Frame::Failed { id: record.id });
    }
    if mock.result_delay_ms > 0 {
        emit(&Frame::ResultReady { id: record.id })?;
        std::thread::sleep(Duration::from_millis(mock.result_delay_ms));
    }
    let output = match &record.input {
        Input::Find { .. } => {
            let request = record
                .generation
                .as_ref()
                .ok_or("generation request absent")?;
            let candidate =
                crate::mocks::create_question_request_with_tools(request, |operation, result| {
                    emit_generation_tool(record.id, operation, result)
                })?;
            Output::Question(if mock.outcome == MockOutcome::Malformed {
                "invalid question".into()
            } else {
                candidate
            })
        }
        Input::Solve { .. } => {
            let request = record
                .generation
                .as_ref()
                .ok_or("generation request absent")?;
            let compiled = request.question()?;
            let candidate =
                crate::mocks::create_proof_request_with_tools(request, |operation, result| {
                    emit_generation_tool(record.id, operation, result)
                })?;
            let source = if mock.outcome == MockOutcome::Malformed {
                Some("invalid proof".into())
            } else if mock.outcome == MockOutcome::WrongTarget {
                let other = (0..3)
                    .find_map(|cursor| {
                        let other = naome_authoring::CompiledQuestion::compile(
                            &crate::mocks::create_question(cursor),
                        )
                        .ok()?;
                        (other.resolution_id() != compiled.resolution_id()).then_some(other)
                    })
                    .ok_or("mock alternate target absent")?;
                crate::mocks::create_proof(&other)
            } else {
                candidate
            };
            source
                .map(|mut source| {
                    source.push_str(
                        &" ".repeat(
                            mock.proof_padding_bytes
                                .min(crate::MAX_PROOF_BYTES.saturating_sub(source.len())),
                        ),
                    );
                    Output::Proof {
                        source,
                        helpers: Vec::new(),
                    }
                })
                .unwrap_or(Output::NoCandidate)
        }
        Input::Interest { question, .. } => {
            let compiled =
                naome_authoring::CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
            let yes = libp2p::futures::executor::block_on(crate::mocks::assess_interest(compiled))?;
            Output::Interest(yes && mock.outcome != MockOutcome::Malformed)
        }
    };
    emit(&Frame::Result {
        id: record.id,
        output,
    })
}

fn descendant() -> Result<(), String> {
    // Stay in the worker's owned group and retain the inherited kernel slot.
    // A safe Tokio signal registration makes TERM non-cooperative; KILL must
    // still terminate this finite developer stand-in with its whole group.
    std::thread::spawn(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        runtime.block_on(async {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(|e| e.to_string())?;
            std::io::stdout()
                .write_all(b"naome descendant ready v1\n")
                .and_then(|_| std::io::stdout().flush())
                .map_err(|e| e.to_string())?;
            while terminate.recv().await.is_some() {}
            Err("descendant signal stream ended".into())
        })
    })
    .join()
    .map_err(|_| "descendant signal owner panicked")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_partial_result_remains_framed_and_large_output_drains_through_eof() {
        let (mut output, input) = tokio::io::duplex(64);
        let cleanup = b"{\"event\":\"cleanup_complete\",\"id\":1}\n";
        output.write_all(cleanup).await.unwrap();
        let mut frames = FrameReader::new(input);
        assert_eq!(frames.next().await.unwrap().unwrap(), cleanup);
        // The pipe has insufficient capacity for the result. Consume a prefix,
        // cancel that read, then keep the prefix while draining the rest.
        let prefix = b"{\"event\":\"result\",\"id\":1,\"output\":\"";
        output.write_all(prefix).await.unwrap();
        let mut waiting = Box::pin(frames.next());
        assert!(libp2p::futures::poll!(waiting.as_mut()).is_pending());
        drop(waiting);
        assert_eq!(frames.partial, prefix);
        let mut remainder = vec![b'x'; 64 * 1024];
        remainder.extend_from_slice(b"\"}\n");
        let expected = [prefix.as_slice(), remainder.as_slice()].concat();
        let supplier = tokio::spawn(async move {
            output.write_all(&remainder).await.unwrap();
        });
        let result = tokio::time::timeout(Duration::from_secs(2), frames.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(result, expected);
        assert!(frames.next().await.unwrap().is_none());
        supplier.await.unwrap();
    }
}
