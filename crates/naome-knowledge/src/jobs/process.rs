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
mod feedback;
use crate::resources::feedback::{Phase, Sample};

const INTERNAL: &str = "NAOME_INTERNAL_RESEARCH_PROVIDER";
const SUPERVISOR: &str = "--research-supervisor-v1";
const WORKER: &str = "--research-worker-v1";
const DESCENDANT: &str = "--research-descendant-v1";
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
    Feedback {
        id: u64,
        phase: Phase,
        sample: Sample,
    },
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
    Reserve {
        id: u64,
        next: u32,
    },
    Program {
        id: u64,
        unit: u32,
        records: Vec<naome_proof::program::Command>,
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
        error: String,
    },
    Uncertain {
        id: u64,
        error: String,
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
    Program {
        id: u64,
        unit: u32,
        records: Vec<naome_proof::program::Command>,
        reply: oneshot::Sender<Result<(), String>>,
    },
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
    computation: crate::resources::ComputationPermit,
) -> Outcome {
    let mut feedback = feedback::Attempt::new(record.input.feedback_role());
    let state = std::sync::Arc::new(std::sync::Mutex::new(None));
    let result = run_owned(
        record,
        remaining_ms,
        events,
        cancel,
        slot,
        computation,
        state.clone(),
        &mut feedback,
    )
    .await;
    let state = state
        .lock()
        .expect("provider disposition owner")
        .unwrap_or(if result.is_ok() {
            State::Complete
        } else {
            State::Failed
        });
    feedback.finish(state);
    Outcome { state, result }
}

async fn run_owned(
    record: Record,
    remaining_ms: u64,
    events: mpsc::Sender<Event>,
    mut cancel: oneshot::Receiver<()>,
    slot: std::fs::File,
    permit: crate::resources::ComputationPermit,
    disposition: std::sync::Arc<std::sync::Mutex<Option<State>>>,
    feedback: &mut feedback::Attempt,
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
        .env(
            "NAOME_EFFECTIVE_RESOURCES",
            crate::resources::child_snapshot()?,
        )
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
        if tokio::time::timeout(
            crate::resources::limits().provider_drain_timeout,
            child.wait(),
        )
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
    let computation = permit.owner();
    let mut working = Some(permit);
    let execution = async {
        input.write_all(&start).await.map_err(|e| e.to_string())?;
        start_delivered = true;
        let mut ready = false;
        let mut checkpoint = record.checkpoint;
        let mut outstanding = None;
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
                Frame::Feedback { id, phase, sample } if ready && id == record.id => {
                    feedback.observe(
                        phase,
                        sample,
                        outstanding,
                        super::provider::complete(&record, checkpoint),
                    )?;
                }
                Frame::Reserve { id, next }
                    if ready
                        && feedback.ready()
                        && outstanding.is_none()
                        && id == record.id
                        && next
                            == checkpoint
                                .checked_add(1)
                                .ok_or("provider checkpoint overflow")? =>
                {
                    drop(working.take());
                    let waiting = Instant::now();
                    working = Some(computation.enter().await);
                    feedback.pause(waiting.elapsed());
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
                Frame::Program { id, unit, records }
                    if ready
                        && id == record.id
                        && outstanding == Some(unit)
                        && matches!(record.input, Input::Solve { .. }) =>
                {
                    super::program::validate_group(&records)?;
                    let (reply, receipt) = oneshot::channel();
                    events
                        .send(Event::Program {
                            id,
                            unit,
                            records,
                            reply,
                        })
                        .await
                        .map_err(|_| "research owner stopped")?;
                    receipt
                        .await
                        .map_err(|_| "research candidate owner stopped")??;
                    let mut bytes =
                        serde_json::to_vec(&Grant { id, next: unit }).map_err(|e| e.to_string())?;
                    bytes.push(b'\n');
                    input.write_all(&bytes).await.map_err(|e| e.to_string())?;
                }
                Frame::Progress {
                    id,
                    checkpoint: next,
                } if ready
                    && feedback.unit_ready(next)
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
                    feedback.checkpoint(next)?;
                    drop(working.take());
                    let waiting = Instant::now();
                    working = Some(computation.enter().await);
                    feedback.pause(waiting.elapsed());
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
                        && feedback.finished()
                        && cleaned
                        && outstanding.is_none()
                        && id == record.id
                        && super::provider::complete(&record, checkpoint) =>
                {
                    output.validate(&record.input)?;
                    if let Output::Program { units } = &output
                        && *units != checkpoint
                    {
                        return Err(
                            "provider program length differs from its durable checkpoints".into(),
                        );
                    }
                    return Ok(output);
                }
                Frame::Uncertain { id, error } if ready && id == record.id => {
                    *disposition.lock().expect("provider disposition owner") = Some(State::InDoubt);
                    return Err(error);
                }
                Frame::Failed { id, error } if ready && id == record.id => {
                    return Err(error);
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
                | Frame::Feedback { id, .. }
                | Frame::Descendant { id, .. }
                | Frame::CpuActive { id, .. }
                | Frame::CpuDone { id, .. }
                | Frame::ResultReady { id }
                | Frame::Reserve { id, .. }
                | Frame::Progress { id, .. }
                | Frame::Result { id, .. }
                | Frame::Failed { id, .. }
                | Frame::Uncertain { id, .. }
                    if id == record.id => {}
                _ => return Err("provider cleanup identity differs".to_owned()),
            }
        }
    };
    let drain_error = match tokio::time::timeout(
        crate::resources::limits().provider_drain_timeout,
        drain,
    )
    .await
    {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some("provider output drain deadline".to_owned()),
    };
    let status = match tokio::time::timeout(
        crate::resources::limits().provider_drain_timeout,
        child.wait(),
    )
    .await
    {
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
            if self.partial.len() + end > max_frame_bytes() {
                return Err("provider frame capacity".into());
            }
            let complete = buffer[end - 1] == b'\n';
            self.partial.extend_from_slice(&buffer[..end]);
            self.reader.consume(end);
            if complete {
                let program = matches!(
                    serde_json::from_slice::<Frame>(&self.partial),
                    Ok(Frame::Program { .. })
                );
                self.total = self
                    .total
                    .checked_add(if program { 0 } else { self.partial.len() })
                    .ok_or("provider stream overflow")?;
                if self.total > crate::resources::limits().provider_stream_bytes {
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

fn emit(frame: &Frame) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(frame).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > max_frame_bytes() {
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
    let bytes = line(&mut reader, max_frame_bytes())?;
    let start: Start = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if start.version != 1
        || (start.remaining_ms == 0
            || Instant::now()
                .checked_add(Duration::from_millis(start.remaining_ms))
                .is_none())
    {
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
    let (sender, receiver) =
        sync_channel::sync_channel(crate::resources::active_limits().supervisor_commands);
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
        while let Ok(bytes) = line(&mut reader, max_frame_bytes()) {
            let program = matches!(
                serde_json::from_slice::<Frame>(&bytes),
                Ok(Frame::Program { .. })
            );
            total = total.saturating_add(if program { 0 } else { bytes.len() });
            if total > crate::resources::limits().provider_stream_bytes
                || sender.send(Message::Provider(bytes)).is_err()
            {
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
        match receiver.recv_timeout(crate::resources::limits().supervisor_poll_interval) {
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
            error: error
                .chars()
                .take(crate::resources::limits().failure_detail_bytes)
                .collect(),
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
        std::thread::sleep(crate::resources::limits().cleanup_poll_interval);
    }
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        match nix::sys::signal::killpg(group, None) {
            Err(nix::errno::Errno::ESRCH) => return Ok(()),
            Ok(()) | Err(nix::errno::Errno::EPERM) if Instant::now() < until => {
                std::thread::sleep(crate::resources::limits().cleanup_poll_interval)
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
    let start: Start = serde_json::from_slice(&line(&mut reader, max_frame_bytes())?)
        .map_err(|e| e.to_string())?;
    let record = start.record;
    record.input.validate()?;
    record.binding.validate()?;
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
    let mut provider = super::provider::select(&record)?;
    let mut owner = WorkerControl {
        id: record.id,
        receiver,
        descendants: Vec::new(),
        blocked_nanos: 0,
    };
    match super::provider::drive(provider.as_mut(), &mut owner, record.checkpoint) {
        Ok(output) => emit(&Frame::Result {
            id: record.id,
            output,
        }),
        Err(super::provider::Failure::Failed(error)) => emit(&Frame::Failed {
            id: record.id,
            error,
        }),
        Err(super::provider::Failure::Uncertain(error)) => emit(&Frame::Uncertain {
            id: record.id,
            error,
        }),
    }
}

struct WorkerControl {
    id: u64,
    receiver: sync_channel::Receiver<Vec<u8>>,
    descendants: Vec<Descendant>,
    blocked_nanos: u64,
}
impl WorkerControl {
    fn grant(&mut self, next: u32) -> Result<(), String> {
        let waiting = Instant::now();
        let bytes = self.receiver.recv();
        self.blocked_nanos = self
            .blocked_nanos
            .saturating_add(waiting.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
        let grant: Grant =
            serde_json::from_slice(&bytes.map_err(|_| "provider durable grant closed")?)
                .map_err(|e| e.to_string())?;
        if grant.id != self.id || grant.next != next {
            return Err("provider durable grant identity differs".into());
        }
        Ok(())
    }
}
impl super::provider::Supervisor for WorkerControl {
    fn blocked_nanos(&self) -> u64 {
        self.blocked_nanos
    }
    fn observe(&mut self, phase: Phase, sample: Sample) -> Result<(), String> {
        emit(&Frame::Feedback {
            id: self.id,
            phase,
            sample,
        })
    }
    fn program(
        &mut self,
        unit: u32,
        records: Vec<naome_proof::program::Command>,
    ) -> Result<(), String> {
        super::program::validate_group(&records)?;
        emit(&Frame::Program {
            id: self.id,
            unit,
            records,
        })?;
        self.grant(unit)
    }
    fn reserve(&mut self, next: u32) -> Result<(), String> {
        emit(&Frame::Reserve { id: self.id, next })?;
        self.grant(next)
    }
    fn checkpoint(&mut self, checkpoint: u32) -> Result<(), String> {
        emit(&Frame::Progress {
            id: self.id,
            checkpoint,
        })?;
        self.grant(checkpoint)
    }
    fn probe(&mut self, probe: super::provider::Probe) -> Result<(), String> {
        use super::provider::Probe;
        match probe {
            Probe::CpuActive(next) => emit(&Frame::CpuActive { id: self.id, next }),
            Probe::CpuDone(next) => emit(&Frame::CpuDone { id: self.id, next }),
            Probe::ResultReady => emit(&Frame::ResultReady { id: self.id }),
            Probe::Descendant => {
                let mut child =
                    ProcessCommand::new(std::env::current_exe().map_err(|e| e.to_string())?)
                        .arg(DESCENDANT)
                        .env(INTERNAL, "descendant-v1")
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .spawn()
                        .map_err(|e| e.to_string())?;
                let output = child.stdout.take().ok_or("descendant readiness absent")?;
                let child = Descendant(child);
                if line(&mut std::io::BufReader::new(output), 64)? != b"naome descendant ready v1\n"
                {
                    return Err("descendant readiness differs".into());
                }
                emit(&Frame::Descendant {
                    id: self.id,
                    pid: child.0.id(),
                })?;
                self.descendants.push(child);
                Ok(())
            }
        }
    }
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
mod tests;
