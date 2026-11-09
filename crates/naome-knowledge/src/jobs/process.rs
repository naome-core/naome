//! The production parent lifeline is independent of synchronous provider work.
use super::*;
use crate::outcome::{JobFailureCode, WorkerFailure};
use std::{
    io::{BufRead, Write},
    os::fd::AsRawFd,
    process::{Child, Command as ProcessCommand, Stdio},
    sync::mpsc as sync_channel,
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
mod feedback;
mod model_bytes;
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

// Define the frame and both streaming codecs together so each numeric tag has
// one payload schema and decoding rejects unknown tags and fields.
macro_rules! worker_frames {
    ($( $variant:ident { $( $(#[$attr:meta])* $field:ident : $owned:ty => $borrowed:ty = $value:expr ),+ $(,)? } ),+ $(,)?) => {
        enum Frame { $( $variant { $( $field: $owned ),+ } ),+ }

        impl serde::Serialize for Frame {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeTuple;
                let mut tuple = serializer.serialize_tuple(2)?;
                match self {
                    $( Self::$variant { $( $field ),+ } => {
                        #[derive(serde::Serialize)]
                        struct Payload<'a> { $( $(#[$attr])* $field: &'a $borrowed ),+ }
                        tuple.serialize_element(&crate::outcome::WorkerFrame::$variant)?;
                        tuple.serialize_element(&Payload { $( $field: $value ),+ })?;
                    } ),+
                }
                tuple.end()
            }
        }

        impl<'de> serde::Deserialize<'de> for Frame {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct FrameVisitor;
                impl<'de> serde::de::Visitor<'de> for FrameVisitor {
                    type Value = Frame;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str("a tagged worker frame")
                    }
                    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Frame, A::Error> {
                        use serde::de::Error as _;
                        let tag: crate::outcome::WorkerFrame = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(0, &self))?;
                        let result = match tag {
                            $( crate::outcome::WorkerFrame::$variant => {
                                #[derive(serde::Deserialize)]
                                #[serde(deny_unknown_fields)]
                                struct Payload { $( $(#[$attr])* $field: $owned ),+ }
                                let payload: Payload = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(1, &self))?;
                                Frame::$variant { $( $field: payload.$field ),+ }
                            } ),+
                        };
                        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                            return Err(A::Error::invalid_length(3, &self));
                        }
                        Ok(result)
                    }
                }
                deserializer.deserialize_tuple(2, FrameVisitor)
            }
        }
    };
}

worker_frames! {
    History { id: u64 => u64 = id, unit: u32 => u32 = unit, request: crate::learning::history::Request => crate::learning::history::Request = request },
    Model { id: u64 => u64 = id, unit: u32 => u32 = unit, blob: crate::learning::Blob => crate::learning::Blob = blob, range: std::ops::Range<usize> => std::ops::Range<usize> = range, #[serde(with = "model_bytes")] bytes: Option<Vec<u8>> => Option<Vec<u8>> = bytes },
    Learning { id: u64 => u64 = id, unit: u32 => u32 = unit, progress: Box<crate::learning::Progress> => crate::learning::Progress = progress.as_ref() },
    Feedback { id: u64 => u64 = id, phase: Phase => Phase = phase, sample: Sample => Sample = sample },
    Ready { id: u64 => u64 = id, binding: String => String = binding, pid: u32 => u32 = pid },
    Descendant { id: u64 => u64 = id, pid: u32 => u32 = pid },
    CpuActive { id: u64 => u64 = id, next: u32 => u32 = next },
    CpuDone { id: u64 => u64 = id, next: u32 => u32 = next },
    ResultReady { id: u64 => u64 = id },
    Reserve { id: u64 => u64 = id, next: u32 => u32 = next },
    Program { id: u64 => u64 = id, unit: u32 => u32 = unit, records: String => String = records },
    Progress { id: u64 => u64 = id, checkpoint: u32 => u32 = checkpoint },
    Result { id: u64 => u64 = id, output: Output => Output = output },
    Failed { id: u64 => u64 = id, code: crate::outcome::JobFailureCode => crate::outcome::JobFailureCode = code },
    Uncertain { id: u64 => u64 = id },
    CleanupComplete { id: u64 => u64 = id },
    CleanupFailed { id: u64 => u64 = id },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    id: u64,
    next: u32,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "model_bytes")]
    data: Option<Vec<u8>>,
}

pub(super) enum Event {
    History {
        id: u64,
        unit: u32,
        request: crate::learning::history::Request,
        reply: oneshot::Sender<Result<crate::learning::history::Receipt, crate::Error>>,
    },
    Model {
        id: u64,
        unit: u32,
        blob: crate::learning::Blob,
        range: std::ops::Range<usize>,
        bytes: Option<Vec<u8>>,
        reply: oneshot::Sender<Result<Vec<u8>, crate::Error>>,
    },
    Learning {
        id: u64,
        unit: u32,
        progress: Box<crate::learning::Progress>,
        reply: oneshot::Sender<Result<(), crate::Error>>,
    },
    Program {
        id: u64,
        unit: u32,
        records: Vec<naome_proof::program::Command>,
        reply: oneshot::Sender<Result<(), crate::Error>>,
    },
    Reserve {
        id: u64,
        next: u32,
        reply: oneshot::Sender<Result<(), crate::Error>>,
    },
    Progress {
        id: u64,
        checkpoint: u32,
        reply: oneshot::Sender<Result<(), crate::Error>>,
    },
}

pub(super) struct Outcome {
    pub state: State,
    pub result: Result<Output, JobFailureCode>,
}

struct OwnedAttempt {
    disposition: std::sync::Mutex<Option<State>>,
    feedback: feedback::Attempt,
    failure: Option<WorkerFailure>,
}

pub(super) async fn run(
    record: Record,
    remaining_ms: u64,
    events: mpsc::Sender<Event>,
    cancel: oneshot::Receiver<()>,
    slot: std::fs::File,
    computation: crate::resources::ComputationPermit,
) -> Outcome {
    let mut attempt = OwnedAttempt {
        disposition: std::sync::Mutex::new(None),
        feedback: feedback::Attempt::new(record.input.feedback_role()),
        failure: None,
    };
    let result = run_owned(
        record,
        remaining_ms,
        events,
        cancel,
        slot,
        computation,
        &mut attempt,
    )
    .await;
    let state = attempt
        .disposition
        .lock()
        .expect("provider disposition owner")
        .unwrap_or(if result.is_ok() {
            State::Complete
        } else {
            State::Failed
        });
    attempt.feedback.finish(state);
    let result = result.map_err(|error| attempt.failure.map(JobFailureCode::from).unwrap_or(error));
    Outcome { state, result }
}

async fn run_owned(
    record: Record,
    remaining_ms: u64,
    events: mpsc::Sender<Event>,
    mut cancel: oneshot::Receiver<()>,
    slot: std::fs::File,
    permit: crate::resources::ComputationPermit,
    attempt: &mut OwnedAttempt,
) -> Result<Output, JobFailureCode> {
    let disposition = &attempt.disposition;
    let feedback = &mut attempt.feedback;
    let failure = &mut attempt.failure;
    let remaining_ms = remaining_ms.min(
        record
            .expires_ms
            .saturating_sub(wall_ms().map_err(|_| WorkerFailure::Clock)?),
    );
    if remaining_ms == 0 {
        *disposition.lock().expect("provider disposition owner") = Some(State::Expired);
        return Err(WorkerFailure::Deadline.into());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_millis(remaining_ms);
    // This is the only deliberately inherited descriptor besides stdio. It is
    // a resource lease, never accepted-store or identity custody. Keeping it in
    // every descendant prevents a restarted node from reusing a live slot.
    let mut command = tokio::process::Command::new(
        std::env::current_exe().map_err(|_| WorkerFailure::SupervisorExecutable)?,
    );
    command
        .arg(SUPERVISOR)
        .env_clear()
        .env(INTERNAL, "supervisor-v1")
        .env(
            "NAOME_EFFECTIVE_RESOURCES",
            crate::resources::child_snapshot().map_err(|_| WorkerFailure::ResourceSnapshot)?,
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
    .map_err(|_| WorkerFailure::StartEncoding)?;
    start.push(b'\n');
    let (spawned, restored) = {
        let _spawn = SPAWN.lock().map_err(|_| WorkerFailure::SpawnLock)?;
        nix::fcntl::fcntl(
            &slot,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .map_err(|_| WorkerFailure::SlotInheritance)?;
        let spawned = command.spawn();
        let restored = nix::fcntl::fcntl(
            &slot,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        );
        (spawned, restored)
    };
    let mut child = spawned.map_err(|_| WorkerFailure::SupervisorSpawn)?;
    *disposition.lock().expect("provider disposition owner") = Some(State::InDoubt);
    if restored.is_err() {
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
                .map_err(|_| WorkerFailure::SlotInheritance)?;
            child
                .wait()
                .await
                .map_err(|_| WorkerFailure::SlotInheritance)?;
        }
        return Err(WorkerFailure::SlotInheritance.into());
    }
    let pid = child.id().ok_or(WorkerFailure::SupervisorIdentity)?;
    crate::network::emit(
        serde_json::json!({"event":crate::outcome::NodeEvent::ResearchStarted,"job":record.id,
        "provider":record.provider,"pid":pid,"lane":record.input.lane(),"remaining_ms":remaining_ms}),
    );
    let mut input = child
        .stdin
        .take()
        .ok_or(WorkerFailure::LifelineUnavailable)?;
    let output = child
        .stdout
        .take()
        .ok_or(WorkerFailure::OutputUnavailable)?;
    let mut reader = FrameReader::new(output);
    let mut cleaned = false;
    let mut start_delivered = false;
    let computation = permit.owner();
    let mut working = Some(permit);
    let execution = async {
        input
            .write_all(&start)
            .await
            .map_err(|_| WorkerFailure::PipeIo)?;
        start_delivered = true;
        let mut ready = false;
        let mut checkpoint = record.checkpoint;
        let mut outstanding = None;
        loop {
            let bytes = reader.next().await?.ok_or(WorkerFailure::FrameTruncated)?;
            let frame: Frame =
                serde_json::from_slice(&bytes).map_err(|_| WorkerFailure::FrameEncoding)?;
            match frame {
                Frame::Ready { id, binding, pid }
                    if !ready && id == record.id && binding == identity(&record) =>
                {
                    ready = true;
                    crate::network::emit(
                        serde_json::json!({"event":crate::outcome::NodeEvent::ResearchWorker,"job":id,"pid":pid}),
                    );
                }
                Frame::Descendant { id, pid }
                    if ready && id == record.id && record.settings.mock.descendant =>
                {
                    crate::network::emit(
                        serde_json::json!({"event":crate::outcome::NodeEvent::ResearchDescendant,"job":id,"pid":pid}),
                    );
                }
                Frame::CpuActive { id, next }
                    if ready && id == record.id && outstanding == Some(next) =>
                {
                    crate::network::emit(
                        serde_json::json!({"event":crate::outcome::NodeEvent::ResearchWorking,"job":id,"phase":crate::outcome::WorkerFrame::CpuActive,"next":next}),
                    );
                }
                Frame::CpuDone { id, next }
                    if ready && id == record.id && outstanding == Some(next) =>
                {
                    crate::network::emit(
                        serde_json::json!({"event":crate::outcome::NodeEvent::ResearchWorking,"job":id,"phase":crate::outcome::WorkerFrame::CpuDone,"next":next}),
                    );
                }
                Frame::ResultReady { id } if ready && id == record.id && outstanding.is_none() => {
                    crate::network::emit(
                        serde_json::json!({"event":crate::outcome::NodeEvent::ResearchWorking,"job":id,"phase":crate::outcome::WorkerFrame::ResultReady}),
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
                                .ok_or(WorkerFailure::CheckpointOverflow)? =>
                {
                    drop(working.take());
                    feedback.wait();
                    working = Some(computation.enter().await);
                    feedback.resume();
                    let (reply, receipt) = oneshot::channel();
                    events
                        .send(Event::Reserve { id, next, reply })
                        .await
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?;
                    receipt
                        .await
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?
                        .map_err(|error| JobFailureCode::from_owner(&error))?;
                    let mut bytes = serde_json::to_vec(&Grant {
                        id,
                        next,
                        data: None,
                    })
                    .map_err(|_| WorkerFailure::GrantEncoding)?;
                    bytes.push(b'\n');
                    input
                        .write_all(&bytes)
                        .await
                        .map_err(|_| WorkerFailure::PipeIo)?;
                    outstanding = Some(next);
                }
                Frame::History { id, unit, request }
                    if ready
                        && id == record.id
                        && unit == 1
                        && outstanding == Some(unit)
                        && record.provider == crate::learning::PROVIDER =>
                {
                    let (reply, receipt) = oneshot::channel();
                    events
                        .send(Event::History {
                            id,
                            unit,
                            request,
                            reply,
                        })
                        .await
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?;
                    let receipt = receipt
                        .await
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?
                        .map_err(|error| JobFailureCode::from_owner(&error))?;
                    let mut response = serde_json::to_vec(&Grant {
                        id,
                        next: unit,
                        data: Some(
                            serde_json::to_vec(&receipt)
                                .map_err(|_| WorkerFailure::GrantEncoding)?,
                        ),
                    })
                    .map_err(|_| WorkerFailure::GrantEncoding)?;
                    response.push(b'\n');
                    input
                        .write_all(&response)
                        .await
                        .map_err(|_| WorkerFailure::PipeIo)?;
                }
                Frame::Model {
                    id,
                    unit,
                    blob,
                    range,
                    bytes,
                } if ready
                    && id == record.id
                    && outstanding == Some(unit)
                    && record.provider == crate::learning::PROVIDER =>
                {
                    let length = blob
                        .range_len(&range)
                        .map_err(|error| JobFailureCode::from_owner(&error))?;
                    if let Some(bytes) = &bytes
                        && bytes.len() != length
                    {
                        return Err(WorkerFailure::ModelLength.into());
                    }
                    let (reply, receipt) = oneshot::channel();
                    events
                        .send(Event::Model {
                            id,
                            unit,
                            blob,
                            range,
                            bytes,
                            reply,
                        })
                        .await
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?;
                    let data = receipt
                        .await
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?
                        .map_err(|error| JobFailureCode::from_owner(&error))?;
                    let mut response = serde_json::to_vec(&Grant {
                        id,
                        next: unit,
                        data: Some(data),
                    })
                    .map_err(|_| WorkerFailure::GrantEncoding)?;
                    response.push(b'\n');
                    input
                        .write_all(&response)
                        .await
                        .map_err(|_| WorkerFailure::PipeIo)?;
                }
                Frame::Learning { id, unit, progress }
                    if ready
                        && id == record.id
                        && outstanding == Some(unit)
                        && record.provider == crate::learning::PROVIDER =>
                {
                    let (reply, receipt) = oneshot::channel();
                    events
                        .send(Event::Learning {
                            id,
                            unit,
                            progress,
                            reply,
                        })
                        .await
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?;
                    receipt
                        .await
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?
                        .map_err(|error| JobFailureCode::from_owner(&error))?;
                    let mut bytes = serde_json::to_vec(&Grant {
                        id,
                        next: unit,
                        data: None,
                    })
                    .map_err(|_| WorkerFailure::GrantEncoding)?;
                    bytes.push(b'\n');
                    input
                        .write_all(&bytes)
                        .await
                        .map_err(|_| WorkerFailure::PipeIo)?;
                }
                Frame::Program { id, unit, records }
                    if ready
                        && id == record.id
                        && outstanding == Some(unit)
                        && matches!(record.input, Input::Solve { .. }) =>
                {
                    if records.len() > naome_proof::program::CHUNK_BYTES * 2 {
                        return Err(WorkerFailure::ProgramCapacity.into());
                    }
                    let bytes =
                        crate::unhex(&records).map_err(|_| WorkerFailure::ProgramEncoding)?;
                    if crate::hex(&bytes) != records {
                        return Err(WorkerFailure::ProgramEncoding.into());
                    }
                    let records = naome_proof::program::decode_records(&bytes)
                        .map_err(|_| WorkerFailure::ProgramEncoding)?;
                    let (reply, receipt) = oneshot::channel();
                    events
                        .send(Event::Program {
                            id,
                            unit,
                            records,
                            reply,
                        })
                        .await
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?;
                    receipt
                        .await
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?
                        .map_err(|error| JobFailureCode::from_owner(&error))?;
                    let mut bytes = serde_json::to_vec(&Grant {
                        id,
                        next: unit,
                        data: None,
                    })
                    .map_err(|_| WorkerFailure::GrantEncoding)?;
                    bytes.push(b'\n');
                    input
                        .write_all(&bytes)
                        .await
                        .map_err(|_| WorkerFailure::PipeIo)?;
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
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?;
                    receipt
                        .await
                        .map_err(|_| WorkerFailure::OwnerUnavailable)?
                        .map_err(|error| JobFailureCode::from_owner(&error))?;
                    feedback.checkpoint(next)?;
                    drop(working.take());
                    feedback.wait();
                    working = Some(computation.enter().await);
                    feedback.resume();
                    let mut bytes = serde_json::to_vec(&Grant {
                        id,
                        next: checkpoint,
                        data: None,
                    })
                    .map_err(|_| WorkerFailure::GrantEncoding)?;
                    bytes.push(b'\n');
                    input
                        .write_all(&bytes)
                        .await
                        .map_err(|_| WorkerFailure::PipeIo)?;
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
                    output
                        .validate(&record.input)
                        .map_err(|error| JobFailureCode::from_owner(&error))?;
                    if let Output::Program { units } = &output
                        && *units != checkpoint
                    {
                        return Err(WorkerFailure::ResultInvalid.into());
                    }
                    return Ok::<Output, JobFailureCode>(output);
                }
                Frame::Uncertain { id } if ready && id == record.id => {
                    *failure = Some(WorkerFailure::ProviderUncertain);
                    *disposition.lock().expect("provider disposition owner") = Some(State::InDoubt);
                    return Err(WorkerFailure::ProviderUncertain.into());
                }
                Frame::Failed { id, code } if ready && id == record.id => {
                    return Err(code);
                }
                Frame::CleanupFailed { id } if id == record.id => {
                    *failure = Some(WorkerFailure::CleanupUnconfirmed);
                    *disposition.lock().expect("provider disposition owner") = Some(State::InDoubt);
                    return Err(WorkerFailure::CleanupUnconfirmed.into());
                }
                _ => return Err(WorkerFailure::FrameIdentity.into()),
            }
        }
    };
    let result = tokio::select! {
        value=execution=>value,
        _=&mut cancel=>{*disposition.lock().expect("provider disposition owner")=Some(State::Cancelled);Err(WorkerFailure::Cancelled.into())},
        _=tokio::time::sleep_until(deadline)=>{*disposition.lock().expect("provider disposition owner")=Some(State::Expired);Err(WorkerFailure::Deadline.into())},
    };
    // Cancellation or expiry can drop the admission wait before it receives a
    // permit. Close that measurement before custody drain and child reaping.
    feedback.resume();
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
                return Ok::<(), JobFailureCode>(());
            };
            match serde_json::from_slice::<Frame>(&frame)
                .map_err(|_| WorkerFailure::FrameEncoding)?
            {
                Frame::CleanupComplete { id } if id == record.id => cleaned = true,
                Frame::CleanupFailed { id } if id == record.id => {
                    cleaned = false;
                    return Err(WorkerFailure::CleanupUnconfirmed.into());
                }
                Frame::Ready { id, .. }
                | Frame::Feedback { id, .. }
                | Frame::Descendant { id, .. }
                | Frame::CpuActive { id, .. }
                | Frame::CpuDone { id, .. }
                | Frame::ResultReady { id }
                | Frame::Reserve { id, .. }
                | Frame::Progress { id, .. }
                | Frame::Model { id, .. }
                | Frame::History { id, .. }
                | Frame::Learning { id, .. }
                | Frame::Result { id, .. }
                | Frame::Failed { id, .. }
                | Frame::Uncertain { id, .. }
                    if id == record.id => {}
                _ => return Err(WorkerFailure::FrameIdentity.into()),
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
        Err(_) => Some(WorkerFailure::OutputDrainDeadline.into()),
    };
    let status = match tokio::time::timeout(
        crate::resources::limits().provider_drain_timeout,
        child.wait(),
    )
    .await
    {
        Ok(status) => status.map_err(|_| WorkerFailure::PipeIo)?,
        Err(_) => {
            child.start_kill().map_err(|_| WorkerFailure::PipeIo)?;
            child.wait().await.map_err(|_| WorkerFailure::PipeIo)?;
            *disposition.lock().expect("provider disposition owner") = Some(State::InDoubt);
            return Err(WorkerFailure::CleanupUnconfirmed.into());
        }
    };
    crate::network::emit(
        serde_json::json!({"event":crate::outcome::NodeEvent::ResearchReaped,"job":record.id,"pid":pid,"exit":status.code()}),
    );
    // An incomplete Start cannot create a worker. When cancellation closed its
    // lifeline before any complete Start or output frame, reaped supervisor
    // exit is sufficient: no provider group was ever created.
    if !start_delivered && reader.total == 0 && drain_error.is_none() {
        cleaned = true;
    }
    if !cleaned {
        *failure = Some(WorkerFailure::CleanupUnconfirmed);
        *disposition.lock().expect("provider disposition owner") = Some(State::InDoubt);
        return Err(WorkerFailure::CleanupUnconfirmed.into());
    }
    // A cleanup receipt confirms process custody. It cannot confirm effects
    // reported as uncertain by the worker.
    *disposition.lock().expect("provider disposition owner") =
        if *failure == Some(WorkerFailure::ProviderUncertain) {
            Some(State::InDoubt)
        } else {
            completion_state.filter(|state| *state != State::InDoubt)
        };
    if let Some(error) = drain_error {
        return Err(result.err().unwrap_or(error));
    }
    if result.is_ok() && !status.success() {
        return Err(WorkerFailure::SupervisorExit.into());
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

    async fn next(&mut self) -> Result<Option<Vec<u8>>, WorkerFailure> {
        loop {
            let buffer = self
                .reader
                .fill_buf()
                .await
                .map_err(|_| WorkerFailure::PipeIo)?;
            if buffer.is_empty() {
                return if self.partial.is_empty() {
                    Ok(None)
                } else {
                    Err(WorkerFailure::FrameTruncated)
                };
            }
            let end = buffer
                .iter()
                .position(|b| *b == b'\n')
                .map(|n| n + 1)
                .unwrap_or(buffer.len());
            if self.partial.len() + end > max_frame_bytes() {
                return Err(WorkerFailure::FrameCapacity);
            }
            let complete = buffer[end - 1] == b'\n';
            self.partial.extend_from_slice(&buffer[..end]);
            self.reader.consume(end);
            if complete {
                let program = matches!(
                    serde_json::from_slice::<Frame>(&self.partial),
                    Ok(Frame::Program { .. } | Frame::Model { .. })
                );
                self.total = self
                    .total
                    .checked_add(if program { 0 } else { self.partial.len() })
                    .ok_or(WorkerFailure::StreamCapacity)?;
                if self.total > crate::resources::limits().provider_stream_bytes {
                    return Err(WorkerFailure::StreamCapacity);
                }
                return Ok(Some(std::mem::take(&mut self.partial)));
            }
        }
    }
}

pub(super) fn internal(arguments: &[std::ffi::OsString]) -> Option<Result<(), crate::Error>> {
    let [argument] = arguments else {
        return None;
    };
    match argument.to_str()? {
        SUPERVISOR => Some(
            if std::env::var(INTERNAL).as_deref() == Ok("supervisor-v1") {
                supervise()
            } else {
                Err(crate::ResearchFailure::ProviderInvocationRequired.into())
            },
        ),
        WORKER => Some(if std::env::var(INTERNAL).as_deref() == Ok("worker-v1") {
            work()
        } else {
            Err(crate::ResearchFailure::ProviderInvocationRequired.into())
        }),
        DESCENDANT => Some(
            if std::env::var(INTERNAL).as_deref() == Ok("descendant-v1") {
                descendant()
            } else {
                Err(crate::ResearchFailure::ProviderInvocationRequired.into())
            },
        ),
        _ => None,
    }
}

fn line(reader: &mut impl BufRead, limit: usize) -> Result<Vec<u8>, crate::Error> {
    let mut bytes = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Err(WorkerFailure::FrameTruncated.into());
        }
        let end = buffer
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(buffer.len());
        if bytes.len().checked_add(end).is_none_or(|size| size > limit) {
            return Err(crate::Error::ResearchMismatch {
                code: crate::ResearchFailure::ProviderPipeCapacity,
                expected: limit as u64,
                actual: bytes.len().saturating_add(end) as u64,
            });
        }
        let complete = buffer[end - 1] == b'\n';
        bytes.extend_from_slice(&buffer[..end]);
        reader.consume(end);
        if complete {
            return Ok(bytes);
        }
    }
}

fn emit(frame: &Frame) -> Result<(), crate::Error> {
    emit_coded(frame).map_err(Into::into)
}

fn emit_coded(frame: &Frame) -> Result<(), WorkerFailure> {
    let mut bytes = serde_json::to_vec(frame).map_err(|_| WorkerFailure::FrameEncoding)?;
    bytes.push(b'\n');
    if bytes.len() > max_frame_bytes() {
        return Err(WorkerFailure::FrameCapacity);
    }
    std::io::stdout()
        .write_all(&bytes)
        .and_then(|_| std::io::stdout().flush())
        .map_err(|_| WorkerFailure::PipeIo)
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
    fn finish(&mut self) -> Result<(), crate::Error> {
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

fn supervise() -> Result<(), crate::Error> {
    // The supervisor is the session/group leader. It stays alive during normal
    // cancellation so the group cannot be confused with a recycled PID.
    nix::unistd::setsid().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let mut reader = std::io::BufReader::new(std::io::stdin());
    let bytes = line(&mut reader, max_frame_bytes())?;
    let start: Start = serde_json::from_slice(&bytes)
        .map_err(|_| crate::ResearchFailure::ProviderStartDecoding)?;
    if start.version != 1
        || (start.remaining_ms == 0
            || Instant::now()
                .checked_add(Duration::from_millis(start.remaining_ms))
                .is_none())
    {
        return Err(crate::ResearchFailure::ProviderStartInvalid.into());
    }
    start.record.input.validate()?;
    start.record.binding.validate()?;
    let child = ProcessCommand::new(std::env::current_exe()?)
        .arg(WORKER)
        .env(INTERNAL, "worker-v1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut child = Worker {
        child,
        teardown_started: false,
    };
    let mut input = child
        .child
        .stdin
        .take()
        .ok_or(crate::ResearchFailure::ProviderWorkerInputMissing)?;
    input.write_all(&bytes)?;
    let output = child
        .child
        .stdout
        .take()
        .ok_or(crate::ResearchFailure::ProviderWorkerOutputMissing)?;
    let (sender, receiver) =
        sync_channel::sync_channel(crate::resources::active_limits().supervisor_commands);
    let parent = sender.clone();
    std::thread::spawn(move || {
        loop {
            match line(
                &mut reader,
                crate::resources::limits().native_model_chunk_bytes * 5 + 1024,
            ) {
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
                Ok(Frame::Program { .. } | Frame::Model { .. })
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
            .map_err(Into::into)
    } else {
        Err(crate::ResearchFailure::ProviderStopped.into())
    }
}

fn process_error(code: crate::ResearchFailure, error: std::io::Error) -> crate::Error {
    let cause = crate::Error::Io {
        kind: crate::outcome::io_fault_kind(&error),
        os_code: error.raw_os_error().and_then(std::num::NonZeroI32::new),
    };
    crate::Error::ResearchContext {
        code,
        cause: Box::new(cause),
    }
}

fn combine_cleanup(primary: crate::Error, errors: &[crate::Error]) -> crate::Error {
    errors
        .iter()
        .cloned()
        .fold(primary, |primary, cleanup| crate::Error::ResearchCombined {
            primary: Box::new(primary),
            cleanup: Box::new(cleanup),
        })
}

fn stop_worker(child: &mut Child) -> Result<(), crate::Error> {
    // Hold the live unreaped Child while signalling its separate provider group.
    // A pre-start cancellation may precede setsid; direct Child.kill covers it.
    let group = nix::unistd::Pid::from_raw(
        i32::try_from(child.id()).map_err(|_| crate::ResearchFailure::ProviderPidOverflow)?,
    );
    let mut signal_errors = Vec::new();
    match nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGTERM) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
        // Darwin skips zombies when signalling a group and can return EPERM
        // for a zombie-only group. Retain the denial until actual absence is
        // observed after reaping; a denial alone never confirms cleanup.
        Err(error) => signal_errors.push(process_error(
            crate::ResearchFailure::ProviderTermSignal,
            std::io::Error::from_raw_os_error(error as i32),
        )),
    }
    // Rust's portable Child API reaps on try_wait. Keep the leader unreaped
    // through both signals instead, including when it exits during this grace.
    std::thread::sleep(Duration::from_millis(300));
    // Stop the original leader before the last group signal. This also covers
    // early cancellation while the worker is still creating its own group.
    if let Err(error) = child.kill() {
        signal_errors.push(process_error(
            crate::ResearchFailure::ProviderChildKill,
            error,
        ));
    }
    // Retain the unreaped leader through the final group signal. Its PID
    // cannot be recycled while we own this Child, even after its exit.
    match nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
        Err(error) => signal_errors.push(process_error(
            crate::ResearchFailure::ProviderKillSignal,
            std::io::Error::from_raw_os_error(error as i32),
        )),
    }
    // All signals are finished before any reaping can release the leader PID.
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        if child
            .try_wait()
            .map_err(|e| {
                combine_cleanup(
                    process_error(crate::ResearchFailure::ProviderWaitFailed, e),
                    &signal_errors,
                )
            })?
            .is_some()
        {
            break;
        }
        if Instant::now() >= until {
            return Err(combine_cleanup(
                crate::ResearchFailure::ProviderReapDeadline.into(),
                &signal_errors,
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
            result => {
                if let Err(error) = result {
                    signal_errors.push(process_error(
                        crate::ResearchFailure::ProviderGroupProbe,
                        std::io::Error::from_raw_os_error(error as i32),
                    ));
                }
                return Err(combine_cleanup(
                    crate::ResearchFailure::ProviderGroupUnconfirmed.into(),
                    &signal_errors,
                ));
            }
        }
    }
}

fn work() -> Result<(), crate::Error> {
    nix::unistd::setsid().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let mut reader = std::io::BufReader::new(std::io::stdin());
    let start: Start = serde_json::from_slice(&line(&mut reader, max_frame_bytes())?)
        .map_err(|_| crate::ResearchFailure::ProviderStartDecoding)?;
    let record = start.record;
    record.input.validate()?;
    record.binding.validate()?;
    let (sender, receiver) = sync_channel::sync_channel(1);
    // A lost supervisor closes this pipe. This dedicated lifeline reader can
    // still stop the group while the provider main thread is doing CPU work.
    std::thread::spawn(move || {
        loop {
            match line(
                &mut reader,
                crate::resources::limits().native_model_chunk_bytes * 5 + 1024,
            ) {
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
        current_unit: record.checkpoint,
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
        Err(super::provider::Failure::Failed) => emit(&Frame::Failed {
            id: record.id,
            code: WorkerFailure::ProviderRejected.into(),
        }),
        Err(super::provider::Failure::Coded(code)) => emit(&Frame::Failed {
            id: record.id,
            code,
        }),
        Err(super::provider::Failure::Uncertain) => emit(&Frame::Uncertain { id: record.id }),
    }
}

struct WorkerControl {
    id: u64,
    current_unit: u32,
    receiver: sync_channel::Receiver<Vec<u8>>,
    descendants: Vec<Descendant>,
    blocked_nanos: u64,
}
impl WorkerControl {
    fn grant_data(&mut self, next: u32) -> Result<Option<Vec<u8>>, WorkerFailure> {
        let waiting = Instant::now();
        let bytes = self.receiver.recv();
        self.blocked_nanos = self
            .blocked_nanos
            .saturating_add(waiting.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
        let grant: Grant = serde_json::from_slice(&bytes.map_err(|_| WorkerFailure::GrantClosed)?)
            .map_err(|_| WorkerFailure::GrantDecoding)?;
        if grant.id != self.id || grant.next != next {
            return Err(WorkerFailure::GrantIdentity);
        }
        Ok(grant.data)
    }
    fn grant(&mut self, next: u32) -> Result<(), WorkerFailure> {
        self.grant_data(next).map(|_| ())
    }
}
impl super::provider::Supervisor for WorkerControl {
    fn external_history_cpu(&self) -> bool {
        true
    }

    fn history(
        &mut self,
        request: &crate::learning::history::Request,
    ) -> Result<crate::learning::history::Receipt, crate::Error> {
        emit_coded(&Frame::History {
            id: self.id,
            unit: self.current_unit,
            request: request.clone(),
        })?;
        serde_json::from_slice(
            &self
                .grant_data(self.current_unit)?
                .ok_or(WorkerFailure::HistoryReceiptMissing)?,
        )
        .map_err(|_| WorkerFailure::HistoryReceiptDecoding.into())
    }
    fn read_model(
        &mut self,
        blob: crate::learning::Blob,
        range: std::ops::Range<usize>,
    ) -> Result<Vec<u8>, crate::Error> {
        emit_coded(&Frame::Model {
            id: self.id,
            unit: self.current_unit,
            blob,
            range,
            bytes: None,
        })?;
        Ok(self
            .grant_data(self.current_unit)?
            .ok_or(WorkerFailure::ModelResponseMissing)?)
    }
    fn write_model(
        &mut self,
        blob: crate::learning::Blob,
        range: std::ops::Range<usize>,
        bytes: Vec<u8>,
    ) -> Result<(), crate::Error> {
        emit_coded(&Frame::Model {
            id: self.id,
            unit: self.current_unit,
            blob,
            range,
            bytes: Some(bytes),
        })?;
        Ok(self.grant(self.current_unit)?)
    }
    fn learning(
        &mut self,
        unit: u32,
        progress: crate::learning::Progress,
    ) -> Result<(), WorkerFailure> {
        emit_coded(&Frame::Learning {
            id: self.id,
            unit,
            progress: Box::new(progress),
        })?;
        self.grant(unit)
    }
    fn blocked_nanos(&self) -> u64 {
        self.blocked_nanos
    }
    fn observe(&mut self, phase: Phase, sample: Sample) -> Result<(), WorkerFailure> {
        emit_coded(&Frame::Feedback {
            id: self.id,
            phase,
            sample,
        })
    }
    fn program(
        &mut self,
        unit: u32,
        records: Vec<naome_proof::program::Command>,
    ) -> Result<(), WorkerFailure> {
        let records = crate::hex(
            &naome_proof::program::encode_records(&records)
                .map_err(|_| WorkerFailure::ProgramEncoding)?,
        );
        emit_coded(&Frame::Program {
            id: self.id,
            unit,
            records,
        })?;
        self.grant(unit)
    }
    fn reserve(&mut self, next: u32) -> Result<(), WorkerFailure> {
        emit_coded(&Frame::Reserve { id: self.id, next })?;
        self.grant(next)?;
        self.current_unit = next;
        Ok(())
    }
    fn checkpoint(&mut self, checkpoint: u32) -> Result<(), WorkerFailure> {
        emit_coded(&Frame::Progress {
            id: self.id,
            checkpoint,
        })?;
        self.grant(checkpoint)
    }
    fn probe(&mut self, probe: super::provider::Probe) -> Result<(), WorkerFailure> {
        use super::provider::Probe;
        match probe {
            Probe::CpuActive(next) => emit_coded(&Frame::CpuActive { id: self.id, next }),
            Probe::CpuDone(next) => emit_coded(&Frame::CpuDone { id: self.id, next }),
            Probe::ResultReady => emit_coded(&Frame::ResultReady { id: self.id }),
            Probe::Descendant => {
                let mut child = ProcessCommand::new(
                    std::env::current_exe().map_err(|_| WorkerFailure::DescendantExecutable)?,
                )
                .arg(DESCENDANT)
                .env(INTERNAL, "descendant-v1")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| WorkerFailure::DescendantSpawn)?;
                let output = child.stdout.take().ok_or(WorkerFailure::DescendantOutput)?;
                let child = Descendant(child);
                if line(&mut std::io::BufReader::new(output), 64)
                    .map_err(|_| WorkerFailure::DescendantRead)?
                    != b"naome descendant ready v1\n"
                {
                    return Err(WorkerFailure::DescendantIdentity);
                }
                emit_coded(&Frame::Descendant {
                    id: self.id,
                    pid: child.0.id(),
                })?;
                self.descendants.push(child);
                Ok(())
            }
        }
    }
}

fn descendant() -> Result<(), crate::Error> {
    // Stay in the worker's owned group and retain the inherited kernel slot.
    // A safe Tokio signal registration makes TERM non-cooperative; KILL must
    // still terminate this finite developer stand-in with its whole group.
    std::thread::spawn(|| -> Result<(), crate::Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            std::io::stdout()
                .write_all(b"naome descendant ready v1\n")
                .and_then(|_| std::io::stdout().flush())?;
            while terminate.recv().await.is_some() {}
            Err(crate::ResearchFailure::DescendantSignalEnded.into())
        })
    })
    .join()
    .map_err(|_| crate::ResearchFailure::DescendantOwnerPanic)?
}

#[cfg(test)]
mod tests;
