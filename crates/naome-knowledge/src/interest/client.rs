//! Isolate descriptor reception from the node; only bounded pipe bytes cross back.
use super::{host, ipc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{BufRead, Read, Write},
    os::unix::net::UnixStream,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

const INTERNAL: &str = "--interest-client-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    version: u8,
    client: String,
    support: host::Support,
    contract: String,
}

pub(crate) struct Live {
    state: Arc<Mutex<Option<host::State>>>,
    lifeline: Arc<Mutex<Option<ChildStdin>>>,
    stopped: Arc<AtomicBool>,
    owner: Option<JoinHandle<()>>,
    pub token: String,
}

impl Live {
    pub(crate) fn open() -> Result<Self, String> {
        let support = host::support()?;
        let expected = host::contract(&support)?;
        let token = host::nonce();
        let mut initial = serde_json::to_vec(&Start {
            version: 1,
            client: token.clone(),
            support,
            contract: expected.clone(),
        })
        .map_err(|e| e.to_string())?;
        initial.push(b'\n');
        if initial.len() > 4096 {
            return Err("interest client start byte limit".into());
        }
        let state = Arc::new(Mutex::new(None));
        let lifeline = Arc::new(Mutex::new(None));
        let stopped = Arc::new(AtomicBool::new(false));
        let current = state.clone();
        let lifetime = lifeline.clone();
        let stop = stopped.clone();
        let client = token.clone();
        let owner = std::thread::Builder::new().name("naome-interest-client".into()).spawn(move || {
            for repair in 0..=1 {
                if stop.load(Ordering::Acquire) { break; }
                let outcome = connection(&initial, &expected, &client, &current, &lifetime, &stop);
                if let Ok(mut current) = current.lock() { *current = None; }
                match lifetime.lock() {
                    Ok(mut current) => { current.take(); }
                    Err(poisoned) => { poisoned.into_inner().take(); }
                }
                if let Err(error) = &outcome {
                    crate::network::emit(json!({"event":"interest_host_unavailable","error":error,"repair":repair}));
                }
                if stop.load(Ordering::Acquire) || outcome.is_ok() { break; }
            }
        }).map_err(|e| e.to_string())?;
        Ok(Self {
            state,
            lifeline,
            stopped,
            owner: Some(owner),
            token,
        })
    }

    pub(crate) fn state(&self) -> Option<host::State> {
        self.state.lock().ok()?.clone()
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        match self.lifeline.lock() {
            Ok(mut current) => {
                current.take();
            }
            Err(poisoned) => {
                poisoned.into_inner().take();
            }
        }
        if let Some(owner) = self.owner.take() {
            let _ = owner.join();
        }
        if let Ok(mut current) = self.state.lock() {
            *current = None;
        }
    }
}

fn reap(child: &mut Child) -> Result<(), String> {
    // All signals target this still-unreaped Child. Even a stopped helper
    // must terminate; no saved PID is signalled after reaping.
    let kill = child.kill();
    let end = Instant::now() + Duration::from_secs(1);
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => {
                crate::network::emit(
                    json!({"event":"interest_client_reaped","pid":child.id(),"status":status.code()}),
                );
                return Ok(());
            }
            None if Instant::now() < end => std::thread::sleep(Duration::from_millis(2)),
            None => return Err(format!("interest client termination unconfirmed: {kill:?}")),
        }
    }
}

fn connection(
    initial: &[u8],
    expected: &str,
    client: &str,
    state: &Arc<Mutex<Option<host::State>>>,
    lifeline: &Arc<Mutex<Option<ChildStdin>>>,
    stop: &AtomicBool,
) -> Result<(), String> {
    let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg(INTERNAL)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = {
        let _spawn = crate::jobs::process::SPAWN
            .lock()
            .map_err(|_| "spawn owner poisoned")?;
        command.spawn().map_err(|e| e.to_string())?
    };
    crate::network::emit(
        json!({"event":"interest_client_started","pid":child.id(),"client":client}),
    );
    let outcome = (|| {
        let mut input = child
            .stdin
            .take()
            .ok_or("interest client lifeline absent")?;
        input.write_all(initial).map_err(|e| e.to_string())?;
        *lifeline
            .lock()
            .map_err(|_| "interest client lifeline poisoned")? = Some(input);
        let mut output = child.stdout.take().ok_or("interest client output absent")?;
        nix::fcntl::fcntl(
            &output,
            nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        )
        .map_err(|e| e.to_string())?;
        let mut buffer = Vec::new();
        let mut generation = None;
        let mut chunk = [0u8; 8192];
        let startup_end = Instant::now() + host::STARTUP;
        let mut last_frame = Instant::now();
        let mut ready = false;
        let mut partial_since = None;
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            if !ready && Instant::now() >= startup_end
                || ready && last_frame.elapsed() > Duration::from_secs(2)
                || partial_since.is_some_and(|at: Instant| at.elapsed() > Duration::from_secs(1))
            {
                return Err("interest client frame or liveness deadline".into());
            }
            match output.read(&mut chunk) {
                Ok(0) => return Err("interest client pipe EOF".into()),
                Ok(count) => buffer.extend_from_slice(&chunk[..count]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(e) => return Err(e.to_string()),
            }
            while buffer.len() >= 4 {
                let size = u32::from_be_bytes(buffer[..4].try_into().expect("header")) as usize;
                if size == 0 || size > ipc::LIMIT {
                    return Err("interest client frame byte limit".into());
                }
                if buffer.len() < size + 4 {
                    break;
                }
                let mut value: Value =
                    serde_json::from_slice(&buffer[4..size + 4]).map_err(|e| e.to_string())?;
                buffer.drain(..size + 4);
                last_frame = Instant::now();
                match value["kind"].as_str() {
                    Some("connected") if generation.is_none() && value["contract"] == expected => {
                        let id = value["generation"]
                            .as_str()
                            .ok_or("interest generation absent")?;
                        crate::object::id_bytes(id)?;
                        generation = Some(id.to_owned());
                    }
                    Some("ready")
                        if value["contract"] == expected
                            && value["generation"].as_str() == generation.as_deref()
                            && generation.is_some() =>
                    {
                        super::proxy::validate_ready(&value)?;
                        crate::network::emit(json!({"event":"interest_model_ready","model":value}));
                        if let Some(object) = value.as_object_mut() {
                            object.remove("tensor_inventory");
                        }
                        *state.lock().map_err(|_| "interest health owner poisoned")? =
                            Some(host::State {
                                generation: generation.clone().expect("connected"),
                                ready: value,
                            });
                        ready = true;
                    }
                    Some("stage") | Some("telemetry")
                        if generation.is_some()
                            && value["generation"].as_str() == generation.as_deref() =>
                    {
                        crate::network::emit(
                            json!({"event":"interest_model_observation","model":value}),
                        );
                    }
                    Some("attached") if generation.is_some() => {}
                    Some("failed") => {
                        crate::network::emit(
                            json!({"event":"interest_model_failed","model":value}),
                        );
                        return Err("resident model failed".into());
                    }
                    _ => return Err("interest client frame identity differs".into()),
                }
            }
            if buffer.len() > ipc::LIMIT + 4 {
                return Err("interest client partial frame byte limit".into());
            }
            if buffer.is_empty() {
                partial_since = None;
            } else if partial_since.is_none() {
                partial_since = Some(Instant::now());
            }
        }
    })();
    // Invalidate selection before teardown, including its bounded reap wait.
    let state_error = match state.lock() {
        Ok(mut current) => {
            *current = None;
            None
        }
        Err(_) => Some("interest health owner poisoned"),
    };
    let lifeline_error = match lifeline.lock() {
        Ok(mut current) => {
            current.take();
            None
        }
        Err(poisoned) => {
            // Recover only for destruction, never for usable selection.
            poisoned.into_inner().take();
            Some("interest client lifeline poisoned")
        }
    };
    let cleanup = reap(&mut child);
    let outcome = if state_error.is_some() || lifeline_error.is_some() {
        stop.store(true, Ordering::Release);
        Err(format!(
            "{}; {:?}; {:?}",
            outcome.err().unwrap_or_default(),
            state_error,
            lifeline_error
        ))
    } else {
        outcome
    };
    match (outcome, cleanup) {
        (result, Ok(())) => result,
        (result, Err(error)) => {
            // Unconfirmed helper custody never funds a replacement helper.
            stop.store(true, Ordering::Release);
            Err(format!("{}; {error}", result.err().unwrap_or_default()))
        }
    }
}

pub(super) fn receive_live(stream: &mut UnixStream) -> Result<Option<Value>, String> {
    // The native plain-read regression retained its borrowed lease. The
    // receiver therefore runs in the helper, never the node. Reported rights
    // close before forwarding bytes; hidden truncation ends only this helper.
    match ipc::receive(stream) {
        Ok((value, fds)) => {
            drop(fds);
            Ok(Some(value))
        }
        Err(error) if error == "interest receive timed out" => Ok(None),
        Err(error) => Err(error),
    }
}

fn forward(value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > ipc::LIMIT {
        return Err("interest client output byte limit".into());
    }
    let mut output = std::io::stdout().lock();
    output
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| output.write_all(&bytes))
        .and_then(|_| output.flush())
        .map_err(|e| e.to_string())
}

fn run() -> Result<(), String> {
    // Remain in this node's group: a daemon-group crash also stops a
    // suspended reader. A reader fault exits only this process, never gossip.
    let mut reader = std::io::BufReader::new(std::io::stdin());
    let mut initial = Vec::new();
    (&mut reader)
        .take(4097)
        .read_until(b'\n', &mut initial)
        .map_err(|e| e.to_string())?;
    if initial.len() > 4096 || !initial.ends_with(b"\n") {
        return Err("interest client initial frame bound".into());
    }
    let start: Start = serde_json::from_slice(&initial).map_err(|e| e.to_string())?;
    start.support.validate()?;
    if start.version != 1 || host::contract(&start.support)? != start.contract {
        return Err("interest client start binding differs".into());
    }
    crate::object::id_bytes(&start.client)?;
    std::thread::spawn(move || {
        let mut byte = [0u8; 1];
        while reader.read(&mut byte).is_ok_and(|count| count > 0) {}
        std::process::exit(125);
    });
    let root = host::namespace();
    host::private_root(&root)?;
    let end = Instant::now() + host::STARTUP;
    let (mut socket, endpoint) = loop {
        match host::connect(&root, &start.contract) {
            Ok(value) => break value,
            Err(_) => host::bootstrap(&root, &start.support, &start.contract)?,
        }
        if Instant::now() >= end {
            return Err("interest client startup deadline".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    forward(&json!({"kind":"connected","generation":endpoint.nonce,"contract":start.contract}))?;
    ipc::send(
        &mut socket,
        &json!({"kind":"attach","nonce":endpoint.nonce,"contract":start.contract,"client":start.client}),
        None,
    )?;
    loop {
        if let Some(value) = receive_live(&mut socket)? {
            forward(&value)?;
        }
    }
}

pub(super) fn internal(args: &[std::ffi::OsString]) -> Option<Result<(), String>> {
    (args.first().is_some_and(|arg| arg == INTERNAL)).then(|| {
        if args.len() != 1 {
            return Err("interest client arguments differ".into());
        }
        run()
    })
}
