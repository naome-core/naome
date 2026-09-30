//! Offline process checks use a small Rust fixture, never the native host.

use naome_research::host_proxy::HostProxyConfig;
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HELLO: &str = r#"{ "type": "connection/hello", "supportedVersions": [1], "requiredCapabilities": [], "optionalCapabilities": [] }"#;
const READY: &str = r#"{ "type": "connection/ready", "selectedVersion": 1, "capabilities": [] }"#;
const OPEN: &str =
    r#"{"type":"operation/request","id":1,"request":{"method":"session/open","sessionId":"s1"}}"#;
const OPENED: &str = r#"{"type":"operation/response","id":1,"result":{"status":"ok","value":{"type":"session/ready","sessionId":"s1"}}}"#;
const STARTED: &str = r#"{"type":"operation/response","id":2,"result":{"status":"ok","value":{"type":"execution/started","cellId":"cell-1"}}}"#;
const RESULT: &str = r#"{ "type": "execute/initialResponse", "id": 2, "result": {"status":"ok","value":{"Result":{"cell_id":"cell-1","content_items":[{"type":"input_text","text":"42"}],"error_text":null,"code_mode_host_duration_ns":0}}} }"#;
const CLOSED: &str = r#"{"type":"cell/closed","sessionId":"s1","cellId":"cell-1"}"#;

fn test_dir(label: &str) -> PathBuf {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "naome-host-proxy-{label}-{}-{nanos}-{serial}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn fake_host() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            let directory = test_dir("fixture");
            let source = directory.join("fixture.rs");
            let binary = directory.join(if cfg!(windows) {
                "fixture.exe"
            } else {
                "fixture"
            });
            fs::write(&source, FAKE_HOST).unwrap();
            let status = Command::new("rustc")
                .args(["--edition=2024", "--crate-name", "naome_host_fixture"])
                .arg(&source)
                .arg("-o")
                .arg(&binary)
                .stdin(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "benign Rust host fixture must compile");
            binary
        })
        .as_path()
}

struct Proxy {
    child: Child,
    input: Option<ChildStdin>,
    frames: mpsc::Receiver<Vec<u8>>,
    directory: PathBuf,
}

impl Proxy {
    fn start(mode: &str, timeout: u64, output_bytes: usize) -> Self {
        let directory = test_dir(mode);
        let config = HostProxyConfig {
            native_binary: fake_host().to_path_buf(),
            status_file: directory.join("host-status.json"),
            timeout_millis: timeout,
            max_output_bytes: output_bytes,
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_naome-research-code-mode-host"));
        command
            .env(
                "NAOME_RESEARCH_HOST_CONFIG",
                serde_json::to_string(&config).unwrap(),
            )
            .env("NAOME_TEST_HOST_MODE", mode)
            .env("NAOME_TEST_HOST_DIRECTORY", &directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take();
        let mut output = child.stdout.take().unwrap();
        let (sender, frames) = mpsc::channel();
        thread::spawn(move || {
            loop {
                let mut prefix = [0; 4];
                if output.read_exact(&mut prefix).is_err() {
                    return;
                }
                let length = u32::from_le_bytes(prefix) as usize;
                assert!(length <= 4 * 1024 * 1024);
                let mut payload = vec![0; length];
                if output.read_exact(&mut payload).is_err() || sender.send(payload).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            input,
            frames,
            directory,
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        let input = self.input.as_mut().unwrap();
        input
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .unwrap();
        input.write_all(bytes).unwrap();
        input.flush().unwrap();
    }

    fn expect(&self, expected: &str) {
        assert_eq!(
            self.frames.recv_timeout(Duration::from_secs(3)).unwrap(),
            expected.as_bytes()
        );
    }

    fn open(&mut self) {
        self.send(HELLO.as_bytes());
        self.expect(READY);
        self.send(OPEN.as_bytes());
        self.expect(OPENED);
    }

    fn stopped(&mut self) -> Vec<Vec<u8>> {
        let cutoff = Instant::now() + Duration::from_secs(3);
        loop {
            if self.child.try_wait().unwrap().is_some() {
                break;
            }
            assert!(
                Instant::now() < cutoff,
                "proxy must stop within its process bound"
            );
            thread::sleep(Duration::from_millis(5));
        }
        let mut delivered = Vec::new();
        loop {
            match self.frames.recv_timeout(Duration::from_secs(3)) {
                Ok(frame) => delivered.push(frame),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    panic!("no process may retain the stdout pipe");
                }
            }
        }
        delivered
    }

    fn received(&self) -> Vec<Vec<u8>> {
        let bytes = fs::read(self.directory.join("received.frames")).unwrap_or_default();
        let mut reader = bytes.as_slice();
        let mut frames = Vec::new();
        while !reader.is_empty() {
            let mut prefix = [0; 4];
            reader.read_exact(&mut prefix).unwrap();
            let mut frame = vec![0; u32::from_le_bytes(prefix) as usize];
            reader.read_exact(&mut frame).unwrap();
            frames.push(frame);
        }
        frames
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn execute(tools: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"type":"operation/request","id":2,"request":{
        "method":"session/execute","sessionId":"s1","request":{
            "tool_call_id":"call-2","enabled_tools":tools,"source":"text(6 * 7)",
            "yield_time_ms":1000,"max_output_tokens":100
        }
    }}))
    .unwrap()
}

#[test]
fn preserves_native_frames_and_text_math_result_bytes() {
    let mut proxy = Proxy::start("normal", 10_000, 4096);
    proxy.open();
    let execute = execute(json!([]));
    proxy.send(&execute);
    proxy.expect(STARTED);
    proxy.expect(RESULT);
    proxy.expect(CLOSED);
    assert_eq!(
        proxy.received(),
        vec![HELLO.as_bytes(), OPEN.as_bytes(), &execute]
    );
    proxy.input.take();
    assert!(proxy.stopped().is_empty());
}

#[test]
fn rejects_enabled_tools_before_native_host_receives_execute() {
    for tools in [Value::Null, json!([{"name":"unused"}]), json!({})] {
        let mut proxy = Proxy::start("normal", 10_000, 4096);
        proxy.open();
        proxy.send(&execute(tools));
        assert!(proxy.stopped().is_empty());
        let status: Value =
            serde_json::from_slice(&fs::read(proxy.directory.join("host-status.json")).unwrap())
                .unwrap();
        assert_eq!(status["state"], "failed");
        assert_eq!(status["proxy_pid"], proxy.child.id());
        assert!(status["native_pid"].as_u64().is_some());
        assert_eq!(proxy.received(), vec![HELLO.as_bytes(), OPEN.as_bytes()]);
    }
    let mut proxy = Proxy::start("normal", 10_000, 4096);
    proxy.open();
    let mut request: Value = serde_json::from_slice(&execute(json!([]))).unwrap();
    request["request"]["request"]
        .as_object_mut()
        .unwrap()
        .remove("enabled_tools");
    proxy.send(&serde_json::to_vec(&request).unwrap());
    assert!(proxy.stopped().is_empty());
    assert_eq!(proxy.received(), vec![HELLO.as_bytes(), OPEN.as_bytes()]);
}

#[test]
fn rejects_delegate_notifications_and_media_before_forwarding() {
    for mode in ["delegate", "media"] {
        let mut proxy = Proxy::start(mode, 10_000, 4096);
        proxy.open();
        proxy.send(&execute(json!([])));
        assert!(
            proxy
                .stopped()
                .iter()
                .all(|frame| frame == STARTED.as_bytes())
        );
    }
}

#[test]
fn rejects_oversized_frame_before_reading_its_payload() {
    let mut proxy = Proxy::start("normal", 10_000, 4096);
    proxy.open();
    proxy
        .input
        .as_mut()
        .unwrap()
        .write_all(&u32::MAX.to_le_bytes())
        .unwrap();
    assert!(proxy.stopped().is_empty());
    assert_eq!(proxy.received(), vec![HELLO.as_bytes(), OPEN.as_bytes()]);
}

#[test]
fn rejects_native_output_frame_before_payload_allocation() {
    let mut proxy = Proxy::start("large-prefix", 10_000, 4096);
    proxy.open();
    proxy.send(&execute(json!([])));
    // Immediate rejection may stop the proxy before an earlier valid frame has
    // left its bounded queue; the forbidden payload must never be forwarded.
    assert!(
        proxy
            .stopped()
            .iter()
            .all(|frame| frame == STARTED.as_bytes())
    );
}

#[test]
fn deadline_stops_native_host_holding_stdio() {
    let mut proxy = Proxy::start("hold", 500, 4096);
    proxy.open();
    assert!(proxy.stopped().is_empty());
}

#[test]
fn pending_cancellation_stops_owned_host_before_forwarding_the_control() {
    let mut proxy = Proxy::start("pending", 10_000, 4096);
    proxy.open();
    let execute = execute(json!([]));
    proxy.send(&execute);
    proxy.expect(STARTED);
    proxy.send(br#"{"type":"operation/cancel","id":2}"#);
    assert!(proxy.stopped().is_empty());
    assert_eq!(
        proxy.received(),
        vec![HELLO.as_bytes(), OPEN.as_bytes(), &execute]
    );
    let status: Value =
        serde_json::from_slice(&fs::read(proxy.directory.join("host-status.json")).unwrap())
            .unwrap();
    assert_eq!(status["state"], "failed");
    assert!(proxy.directory.join("host-status.json.failed").exists());
}

#[test]
fn parent_eof_stops_independent_host_group_and_all_stdout_holders() {
    let mut proxy = Proxy::start("hold", 10_000, 4096);
    proxy.open();
    #[cfg(unix)]
    {
        let proxy_pid = rustix::process::Pid::from_raw(proxy.child.id() as i32).unwrap();
        assert_eq!(
            rustix::process::getpgid(Some(proxy_pid)).unwrap(),
            proxy_pid
        );
        let native_pid: i32 = fs::read_to_string(proxy.directory.join("native.pid"))
            .unwrap()
            .parse()
            .unwrap();
        let native_pid = rustix::process::Pid::from_raw(native_pid).unwrap();
        assert_eq!(
            rustix::process::getpgid(Some(native_pid)).unwrap(),
            proxy_pid
        );
        assert_ne!(proxy_pid, rustix::process::getpgrp());
    }
    proxy.input.take();
    assert!(proxy.stopped().is_empty());
}

#[cfg(unix)]
#[test]
fn refuses_to_launch_a_host_without_own_process_group() {
    let directory = test_dir("unowned");
    let config = HostProxyConfig {
        native_binary: fake_host().to_path_buf(),
        status_file: directory.join("host-status.json"),
        timeout_millis: 500,
        max_output_bytes: 4096,
    };
    let status = Command::new(env!("CARGO_BIN_EXE_naome-research-code-mode-host"))
        .env(
            "NAOME_RESEARCH_HOST_CONFIG",
            serde_json::to_string(&config).unwrap(),
        )
        .env("NAOME_TEST_HOST_DIRECTORY", &directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(!directory.join("native.pid").exists());
    fs::remove_dir_all(directory).unwrap();
}

// This fixture performs fixed protocol replies and optionally starts one benign
// helper that holds inherited stdio. It has no provider, auth or model code.
const FAKE_HOST: &str = r###"
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
fn send(bytes: &str) {
    let mut out = std::io::stdout();
    out.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
    out.write_all(bytes.as_bytes()).unwrap();
    out.flush().unwrap();
}
fn main() {
    let directory = std::path::PathBuf::from(std::env::var_os("NAOME_TEST_HOST_DIRECTORY").unwrap());
    let mode = std::env::var("NAOME_TEST_HOST_MODE").unwrap_or_default();
    if mode == "helper" {
        fs::write(directory.join("helper.pid"), std::process::id().to_string()).unwrap();
        thread::sleep(Duration::from_secs(30));
        return;
    }
    fs::write(directory.join("native.pid"), std::process::id().to_string()).unwrap();
    let _helper = if mode == "hold" || mode == "pending" {
        Some(Command::new(std::env::current_exe().unwrap()).env("NAOME_TEST_HOST_MODE", "helper")
            .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap())
    } else { None };
    let mut log = OpenOptions::new().create(true).append(true).open(directory.join("received.frames")).unwrap();
    let mut input = std::io::stdin();
    let mut step = 0;
    loop {
        let mut prefix = [0; 4];
        if input.read_exact(&mut prefix).is_err() { break; }
        let length = u32::from_le_bytes(prefix) as usize;
        if length > 32768 { break; }
        let mut bytes = vec![0; length];
        if input.read_exact(&mut bytes).is_err() { break; }
        log.write_all(&prefix).unwrap(); log.write_all(&bytes).unwrap(); log.flush().unwrap();
        match step {
            0 => send(r#"{ "type": "connection/ready", "selectedVersion": 1, "capabilities": [] }"#),
            1 => send(r#"{"type":"operation/response","id":1,"result":{"status":"ok","value":{"type":"session/ready","sessionId":"s1"}}}"#),
            _ => {
                send(r#"{"type":"operation/response","id":2,"result":{"status":"ok","value":{"type":"execution/started","cellId":"cell-1"}}}"#);
                match mode.as_str() {
                    "pending" => {},
                    "delegate" => send(r#"{"type":"delegate/request","id":8,"sessionId":"s1","request":{"type":"notification/send","callId":"c","cellId":"cell-1","text":"42"}}"#),
                    "media" => send(r#"{"type":"execute/initialResponse","id":2,"result":{"status":"ok","value":{"Result":{"cell_id":"cell-1","content_items":[{"type":"input_image","image_url":"data:image/png;base64,AA=="}],"error_text":null,"code_mode_host_duration_ns":0}}}}"#),
                    "large-prefix" => { let mut out = std::io::stdout(); out.write_all(&u32::MAX.to_le_bytes()).unwrap(); out.flush().unwrap(); },
                    _ => {
                        send(r#"{ "type": "execute/initialResponse", "id": 2, "result": {"status":"ok","value":{"Result":{"cell_id":"cell-1","content_items":[{"type":"input_text","text":"42"}],"error_text":null,"code_mode_host_duration_ns":0}}} }"#);
                        send(r#"{"type":"cell/closed","sessionId":"s1","cellId":"cell-1"}"#);
                    }
                }
            }
        }
        step += 1;
    }
    thread::sleep(Duration::from_secs(30));
}
"###;
