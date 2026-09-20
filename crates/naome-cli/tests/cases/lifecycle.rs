use super::*;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{ExitStatus, Stdio},
};

fn exit(child: &mut Child, budget: Duration) -> ExitStatus {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("main executable exceeded shutdown bound");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
fn directories(lab: &Lab, node: usize) -> [PathBuf; 4] {
    [
        format!("node-{node}/history"),
        format!("node-{node}/signer"),
        format!("anchor-history-{node}"),
        format!("anchor-signer-{node}"),
    ]
    .map(|p| lab.root.join(p))
}
// Directory entries are part of the oracle: an empty recreated store is a failure.
fn image(lab: &Lab, node: usize) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut result = BTreeMap::new();
    for directory in directories(lab, node) {
        if !directory.exists() {
            continue;
        }
        result.insert(directory.clone(), None);
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            result.insert(path.clone(), Some(fs::read(path).unwrap()));
        }
    }
    result
}
fn refused(lab: &Lab, node: usize) {
    let before = image(lab, node);
    let mut child = Command::new(process_binary("naome-validator"))
        .args(["start", &lab.config(node)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(!exit(&mut child, Duration::from_secs(4)).success());
    assert_eq!(image(lab, node), before, "failed startup changed authority");
}
pub(super) fn refuse_missing_stores(lab: &Lab, node: usize) {
    let original = image(lab, node);
    for directory in directories(lab, node) {
        let saved = directory.with_extension("held");
        fs::rename(&directory, &saved).unwrap();
        refused(lab, node);
        assert!(!directory.exists());
        fs::rename(saved, directory).unwrap();
    }
    let dirs = directories(lab, node);
    for directory in &dirs {
        fs::rename(directory, directory.with_extension("held")).unwrap();
    }
    refused(lab, node);
    for directory in &dirs {
        assert!(!directory.exists());
        fs::rename(directory.with_extension("held"), directory).unwrap();
    }
    assert_eq!(image(lab, node), original);
}

#[test]
fn canonical_startup_preflight_preserves_authority_and_live_owner() {
    let _guard = process_guard();
    let mut lab = Lab::new();
    let config_path = PathBuf::from(lab.config(0));
    let original = fs::read(&config_path).unwrap();
    let fifo = lab.root.join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let occupied = lab.root.join("occupied.sock");
    fs::write(&occupied, b"retain").unwrap();
    let base: Value = serde_json::from_slice(&original).unwrap();
    for (field, value) in [
        (
            "consensus_key",
            serde_json::json!(lab.root.join("missing.key")),
        ),
        (
            "transport_key",
            serde_json::json!(lab.root.join("node-1/transport.key")),
        ),
        ("consensus_key", serde_json::json!(fifo)),
        ("control_socket", serde_json::json!(occupied)),
        ("maximum_round", serde_json::json!(u64::MAX)),
        ("listen_address", serde_json::json!("127.0.0.1:0")),
        ("listen_address", serde_json::json!("224.0.0.1:4000")),
    ] {
        let mut config = base.clone();
        config[field] = value;
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        refused(&lab, 0);
    }
    fs::write(&config_path, &original).unwrap();
    assert_eq!(fs::read(occupied).unwrap(), b"retain");
    // A named-pipe configuration is also rejected before opening a store.
    let mut child = Command::new(process_binary("naome-validator"))
        .args(["start", &path(&fifo)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(!exit(&mut child, Duration::from_secs(4)).success());
    refuse_missing_stores(&lab, 0);
    lab.start(0);
    let status = lab.wait(0, |_| true);
    let socket = lab.root.join("node-0/control.sock");
    use std::os::unix::fs::MetadataExt;
    let inode = fs::symlink_metadata(&socket).unwrap().ino();
    refused(&lab, 0);
    assert_eq!(fs::symlink_metadata(&socket).unwrap().ino(), inode);
    assert_eq!(lab.status(0).unwrap()["state"], status["state"]);
    lab.stop(0);
    lab.start(0);
    lab.wait(0, |_| true);
    lab.stop(0);
}

fn stream(lab: &Lab) -> UnixStream {
    let stream = UnixStream::connect(lab.root.join("node-0/control.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    stream
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut result = (bytes.len() as u32).to_be_bytes().to_vec();
    result.extend_from_slice(bytes);
    result
}
fn response(stream: &mut UnixStream) -> Value {
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let length = u32::from_be_bytes(length) as usize;
    assert!(length <= 3 * 1024 * 1024);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn canonical_control_framing_timeouts_and_stalled_clients_release_custody() {
    let _guard = process_guard();
    let mut lab = Lab::new();
    lab.start(0);
    let before = lab.wait(0, |_| true);
    for bytes in [
        vec![0, 0],
        [1024u32.to_be_bytes().as_slice(), b"{"].concat(),
    ] {
        let mut client = stream(&lab);
        let start = Instant::now();
        client.write_all(&bytes).unwrap();
        assert!(response(&mut client).get("error").is_some());
        assert!(start.elapsed() < Duration::from_secs(4));
        // Data arriving after a failed frame can never become a fresh command.
        let _ = client.write_all(&frame(br#"{"command":"shutdown"}"#));
    }
    for bytes in [
        ((3 * 1024 * 1024 + 1) as u32).to_be_bytes().to_vec(),
        frame(b"{"),
        frame(br#"{"command":"status","command":"shutdown"}"#),
        frame(br#"{"command":"status","extra":1}"#),
        frame(br#"{"command":"submit","bytes":"00"}"#),
    ] {
        let mut client = stream(&lab);
        client
            .write_all(&[bytes, frame(br#"{"command":"shutdown"}"#)].concat())
            .unwrap();
        assert!(response(&mut client).get("error").is_some());
    }
    let mut client = stream(&lab);
    client
        .write_all(&frame(
            br#"{"command":"history","height":18446744073709551615}"#,
        ))
        .unwrap();
    assert!(response(&mut client).get("error").is_some());
    let after = lab.status(0).unwrap();
    for field in ["height", "head", "state", "pending_operations"] {
        assert_eq!(after[field], before[field]);
    }
    lab.submit(0, 4, example("question-a.nao"), "valid-after-bad-frames");
    lab.wait(0, |s| s["pending_operations"] == 1);
    // Fill every connection permit with stalled partial headers. SIGINT must
    // remain responsive without waiting for their read/write deadlines.
    for signal in [rustix::process::Signal::INT, rustix::process::Signal::TERM] {
        let clients = (0..16)
            .map(|_| {
                let mut client = stream(&lab);
                client.write_all(&[0]).unwrap();
                client
            })
            .collect::<Vec<_>>();
        let mut child = lab.nodes[0].take().unwrap();
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
            signal,
        )
        .unwrap();
        assert!(exit(&mut child, Duration::from_secs(3)).success());
        assert!(!lab.root.join("node-0/control.sock").exists());
        drop(clients);
        lab.start(0);
        lab.wait(0, |_| true);
    }
    lab.stop(0);
}

fn blocked_output() -> (Stdio, UnixStream) {
    let (mut writer, reader) = UnixStream::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    let mut filled = 0;
    loop {
        match writer.write(&[0; 8192]) {
            Ok(count) => {
                filled += count;
                assert!(filled < 16 * 1024 * 1024);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill stdout: {error}"),
        }
    }
    writer.set_nonblocking(false).unwrap();
    (Stdio::from(OwnedFd::from(writer)), reader)
}
#[test]
fn canonical_stalled_output_cannot_hold_locks_or_repeat_shutdown_flush() {
    let _guard = process_guard();
    let mut lab = Lab::new();
    let (stdout, _unread) = blocked_output();
    lab.nodes[0] = Some(
        Command::new(process_binary("naome-validator"))
            .args(["start", &lab.config(0)])
            .stdout(stdout)
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    lab.wait(0, |_| true);
    let start = Instant::now();
    command(&["shutdown".into(), lab.config(0)]);
    let mut child = lab.nodes[0].take().unwrap();
    assert!(!exit(&mut child, Duration::from_millis(3200)).success());
    assert!(start.elapsed() < Duration::from_millis(3500));
    lab.start(0);
    lab.wait(0, |_| true);
    lab.stop(0);
    let (stderr, _unread) = blocked_output();
    let mut child = Command::new(process_binary("naome-validator"))
        .args(["start", &lab.file("missing.json")])
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .unwrap();
    assert!(!exit(&mut child, Duration::from_millis(1500)).success());
}
