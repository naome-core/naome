//! One bounded JSON frame with an optional borrowed kernel lease.
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags};
use std::{
    io::{IoSlice, IoSliceMut, Write},
    os::fd::{AsRawFd, OwnedFd},
    os::unix::net::UnixStream,
};

pub(super) const LIMIT: usize = 128 * 1024;
pub(super) struct Fds(pub Vec<OwnedFd>);
pub(super) fn send(
    stream: &mut UnixStream,
    value: &serde_json::Value,
    fd: Option<i32>,
) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() > LIMIT {
        return Err("interest frame byte limit".into());
    }
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.append(&mut bytes);
    let bytes = frame;
    let written = if let Some(fd) = fd {
        sendmsg::<()>(
            stream.as_raw_fd(),
            &[IoSlice::new(&bytes)],
            &[ControlMessage::ScmRights(&[fd])],
            MsgFlags::empty(),
            None,
        )
        .map_err(|e| e.to_string())?
    } else {
        stream.write(&bytes).map_err(|e| e.to_string())?
    };
    stream
        .write_all(&bytes[written..])
        .map_err(|e| e.to_string())
}
pub(super) fn receive(stream: &mut UnixStream) -> Result<(serde_json::Value, Fds), String> {
    receive_with_buffer::<4096>(stream)
}

fn receive_with_buffer<const N: usize>(
    stream: &mut UnixStream,
) -> Result<(serde_json::Value, Fds), String> {
    receive_with_flags::<N>(stream, |fd| {
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    })
}

fn receive_with_flags<const N: usize>(
    stream: &mut UnixStream,
    mut set_flags: impl FnMut(&OwnedFd) -> Result<(), String>,
) -> Result<(serde_json::Value, Fds), String> {
    let until = stream
        .read_timeout()
        .map_err(|e| e.to_string())?
        .map(|limit| std::time::Instant::now() + limit);
    let mut fds = Fds(Vec::new());
    let mut started = false;
    let mut header = [0u8; 4];
    receive_exact::<N>(
        stream,
        &mut header,
        &mut fds,
        &mut set_flags,
        until,
        &mut started,
    )?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > LIMIT {
        return Err("interest frame byte limit".into());
    }
    let mut bytes = vec![0; size];
    receive_exact::<N>(
        stream,
        &mut bytes,
        &mut fds,
        &mut set_flags,
        until,
        &mut started,
    )?;
    let value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    check_deadline(until, started)?;
    Ok((value, fds))
}

fn check_deadline(until: Option<std::time::Instant>, started: bool) -> Result<(), String> {
    if until.is_some_and(|end| std::time::Instant::now() >= end) {
        return Err(if started {
            "interest partial frame receive timed out"
        } else {
            "interest receive timed out"
        }
        .into());
    }
    Ok(())
}

fn receive_exact<const N: usize>(
    stream: &UnixStream,
    mut bytes: &mut [u8],
    fds: &mut Fds,
    set_flags: &mut impl FnMut(&OwnedFd) -> Result<(), String>,
    until: Option<std::time::Instant>,
    started: &mut bool,
) -> Result<(), String> {
    // Every chunk uses recvmsg. Plain read on a continuation could silently
    // install descriptors on Darwin, bypassing both ownership and CLOEXEC.
    while !bytes.is_empty() {
        check_deadline(until, *started)?;
        let mut space = [std::mem::MaybeUninit::<u8>::uninit(); N];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut iov = [IoSliceMut::new(bytes)];
        let result = {
            let _spawn = crate::jobs::process::SPAWN
                .lock()
                .map_err(|_| "spawn owner poisoned")?;
            check_deadline(until, *started)?;
            let flags = RecvFlags::DONTWAIT;
            #[cfg(target_os = "linux")]
            let flags = flags | RecvFlags::CMSG_CLOEXEC;
            match rustix::net::recvmsg(stream, &mut iov, &mut control, flags) {
                Ok(message) => {
                    if message.flags.contains(ReturnFlags::CTRUNC) {
                        // Only owned broker/provider/client helper processes
                        // receive descriptors; gossip receives ordinary pipes.
                        std::process::exit(125);
                    }
                    for ancillary in control.drain() {
                        if let RecvAncillaryMessage::ScmRights(values) = ancillary {
                            fds.0.extend(values);
                        }
                    }
                    for fd in &fds.0 {
                        if let Err(error) = set_flags(fd) {
                            fds.0.clear();
                            return Err(error);
                        }
                    }
                    Ok(message.bytes)
                }
                Err(error) => Err(error),
            }
        };
        match result {
            Ok(0) => return Err("interest frame EOF".into()),
            Ok(count) => {
                *started = true;
                bytes = &mut bytes[count..];
            }
            Err(rustix::io::Errno::AGAIN) => {
                check_deadline(until, *started)?;
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}
pub(super) fn peer(stream: &UnixStream) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let uid = nix::unistd::getpeereid(stream)
        .map_err(|e| e.to_string())?
        .0
        .as_raw();
    #[cfg(target_os = "linux")]
    let uid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|e| e.to_string())?
        .uid();
    if uid != nix::unistd::geteuid().as_raw() {
        return Err("interest peer UID differs".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
    #[test]
    fn received_description_holds_lock_after_sender_closes_until_receiver_closes() {
        if isolate("received_description_holds_lock_after_sender_closes_until_receiver_closes") {
            return;
        }
        let path = std::env::temp_dir().join(format!(
            "naome-scm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let inventory_before = fd_count();
        send(
            &mut sender,
            &serde_json::json!({"kind":"hold"}),
            Some(lease.as_raw_fd()),
        )
        .unwrap();
        let (_, fds) = receive(&mut receiver).unwrap();
        assert_eq!(fds.0.len(), 1);
        drop(lease);
        drop(sender);
        assert!(matches!(
            probe.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(fds);
        assert_eq!(fd_count(), inventory_before - 2);
        probe.try_lock().unwrap();
        drop(probe);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn malformed_json_closes_every_received_description() {
        let path = std::env::temp_dir().join(format!(
            "naome-scm-bad-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
        let data = [0u8, 0, 0, 1, b'{'];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(&data)],
            &[ControlMessage::ScmRights(&[lease.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(lease);
        assert!(receive(&mut receiver).is_err());
        probe.try_lock().unwrap();
        drop(probe);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn descriptors_on_payload_chunks_are_owned_and_closed_with_the_frame() {
        let p = path("payload");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        lease.try_lock().unwrap();
        let probe = OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&2u32.to_be_bytes()).unwrap();
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(b"{}")],
            &[ControlMessage::ScmRights(&[lease.as_raw_fd(); 32])],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(lease);
        let (value, fds) = receive(&mut receiver).unwrap();
        assert_eq!(value, serde_json::json!({}));
        assert_eq!(fds.0.len(), 32);
        assert!(matches!(
            probe.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        for fd in &fds.0 {
            assert!(
                nix::fcntl::FdFlag::from_bits_retain(
                    nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).unwrap()
                )
                .contains(nix::fcntl::FdFlag::FD_CLOEXEC)
            );
        }
        drop(fds);
        probe.try_lock().unwrap();
        drop(probe);
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn expired_readable_frame_closes_already_received_descriptors() {
        if isolate("expired_readable_frame_closes_already_received_descriptors") {
            return;
        }
        let p = path("expired-readable");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        lease.try_lock().unwrap();
        let probe = OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_millis(10)))
            .unwrap();
        send(&mut sender, &serde_json::json!({}), Some(lease.as_raw_fd())).unwrap();
        drop(lease);
        let mut received_first_fd = false;
        let result = receive_with_flags::<4096>(&mut receiver, |fd| {
            assert!(
                !received_first_fd,
                "only the first descriptor reaches the flag setter"
            );
            received_first_fd = true;
            nix::fcntl::fcntl(
                fd,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
            )
            .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(25));
            Ok(())
        });
        assert!(
            received_first_fd,
            "descriptor custody precedes deadline expiry"
        );
        assert_eq!(
            result.err().unwrap(),
            "interest partial frame receive timed out"
        );
        // The sender remains open and all data was already readable. A
        // successful Frame after the original deadline would fail this case.
        probe.try_lock().unwrap();
        drop(probe);
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn spawn_contention_cannot_receive_an_expired_readable_frame() {
        if isolate("spawn_contention_cannot_receive_an_expired_readable_frame") {
            return;
        }
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_millis(10)))
            .unwrap();
        send(&mut sender, &serde_json::json!({}), None).unwrap();
        let guard = crate::jobs::process::SPAWN.lock().unwrap();
        let original_until = std::time::Instant::now() + std::time::Duration::from_millis(10);
        let (ready, started) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            ready.send(()).unwrap();
            let mut bytes = [0u8; 4];
            let mut fds = Fds(Vec::new());
            let mut began = false;
            receive_exact::<4096>(
                &receiver,
                &mut bytes,
                &mut fds,
                &mut |_| Ok(()),
                Some(original_until),
                &mut began,
            )
        });
        started.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(25));
        drop(guard);
        assert_eq!(
            reader.join().unwrap().err().unwrap(),
            "interest receive timed out"
        );
    }
    fn fd_count() -> usize {
        std::fs::read_dir("/dev/fd").unwrap().count()
    }

    fn path(kind: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "naome-scm-{kind}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    #[test]
    fn more_than_sixteen_descriptors_are_owned_cloexec_and_closed_on_parser_error() {
        if isolate("more_than_sixteen_descriptors_are_owned_cloexec_and_closed_on_parser_error") {
            return;
        }
        let p = path("many");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        lease.try_lock().unwrap();
        let probe = OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        let inventory_before = fd_count();
        let raw = vec![lease.as_raw_fd(); 32];
        let data = [0u8, 0, 0, 2, b'{', b'}'];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(&data)],
            &[ControlMessage::ScmRights(&raw)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        let (_, fds) = receive(&mut receiver).unwrap();
        assert_eq!(fds.0.len(), 32);
        for fd in &fds.0 {
            assert!(
                nix::fcntl::FdFlag::from_bits_retain(
                    nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).unwrap()
                )
                .contains(nix::fcntl::FdFlag::FD_CLOEXEC)
            );
        }
        drop(lease);
        drop(fds);
        assert_eq!(fd_count(), inventory_before - 1);
        probe.try_lock().unwrap();
        drop(probe);
        std::fs::remove_file(p).unwrap();
        let p = path("many-malformed");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        lease.try_lock().unwrap();
        let probe = OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        let inventory_before = fd_count();
        let raw = vec![lease.as_raw_fd(); 32];
        let data = [0u8, 0, 0, 1, b'{'];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(&data)],
            &[ControlMessage::ScmRights(&raw)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(lease);
        assert!(receive(&mut receiver).is_err());
        assert_eq!(fd_count(), inventory_before - 1);
        probe.try_lock().unwrap();
        drop(probe);
        std::fs::remove_file(p).unwrap();
    }
    #[test]
    fn partial_frame_failure_closes_all_received_leases() {
        if isolate("partial_frame_failure_closes_all_received_leases") {
            return;
        }
        let p = path("partial");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        lease.try_lock().unwrap();
        let probe = OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        let inventory_before = fd_count();
        let raw = vec![lease.as_raw_fd(); 32];
        let data = [0u8, 0, 0, 8, b'{'];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(&data)],
            &[ControlMessage::ScmRights(&raw)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(lease);
        drop(sender);
        assert!(receive(&mut receiver).is_err());
        assert_eq!(fd_count(), inventory_before - 2);
        probe.try_lock().unwrap();
        drop(probe);
        std::fs::remove_file(p).unwrap();
    }
    fn child_test(name: &str) -> std::process::Command {
        let module = module_path!().split_once("::").unwrap().1;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(format!("{module}::{name}"))
            .arg("--test-threads=1")
            .env_clear();
        command
    }
    fn isolate(name: &str) -> bool {
        const CASE: &str = "NAOME_SCM_ISOLATED_CASE";
        if std::env::var(CASE).as_deref() == Ok(name) {
            return false;
        }
        // Global FD inventories are meaningful only inside this one-case
        // child; unrelated workspace tests keep their usual parallelism.
        let mut command = child_test(name);
        command.env(CASE, name);
        let mut child = {
            let _guard = crate::jobs::process::SPAWN.lock().unwrap();
            command.spawn().unwrap()
        };
        assert!(
            child.wait().unwrap().success(),
            "isolated FD case {name} failed"
        );
        true
    }
    #[test]
    fn actual_truncated_control_terminates_receiver_and_releases_hidden_fds() {
        const CHILD: &str = "NAOME_SCM_TRUNCATED_CHILD";
        if std::env::var_os(CHILD).is_none()
            && isolate("actual_truncated_control_terminates_receiver_and_releases_hidden_fds")
        {
            return;
        }
        if let Some(p) = std::env::var_os(CHILD) {
            let mut socket = UnixStream::connect(p).unwrap();
            let _ = receive_with_buffer::<{ rustix::cmsg_space!(ScmRights(16)) }>(&mut socket);
            panic!("truncated control did not terminate its receiver");
        }
        let p = path("ctrunc");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        lease.try_lock().unwrap();
        let probe = OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let socket = p.with_extension("sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let mut command =
            child_test("actual_truncated_control_terminates_receiver_and_releases_hidden_fds");
        command.env(CHILD, &socket);
        let mut child = {
            let _guard = crate::jobs::process::SPAWN.lock().unwrap();
            command.spawn().unwrap()
        };
        let (sender, _) = listener.accept().unwrap();
        let inventory_before = fd_count();
        let raw = vec![lease.as_raw_fd(); 32];
        let data = [0u8, 0, 0, 2, b'{', b'}'];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(&data)],
            &[ControlMessage::ScmRights(&raw)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(lease);
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(125));
        assert_eq!(fd_count(), inventory_before - 1);
        probe.try_lock().unwrap();
        drop(probe);
        std::fs::remove_file(p).unwrap();
        std::fs::remove_file(socket).unwrap();
    }
    #[test]
    fn received_descriptors_do_not_survive_exec() {
        use std::os::unix::fs::MetadataExt;
        const CHILD: &str = "NAOME_SCM_EXEC_IDENTITY";
        if let Ok(identity) = std::env::var(CHILD) {
            for entry in std::fs::read_dir("/dev/fd").unwrap() {
                if let Ok(metadata) = entry.unwrap().path().metadata() {
                    assert_ne!(
                        format!("{}:{}", metadata.dev(), metadata.ino()),
                        identity,
                        "received lease leaked through exec"
                    );
                }
            }
            return;
        }
        let p = path("exec");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        let metadata = lease.metadata().unwrap();
        let identity = format!("{}:{}", metadata.dev(), metadata.ino());
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        send(
            &mut sender,
            &serde_json::json!({"kind":"hold"}),
            Some(lease.as_raw_fd()),
        )
        .unwrap();
        let (_, fds) = receive(&mut receiver).unwrap();
        drop(lease);
        let mut command = child_test("received_descriptors_do_not_survive_exec");
        command.env(CHILD, identity);
        let mut child = {
            let _guard = crate::jobs::process::SPAWN.lock().unwrap();
            command.spawn().unwrap()
        };
        assert!(child.wait().unwrap().success());
        drop(fds);
        std::fs::remove_file(p).unwrap();
    }
    #[test]
    fn failed_cloexec_closes_received_descriptors_before_spawn_lock_release() {
        let p = path("flag-error");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        lease.try_lock().unwrap();
        let probe = OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        send(
            &mut sender,
            &serde_json::json!({"kind":"hold"}),
            Some(lease.as_raw_fd()),
        )
        .unwrap();
        drop(lease);
        let error = receive_with_flags::<4096>(&mut receiver, |_| {
            assert!(crate::jobs::process::SPAWN.try_lock().is_err());
            assert!(matches!(
                probe.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ));
            Err("injected F_SETFD failure".into())
        })
        .err()
        .unwrap();
        assert_eq!(error, "injected F_SETFD failure");
        let _guard = crate::jobs::process::SPAWN.lock().unwrap();
        probe.try_lock().unwrap();
        drop(probe);
        std::fs::remove_file(p).unwrap();
    }
}
