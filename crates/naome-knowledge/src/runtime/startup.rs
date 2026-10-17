//! Transient startup custody, independent of synchronous mathematical replay.
use std::{
    io::Read,
    path::Path,
    process::ExitStatus,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

pub(super) const TIMEOUT: Duration = Duration::from_secs(1800);
const MAX_FRAME: usize = 80;
const POLL: Duration = Duration::from_millis(10);

/// This flag is raised only by the checked daemon's actual listener readiness.
/// It is never persisted and supplies no proof validity or resource admission.
pub(crate) struct Startup {
    ready: Arc<AtomicBool>,
    instance_sha256: String,
}

impl Startup {
    pub(super) fn arm(token: &str) -> Result<Self, String> {
        let pid = nix::unistd::getpid();
        if nix::unistd::getpgrp() != pid
            || nix::unistd::getsid(None).map_err(|e| e.to_string())? != pid
        {
            return Err("startup lifeline requires its own detached session".into());
        }
        if token.len() != 64 || crate::unhex(token)?.len() != 32 {
            return Err("invalid startup instance nonce".into());
        }
        let input = std::io::stdin();
        let flags =
            nix::fcntl::fcntl(&input, nix::fcntl::FcntlArg::F_GETFL).map_err(|e| e.to_string())?;
        nix::fcntl::fcntl(
            &input,
            nix::fcntl::FcntlArg::F_SETFL(
                nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK,
            ),
        )
        .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + TIMEOUT;
        let ready = Arc::new(AtomicBool::new(false));
        let witness = ready.clone();
        use sha2::Digest;
        let instance_sha256 = crate::hex(&sha2::Sha256::digest(token.as_bytes()));
        let token = token.to_owned();
        let (started, begin) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("naome-startup-lifeline".into())
            .spawn(move || {
                if observe(input, &token, &witness, deadline, started).is_err() {
                    // setsid succeeded before arming. This is this process's
                    // actual group, never a persisted PID or a discovered name.
                    let _ = nix::sys::signal::killpg(
                        nix::unistd::getpgrp(),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    std::process::exit(125);
                }
            })
            .map_err(|e| format!("startup lifeline thread: {e}"))?;
        begin
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| "startup begin frame unavailable")?;
        Ok(Self {
            ready,
            instance_sha256,
        })
    }

    pub(super) fn ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    pub(crate) fn phase(&self, phase: &str) {
        // This bounded diagnostic binds an observed replay phase to this
        // launch. It is neither a readiness receipt nor a proof certificate.
        crate::network::emit(serde_json::json!({
            "event": "startup_replay", "phase": phase,
            "pid": std::process::id(), "instance_sha256": self.instance_sha256,
        }));
    }
}

pub(super) fn begin(token: &str) -> Vec<u8> {
    format!("begin {token}\n").into_bytes()
}

pub(super) fn acknowledge(token: &str) -> Vec<u8> {
    format!("ready {token}\n").into_bytes()
}

pub(super) async fn wait(
    directory: &Path,
    token: &str,
    deadline: tokio::time::Instant,
    mut exited: impl FnMut() -> Result<Option<ExitStatus>, String>,
) -> Result<super::Status, String> {
    loop {
        if let Some(exit) = exited()? {
            return Err(format!(
                "node failed to start ({exit}); inspect {}",
                directory.join("node.log").display()
            ));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("node startup deadline".into());
        }
        let response = tokio::time::timeout_at(
            deadline,
            super::request(directory, super::Operation::Status, Some(token)),
        )
        .await
        .map_err(|_| "node startup deadline")??;
        if let Some(status) = response
            && status.running
        {
            if tokio::time::Instant::now() >= deadline {
                return Err("node startup deadline before acknowledgement".into());
            }
            return Ok(status);
        }
        tokio::time::sleep(
            Duration::from_millis(50)
                .min(deadline.saturating_duration_since(tokio::time::Instant::now())),
        )
        .await;
    }
}

fn observe(
    mut input: impl Read,
    token: &str,
    ready: &AtomicBool,
    deadline: Instant,
    started: mpsc::SyncSender<()>,
) -> Result<(), String> {
    let mut begun = false;
    let mut frame = Vec::with_capacity(MAX_FRAME);
    loop {
        if Instant::now() >= deadline {
            return Err("startup lifeline deadline".into());
        }
        let mut byte = [0u8; 1];
        match input.read(&mut byte) {
            Ok(0) => return Err("startup parent lifeline closed".into()),
            Ok(_) => {
                frame.push(byte[0]);
                if frame.len() > MAX_FRAME {
                    return Err("startup lifeline frame limit".into());
                }
                if byte[0] != b'\n' {
                    continue;
                }
                if !begun && frame == begin(token) {
                    started.send(()).map_err(|_| "startup owner unavailable")?;
                    begun = true;
                    frame.clear();
                } else if begun && frame == acknowledge(token) && ready.load(Ordering::Acquire) {
                    // A successful checked Status response caused the parent
                    // to send this instance-bound acknowledgement. Only now
                    // may ordinary detached operation outlive the launcher.
                    return Ok(());
                } else {
                    return Err("startup lifeline instance or readiness mismatch".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("startup parent lifeline unreadable".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn check(bytes: Vec<u8>, ready: bool, expired: bool) -> Result<(), String> {
        let (send, receive) = mpsc::sync_channel(1);
        let token = "ab".repeat(32);
        let deadline = Instant::now()
            + if expired {
                Duration::ZERO
            } else {
                Duration::from_secs(1)
            };
        let result = observe(
            Cursor::new(bytes),
            &token,
            &AtomicBool::new(ready),
            deadline,
            send,
        );
        drop(receive);
        result
    }

    #[test]
    fn startup_release_requires_begin_checked_readiness_and_exact_instance() {
        let token = "ab".repeat(32);
        let frames = [begin(&token), acknowledge(&token)].concat();
        assert!(check(frames.clone(), true, false).is_ok());
        assert!(
            check(frames, false, false)
                .unwrap_err()
                .contains("readiness mismatch")
        );
        assert!(check(acknowledge(&token), true, false).is_err());
        assert!(
            check(
                [begin(&token), acknowledge(&"cd".repeat(32))].concat(),
                true,
                false
            )
            .is_err()
        );
        assert!(check([begin(&token), begin(&token)].concat(), true, false).is_err());
    }

    #[test]
    fn parent_eof_partial_frame_and_expiry_never_release_startup() {
        let token = "ab".repeat(32);
        assert!(
            check(Vec::new(), true, false)
                .unwrap_err()
                .contains("lifeline closed")
        );
        assert!(
            check(begin(&token), true, false)
                .unwrap_err()
                .contains("lifeline closed")
        );
        assert!(check(b"begin ab".to_vec(), true, false).is_err());
        assert!(
            check([begin(&token), acknowledge(&token)].concat(), true, true)
                .unwrap_err()
                .contains("deadline")
        );
        assert!(
            check(vec![b'x'; MAX_FRAME + 1], true, false)
                .unwrap_err()
                .contains("frame limit")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn checked_ready_can_arrive_after_the_old_lifecycle_window() {
        let directory = crate::runtime::tests::Directory::new();
        let token = "ab".repeat(32);
        let started = tokio::time::Instant::now();
        let deadline = started + TIMEOUT;
        let serve = async {
            // Virtual time tests the startup/RPC distinction. It supplies no
            // native replay, large-corpus, custody or resource qualification.
            tokio::time::sleep(Duration::from_secs(16)).await;
            let control = super::super::Control::bind_token(&directory.0, token.clone()).unwrap();
            let (stream, _) = control.listener.accept().await.unwrap();
            control.respond(stream, 0, true).await.unwrap();
        };
        let (status, ()) = tokio::join!(wait(&directory.0, &token, deadline, || Ok(None)), serve);
        assert!(status.unwrap().running);
        assert!(tokio::time::Instant::now() - started >= Duration::from_secs(16));
    }

    #[tokio::test(start_paused = true)]
    async fn startup_expiry_and_wrong_instance_never_reset_the_original_deadline() {
        let directory = crate::runtime::tests::Directory::new();
        let _other = super::super::Control::bind_token(&directory.0, "cd".repeat(32)).unwrap();
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_millis(75);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                wait(&directory.0, &"ab".repeat(32), deadline, || Ok(None))
            )
            .await
            .unwrap()
            .unwrap_err()
            .contains("startup deadline")
        );
        assert!(tokio::time::Instant::now() >= deadline);
        assert!(tokio::time::Instant::now() - started < Duration::from_millis(100));
    }
}
