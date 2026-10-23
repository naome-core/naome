//! Transient startup custody, independent of synchronous mathematical replay.
use std::{
    io::{Read, Write},
    path::Path,
    process::ExitStatus,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

const MAX_FRAME: usize = 80;

// An inherited pipe is the owner's live capability. These absolute times only
// narrow the existing startup interval; they grant no resource or proof authority.
pub(super) const HANDOFF_ACTIVE: &str = "NAOME_STARTUP_HANDOFF_ACTIVE_NS";
pub(super) const HANDOFF_CLEANUP: &str = "NAOME_STARTUP_HANDOFF_CLEANUP_NS";
pub(super) const CUSTODY_ACTIVE: &str = "NAOME_STARTUP_CUSTODY_ACTIVE_NS";

pub(super) fn native_ns() -> Result<u64, String> {
    let now =
        nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).map_err(|e| e.to_string())?;
    u64::try_from(now.tv_sec())
        .ok()
        .and_then(|s| s.checked_mul(1_000_000_000))
        .and_then(|s| s.checked_add(u64::try_from(now.tv_nsec()).ok()?))
        .ok_or_else(|| "invalid native startup clock".into())
}

fn nonblocking(input: &std::io::Stdin) -> Result<(), String> {
    let flags =
        nix::fcntl::fcntl(input, nix::fcntl::FcntlArg::F_GETFL).map_err(|e| e.to_string())?;
    nix::fcntl::fcntl(
        input,
        nix::fcntl::FcntlArg::F_SETFL(
            nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK,
        ),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub(super) struct Handoff {
    input: std::io::Stdin,
    pub active_ns: u64,
    cleanup_ns: u64,
}

impl Handoff {
    pub fn open() -> Result<Self, String> {
        let parse = |name| {
            std::env::var(name)
                .map_err(|_| "missing startup owner endpoint")?
                .parse::<u64>()
                .map_err(|_| "invalid startup owner endpoint")
        };
        let active_ns = parse(HANDOFF_ACTIVE)?;
        let cleanup_ns = parse(HANDOFF_CLEANUP)?;
        if active_ns.checked_add(10_000_000_000) != Some(cleanup_ns) {
            return Err("startup owner must retain original ten-second cleanup".into());
        }
        let input = std::io::stdin();
        let metadata = nix::sys::stat::fstat(&input).map_err(|e| e.to_string())?;
        if nix::sys::stat::SFlag::from_bits_truncate(metadata.st_mode)
            & nix::sys::stat::SFlag::S_IFMT
            != nix::sys::stat::SFlag::S_IFIFO
        {
            return Err("startup owner requires its inherited stdin pipe".into());
        }
        nonblocking(&input)?;
        let mut owner = Self {
            input,
            active_ns,
            cleanup_ns,
        };
        let left = owner.remaining()?;
        if left > Duration::from_secs(180) {
            return Err("startup owner active interval exceeds original allowance".into());
        }
        owner.before_offer()?;
        Ok(owner)
    }

    fn remaining(&self) -> Result<Duration, String> {
        self.active_ns
            .checked_sub(native_ns()?)
            .filter(|n| *n > 0)
            .map(Duration::from_nanos)
            .ok_or_else(|| "original startup owner deadline".into())
    }

    pub fn deadline(&self) -> Result<tokio::time::Instant, String> {
        Ok(tokio::time::Instant::now() + self.remaining()?)
    }

    pub fn abort_deadline(&self) -> Result<Instant, String> {
        // The original leaf stage, never a fresh cleanup allowance.
        let end = self
            .active_ns
            .checked_add(600_000_000)
            .ok_or("startup owner endpoint overflow")?;
        Ok(Instant::now()
            + Duration::from_nanos(end.saturating_sub(native_ns()?))
                .min(Duration::from_millis(500)))
    }

    pub fn before_offer(&mut self) -> Result<(), String> {
        self.remaining()?;
        let mut byte = [0u8; 1];
        match self.input.read(&mut byte) {
            Ok(0) => Err("startup owner lifeline closed before handoff".into()),
            Ok(_) => Err("startup owner acknowledged before original Child offer".into()),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(format!("startup owner lifeline: {e}")),
        }
    }

    pub async fn wait_for_loss(&mut self) -> Result<(), String> {
        loop {
            self.before_offer()?;
            tokio::time::sleep(crate::resources::limits().custody_poll_interval).await;
        }
    }

    pub fn report_abort(
        &self,
        pid: u32,
        token: &str,
        report: &serde_json::Value,
    ) -> Result<(), String> {
        let observed_ns = native_ns()?;
        let timely = self
            .active_ns
            .checked_add(700_000_000)
            .is_some_and(|end| observed_ns <= end);
        let value = serde_json::json!({"kind":"STARTUP_ABORT_COMPLETION_V1","pid":pid,
            "token":token,"active_ns":self.active_ns,"cleanup_ns":self.cleanup_ns,
            "observed_ns":observed_ns,"timely":timely,"report":report});
        let mut output = std::io::stdout().lock();
        writeln!(output, "{value}").map_err(|e| e.to_string())?;
        output.flush().map_err(|e| e.to_string())
    }

    pub async fn transfer(&mut self, pid: u32, token: &str) -> Result<(), String> {
        self.before_offer()?;
        let offer = serde_json::json!({"kind":"STARTUP_CHILD_CUSTODY_V1",
            "pid":pid,"token":token,"active_ns":self.active_ns,"cleanup_ns":self.cleanup_ns});
        // This first frame precedes the daemon ACK. The actual Child has not
        // been polled/reaped in this mode and its PID cannot be reused here.
        writeln!(std::io::stdout().lock(), "{offer}").map_err(|e| e.to_string())?;
        let expected = format!("owned {token}\n").into_bytes();
        let mut frame = Vec::with_capacity(MAX_FRAME);
        loop {
            let left = self.remaining()?;
            let mut byte = [0u8; 1];
            match self.input.read(&mut byte) {
                Ok(0) => {
                    return Err(
                        "startup owner lifeline closed before custody acknowledgement".into(),
                    );
                }
                Ok(_) => {
                    frame.push(byte[0]);
                    if frame.len() > MAX_FRAME {
                        return Err("startup owner frame limit".into());
                    }
                    if byte[0] == b'\n' {
                        if frame != expected {
                            return Err("startup owner instance mismatch".into());
                        }
                        self.remaining()?;
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(crate::resources::limits().custody_poll_interval.min(left))
                        .await
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(format!("startup owner read: {e}")),
            }
        }
    }
}

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
        let custody_active = match std::env::var(CUSTODY_ACTIVE) {
            Ok(value) => Some(
                value
                    .parse::<u64>()
                    .map_err(|_| "invalid daemon custody endpoint")?,
            ),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err("invalid daemon custody endpoint encoding".into()),
        };
        if custody_active.is_some_and(|end| native_ns().map_or(true, |now| now >= end)) {
            return Err("original daemon custody endpoint expired before arming".into());
        }
        let deadline = Instant::now() + crate::resources::limits().startup_timeout;
        let ready = Arc::new(AtomicBool::new(false));
        let witness = ready.clone();
        use sha2::Digest;
        let instance_sha256 = crate::hex(&sha2::Sha256::digest(token.as_bytes()));
        let token = token.to_owned();
        let (started, begin) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("naome-startup-lifeline".into())
            .spawn(move || {
                if observe(input, &token, &witness, deadline, custody_active, started).is_err() {
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
            crate::resources::limits()
                .lifecycle_poll_interval
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
    custody_active: Option<u64>,
    started: mpsc::SyncSender<()>,
) -> Result<(), String> {
    let mut begun = false;
    let mut frame = Vec::with_capacity(MAX_FRAME);
    loop {
        if Instant::now() >= deadline
            || custody_active.is_some_and(|end| native_ns().map_or(true, |now| now >= end))
        {
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
                std::thread::sleep(
                    crate::resources::limits()
                        .custody_poll_interval
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
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
            None,
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

    #[test]
    fn original_native_custody_cutoff_cannot_be_replaced_by_the_long_startup_clock() {
        let token = "ab".repeat(32);
        let (send, _receive) = mpsc::sync_channel(1);
        let result = observe(
            Cursor::new([begin(&token), acknowledge(&token)].concat()),
            &token,
            &AtomicBool::new(true),
            Instant::now() + crate::resources::limits().startup_timeout,
            Some(0),
            send,
        );
        assert!(result.unwrap_err().contains("lifeline deadline"));
    }

    #[tokio::test(start_paused = true)]
    async fn checked_ready_can_arrive_after_the_control_lifecycle_timeout() {
        let directory = crate::runtime::tests::Directory::new();
        let token = "ab".repeat(32);
        let started = tokio::time::Instant::now();
        let deadline = started + crate::resources::limits().startup_timeout;
        let serve = async {
            // Virtual time tests the startup/RPC distinction. It supplies no
            // native replay, large-corpus, custody or resource qualification.
            tokio::time::sleep(
                crate::resources::limits().lifecycle_timeout + Duration::from_secs(1),
            )
            .await;
            let control = super::super::Control::bind_token(&directory.0, token.clone()).unwrap();
            let (stream, _) = control.listener.accept().await.unwrap();
            control.respond(stream, 0, true).await.unwrap();
        };
        let (status, ()) = tokio::join!(wait(&directory.0, &token, deadline, || Ok(None)), serve);
        assert!(status.unwrap().running);
        assert!(
            tokio::time::Instant::now() - started
                >= crate::resources::limits().lifecycle_timeout + Duration::from_secs(1)
        );
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
