//! Optional caller-owned status replay custody; no stored validity authority.
use nix::{
    sys::{
        resource::{UsageWho, getrusage},
        signal::{Signal, killpg},
    },
    time::{ClockId, clock_gettime},
    unistd::{getpgrp, getpid, getsid},
};
use std::{
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const SETTING: &str = "NAOME_STATUS_REPLAY_GUARD";
// Fixed grammar: verb, a 256-bit nonce, two u64 clocks and separators.
const MAX_FRAME: usize = 192;
fn active_ns() -> u64 {
    crate::resources::limits().replay_guard_timeout.as_nanos() as u64
}
fn fresh_ns() -> u64 {
    crate::resources::limits().replay_guard_freshness.as_nanos() as u64
}
fn own_rss_bytes() -> u64 {
    crate::resources::limits().replay_guard_bytes as u64
}

struct Descriptor {
    nonce: String,
    deadline: u64,
}
struct Grants {
    nonce: String,
    deadline: u64,
    opened: u64,
    sampled: Option<u64>,
    sequence: u64,
    frame: Vec<u8>,
}
pub(super) struct Guard {
    done: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
    deadline: u64,
    sampled: Arc<AtomicU64>,
}

fn now() -> Result<u64, String> {
    let value = clock_gettime(ClockId::CLOCK_MONOTONIC).map_err(|error| error.to_string())?;
    u64::try_from(value.tv_sec())
        .map_err(|_| "negative replay clock")?
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec() as u64))
        .ok_or_else(|| "replay clock overflow".into())
}
fn own_peak() -> Result<u64, String> {
    let value = u64::try_from(
        getrusage(UsageWho::RUSAGE_SELF)
            .map_err(|error| error.to_string())?
            .max_rss(),
    )
    .map_err(|_| "negative replay RSS")?;
    #[cfg(target_os = "linux")]
    let value = value.checked_mul(1024).ok_or("replay RSS overflow")?;
    if value == 0 {
        return Err("own replay RSS unavailable".into());
    }
    Ok(value)
}
impl Descriptor {
    fn parse(value: &str, current: u64) -> Result<Self, String> {
        let Some((nonce, deadline)) = value.split_once(':') else {
            return Err("invalid status replay descriptor".into());
        };
        if nonce.len() != 64 || crate::unhex(nonce)?.len() != 32 {
            return Err("invalid status replay nonce".into());
        }
        let deadline: u64 = deadline.parse().map_err(|_| "invalid replay cutoff")?;
        if deadline <= current || deadline - current > active_ns() {
            return Err(
                "status replay cutoff is expired or exceeds its configured allowance".into(),
            );
        }
        Ok(Self {
            nonce: nonce.to_owned(),
            deadline,
        })
    }
}
impl Grants {
    fn new(descriptor: Descriptor, opened: u64) -> Self {
        Self {
            nonce: descriptor.nonce,
            deadline: descriptor.deadline,
            opened,
            sampled: None,
            sequence: 0,
            frame: Vec::with_capacity(MAX_FRAME),
        }
    }
    fn push(&mut self, input: &[u8], current: u64) -> Result<bool, String> {
        let mut received = false;
        for byte in input {
            self.frame.push(*byte);
            if self.frame.len() > MAX_FRAME {
                return Err("status replay frame limit".into());
            }
            if *byte != b'\n' {
                continue;
            }
            let line = std::str::from_utf8(&self.frame).map_err(|_| "invalid replay frame")?;
            let fields = line.trim_end_matches('\n').split(' ').collect::<Vec<_>>();
            if fields.len() != 4 || fields[0] != "grant" || fields[1] != self.nonce {
                return Err("status replay grant identity differs".into());
            }
            let sequence: u64 = fields[2].parse().map_err(|_| "invalid replay sequence")?;
            let sampled: u64 = fields[3]
                .parse()
                .map_err(|_| "invalid replay sample clock")?;
            if self.sequence.checked_add(1) != Some(sequence)
                || sampled == 0
                || sampled > current
                || self.sampled.is_some_and(|previous| sampled < previous)
                || current - sampled > fresh_ns()
                || current >= self.deadline
            {
                return Err("status replay sequence, freshness or cutoff differs".into());
            }
            self.sampled = Some(sampled);
            self.sequence = sequence;
            self.frame.clear();
            received = true;
        }
        Ok(received)
    }
    fn check(&self, current: u64, peak: u64) -> Result<(), String> {
        check_usage(current, peak, self.deadline)?;
        let sampled = self.sampled.unwrap_or(self.opened);
        if sampled > current || current - sampled > fresh_ns() {
            return Err("status replay grant expired".into());
        }
        Ok(())
    }
}
fn check_usage(current: u64, peak: u64, deadline: u64) -> Result<(), String> {
    if current >= deadline {
        return Err("original status replay deadline reached".into());
    }
    if peak == 0 || peak > own_rss_bytes() {
        return Err("status replay own RSS exceeds its configured budget or is unavailable".into());
    }
    Ok(())
}
fn fail_group(_error: &str) -> ! {
    // No output or other fallible/blocking work may precede termination.
    // Arming verified this caller's detached group. No discovered/persisted PID.
    let _ = killpg(getpgrp(), Signal::SIGKILL);
    std::process::exit(125)
}

pub(super) fn optional(command: &str) -> Result<Option<Guard>, String> {
    let value = match std::env::var(SETTING) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => return Err("invalid status replay setting".into()),
    };
    if command != "status" {
        return Err("status replay guard requires the status command".into());
    }
    let current = now()?;
    let descriptor = Descriptor::parse(&value, current)?;
    if getpgrp() != getpid() || getsid(None).map_err(|error| error.to_string())? != getpid() {
        return Err("status replay guard requires its own detached group".into());
    }
    let input = std::io::stdin();
    let flags = nix::fcntl::fcntl(&input, nix::fcntl::FcntlArg::F_GETFL)
        .map_err(|error| error.to_string())?;
    nix::fcntl::fcntl(
        &input,
        nix::fcntl::FcntlArg::F_SETFL(
            nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK,
        ),
    )
    .map_err(|error| error.to_string())?;
    let deadline = descriptor.deadline;
    let done = Arc::new(AtomicBool::new(false));
    let finished = done.clone();
    let sampled = Arc::new(AtomicU64::new(0));
    let latest = sampled.clone();
    let (send, receive) = mpsc::sync_channel(1);
    let watcher = thread::Builder::new()
        .name("naome-status-replay-lifeline".into())
        .spawn(move || {
            if let Err(error) = watch(input, descriptor, &finished, &latest, send) {
                fail_group(&error);
            }
        })
        .map_err(|error| error.to_string())?;
    let guard = Guard {
        done,
        watcher: Some(watcher),
        deadline,
        sampled,
    };
    receive
        .recv_timeout(Duration::from_nanos(
            fresh_ns().min(deadline.saturating_sub(now()?)),
        ))
        .map_err(|_| "status replay initial grant unavailable")?;
    Ok(Some(guard))
}
fn watch(
    mut input: impl Read,
    descriptor: Descriptor,
    done: &AtomicBool,
    sampled: &AtomicU64,
    started: mpsc::SyncSender<()>,
) -> Result<(), String> {
    let mut state = Grants::new(descriptor, now()?);
    let mut admitted = false;
    let mut bytes = [0; 512];
    while !done.load(Ordering::Acquire) {
        state.check(now()?, own_peak()?)?;
        match input.read(&mut bytes) {
            Ok(0) => return Err("status replay parent lifeline closed".into()),
            Ok(count) => {
                let received = state.push(&bytes[..count], now()?)?;
                if received {
                    sampled.store(
                        state.sampled.expect("valid complete grant"),
                        Ordering::Release,
                    );
                }
                if received && !admitted {
                    state.check(now()?, own_peak()?)?;
                    started.send(()).map_err(|_| "status replay caller gone")?;
                    admitted = true;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(crate::resources::limits().custody_poll_interval)
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("status replay lifeline unreadable: {error}")),
        }
    }
    Ok(())
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Err(error) = self.check_final() {
            fail_group(&error);
        }
        self.done.store(true, Ordering::Release);
        if self
            .watcher
            .take()
            .is_some_and(|watcher| watcher.join().is_err())
        {
            fail_group("status replay watcher panicked");
        }
        // Joining and dropping the watcher are inside the original interval.
        if let Err(error) = self.check_final() {
            fail_group(&error);
        }
    }
}
impl Guard {
    fn check_final(&self) -> Result<(), String> {
        let current = now()?;
        let sampled = self.sampled.load(Ordering::Acquire);
        if sampled == 0 || sampled > current || current - sampled > fresh_ns() {
            return Err("status replay final grant expired".into());
        }
        check_usage(current, own_peak()?, self.deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> Descriptor {
        Descriptor {
            nonce: "ab".repeat(32),
            deadline: 100 * 1_000_000_000,
        }
    }
    fn frame(sequence: u64, sampled: u64) -> Vec<u8> {
        format!("grant {} {sequence} {sampled}\n", "ab".repeat(32)).into_bytes()
    }
    #[test]
    fn descriptor_preserves_original_cutoff_and_rejects_invalid_windows() {
        let nonce = "ab".repeat(32);
        assert!(Descriptor::parse(&format!("{nonce}:{}", active_ns()), 1).is_ok());
        for value in [
            format!("{nonce}:1"),
            format!("{nonce}:{}", active_ns() + 2),
            format!("{nonce}:invalid"),
            "00:100".into(),
            format!("{}:100", "zz".repeat(32)),
        ] {
            assert!(Descriptor::parse(&value, 1).is_err());
        }
    }
    #[test]
    fn grants_require_exact_nonce_order_and_fresh_sample_clocks() {
        let mut state = Grants::new(descriptor(), 1);
        assert!(state.push(&frame(1, 1), 2).unwrap());
        assert!(state.push(&frame(2, 2), 3).unwrap());
        for bad in [frame(2, 2), frame(4, 3), frame(3, 4), frame(3, 1)] {
            assert!(state.push(&bad, 3).is_err());
            state.frame.clear();
        }
        let wrong = format!("grant {} 3 3\n", "cd".repeat(32));
        assert!(state.push(wrong.as_bytes(), 3).is_err());
    }
    #[test]
    fn partial_and_oversized_frames_never_admit_a_grant() {
        let mut state = Grants::new(descriptor(), 1);
        let value = frame(1, 1);
        assert!(!state.push(&value[..value.len() - 1], 2).unwrap());
        assert_eq!(state.sequence, 0);
        assert!(state.push(b"\n", 2).unwrap());
        assert_eq!(state.sequence, 1);
        assert!(state.push(&[b'x'; MAX_FRAME + 1], 3).is_err());
    }
    #[test]
    fn silence_and_original_expiry_never_renew_admission() {
        let mut state = Grants::new(descriptor(), 1);
        assert!(state.check(fresh_ns() + 2, 1).is_err());
        assert!(state.push(&frame(1, 1), 2).unwrap());
        assert!(state.check(fresh_ns() + 2, 1).is_err());
        assert!(
            state
                .push(&frame(2, state.deadline), state.deadline)
                .is_err()
        );
    }
    #[test]
    fn final_usage_and_both_reserves_preserve_total_rss_limit() {
        assert_eq!(own_rss_bytes() + 2 * 64 * 1024 * 1024, 512 * 1024 * 1024);
        assert!(check_usage(1, own_rss_bytes(), 2).is_ok());
        assert!(check_usage(1, own_rss_bytes() + 1, 2).is_err());
        assert!(check_usage(1, 0, 2).is_err());
        assert!(check_usage(2, own_rss_bytes(), 2).is_err());
    }
}
