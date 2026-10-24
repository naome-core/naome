//! Native process-group custody shared by bounded providers and decision inference.
use std::{
    fs::File,
    process::Child,
    time::{Duration, Instant},
};

static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serialize the deliberate inheritance of a physical worker lease. The
/// caller retains child custody and must reconcile a failed flag restoration.
pub(crate) fn spawn_with_slot<T>(
    slot: &File,
    spawn: impl FnOnce() -> T,
) -> Result<(T, nix::Result<()>), String> {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    let _spawn = SPAWN.lock().map_err(|_| "process spawn lock poisoned")?;
    let original =
        FdFlag::from_bits_retain(fcntl(slot, FcntlArg::F_GETFD).map_err(|e| e.to_string())?);
    fcntl(
        slot,
        FcntlArg::F_SETFD(original.difference(FdFlag::FD_CLOEXEC)),
    )
    .map_err(|e| e.to_string())?;
    let spawned = spawn();
    let restored = fcntl(slot, FcntlArg::F_SETFD(original)).map(|_| ());
    Ok((spawned, restored))
}

pub(crate) fn stop_worker(child: &mut Child) -> Result<(), String> {
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

pub(crate) fn monotonic_ns() -> Result<u64, String> {
    let now =
        nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).map_err(|e| e.to_string())?;
    u64::try_from(now.tv_sec())
        .ok()
        .and_then(|s| s.checked_mul(1_000_000_000))
        .and_then(|s| s.checked_add(u64::try_from(now.tv_nsec()).ok()?))
        .ok_or_else(|| "invalid native startup clock".into())
}

#[cfg(test)]
mod tests;
