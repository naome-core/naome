//! Bounded output and wall-clock custody for trusted, read-only OS probes.
use std::{
    io::{ErrorKind, Read},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

// A timed-out Child stays owned until a later try_wait confirms reaping. Never
// accumulate helper processes when the OS cannot complete a previous probe.
static OWNED: Mutex<Option<Child>> = Mutex::new(None);

pub(super) fn run(
    path: &str,
    arguments: &[&str],
    maximum: usize,
    deadline: Instant,
) -> Result<String, String> {
    let mut owned = OWNED
        .lock()
        .map_err(|_| "hardware probe custody unavailable")?;
    if let Some(child) = owned.as_mut() {
        match child
            .try_wait()
            .map_err(|_| "hardware probe custody unconfirmed")?
        {
            Some(_) => {
                owned.take();
            }
            None => return Err("previous hardware probe cleanup pending".into()),
        }
    }
    if Instant::now() >= deadline {
        return Err("hardware observation deadline".into());
    }
    *owned = Some(
        Command::new(path)
            .args(arguments)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?,
    );
    let child = owned.as_mut().expect("owned hardware probe");
    let mut output = child
        .stdout
        .take()
        .ok_or("hardware observation output absent")?;
    let flags = nix::fcntl::fcntl(&output, nix::fcntl::FcntlArg::F_GETFL)
        .map_err(|error| error.to_string());
    let result = flags.and_then(|flags| {
        nix::fcntl::fcntl(
            &output,
            nix::fcntl::FcntlArg::F_SETFL(
                nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK,
            ),
        )
        .map_err(|error| error.to_string())?;
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        let mut eof = false;
        loop {
            if Instant::now() >= deadline {
                return Err("hardware observation deadline".into());
            }
            match output.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(count) => {
                    if bytes.len().saturating_add(count) > maximum {
                        return Err("hardware observation capacity".into());
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.to_string()),
            }
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())?
                && eof
            {
                if !status.success() {
                    return Err("hardware observation failed".into());
                }
                return String::from_utf8(bytes).map_err(|error| error.to_string());
            }
            if !eof {
                // Drain a ready pipe before waiting; output remains capped.
                match output.read(&mut buffer) {
                    Ok(0) => eof = true,
                    Ok(count) => {
                        if bytes.len().saturating_add(count) > maximum {
                            return Err("hardware observation capacity".into());
                        }
                        bytes.extend_from_slice(&buffer[..count]);
                        continue;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.to_string()),
                }
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(1)),
            );
        }
    });
    match child.try_wait() {
        Ok(Some(_)) => {
            owned.take();
        }
        Ok(None) => {
            // The exact original unreaped Child still owns this PID. Keep it
            // through cleanup; do not signal after an uncertain try_wait error.
            let _ = child.kill();
            if matches!(child.try_wait(), Ok(Some(_))) {
                owned.take();
            }
        }
        Err(_) => {}
    }
    result
}

#[cfg(test)]
mod tests;
