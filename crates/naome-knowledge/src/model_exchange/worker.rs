use super::{Bundle, Challenge, Comparison, bundle::Artifacts, replay::replay};
use crate::{jobs::ModelLease, resources::MemoryLease};
use serde::{Deserialize, Serialize};
use std::os::fd::AsRawFd;
use std::{
    io::{Read, Write},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const COMMAND: &str = "__model-reference";
const INTERNAL: &str = "NAOME_MODEL_REFERENCE";
const HEADER_BYTES: usize = 8192;
const RECEIPT_BYTES: usize = 4096;
const WATCHDOG: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    challenge: Challenge,
    previous: Option<Comparison>,
    slot_fd: i32,
}

pub(crate) async fn compare(
    challenge: Challenge,
    previous: Option<Comparison>,
    local: &Bundle,
    remote: &Bundle,
    lease: ModelLease,
) -> Result<Comparison, String> {
    if local.registration != challenge.local || remote.registration != challenge.remote {
        return Err("reference registrations differ from transferred bytes".into());
    }
    let header = crate::checkpoint::encode(&Start {
        challenge: challenge.clone(),
        previous,
        slot_fd: lease.slot.as_raw_fd(),
    })?;
    if header.len() > HEADER_BYTES {
        return Err("reference request byte capacity".into());
    }

    let mut command =
        tokio::process::Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg(COMMAND)
        .env_clear()
        .env(INTERNAL, "1")
        .env(
            "NAOME_EFFECTIVE_RESOURCES",
            crate::resources::child_snapshot()?,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let (spawned, restored) = crate::jobs::spawn_in_slot(&mut command, &lease.slot)?;
    let mut child = spawned.map_err(|e| e.to_string())?;
    if let Err(error) = restored {
        let _ = child.kill().await;
        return Err(error.to_string());
    }
    let mut input = child.stdin.take().ok_or("reference request pipe absent")?;
    let mut output = child
        .stdout
        .take()
        .ok_or("reference response pipe absent")?;
    let result = tokio::time::timeout(WATCHDOG, async {
        input
            .write_all(&(header.len() as u32).to_be_bytes())
            .await?;
        input.write_all(&header).await?;
        for part in local.parts().chain(remote.parts()) {
            input.write_all(part).await?;
        }
        let mut response = Vec::new();
        (&mut output)
            .take(RECEIPT_BYTES as u64 + 1)
            .read_to_end(&mut response)
            .await?;
        if response.len() > RECEIPT_BYTES {
            return Err(std::io::Error::other("reference response byte capacity"));
        }
        Ok::<_, std::io::Error>((child.wait().await?, response))
    })
    .await;
    drop(input); // Closing the pipe also revokes the child's work after parent loss.
    let (status, response) = match result {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            let _ = child.kill().await;
            return Err(error.to_string());
        }
        Err(_) => {
            let _ = child.kill().await;
            return Err("reference comparison watchdog expired".into());
        }
    };
    if !status.success() {
        return Err(format!("reference worker stopped: {status}"));
    }
    let result: Result<Comparison, String> = crate::checkpoint::decode(&response)?;
    let comparison = result?;
    if comparison.challenge != challenge {
        return Err("reference response belongs to different registrations".into());
    }
    Ok(comparison)
}

pub(crate) fn internal(arguments: &[std::ffi::OsString]) -> Option<Result<(), String>> {
    let [arg] = arguments else { return None };
    (arg == COMMAND).then(|| {
        if std::env::var(INTERNAL).as_deref() != Ok("1") {
            return Err("internal reference invocation required".into());
        }
        let result = run();
        let bytes = crate::checkpoint::encode(&result)?;
        if bytes.len() > RECEIPT_BYTES {
            return Err("reference receipt byte capacity".into());
        }
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|e| e.to_string())
    })
}

fn run() -> Result<Comparison, String> {
    // The node also reserves this envelope for the lifetime of the child.
    let _work = MemoryLease::acquire(crate::resources::limits().native_model_work_bytes)
        .map_err(|e| e.to_string())?;
    let mut input = std::io::stdin().lock();
    let mut len = [0; 4];
    input.read_exact(&mut len).map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len) as usize;
    if len > HEADER_BYTES {
        return Err("reference request byte capacity".into());
    }
    let mut header = vec![0; len];
    input.read_exact(&mut header).map_err(|e| e.to_string())?;
    let Start {
        challenge,
        previous,
        slot_fd,
    } = crate::checkpoint::decode(&header)?;
    challenge.validate()?;
    // No new descendants are started. The inherited physical lease remains
    // open until the process exits, including during parent crash cleanup.
    if slot_fd <= 2 {
        return Err("model reference worker slot descriptor differs".into());
    }
    let mut load = |registration: &super::Registration| {
        let memory = Bundle::reserve(registration)?;
        let parts = registration
            .model
            .blobs()
            .map(|blob| {
                let mut bytes = vec![0; blob.bytes];
                input.read_exact(&mut bytes).map_err(|e| e.to_string())?;
                Ok(bytes)
            })
            .collect::<Result<_, String>>()?;
        Bundle::new(registration.clone(), parts, memory)
    };
    let local = load(&challenge.local)?;
    let remote = load(&challenge.remote)?;
    drop(input);
    // This worker has no subprocesses or filesystem custody. EOF or unexpected
    // bytes kill in-progress inference even when its parent died abruptly.
    std::thread::spawn(|| {
        let _ = std::io::stdin().read(&mut [0]);
        std::process::exit(125);
    });
    replay(
        challenge,
        previous.as_ref(),
        &mut Artifacts(&local, &remote),
    )
}
