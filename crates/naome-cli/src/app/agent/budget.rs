//! Durable, exclusive inference reservations. Missing results consume the whole
//! reserved tool allowance, because a crashed provider's usage is unknowable.
use super::*;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
};

pub(super) struct Budget {
    _lock: File,
    prefix: PathBuf,
    context: String,
    maximum: u64,
    tools: u64,
}
impl Drop for Budget {
    fn drop(&mut self) {
        // An incidental fork can retain this shared file description until
        // exec, even though the descriptor is close-on-exec. Release the owning
        // review's lock explicitly, as storage's ExclusiveLock does, before the
        // File close fallback. A forked provider never owns budget authority.
        let _ = self._lock.unlock();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    context: String,
    index: u64,
    remaining: u64,
    request: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Outcome {
    context: String,
    pub index: u64,
    pub request: String,
    pub decision: Decision,
    pub elapsed_ms: u64,
}
impl Budget {
    pub fn open(
        directory: &Path,
        question: &str,
        attempt: u64,
        context: String,
        maximum: u64,
        tools: u64,
    ) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("agent budget directory must be private and owned by this user".into());
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(directory.join("agent-review.lock"))?;
        let metadata = lock.metadata()?;
        if !metadata.is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("agent budget lock must be a private owned regular file".into());
        }
        lock.try_lock()
            .map_err(|_| "another agent review is active for this node")?;
        let _ = files::unhex::<32>(question)?;
        Ok(Self {
            _lock: lock,
            prefix: directory.join(format!("agent-{question}-{attempt}")),
            context,
            maximum,
            tools,
        })
    }
    pub fn path(&self, suffix: &str) -> PathBuf {
        self.prefix.with_extension(suffix)
    }
    pub fn load(&self) -> Result<(u64, u64, Option<Outcome>)> {
        let mut used = 0;
        let mut remaining = self.tools;
        let mut accepted = None;
        for index in 1..=self.maximum {
            let reservation_path = self.path(&format!("{index}.reservation"));
            let outcome_path = self.path(&format!("{index}.result"));
            if !reservation_path.try_exists()? {
                if outcome_path.try_exists()? {
                    return Err("orphaned agent result".into());
                }
                continue;
            }
            if index != used + 1 || accepted.is_some() {
                return Err("invalid agent budget sequence".into());
            }
            let bytes = files::read(&reservation_path, 65536, true)?;
            let reservation: Reservation = serde_json::from_slice(&bytes)?;
            if reservation.context != self.context
                || reservation.index != index
                || reservation.remaining != remaining
            {
                return Err("agent budget context or allowance changed".into());
            }
            files::create_or_match(&reservation_path, &bytes, true)?;
            used = index;
            if outcome_path.try_exists()? {
                let bytes = files::read(&outcome_path, 65536, true)?;
                let outcome: Outcome = serde_json::from_slice(&bytes)?;
                if outcome.context != self.context
                    || outcome.index != index
                    || outcome.request != reservation.request
                    || !valid_decision(&outcome.decision)
                {
                    return Err("invalid durable agent result".into());
                }
                files::create_or_match(&outcome_path, &bytes, true)?;
                if outcome.decision.tool_calls <= remaining {
                    remaining -= outcome.decision.tool_calls;
                    accepted = Some(outcome);
                } else {
                    remaining = 0;
                }
            } else {
                remaining = 0;
            }
        }
        Ok((used, remaining, accepted))
    }
    pub fn reserve(&self, index: u64, remaining: u64, input: &[u8]) -> Result<String> {
        let request = files::hex(&Sha256::digest(input));
        files::create(
            &self.path(&format!("{index}.reservation")),
            &serde_json::to_vec(&Reservation {
                context: self.context.clone(),
                index,
                remaining,
                request: request.clone(),
            })?,
            true,
        )?;
        Ok(request)
    }
    pub fn complete(
        &self,
        index: u64,
        request: String,
        decision: Decision,
        elapsed_ms: u64,
    ) -> Result<()> {
        let bytes = serde_json::to_vec(&Outcome {
            context: self.context.clone(),
            index,
            request,
            decision,
            elapsed_ms,
        })?;
        if bytes.len() > 65536 {
            return Err("agent result exceeds durable limit".into());
        }
        files::create(&self.path(&format!("{index}.result")), &bytes, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_budget_releases_lock_even_while_inherited_description_survives() {
        let directory = std::env::temp_dir().join(format!(
            "nr-agent-lock-{}-{}",
            std::process::id(),
            files::hex(files::random().unwrap().as_ref())
        ));
        files::directory(&directory).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let question = "11".repeat(32);
        let open = || Budget::open(&directory, &question, 1, "context".into(), 2, 4);
        let budget = open().unwrap();
        // Duplication models the shared open-file description inherited by an
        // unrelated fork. Production never exposes or duplicates the lock.
        let inherited = budget._lock.try_clone().unwrap();
        assert!(open().is_err());
        drop(budget);
        let next = open().expect("finished review releases authority despite inherited descriptor");
        assert!(open().is_err());
        drop(inherited);
        assert!(
            open().is_err(),
            "closing an old descriptor must not release the new owner"
        );
        drop(next);
        assert!(open().is_ok());
    }
}
