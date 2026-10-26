//! Native ownership and adaptive scheduling for the checker-owned evaluator.
use crate::resources::adaptive::{Budget, Snapshot};
use naome_checker::program::{CheckedProgram, Engine};
use naome_proof::program::{Command, RECORD_BYTES};
use rusqlite::Connection;
mod lifecycle;
pub(crate) use lifecycle::retire_candidate;
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, Read},
    ops::Deref,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize)]
pub struct Status {
    #[serde(flatten)]
    pub processing: naome_checker::program::Status,
    pub budget: Option<Snapshot>,
}
impl Deref for Status {
    type Target = naome_checker::program::Status;
    fn deref(&self) -> &Self::Target {
        &self.processing
    }
}

pub struct Work {
    engine: Engine,
    path: PathBuf,
    _lock: crate::storage::LockFile,
    identity: (u64, u64),
    last_budget: Option<Snapshot>,
    last_recorded_budget: Option<Snapshot>,
}

/// Keep native file authority alive for as long as the mathematical result is
/// used to copy canonical input or publish checked context nodes.
pub(crate) struct CheckedWork {
    proof: CheckedProgram,
    path: PathBuf,
    identity: (u64, u64),
    _lock: crate::storage::LockFile,
}
impl CheckedWork {
    pub(crate) fn suspend_cache(&mut self) -> Result<(), crate::Error> {
        self.proof()?;
        self.proof.suspend_cache().map_err(crate::Error::from)
    }
    pub(crate) fn restrict_cache(&mut self, bytes: u64) -> Result<(), crate::Error> {
        self.proof()?;
        self.proof
            .restrict_cache(crate::resources::program_cache(bytes))
            .map_err(crate::Error::from)
    }
    pub(crate) fn proof(&self) -> Result<&CheckedProgram, crate::Error> {
        let metadata = crate::storage::owned_file(&self.path)?;
        if self.identity != (metadata.dev(), metadata.ino()) {
            return Err("proof work changed outside its owner".into());
        }
        Ok(&self.proof)
    }
}

impl Work {
    pub(crate) fn suspend_cache(&mut self) -> Result<(), crate::Error> {
        self.live()?;
        self.engine.suspend_cache().map_err(crate::Error::from)
    }
    pub fn open(path: &Path) -> Result<Self, crate::Error> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent).map_err(crate::Error::from)?;
        let path = fs::canonicalize(parent)
            .map_err(crate::Error::from)?
            .join(path.file_name().ok_or("proof work filename missing")?);
        let _disk = crate::resources::DiskLease::acquire(
            path.parent().expect("proof work parent"),
            128 * 1024,
        )?;
        let lock_path = path.with_extension("proof-work.lock");
        let lock = crate::storage::LockFile::open(&lock_path).map_err(crate::Error::from)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(crate::Error::ExecutionLimit),
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        if !path.exists() {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(&path)
                .map_err(crate::Error::from)?;
        }
        let metadata = crate::storage::owned_file(&path)?;
        let connection = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(naome_checker::program::Error::Storage)?;
        crate::storage::sqlite_common(&connection, 1024 * 1024)
            .map_err(naome_checker::program::Error::Storage)?;
        let engine = Engine::open(connection)?;
        File::open(path.parent().expect("proof parent"))
            .and_then(|f| f.sync_all())
            .map_err(crate::Error::from)?;
        Ok(Self {
            engine,
            path,
            _lock: lock,
            identity: (metadata.dev(), metadata.ino()),
            last_budget: None,
            last_recorded_budget: None,
        })
    }
    fn live(&self) -> Result<(), crate::Error> {
        let metadata = crate::storage::owned_file(&self.path)?;
        if self.identity != (metadata.dev(), metadata.ino()) {
            return Err("proof work changed outside its owner".into());
        }
        Ok(())
    }
    pub fn directory(&self) -> &Path {
        self.path.parent().expect("proof work parent")
    }
    pub fn append(&mut self, command: &Command) -> Result<u64, crate::Error> {
        self.append_group(std::slice::from_ref(command))
            .map(|value| value.expect("one appended command"))
    }
    pub(crate) fn append_group(
        &mut self,
        commands: &[Command],
    ) -> Result<Option<u64>, crate::Error> {
        self.live()?;
        let _disk = crate::resources::DiskLease::acquire(
            self.directory(),
            commands.len() as u64 * 32 * 1024,
        )?;
        self.engine
            .append_group(commands)
            .map_err(crate::Error::from)
    }
    /// Parsing and resource reservations belong to the native owner. Every
    /// committed group is canonicalized and hashed by the shared checker.
    pub fn append_reader(&mut self, reader: &mut impl BufRead) -> Result<u64, crate::Error> {
        let mut count = 0;
        let mut pending = Vec::new();
        loop {
            let mut line = Vec::new();
            let bytes = (&mut *reader)
                .take((RECORD_BYTES + 1) as u64)
                .read_until(b'\n', &mut line)
                .map_err(crate::Error::from)?;
            if bytes == 0 {
                self.append_group(&pending)?;
                return Ok(count + pending.len() as u64);
            }
            if bytes > RECORD_BYTES {
                self.append_group(&pending)?;
                return Err("proof command byte capacity; split construction into records".into());
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let command = match serde_json::from_slice(&line) {
                Ok(command) => command,
                Err(e) => {
                    self.append_group(&pending)?;
                    return Err(format!(
                        "proof command after {} appended records: {e}",
                        count + pending.len() as u64
                    )
                    .into());
                }
            };
            pending.push(command);
            if pending.len()
                >= crate::resources::adaptive::batch(
                    crate::resources::active_limits()
                        .compaction_records
                        .min(naome_proof::program::CHUNK_RECORDS),
                )
                .max(1)
            {
                self.append_group(&pending)?;
                count += pending.len() as u64;
                pending.clear();
            }
        }
    }
    pub fn record_budget(&mut self, snapshot: &Snapshot) -> Result<(), crate::Error> {
        self.live()?;
        if self.last_recorded_budget.as_ref().is_none_or(|last| {
            last.selection != snapshot.selection
                || last.budget != snapshot.budget
                || snapshot.timestamp_ms.saturating_sub(last.timestamp_ms) >= 60_000
        }) {
            self.engine.record_budget(
                &serde_json::to_vec(snapshot)
                    .map_err(|error| crate::Error::InvalidInput(error.to_string()))?,
            )?;
            self.last_recorded_budget = Some(snapshot.clone());
        }
        self.last_budget = Some(snapshot.clone());
        Ok(())
    }
    pub(crate) fn restrict_cache(&mut self, bytes: u64) -> Result<(), crate::Error> {
        self.live()?;
        self.engine
            .advance(0, bytes, &naome_checker::ArtifactState::new())
            .map(|_| ())
            .map_err(crate::Error::from)
    }
    pub fn advance(
        &mut self,
        budget: &Budget,
        context: &dyn naome_checker::ContextView,
    ) -> Result<bool, crate::Error> {
        self.advance_impl(budget, context, None)
    }
    /// Uses the same resource admission, quantum feedback and rollback as
    /// ordinary checking, capturing one bounded fragment before a failure.
    pub fn advance_with_inspection(
        &mut self,
        budget: &Budget,
        context: &dyn naome_checker::ContextView,
        query: &naome_checker::diagnostics::FormulaQuery,
    ) -> Result<bool, crate::Error> {
        query
            .validate()
            .map_err(crate::Error::DiagnosticInspection)?;
        self.advance_impl(budget, context, Some(query))
    }
    /// Reads only live, authenticated prefix state named by a bound diagnostic.
    /// Reopening or rolling back may require the ordinary checker to replay.
    pub fn inspect_formula(
        &self,
        diagnostic: &naome_checker::diagnostics::ProofDiagnostic,
        query: &naome_checker::diagnostics::FormulaQuery,
        context: &dyn naome_checker::ContextView,
    ) -> Result<naome_checker::diagnostics::FormulaFragment, crate::Error> {
        self.live()?;
        query
            .validate()
            .map_err(crate::Error::DiagnosticInspection)?;
        crate::resources::require_work_admission()?;
        let _memory = crate::resources::MemoryLease::acquire(
            query.maximum_nodes * 256 + query.path.len() * 64 + 1024,
        )?;
        self.engine
            .inspect_formula(diagnostic, query, context)
            .map_err(crate::Error::from)
    }
    fn advance_impl(
        &mut self,
        budget: &Budget,
        context: &dyn naome_checker::ContextView,
        query: Option<&naome_checker::diagnostics::FormulaQuery>,
    ) -> Result<bool, crate::Error> {
        self.live()?;
        let _inspection_memory = query
            .map(|query| {
                crate::resources::MemoryLease::acquire(
                    query.maximum_nodes * 256 + query.path.len() * 64 + 1024,
                )
            })
            .transpose()?;
        if budget.cache_bytes < 4096
            || budget.cache_bytes > (budget.memory_bytes / 4).max(4096)
            || budget.cache_bytes > crate::resources::limits().memory_bytes as u64 / 4
        {
            return Err("invalid effective cache budget".into());
        }
        let cache = crate::resources::program_cache(
            budget.cache_bytes.min(
                crate::resources::adaptive::current()
                    .map_or(budget.cache_bytes, |active| active.budget.cache_bytes),
            ),
        );
        self.restrict_cache(cache)?;
        if budget.paused.is_some() || budget.batch_steps == 0 {
            return Ok(false);
        }
        crate::resources::require_work_admission()?;
        if budget.memory_bytes < 8 * 1024 * 1024
            || budget.cache_bytes > budget.memory_bytes / 4
            || budget.batch_steps > budget.memory_bytes as usize / 8192
            || budget.concurrency == 0
        {
            return Err("invalid effective proof budget".into());
        }
        let _disk = crate::resources::DiskLease::acquire(
            self.directory(),
            (budget.batch_steps as u64).saturating_mul(16 * 1024),
        )?;
        let started = std::time::Instant::now();
        let steps = crate::resources::adaptive::batch(budget.batch_steps);
        let result = match query {
            Some(query) => self
                .engine
                .advance_with_inspection(steps, cache, context, query),
            None => self.engine.advance(steps, cache, context),
        };
        crate::resources::feedback::record(
            crate::resources::feedback::Kind::Check,
            self.engine.last_quantum_steps(),
            started.elapsed(),
        );
        result.map_err(crate::Error::from)
    }
    pub fn status(&self) -> Result<Status, crate::Error> {
        self.live()?;
        Ok(Status {
            processing: self.engine.status()?,
            budget: self.last_budget.clone(),
        })
    }
    pub(crate) fn into_checked(self) -> Result<CheckedWork, crate::Error> {
        self.live()?;
        Ok(CheckedWork {
            proof: self.engine.checked()?,
            path: self.path,
            identity: self.identity,
            _lock: self._lock,
        })
    }
    pub(crate) fn prepare_export(&mut self, budget: &Budget) -> Result<bool, crate::Error> {
        self.live()?;
        self.restrict_cache(crate::resources::program_cache(budget.cache_bytes))?;
        if budget.paused.is_some() || budget.batch_steps == 0 {
            return Ok(false);
        }
        crate::resources::require_work_admission()?;
        let _disk = crate::resources::DiskLease::acquire(
            self.directory(),
            (budget.batch_steps as u64).saturating_mul(8192),
        )?;
        self.engine
            .prepare_export(budget.batch_steps)
            .map_err(crate::Error::from)
    }
}

#[cfg(test)]
mod tests;
