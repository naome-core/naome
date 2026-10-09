use super::*;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Account {
    pub settings: RoleSettings,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub spent_ms: u64,
    pub reserved_units: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub version: u8,
    pub compatibility: String,
    pub configuration: String,
    pub next_id: u64,
    pub next_cursor: u64,
    pub observed_ms: u64,
    pub retired_jobs: u64,
    pub total_spent_ms: u64,
    pub total_reserved_units: u64,
    pub records: BTreeMap<u64, Record>,
    pub accounts: BTreeMap<String, Account>,
    pub slots: Vec<(u64, u64)>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u8,
    payload: T,
    sha256: String,
}

pub(super) struct Disk {
    path: PathBuf,
    slots: Vec<(u64, u64)>,
}

impl Disk {
    pub(super) fn open(
        directory: &Path,
        settings: Settings,
        cursor: u64,
    ) -> Result<(Self, Journal), String> {
        let root = research_directory(directory)?;
        let path = root.join("jobs.json");
        let marker = directory.join("research.initialized");
        let initialized = marker_valid(&marker, b"naome-research-jobs-v1\n")?;
        let mut journal: Journal = match read(&path, MAX_JOURNAL_BYTES)? {
            Some(value) => value,
            None => {
                if initialized {
                    return Err("research journal is missing; refusing a fresh allowance".into());
                }
                Journal {
                    version: 1,
                    compatibility: crate::hex(&crate::compatibility()),
                    configuration: identity(&settings),
                    next_id: 1,
                    next_cursor: cursor,
                    observed_ms: wall_ms()?,
                    retired_jobs: 0,
                    total_spent_ms: 0,
                    total_reserved_units: 0,
                    records: BTreeMap::new(),
                    accounts: BTreeMap::new(),
                    slots: install_slots(&root)?,
                }
            }
        };
        let now = wall_ms()?;
        journal.validate(settings)?;
        for (index, expected) in journal.slots.iter().enumerate() {
            let file = slot_file(&root, index, false)?;
            let metadata = file.metadata().map_err(|e| e.to_string())?;
            if (metadata.dev(), metadata.ino()) != *expected {
                return Err("research physical slot identity differs".into());
            }
        }
        if now < journal.observed_ms {
            return Err(
                "research clock moved backwards; original budgets require reconciliation".into(),
            );
        }
        // Deterministic mock state is resumable. Charge downtime conservatively;
        // neither a process PID nor a prior provider response grants authority.
        for record in journal.records.values_mut() {
            if !record.state.terminal() && record.state != State::InDoubt {
                let elapsed = now
                    .checked_sub(record.accounted_ms)
                    .ok_or("research clock rollback")?;
                record.spent_ms = record.spent_ms.saturating_add(elapsed);
                journal.total_spent_ms = journal.total_spent_ms.saturating_add(elapsed);
                if let Some(account) = journal.accounts.get_mut(&record.input.account_key()) {
                    account.spent_ms = account.spent_ms.saturating_add(elapsed);
                }
                record.accounted_ms = now;
                record.state = if record.state == State::Running
                    && record.settings.recovery == RecoveryPolicy::HoldInFlight
                {
                    State::InDoubt
                } else if now >= record.expires_ms
                    || record.spent_ms >= record.settings.limits.horizon_ms
                {
                    State::Expired
                } else if record.provider == "naome-deterministic-mocks-v1"
                    && record.settings.recovery == RecoveryPolicy::DeterministicCheckpoint
                {
                    State::Suspended
                } else {
                    State::InDoubt
                };
            }
        }
        journal.observed_ms = now;
        let disk = Self {
            path,
            slots: journal.slots.clone(),
        };
        disk.save(&journal)?;
        if !initialized {
            write_marker(&marker, b"naome-research-jobs-v1\n")?;
        }
        Ok((disk, journal))
    }

    pub(super) fn save(&self, journal: &Journal) -> Result<(), String> {
        write(&self.path, journal, MAX_JOURNAL_BYTES)
    }

    /// Seven stable kernel locks cap physical provider lifetimes across a daemon
    /// crash. Supervisors, workers and their owned descendants retain the same
    /// open description until exit; a restart never signals a persisted PID.
    pub(super) fn slot(&self, lane: usize) -> Result<Option<File>, String> {
        let range = match lane {
            0 => 0..1,
            1 => 1..3,
            2 => 3..5,
            3 => 5..7,
            _ => return Err("research slot lane differs".into()),
        };
        let root = self.path.parent().ok_or("research slot parent absent")?;
        for index in range {
            let file = slot_file(root, index, false)?;
            let metadata = file.metadata().map_err(|e| e.to_string())?;
            if self.slots.get(index) != Some(&(metadata.dev(), metadata.ino())) {
                return Err("research physical slot identity differs".into());
            }
            match file.try_lock() {
                Ok(()) => {
                    file.sync_all().map_err(|e| e.to_string())?;
                    File::open(root)
                        .and_then(|f| f.sync_all())
                        .map_err(|e| e.to_string())?;
                    return Ok(Some(file));
                }
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(error) => return Err(format!("research slot lock: {error}")),
            }
        }
        Ok(None)
    }
}

impl Journal {
    pub(super) fn validate(&self, settings: Settings) -> Result<(), String> {
        if self.version != 1
            || self.compatibility != crate::hex(&crate::compatibility())
            || self.configuration != identity(&settings)
            || self.next_id == 0
            || self.records.len() > MAX_RECORDS
            || self.accounts.len() > MAX_ACCOUNTS
            || self.slots.len() != 7
        {
            return Err(
                "research journal version, compatibility, configuration or capacity differs".into(),
            );
        }
        if self
            .retired_jobs
            .checked_add(self.records.len() as u64)
            .and_then(|n| n.checked_add(1))
            != Some(self.next_id)
        {
            return Err("research monotonic sequence or retired accounting differs".into());
        }
        let units = self
            .accounts
            .values()
            .try_fold(0u64, |sum, a| sum.checked_add(u64::from(a.reserved_units)))
            .ok_or("research aggregate units overflow")?;
        let spent = self
            .accounts
            .values()
            .try_fold(0u64, |sum, a| sum.checked_add(a.spent_ms))
            .ok_or("research aggregate time overflow")?;
        if units > self.total_reserved_units || spent > self.total_spent_ms {
            return Err("research aggregate original allowance differs".into());
        }
        for (id, r) in &self.records {
            r.input.validate()?;
            r.binding.validate()?;
            if *id != r.id
                || *id >= self.next_id
                || r.provider != "naome-deterministic-mocks-v1"
                || r.settings != settings.for_input(&r.input)
                || r.configuration != identity(&r.settings)
                || r.created_ms > r.accounted_ms
                || r.accounted_ms > self.observed_ms
                || r.expires_ms
                    != r.created_ms
                        .checked_add(r.settings.limits.horizon_ms)
                        .ok_or("job horizon overflow")?
                || r.checkpoint > r.reserved_units
                || r.reserved_units > r.settings.limits.work_units
                || r.checkpoint > r.settings.mock.steps
                || r.acknowledged && !r.state.terminal()
                || (r.state == State::Complete) != r.result.is_some()
                || r.state == State::Complete
                    && (r.checkpoint != r.settings.mock.steps || r.settings.mock.steps == 0)
            {
                return Err(
                    "research record identity, lifecycle, checkpoint or budget differs".into(),
                );
            }
            if r.failure.as_ref().is_some_and(|reason| reason.len() > 512) {
                return Err("research failure detail capacity".into());
            }
            if let Some(output) = &r.result {
                output.validate(&r.input)?;
            }
            if !matches!(r.input, Input::Find { .. }) {
                let account = self
                    .accounts
                    .get(&r.input.account_key())
                    .ok_or("missing original obligation budget")?;
                if account.settings != r.settings
                    || account.created_ms != r.created_ms
                    || account.expires_ms != r.expires_ms
                    || account.reserved_units < r.reserved_units
                    || account.spent_ms < r.spent_ms
                {
                    return Err("research original obligation budget differs".into());
                }
            }
            if let Input::Find { cursor } = r.input
                && cursor >= self.next_cursor
            {
                return Err("research finding cursor binding differs".into());
            }
        }
        for (key, a) in &self.accounts {
            crate::object::id_bytes(key)?;
            if ![settings.solving, settings.interest].contains(&a.settings)
                || !(10..=MAX_HORIZON_MS).contains(&a.settings.limits.horizon_ms)
                || !(1..=1_000_000).contains(&a.settings.limits.work_units)
                || a.created_ms.checked_add(a.settings.limits.horizon_ms) != Some(a.expires_ms)
                || a.reserved_units > a.settings.limits.work_units
            {
                return Err("research obligation allowance corruption".into());
            }
        }
        Ok(())
    }
}

pub(crate) fn research_directory(directory: &Path) -> Result<PathBuf, String> {
    let path = directory.join("research");
    match fs::symlink_metadata(&path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == nix::unistd::geteuid().as_raw() => {}
        Ok(_) => return Err("research path must be one owned directory".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if marker_valid(
                &directory.join("research.initialized"),
                b"naome-research-jobs-v1\n",
            )? {
                return Err("established research directory is missing; no fresh allowance".into());
            }
            fs::create_dir(&path).map_err(|e| e.to_string())?;
            File::open(directory)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
        }
        Err(e) => return Err(e.to_string()),
    }
    Ok(path)
}

fn slot_file(root: &Path, index: usize, create: bool) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(root.join(format!("slot-{index}.lock")))
        .map_err(|e| format!("research slot-{index} unavailable: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err("research slot must be one owned regular file".into());
    }
    Ok(file)
}

fn install_slots(root: &Path) -> Result<Vec<(u64, u64)>, String> {
    let mut slots = Vec::new();
    for index in 0..7 {
        let file = slot_file(root, index, true)?;
        file.sync_all().map_err(|e| e.to_string())?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        slots.push((metadata.dev(), metadata.ino()));
    }
    File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(slots)
}

pub(crate) fn marker_valid(path: &Path, expected: &[u8]) -> Result<bool, String> {
    match read_owned(path, 64)? {
        None => Ok(false),
        Some(bytes) if bytes == expected => Ok(true),
        Some(_) => Err("research initialization marker corruption".into()),
    }
}

pub(crate) fn write_marker(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    File::open(path.parent().ok_or("research marker parent absent")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

pub(crate) fn read<T: serde::de::DeserializeOwned + Serialize>(
    path: &Path,
    limit: usize,
) -> Result<Option<T>, String> {
    let Some(raw) = read_owned(path, limit)? else {
        return Ok(None);
    };
    let envelope: Envelope<T> =
        serde_json::from_slice(&raw).map_err(|e| format!("research checkpoint corruption: {e}"))?;
    if envelope.version != 1
        || identity(&envelope.payload) != envelope.sha256
        || serde_json::to_vec(&envelope).map_err(|e| e.to_string())? != raw
    {
        return Err("research checkpoint digest or version differs".into());
    }
    Ok(Some(envelope.payload))
}

fn read_owned(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err("research checkpoint must be one regular owned file".into());
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).map_err(|_| "research read limit")? + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("research checkpoint byte capacity".into());
    }
    Ok(Some(bytes))
}

pub(crate) fn write<T: Serialize>(path: &Path, payload: &T, limit: usize) -> Result<(), String> {
    let bytes = serde_json::to_vec(&Envelope {
        version: 1,
        payload,
        sha256: identity(payload),
    })
    .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("research checkpoint byte capacity".into());
    }
    let temporary = path.with_extension("incoming");
    match fs::symlink_metadata(&temporary) {
        Ok(m)
            if m.is_file()
                && m.nlink() == 1
                && !m.file_type().is_symlink()
                && m.uid() == nix::unistd::geteuid().as_raw() =>
        {
            fs::remove_file(&temporary).map_err(|e| e.to_string())?
        }
        Ok(_) => return Err("research incoming path differs".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    if let Ok(m) = fs::symlink_metadata(path)
        && (!m.is_file()
            || m.nlink() != 1
            || m.file_type().is_symlink()
            || m.uid() != nix::unistd::geteuid().as_raw())
    {
        return Err("research checkpoint path differs".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(&temporary, path).map_err(|e| e.to_string())?;
    File::open(path.parent().ok_or("research parent directory")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}
