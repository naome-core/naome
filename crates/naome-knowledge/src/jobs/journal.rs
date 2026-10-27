use super::*;
use crate::storage::{RESEARCH_MARKER, marker_valid, research_directory, write_marker};
use std::{
    collections::BTreeSet,
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

mod learning;

const CHECKPOINT_DOMAIN: &str = "naome:research-jobs";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Account {
    pub settings: RoleSettings,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub spent_ms: u64,
    pub reserved_units: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub compatibility: String,
    pub configuration: String,
    pub next_id: u64,
    pub next_cursor: u64,
    pub observed_ms: u64,
    pub retired_jobs: u64,
    pub total_spent_ms: u64,
    pub total_reserved_units: u64,
    pub records: super::tracked::TrackedMap<u64, Record>,
    pub accounts: super::tracked::TrackedMap<String, Account>,
    pub learning: Option<crate::learning::State>,
    pub slots: Vec<(u64, u64)>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
    compatibility: String,
    configuration: String,
    next_id: u64,
    next_cursor: u64,
    observed_ms: u64,
    retired_jobs: u64,
    total_spent_ms: u64,
    total_reserved_units: u64,
    slots: Vec<(u64, u64)>,
    resident_records: Vec<u64>,
    workers: [usize; 4],
}
impl Journal {
    fn header(&self) -> Header {
        Header {
            compatibility: self.compatibility.clone(),
            configuration: self.configuration.clone(),
            next_id: self.next_id,
            next_cursor: self.next_cursor,
            observed_ms: self.observed_ms,
            retired_jobs: self.retired_jobs,
            total_spent_ms: self.total_spent_ms,
            total_reserved_units: self.total_reserved_units,
            slots: self.slots.clone(),
            resident_records: self.records.keys().copied().collect(),
            workers: crate::resources::limits().workers,
        }
    }
    fn from_header(header: Header) -> Self {
        Self {
            compatibility: header.compatibility,
            configuration: header.configuration,
            next_id: header.next_id,
            next_cursor: header.next_cursor,
            observed_ms: header.observed_ms,
            retired_jobs: header.retired_jobs,
            total_spent_ms: header.total_spent_ms,
            total_reserved_units: header.total_reserved_units,
            slots: header.slots,
            learning: None,
            records: super::tracked::TrackedMap::new(),
            accounts: super::tracked::TrackedMap::new(),
        }
    }
    pub(super) fn remember_holds(&mut self) -> Result<(), String> {
        for record in self
            .records
            .values()
            .filter(|r| r.state == State::InDoubt && !matches!(r.input, Input::Find { .. }))
        {
            let key = record.input.account_key();
            let previous = self
                .accounts
                .get(&key)
                .ok_or("uncertain job original account missing")?
                .held;
            let held = Some(previous.map_or(record.id, |old| old.min(record.id)));
            if previous != held {
                self.accounts.get_mut(&key).expect("original account").held = held;
            }
        }
        Ok(())
    }
    pub(super) fn encoded_active_len(&mut self) -> Result<usize, String> {
        let learning = match &self.learning {
            Some(state) => crate::checkpoint::encode(state)?.len(),
            None => 0,
        };
        self.records
            .encoded_len()?
            .checked_add(self.accounts.encoded_len()?)
            .and_then(|bytes| bytes.checked_add(learning))
            .and_then(|bytes| bytes.checked_add(4096))
            .ok_or("active journal byte overflow".into())
    }
}

pub(super) struct Disk {
    path: PathBuf,
    slots: Vec<(u64, u64)>,
    workers: [usize; 4],
    checkpoint: crate::checkpoint::Checkpoint,
    learning_hash: String,
    verified_models: std::collections::BTreeSet<String>,
}

impl Disk {
    pub(super) fn open(
        directory: &Path,
        settings: Settings,
        cursor: u64,
    ) -> Result<(Self, Journal), String> {
        let root = research_directory(directory)?;
        let path = root.join("jobs.sqlite3");
        let marker = directory.join("research.initialized");
        let established = marker_valid(&marker, RESEARCH_MARKER)?;
        let checkpoint = if path.exists() {
            crate::checkpoint::Checkpoint::open_for_replay(&path, CHECKPOINT_DOMAIN)?
        } else {
            if established {
                return Err("research journal is missing; refusing a fresh allowance".into());
            }
            let journal = Journal {
                compatibility: crate::hex(&crate::compatibility()),
                configuration: identity(&settings),
                next_id: 1,
                next_cursor: cursor,
                observed_ms: wall_ms()?,
                retired_jobs: 0,
                total_spent_ms: 0,
                total_reserved_units: 0,
                learning: settings
                    .native_proof_learning
                    .then(crate::learning::State::fresh),
                records: super::tracked::TrackedMap::new(),
                accounts: super::tracked::TrackedMap::new(),
                slots: install_slots(&root)?,
            };
            journal.validate(settings)?;
            crate::checkpoint::Checkpoint::create(
                &path,
                CHECKPOINT_DOMAIN,
                &journal.header(),
                vec![crate::checkpoint::Update::put(
                    "learning",
                    "current",
                    &journal.learning,
                )?],
            )?
        };
        checkpoint.require_kinds(&[
            "record",
            "account",
            "request",
            "history",
            "program",
            "learning",
            "learned",
            "sample",
            "replay_seen",
            "model",
            "peer_pending",
            "peer_receipt",
            "model_owner",
            "model_use",
            "model_gc",
        ])?;
        checkpoint.scan(
            "program",
            naome_proof::program::CHUNK_BYTES,
            |key, bytes| {
                let (id, unit) = key.split_once(':').ok_or("invalid provider program key")?;
                let id = id
                    .parse::<u64>()
                    .map_err(|_| "invalid provider program job")?;
                let unit = unit
                    .parse::<u32>()
                    .map_err(|_| "invalid provider program unit")?;
                if key != format!("{id}:{unit}") || unit == 0 {
                    return Err("noncanonical provider program key".into());
                }
                let record = checkpoint
                    .get::<Record>("record", &id.to_string(), crate::checkpoint::MAX_ROW)?
                    .ok_or("provider program job missing")?;
                if unit > record.reserved_units || !matches!(record.input, Input::Solve { .. }) {
                    return Err("provider program reservation missing".into());
                }
                let commands: Vec<naome_proof::program::Command> =
                    serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
                super::program::validate_group(&commands)
            },
        )?;
        let header: Header = checkpoint.header()?;
        if header.compatibility != crate::hex(&crate::compatibility())
            || crate::object::id_bytes(&header.configuration).is_err()
        {
            return Err("unsupported research journal configuration or header".into());
        }
        let resident = header
            .resident_records
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if resident.len() != header.resident_records.len() {
            return Err("research resident record index differs".into());
        }
        let old_workers = header.workers;
        if old_workers
            .iter()
            .try_fold(0usize, |n, w| n.checked_add(*w))
            != Some(header.slots.len())
        {
            return Err("research physical slot allocation differs".into());
        }
        let mut journal = Journal::from_header(header);
        journal.learning = checkpoint
            .get(
                "learning",
                "current",
                crate::resources::limits().closure_bytes,
            )?
            .ok_or("local learning state missing")?;
        learning::validate_rows(&checkpoint, journal.learning.as_ref())?;
        let persisted_learning_hash = crate::learning::digest(&journal.learning);
        if settings.native_proof_learning && journal.learning.is_none() {
            journal.learning = Some(crate::learning::State::fresh());
        }
        if let Some(learning) = &journal.learning {
            learning.validate()?;
        }
        journal.configuration = identity(&settings);
        let mut resident_bytes = 4096usize;
        let mut terminal_residents = Vec::new();
        let mut observed_residents = 0usize;
        let mut unacknowledged = 0usize;
        checkpoint.scan(
            "record",
            crate::checkpoint::MAX_ROW,
            |key, bytes| {
                let record: Record = crate::checkpoint::decode(bytes)?;
                if record.id.to_string() != key
                    || checkpoint.get::<u64>("history", &format!("{:020}", record.id), 32)?
                        != Some(record.id)
                {
                    return Err("research record row identity differs".into());
                }
                let account = if matches!(record.input, Input::Find { .. }) {
                    None
                } else {
                    checkpoint.get::<Account>("account", &record.input.account_key(), 8192)?
                };
                validate_record(
                    record.id,
                    &record,
                    settings,
                    journal.observed_ms,
                    journal.next_id,
                    journal.next_cursor,
                    account.as_ref(),
                )?;
                if !record.acknowledged {
                    unacknowledged = unacknowledged
                        .checked_add(1)
                        .ok_or("research request count overflow")?;
                    if checkpoint.get::<u64>(
                        "request",
                        &super::request_key(&record.input, &record.binding, record.settings),
                        64,
                    )? != Some(record.id)
                    {
                        return Err("research unacknowledged request index differs".into());
                    }
                }
                if resident.contains(&record.id) {
                    observed_residents += 1;
                    let charge = bytes.len().checked_add(key.len() + 128)
                        .and_then(|bytes| bytes.checked_add(if matches!(record.input, Input::Find { .. }) { 0 } else { 8192 }))
                        .ok_or("research resident memory overflow")?;
                    if record.state.terminal() {
                        terminal_residents.push((record.id, charge));
                    } else {
                        resident_bytes = resident_bytes.checked_add(charge).ok_or("research resident memory overflow")?;
                        if resident_bytes > crate::resources::limits().active_job_bytes {
                            return Err("resource overload: retained active research obligations exceed installed capacity".into());
                        }
                        journal.records.insert(record.id, record);
                    }
                }
                Ok(())
            },
        )?;
        if checkpoint.count("history")? != checkpoint.count("record")? {
            return Err("research history index cardinality differs".into());
        }
        if checkpoint.count("request")? != unacknowledged {
            return Err("research request index cardinality differs".into());
        }
        if resident.len() != observed_residents {
            return Err("research resident record is missing".into());
        }
        // Completed results are immutable history. Keep only the part that fits
        // the new working set; recovery scans still visit every archived row.
        for (id, charge) in terminal_residents {
            if resident_bytes
                .checked_add(charge)
                .is_some_and(|bytes| bytes <= crate::resources::limits().active_job_bytes)
                && journal.records.len() < crate::resources::limits().resident_jobs
            {
                let record = checkpoint
                    .get::<Record>("record", &id.to_string(), crate::checkpoint::MAX_ROW)?
                    .ok_or("research resident record disappeared")?;
                resident_bytes += charge;
                journal.records.insert(id, record);
            } else {
                journal.retired_jobs = journal
                    .retired_jobs
                    .checked_add(1)
                    .ok_or("research retired count overflow")?;
            }
        }
        let needed = journal
            .records
            .values()
            .filter(|r| !matches!(r.input, Input::Find { .. }))
            .map(|r| r.input.account_key())
            .collect::<BTreeSet<_>>();
        let mut units = 0u64;
        let mut spent = 0u64;
        checkpoint.scan("account", 8192, |key, bytes| {
            let account: Account = crate::checkpoint::decode(bytes)?;
            validate_account(key, &account, settings)?;
            units = units
                .checked_add(u64::from(account.reserved_units))
                .ok_or("research archive unit overflow")?;
            spent = spent
                .checked_add(account.spent_ms)
                .ok_or("research archive time overflow")?;
            if let Some(id) = account.held {
                let held = checkpoint
                    .get::<Record>("record", &id.to_string(), crate::checkpoint::MAX_ROW)?
                    .ok_or("held research job is missing")?;
                if held.state != State::InDoubt || held.input.account_key() != key {
                    return Err("held research account identity differs".into());
                }
            }
            if needed.contains(key) {
                journal.accounts.insert(key.to_owned(), account);
            }
            Ok(())
        })?;
        if units > journal.total_reserved_units || spent > journal.total_spent_ms {
            return Err("research archived allowance differs".into());
        }
        let now = wall_ms()?;
        journal.validate(settings)?;
        for (index, expected) in journal.slots.iter().enumerate() {
            let file = slot_file(&root, index, false)?;
            let metadata = file.file().metadata().map_err(|e| e.to_string())?;
            if (metadata.dev(), metadata.ino()) != *expected {
                return Err("research physical slot identity differs".into());
            }
        }
        let mut reconfiguration_locks = Vec::new();
        if old_workers != crate::resources::limits().workers {
            for index in 0..journal.slots.len() {
                let file = slot_file(&root, index, false)?;
                file.try_lock().map_err(|_|"provider slot reconfiguration requires every previous physical worker to drain")?;
                reconfiguration_locks.push(file);
            }
            journal.slots = install_slots(&root)?;
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
                } else if record
                    .allowance(journal.accounts.get(&record.input.account_key()), now)
                    .time_expired()
                {
                    State::Expired
                } else if super::provider::resumable(record)
                    && record.settings.recovery == RecoveryPolicy::DeterministicCheckpoint
                {
                    State::Suspended
                } else {
                    State::InDoubt
                };
            }
        }
        journal.observed_ms = now;
        journal.remember_holds()?;
        let mut disk = Self {
            path,
            slots: journal.slots.clone(),
            workers: crate::resources::limits().workers,
            learning_hash: persisted_learning_hash,
            verified_models: std::collections::BTreeSet::new(),
            checkpoint,
        };
        disk.save(&mut journal)?;
        if disk.checkpoint.count("model")? > 0 {
            disk.collect_models(&mut journal)?;
        }
        if let Some(learning) = &journal.learning {
            for blob in learning.blobs() {
                disk.verify_blob(blob)?;
            }
        }
        for record in journal.records.values().filter(|r| !r.acknowledged) {
            if let Some(native) = &record.native {
                disk.verify_models(native)?;
            }
        }
        disk.retire_acknowledged_candidates()?;
        drop(reconfiguration_locks);
        if !established {
            write_marker(&marker, RESEARCH_MARKER)?;
        }
        Ok((disk, journal))
    }

    fn node_directory(&self) -> &Path {
        self.path
            .parent()
            .and_then(Path::parent)
            .expect("job journal node directory")
    }
    fn retire_candidate_cache(&self, id: u64) {
        if let Err(error) = crate::proof_work::retire_candidate(self.node_directory(), id) {
            // Retirement cannot revoke a durable acknowledgement or classify
            // temporary cleanup pressure as corruption of canonical history.
            crate::network::emit(
                serde_json::json!({"event":"candidate_cache_retirement_deferred","job":id,"error":error}),
            );
        }
    }
    fn retire_acknowledged_candidates(&self) -> Result<(), String> {
        let root = self.node_directory().join(".program-work");
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name();
            let Some(job) = name
                .to_str()
                .and_then(|name| name.strip_prefix("candidate-"))
                .and_then(|name| {
                    name.strip_suffix(".sqlite3")
                        .or_else(|| name.strip_suffix(".proof-work.lock"))
                })
            else {
                continue;
            };
            let Ok(id) = job.parse::<u64>() else { continue };
            if id == 0 || job != id.to_string() {
                continue;
            }
            let record =
                self.checkpoint
                    .get::<Record>("record", job, crate::checkpoint::MAX_ROW)?;
            if record.is_some_and(|record| {
                record.id == id && record.acknowledged && record.state.terminal()
            }) {
                self.retire_candidate_cache(id);
            }
        }
        Ok(())
    }

    pub(super) fn save(&mut self, journal: &mut Journal) -> Result<(), crate::Error> {
        self.save_with(journal, Vec::new())
    }
    pub(super) fn save_with(
        &mut self,
        journal: &mut Journal,
        extra: Vec<crate::checkpoint::Update>,
    ) -> Result<(), crate::Error> {
        journal
            .remember_holds()
            .map_err(crate::Error::CorruptStorage)?;
        if journal
            .encoded_active_len()
            .map_err(crate::Error::CorruptStorage)?
            > crate::resources::limits().active_job_bytes
        {
            return Err(crate::Error::CorruptStorage(
                "active journal byte capacity".into(),
            ));
        }
        let mut updates = journal
            .records
            .updates("record")?
            .into_iter()
            .filter(|update| matches!(update, crate::checkpoint::Update::Put { .. }))
            .collect::<Vec<_>>();
        updates.extend(journal.accounts.updates("account")?);
        let learning_hash = crate::learning::digest(&journal.learning);
        if learning_hash != self.learning_hash {
            updates.push(crate::checkpoint::Update::put(
                "learning",
                "current",
                &journal.learning,
            )?);
        }
        if learning_hash != self.learning_hash {
            let refs: Vec<_> = journal
                .learning
                .as_ref()
                .into_iter()
                .flat_map(|s| s.blobs().cloned())
                .collect();
            self.update_model_refs(&mut updates, "global", refs)?;
        }
        for (id, record) in &journal.records {
            if !journal.records.changed(id) {
                continue;
            }
            if record.native.is_some() {
                self.update_model_refs(
                    &mut updates,
                    &format!("job{id}"),
                    Self::record_model_refs(record),
                )?;
            }
            let history = format!("{id:020}");
            if self
                .checkpoint
                .get::<u64>("history", &history, 32)
                .map_err(crate::Error::CorruptStorage)?
                .is_none()
            {
                updates.push(crate::checkpoint::Update::put("history", history, id)?);
            }
            let key = super::request_key(&record.input, &record.binding, record.settings);
            if record.acknowledged {
                if self
                    .checkpoint
                    .get::<u64>("request", &key, 64)
                    .map_err(crate::Error::CorruptStorage)?
                    == Some(*id)
                {
                    updates.push(crate::checkpoint::Update::Remove {
                        kind: "request",
                        key,
                    });
                }
            } else {
                updates.push(crate::checkpoint::Update::put("request", key, id)?);
            }
        }

        updates.extend(extra);
        self.checkpoint
            .commit(&journal.header(), updates)
            .map_err(crate::Error::from)?;
        for (id, record) in &journal.records {
            if journal.records.changed(id) && record.acknowledged && record.state.terminal() {
                self.retire_candidate_cache(*id);
            }
        }
        self.learning_hash = learning_hash;
        journal.records.clean();
        journal.accounts.clean();
        let retained = journal
            .records
            .values()
            .filter(|r| !matches!(r.input, Input::Find { .. }))
            .map(|r| r.input.account_key())
            .collect::<BTreeSet<_>>();
        journal.accounts.evict_except(&retained);
        Ok(())
    }

    /// Fixed-width history keys give a bounded FIFO scan through the startup
    /// snapshot. New work cannot extend this recovery horizon indefinitely.
    pub(super) fn recovery_page(
        &self,
        after: u64,
        before: u64,
        skip: &BTreeSet<u64>,
    ) -> Result<super::RecoveryPage, String> {
        let rows = self.checkpoint.page(
            "history",
            Some(&format!("{after:020}")),
            crate::resources::limits().terminal_job_page,
            crate::resources::limits().provider_stream_bytes,
        )?;
        let mut records = Vec::new();
        let mut next = None;
        let mut bytes = 0usize;
        for (key, payload) in rows {
            let id: u64 = crate::checkpoint::decode(&payload)?;
            if id == 0 || key != format!("{id:020}") {
                return Err("research FIFO history identity differs".into());
            }
            if id >= before {
                next = None;
                break;
            }
            if !skip.contains(&id) {
                let record = self
                    .checkpoint
                    .get::<Record>("record", &id.to_string(), crate::checkpoint::MAX_ROW)?
                    .ok_or("research history record is missing")?;
                if record.id != id {
                    return Err("research history record identity differs".into());
                }
                if !record.acknowledged && !record.input.internal() {
                    let size = crate::checkpoint::encode(&record)?.len();
                    if !records.is_empty()
                        && bytes
                            .checked_add(size)
                            .is_none_or(|n| n > crate::resources::limits().active_job_bytes)
                    {
                        break;
                    }
                    bytes = bytes
                        .checked_add(size)
                        .ok_or("research recovery bytes overflow")?;
                    records.push(record);
                }
            }
            next = Some(id);
        }
        Ok(super::RecoveryPage { records, next })
    }

    pub(super) fn request(
        &self,
        input: &Input,
        binding: &Binding,
        settings: RoleSettings,
    ) -> Result<Option<Record>, String> {
        let key = super::request_key(input, binding, settings);
        let Some(id) = self.checkpoint.get::<u64>("request", &key, 64)? else {
            return Ok(None);
        };
        let record = self
            .checkpoint
            .get::<Record>("record", &id.to_string(), crate::checkpoint::MAX_ROW)?
            .ok_or("indexed research request is missing")?;
        if record.id != id
            || record.input != *input
            || record.binding != *binding
            || record.settings != settings
            || record.acknowledged
        {
            return Err("research request identity index differs".into());
        }
        Ok(Some(record))
    }
    pub(super) fn acknowledge(&mut self, journal: &Journal, id: u64) -> Result<(), String> {
        let Some(mut record) =
            self.checkpoint
                .get::<Record>("record", &id.to_string(), crate::checkpoint::MAX_ROW)?
        else {
            if id < journal.next_id {
                return Ok(());
            }
            return Err("unknown research acknowledgement".into());
        };
        if !record.state.terminal() {
            return Err("acknowledged research job is still running or held".into());
        }
        record.acknowledged = true;
        let key = super::request_key(&record.input, &record.binding, record.settings);
        let mut updates = vec![crate::checkpoint::Update::put("record", id, &record)?];
        if self.checkpoint.get::<u64>("request", &key, 64)? == Some(id) {
            updates.push(crate::checkpoint::Update::Remove {
                kind: "request",
                key,
            });
        }
        if record.native.is_some() {
            self.update_model_refs(&mut updates, &format!("job{id}"), Vec::new())?;
        }
        self.checkpoint
            .commit(&journal.header(), updates)
            .map_err(crate::Error::from)?;
        self.retire_candidate_cache(id);
        Ok(())
    }
    pub(super) fn program_group(
        &self,
        id: u64,
        unit: u32,
    ) -> Result<Vec<naome_proof::program::Command>, String> {
        let records = self
            .checkpoint
            .get::<Vec<naome_proof::program::Command>>(
                "program",
                &format!("{id}:{unit}"),
                naome_proof::program::CHUNK_BYTES,
            )?
            .ok_or("provider program group missing")?;
        super::program::validate_group(&records)?;
        Ok(records)
    }
    pub(super) fn save_program_group(
        &mut self,
        journal: &Journal,
        id: u64,
        unit: u32,
        records: Vec<naome_proof::program::Command>,
    ) -> Result<(), crate::Error> {
        super::program::validate_group(&records)?;
        let record = journal
            .records
            .get(&id)
            .ok_or("provider program original job missing")?;
        if unit == 0
            || unit > record.reserved_units
            || unit > record.checkpoint.saturating_add(1)
            || !matches!(record.input, Input::Solve { .. })
        {
            return Err("provider program original reservation missing".into());
        }
        let key = format!("{id}:{unit}");
        if let Some(previous) = self.checkpoint.get::<Vec<naome_proof::program::Command>>(
            "program",
            &key,
            naome_proof::program::CHUNK_BYTES,
        )? {
            return if previous == records {
                Ok(())
            } else {
                Err("resumed provider program group differs".into())
            };
        }
        let _disk = crate::resources::DiskLease::acquire(
            self.directory(),
            (naome_proof::program::CHUNK_BYTES as u64) * 4,
        )?;
        self.checkpoint
            .commit(
                &journal.header(),
                vec![crate::checkpoint::Update::put("program", key, &records)?],
            )
            .map_err(crate::Error::from)
    }
    pub(super) fn directory(&self) -> &Path {
        self.path.parent().expect("canonical research parent")
    }
    pub(super) fn account(&self, key: &str) -> Result<Option<Account>, String> {
        self.checkpoint.get("account", key, 8192)
    }

    #[cfg(all(test, feature = "system-tests"))]
    pub(super) fn account_count(&self) -> usize {
        let mut count = 0;
        self.checkpoint
            .scan("account", 8192, |_, _| {
                count += 1;
                Ok(())
            })
            .unwrap();
        count
    }

    #[cfg(all(test, feature = "system-tests"))]
    pub(super) fn last_write_stats(&self) -> (usize, usize) {
        self.checkpoint.last_write
    }

    #[cfg(test)]
    pub(super) fn saved(&self) -> Result<serde_json::Value, String> {
        let mut value =
            serde_json::to_value(self.checkpoint.header::<Header>()?).map_err(|e| e.to_string())?;
        let resident = self.checkpoint.header::<Header>()?.resident_records;
        for kind in ["record", "account"] {
            let mut records = serde_json::Map::new();
            self.checkpoint.scan(
                kind,
                crate::resources::limits().active_job_bytes,
                |key, bytes| {
                    if kind == "record"
                        && key.parse::<u64>().is_ok_and(|id| !resident.contains(&id))
                    {
                        return Ok(());
                    }
                    records.insert(
                        key.to_owned(),
                        serde_json::from_slice(bytes).map_err(|e| e.to_string())?,
                    );
                    Ok(())
                },
            )?;
            value[if kind == "record" {
                "records"
            } else {
                "accounts"
            }] = serde_json::Value::Object(records);
        }
        Ok(serde_json::json!({"payload":value}))
    }

    /// Stable kernel locks cap physical provider lifetimes across a daemon
    /// crash. Supervisors, workers and their owned descendants retain the same
    /// open description until exit; a restart never signals a persisted PID.
    pub(super) fn slot(&self, lane: usize) -> Result<Option<File>, String> {
        let count = *self.workers.get(lane).ok_or("research slot lane differs")?;
        let first = self.workers[..lane].iter().sum::<usize>();
        let range = first..first + count;
        let root = self.path.parent().ok_or("research slot parent absent")?;
        for index in range {
            let file = slot_file(root, index, false)?;
            let metadata = file.file().metadata().map_err(|e| e.to_string())?;
            if self.slots.get(index) != Some(&(metadata.dev(), metadata.ino())) {
                return Err("research physical slot identity differs".into());
            }
            match file.try_lock() {
                Ok(()) => {
                    file.file().sync_all().map_err(|e| e.to_string())?;
                    File::open(root)
                        .and_then(|f| f.sync_all())
                        .map_err(|e| e.to_string())?;
                    return Ok(Some(file.into_file()));
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
        self.validate_changes(settings, true)
    }

    pub(super) fn validate_delta(&self, settings: Settings) -> Result<(), String> {
        self.validate_changes(settings, false)
    }

    fn validate_changes(&self, settings: Settings, full: bool) -> Result<(), String> {
        if self.compatibility != crate::hex(&crate::compatibility())
            || self.configuration != identity(&settings)
            || self.next_id == 0
            || self.slots.is_empty()
        {
            return Err("research journal compatibility, configuration or capacity differs".into());
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
            if !full && !self.records.changed(id) {
                continue;
            }
            validate_record(
                *id,
                r,
                settings,
                self.observed_ms,
                self.next_id,
                self.next_cursor,
                self.accounts.get(&r.input.account_key()),
            )?;
        }
        for (key, account) in &self.accounts {
            if full || self.accounts.changed(key) {
                validate_account(key, account, settings)?;
            }
        }
        Ok(())
    }
}

fn validate_record(
    id: u64,
    r: &Record,
    _settings: Settings,
    observed_ms: u64,
    next_id: u64,
    next_cursor: u64,
    account: Option<&Account>,
) -> Result<(), String> {
    r.input.validate()?;
    if let Some(native) = &r.native {
        if native.training != matches!(r.input, Input::Train { .. }) {
            return Err("native training role differs".into());
        }
        if let Input::Train { epoch } = r.input
            && epoch != native.base.learning_epoch()
        {
            return Err("native learning epoch differs".into());
        }
        native.validate()?;
        match &r.input {
            Input::Solve { .. } => native.validate_generated_trace()?,
            Input::Peer {
                question,
                artifact,
                certificate,
                ..
            } => {
                if let Some(solution) = native.progress.as_ref().and_then(|p| p.result.as_ref()) {
                    crate::learning::peer::validate_solution(
                        question,
                        artifact,
                        certificate,
                        solution,
                    )?;
                }
            }
            _ => {}
        }
        if r.provider != crate::learning::PROVIDER
            || !matches!(
                r.input,
                Input::Solve { .. } | Input::Peer { .. } | Input::Train { .. }
            )
        {
            return Err("native provider snapshot role differs".into());
        }
    } else if r.provider == crate::learning::PROVIDER {
        return Err("native provider snapshot absent".into());
    }
    r.binding.validate()?;
    r.settings.validate_history()?;
    if id != r.id
        || id >= next_id
        || !super::provider::valid_checkpoint(r)
        || r.configuration != identity(&r.settings)
        || r.created_ms > r.accounted_ms
        || r.accounted_ms > observed_ms
        || r.expires_ms
            != r.created_ms
                .checked_add(r.settings.limits.horizon_ms)
                .ok_or("job horizon overflow")?
        || r.checkpoint > r.reserved_units
        || r.reserved_units > r.settings.limits.work_units
        || r.acknowledged && !r.state.terminal()
        || (r.state == State::Complete) != r.result.is_some()
    {
        return Err("research record identity, lifecycle, checkpoint or budget differs".into());
    }
    if r.failure
        .as_ref()
        .is_some_and(|reason| reason.len() > crate::checkpoint::MAX_ROW)
    {
        return Err("research failure detail capacity".into());
    }
    if let Some(output) = &r.result {
        output.validate_retained(&r.input)?;
        if let Output::Program { units } = output
            && *units != r.checkpoint
        {
            return Err("retained program differs from original checkpoints".into());
        }
    }
    if !matches!(r.input, Input::Find { .. }) {
        let account = account.ok_or("missing original obligation budget")?;
        if account.settings != r.settings
            || account.created_ms != r.created_ms
            || account.expires_ms != r.expires_ms
            || account.reserved_units < r.reserved_units
            || account.spent_ms < r.spent_ms
        {
            return Err("research original obligation budget differs".into());
        }
    }
    if let Input::Find { cursor, .. } = r.input
        && cursor >= next_cursor
    {
        return Err("research finding cursor binding differs".into());
    }
    Ok(())
}

fn validate_account(key: &str, account: &Account, _settings: Settings) -> Result<(), String> {
    crate::object::id_bytes(key)?;
    account.settings.validate_history()?;
    if account.settings.limits.horizon_ms == 0
        || account.settings.limits.work_units == 0
        || account
            .created_ms
            .checked_add(account.settings.limits.horizon_ms)
            != Some(account.expires_ms)
        || account.held == Some(0)
        || account.reserved_units > account.settings.limits.work_units
    {
        return Err("research obligation allowance corruption".into());
    }
    Ok(())
}

fn slot_file(root: &Path, index: usize, create: bool) -> Result<crate::storage::LockFile, String> {
    let path = root.join(format!("slot-{index}.lock"));
    (if create {
        crate::storage::LockFile::open(&path)
    } else {
        crate::storage::LockFile::existing(&path)
    })
    .map_err(|e| format!("research slot-{index} unavailable: {e}"))
}

fn install_slots(root: &Path) -> Result<Vec<(u64, u64)>, String> {
    let mut slots = Vec::new();
    for index in 0..crate::resources::limits().workers.iter().sum() {
        let file = slot_file(root, index, true)?;
        file.file().sync_all().map_err(|e| e.to_string())?;
        let metadata = file.file().metadata().map_err(|e| e.to_string())?;
        slots.push((metadata.dev(), metadata.ino()));
    }
    File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(slots)
}
