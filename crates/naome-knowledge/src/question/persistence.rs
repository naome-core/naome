//! Original registry inputs and delivery provenance, separate from proof objects.
use super::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

const MARKER: &[u8] = b"naome-question-registry\n";
const CHECKPOINT_DOMAIN: &str = "naome:questions";

#[cfg(test)]
thread_local! { static FAIL_EXCHANGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(super) fn fail_next_exchange() {
    FAIL_EXCHANGE.with(|value| value.set(true));
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    Baseline,
    Prepared,
    Admitted,
    Exchange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FirstAdmission {
    record: String,
    input: String,
    policy: String,
    snapshot_before: String,
    snapshot_after: String,
    registry_before: String,
    registry_after: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub source: String,
    pub kind: Kind,
    first: Option<FirstAdmission>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    compatibility: String,
    policy: String,
    backlog_sequence: u64,
    backlog_cursor: Option<String>,
}

/// Only the header and one bounded page are resident. All original sources,
/// first-admission receipts and unresolved FIFO entries remain on disk.
pub(super) struct Persistence {
    checkpoint: crate::checkpoint::Checkpoint,
    header: Header,
    fault: std::sync::Mutex<Option<String>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backlog {
    source: String,
    resolution: String,
}
impl Persistence {
    pub(super) fn open(directory: &Path, policy: PrefilterPolicy) -> Result<Self, String> {
        let root = crate::storage::research_directory(directory)?;
        let path = root.join("questions.sqlite3");
        let marker = directory.join("question-registry.initialized");
        let established = crate::storage::marker_valid(&marker, MARKER)?;
        let checkpoint = if path.exists() {
            crate::checkpoint::Checkpoint::open_for_replay(&path, CHECKPOINT_DOMAIN)?
        } else {
            if established {
                return Err(
                    "question registry checkpoint is missing; refusing to replace provenance"
                        .into(),
                );
            }
            let header = Header {
                compatibility: crate::hex(&crate::compatibility()),
                policy: crate::hex(&policy.identity()),
                backlog_sequence: 0,
                backlog_cursor: None,
            };
            crate::checkpoint::Checkpoint::create(&path, CHECKPOINT_DOMAIN, &header, vec![])?
        };
        checkpoint.require_kinds(&["question", "admitted", "backlog", "queued", "publication"])?;
        let header: Header = checkpoint.header()?;
        if header.compatibility != crate::hex(&crate::compatibility())
            || crate::object::id_bytes(&header.policy).is_err()
        {
            return Err("question registry compatibility or policy identity differs".into());
        }
        let persistence = Self {
            checkpoint,
            header,
            fault: std::sync::Mutex::new(None),
        };
        if !established {
            crate::storage::write_marker(&marker, MARKER)?;
        }
        Ok(persistence)
    }
    fn report<T>(&self, result: Result<T, String>) -> Result<T, String> {
        if let Err(error) = &result {
            *self.fault.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.clone());
        }
        result
    }
    pub(super) fn error(&self) -> Option<String> {
        self.fault.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    /// Recompile each original source once, validate all durable relationships,
    /// and hand the resulting formal value straight to the checked registry.
    pub(super) fn replay(
        &self,
        mut visit: impl FnMut(Entry, CompiledQuestion) -> Result<(), String>,
    ) -> Result<(), String> {
        self.report((|| {
            let mut admitted = 0usize;
            let mut queued = 0usize;
            self.checkpoint
                .scan("question", QUESTION_ENTRY_MAX_BYTES, |key, bytes| {
                    let entry: Entry = crate::checkpoint::decode(bytes)?;
                    let question = validate_entry(key, &entry)?;
                    if entry.kind == Kind::Admitted {
                        admitted = admitted
                            .checked_add(1)
                            .ok_or("question admission count overflow")?;
                        let resolution = crate::hex(question.resolution_id());
                        if self
                            .checkpoint
                            .get::<String>("admitted", &resolution, 128)?
                            .as_deref()
                            != Some(key)
                        {
                            return Err("question admission source index differs".into());
                        }
                        if let Some(sequence) =
                            self.checkpoint.get::<String>("queued", &resolution, 128)?
                        {
                            let number = sequence
                                .parse::<u64>()
                                .map_err(|_| "question FIFO sequence differs")?;
                            if number == 0
                                || number > self.header.backlog_sequence
                                || sequence != format!("{number:020}")
                            {
                                return Err("question FIFO sequence differs".into());
                            }
                            let backlog = self
                                .checkpoint
                                .get::<Backlog>("backlog", &sequence, 512)?
                                .ok_or("question FIFO entry missing")?;
                            if backlog.source != key || backlog.resolution != resolution {
                                return Err("question FIFO source or resolution differs".into());
                            }
                            queued = queued
                                .checked_add(1)
                                .ok_or("question FIFO count overflow")?;
                        }
                    }
                    visit(entry, question)
                })?;
            if self.checkpoint.count("admitted")? != admitted
                || self.checkpoint.count("backlog")? != queued
                || self.checkpoint.count("queued")? != queued
            {
                return Err("question durable index cardinality differs".into());
            }
            Ok(())
        })())
    }
    #[cfg(test)]
    pub(super) fn entries_page(&self, after: Option<&str>) -> Result<Vec<(String, Entry)>, String> {
        self.report((|| {
            self.checkpoint
                .page(
                    "question",
                    after,
                    crate::resources::active_limits().question_page,
                    crate::resources::limits()
                        .active_job_bytes
                        .min(crate::resources::active_limits().checked_cache_bytes),
                )?
                .into_iter()
                .map(|(key, bytes)| {
                    let entry: Entry = crate::checkpoint::decode(&bytes)?;
                    validate_entry(&key, &entry)?;
                    Ok((key, entry))
                })
                .collect()
        })())
    }
    pub(super) fn admitted(
        &self,
        resolution: &Identity,
    ) -> Result<Option<(CompiledQuestion, Identity)>, String> {
        self.report((|| {
            let Some(key) =
                self.checkpoint
                    .get::<String>("admitted", &crate::hex(resolution), 128)?
            else {
                return Ok(None);
            };
            let entry = self
                .checkpoint
                .get::<Entry>("question", &key, QUESTION_ENTRY_MAX_BYTES)?
                .ok_or("admitted original source is missing")?;
            let question = validate_entry(&key, &entry)?;
            if entry.kind != Kind::Admitted || question.resolution_id() != resolution {
                return Err("admission source index differs".into());
            }
            let record = *question.source_hash();
            Ok(Some((question, record)))
        })())
    }
    fn queue_updates(
        &mut self,
        question: &CompiledQuestion,
    ) -> Result<Vec<crate::checkpoint::Update>, String> {
        use crate::checkpoint::Update;
        let source = crate::hex(question.source_hash());
        let resolution = crate::hex(question.resolution_id());
        let mut updates = vec![Update::put("admitted", &resolution, &source)?];
        if self
            .checkpoint
            .get::<String>("queued", &resolution, 128)?
            .is_none()
        {
            self.header.backlog_sequence = self
                .header
                .backlog_sequence
                .checked_add(1)
                .ok_or("question FIFO sequence exhausted")?;
            let sequence = format!("{:020}", self.header.backlog_sequence);
            updates.push(Update::put("queued", &resolution, &sequence)?);
            updates.push(Update::put(
                "backlog",
                sequence,
                &Backlog { source, resolution },
            )?);
        }
        Ok(updates)
    }
    /// The cursor is committed before work is offered. A crash preserves the
    /// row and rotates the next attempt; a busy worker never loses the entry.
    pub(super) fn next_backlog(&mut self) -> Result<Option<CompiledQuestion>, String> {
        let read = |after: Option<&str>| {
            self.checkpoint.page(
                "backlog",
                after,
                1,
                crate::resources::limits().active_job_bytes,
            )
        };
        let mut page = read(self.header.backlog_cursor.as_deref())?;
        if page.is_empty() {
            page = read(None)?;
        }
        let Some((sequence, bytes)) = page.pop() else {
            return Ok(None);
        };
        let backlog: Backlog = crate::checkpoint::decode(&bytes)?;
        let entry = self
            .checkpoint
            .get::<Entry>("question", &backlog.source, QUESTION_ENTRY_MAX_BYTES)?
            .ok_or("backlog original source missing")?;
        let question = validate_entry(&backlog.source, &entry)?;
        if entry.kind != Kind::Admitted
            || crate::hex(question.resolution_id()) != backlog.resolution
            || self
                .checkpoint
                .get::<String>("queued", &backlog.resolution, 128)?
                .as_deref()
                != Some(sequence.as_str())
        {
            return Err("question backlog identity differs".into());
        }
        self.header.backlog_cursor = Some(sequence);
        self.checkpoint
            .commit(&self.header, vec![])
            .map_err(crate::Error::from)?;
        Ok(Some(question))
    }
    pub(super) fn settle_backlog(&mut self, resolution: &Identity) -> Result<(), String> {
        use crate::checkpoint::Update;
        let key = crate::hex(resolution);
        let Some(sequence) = self.checkpoint.get::<String>("queued", &key, 128)? else {
            return Ok(());
        };
        self.checkpoint
            .commit(
                &self.header,
                vec![
                    Update::Remove {
                        kind: "queued",
                        key,
                    },
                    Update::Remove {
                        kind: "backlog",
                        key: sequence,
                    },
                ],
            )
            .map_err(|error| crate::Error::from(error).to_string())
    }
    /// An outbox entry precedes the proof commit. Recovery decides its outcome
    /// from the rechecked graph, never from a persisted success flag.
    pub(super) fn stage_publication(
        &mut self,
        root: naome_proof::ProofId,
        question: &CompiledQuestion,
    ) -> Result<(), crate::Error> {
        crate::resources::require_disk_space(
            self.checkpoint.directory(),
            QUESTION_ENTRY_MAX_BYTES as u64 * 4,
        )?;
        self.checkpoint
            .commit(
                &self.header,
                vec![crate::checkpoint::Update::put(
                    "publication",
                    crate::hex(root.as_bytes()),
                    &question.source(),
                )?],
            )
            .map_err(crate::Error::from)
    }
    pub(super) fn finish_publication(
        &mut self,
        root: naome_proof::ProofId,
    ) -> Result<(), crate::Error> {
        self.checkpoint
            .commit(
                &self.header,
                vec![crate::checkpoint::Update::Remove {
                    kind: "publication",
                    key: crate::hex(root.as_bytes()),
                }],
            )
            .map_err(crate::Error::from)
    }
    pub(super) fn publications(
        &self,
    ) -> Result<Vec<(naome_proof::ProofId, CompiledQuestion)>, String> {
        self.checkpoint
            .page(
                "publication",
                None,
                crate::resources::active_limits().publications,
                crate::resources::limits().active_job_bytes,
            )?
            .into_iter()
            .map(|(key, bytes)| {
                let root = naome_proof::ProofId::from_bytes(crate::object::id_bytes(&key)?);
                let source: String = crate::checkpoint::decode(&bytes)?;
                let question = CompiledQuestion::compile(&source).map_err(|e| e.to_string())?;
                Ok((root, question))
            })
            .collect()
    }

    pub(super) fn retain(
        &mut self,
        question: &CompiledQuestion,
        kind: Kind,
        receipt: Option<&AdmissionReceipt>,
    ) -> Result<(), String> {
        #[cfg(test)]
        if kind == Kind::Exchange && FAIL_EXCHANGE.with(|value| value.replace(false)) {
            return Err("injected question persistence failure".into());
        }
        if kind != Kind::Exchange {
            crate::resources::require_disk_space(
                self.checkpoint.directory(),
                question.source().len() as u64,
            )?;
        }
        let first = receipt.map(|r| FirstAdmission {
            record: crate::hex(&r.record()),
            input: crate::hex(&r.input()),
            policy: crate::hex(&r.policy()),
            snapshot_before: crate::hex(&r.snapshot_before()),
            snapshot_after: crate::hex(&r.snapshot_after()),
            registry_before: crate::hex(&r.registry_before()),
            registry_after: crate::hex(&r.registry_after()),
        });
        let key = crate::hex(question.source_hash());
        let original = self
            .checkpoint
            .get::<Entry>("question", &key, QUESTION_ENTRY_MAX_BYTES)?;
        let entry = match original {
            Some(mut original) if original.first.is_some() => {
                if original.source != question.source() {
                    return Err("original question source differs".into());
                }
                if let Some(first) = first {
                    if crate::checkpoint::encode(
                        original.first.as_ref().expect("original provenance"),
                    )? != crate::checkpoint::encode(&first)?
                    {
                        return Err("first admission provenance cannot be replaced".into());
                    }
                    original.kind = kind;
                }
                original
            }
            _ => Entry {
                source: question.source().to_owned(),
                kind,
                first,
            },
        };
        validate_entry(&key, &entry)?;
        let mut updates = vec![crate::checkpoint::Update::put("question", key, &entry)?];
        if entry.kind == Kind::Prepared {
            let resolution = crate::hex(question.resolution_id());
            if let Some(sequence) = self.checkpoint.get::<String>("queued", &resolution, 128)? {
                updates.push(crate::checkpoint::Update::Remove {
                    kind: "queued",
                    key: resolution.clone(),
                });
                updates.push(crate::checkpoint::Update::Remove {
                    kind: "backlog",
                    key: sequence,
                });
            }
            updates.push(crate::checkpoint::Update::Remove {
                kind: "admitted",
                key: resolution,
            });
        }
        self.checkpoint
            .commit(&self.header, updates)
            .map_err(|error| crate::Error::from(error).to_string())
    }
    pub(super) fn delivered(
        &mut self,
        question: &CompiledQuestion,
        delivered: bool,
    ) -> Result<(), String> {
        let key = crate::hex(question.source_hash());
        let mut entry = self
            .checkpoint
            .get::<Entry>("question", &key, QUESTION_ENTRY_MAX_BYTES)?
            .ok_or("prepared question record absent")?;
        if entry.kind != Kind::Prepared {
            return Err("question delivery lifecycle differs".into());
        }
        let mut updates = if delivered {
            entry.kind = Kind::Admitted;
            let mut updates = self.queue_updates(question)?;
            updates.push(crate::checkpoint::Update::put("question", key, &entry)?);
            updates
        } else {
            vec![crate::checkpoint::Update::Remove {
                kind: "question",
                key,
            }]
        };
        self.checkpoint
            .commit(&self.header, std::mem::take(&mut updates))
            .map_err(|error| crate::Error::from(error).to_string())
    }
}
fn validate_entry(key: &str, entry: &Entry) -> Result<CompiledQuestion, String> {
    let question = CompiledQuestion::compile(&entry.source).map_err(|e| e.to_string())?;
    if key != crate::hex(question.source_hash())
        || matches!(entry.kind, Kind::Prepared | Kind::Admitted) != entry.first.is_some()
    {
        return Err("question source identity or admission provenance differs".into());
    }
    if let Some(first) = &entry.first {
        for value in [
            &first.record,
            &first.input,
            &first.policy,
            &first.snapshot_before,
            &first.snapshot_after,
            &first.registry_before,
            &first.registry_after,
        ] {
            crate::object::id_bytes(value)?;
        }
        if first.record != key {
            return Err("question admission original record differs".into());
        }
    }
    Ok(question)
}

#[cfg(test)]
mod tests;
