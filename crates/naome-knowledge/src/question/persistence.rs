//! Original registry inputs and delivery provenance, separate from proof objects.
use super::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    compatibility: String,
    policy: String,
    entries: BTreeMap<String, Entry>,
}

pub(super) struct Persistence {
    path: PathBuf,
    state: State,
}

impl Persistence {
    pub(super) fn open(
        directory: &Path,
        policy: PrefilterPolicy,
    ) -> Result<(Self, Vec<Entry>), String> {
        let root = crate::jobs::research_directory(directory)?;
        let path = root.join("questions.json");
        let marker = directory.join("question-registry.initialized");
        let initialized = crate::jobs::marker_valid(&marker, b"naome-question-registry-v1\n")?;
        let state: State = match crate::jobs::read_checkpoint(&path, MAX_QUESTION_CHECKPOINT_BYTES)?
        {
            Some(state) => state,
            None => {
                if initialized {
                    return Err(
                        "question registry checkpoint is missing; refusing to replace provenance"
                            .into(),
                    );
                }
                State {
                    version: 1,
                    compatibility: crate::hex(&crate::compatibility()),
                    policy: crate::hex(&policy.identity()),
                    entries: BTreeMap::new(),
                }
            }
        };
        if state.version != 1
            || state.compatibility != crate::hex(&crate::compatibility())
            || state.policy != crate::hex(&policy.identity())
            || state.entries.len() > MAX_REGISTERED_QUESTIONS
            || state
                .entries
                .values()
                .map(|e| e.source.len())
                .sum::<usize>()
                > MAX_REGISTERED_SOURCE_BYTES
        {
            return Err(
                "question registry version, policy, compatibility or capacity differs".into(),
            );
        }
        for (key, entry) in &state.entries {
            let question = CompiledQuestion::compile(&entry.source).map_err(|e| e.to_string())?;
            if key != &crate::hex(question.source_hash()) {
                return Err("question original source identity differs".into());
            }
            if matches!(entry.kind, Kind::Prepared | Kind::Admitted) != entry.first.is_some() {
                return Err("question admission provenance is incomplete".into());
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
                if &first.record != key {
                    return Err("question admission original record differs".into());
                }
            }
        }
        let entries = state.entries.values().cloned().collect();
        let persistence = Self { path, state };
        persistence.save()?;
        if !initialized {
            crate::jobs::write_marker(&marker, b"naome-question-registry-v1\n")?;
        }
        Ok((persistence, entries))
    }

    fn save(&self) -> Result<(), String> {
        crate::jobs::write_checkpoint(&self.path, &self.state, MAX_QUESTION_CHECKPOINT_BYTES)
    }

    pub(super) fn retain(
        &mut self,
        question: &CompiledQuestion,
        kind: Kind,
        receipt: Option<&AdmissionReceipt>,
    ) -> Result<(), String> {
        let first = receipt.map(|r| FirstAdmission {
            record: crate::hex(&r.record()),
            input: crate::hex(&r.input()),
            policy: crate::hex(&r.policy()),
            snapshot_before: crate::hex(&r.snapshot_before()),
            snapshot_after: crate::hex(&r.snapshot_after()),
            registry_before: crate::hex(&r.registry_before()),
            registry_after: crate::hex(&r.registry_after()),
        });
        self.state.entries.insert(
            crate::hex(question.source_hash()),
            Entry {
                source: question.source().to_owned(),
                kind,
                first,
            },
        );
        self.save()
    }

    pub(super) fn delivered(
        &mut self,
        question: &CompiledQuestion,
        delivered: bool,
    ) -> Result<(), String> {
        let key = crate::hex(question.source_hash());
        if delivered {
            let entry = self
                .state
                .entries
                .get_mut(&key)
                .ok_or("prepared question record absent")?;
            if entry.kind != Kind::Prepared {
                return Err("question delivery lifecycle differs".into());
            }
            entry.kind = Kind::Admitted;
        } else {
            self.state.entries.remove(&key);
        }
        self.save()
    }
}
