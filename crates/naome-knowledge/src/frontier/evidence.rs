//! Durable attempt observations, subordinate to the checked graph and job owner.
use super::*;
use crate::checkpoint::{Checkpoint, Update};
use serde::{Deserialize, Serialize};
const DOMAIN: &str = "naome:research-evidence";
const MARKER: &[u8] = b"naome-research-evidence\n";
const MAX_RECORD: usize = 6 * naome_authoring::QUESTION_SOURCE_MAX_BYTES + 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Candidate,
    NoCandidate,
    Rejected,
    Failed,
    Expired,
    InDoubt,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    random: u64,
    draws: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub question: String,
    pub solver: String,
    pub knowledge: String,
    pub last_draw: u64,
    pub last_job: u64,
    pub outcomes: [u64; 6],
    pub last_outcome: Outcome,
    pub units: u64,
    pub spent_ms: u64,
    pub verified: Option<String>,
    pub prepared: Option<String>,
    pub verified_units: u32,
    pub verified_ms: u64,
    last_units: u32,
}
impl Record {
    /// A returned candidate remains unverified until its exact checked solution
    /// is durable. This is scheduling feedback, never a mathematical negative.
    pub(super) fn unverified_attempts(&self) -> u64 {
        self.outcomes
            .iter()
            .fold(0u64, |sum, n| sum.saturating_add(*n))
            .saturating_sub(u64::from(self.verified.is_some()))
    }
    pub(super) fn substantive_attempts(&self) -> u64 {
        self.outcomes[..=Outcome::Rejected as usize]
            .iter()
            .fold(0u64, |sum, n| sum.saturating_add(*n))
    }
    fn validate(&self, key: &str) -> Result<(), String> {
        let question = CompiledQuestion::compile(&self.question).map_err(|e| e.to_string())?;
        if key != record_key(&self.solver, &question) || self.last_job == 0 {
            return Err("research evidence identity differs".into());
        }
        crate::object::id_bytes(&self.knowledge)?;
        crate::object::id_bytes(&self.solver)?;
        for root in [&self.verified, &self.prepared].into_iter().flatten() {
            crate::object::id_bytes(root)?;
        }
        if self.prepared.is_some() && self.last_outcome != Outcome::Candidate
            || self.verified_units as u64 > self.units
            || self.last_units as u64 > self.units
        {
            return Err("research evidence outcome or cost differs".into());
        }
        Ok(())
    }
}
fn record_key(solver: &str, question: &CompiledQuestion) -> String {
    let mut hash = sha2::Sha256::new();
    hash.update(solver.as_bytes());
    hash.update(question.resolution_id());
    crate::hex(&hash.finalize())
}
pub(super) struct Evidence {
    checkpoint: Checkpoint,
    header: Header,
    solver: String,
}
impl Evidence {
    pub(super) fn open(
        directory: &Path,
        seed: u64,
        settings: jobs::Settings,
    ) -> Result<Self, String> {
        let directory = crate::storage::research_directory(directory)?;
        let path = directory.join("evidence.sqlite3");
        let marker = directory.join("evidence.initialized");
        let solver = jobs::solver_identity(settings);
        let checkpoint = if path.exists() {
            Checkpoint::open_for_replay(&path, DOMAIN)?
        } else {
            if crate::storage::marker_valid(&marker, MARKER)? {
                return Err("established research evidence is missing".into());
            }
            Checkpoint::create(
                &path,
                DOMAIN,
                &Header {
                    random: seed.max(1),
                    draws: 0,
                },
                vec![],
            )?
        };
        let header: Header = checkpoint.header()?;
        if header.random == 0 {
            return Err("invalid research random state".into());
        }
        checkpoint.require_kinds(&["question"])?;
        if !crate::storage::marker_valid(&marker, MARKER)? {
            crate::storage::write_marker(&marker, MARKER)?;
        }
        Ok(Self {
            checkpoint,
            header,
            solver,
        })
    }
    pub(super) fn random(&self) -> u64 {
        self.header.random
    }
    pub(super) fn draws(&self) -> u64 {
        self.header.draws
    }
    pub(super) fn replay(
        &mut self,
        mut visit: impl FnMut(&Record) -> Result<bool, String>,
    ) -> Result<(), String> {
        let mut after = None;
        loop {
            let page = self
                .checkpoint
                .page(
                    "question",
                    after.as_deref(),
                    16,
                    crate::resources::active_limits().question_cache_bytes,
                )
                .map_err(|e| e.to_string())?;
            if page.is_empty() {
                return Ok(());
            }
            for (key, bytes) in page {
                let mut record: Record = crate::checkpoint::decode(&bytes)?;
                record.validate(&key)?;
                if record.solver == self.solver && visit(&record)? && record.verified.is_none() {
                    record.verified = record.prepared.clone();
                    let question =
                        CompiledQuestion::compile(&record.question).map_err(|e| e.to_string())?;
                    self.put(&question, &record).map_err(|e| e.to_string())?;
                }
                after = Some(key);
            }
        }
    }
    pub(super) fn get(&self, question: &CompiledQuestion) -> Result<Option<Record>, crate::Error> {
        self.checkpoint
            .get("question", &record_key(&self.solver, question), MAX_RECORD)
            .map_err(crate::Error::CorruptStorage)
    }
    pub(super) fn selected(&mut self, random: u64) -> Result<(), crate::Error> {
        let next = Header {
            random,
            draws: self
                .header
                .draws
                .checked_add(1)
                .ok_or("research draw overflow")?,
        };
        self.commit(&next, vec![])?;
        self.header = next;
        Ok(())
    }
    fn commit(&mut self, header: &Header, updates: Vec<Update>) -> Result<(), crate::Error> {
        let needed = updates
            .iter()
            .map(|update| match update {
                Update::Put { payload, .. } => payload.len() as u64,
                _ => 0,
            })
            .sum::<u64>()
            .saturating_add(8192);
        let _disk = crate::resources::DiskLease::acquire(self.checkpoint.directory(), needed)?;
        self.checkpoint
            .commit(header, updates)
            .map_err(crate::Error::from)
    }
    fn put(&mut self, question: &CompiledQuestion, record: &Record) -> Result<(), crate::Error> {
        let header = Header {
            random: self.header.random,
            draws: self.header.draws,
        };
        self.commit(
            &header,
            vec![Update::put(
                "question",
                record_key(&self.solver, question),
                record,
            )?],
        )
    }
    pub(super) fn attempted(
        &mut self,
        question: &CompiledQuestion,
        knowledge: [u8; 32],
        completion: &jobs::Completion,
        outcome: Outcome,
    ) -> Result<(), crate::Error> {
        if completion.id == 0 {
            return Ok(());
        }
        let mut record = self.get(question)?.unwrap_or(Record {
            question: question.source().into(),
            solver: self.solver.clone(),
            knowledge: crate::hex(&knowledge),
            last_draw: 0,
            last_job: 0,
            outcomes: [0; 6],
            last_outcome: outcome,
            units: 0,
            spent_ms: 0,
            verified: None,
            prepared: None,
            verified_units: 0,
            verified_ms: 0,
            last_units: 0,
        });
        if completion.id <= record.last_job {
            return Ok(());
        }
        record.knowledge = crate::hex(&knowledge);
        record.last_draw = self.header.draws;
        record.last_job = completion.id;
        record.last_outcome = outcome;
        record.outcomes[outcome as usize] = record.outcomes[outcome as usize]
            .checked_add(1)
            .ok_or("research attempt overflow")?;
        record.units = record
            .units
            .checked_add(u64::from(completion.reserved_units))
            .ok_or("research work overflow")?;
        record.spent_ms = record
            .spent_ms
            .checked_add(completion.spent_ms)
            .ok_or("research time overflow")?;
        record.last_units = completion.reserved_units;
        record.prepared = None;
        if record.verified.is_none() {
            record.verified_units = record.last_units;
            record.verified_ms = completion.spent_ms;
        }
        self.put(question, &record)
    }
    pub(super) fn prepared(
        &mut self,
        question: &CompiledQuestion,
        job: u64,
        root: ArtifactId,
    ) -> Result<(), crate::Error> {
        let Some(mut record) = self.get(question)? else {
            return Ok(());
        };
        if record.last_job != job {
            return Err("research prepared job differs".into());
        }
        if record.last_outcome != Outcome::Candidate {
            return Err("only a candidate job can supply checked evidence".into());
        }
        record.prepared = Some(crate::hex(root.as_bytes()));
        self.put(question, &record)
    }
    pub(super) fn rejected(
        &mut self,
        question: &CompiledQuestion,
        job: u64,
    ) -> Result<(), crate::Error> {
        let Some(mut record) = self.get(question)? else {
            return Ok(());
        };
        if record.last_job != job || record.last_outcome == Outcome::Rejected {
            return Ok(());
        }
        record.last_outcome = Outcome::Rejected;
        record.prepared = None;
        record.outcomes[Outcome::Candidate as usize] =
            record.outcomes[Outcome::Candidate as usize].saturating_sub(1);
        record.outcomes[Outcome::Rejected as usize] =
            record.outcomes[Outcome::Rejected as usize].saturating_add(1);
        self.put(question, &record)
    }
    pub(super) fn verified(
        &mut self,
        question: &CompiledQuestion,
        job: u64,
        root: ArtifactId,
    ) -> Result<Option<(u32, u64)>, crate::Error> {
        let Some(mut record) = self.get(question)? else {
            return Ok(None);
        };
        if record.last_job != job || record.verified.is_some() {
            return Ok(None);
        }
        if record.last_outcome != Outcome::Candidate
            || record.prepared.as_deref() != Some(crate::hex(root.as_bytes()).as_str())
        {
            return Err(
                "verified research evidence is not bound to the checked candidate job".into(),
            );
        }
        record.verified = Some(crate::hex(root.as_bytes()));
        record.verified_units = record.last_units;
        self.put(question, &record)?;
        Ok(Some((record.verified_units, record.verified_ms)))
    }
}
