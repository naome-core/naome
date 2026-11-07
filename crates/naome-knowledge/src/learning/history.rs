//! Bounded preparation from admitted sources and terminal job observations.
//! The job journal owns history; the selected replay is only a working view.
use super::*;

pub const SOURCES: usize = REPLAY;
pub const PAGE_BYTES: usize = REPLAY * 8 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lane {
    #[default]
    Sources,
    Records,
}
impl Lane {
    fn key(self, key: &str) -> Result<(), String> {
        match self {
            Self::Sources => {
                crate::object::id_bytes(key)?;
                Ok(())
            }
            Self::Records => {
                let id = key
                    .parse::<u64>()
                    .map_err(|_| "history record key syntax")?;
                if id == 0 || id.to_string() != key {
                    return Err("history record key encoding".into());
                }
                Ok(())
            }
        }
    }
}

/// The two existing journal views take turns within one original read budget.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    sources: Option<String>,
    records: Option<String>,
    lane: Lane,
}
impl Cursor {
    pub(super) fn validate(&self) -> Result<(), String> {
        for (lane, key) in [
            (Lane::Sources, &self.sources),
            (Lane::Records, &self.records),
        ] {
            if let Some(key) = key {
                lane.key(key)?;
            }
        }
        Ok(())
    }
    fn after(&self) -> &Option<String> {
        match self.lane {
            Lane::Sources => &self.sources,
            Lane::Records => &self.records,
        }
    }
    pub(super) fn matches(&self, request: &Request) -> bool {
        self.lane == request.lane && self.after() == &request.after
    }
    pub(super) fn advance(&mut self, receipt: &Receipt) {
        match self.lane {
            Lane::Sources => {
                self.sources.clone_from(&receipt.next);
                self.lane = Lane::Records;
            }
            Lane::Records => {
                self.records.clone_from(&receipt.next);
                self.lane = Lane::Sources;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub lane: Lane,
    pub after: Option<String>,
    pub horizon: u64,
}
impl Request {
    pub fn validate(&self) -> Result<(), String> {
        if self.horizon == 0 {
            return Err("history request lacks its original job".into());
        }
        if let Some(after) = &self.after {
            self.lane.key(after)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub request: Request,
    pub blob: Blob,
    pub next: Option<String>,
    pub read_bytes: usize,
    pub read_operations: usize,
    pub read_cpu_micros: u64,
}
impl Receipt {
    pub fn validate(&self, request: &Request) -> Result<(), String> {
        request.validate()?;
        self.blob.validate()?;
        if self.request != *request
            || self.blob.bytes > PAGE_BYTES
            || self.read_bytes > crate::resources::limits().native_model_blob_bytes
            || self.read_operations > 4 * SOURCES + 1
        {
            return Err("history page differs from its bounded request".into());
        }
        if let Some(next) = &self.next {
            request.lane.key(next)?;
            if request.after.as_ref().is_some_and(|after| next <= after) {
                return Err("history cursor did not advance".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub job: u64,
    pub origin: Origin,
    pub question: String,
    pub solution: Solution,
    pub peer_certificate: Option<Vec<u8>>,
}
impl Source {
    fn example(&self) -> Result<Example, String> {
        match (&self.origin, &self.peer_certificate) {
            (Origin::Local, None) => {}
            (Origin::Peer { artifact, .. }, Some(certificate)) => {
                peer::validate_solution(&self.question, artifact, certificate, &self.solution)?;
            }
            _ => return Err("historical origin lacks its exact admission evidence".into()),
        }
        let question = CompiledQuestion::compile(&self.question).map_err(|e| e.to_string())?;
        let checked = self.solution.checked()?.into_checked_proof();
        let target = if self.solution.refuted {
            question.refuted_target()
        } else {
            question.proved_target()
        };
        if checked.conclusion() != target {
            return Err("historical proof conclusion differs from its question".into());
        }
        let example = Example {
            origin: self.origin.clone(),
            job: self.job,
            question: self.question.clone(),
            proof_id: self.solution.proof_id.clone(),
            refuted: self.solution.refuted,
            tree: self.solution.tree.clone(),
        };
        // A pointer or a checked flag cannot substitute the complete original
        // context, definitions, helper closure and reconstructed native proof.
        if matches!(example.tree, search::Tree::Stored { .. }) {
            return Err("history source lacks its complete trajectory".into());
        }
        state::validate_example(&example)?;
        Ok(example)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub request: Request,
    pub next: Option<String>,
    pub examined: Vec<(String, u64)>,
    pub sources: Vec<Source>,
    pub records: Vec<Record>,
}

/// Every scanned record is represented, including an explicit absence of an
/// eligible terminal observation. The page hash binds the journal's decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub job: u64,
    pub observation: Option<experience::Observation>,
}
impl Page {
    fn validate(&self, receipt: &Receipt) -> Result<(), String> {
        receipt.validate(&self.request)?;
        let bytes = crate::checkpoint::encode(self)?;
        if Blob::of(&bytes) != receipt.blob
            || self.next != receipt.next
            || self.examined.len() > SOURCES
            || self.sources.len() > self.examined.len()
            || self.records.len() > self.examined.len()
            || !self.examined.windows(2).all(|pair| pair[0].0 < pair[1].0)
        {
            return Err("history page identity or sequence differs".into());
        }
        for (proof, job) in &self.examined {
            self.request.lane.key(proof)?;
            if *job == 0
                || self
                    .request
                    .after
                    .as_ref()
                    .is_some_and(|after| proof <= after)
            {
                return Err("history page source cursor differs".into());
            }
        }
        if self
            .next
            .as_ref()
            .is_some_and(|next| self.examined.last().is_none_or(|(last, _)| next != last))
        {
            return Err("history continuation lacks its last examined source".into());
        }
        if self.request.lane == Lane::Records {
            if !self.sources.is_empty()
                || self.records.len() != self.examined.len()
                || self
                    .records
                    .iter()
                    .zip(&self.examined)
                    .any(|(record, (key, job))| record.job != *job || key != &job.to_string())
            {
                return Err("history record page omitted or substituted a scanned job".into());
            }
            for record in &self.records {
                if let Some(observation) = &record.observation {
                    observation.validate()?;
                    if observation.summary.job != record.job || record.job >= self.request.horizon {
                        return Err(
                            "history observation differs from its original job horizon".into()
                        );
                    }
                }
            }
            return Ok(());
        }
        if !self.records.is_empty() {
            return Err("admitted source page contains a different journal view".into());
        }
        let expected: Vec<_> = self
            .examined
            .iter()
            .filter(|(_, job)| *job < self.request.horizon)
            .cloned()
            .collect();
        let actual: Vec<_> = self
            .sources
            .iter()
            .map(|source| (source.solution.proof_id.clone(), source.job))
            .collect();
        if actual != expected {
            return Err("historical page omitted or substituted an owned source".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub blob: Blob,
    pub page: Receipt,
    pub context: [u16; meta::CONTEXT],
    pub available: usize,
    pub retained: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Working {
    base_hash: String,
    page: Receipt,
    replay: Vec<Example>,
    evidence: Vec<Evidence>,
    observations: Vec<experience::Observation>,
    available: usize,
    retained: usize,
}
pub(super) struct Sources {
    pub state: State,
    pub evidence: Vec<Evidence>,
    pub observations: Vec<experience::Observation>,
}
impl Working {
    fn prepare(job: &Job, page: &Page, receipt: &Receipt) -> Result<Self, String> {
        page.validate(receipt)?;
        let mut state = job.base.clone();
        let mut evidence: BTreeMap<_, _> = job
            .evidence
            .iter()
            .cloned()
            .map(|source| (source.job, source))
            .collect();
        let mut eligible = Vec::new();
        for source in &page.sources {
            if !State::eligible(&source.question) {
                continue;
            }
            let example = source.example()?;
            eligible.push(example.proof_id.clone());
            let trace = Evidence {
                job: example.job,
                proof_id: example.proof_id.clone(),
                trace: example.tree.clone(),
            };
            state.reload(example)?;
            evidence.insert(trace.job, trace);
        }
        state.compact()?;
        let retained = state
            .training_sources()
            .filter(|example| eligible.contains(&example.proof_id))
            .count();
        let needed = state
            .training_sources()
            .filter_map(Example::evidence_job)
            .collect::<std::collections::BTreeSet<_>>();
        let evidence: Vec<_> = evidence
            .into_values()
            .filter(|source| needed.contains(&source.job))
            .collect();
        // This also checks every reconstructed pointer before any model loads.
        for example in state.training_sources() {
            let tree = example.trajectory(&evidence)?;
            state::validate_example(&Example {
                tree: tree.clone(),
                ..example.clone()
            })?;
        }
        let result = Self {
            base_hash: job.base_hash.clone(),
            page: receipt.clone(),
            replay: state.replay,
            evidence,
            observations: page
                .records
                .iter()
                .filter_map(|record| record.observation.clone())
                .collect(),
            available: eligible.len(),
            retained,
        };
        if crate::checkpoint::encode(&result)?.len() > PAGE_BYTES + 32 * 1024 + 8192 {
            return Err("prepared replay exceeds existing working source capacity".into());
        }
        Ok(result)
    }
    fn state(&self, job: &Job) -> Result<State, String> {
        if self.base_hash != job.base_hash || Some(&self.page) != job.history.as_ref() {
            return Err("prepared replay differs from its immutable job".into());
        }
        let mut state = job.base.clone();
        state.replay.clone_from(&self.replay);
        state.validate()?;
        Ok(state)
    }
}

impl Job {
    #[cfg(test)]
    pub(super) fn preflight_history<I: ArtifactIo + ?Sized>(
        &self,
        io: &mut I,
    ) -> Result<serde_json::Value, String> {
        let receipt = self.history.as_ref().ok_or("preflight history absent")?;
        let page: Page = crate::checkpoint::decode(&artifact::load(io, &receipt.blob)?)?;
        let working = Working::prepare(self, &page, receipt)?;
        let state = working.state(self)?;
        let pool = state.training_pool_for(&working.evidence, true)?;
        if pool.is_empty() {
            return Err("preflight requires genuine checked decisions".into());
        }
        Ok(serde_json::json!({"working":working,"state":state,
            "context":meta::context(&state),"decision_states":pool.graphs().len()}))
    }
    pub fn request_history(&mut self, job: u64) {
        self.history_request = Some(Request {
            lane: self.base.history_cursor.lane,
            after: self.base.history_cursor.after().clone(),
            horizon: job,
        });
    }
    pub(super) fn prepare_history<I: ArtifactIo + ?Sized>(
        &mut self,
        progress: &mut Progress,
        engine: &mut Engine,
        io: &mut I,
    ) -> Result<Option<Sources>, String> {
        let Some(request) = self.history_request.clone() else {
            return Ok(None);
        };
        let receipt = if let Some(receipt) = &self.history {
            receipt.clone()
        } else {
            let receipt = io.history(&request)?;
            receipt.validate(&request)?;
            self.history = Some(receipt.clone());
            receipt
        };
        if let Some(prepared) = &progress.prepared
            && let Some((blob, working)) = &engine.prepared
            && *blob == prepared.blob
        {
            return Ok(Some(Sources {
                state: working.state(self)?,
                evidence: working.evidence.clone(),
                observations: working.observations.clone(),
            }));
        }
        let page: Page = crate::checkpoint::decode(&artifact::load(io, &receipt.blob)?)?;
        let working = Working::prepare(self, &page, &receipt)?;
        let state = working.state(self)?;
        let bytes = crate::checkpoint::encode(&working)?;
        let blob = Blob::of(&bytes);
        let prepared = Prepared {
            blob: blob.clone(),
            page: receipt,
            context: meta::context(&state),
            available: working.available,
            retained: working.retained,
        };
        if let Some(previous) = &progress.prepared {
            if *previous != prepared || artifact::load(io, &previous.blob)? != bytes {
                return Err("prepared replay changed across continuation".into());
            }
        } else {
            artifact::save(io, &bytes)?;
            progress.prepared = Some(prepared);
        }
        let evidence = working.evidence.clone();
        let observations = working.observations.clone();
        engine.prepared = Some((blob, working));
        Ok(Some(Sources {
            state,
            evidence,
            observations,
        }))
    }
}

#[cfg(test)]
pub(crate) fn inspect_reload(job: &Job, receipt: &Receipt, bytes: &[u8]) -> Result<State, String> {
    let page: Page = crate::checkpoint::decode(bytes)?;
    Working::prepare(job, &page, receipt)?.state(job)
}

#[cfg(test)]
mod tests;
