//! Canonical-write indexing. Accounts survive cache loss and restart; searches
//! cannot enqueue, reserve or renew document work.
use super::{
    cache::{Cache, Settings},
    host::Host,
    local::LocalEncoder,
    semantic::SourceVectorRow,
    snapshot::Frozen,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const LIMIT_MS: u64 = 30_000;
const LIMIT_UNITS: u64 = 2 * (super::local::MAX_CHUNKS as u64 + 2);
const CLEANUP_MS: u64 = 2_500;
const MAX_WORK_BYTES: usize = 16 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Account {
    version: u8,
    key: String,
    limit_ms: u64,
    limit_units: u64,
    spent_ms: u64,
    spent_units: u64,
    reserved_ms: u64,
    stage: String,
    reason: Option<String>,
}
impl Account {
    fn pending(&mut self, cache: &Cache) -> Result<bool, String> {
        if self.limit_ms - self.spent_ms <= CLEANUP_MS || self.spent_units >= self.limit_units {
            self.stage = "failed".into();
            self.reason = Some("original cumulative index allowance exhausted".into());
            self.save(cache)?;
            return Ok(false);
        }
        self.stage = "pending".into();
        self.reason = None;
        self.save(cache)?;
        Ok(true)
    }
    fn load(cache: &Cache, key: &str) -> Result<Self, String> {
        crate::object::id_bytes(key)?;
        let path = cache.accounts.join("work").join(format!("{key}.json"));
        let marker = cache
            .accounts
            .join("work-markers")
            .join(format!("{key}.json"));
        let initialized = crate::jobs::marker_valid(&marker, key.as_bytes())?;
        let saved = crate::jobs::read_checkpoint(&path, MAX_WORK_BYTES)?;
        cache.establish_account(key, saved.is_some(), initialized)?;
        if saved.is_none() && initialized {
            return Err("index work account missing; refusing allowance reset".into());
        }
        let new = saved.is_none();
        let mut account: Self = saved.unwrap_or(Self {
            version: 1,
            key: key.into(),
            limit_ms: LIMIT_MS,
            limit_units: LIMIT_UNITS,
            spent_ms: 0,
            spent_units: 0,
            reserved_ms: 0,
            stage: "pending".into(),
            reason: None,
        });
        if account.version != 1
            || account.key != key
            || account.limit_ms != LIMIT_MS
            || account.limit_units != LIMIT_UNITS
            || account.spent_ms > LIMIT_MS
            || account.spent_units > LIMIT_UNITS
            || account.reserved_ms > account.spent_ms
            || !["pending", "indexing", "indexed", "failed"].contains(&account.stage.as_str())
        {
            return Err("index work account identity or original allowance differs".into());
        }
        // Reservation is charged before spawn. An interrupted attempt never
        // receives a refund or a new budget on recovery.
        if account.reserved_ms != 0 {
            account.reserved_ms = 0;
            account.stage = "failed".into();
            account.reason =
                Some("interrupted index attempt; original reservation consumed".into());
            account.save(cache)?;
        }
        if new {
            account.save(cache)?;
        }
        if !initialized {
            cache.room(key.len())?;
            crate::jobs::write_marker(&marker, key.as_bytes())?;
        }
        Ok(account)
    }
    fn save(&self, cache: &Cache) -> Result<(), String> {
        cache.room(serde_json::to_vec(self).map_err(|e| e.to_string())?.len())?;
        crate::jobs::write_checkpoint(
            &cache
                .accounts
                .join("work")
                .join(format!("{}.json", self.key)),
            self,
            MAX_WORK_BYTES,
        )
    }
    fn reserve(&mut self, cache: &Cache) -> Result<u64, String> {
        let remaining = self.limit_ms - self.spent_ms;
        if remaining <= CLEANUP_MS || self.spent_units >= self.limit_units {
            self.stage = "failed".into();
            self.reason = Some("original cumulative index allowance exhausted".into());
            self.save(cache)?;
            return Err("original cumulative index allowance exhausted".into());
        }
        self.reserved_ms = remaining;
        self.spent_ms += remaining;
        self.spent_units += 1; // Model admission is itself bounded work.
        self.stage = "indexing".into();
        self.reason = None;
        self.save(cache)?;
        Ok(remaining)
    }
    fn unit(&mut self, cache: &Cache) -> Result<(), String> {
        if self.spent_units == self.limit_units {
            return Err("original index work-unit allowance exhausted".into());
        }
        self.spent_units += 1;
        self.save(cache)
    }
    fn complete(
        &mut self,
        cache: &Cache,
        elapsed: Duration,
        result: &Result<(), String>,
    ) -> Result<(), String> {
        if result.is_ok() {
            let actual = u64::try_from(elapsed.as_nanos().div_ceil(1_000_000)).unwrap_or(u64::MAX);
            self.spent_ms -= self.reserved_ms.saturating_sub(actual);
            self.stage = "indexed".into();
            self.reason = None;
        } else {
            self.stage = "failed".into();
            self.reason = result
                .as_ref()
                .err()
                .map(|e| e.chars().take(1024).collect());
        }
        self.reserved_ms = 0;
        self.save(cache)
    }
}

enum Work {
    Proof {
        key: String,
        id: String,
        content: String,
    },
    Question {
        key: String,
        query: String,
    },
}
impl Work {
    fn key(&self) -> &str {
        match self {
            Self::Proof { key, .. } | Self::Question { key, .. } => key,
        }
    }
}
pub(super) struct Owner {
    source: Option<Arc<Frozen>>,
    work: VecDeque<Work>,
    stopped: Arc<AtomicBool>,
    cleanup_error: Option<String>,
    next_admission: Instant,
}
impl Owner {
    pub fn new(stopped: Arc<AtomicBool>) -> Self {
        Self {
            source: None,
            work: VecDeque::new(),
            stopped,
            cleanup_error: None,
            next_admission: Instant::now(),
        }
    }
    pub fn source(&self) -> Option<&Arc<Frozen>> {
        self.source.as_ref()
    }
    pub fn cleanup_error(&self) -> Option<&str> {
        self.cleanup_error.as_deref()
    }
    pub fn pending(&self) -> bool {
        !self.work.is_empty() && Instant::now() >= self.next_admission
    }
    pub fn reconcile(&mut self, source: Arc<Frozen>, cache: &Cache) -> Result<(), String> {
        self.work.clear();
        self.source = Some(source.clone());
        // Persist pending intent before any host is admitted. These accounts are
        // never collected with disposable source snapshots or vector rows.
        for reference in &source.corpus().references {
            let id = &reference.proof.proof_id;
            let content = source.semantic_content(id)?;
            let key = SourceVectorRow::key(&LocalEncoder::identity_specification(), id, &content);
            let mut account = Account::load(cache, &key)?;
            if cache.row(&key, &source).ok().flatten().is_none() {
                if account.pending(cache)? {
                    self.work.push_back(Work::Proof {
                        key,
                        id: id.clone(),
                        content,
                    });
                }
            } else {
                account.stage = "indexed".into();
                account.reason = None;
                account.save(cache)?;
            }
        }
        for (hash, record) in source.stored_questions() {
            let query = source
                .query_projections()
                .find(|(id, _)| *id == hash)
                .ok_or("native query projection absent")?
                .1
                .to_string();
            let key = crate::hex(&Sha256::digest(
                serde_json::to_vec(&(
                    "naome:stored-question-query:v1",
                    hash,
                    &record.source,
                    &query,
                    LocalEncoder::identity_specification(),
                ))
                .map_err(|e| e.to_string())?,
            ));
            let mut account = Account::load(cache, &key)?;
            if cache.query(&query).ok().flatten().is_some() {
                account.stage = "indexed".into();
                account.reason = None;
                account.save(cache)?;
            } else if query.trim().is_empty() || query.len() > 1024 {
                account.stage = "failed".into();
                account.reason =
                    Some("complete stored question projection exceeds query capacity".into());
                account.save(cache)?;
            } else {
                if account.pending(cache)? {
                    self.work.push_back(Work::Question { key, query });
                }
            }
        }
        cache.assemble(&source)?;
        cache.progress(
            &source,
            if self.work.is_empty() {
                "complete"
            } else {
                "pending"
            },
            source
                .corpus()
                .references
                .len()
                .saturating_sub(self.work.len()),
            None,
        )?;
        Ok(())
    }
    pub fn step(&mut self, cache: &Cache, settings: &Settings) -> Result<(), String> {
        if let Some(error) = &self.cleanup_error {
            return Err(error.clone());
        }
        let Some(work) = self.work.pop_front() else {
            return Ok(());
        };
        let source = self
            .source
            .as_ref()
            .ok_or("index work canonical source absent")?
            .clone();
        let mut account = Account::load(cache, work.key())?;
        let stopped = self.stopped.clone();
        if stopped.load(Ordering::Acquire) {
            return Err("indexing stopped before admission".into());
        }
        let lease = match cache.model_lock() {
            Ok(lease) => lease,
            Err(error) if error.starts_with("retrieval model lease is occupied or unavailable") => {
                self.work.push_front(work);
                self.next_admission = Instant::now() + Duration::from_secs(1);
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let remaining = match account.reserve(cache) {
            Ok(ms) => ms,
            Err(error) => {
                cache.progress(&source, "failed", 0, Some(&error))?;
                return self.cleanup_error.clone().map_or(Ok(()), Err);
            }
        };
        let clock = Instant::now();
        let finish_by = clock + Duration::from_millis(remaining);
        let deadline = finish_by - Duration::from_millis(CLEANUP_MS);
        let cancelled = || stopped.load(Ordering::Acquire) || Instant::now() >= deadline;
        let mut host =
            match Host::start(settings.clone(), lease, &cancelled, deadline).map_err(|failure| {
                if failure.cleanup_uncertain {
                    self.cleanup_error = Some(failure.message.clone());
                }
                failure.message
            }) {
                Ok(host) => host,
                Err(error) => {
                    let result = Err(error.clone());
                    account.complete(cache, clock.elapsed(), &result)?;
                    cache.progress(&source, "failed", 0, Some(&error))?;
                    return self.cleanup_error.clone().map_or(Ok(()), Err);
                }
            };
        let result = (|| {
            match work {
                Work::Proof { key, id, content } => {
                    account.unit(cache)?;
                    let coverage = host.prepare(1, content.clone(), &cancelled, deadline)?;
                    if coverage.is_empty() || coverage.len() > super::local::MAX_CHUNKS {
                        return Err("index complete token coverage capacity".into());
                    }
                    let mut chunks = Vec::with_capacity(coverage.len());
                    for position in 0..coverage.len() {
                        account.unit(cache)?;
                        chunks.push(host.chunk(1, position, &cancelled, deadline)?);
                    }
                    let row = SourceVectorRow::new(
                        LocalEncoder::identity_specification(),
                        source.reference(&id).ok_or("index proof source absent")?,
                        &content,
                        chunks,
                    )?;
                    host.finish()
                        .inspect_err(|error| self.cleanup_error = Some(error.clone()))?;
                    if stopped.load(Ordering::Acquire) || Instant::now() >= finish_by {
                        return Err("index cancelled before verified row publication".into());
                    }
                    cache.save_row(&key, &row)?;
                    cache
                        .row(&key, &source)?
                        .ok_or("published index row absent")?;
                }
                Work::Question { query, .. } => {
                    account.unit(cache)?;
                    let vector = host.query(query.clone(), &cancelled, deadline)?;
                    host.finish()
                        .inspect_err(|error| self.cleanup_error = Some(error.clone()))?;
                    if stopped.load(Ordering::Acquire) || Instant::now() >= finish_by {
                        return Err("index cancelled before question vector publication".into());
                    }
                    cache.save_query(&query, vector)?;
                    cache
                        .query(&query)?
                        .ok_or("published question vector absent")?;
                }
            }
            if Instant::now() >= finish_by {
                return Err("index publication exceeded original attempt allowance".into());
            }
            Ok(())
        })();
        let cleanup = host.finish();
        if let Err(error) = &cleanup {
            self.cleanup_error = Some(error.clone());
        }
        let result = result.and(cleanup);
        account.complete(cache, clock.elapsed(), &result)?;
        if let Err(error) = &result {
            cache.progress(&source, "failed", 0, Some(error))?;
        }
        cache.assemble(&source)?;
        if result.is_ok() {
            cache.progress(&source, "complete", source.corpus().references.len(), None)?;
        }
        result.or_else(|_| self.cleanup_error.clone().map_or(Ok(()), Err))
    }
}

#[cfg(test)]
mod tests;
