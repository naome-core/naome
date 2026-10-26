//! Durable untrusted local proof backlog. FIFO pages have no population or
//! lifetime ceiling; only complete checking in Graph can publish a proof.
use super::*;
use crate::{
    checkpoint::{Checkpoint, Update},
    object::BinaryArtifact,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u8,
    next: u64,
    cursor: Option<String>,
}
pub(super) struct PendingStore {
    checkpoint: Checkpoint,
    header: Header,
    scheduled: bool,
}
impl PendingStore {
    pub(super) fn open(directory: &Path) -> Result<Self, crate::Error> {
        let root = crate::storage::research_directory(directory)?;
        let path = root.join("proof-backlog.sqlite3");
        let marker = root.join("proof-backlog.initialized");
        let established = crate::storage::marker_valid(&marker, b"naome:proof-backlog:v1\n")?;
        let checkpoint = if std::fs::symlink_metadata(&path).is_ok() {
            Checkpoint::open_for_replay(&path, "naome:proof-backlog:v1")?
        } else {
            if established {
                return Err("proof backlog is missing; refusing to discard retained work".into());
            }
            Checkpoint::create(
                &path,
                "naome:proof-backlog:v1",
                &Header {
                    version: 1,
                    next: 1,
                    cursor: None,
                },
                vec![],
            )?
        };
        checkpoint.require_kinds(&["pending", "proof", "edge"])?;
        let header: Header = checkpoint.header()?;
        if header.version != 1 || header.next == 0 {
            return Err("proof backlog version or sequence differs".into());
        }
        let mut after = None;
        let mut count = 0usize;
        let mut edges = 0usize;
        loop {
            let page = checkpoint.page(
                "pending",
                after.as_deref(),
                crate::resources::active_limits().pending_page,
                crate::resources::limits().active_job_bytes,
            )?;
            if page.is_empty() {
                break;
            }
            for (sequence, bytes) in page {
                after = Some(sequence.clone());
                if sequence.len() != 20
                    || sequence
                        .parse::<u64>()
                        .map_or(true, |n| n == 0 || n >= header.next)
                {
                    return Err("proof backlog FIFO sequence differs".into());
                }
                let proof = decode(&bytes)?;
                let id = crate::hex(proof.id.as_bytes());
                if checkpoint.get::<String>("proof", &id, 128)?.as_deref()
                    != Some(sequence.as_str())
                {
                    return Err("proof backlog identity index differs".into());
                }
                for dependency in &proof.dependencies {
                    if checkpoint.get::<bool>(
                        "edge",
                        &format!("{id}{}", crate::hex(dependency.as_bytes())),
                        8,
                    )? != Some(true)
                    {
                        return Err("proof backlog dependency index differs".into());
                    }
                }
                count = count.checked_add(1).ok_or("proof backlog count overflow")?;
                edges = edges
                    .checked_add(proof.dependencies.len())
                    .ok_or("proof backlog edge overflow")?;
            }
        }
        if checkpoint.count("proof")? != count || checkpoint.count("edge")? != edges {
            return Err("proof backlog index cardinality differs".into());
        }
        if !established {
            crate::storage::write_marker(&marker, b"naome:proof-backlog:v1\n")?;
        }
        Ok(Self {
            checkpoint,
            header,
            scheduled: false,
        })
    }
    fn has_path(
        &self,
        starts: &[String],
        target: &str,
        timeout: std::time::Duration,
    ) -> Result<bool, crate::Error> {
        self.checkpoint.query(|connection| {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or("cycle traversal deadline overflow")?;
        connection
            .progress_handler(1000, Some(move || std::time::Instant::now() >= deadline))
            .map_err(sql)?;
        let result = (|| {
            for start in starts {
                if std::time::Instant::now() >= deadline {
                    return Err(crate::Error::ExecutionLimit);
                }
                let found:Result<bool,rusqlite::Error>=connection.query_row(
                    "WITH RECURSIVE reach(id) AS (VALUES(?1) UNION SELECT substr(e.key,65,64) FROM reach r JOIN entries e ON e.kind='edge' AND e.key >= r.id || ?3 AND e.key <= r.id || ?4) SELECT EXISTS(SELECT 1 FROM reach WHERE id=?2)",
                    rusqlite::params![start,target,"0".repeat(64),"f".repeat(64)],|r|r.get(0));
                match found {
                    Ok(true) => return Ok(true),
                    Ok(false) => {}
                    Err(error)
                        if error.sqlite_error_code()
                            == Some(rusqlite::ErrorCode::OperationInterrupted) =>
                    {
                        return Err(crate::Error::ExecutionLimit);
                    }
                    Err(error) => return Err(sql(error)),
                }
            }
                Ok(false)
        })();
        connection
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(sql)?;
        result
        })
    }

    #[cfg(test)]
    pub(super) fn changes(&self) -> u64 {
        self.checkpoint
            .query(|connection| Ok(connection.total_changes()))
            .unwrap()
    }
    pub(super) fn contains(&self, id: ArtifactId) -> Result<bool, crate::Error> {
        Ok(self
            .checkpoint
            .get::<String>("proof", &crate::hex(id.as_bytes()), 128)?
            .is_some())
    }
    pub(super) fn len(&self) -> Result<usize, crate::Error> {
        Ok(self.checkpoint.count("pending")?)
    }
    pub(super) fn insert(
        &mut self,
        candidate: &Candidate,
        context: &DiskArtifactState,
    ) -> Result<(), crate::Error> {
        crate::resources::require_disk_space(
            self.checkpoint.directory(),
            candidate.bytes.len() as u64,
        )?;
        let id = crate::hex(candidate.id.as_bytes());
        let starts = candidate
            .dependencies
            .iter()
            .map(|id| crate::hex(id.as_bytes()))
            .collect::<Vec<_>>();
        if self.has_path(&starts, &id, crate::resources::limits().request_timeout)? {
            return Err("dependency cycle".into());
        }
        let sequence = format!("{:020}", self.header.next);
        let mut header = self.header.clone();
        header.next = header
            .next
            .checked_add(1)
            .ok_or("proof backlog FIFO exhausted")?;
        let mut updates = vec![
            Update::put("proof", &id, &sequence)?,
            Update::Put {
                kind: "pending",
                key: sequence.clone(),
                payload: encode(&candidate.record())?,
            },
        ];
        for dependency in &starts {
            updates.push(Update::put("edge", format!("{id}{dependency}"), &true)?);
        }
        self.checkpoint.commit(&header, updates)?;
        self.header = header;
        if self.scheduled {
            self.schedule_one(&sequence, &candidate.dependencies, context)?;
        }
        Ok(())
    }
    pub(super) fn remove(&mut self, id: ArtifactId) -> Result<(), crate::Error> {
        let id = crate::hex(id.as_bytes());
        let Some(sequence) = self.checkpoint.get::<String>("proof", &id, 128)? else {
            return Ok(());
        };
        let bytes = self
            .checkpoint
            .get_bytes(
                "pending",
                &sequence,
                crate::resources::limits().active_job_bytes,
            )?
            .ok_or("proof backlog payload is missing")?;
        let proof = decode(&bytes)?;
        let mut updates = vec![
            Update::Remove {
                kind: "pending",
                key: sequence.clone(),
            },
            Update::Remove {
                kind: "proof",
                key: id.clone(),
            },
        ];
        for dependency in &proof.dependencies {
            updates.push(Update::Remove {
                kind: "edge",
                key: format!("{id}{}", crate::hex(dependency.as_bytes())),
            });
        }
        self.checkpoint.commit(&self.header, updates)?;
        if self.scheduled {
            self.checkpoint.query(|connection| {
                connection
                    .execute(
                        "DELETE FROM temp.proof_ready WHERE sequence=?1",
                        [&sequence],
                    )
                    .map_err(sql)?;
                connection
                    .execute(
                        "DELETE FROM temp.proof_waiting WHERE sequence=?1",
                        [&sequence],
                    )
                    .map_err(sql)?;
                Ok(())
            })?;
        }
        Ok(())
    }
    /// Build disposable readiness indexes once from canonical untrusted rows.
    /// Mathematical membership comes only from the freshly rechecked context.
    pub(super) fn schedule(&mut self, context: &DiskArtifactState) -> Result<(), crate::Error> {
        if self.scheduled {
            return Ok(());
        }
        self.checkpoint.query(|connection| {
            connection.execute_batch("CREATE TEMP TABLE IF NOT EXISTS proof_ready(sequence TEXT PRIMARY KEY) WITHOUT ROWID; CREATE TEMP TABLE IF NOT EXISTS proof_waiting(dependency BLOB, sequence TEXT, PRIMARY KEY(dependency,sequence)) WITHOUT ROWID; CREATE INDEX IF NOT EXISTS temp.waiting_by_sequence ON proof_waiting(sequence); DELETE FROM proof_ready; DELETE FROM proof_waiting;").map_err(sql)
        })?;
        let mut after = None;
        loop {
            let page = self.checkpoint.page(
                "pending",
                after.as_deref(),
                crate::resources::active_limits().pending_page,
                crate::resources::limits().active_job_bytes,
            )?;
            if page.is_empty() {
                break;
            }
            for (sequence, bytes) in page {
                let proof = decode(&bytes)?;
                self.schedule_one(&sequence, &proof.dependencies, context)?;
                after = Some(sequence);
            }
        }
        self.scheduled = true;
        Ok(())
    }
    fn schedule_one(
        &self,
        sequence: &str,
        dependencies: &BTreeSet<ArtifactId>,
        context: &DiskArtifactState,
    ) -> Result<(), crate::Error> {
        let missing = dependencies
            .iter()
            .filter_map(|id| match context.contains_artifact(*id) {
                Ok(true) => None,
                Ok(false) => Some(Ok(*id)),
                Err(e) => Some(Err(crate::Error::from(e))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.checkpoint.query(|connection| {
            if missing.is_empty() {
                connection
                    .execute("INSERT INTO temp.proof_ready VALUES(?1)", [sequence])
                    .map_err(sql)?;
            } else {
                for id in missing {
                    connection
                        .execute(
                            "INSERT INTO temp.proof_waiting VALUES(?1,?2)",
                            rusqlite::params![id.as_bytes().as_slice(), sequence],
                        )
                        .map_err(sql)?;
                }
            }
            Ok(())
        })
    }
    pub(super) fn accepted(&mut self, id: ArtifactId) -> Result<(), crate::Error> {
        if !self.scheduled {
            return Ok(());
        }
        self.checkpoint.query(|connection| {
            let tx = connection.unchecked_transaction().map_err(sql)?;
            tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS proof_notified(sequence TEXT PRIMARY KEY) WITHOUT ROWID; DELETE FROM proof_notified;").map_err(sql)?;
            tx.execute("INSERT INTO temp.proof_notified SELECT sequence FROM temp.proof_waiting WHERE dependency=?1", [id.as_bytes().as_slice()]).map_err(sql)?;
            tx.execute("DELETE FROM temp.proof_waiting WHERE dependency=?1", [id.as_bytes().as_slice()]).map_err(sql)?;
            tx.execute_batch("INSERT OR IGNORE INTO temp.proof_ready SELECT sequence FROM temp.proof_notified n WHERE NOT EXISTS(SELECT 1 FROM temp.proof_waiting w WHERE w.sequence=n.sequence); DELETE FROM temp.proof_notified;").map_err(sql)?;
            tx.commit().map_err(sql)
        })
    }
    pub(super) fn next_page(&mut self) -> Result<Vec<Candidate>, crate::Error> {
        if !self.scheduled {
            return Err("proof backlog readiness not initialized".into());
        }
        let read = |after: Option<&str>| {
            self.checkpoint.query(|connection| {
            let mut statement = connection.prepare("SELECT sequence FROM temp.proof_ready WHERE sequence > ?1 ORDER BY sequence LIMIT ?2").map_err(sql)?;
            statement.query_map(rusqlite::params![after.unwrap_or(""), i64::try_from(crate::resources::active_limits().pending_page).map_err(|_| "pending page width")?], |r| r.get::<_, String>(0)).map_err(sql)?.collect::<Result<Vec<_>, _>>().map_err(sql)
        })
        };
        let mut keys = read(self.header.cursor.as_deref())?;
        if keys.is_empty() {
            keys = read(None)?;
        }
        let mut result = Vec::new();
        let mut used = 0usize;
        for sequence in keys {
            let bytes = self
                .checkpoint
                .get_bytes("pending", &sequence, crate::checkpoint::MAX_ROW)?
                .ok_or("ready backlog record missing")?;
            if !result.is_empty()
                && bytes.len()
                    > crate::resources::limits()
                        .closure_bytes
                        .saturating_sub(used)
            {
                break;
            }
            used += bytes.len();
            self.header.cursor = Some(sequence);
            result.push(decode(&bytes)?);
        }
        // Fairness is volatile derived state; blocked ticks perform no fsync.
        Ok(result)
    }
    pub(super) fn ids(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ArtifactId>, crate::Error> {
        self.checkpoint
            .page(
                "proof",
                after,
                limit.min(crate::resources::active_limits().id_page),
                crate::resources::limits().closure_bytes,
            )?
            .into_iter()
            .map(|(id, _)| crate::object::id_bytes(&id).map(ArtifactId::from_bytes))
            .collect()
    }
}
fn encode(artifact: &BinaryArtifact) -> Result<Vec<u8>, crate::Error> {
    serde_json::to_vec(&artifact.envelope()).map_err(|error| error.to_string().into())
}
fn decode(bytes: &[u8]) -> Result<Candidate, crate::Error> {
    if bytes.len() > 2 * naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES + 1024 {
        return Err("artifact backlog row limit".into());
    }
    let envelope: crate::Envelope =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    envelope.prepare_retained()
}

fn sql(error: rusqlite::Error) -> crate::Error {
    crate::Error::CorruptStorage(format!("proof backlog index: {error}"))
}
