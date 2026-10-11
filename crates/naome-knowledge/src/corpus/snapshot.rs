//! Frozen node-owned source records. Only compact handles enter provider input.
//! Deduplicated rows remain outside accepted objects and confer no admission.
use super::{CachedReference, ProofCorpus, Reference};
use crate::{Graph, question::StoredQuestion};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

const VERSION: u8 = 1;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_PROOF_ROW_BYTES: usize = 2 * crate::MAX_PROOF_BYTES + 4096;
const MAX_STATEMENT_BYTES: usize = 16 * naome_foundation::FORMULA_MAX_BYTES;
const MAX_QUESTION_ROW_BYTES: usize = 6 * naome_authoring::QUESTION_SOURCE_MAX_BYTES + 2048;
const MAX_STORE_BYTES: u64 = 768 * 1024 * 1024;
const MAX_SNAPSHOTS: usize = 128;
const BUCKETS: [&str; 4] = ["manifests", "proofs", "statements", "questions"];

fn digest(bytes: &[u8]) -> String {
    crate::hex(&Sha256::digest(bytes))
}
fn encoded(value: &impl Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Handle {
    pub version: u8,
    pub snapshot_id: String,
    pub artifact_snapshot: String,
    pub graph_root: String,
    pub knowledge_snapshot: String,
    pub proof_count: usize,
    pub question_count: Option<usize>,
}
impl Handle {
    pub fn validate(&self) -> Result<(), String> {
        for id in [
            &self.snapshot_id,
            &self.artifact_snapshot,
            &self.graph_root,
            &self.knowledge_snapshot,
        ] {
            crate::object::id_bytes(id)?;
        }
        if self.version != VERSION
            || self.proof_count > crate::MAX_OBJECTS
            || self
                .question_count
                .is_some_and(|n| n > crate::question::MAX_REGISTERED_QUESTIONS)
        {
            return Err("frozen snapshot handle version or capacity differs".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    artifact_snapshot: String,
    graph_root: String,
    knowledge_snapshot: String,
    proofs: BTreeMap<String, String>,
    questions: Option<BTreeMap<String, String>>,
}
impl Manifest {
    fn handle(&self) -> Result<Handle, String> {
        Ok(Handle {
            version: self.version,
            snapshot_id: digest(&encoded(self)?),
            artifact_snapshot: self.artifact_snapshot.clone(),
            graph_root: self.graph_root.clone(),
            knowledge_snapshot: self.knowledge_snapshot.clone(),
            proof_count: self.proofs.len(),
            question_count: self.questions.as_ref().map(BTreeMap::len),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    digest: String,
    bytes: usize,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredProof {
    proof: crate::Envelope,
    statement: Statement,
    dependencies: Vec<String>,
}

/// Target association describes actually retained local questions. It does not
/// identify the question that historically caused this proof to be produced.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Association {
    pub source_hash: String,
    pub association: &'static str,
    pub resolution: &'static str,
    pub record: Arc<StoredQuestion>,
}

/// Constructor/import checks precede immutable publication. Subsequent tool
/// reads borrow this source; they never rebuild the accepted graph.
#[derive(Clone)]
pub(crate) struct Frozen {
    manifest: Manifest,
    handle: Handle,
    corpus: Arc<ProofCorpus>,
    rows: BTreeMap<String, CachedReference>,
    questions: Option<BTreeMap<String, Arc<StoredQuestion>>>,
    by_statement: BTreeMap<String, Vec<Association>>,
    query_projections: BTreeMap<String, Arc<str>>,
}
impl Frozen {
    pub(super) fn stored_questions(&self) -> impl Iterator<Item = (&String, &Arc<StoredQuestion>)> {
        self.questions.iter().flat_map(|entries| entries.iter())
    }
    /// Full native query projection v1, matched to exact retained source bytes
    /// or the identical complete projection. Never truncate a native question.
    pub(super) fn stored_query(&self, query: &str) -> Result<Option<String>, String> {
        for (hash, record) in self.stored_questions() {
            let projected = self
                .query_projections
                .get(hash)
                .ok_or("checked native query projection absent")?;
            if query == record.source || query == projected.as_ref() {
                return Ok(Some(projected.to_string()));
            }
        }
        Ok(None)
    }
    pub(super) fn query_projections(&self) -> impl Iterator<Item = (&String, &Arc<str>)> {
        self.query_projections.iter()
    }
    #[cfg(test)]
    pub fn capture(
        graph: &Graph,
        questions: Option<BTreeMap<String, StoredQuestion>>,
        knowledge_snapshot: &str,
    ) -> Result<Self, String> {
        Seed::capture(graph, questions, knowledge_snapshot)?.freeze()
    }
    fn assemble(
        manifest: Manifest,
        corpus: Arc<ProofCorpus>,
        rows: BTreeMap<String, CachedReference>,
        questions: Option<BTreeMap<String, Arc<StoredQuestion>>>,
    ) -> Result<Self, String> {
        let handle = manifest.handle()?;
        handle.validate()?;
        let mut by_statement: BTreeMap<String, Vec<Association>> = BTreeMap::new();
        let mut query_projections = BTreeMap::new();
        if let Some(questions) = &questions {
            if questions.len() > crate::question::MAX_REGISTERED_QUESTIONS
                || questions
                    .values()
                    .map(|entry| entry.source.len())
                    .sum::<usize>()
                    > crate::question::MAX_REGISTERED_SOURCE_BYTES
            {
                return Err("frozen original question record capacity".into());
            }
            for (source_hash, record) in questions {
                let question = record.validate(source_hash)?;
                query_projections.insert(
                    source_hash.clone(),
                    Arc::from(question.core().to_controlled_english()),
                );
                for (resolution, target) in [
                    ("proved", question.proved_target()),
                    ("refuted", question.refuted_target()),
                ] {
                    let statement = crate::hex(crate::object::target_id(target)?.as_bytes());
                    by_statement
                        .entry(statement)
                        .or_default()
                        .push(Association {
                            source_hash: source_hash.clone(),
                            association: "matching_registered_question",
                            resolution,
                            record: record.clone(),
                        });
                }
            }
        }
        Ok(Self {
            manifest,
            handle,
            corpus,
            rows,
            questions,
            by_statement,
            query_projections,
        })
    }
    pub fn handle(&self) -> &Handle {
        &self.handle
    }
    pub fn corpus(&self) -> &ProofCorpus {
        &self.corpus
    }
    pub fn reference(&self, id: &str) -> Option<&Reference> {
        self.rows.get(id).map(|row| row.reference.as_ref())
    }
    pub fn associations(&self, statement: &str) -> &[Association] {
        self.by_statement
            .get(statement)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
    pub fn full_record(&self, id: &str) -> Result<Option<serde_json::Value>, String> {
        crate::object::id_bytes(id)?;
        Ok(self.reference(id).map(|row|serde_json::json!({
            "envelope":row.proof,"native_conclusion":row.native_conclusion,
            "direct_dependencies":row.dependencies,"citation_expression":format!("cite(\"{id}\")"),
            "original_proof_source":{"availability":"not_stored"},
            "original_question_records":{"availability":if self.questions.is_some(){"available"}else{"unavailable_in_frozen_snapshot"},
                "association_semantics":"matching local target, not causal proof provenance",
                "matching_registered_questions":self.associations(&row.proof.statement_id)},
        })))
    }
    pub fn semantic_content(&self, id: &str) -> Result<String, String> {
        let reference = self
            .reference(id)
            .ok_or("semantic source proof is absent")?;
        let mut content = self.base_semantic_content(id)?;
        content.push_str("\nnaome:semantic-actual-question-associations:v6\n");
        match &self.questions {
            None => content
                .push_str("Original question records are unavailable in this frozen snapshot.\n"),
            Some(_) => {
                let matching = self.associations(&reference.proof.statement_id);
                if matching.is_empty() {
                    content.push_str(
                        "No matching registered question is retained in this snapshot.\n",
                    );
                } else {
                    content.push_str("Matching retained question sources by native target; not causal proof provenance:\n");
                    for association in matching {
                        use std::fmt::Write;
                        writeln!(
                            content,
                            "Target orientation: {}. Original question source:\n{}",
                            association.resolution, association.record.source
                        )
                        .map_err(|e| e.to_string())?;
                    }
                }
            }
        }
        if content.len() > super::local::MAX_INPUT_BYTES {
            return Err(
                "complete semantic proof and actual question association capacity exceeded".into(),
            );
        }
        Ok(content)
    }
    pub fn base_semantic_content(&self, id: &str) -> Result<String, String> {
        let row = self.rows.get(id).ok_or("semantic source proof is absent")?;
        super::semantic::proof_content(&row.reference, &row.controlled_conclusion)
    }
}

pub(crate) struct Store {
    root: PathBuf,
}
impl Store {
    pub fn cursor_key(&self) -> Result<super::cursor::Key, String> {
        super::cursor::Key::open(self.root.parent().ok_or("cursor directory absent")?)
    }

    pub fn open(directory: &Path) -> Result<Self, String> {
        let root = crate::jobs::research_directory(directory)?.join("snapshots");
        owned_directory(&root)?;
        for bucket in BUCKETS {
            owned_directory(&root.join(bucket))?;
        }
        let store = Self { root };
        store.inventory()?;
        Ok(store)
    }
    fn path(&self, bucket: &str, id: &str) -> Result<PathBuf, String> {
        crate::object::id_bytes(id)?;
        let suffix = if bucket == "statements" {
            "txt"
        } else {
            "json"
        };
        Ok(self.root.join(bucket).join(format!("{id}.{suffix}")))
    }
    /// Row fsync/rename and manifest fsync precede the journal reference. A crash
    /// can leave disposable orphan rows, never a partially published snapshot.
    pub fn persist(&self, snapshot: &Frozen) -> Result<(), String> {
        let (mut size, count) = self.inventory()?;
        let mut pending: BTreeMap<(&str, String), (Vec<u8>, usize)> = BTreeMap::new();
        let mut statements: BTreeMap<&str, Statement> = BTreeMap::new();
        for row in snapshot.rows.values() {
            let conclusion = row.reference.native_conclusion.as_bytes();
            let statement = statements
                .entry(&row.reference.proof.statement_id)
                .or_insert_with(|| Statement {
                    digest: digest(conclusion),
                    bytes: conclusion.len(),
                })
                .clone();
            if statement.bytes > MAX_STATEMENT_BYTES {
                return Err("frozen statement source byte limit".into());
            }
            pending
                .entry(("statements", statement.digest.clone()))
                .or_insert_with(|| (conclusion.to_vec(), MAX_STATEMENT_BYTES));
            let data = encoded(&StoredProof {
                proof: row.reference.proof.clone(),
                statement,
                dependencies: row.reference.dependencies.clone(),
            })?;
            pending.insert(("proofs", row.digest.clone()), (data, MAX_PROOF_ROW_BYTES));
        }
        if let Some(questions) = &snapshot.questions {
            for row in questions.values() {
                let data = encoded(row)?;
                pending.insert(("questions", digest(&data)), (data, MAX_QUESTION_ROW_BYTES));
            }
        }
        let data = encoded(&snapshot.manifest)?;
        let manifest = self.path("manifests", &snapshot.handle.snapshot_id)?;
        if !manifest.exists() && count >= MAX_SNAPSHOTS {
            return Err("frozen retained snapshot count capacity".into());
        }
        pending.insert(
            ("manifests", snapshot.handle.snapshot_id.clone()),
            (data, MAX_MANIFEST_BYTES),
        );
        let mut unique = BTreeMap::new();
        for ((bucket, id), (data, maximum)) in pending {
            if data.len() > maximum {
                return Err("frozen source row capacity".into());
            }
            let path = self.path(bucket, &id)?;
            if path.exists() {
                if read_regular(&path, maximum)? != data {
                    return Err("frozen source row is corrupt; refusing replacement".into());
                }
            } else if let std::collections::btree_map::Entry::Vacant(entry) = unique.entry(path) {
                size = size
                    .checked_add(data.len() as u64)
                    .ok_or("frozen source storage overflow")?;
                entry.insert(data);
            }
        }
        if size > MAX_STORE_BYTES {
            return Err("frozen source storage capacity; retained jobs remain pinned".into());
        }
        // Map ordering is not the publication protocol: manifests are last.
        for (path, data) in &unique {
            if path.parent() != Some(self.root.join("manifests").as_path()) {
                write_new_atomic(path, data)?;
            }
        }
        if let Some(data) = unique.get(&manifest) {
            write_new_atomic(&manifest, data)?;
        }
        Ok(())
    }
    pub fn load(&self, expected: &Handle) -> Result<Frozen, String> {
        expected.validate()?;
        let bytes = read_regular(
            &self.path("manifests", &expected.snapshot_id)?,
            MAX_MANIFEST_BYTES,
        )?;
        if digest(&bytes) != expected.snapshot_id {
            return Err("frozen manifest digest differs".into());
        }
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if manifest.handle()? != *expected {
            return Err("frozen manifest handle differs".into());
        }
        let mut statements: BTreeMap<String, Arc<str>> = BTreeMap::new();
        let mut rows = BTreeMap::new();
        let mut references = Vec::new();
        for (proof_id, row_digest) in &manifest.proofs {
            crate::object::id_bytes(proof_id)?;
            let row: StoredProof = serde_json::from_slice(&read_regular(
                &self.path("proofs", row_digest)?,
                MAX_PROOF_ROW_BYTES,
            )?)
            .map_err(|e| e.to_string())?;
            if row.statement.bytes > MAX_STATEMENT_BYTES
                || row.proof.proof_id != *proof_id
                || row.dependencies.len() > crate::MAX_DEPENDENCIES
            {
                return Err("frozen proof row binding or capacity differs".into());
            }
            let text = if let Some(text) = statements.get(&row.statement.digest) {
                text.clone()
            } else {
                let bytes = read_regular(
                    &self.path("statements", &row.statement.digest)?,
                    MAX_STATEMENT_BYTES,
                )?;
                if digest(&bytes) != row.statement.digest || bytes.len() != row.statement.bytes {
                    return Err("frozen statement source differs".into());
                }
                let text: Arc<str> = String::from_utf8(bytes).map_err(|e| e.to_string())?.into();
                statements.insert(row.statement.digest.clone(), text.clone());
                text
            };
            if text.len() != row.statement.bytes {
                return Err("frozen statement length differs".into());
            }
            let cached = CachedReference::new(
                Reference {
                    proof: row.proof,
                    native_conclusion: text,
                    dependencies: row.dependencies,
                },
                Arc::from(""),
            );
            if cached.digest != *row_digest {
                return Err("frozen complete proof projection digest differs".into());
            }
            references.push(cached.reference.clone());
            rows.insert(proof_id.clone(), cached);
        }
        let corpus = Arc::new(ProofCorpus {
            artifact_snapshot: manifest.artifact_snapshot.clone(),
            graph_root: manifest.graph_root.clone(),
            references,
            definitions_supported: false,
            registry_entries_included: false,
        });
        let checked = corpus.checked_graph()?;
        // Import derives English again from the actual checker-owned formula,
        // never from mutable cache text. Native manifest and row bytes stay v1.
        rows = checked
            .corpus_references()
            .map(|row| (row.reference.proof.proof_id.clone(), row.clone()))
            .collect();
        let questions = manifest
            .questions
            .as_ref()
            .map(|entries| {
                entries
                    .iter()
                    .map(|(id, row_digest)| {
                        crate::object::id_bytes(id)?;
                        let bytes = read_regular(
                            &self.path("questions", row_digest)?,
                            MAX_QUESTION_ROW_BYTES,
                        )?;
                        if digest(&bytes) != *row_digest {
                            return Err("frozen original question row differs".into());
                        }
                        let record: StoredQuestion =
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                        record.validate(id)?;
                        Ok((id.clone(), Arc::new(record)))
                    })
                    .collect::<Result<_, String>>()
            })
            .transpose()?;
        Frozen::assemble(manifest, corpus, rows, questions)
    }
    /// Pins include every retained journal record, pending publication and live
    /// process; terminal, unacknowledged and InDoubt requests are not exceptions.
    pub fn collect(&self, pins: &BTreeSet<String>) -> Result<(), String> {
        let mut keep: BTreeMap<&str, BTreeSet<String>> = BUCKETS
            .into_iter()
            .map(|name| (name, BTreeSet::new()))
            .collect();
        for id in pins {
            let bytes = read_regular(&self.path("manifests", id)?, MAX_MANIFEST_BYTES)?;
            if digest(&bytes) != *id {
                return Err("pinned frozen manifest differs".into());
            }
            let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            manifest.handle()?.validate()?;
            keep.get_mut("manifests")
                .expect("bucket")
                .insert(id.clone());
            for digest in manifest.proofs.values() {
                keep.get_mut("proofs")
                    .expect("bucket")
                    .insert(digest.clone());
                let row: StoredProof = serde_json::from_slice(&read_regular(
                    &self.path("proofs", digest)?,
                    MAX_PROOF_ROW_BYTES,
                )?)
                .map_err(|e| e.to_string())?;
                crate::object::id_bytes(&row.statement.digest)?;
                keep.get_mut("statements")
                    .expect("bucket")
                    .insert(row.statement.digest);
            }
            if let Some(questions) = manifest.questions {
                keep.get_mut("questions")
                    .expect("bucket")
                    .extend(questions.into_values());
            }
        }
        for bucket in BUCKETS {
            let directory = self.root.join(bucket);
            for entry in fs::read_dir(&directory).map_err(|e| e.to_string())? {
                let path = entry.map_err(|e| e.to_string())?.path();
                let (id, temporary) = file_identity(&path)?;
                if temporary || !keep[bucket].contains(&id) {
                    read_regular(&path, MAX_STATEMENT_BYTES)?;
                    fs::remove_file(path).map_err(|e| e.to_string())?;
                }
            }
            sync(&directory)?;
        }
        Ok(())
    }
    fn inventory(&self) -> Result<(u64, usize), String> {
        let mut bytes = 0u64;
        let mut manifests = 0usize;
        for bucket in BUCKETS {
            for entry in fs::read_dir(self.root.join(bucket)).map_err(|e| e.to_string())? {
                let path = entry.map_err(|e| e.to_string())?.path();
                let (_, temporary) = file_identity(&path)?;
                let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
                if !metadata.is_file()
                    || metadata.nlink() != 1
                    || metadata.uid() != nix::unistd::geteuid().as_raw()
                {
                    return Err("frozen row must be one owned regular file".into());
                }
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or("frozen storage overflow")?;
                manifests += usize::from(bucket == "manifests" && !temporary);
            }
        }
        if bytes > MAX_STORE_BYTES || manifests > MAX_SNAPSHOTS {
            return Err("frozen retained store capacity".into());
        }
        Ok((bytes, manifests))
    }
}

fn file_identity(path: &Path) -> Result<(String, bool), String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("unknown frozen source file")?;
    let temporary = name.starts_with(".incoming-");
    let name = name.strip_prefix(".incoming-").unwrap_or(name);
    let id = name
        .strip_suffix(".json")
        .or_else(|| name.strip_suffix(".txt"))
        .ok_or("unknown frozen source file")?;
    crate::object::id_bytes(id)?;
    Ok((id.into(), temporary))
}
pub(super) fn owned_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|e| e.to_string())?;
            sync(path.parent().ok_or("frozen directory parent absent")?)?;
        }
        Err(error) => return Err(error.to_string()),
        _ => {}
    }
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err("frozen source directory must be owned and unaliased".into());
    }
    Ok(())
}
pub(super) fn read_regular(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.len() > maximum as u64
    {
        return Err("frozen/model asset must be one owned bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > maximum {
        return Err("frozen/model asset byte limit".into());
    }
    Ok(bytes)
}
fn sync(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}
fn write_new_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let directory = path.parent().ok_or("frozen row directory absent")?;
    let temporary = directory.join(format!(
        ".incoming-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or("frozen row name")?
    ));
    if temporary.exists() {
        read_regular(&temporary, MAX_STATEMENT_BYTES)?;
        fs::remove_file(&temporary).map_err(|e| e.to_string())?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(&temporary, path).map_err(|e| e.to_string())?;
    sync(directory)
}

#[cfg(test)]
mod tests;

impl std::fmt::Debug for Frozen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frozen")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

/// Cheap checked-custody capture on the node loop; compilation and persistence
/// happen on the bounded source service, away from gossip and job control.
#[derive(Clone)]
pub(crate) struct Seed {
    corpus: Arc<ProofCorpus>,
    rows: BTreeMap<String, CachedReference>,
    questions: Option<BTreeMap<String, StoredQuestion>>,
    knowledge_snapshot: String,
}
impl Seed {
    pub fn capture(
        graph: &Graph,
        questions: Option<BTreeMap<String, StoredQuestion>>,
        knowledge_snapshot: &str,
    ) -> Result<Self, String> {
        crate::object::id_bytes(knowledge_snapshot)?;
        Ok(Self {
            corpus: Arc::new(ProofCorpus::capture(graph)?),
            rows: graph
                .corpus_references()
                .map(|row| (row.reference.proof.proof_id.clone(), row.clone()))
                .collect(),
            questions,
            knowledge_snapshot: knowledge_snapshot.into(),
        })
    }
    pub fn freeze(self) -> Result<Frozen, String> {
        let manifest = Manifest {
            version: VERSION,
            artifact_snapshot: self.corpus.artifact_snapshot.clone(),
            graph_root: self.corpus.graph_root.clone(),
            knowledge_snapshot: self.knowledge_snapshot,
            proofs: self
                .rows
                .iter()
                .map(|(id, row)| (id.clone(), row.digest.clone()))
                .collect(),
            questions: self
                .questions
                .as_ref()
                .map(|entries| {
                    entries
                        .iter()
                        .map(|(id, row)| Ok((id.clone(), digest(&encoded(row)?))))
                        .collect::<Result<_, String>>()
                })
                .transpose()?,
        };
        let handle = manifest.handle()?;
        handle.validate()?;
        if encoded(&manifest)?.len() > MAX_MANIFEST_BYTES {
            return Err("frozen manifest byte limit".into());
        }
        Frozen::assemble(
            manifest,
            self.corpus,
            self.rows,
            self.questions.map(|entries| {
                entries
                    .into_iter()
                    .map(|(id, row)| (id, Arc::new(row)))
                    .collect()
            }),
        )
    }
}
