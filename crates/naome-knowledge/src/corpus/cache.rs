//! Disposable derived vectors. Canonical accepted objects never depend on them.
use super::{
    local::LocalEncoder,
    semantic::{SemanticIndex, SemanticPage, SourceVectorRow},
    snapshot::{Frozen, owned_directory, read_regular},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

const MAX_ROW_BYTES: usize = 4 * 1024 * 1024;
const MAX_INDEX_BYTES: usize = 256 * 1024 * 1024;
const MAX_DISK_BYTES: u64 = 768 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub model_directory: PathBuf,
    #[serde(default = "quantum_ms")]
    pub quantum_ms: u64,
    #[serde(default = "memory_bytes")]
    pub memory_bytes: u64,
}
fn quantum_ms() -> u64 {
    30_000
}
fn memory_bytes() -> u64 {
    1024 * 1024 * 1024
}
impl Settings {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !self.model_directory.is_absolute()
            || self.model_directory.as_os_str().as_encoded_bytes().len() > 4096
            || !(100..=30_000).contains(&self.quantum_ms)
            || !(256 * 1024 * 1024..=1024 * 1024 * 1024).contains(&self.memory_bytes)
        {
            return Err("local retrieval model path, quantum or memory limit differs".into());
        }
        Ok(())
    }
}

pub(super) struct Cache {
    pub(super) root: PathBuf,
    pub(super) accounts: PathBuf,
    known_accounts: RefCell<BTreeSet<String>>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QueryVector {
    version: u8,
    encoder: super::semantic::EncoderIdentity,
    query: String,
    vector: Vec<f32>,
}
impl QueryVector {
    fn validate(&self, query: &str) -> Result<(), String> {
        let encoder = LocalEncoder::identity_specification();
        let norm: f64 = self
            .vector
            .iter()
            .map(|v| f64::from(*v).powi(2))
            .sum::<f64>()
            .sqrt();
        if self.version != 1
            || self.encoder != encoder
            || self.query != query
            || query.trim().is_empty()
            || query.len() > 1024
            || self.vector.len() != usize::from(encoder.dimensions)
            || self.vector.iter().any(|v| !v.is_finite())
            || (norm - 1.0).abs() > 0.000_002
        {
            return Err("saved query vector source, encoder or normalization differs".into());
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    source_id: String,
    index_key: String,
    rows: Vec<String>,
    complete: bool,
}
impl Cache {
    pub fn open(directory: &Path) -> Result<Self, String> {
        let research = crate::jobs::research_directory(directory)?;
        let root = research.join("embeddings");
        // Disposable vector loss must not recreate the original work accounts.
        let accounts = research.join("index-work");
        let marker = directory.join("index-work.initialized");
        let initialized = crate::jobs::marker_valid(&marker, b"naome-index-work-v1\n")?;
        if initialized {
            for path in [
                &accounts,
                &accounts.join("work"),
                &accounts.join("work-markers"),
            ] {
                if !fs::symlink_metadata(path)
                    .map_err(|e| {
                        format!("established index accounts unavailable; refusing reset: {e}")
                    })?
                    .is_dir()
                {
                    return Err("established index account directory differs".into());
                }
            }
        }
        owned_directory(&accounts)?;
        for bucket in ["work", "work-markers"] {
            owned_directory(&accounts.join(bucket))?;
        }
        owned_directory(&root)?;
        for bucket in ["rows", "indexes", "rankings", "manifests", "queries"] {
            owned_directory(&root.join(bucket))?;
        }
        let known_path = accounts.join("known.json");
        let known_accounts: Option<BTreeSet<String>> =
            crate::jobs::read_checkpoint(&known_path, 2 * 1024 * 1024)?;
        if initialized && known_accounts.is_none() {
            return Err("established index account catalogue missing; refusing reset".into());
        }
        let known_accounts = known_accounts.unwrap_or_default();
        if known_accounts.len() > 16_384 {
            return Err("index account catalogue capacity".into());
        }
        for key in &known_accounts {
            crate::object::id_bytes(key)?;
        }
        if !initialized {
            crate::jobs::write_checkpoint(&known_path, &known_accounts, 2 * 1024 * 1024)?;
        }
        let cache = Self {
            root,
            accounts,
            known_accounts: RefCell::new(known_accounts),
        };
        cache.inventory()?;
        if !initialized {
            crate::jobs::write_marker(&marker, b"naome-index-work-v1\n")?;
        }
        Ok(cache)
    }
    pub(super) fn establish_account(
        &self,
        key: &str,
        present: bool,
        marker: bool,
    ) -> Result<(), String> {
        let mut known = self.known_accounts.borrow_mut();
        if known.contains(key) {
            if !present || !marker {
                return Err(
                    "established index account or marker missing; refusing allowance reset".into(),
                );
            }
        } else {
            if known.len() >= 16_384 {
                return Err("index account catalogue capacity".into());
            }
            known.insert(key.into());
            crate::jobs::write_checkpoint(
                &self.accounts.join("known.json"),
                &*known,
                2 * 1024 * 1024,
            )?;
        }
        Ok(())
    }
    pub fn model_lock(&self) -> Result<std::fs::File, String> {
        model_lease(&std::env::temp_dir())
    }
    pub(super) fn query_key(query: &str) -> String {
        crate::hex(&Sha256::digest(
            serde_json::to_vec(&(
                "naome:query-vector:v1",
                LocalEncoder::identity_specification(),
                query,
            ))
            .expect("finite query key"),
        ))
    }
    pub fn query(&self, query: &str) -> Result<Option<Vec<f32>>, String> {
        let row: Option<QueryVector> = crate::jobs::read_checkpoint(
            &self
                .root
                .join("queries")
                .join(format!("{}.json", Self::query_key(query))),
            16 * 1024,
        )?;
        row.map(|row| {
            row.validate(query)?;
            Ok(row.vector)
        })
        .transpose()
    }
    pub fn save_query(&self, query: &str, vector: Vec<f32>) -> Result<(), String> {
        let row = QueryVector {
            version: 1,
            encoder: LocalEncoder::identity_specification(),
            query: query.into(),
            vector,
        };
        row.validate(query)?;
        self.room(serde_json::to_vec(&row).map_err(|e| e.to_string())?.len())?;
        crate::jobs::write_checkpoint(
            &self
                .root
                .join("queries")
                .join(format!("{}.json", Self::query_key(query))),
            &row,
            16 * 1024,
        )
    }
    /// Only the indexing owner assembles snapshots from previously prepared rows.
    pub fn assemble(&self, source: &Frozen) -> Result<bool, String> {
        if self.index(source).ok().flatten().is_some() {
            return Ok(true);
        }
        let mut rows = Vec::with_capacity(source.corpus().references.len());
        for reference in &source.corpus().references {
            let content = source.semantic_content(&reference.proof.proof_id)?;
            let key = SourceVectorRow::key(
                &LocalEncoder::identity_specification(),
                &reference.proof.proof_id,
                &content,
            );
            let Some(row) = self.row(&key, source).ok().flatten() else {
                return Ok(false);
            };
            rows.push(row);
        }
        let index = SemanticIndex::build_source(
            source,
            LocalEncoder::identity_specification(),
            rows.clone(),
        )?;
        self.save_partial(source, &rows)?;
        self.save_index(source, &index)?;
        Ok(true)
    }
    pub fn index_key(source: &Frozen) -> String {
        crate::hex(&Sha256::digest(
            serde_json::to_vec(&(
                "naome:source-index:v3",
                source.handle(),
                LocalEncoder::identity_specification(),
            ))
            .expect("fixed source identity"),
        ))
    }
    pub fn row(&self, key: &str, source: &Frozen) -> Result<Option<SourceVectorRow>, String> {
        crate::object::id_bytes(key)?;
        let row: Option<SourceVectorRow> = crate::jobs::read_checkpoint(
            &self.root.join("rows").join(format!("{key}.json")),
            MAX_ROW_BYTES,
        )?;
        if let Some(row) = &row {
            row.validate(source, &LocalEncoder::identity_specification())?;
            if row.bound_key() != key {
                return Err("derived vector filename binding differs".into());
            }
        }
        Ok(row)
    }
    pub fn save_row(&self, key: &str, row: &SourceVectorRow) -> Result<(), String> {
        crate::object::id_bytes(key)?;
        if row.bound_key() != key {
            return Err("derived vector publication filename binding differs".into());
        }
        self.room(serde_json::to_vec(row).map_err(|e| e.to_string())?.len())?;
        crate::jobs::write_checkpoint(
            &self.root.join("rows").join(format!("{key}.json")),
            row,
            MAX_ROW_BYTES,
        )
    }
    pub fn index(&self, source: &Frozen) -> Result<Option<SemanticIndex>, String> {
        let manifest: Option<Manifest> = crate::jobs::read_checkpoint(
            &self
                .root
                .join("manifests")
                .join(format!("{}.json", source.handle().snapshot_id)),
            1024 * 1024,
        )?;
        let Some(manifest) = manifest else {
            return Ok(None);
        };
        self.validate_manifest(&manifest)?;
        if manifest.source_id != source.handle().snapshot_id
            || manifest.index_key != Self::index_key(source)
            || !manifest.complete
        {
            return Ok(None);
        }
        let path = self
            .root
            .join("indexes")
            .join(format!("{}.json", Self::index_key(source)));
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
            Ok(_) => {
                // The canonical checkpoint wrapper checks source bytes before
                // mathematical-custody and vector/content import checks.
                let _ = read_regular(&path, MAX_INDEX_BYTES)?;
                let index: SemanticIndex = crate::jobs::read_checkpoint(&path, MAX_INDEX_BYTES)?
                    .ok_or("retrieval index disappeared")?;
                let bytes = serde_json::to_vec(&index).map_err(|e| e.to_string())?;
                let index = SemanticIndex::from_json_source(source, &bytes)?;
                if index.encoder_identity() != &LocalEncoder::identity_specification() {
                    return Err("retrieval index encoder differs".into());
                }
                Ok(Some(index))
            }
        }
    }
    pub fn save_index(&self, source: &Frozen, index: &SemanticIndex) -> Result<(), String> {
        self.room(serde_json::to_vec(index).map_err(|e| e.to_string())?.len())?;
        crate::jobs::write_checkpoint(
            &self
                .root
                .join("indexes")
                .join(format!("{}.json", Self::index_key(source))),
            index,
            MAX_INDEX_BYTES,
        )?;
        let path = self
            .root
            .join("manifests")
            .join(format!("{}.json", source.handle().snapshot_id));
        let mut manifest: Manifest = crate::jobs::read_checkpoint(&path, 1024 * 1024)?
            .ok_or("complete retrieval rows manifest absent")?;
        self.validate_manifest(&manifest)?;
        if manifest.rows.len() != source.corpus().references.len() {
            return Err("complete retrieval rows manifest count differs".into());
        }
        manifest.complete = true;
        self.room(
            serde_json::to_vec(&manifest)
                .map_err(|e| e.to_string())?
                .len(),
        )?;
        crate::jobs::write_checkpoint(&path, &manifest, 1024 * 1024)
    }
    pub fn save_partial(&self, source: &Frozen, rows: &[SourceVectorRow]) -> Result<(), String> {
        if rows.len() > source.corpus().references.len() {
            return Err("derived partial manifest count differs".into());
        }
        let manifest = Manifest {
            version: 3,
            source_id: source.handle().snapshot_id.clone(),
            index_key: Self::index_key(source),
            rows: rows.iter().map(SourceVectorRow::bound_key).collect(),
            complete: false,
        };
        self.validate_manifest(&manifest)?;
        self.room(
            serde_json::to_vec(&manifest)
                .map_err(|e| e.to_string())?
                .len(),
        )?;
        crate::jobs::write_checkpoint(
            &self
                .root
                .join("manifests")
                .join(format!("{}.json", source.handle().snapshot_id)),
            &manifest,
            1024 * 1024,
        )
    }
    fn validate_manifest(&self, manifest: &Manifest) -> Result<(), String> {
        crate::object::id_bytes(&manifest.source_id)?;
        crate::object::id_bytes(&manifest.index_key)?;
        if manifest.version != 3 || manifest.rows.len() > crate::MAX_OBJECTS {
            return Err("derived manifest version or count differs".into());
        }
        for row in &manifest.rows {
            crate::object::id_bytes(row)?;
        }
        Ok(())
    }
    pub fn ranking(&self, key: &str) -> Result<Option<SemanticPage>, String> {
        crate::object::id_bytes(key)?;
        crate::jobs::read_checkpoint(
            &self.root.join("rankings").join(format!("{key}.json")),
            1024 * 1024,
        )
    }
    pub fn save_ranking(&self, key: &str, ranking: &SemanticPage) -> Result<(), String> {
        crate::object::id_bytes(key)?;
        self.room(
            serde_json::to_vec(ranking)
                .map_err(|e| e.to_string())?
                .len(),
        )?;
        crate::jobs::write_checkpoint(
            &self.root.join("rankings").join(format!("{key}.json")),
            ranking,
            1024 * 1024,
        )
    }
    pub fn progress(
        &self,
        source: &Frozen,
        stage: &str,
        _indexed: usize,
        reason: Option<&str>,
    ) -> Result<(), String> {
        let mut indexed = 0;
        for reference in &source.corpus().references {
            let content = source.semantic_content(&reference.proof.proof_id)?;
            let key = SourceVectorRow::key(
                &LocalEncoder::identity_specification(),
                &reference.proof.proof_id,
                &content,
            );
            indexed += usize::from(self.row(&key, source).ok().flatten().is_some());
        }
        let total_questions = source.query_projections().count();
        let indexed_questions = source
            .query_projections()
            .filter(|(_, query)| self.query(query).ok().flatten().is_some())
            .count();
        let complete = indexed == source.corpus().references.len()
            && indexed_questions == total_questions
            && self.index(source).ok().flatten().is_some();
        let stage = if complete {
            "complete"
        } else if stage == "complete" {
            "incomplete"
        } else {
            stage
        };
        let value = serde_json::json!({"version":2,"source":source.handle(),"stage":stage,"indexed_proofs":indexed,
            "total_proofs":source.corpus().references.len(),"complete":complete,
            "indexed_questions":indexed_questions,"total_questions":total_questions,
            "encoder":LocalEncoder::identity_specification(),"reason":reason});
        self.room(serde_json::to_vec(&value).map_err(|e| e.to_string())?.len())?;
        crate::jobs::write_checkpoint(&self.root.join("progress.json"), &value, 8192)?;
        crate::network::emit(
            serde_json::json!({"event":"retrieval_index_progress","progress":value}),
        );
        Ok(())
    }
    pub(super) fn room(&self, new_bytes: usize) -> Result<(), String> {
        if self
            .inventory()?
            .checked_add(new_bytes as u64 + 256)
            .is_none_or(|bytes| bytes > MAX_DISK_BYTES)
        {
            return Err("derived retrieval cache byte capacity".into());
        }
        Ok(())
    }
    fn inventory(&self) -> Result<u64, String> {
        let mut bytes = 0u64;
        match fs::symlink_metadata(self.root.join("progress.json")) {
            Ok(_) => bytes = read_regular(&self.root.join("progress.json"), 8192)?.len() as u64,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        let mut files = 0usize;
        bytes = bytes
            .checked_add(
                read_regular(&self.accounts.join("known.json"), 2 * 1024 * 1024)?.len() as u64,
            )
            .ok_or("index catalogue byte overflow")?;
        for path in ["rows", "indexes", "rankings", "manifests", "queries"]
            .map(|bucket| self.root.join(bucket))
            .into_iter()
            .chain(["work", "work-markers"].map(|bucket| self.accounts.join(bucket)))
        {
            for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                files += 1;
                if files > 32_768 {
                    return Err("derived cache file capacity".into());
                }
                let metadata = entry.path().symlink_metadata().map_err(|e| e.to_string())?;
                use std::os::unix::fs::MetadataExt;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.nlink() != 1
                    || metadata.uid() != nix::unistd::geteuid().as_raw()
                {
                    return Err("derived cache row ownership differs".into());
                }
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "derived cache row name differs")?;
                let id = name
                    .strip_suffix(".json")
                    .or_else(|| name.strip_suffix(".incoming"))
                    .ok_or("derived cache row suffix differs")?;
                crate::object::id_bytes(id)?;
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or("derived cache byte overflow")?;
                if bytes > MAX_DISK_BYTES {
                    return Err("derived cache byte capacity".into());
                }
            }
        }
        Ok(bytes)
    }
    /// Unused derived rows may be rebuilt, but never reset a job allowance.
    #[cfg(test)]
    pub fn collect(&self, source_pins: &BTreeSet<String>) -> Result<(), String> {
        self.collect_with_rows(source_pins, &BTreeSet::new())
    }
    pub fn collect_with_rows(
        &self,
        source_pins: &BTreeSet<String>,
        prepared_rows: &BTreeSet<String>,
    ) -> Result<(), String> {
        self.inventory()?;
        let mut row_pins = prepared_rows.clone();
        let mut index_pins = BTreeSet::new();
        for source_id in source_pins {
            crate::object::id_bytes(source_id)?;
            if let Some(manifest) = crate::jobs::read_checkpoint::<Manifest>(
                &self
                    .root
                    .join("manifests")
                    .join(format!("{source_id}.json")),
                1024 * 1024,
            )? {
                self.validate_manifest(&manifest)?;
                if &manifest.source_id != source_id {
                    return Err("derived manifest filename differs".into());
                }
                row_pins.extend(manifest.rows);
                index_pins.insert(manifest.index_key);
            }
        }
        for (bucket, pins) in [
            ("indexes", &index_pins),
            ("rows", &row_pins),
            ("manifests", source_pins),
        ] {
            for entry in fs::read_dir(self.root.join(bucket)).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "derived cache name differs")?;
                if let Some(id) = name.strip_suffix(".json") {
                    crate::object::id_bytes(id)?;
                    if !pins.contains(id) {
                        fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
                    }
                } else if name.ends_with(".incoming") {
                    fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
                } else {
                    return Err("derived cache row suffix differs".into());
                }
            }
            std::fs::File::open(self.root.join(bucket))
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
        }
        for entry in fs::read_dir(self.root.join("rankings")).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".incoming"))
            {
                fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
                continue;
            }
            let ranking: SemanticPage = crate::jobs::read_checkpoint(&entry.path(), 1024 * 1024)?
                .ok_or("derived ranking disappeared")?;
            if ranking
                .source_snapshot
                .as_ref()
                .is_none_or(|source| !source_pins.contains(source))
            {
                fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
            }
        }
        std::fs::File::open(self.root.join("rankings"))
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn model_lease(directory: &Path) -> Result<std::fs::File, String> {
    use std::{
        fs::{File, OpenOptions},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    #[derive(Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Identity {
        version: u8,
        uid: u32,
        dev: u64,
        ino: u64,
    }
    let uid = nix::unistd::geteuid().as_raw();
    let prefix = format!("naome-retrieval-cpu-{uid}");
    let path = directory.join(format!("{prefix}.lock"));
    let marker = directory.join(format!("{prefix}.initialized"));
    let initialized = match fs::symlink_metadata(&marker) {
        Ok(_) => Some(
            serde_json::from_slice::<Identity>(&read_regular(&marker, 256)?)
                .map_err(|e| e.to_string())?,
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.to_string()),
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(initialized.is_none())
        .truncate(false)
        .mode(0o600)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(&path)
        .map_err(|e| format!("retrieval established physical lease is unavailable: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != uid {
        return Err("retrieval physical model lease ownership differs".into());
    }
    let expected = Identity {
        version: 1,
        uid,
        dev: metadata.dev(),
        ino: metadata.ino(),
    };
    if initialized.as_ref().is_some_and(|value| value != &expected) {
        return Err("retrieval physical model lease inode differs".into());
    }
    file.try_lock()
        .map_err(|e| format!("retrieval model lease is occupied or unavailable: {e}"))?;
    file.sync_all().map_err(|e| e.to_string())?;
    if initialized.is_none() {
        let bytes = serde_json::to_vec(&expected).map_err(|e| e.to_string())?;
        match crate::jobs::write_marker(&marker, &bytes) {
            Ok(()) => {}
            Err(error) => {
                let existing: Identity = serde_json::from_slice(&read_regular(&marker, 256)?)
                    .map_err(|e| e.to_string())?;
                if existing != expected {
                    return Err(format!(
                        "retrieval concurrent lease initialization differs: {error}"
                    ));
                }
            }
        }
    }
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|e| e.to_string())?;
    // Recheck the path after initialization; alias replacement never creates a
    // second lease while a former model host retains the old open descriptor.
    let current = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if current.dev() != expected.dev
        || current.ino() != expected.ino
        || current.nlink() != 1
        || current.file_type().is_symlink()
    {
        return Err("retrieval physical lease changed during admission".into());
    }
    Ok(file)
}

#[cfg(test)]
mod tests;
