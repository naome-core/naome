use super::{BatchCut, COMMIT_DEADLINE_ERROR};
use crate::object::BinaryProof;
use naome_proof::ProofId;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use sha2::{Digest, Sha256};
use std::{cell::Cell, collections::BTreeMap, fs, path::Path, time::Instant};

#[cfg(test)]
std::thread_local! { static SET_SCANS: Cell<usize> = const { Cell::new(0) }; }
#[cfg(test)]
pub(super) fn set_scan_count() -> usize {
    SET_SCANS.with(Cell::get)
}

const APPLICATION_ID: i64 = 0x4e414f31;
const SCHEMA_VERSION: i64 = 5;
const IDS_PAGE_QUERY: &str = "SELECT substr(id,1,33) FROM proofs
    WHERE id > ?1 ORDER BY id LIMIT ?2";

const TABLES: [(&str, &str); 5] = [
    (
        "meta",
        "CREATE TABLE meta (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        database_id BLOB NOT NULL CHECK(length(database_id) = 32),
        state TEXT NOT NULL CHECK(state IN ('initializing', 'active')),
        corpus_root BLOB,
        corpus_count INTEGER NOT NULL CHECK(corpus_count >= 0),
        payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0),
        CHECK((state = 'initializing' AND corpus_root IS NULL AND corpus_count = 0 AND payload_bytes = 0) OR
              (state = 'active' AND corpus_root IS NOT NULL AND length(corpus_root) = 32))
    ) STRICT",
    ),
    (
        "commits",
        "CREATE TABLE commits (
        id BLOB PRIMARY KEY CHECK(length(id) = 32),
        root BLOB NOT NULL CHECK(length(root) = 32),
        member_count INTEGER NOT NULL CHECK(member_count >= 1),
        FOREIGN KEY(root) REFERENCES proofs(id) DEFERRABLE INITIALLY DEFERRED
    ) STRICT, WITHOUT ROWID",
    ),
    (
        "proofs",
        "CREATE TABLE proofs (
        id BLOB PRIMARY KEY CHECK(length(id) = 32),
        replay_order INTEGER NOT NULL UNIQUE CHECK(replay_order > 0),
        statement BLOB NOT NULL CHECK(length(statement) = 32),
        compatibility BLOB NOT NULL CHECK(length(compatibility) = 32),
        payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 4194304),
        payload_length INTEGER NOT NULL CHECK(payload_length = length(payload)),
        payload_digest BLOB NOT NULL CHECK(length(payload_digest) = 32),
        origin_commit BLOB NOT NULL CHECK(length(origin_commit) = 32),
        FOREIGN KEY(origin_commit) REFERENCES commits(id) DEFERRABLE INITIALLY DEFERRED
    ) STRICT, WITHOUT ROWID",
    ),
    (
        "dependencies",
        "CREATE TABLE dependencies (
        proof_id BLOB NOT NULL CHECK(length(proof_id) = 32),
        ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 65535),
        target BLOB NOT NULL CHECK(length(target) = 32),
        PRIMARY KEY(proof_id, ordinal),
        UNIQUE(proof_id, target),
        FOREIGN KEY(proof_id) REFERENCES proofs(id),
        FOREIGN KEY(target) REFERENCES proofs(id) DEFERRABLE INITIALLY DEFERRED
    ) STRICT, WITHOUT ROWID",
    ),
    (
        "members",
        "CREATE TABLE members (
        commit_id BLOB NOT NULL CHECK(length(commit_id) = 32),
        proof_id BLOB NOT NULL CHECK(length(proof_id) = 32),
        PRIMARY KEY(commit_id, proof_id),
        UNIQUE(proof_id),
        FOREIGN KEY(commit_id) REFERENCES commits(id),
        FOREIGN KEY(proof_id) REFERENCES proofs(id)
    ) STRICT, WITHOUT ROWID",
    ),
];

// Parent insertion resolves deferred foreign keys through their child keys.
// Without these indexes SQLite scans accepted records even for one new proof.
const INDEXES: [(&str, &str); 3] = [
    (
        "proofs_by_origin_commit",
        "CREATE INDEX proofs_by_origin_commit ON proofs(origin_commit)",
    ),
    (
        "commits_by_root",
        "CREATE INDEX commits_by_root ON commits(root)",
    ),
    (
        "dependencies_by_target",
        "CREATE INDEX dependencies_by_target ON dependencies(target)",
    ),
];

/// One connection, serialized by the enclosing Store mutex and directory lock.
/// Stored syntax and hashes never establish mathematical proof validity.
pub(super) struct Commit<'a> {
    pub expected: Summary,
    pub deadline: Option<Instant>,
    pub cut: Option<BatchCut>,
    pub next_root: Option<[u8; 32]>,
    pub guard: Option<&'a crate::graph::CommitGuard>,
}

pub(super) struct Catalog {
    connection: Connection,
    database_id: [u8; 32],
    validated_data_version: Cell<Option<i64>>,
}

impl Catalog {
    pub(super) fn open(path: &Path, database_id: [u8; 32]) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !regular_unaliased(&metadata) {
            return Err("proof catalog must be a regular file".into());
        }
        let connection = open_connection(path)?;
        verify_version(&connection)?;
        configure(&connection)?;
        verify_schema(&connection)?;
        read_meta(&connection, Some(database_id))?;
        Ok(Self {
            connection,
            database_id,
            validated_data_version: Cell::new(None),
        })
    }

    /// Resume only an unpublished initialization file with no initialized schema.
    /// The enclosing Store never invokes this on the final canonical database.
    pub(super) fn initialize_stage(path: &Path, database_id: [u8; 32]) -> Result<Self, String> {
        if !path.exists() {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|error| error.to_string())?;
        }
        let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !regular_unaliased(&metadata) {
            return Err("catalog initialization stage is not a regular file".into());
        }
        let connection = open_connection(path)?;
        let application: i64 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(sql_error)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(sql_error)?;
        let objects: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE sql IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        if application != 0 || version != 0 || objects != 0 {
            return Err("catalog initialization stage is not empty".into());
        }
        configure(&connection)?;
        initialize_schema(&connection, database_id)?;
        #[cfg(unix)]
        {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| error.to_string())?;
        }
        verify_schema(&connection)?;
        read_meta(&connection, Some(database_id))?;
        Ok(Self {
            connection,
            database_id,
            validated_data_version: Cell::new(None),
        })
    }

    /// Recovery may inspect an existing inactive catalog before the enclosing
    /// lineage receipt was written. This never creates or repairs a schema.
    pub(super) fn inspect_identity(path: &Path) -> Result<[u8; 32], String> {
        let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !regular_unaliased(&metadata) {
            return Err("proof catalog must be a regular file".into());
        }
        let connection = open_connection(path)?;
        verify_version(&connection)?;
        configure(&connection)?;
        verify_schema(&connection)?;
        Ok(read_meta(&connection, None)?.database_id)
    }

    pub(super) fn identity(&self) -> Result<[u8; 32], String> {
        Ok(self.meta()?.database_id)
    }

    pub(super) fn active(&self) -> Result<bool, String> {
        Ok(self.meta()?.active)
    }

    /// Validate the complete catalog with bounded owned records. This establishes
    /// storage integrity only; Graph still rechecks every proof mathematically.
    pub(super) fn summary(&self) -> Result<Summary, String> {
        let transaction = begin(&self.connection, TransactionBehavior::Deferred)?;
        let summary = validate_catalog(&transaction, self.database_id)?;
        let version = self.check_data_version(&transaction)?;
        transaction.commit().map_err(sql_error)?;
        self.validated_data_version.set(Some(version));
        Ok(summary)
    }

    pub(super) fn replay_page(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<(u64, BinaryProof)>, String> {
        page_limit(limit, crate::resources::limits().replay_page)?;
        let after_sql = i64::try_from(after).map_err(|_| "catalog replay cursor width")?;
        let transaction = begin(&self.connection, TransactionBehavior::Deferred)?;
        let meta = read_meta(&transaction, Some(self.database_id))?;
        self.require_validated_version(&transaction)?;
        let after_count = usize::try_from(after).map_err(|_| "catalog replay cursor width")?;
        if after_count > meta.count {
            return Err("catalog replay cursor exceeds corpus count".into());
        }
        let mut keys = Vec::with_capacity(limit);
        {
            let mut statement = transaction
                .prepare(
                    "SELECT replay_order, substr(id,1,33) FROM proofs
                 WHERE replay_order > ?1 ORDER BY replay_order LIMIT ?2",
                )
                .map_err(sql_error)?;
            let mut rows = statement
                .query(params![after_sql, sql_width(limit)?])
                .map_err(sql_error)?;
            while let Some(row) = rows.next().map_err(sql_error)? {
                let ordinal = replay_ordinal(row.get(0).map_err(sql_error)?)?;
                let expected = after
                    .checked_add(u64::try_from(keys.len()).map_err(|_| "catalog page width")?)
                    .and_then(|value| value.checked_add(1))
                    .ok_or("catalog replay ordinal overflow")?;
                if ordinal != expected {
                    return Err("catalog replay ordering is incomplete".into());
                }
                keys.push((ordinal, key(row.get(1).map_err(sql_error)?)?));
            }
        }
        if keys.len() != limit.min(meta.count - after_count) {
            return Err("catalog replay page count differs".into());
        }
        let mut objects = Vec::with_capacity(keys.len());
        for (ordinal, id) in keys {
            let record =
                read_record(&transaction, id)?.ok_or("catalog replay proof disappeared")?;
            if record.replay_order != ordinal {
                return Err("catalog replay proof order differs".into());
            }
            objects.push((ordinal, record.object));
        }
        transaction.commit().map_err(sql_error)?;
        Ok(objects)
    }

    pub(super) fn ids_page(
        &self,
        after: Option<ProofId>,
        limit: usize,
        expected: Summary,
    ) -> Result<Vec<ProofId>, String> {
        page_limit(limit, crate::resources::limits().id_page)?;
        let transaction = begin(&self.connection, TransactionBehavior::Deferred)?;
        check_expected_summary(&read_meta(&transaction, Some(self.database_id))?, expected)?;
        self.require_validated_version(&transaction)?;
        // Every stored key is a 32-byte BLOB; the empty BLOB sorts before all
        // of them, including the all-zero key. Keep the range seek unconditional.
        let cursor = after.map(|id| id.as_bytes().to_vec()).unwrap_or_default();
        let mut ids = Vec::with_capacity(limit);
        {
            let mut statement = transaction
                .prepare_cached(IDS_PAGE_QUERY)
                .map_err(sql_error)?;
            let mut rows = statement
                .query(params![cursor, sql_width(limit)?])
                .map_err(sql_error)?;
            let mut previous = after.map(|id| *id.as_bytes());
            while let Some(row) = rows.next().map_err(sql_error)? {
                let id = key(row.get(0).map_err(sql_error)?)?;
                if previous.is_some_and(|value| value >= id) {
                    return Err("catalog proof ID page ordering differs".into());
                }
                ids.push(ProofId::from_bytes(id));
                previous = Some(id);
            }
        }
        transaction.commit().map_err(sql_error)?;
        Ok(ids)
    }

    pub(super) fn get(
        &self,
        id: ProofId,
        expected: Summary,
    ) -> Result<Option<BinaryProof>, String> {
        let transaction = begin(&self.connection, TransactionBehavior::Deferred)?;
        check_expected_summary(&read_meta(&transaction, Some(self.database_id))?, expected)?;
        self.require_validated_version(&transaction)?;
        let record = read_record(&transaction, *id.as_bytes())?;
        transaction.commit().map_err(sql_error)?;
        Ok(record.map(|record| record.object))
    }

    pub(super) fn contains(&self, id: ProofId, expected: Summary) -> Result<bool, String> {
        // Preserve payload, digest, content-address and relation checks without
        // allocating hex or materializing a certificate for a membership query.
        self.get(id, expected).map(|object| object.is_some())
    }

    /// The enclosing Graph calls this only after complete mathematical replay.
    pub(super) fn activate(&self, root: [u8; 32]) -> Result<(), String> {
        let transaction = begin(&self.connection, TransactionBehavior::Immediate)?;
        let summary = validate_catalog(&transaction, self.database_id)?;
        let version = self.check_data_version(&transaction)?;
        if summary.root != root {
            return Err("replayed corpus root differs from catalog".into());
        }
        if !read_meta(&transaction, Some(self.database_id))?.active {
            transaction
                .execute(
                    "UPDATE meta SET state = 'active', corpus_root = ?1 WHERE singleton = 1",
                    params![root.as_slice()],
                )
                .map_err(sql_error)?;
        }
        transaction.commit().map_err(sql_error)?;
        self.validated_data_version.set(Some(version));
        Ok(())
    }

    pub(super) fn persist(
        &self,
        root: ProofId,
        objects: &[&BinaryProof],
        commit: Commit<'_>,
    ) -> Result<Summary, String> {
        let Commit {
            expected,
            deadline,
            cut,
            next_root,
            guard,
        } = commit;
        let prepared = prepare(objects.iter().copied())?;
        let root = *root.as_bytes();
        let commit = commit_digest(root, prepared.values().map(|object| &object.member))?;
        fail_at(cut, BatchCut::BeforeWrite)?;
        let transaction = begin(&self.connection, TransactionBehavior::Immediate)?;
        let meta = read_meta(&transaction, Some(self.database_id))?;
        check_expected_summary(&meta, expected)?;
        // BEGIN IMMEDIATE excludes another writer while this generation is
        // checked and advanced. Only this serialized connection may extend the
        // fully validated catalog; external changes require a fresh Graph replay.
        self.require_validated_version(&transaction)?;
        let inserted = insert_commit(&transaction, commit, root, &prepared, meta.count, cut)?;
        let summary = if inserted {
            verify_commit(&transaction, commit, root, &prepared)?;
            commit_summary(&transaction, expected, &prepared, next_root)?
        } else {
            expected
        };
        fail_at(cut, BatchCut::BeforeCommit)?;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            transaction.rollback().map_err(sql_error)?;
            return Err(COMMIT_DEADLINE_ERROR.into());
        }
        if let Some(guard) = guard
            && let Err(error) = guard.check()
        {
            transaction.rollback().map_err(sql_error)?;
            return Err(error);
        }
        transaction.commit().map_err(sql_error)?;
        // A failure here is ambiguous durability. The Graph must halt and a
        // restart must replay the complete committed transaction.
        fail_at(cut, BatchCut::AfterCommit)?;
        Ok(summary)
    }

    fn meta(&self) -> Result<Meta, String> {
        read_meta(&self.connection, Some(self.database_id))
    }

    fn check_data_version(&self, connection: &Connection) -> Result<i64, String> {
        let version: i64 = connection
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(sql_error)?;
        if self
            .validated_data_version
            .get()
            .is_some_and(|validated| validated != version)
        {
            return Err("proof catalog changed outside its owned connection".into());
        }
        Ok(version)
    }

    fn require_validated_version(&self, connection: &Connection) -> Result<(), String> {
        if self.validated_data_version.get().is_none() {
            return Err("proof catalog has not been validated".into());
        }
        self.check_data_version(connection).map(|_| ())
    }

    #[cfg(test)]
    pub(super) fn inventory_fullscan_steps(&self) -> i32 {
        self.connection
            .prepare_cached(IDS_PAGE_QUERY)
            .unwrap()
            .get_status(rusqlite::StatementStatus::FullscanStep)
    }

    #[cfg(test)]
    pub(super) fn set_max_page_count(&self, pages: u64) -> Result<(), String> {
        let pages = i64::try_from(pages).map_err(|_| "invalid test page limit")?;
        if pages <= 0 {
            return Err("invalid test page limit".into());
        }
        self.connection
            .pragma_update(None, "max_page_count", pages)
            .map_err(sql_error)?;
        let actual: i64 = self
            .connection
            .pragma_query_value(None, "max_page_count", |row| row.get(0))
            .map_err(sql_error)?;
        if actual != pages {
            return Err("test page limit cannot shrink below allocated catalog".into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn page_count(&self) -> Result<u64, String> {
        let pages: i64 = self
            .connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .map_err(sql_error)?;
        u64::try_from(pages).map_err(|_| "catalog page count width".into())
    }
}

fn initialize_schema(connection: &Connection, database_id: [u8; 32]) -> Result<(), String> {
    let transaction = begin(connection, TransactionBehavior::Immediate)?;
    for (_, sql) in TABLES.iter().chain(INDEXES.iter()) {
        transaction.execute_batch(sql).map_err(sql_error)?;
    }
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(sql_error)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(sql_error)?;
    transaction
        .execute(
            "INSERT INTO meta(singleton, database_id, state,
            corpus_root, corpus_count, payload_bytes) VALUES(1, ?1, 'initializing', NULL, 0, 0)",
            params![database_id.as_slice()],
        )
        .map_err(sql_error)?;
    transaction.commit().map_err(sql_error)?;
    Ok(())
}

struct Meta {
    database_id: [u8; 32],
    active: bool,
    corpus_root: Option<[u8; 32]>,
    count: usize,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Summary {
    pub(crate) root: [u8; 32],
    pub(crate) count: usize,
    pub(crate) bytes: usize,
}

#[derive(PartialEq, Eq)]
struct Member {
    id: [u8; 32],
    statement: [u8; 32],
    compatibility: [u8; 32],
    length: usize,
    digest: [u8; 32],
    dependencies: Vec<[u8; 32]>,
}

struct Prepared {
    member: Member,
    payload: Vec<u8>,
    input_order: usize,
}

struct Record {
    member: Member,
    origin: [u8; 32],
    replay_order: u64,
    object: BinaryProof,
}

fn prepare<'a>(
    objects: impl Iterator<Item = &'a BinaryProof>,
) -> Result<BTreeMap<[u8; 32], Prepared>, String> {
    let mut prepared = BTreeMap::new();
    let mut bytes = 0usize;
    for object in objects {
        if prepared.len() >= crate::resources::limits().batch_objects {
            return Err("catalog batch object count limit".into());
        }
        let candidate = object;
        let payload = candidate.bytes.to_vec();
        bytes = bytes
            .checked_add(payload.len())
            .ok_or("catalog batch byte overflow")?;
        if bytes > crate::resources::limits().batch_bytes {
            return Err("catalog batch byte capacity".into());
        }
        let id = *candidate.id.as_bytes();
        let member = Member {
            id,
            statement: *candidate.statement.as_bytes(),
            compatibility: crate::compatibility(),
            length: payload.len(),
            digest: Sha256::digest(&payload).into(),
            dependencies: candidate
                .dependencies
                .iter()
                .map(|id| *id.as_bytes())
                .collect(),
        };
        let input_order = prepared.len();
        if prepared
            .insert(
                id,
                Prepared {
                    member,
                    payload,
                    input_order,
                },
            )
            .is_some()
        {
            return Err("duplicate catalog batch proof ID".into());
        }
    }
    if prepared.is_empty() {
        return Err("empty catalog batch".into());
    }
    Ok(prepared)
}

fn regular_unaliased(metadata: &fs::Metadata) -> bool {
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return false;
        }
    }
    true
}

fn open_connection(path: &Path) -> Result<Connection, String> {
    // Resolve legitimate directory aliases (including macOS /var) without
    // resolving the catalog leaf; SQLite must still refuse a substituted leaf.
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let path = fs::canonicalize(parent)
        .map_err(|error| error.to_string())?
        .join(path.file_name().ok_or("proof catalog filename missing")?);
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(sql_error)?;
    connection
        .busy_timeout(crate::resources::limits().sqlite_busy_timeout)
        .map_err(sql_error)?;
    Ok(connection)
}

fn configure(connection: &Connection) -> Result<(), String> {
    connection
        .busy_timeout(crate::resources::limits().sqlite_busy_timeout)
        .map_err(sql_error)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = DELETE;
         PRAGMA synchronous = EXTRA;
         PRAGMA foreign_keys = ON;

         PRAGMA temp_store = FILE;
         PRAGMA mmap_size = 0;
         PRAGMA trusted_schema = OFF;",
        )
        .map_err(sql_error)?;
    connection
        .pragma_update(
            None,
            "cache_size",
            -(i64::try_from((crate::resources::limits().catalog_cache_bytes / 1024).max(1))
                .map_err(|_| "SQLite cache width")?),
        )
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "macos")]
    connection
        .pragma_update(None, "fullfsync", true)
        .map_err(sql_error)?;
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(sql_error)?;
    if journal != "delete" {
        return Err("catalog journal mode differs".into());
    }
    for (name, expected) in [
        ("synchronous", 3),
        ("foreign_keys", 1),
        ("cache_size", -8192),
        ("temp_store", 1),
        ("mmap_size", 0),
        ("busy_timeout", 100),
        ("trusted_schema", 0),
    ] {
        let actual: i64 = connection
            .pragma_query_value(None, name, |row| row.get(0))
            .map_err(sql_error)?;
        if actual != expected {
            return Err(format!("catalog pragma {name} differs"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let fullfsync: i64 = connection
            .pragma_query_value(None, "fullfsync", |row| row.get(0))
            .map_err(sql_error)?;
        if fullfsync != 1 {
            return Err("catalog fullfsync differs".into());
        }
    }
    Ok(())
}

fn verify_version(connection: &Connection) -> Result<(), String> {
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(sql_error)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(sql_error)?;
    if application != APPLICATION_ID || version != SCHEMA_VERSION {
        return Err("unsupported or uninitialized proof catalog".into());
    }
    Ok(())
}

fn verify_schema(connection: &Connection) -> Result<(), String> {
    verify_version(connection)?;
    let mut statement = connection
        .prepare(
            "SELECT substr(type,1,17), substr(name,1,65), substr(sql,1,8193)
         FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name",
        )
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut found = 0;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let kind: String = row.get(0).map_err(sql_error)?;
        let name: String = row.get(1).map_err(sql_error)?;
        let sql: String = row.get(2).map_err(sql_error)?;
        let expected = match kind.as_str() {
            "table" => TABLES.iter().find(|(table, _)| *table == name),
            "index" => INDEXES.iter().find(|(index, _)| *index == name),
            _ => None,
        }
        .ok_or("unexpected catalog schema object")?;
        if sql.len() > 8192 || normalize_sql(&sql) != normalize_sql(expected.1) {
            return Err("catalog schema differs from current version".into());
        }
        found += 1;
    }
    if found != TABLES.len() + INDEXES.len() {
        return Err("incomplete catalog schema".into());
    }
    let check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(sql_error)?;
    if check != "ok" {
        return Err(format!("catalog integrity failure: {check}"));
    }
    verify_foreign_keys(connection)
}

fn normalize_sql(sql: &str) -> String {
    let mut sql = sql.to_owned();
    // ALTER TABLE quotes only these exact known table identifiers. Do not
    // remove arbitrary quotes from expressions or relax supported constraints.
    for (name, _) in &TABLES {
        sql = sql.replace(&format!("TABLE \"{name}\""), &format!("TABLE {name}"));
        sql = sql.replace(
            &format!("REFERENCES \"{name}\""),
            &format!("REFERENCES {name}"),
        );
    }
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn read_meta(connection: &Connection, expected_id: Option<[u8; 32]>) -> Result<Meta, String> {
    if count(connection, "meta")? != 1 {
        return Err("catalog metadata row count differs".into());
    }
    let (id, state, root, count, bytes): (Vec<u8>, String, Option<Vec<u8>>, i64, i64) = connection
        .query_row(
            "SELECT substr(database_id,1,33), substr(state,1,13), substr(corpus_root,1,33), corpus_count, payload_bytes
             FROM meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(sql_error)?;
    let database_id = key(id)?;
    if expected_id.is_some_and(|expected| expected != database_id) {
        return Err("catalog database identity differs from lineage receipt".into());
    }
    let active = match state.as_str() {
        "initializing" => false,
        "active" => true,
        _ => return Err("catalog activation state differs".into()),
    };
    let corpus_root = root.map(key).transpose()?;
    if active != corpus_root.is_some() {
        return Err("catalog activation root missing or premature".into());
    }
    let count = usize::try_from(count).map_err(|_| "catalog count width")?;
    let bytes = usize::try_from(bytes).map_err(|_| "catalog byte width")?;
    if !active && (count != 0 || bytes != 0) {
        return Err("initializing catalog contains accepted data".into());
    }
    Ok(Meta {
        database_id,
        active,
        corpus_root,
        count,
        bytes,
    })
}

fn validate_catalog(connection: &Connection, database_id: [u8; 32]) -> Result<Summary, String> {
    verify_schema(connection)?;
    let meta = read_meta(connection, Some(database_id))?;
    let summary = verify_summary(connection, &meta)?;
    let mut statement = connection
        .prepare("SELECT substr(id,1,33), replay_order FROM proofs ORDER BY replay_order")
        .map_err(sql_error)?;
    let mut proof_order = connection
        .prepare("SELECT replay_order FROM proofs WHERE id = ?1")
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut observed = 0usize;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let id = key(row.get(0).map_err(sql_error)?)?;
        let ordinal = replay_ordinal(row.get(1).map_err(sql_error)?)?;
        observed = observed
            .checked_add(1)
            .ok_or("catalog replay count overflow")?;
        if ordinal != u64::try_from(observed).map_err(|_| "catalog replay count width")? {
            return Err("catalog replay ordering is incomplete".into());
        }
        let stored_ordinal: Option<i64> = proof_order
            .query_row(params![id.as_slice()], |row| row.get(0))
            .optional()
            .map_err(sql_error)?;
        let stored_ordinal = stored_ordinal.ok_or("missing catalog proof during validation")?;
        if replay_ordinal(stored_ordinal)? != ordinal {
            return Err("catalog replay proof order differs".into());
        }
    }
    if observed != summary.count {
        return Err("catalog payload count differs".into());
    }
    verify_commits(connection)?;
    Ok(summary)
}

fn check_expected_summary(meta: &Meta, expected: Summary) -> Result<(), String> {
    if !meta.active {
        return Err("canonical catalog is not active".into());
    }
    if meta.corpus_root != Some(expected.root)
        || meta.count != expected.count
        || meta.bytes != expected.bytes
    {
        return Err("canonical catalog differs from the committed graph summary".into());
    }
    Ok(())
}

fn read_record(connection: &Connection, id: [u8; 32]) -> Result<Option<Record>, String> {
    type Stored = (Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, i64);
    let stored: Option<Stored> = {
        let mut statement = connection
            .prepare_cached(
                "SELECT substr(statement,1,33), substr(compatibility,1,33), substr(payload,1,4194305),
                payload_length, substr(payload_digest,1,33), substr(origin_commit,1,33), replay_order
         FROM proofs WHERE id = ?1",
            )
            .map_err(sql_error)?;
        statement
            .query_row(params![id.as_slice()], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })
            .optional()
            .map_err(sql_error)?
    };
    let Some((statement, compatibility, payload, length, digest, origin, ordinal)) = stored else {
        return Ok(None);
    };
    let statement = key(statement)?;
    let compatibility = key(compatibility)?;
    let digest = key(digest)?;
    let origin = key(origin)?;
    let replay_order = replay_ordinal(ordinal)?;
    if payload.is_empty()
        || payload.len() > crate::resources::limits().proof_bytes
        || usize::try_from(length).ok() != Some(payload.len())
        || <[u8; 32]>::from(Sha256::digest(&payload)) != digest
    {
        return Err("catalog payload length or digest differs".into());
    }
    if compatibility != crate::compatibility()
        || crate::object::content_id(naome_proof::StatementId::from_bytes(statement), &payload)
            .as_bytes()
            != &id
    {
        return Err("catalog canonical proof identity differs".into());
    }
    let dependencies = read_dependencies(connection, id)?;
    let object = BinaryProof {
        id: ProofId::from_bytes(id),
        statement: naome_proof::StatementId::from_bytes(statement),
        bytes: payload.clone().into(),
        _memory: Some(crate::resources::MemoryLease::acquire(
            payload
                .len()
                .checked_mul(4)
                .ok_or("proof memory overflow")?,
        )?),
        dependencies: dependencies
            .iter()
            .copied()
            .map(ProofId::from_bytes)
            .collect(),
    };
    let member_origin: Option<Vec<u8>> = {
        let mut statement = connection
            .prepare_cached("SELECT substr(commit_id,1,33) FROM members WHERE proof_id = ?1")
            .map_err(sql_error)?;
        statement
            .query_row(params![id.as_slice()], |row| row.get(0))
            .optional()
            .map_err(sql_error)?
    };
    if member_origin.map(key).transpose()? != Some(origin) {
        return Err("catalog proof originating membership differs".into());
    }
    let exists: bool = {
        let mut statement = connection
            .prepare_cached("SELECT EXISTS(SELECT 1 FROM commits WHERE id = ?1)")
            .map_err(sql_error)?;
        statement
            .query_row(params![origin.as_slice()], |row| row.get(0))
            .map_err(sql_error)?
    };
    if !exists {
        return Err("catalog proof originating commit missing".into());
    }
    let unordered: bool = {
        let mut statement = connection
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM dependencies d LEFT JOIN proofs p ON p.id = d.target
         WHERE d.proof_id = ?1 AND (p.id IS NULL OR p.replay_order >= ?2))",
            )
            .map_err(sql_error)?;
        statement
            .query_row(params![id.as_slice(), ordinal], |row| row.get(0))
            .map_err(sql_error)?
    };
    if unordered {
        return Err("catalog dependency replay order differs".into());
    }
    Ok(Some(Record {
        member: Member {
            id,
            statement,
            compatibility,
            length: payload.len(),
            digest,
            dependencies,
        },
        origin,
        replay_order,
        object,
    }))
}

fn verify_summary(connection: &Connection, meta: &Meta) -> Result<Summary, String> {
    let summary = corpus_summary(connection)?;
    verify_summary_fields(connection, meta, summary)
}

fn verify_summary_fields(
    connection: &Connection,
    meta: &Meta,
    summary: Summary,
) -> Result<Summary, String> {
    if summary.count != meta.count
        || summary.bytes != meta.bytes
        || (meta.active && meta.corpus_root != Some(summary.root))
    {
        return Err("catalog corpus root, count or byte total differs".into());
    }
    if count(connection, "members")? != summary.count {
        return Err("catalog relation count differs".into());
    }
    let (first, last): (i64, i64) = connection
        .query_row(
            "SELECT coalesce(min(replay_order),0), coalesce(max(replay_order),0) FROM proofs",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql_error)?;
    let expected_first = if summary.count == 0 { 0 } else { 1 };
    if last != sql_width(summary.count)? || first != expected_first {
        return Err("catalog replay ordering is incomplete".into());
    }
    let incomplete: i64 = connection
        .query_row(
            "SELECT count(*) FROM commits c WHERE c.member_count !=
             (SELECT count(*) FROM members m WHERE m.commit_id = c.id)
         OR NOT EXISTS(SELECT 1 FROM members m WHERE m.commit_id = c.id AND m.proof_id = c.root)",
            [],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    let orphan_origin: i64 = connection
        .query_row(
            "SELECT count(*) FROM proofs p WHERE NOT EXISTS(
            SELECT 1 FROM members m WHERE m.commit_id = p.origin_commit AND m.proof_id = p.id)",
            [],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if incomplete != 0 || orphan_origin != 0 {
        return Err("incomplete catalog commit membership".into());
    }
    verify_foreign_keys(connection)?;
    let missing: i64 = connection.query_row(
        "SELECT count(*) FROM dependencies d LEFT JOIN proofs p ON p.id = d.target WHERE p.id IS NULL",
        [], |row| row.get(0),
    ).map_err(sql_error)?;
    if missing != 0 {
        return Err("catalog has missing proof dependencies".into());
    }
    let unordered: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM dependencies d JOIN proofs p ON p.id = d.proof_id
         JOIN proofs target ON target.id = d.target WHERE target.replay_order >= p.replay_order)",
            [],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if unordered {
        return Err("catalog dependency replay order differs".into());
    }
    Ok(summary)
}

fn corpus_summary(connection: &Connection) -> Result<Summary, String> {
    #[cfg(test)]
    SET_SCANS.with(|count| count.set(count.get() + 1));
    let (count, bytes, invalid): (i64, i64, i64) = connection
        .query_row(
            "SELECT count(*), coalesce(sum(payload_length), 0),
            coalesce(sum(CASE WHEN payload_length != length(payload)
                OR length(payload) NOT BETWEEN 1 AND 4194304 THEN 1 ELSE 0 END), 0) FROM proofs",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sql_error)?;
    let count = usize::try_from(count).map_err(|_| "catalog count width")?;
    let bytes = usize::try_from(bytes).map_err(|_| "catalog byte width")?;
    if invalid != 0 {
        return Err("catalog payload width differs".into());
    }
    let mut fingerprint = naome_checker::context::ProofSetFingerprint::default();
    let mut statement = connection
        .prepare("SELECT substr(id,1,33) FROM proofs ORDER BY id")
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        fingerprint
            .push(ProofId::from_bytes(key(row.get(0).map_err(sql_error)?)?))
            .map_err(|e| e.to_string())?;
    }
    let root = crate::corpus::root(count, fingerprint.finish())?;
    Ok(Summary { root, count, bytes })
}

fn commit_summary(
    connection: &Connection,
    preceding: Summary,
    objects: &BTreeMap<[u8; 32], Prepared>,
    next_root: Option<[u8; 32]>,
) -> Result<Summary, String> {
    let count = preceding
        .count
        .checked_add(objects.len())
        .ok_or("catalog count overflow")?;
    let bytes = objects
        .values()
        .try_fold(preceding.bytes, |total, object| {
            total
                .checked_add(object.member.length)
                .ok_or("catalog byte overflow")
        })?;
    let root = match next_root {
        Some(root) => root,
        // Envelope fixtures deliberately bypass mathematical checking. Only
        // tests may reconstruct a proposed set root from stored syntax.
        #[cfg(test)]
        None => corpus_summary(connection)?.root,
        #[cfg(not(test))]
        None => return Err("checked successor fingerprint missing".into()),
    };
    let summary = Summary { root, count, bytes };
    let changed = connection.execute(
        "UPDATE meta SET corpus_root = ?1, corpus_count = ?2, payload_bytes = ?3 WHERE singleton = 1",
        params![summary.root.as_slice(), sql_width(summary.count)?, sql_width(summary.bytes)?],
    ).map_err(sql_error)?;
    if changed != 1 {
        return Err("catalog metadata update count differs".into());
    }
    let meta = read_meta(connection, None)?;
    check_expected_summary(&meta, summary)?;
    Ok(summary)
}

fn insert_commit(
    connection: &Connection,
    commit: [u8; 32],
    root: [u8; 32],
    objects: &BTreeMap<[u8; 32], Prepared>,
    preceding_count: usize,
    cut: Option<BatchCut>,
) -> Result<bool, String> {
    let existing: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM commits WHERE id = ?1",
            params![commit.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_error)?;
    if existing.is_some() {
        verify_commit(connection, commit, root, objects)?;
        fail_at(cut, BatchCut::DuringWrite)?;
        return Ok(false);
    }
    if !objects.contains_key(&root) {
        return Err("catalog commit root missing from members".into());
    }
    connection
        .execute(
            "INSERT INTO commits(id, root, member_count) VALUES(?1, ?2, ?3)",
            params![
                commit.as_slice(),
                root.as_slice(),
                sql_width(objects.len())?
            ],
        )
        .map_err(sql_error)?;
    for object in objects.values() {
        let member = &object.member;
        if proof_exists(connection, member.id)? {
            return Err("concrete proof already belongs to another commit".into());
        } else {
            let replay_order = preceding_count
                .checked_add(object.input_order)
                .and_then(|value| value.checked_add(1))
                .ok_or("catalog replay ordinal overflow")?;
            connection.execute(
                "INSERT INTO proofs(id, statement, compatibility, payload, payload_length, payload_digest, origin_commit, replay_order)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![member.id.as_slice(), member.statement.as_slice(), member.compatibility.as_slice(),
                    object.payload.as_slice(), sql_width(member.length)?, member.digest.as_slice(), commit.as_slice(), sql_width(replay_order)?],
            ).map_err(sql_error)?;
            for (ordinal, dependency) in member.dependencies.iter().enumerate() {
                connection
                    .execute(
                        "INSERT INTO dependencies(proof_id, ordinal, target) VALUES(?1, ?2, ?3)",
                        params![
                            member.id.as_slice(),
                            sql_width(ordinal)?,
                            dependency.as_slice()
                        ],
                    )
                    .map_err(sql_error)?;
            }
        }
        connection
            .execute(
                "INSERT INTO members(commit_id, proof_id) VALUES(?1, ?2)",
                params![commit.as_slice(), member.id.as_slice()],
            )
            .map_err(sql_error)?;
        fail_at(cut, BatchCut::DuringWrite)?;
    }
    Ok(true)
}

fn verify_commit(
    connection: &Connection,
    commit: [u8; 32],
    root: [u8; 32],
    objects: &BTreeMap<[u8; 32], Prepared>,
) -> Result<(), String> {
    let (stored_root, stored_count): (Vec<u8>, i64) = connection
        .query_row(
            "SELECT substr(root,1,33), member_count FROM commits WHERE id = ?1",
            params![commit.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql_error)?;
    let members = read_members(connection, commit)?;
    if key(stored_root)? != root
        || usize::try_from(stored_count).ok() != Some(objects.len())
        || members != objects.keys().copied().collect::<Vec<_>>()
        || !objects.contains_key(&root)
    {
        return Err("existing catalog commit membership differs".into());
    }
    for object in objects.values() {
        verify_proof(connection, object, commit)?;
    }
    Ok(())
}

fn verify_proof(
    connection: &Connection,
    expected: &Prepared,
    commit: [u8; 32],
) -> Result<(), String> {
    let record =
        read_record(connection, expected.member.id)?.ok_or("catalog commit proof missing")?;
    if record.member != expected.member
        || record.object.bytes.as_ref() != expected.payload.as_slice()
        || record.origin != commit
    {
        return Err("immutable catalog proof collision or corruption".into());
    }
    Ok(())
}

fn read_dependencies(connection: &Connection, id: [u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    let mut statement = connection
        .prepare_cached("SELECT ordinal, substr(target,1,33) FROM dependencies WHERE proof_id = ?1 ORDER BY ordinal")
        .map_err(sql_error)?;
    let mut rows = statement.query(params![id.as_slice()]).map_err(sql_error)?;
    let mut dependencies = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        let ordinal: i64 = row.get(0).map_err(sql_error)?;
        let target = key(row.get(1).map_err(sql_error)?)?;
        if dependencies.len() >= crate::resources::limits().proof_dependencies
            || usize::try_from(ordinal).ok() != Some(dependencies.len())
            || dependencies
                .last()
                .is_some_and(|previous| *previous >= target)
        {
            return Err("catalog dependency ordering or width differs".into());
        }
        dependencies.push(target);
    }
    Ok(dependencies)
}

fn read_members(connection: &Connection, commit: [u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    let mut statement = connection
        .prepare_cached(
            "SELECT substr(proof_id,1,33) FROM members WHERE commit_id = ?1 ORDER BY proof_id",
        )
        .map_err(sql_error)?;
    let mut rows = statement
        .query(params![commit.as_slice()])
        .map_err(sql_error)?;
    let mut members = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        let id = key(row.get(0).map_err(sql_error)?)?;
        if members.len() >= crate::resources::limits().batch_objects
            || members.last().is_some_and(|previous| *previous >= id)
        {
            return Err("catalog membership ordering or count differs".into());
        }
        members.push(id);
    }
    Ok(members)
}

fn verify_commits(connection: &Connection) -> Result<(), String> {
    let mut statement = connection
        .prepare("SELECT substr(id,1,33), substr(root,1,33), member_count FROM commits ORDER BY id")
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let id = key(row.get(0).map_err(sql_error)?)?;
        let root = key(row.get(1).map_err(sql_error)?)?;
        let count: i64 = row.get(2).map_err(sql_error)?;
        let members = read_members(connection, id)?;
        if usize::try_from(count).ok() != Some(members.len()) || !members.contains(&root) {
            return Err("catalog commit root or member count differs".into());
        }
        let mut bound = Vec::with_capacity(members.len());
        for member in members {
            let record = read_record(connection, member)?.ok_or("missing catalog commit proof")?;
            record.object.clone().prepare()?;
            if record.origin != id {
                return Err("catalog proof belongs to a different originating commit".into());
            }
            bound.push(record.member);
        }
        if commit_digest(root, bound.iter())? != id {
            return Err("catalog commit digest differs".into());
        }
    }
    Ok(())
}

fn commit_digest<'a>(
    root: [u8; 32],
    members: impl Iterator<Item = &'a Member>,
) -> Result<[u8; 32], String> {
    let members: Vec<_> = members.collect();
    if members.is_empty()
        || members.len() > crate::resources::limits().batch_objects
        || !members.iter().any(|member| member.id == root)
    {
        return Err("invalid catalog commit membership".into());
    }
    let mut hash = Sha256::new();
    hash.update(b"naome:knowledge:catalog-commit:v1\0");
    hash.update(root);
    hash.update(
        u32::try_from(members.len())
            .map_err(|_| "catalog commit count width")?
            .to_be_bytes(),
    );
    let mut previous = None;
    let mut bytes = 0usize;
    for member in members {
        if previous.is_some_and(|id| id >= member.id) {
            return Err("catalog commit members are not uniquely sorted".into());
        }
        hash.update(member.id);
        hash.update(member.statement);
        hash.update(member.compatibility);
        if member.length == 0
            || member.length > crate::resources::limits().proof_bytes
            || member.dependencies.len() > crate::resources::limits().proof_dependencies
        {
            return Err("catalog commit member width differs".into());
        }
        bytes = bytes
            .checked_add(member.length)
            .ok_or("catalog batch byte overflow")?;
        if bytes > crate::resources::limits().batch_bytes {
            return Err("catalog batch byte capacity".into());
        }
        hash.update(
            u32::try_from(member.length)
                .map_err(|_| "catalog payload width")?
                .to_be_bytes(),
        );
        hash.update(member.digest);
        hash.update(
            u32::try_from(member.dependencies.len())
                .map_err(|_| "catalog dependency width")?
                .to_be_bytes(),
        );
        for dependency in &member.dependencies {
            hash.update(dependency);
        }
        previous = Some(member.id);
    }
    Ok(hash.finalize().into())
}

fn verify_foreign_keys(connection: &Connection) -> Result<(), String> {
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(sql_error)?;
    if statement
        .query([])
        .map_err(sql_error)?
        .next()
        .map_err(sql_error)?
        .is_some()
    {
        return Err("catalog foreign-key relation differs".into());
    }
    Ok(())
}

fn proof_exists(connection: &Connection, id: [u8; 32]) -> Result<bool, String> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM proofs WHERE id = ?1)",
            params![id.as_slice()],
            |row| row.get(0),
        )
        .map_err(sql_error)
}

fn count(connection: &Connection, table: &str) -> Result<usize, String> {
    // Every caller supplies one of this module's fixed schema table names.
    let count: i64 = connection
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map_err(sql_error)?;
    usize::try_from(count).map_err(|_| "catalog relation count width".into())
}

fn begin(
    connection: &Connection,
    behavior: TransactionBehavior,
) -> Result<Transaction<'_>, String> {
    Transaction::new_unchecked(connection, behavior).map_err(sql_error)
}

fn key(bytes: Vec<u8>) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "catalog identity width".into())
}

fn replay_ordinal(value: i64) -> Result<u64, String> {
    let ordinal = u64::try_from(value).map_err(|_| "catalog replay ordinal width")?;
    if ordinal == 0 {
        return Err("catalog replay ordinal must be positive".into());
    }
    Ok(ordinal)
}

fn sql_width(value: usize) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| "catalog integer width".into())
}

fn page_limit(limit: usize, maximum: usize) -> Result<(), String> {
    if limit == 0 || limit > maximum {
        return Err("catalog page limit outside supported bounds".into());
    }
    Ok(())
}

fn fail_at(cut: Option<BatchCut>, position: BatchCut) -> Result<(), String> {
    #[cfg(test)]
    if cut == Some(position) {
        return Err("injected batch persistence cut".into());
    }
    let _ = (cut, position);
    Ok(())
}

fn sql_error(error: rusqlite::Error) -> String {
    format!("proof catalog: {error}")
}
