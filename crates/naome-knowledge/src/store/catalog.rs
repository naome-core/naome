use super::BatchCut;
use crate::{Envelope, MAX_ACCEPTED_BYTES, MAX_DEPENDENCIES, MAX_OBJECTS, MAX_PROOF_BYTES};
use naome_proof::ProofId;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, time::Duration};

const APPLICATION_ID: i64 = 0x4e414f31;
const SCHEMA_VERSION: i64 = 1;

// Every proof has one originating commit membership. Keep bounded metadata work
// until the separately qualified streaming stage.
const MAX_MEMBERS: usize = MAX_OBJECTS;

const TABLES: [(&str, &str); 5] = [
    (
        "meta",
        "CREATE TABLE meta (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        database_id BLOB NOT NULL CHECK(length(database_id) = 32),
        state TEXT NOT NULL CHECK(state IN ('initializing', 'active')),
        corpus_root BLOB,
        corpus_count INTEGER NOT NULL CHECK(corpus_count BETWEEN 0 AND 4096),
        payload_bytes INTEGER NOT NULL CHECK(payload_bytes BETWEEN 0 AND 67108864),
        CHECK((state = 'initializing' AND corpus_root IS NULL AND corpus_count = 0 AND payload_bytes = 0) OR
              (state = 'active' AND corpus_root IS NOT NULL AND length(corpus_root) = 32))
    ) STRICT",
    ),
    (
        "commits",
        "CREATE TABLE commits (
        id BLOB PRIMARY KEY CHECK(length(id) = 32),
        root BLOB NOT NULL CHECK(length(root) = 32),
        member_count INTEGER NOT NULL CHECK(member_count BETWEEN 1 AND 4096),
        FOREIGN KEY(root) REFERENCES proofs(id) DEFERRABLE INITIALLY DEFERRED
    ) STRICT, WITHOUT ROWID",
    ),
    (
        "proofs",
        "CREATE TABLE proofs (
        id BLOB PRIMARY KEY CHECK(length(id) = 32),
        statement BLOB NOT NULL CHECK(length(statement) = 32),
        compatibility BLOB NOT NULL CHECK(length(compatibility) = 32),
        payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 65536),
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
        ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 31),
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

/// One connection, serialized by the enclosing Store mutex and directory lock.
/// Stored syntax and hashes never establish mathematical proof validity.
pub(super) struct Catalog {
    connection: Connection,
    database_id: [u8; 32],
}

impl Catalog {
    pub(super) fn open(path: &Path, database_id: [u8; 32]) -> Result<Self, String> {
        let new = match fs::symlink_metadata(path) {
            Ok(metadata) if regular_unaliased(&metadata) => false,
            Ok(_) => return Err("proof catalog must be a regular file".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|error| error.to_string())?;
                true
            }
            Err(error) => return Err(error.to_string()),
        };
        let connection = open_connection(path)?;
        if !new {
            verify_version(&connection)?;
        }
        configure(&connection)?;
        if new {
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
        }
        verify_schema(&connection)?;
        read_meta(&connection, Some(database_id))?;
        Ok(Self {
            connection,
            database_id,
        })
    }

    /// Resume only an unpublished initialization file with no initialized schema.
    /// The enclosing Store never invokes this on the final canonical database.
    pub(super) fn initialize_stage(path: &Path, database_id: [u8; 32]) -> Result<Self, String> {
        if !path.exists() {
            return Self::open(path, database_id);
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
                "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
                [],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        if application != 0 || version != 0 || objects != 0 {
            return Err("catalog initialization stage is not empty".into());
        }
        configure(&connection)?;
        initialize_schema(&connection, database_id)?;
        verify_schema(&connection)?;
        read_meta(&connection, Some(database_id))?;
        Ok(Self {
            connection,
            database_id,
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

    /// Revalidate every canonical record before full mathematical Graph replay.
    pub(super) fn load(&self) -> Result<Vec<Envelope>, String> {
        let transaction = begin(&self.connection, TransactionBehavior::Deferred)?;
        let (objects, _) = read_catalog(&transaction, self.database_id)?;
        transaction.commit().map_err(sql_error)?;
        Ok(objects)
    }

    /// The enclosing Graph calls this only after complete mathematical replay.
    pub(super) fn activate(&self, root: [u8; 32]) -> Result<(), String> {
        let transaction = begin(&self.connection, TransactionBehavior::Immediate)?;
        let (_, actual_root) = read_catalog(&transaction, self.database_id)?;
        if actual_root != root {
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
        transaction.commit().map_err(sql_error)
    }

    pub(super) fn persist(
        &self,
        root: ProofId,
        objects: &[&Envelope],
        cut: Option<BatchCut>,
    ) -> Result<(), String> {
        let prepared = prepare(objects.iter().copied())?;
        let root = *root.as_bytes();
        let commit = commit_digest(root, prepared.values().map(|object| &object.member))?;
        fail_at(cut, BatchCut::BeforeWrite)?;
        let transaction = begin(&self.connection, TransactionBehavior::Immediate)?;
        let meta = read_meta(&transaction, Some(self.database_id))?;
        if !meta.active {
            return Err("cannot persist accepted data in an initializing catalog".into());
        }
        verify_summary(&transaction, &meta)?;
        insert_commit(&transaction, commit, root, &prepared, cut)?;
        update_summary(&transaction)?;
        fail_at(cut, BatchCut::BeforeCommit)?;
        transaction.commit().map_err(sql_error)?;
        // A failure here is ambiguous durability. The Graph must halt and a
        // restart must replay the complete committed transaction.
        fail_at(cut, BatchCut::AfterCommit)
    }

    fn meta(&self) -> Result<Meta, String> {
        read_meta(&self.connection, Some(self.database_id))
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
    for (_, sql) in TABLES {
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

struct Summary {
    root: [u8; 32],
    count: usize,
    bytes: usize,
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
}

fn prepare<'a>(
    objects: impl Iterator<Item = &'a Envelope>,
) -> Result<BTreeMap<[u8; 32], Prepared>, String> {
    let mut prepared = BTreeMap::new();
    let mut bytes = 0usize;
    for object in objects {
        if prepared.len() >= MAX_OBJECTS {
            return Err("catalog batch object count limit".into());
        }
        let candidate = object.clone().prepare()?;
        let payload = candidate.normal.canonical_bytes().to_vec();
        bytes = bytes
            .checked_add(payload.len())
            .ok_or("catalog batch byte overflow")?;
        if bytes > MAX_ACCEPTED_BYTES {
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
        if prepared.insert(id, Prepared { member, payload }).is_some() {
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
        .busy_timeout(Duration::from_millis(100))
        .map_err(sql_error)?;
    Ok(connection)
}

fn configure(connection: &Connection) -> Result<(), String> {
    connection
        .busy_timeout(Duration::from_millis(100))
        .map_err(sql_error)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = DELETE;
         PRAGMA synchronous = EXTRA;
         PRAGMA foreign_keys = ON;
         PRAGMA cache_size = -8192;
         PRAGMA temp_store = FILE;
         PRAGMA mmap_size = 0;
         PRAGMA trusted_schema = OFF;",
        )
        .map_err(sql_error)?;
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
    let mut statement = connection.prepare(
        "SELECT type, name, sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name",
    ).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut found = 0;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let kind: String = row.get(0).map_err(sql_error)?;
        let name: String = row.get(1).map_err(sql_error)?;
        let sql: String = row.get(2).map_err(sql_error)?;
        let expected = TABLES
            .iter()
            .find(|(table, _)| *table == name)
            .ok_or("unexpected catalog schema object")?;
        if kind != "table" || normalize_sql(&sql) != normalize_sql(expected.1) {
            return Err("catalog schema differs from version 1".into());
        }
        found += 1;
    }
    if found != TABLES.len() {
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
    sql.trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_meta(connection: &Connection, expected_id: Option<[u8; 32]>) -> Result<Meta, String> {
    if count(connection, "meta")? != 1 {
        return Err("catalog metadata row count differs".into());
    }
    let (id, state, root, count, bytes): (Vec<u8>, String, Option<Vec<u8>>, i64, i64) = connection
        .query_row(
            "SELECT database_id, state, corpus_root, corpus_count, payload_bytes
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
    if count > MAX_OBJECTS || bytes > MAX_ACCEPTED_BYTES {
        return Err("catalog capacity".into());
    }
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

fn read_catalog(
    connection: &Connection,
    database_id: [u8; 32],
) -> Result<(Vec<Envelope>, [u8; 32]), String> {
    verify_schema(connection)?;
    let meta = read_meta(connection, Some(database_id))?;
    let summary = verify_summary(connection, &meta)?;
    let mut records = BTreeMap::new();
    let mut objects = Vec::with_capacity(summary.count);
    let mut statement = connection.prepare(
        "SELECT id, statement, compatibility, substr(payload,1,65537), payload_length, payload_digest, origin_commit
         FROM proofs ORDER BY id",
    ).map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let id = key(row.get(0).map_err(sql_error)?)?;
        let claimed_statement = key(row.get(1).map_err(sql_error)?)?;
        let compatibility = key(row.get(2).map_err(sql_error)?)?;
        let payload: Vec<u8> = row.get(3).map_err(sql_error)?;
        let length: i64 = row.get(4).map_err(sql_error)?;
        let digest = key(row.get(5).map_err(sql_error)?)?;
        let origin = key(row.get(6).map_err(sql_error)?)?;
        if payload.len() > MAX_PROOF_BYTES
            || usize::try_from(length).ok() != Some(payload.len())
            || <[u8; 32]>::from(Sha256::digest(&payload)) != digest
        {
            return Err("catalog payload length or digest differs".into());
        }
        let envelope = Envelope {
            compatibility: crate::hex(&compatibility),
            proof_id: crate::hex(&id),
            statement_id: crate::hex(&claimed_statement),
            proof: crate::hex(&payload),
        };
        let candidate = envelope.prepare()?;
        let dependencies = read_dependencies(connection, id)?;
        let expected: Vec<_> = candidate
            .dependencies
            .iter()
            .map(|id| *id.as_bytes())
            .collect();
        if dependencies != expected {
            return Err("catalog dependency metadata differs from canonical proof".into());
        }
        let member = Member {
            id,
            statement: claimed_statement,
            compatibility,
            length: payload.len(),
            digest,
            dependencies,
        };
        if records.insert(id, (member, origin)).is_some() {
            return Err("duplicate catalog proof identity".into());
        }
        objects.push(candidate.envelope);
    }
    verify_commits(connection, &records)?;
    if objects.len() != summary.count {
        return Err("catalog payload count differs".into());
    }
    Ok((objects, summary.root))
}

fn verify_summary(connection: &Connection, meta: &Meta) -> Result<Summary, String> {
    let summary = corpus_summary(connection)?;
    if summary.count != meta.count
        || summary.bytes != meta.bytes
        || (meta.active && meta.corpus_root != Some(summary.root))
    {
        return Err("catalog corpus root, count or byte total differs".into());
    }
    if count(connection, "commits")? > MAX_OBJECTS {
        return Err("catalog history count limit".into());
    }
    if count(connection, "members")? > MAX_MEMBERS
        || count(connection, "dependencies")? > MAX_OBJECTS * MAX_DEPENDENCIES
    {
        return Err("catalog relation count limit".into());
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
    Ok(summary)
}

fn corpus_summary(connection: &Connection) -> Result<Summary, String> {
    let (count, bytes, invalid): (i64, i64, i64) = connection
        .query_row(
            "SELECT count(*), coalesce(sum(payload_length), 0),
            coalesce(sum(CASE WHEN payload_length != length(payload)
                OR length(payload) NOT BETWEEN 1 AND 65536 THEN 1 ELSE 0 END), 0) FROM proofs",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sql_error)?;
    let count = usize::try_from(count).map_err(|_| "catalog count width")?;
    let bytes = usize::try_from(bytes).map_err(|_| "catalog byte width")?;
    if count > MAX_OBJECTS || bytes > MAX_ACCEPTED_BYTES || invalid != 0 {
        return Err("catalog proof count, byte capacity or payload width".into());
    }
    let mut hash = Sha256::new();
    hash.update(b"naome:knowledge:set:v1\0");
    hash.update(crate::compatibility());
    hash.update((count as u32).to_be_bytes());
    let mut statement = connection
        .prepare("SELECT id FROM proofs ORDER BY id")
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut observed = 0;
    while let Some(row) = rows.next().map_err(sql_error)? {
        hash.update(key(row.get(0).map_err(sql_error)?)?);
        observed += 1;
    }
    if observed != count {
        return Err("catalog root traversal count differs".into());
    }
    Ok(Summary {
        root: hash.finalize().into(),
        count,
        bytes,
    })
}

fn update_summary(connection: &Connection) -> Result<(), String> {
    let summary = corpus_summary(connection)?;
    connection.execute(
        "UPDATE meta SET corpus_root = ?1, corpus_count = ?2, payload_bytes = ?3 WHERE singleton = 1",
        params![summary.root.as_slice(), summary.count as i64, summary.bytes as i64],
    ).map_err(sql_error)?;
    let meta = read_meta(connection, None)?;
    verify_summary(connection, &meta).map(|_| ())
}

fn insert_commit(
    connection: &Connection,
    commit: [u8; 32],
    root: [u8; 32],
    objects: &BTreeMap<[u8; 32], Prepared>,
    cut: Option<BatchCut>,
) -> Result<(), String> {
    let existing: Option<Vec<u8>> = connection
        .query_row(
            "SELECT id FROM commits WHERE id = ?1",
            params![commit.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_error)?;
    if existing.is_some() {
        verify_commit(connection, commit, root, objects)?;
        fail_at(cut, BatchCut::DuringWrite)?;
        return Ok(());
    }
    if !objects.contains_key(&root) {
        return Err("catalog commit root missing from members".into());
    }
    connection
        .execute(
            "INSERT INTO commits(id, root, member_count) VALUES(?1, ?2, ?3)",
            params![commit.as_slice(), root.as_slice(), objects.len() as i64],
        )
        .map_err(sql_error)?;
    for object in objects.values() {
        let member = &object.member;
        if proof_exists(connection, member.id)? {
            return Err("concrete proof already belongs to another commit".into());
        } else {
            connection.execute(
                "INSERT INTO proofs(id, statement, compatibility, payload, payload_length, payload_digest, origin_commit)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![member.id.as_slice(), member.statement.as_slice(), member.compatibility.as_slice(),
                    object.payload.as_slice(), member.length as i64, member.digest.as_slice(), commit.as_slice()],
            ).map_err(sql_error)?;
            for (ordinal, dependency) in member.dependencies.iter().enumerate() {
                connection
                    .execute(
                        "INSERT INTO dependencies(proof_id, ordinal, target) VALUES(?1, ?2, ?3)",
                        params![member.id.as_slice(), ordinal as i64, dependency.as_slice()],
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
    Ok(())
}

fn verify_commit(
    connection: &Connection,
    commit: [u8; 32],
    root: [u8; 32],
    objects: &BTreeMap<[u8; 32], Prepared>,
) -> Result<(), String> {
    let (stored_root, stored_count): (Vec<u8>, i64) = connection
        .query_row(
            "SELECT root, member_count FROM commits WHERE id = ?1",
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
        verify_proof(connection, object)?;
    }
    Ok(())
}

fn verify_proof(connection: &Connection, expected: &Prepared) -> Result<(), String> {
    let member = &expected.member;
    let (statement, compatibility, payload, length, digest): (Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>) =
        connection.query_row(
            "SELECT statement, compatibility,
                CASE WHEN length(payload) <= 65536 THEN payload ELSE NULL END, payload_length, payload_digest
             FROM proofs WHERE id = ?1", params![member.id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).map_err(sql_error)?;
    if key(statement)? != member.statement
        || key(compatibility)? != member.compatibility
        || payload != expected.payload
        || usize::try_from(length).ok() != Some(member.length)
        || key(digest)? != member.digest
        || read_dependencies(connection, member.id)? != member.dependencies
    {
        return Err("immutable catalog proof collision or corruption".into());
    }
    Ok(())
}

fn read_dependencies(connection: &Connection, id: [u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    let mut statement = connection
        .prepare("SELECT ordinal, target FROM dependencies WHERE proof_id = ?1 ORDER BY ordinal")
        .map_err(sql_error)?;
    let mut rows = statement.query(params![id.as_slice()]).map_err(sql_error)?;
    let mut dependencies = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        let ordinal: i64 = row.get(0).map_err(sql_error)?;
        let target = key(row.get(1).map_err(sql_error)?)?;
        if dependencies.len() >= MAX_DEPENDENCIES
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
        .prepare("SELECT proof_id FROM members WHERE commit_id = ?1 ORDER BY proof_id")
        .map_err(sql_error)?;
    let mut rows = statement
        .query(params![commit.as_slice()])
        .map_err(sql_error)?;
    let mut members = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        let id = key(row.get(0).map_err(sql_error)?)?;
        if members.len() >= MAX_OBJECTS || members.last().is_some_and(|previous| *previous >= id) {
            return Err("catalog membership ordering or count differs".into());
        }
        members.push(id);
    }
    Ok(members)
}

fn verify_commits(
    connection: &Connection,
    records: &BTreeMap<[u8; 32], (Member, [u8; 32])>,
) -> Result<(), String> {
    let mut statement = connection
        .prepare("SELECT id, root, member_count FROM commits ORDER BY id")
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
            let (record, origin) = records.get(&member).ok_or("missing catalog commit proof")?;
            if *origin != id {
                return Err("catalog proof belongs to a different originating commit".into());
            }
            bound.push(record);
        }
        if commit_digest(root, bound.into_iter())? != id {
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
        || members.len() > MAX_OBJECTS
        || !members.iter().any(|member| member.id == root)
    {
        return Err("invalid catalog commit membership".into());
    }
    let mut hash = Sha256::new();
    hash.update(b"naome:knowledge:catalog-commit:v1\0");
    hash.update(root);
    hash.update((members.len() as u32).to_be_bytes());
    let mut previous = None;
    for member in members {
        if previous.is_some_and(|id| id >= member.id) {
            return Err("catalog commit members are not uniquely sorted".into());
        }
        hash.update(member.id);
        hash.update(member.statement);
        hash.update(member.compatibility);
        hash.update((member.length as u32).to_be_bytes());
        hash.update(member.digest);
        hash.update((member.dependencies.len() as u32).to_be_bytes());
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
