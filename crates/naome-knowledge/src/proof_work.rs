//! Durable incremental proof processing. Inputs, formula nodes and completed
//! transformation equations survive crashes. A fresh owner rechecks equations
//! and the proof prefix; persisted `proved` bits never grant mathematical trust.
use crate::resources::adaptive::{Budget, Snapshot};
use naome_checker::program::{self as checker, Value};
use naome_foundation::{
    Formula,
    construction::Expression,
    graph::{Node, Properties, Transform, Variable},
};
use naome_proof::program::{Command, RECORD_BYTES};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const APPLICATION_ID: i64 = 0x4e415057;
pub(crate) mod cli;
fn sql<T>(value: rusqlite::Result<T>) -> Result<T, String> {
    value.map_err(|e| e.to_string())
}
fn number(n: u64) -> Result<i64, String> {
    i64::try_from(n).map_err(|_| "physical storage address exhausted".into())
}
fn unsigned(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(e),
        )
    })
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn command_hash(previous: [u8; 32], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(naome_proof::program::FORMAT);
    hash.update(previous);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub format: &'static str,
    pub commands: u64,
    pub committed_commands: u64,
    pub checked_commands: u64,
    pub formula_nodes: u64,
    pub transformation_equations: u64,
    pub sealed: bool,
    pub fully_checked: bool,
    pub program_hash: String,
    pub conclusion: Option<String>,
    pub database_bytes: u64,
    pub budget: Option<Snapshot>,
}

pub struct Work {
    connection: Connection,
    path: PathBuf,
    _lock: File,
    identity: (u64, u64),
    data_version: i64,
    cursor: u64,
    checked_hash: [u8; 32],
    active: Option<Evaluation>,
    accepted: Option<u64>,
    last_budget: Option<Snapshot>,
    last_recorded_budget: Option<Snapshot>,
    cache_budget: u64,
}
struct Evaluation {
    operations: Vec<Operation>,
    registers: Vec<u64>,
    position: usize,
    proved: bool,
    seal: bool,
    source_hash: [u8; 32],
    restore_sequence: i64,
    restoring: bool,
}
enum Operation {
    Input(u64),
    Equal(u32, u32),
    Member(u32, u32),
    Not(usize),
    Implies(usize, usize),
    Bind(usize, u32),
    Vacuous(usize),
    Substitute(usize, u32, u32),
    AssertEqual(usize, u64),
}
fn compile(expression: Expression<u64>, operations: &mut Vec<Operation>) -> usize {
    let operation = match expression {
        Expression::Input(f) => Operation::Input(f),
        Expression::Equal(a, b) => Operation::Equal(a.identifier(), b.identifier()),
        Expression::Member(a, b) => Operation::Member(a.identifier(), b.identifier()),
        Expression::Not(a) => Operation::Not(compile(*a, operations)),
        Expression::Implies(a, b) => {
            Operation::Implies(compile(*a, operations), compile(*b, operations))
        }
        Expression::ForAll(v, a) => Operation::Bind(compile(*a, operations), v.identifier()),
        Expression::Vacuous(a) => Operation::Vacuous(compile(*a, operations)),
        Expression::Substitute(a, b, f) => {
            Operation::Substitute(compile(*f, operations), a.identifier(), b.identifier())
        }
    };
    let result = operations.len();
    operations.push(operation);
    result
}

impl Work {
    pub fn open(path: &Path) -> Result<Self, String> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let path = fs::canonicalize(parent)
            .map_err(|e| e.to_string())?
            .join(path.file_name().ok_or("proof work filename missing")?);
        let lock_path = path.with_extension("proof-work.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(&lock_path)
            .map_err(|e| e.to_string())?;
        crate::storage::owned_file(&lock_path)?;
        lock.try_lock().map_err(|_| "proof work is already owned")?;
        if !path.exists() {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(&path)
                .map_err(|e| e.to_string())?;
        }
        let metadata = crate::storage::owned_file(&path)?;
        let connection = sql(Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ))?;
        let app: i64 = sql(connection.pragma_query_value(None, "application_id", |r| r.get(0)))?;
        if app == 0 {
            let tables: i64 =
                sql(connection.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0)))?;
            if tables != 0 {
                return Err("unknown proof work database".into());
            }
            sql(connection.execute_batch("BEGIN IMMEDIATE;
                CREATE TABLE state(id INTEGER PRIMARY KEY CHECK(id=1), commands INTEGER NOT NULL, committed INTEGER NOT NULL, sealed INTEGER NOT NULL, hash BLOB NOT NULL CHECK(length(hash)=32)) STRICT;
                INSERT INTO state VALUES(1,0,0,0,zeroblob(32));
                CREATE TABLE input(position INTEGER PRIMARY KEY, command BLOB NOT NULL CHECK(length(command)<=4096), hash BLOB NOT NULL CHECK(length(hash)=32)) STRICT;
                CREATE TABLE result(position INTEGER PRIMARY KEY, node INTEGER NOT NULL, proved INTEGER NOT NULL CHECK(proved IN (0,1))) STRICT;
                CREATE TABLE node(id INTEGER PRIMARY KEY, hash BLOB NOT NULL UNIQUE CHECK(length(hash)=32), tag INTEGER NOT NULL, a INTEGER NOT NULL, b INTEGER NOT NULL, ak INTEGER NOT NULL, bk INTEGER NOT NULL, free INTEGER NOT NULL, required INTEGER NOT NULL) STRICT;
                CREATE TABLE equation(sequence INTEGER PRIMARY KEY, position INTEGER NOT NULL, operation INTEGER NOT NULL, source INTEGER NOT NULL, depth INTEGER NOT NULL, result INTEGER NOT NULL, UNIQUE(position,operation,source,depth)) STRICT;
                CREATE INDEX equation_order ON equation(position,operation,sequence);
                CREATE TABLE budget(sequence INTEGER PRIMARY KEY, snapshot BLOB NOT NULL CHECK(length(snapshot)<=4096), command INTEGER NOT NULL, equation INTEGER NOT NULL) STRICT;
                PRAGMA application_id=1312903255; PRAGMA user_version=1; COMMIT;"))?;
        } else if app != APPLICATION_ID {
            return Err("proof work format mismatch".into());
        }
        let version: i64 = sql(connection.pragma_query_value(None, "user_version", |r| r.get(0)))?;
        if version != 1 {
            return Err("unsupported proof work version".into());
        }
        crate::storage::sqlite_common(&connection, 1024 * 1024).map_err(|e| e.to_string())?;
        sql(connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
            CREATE TEMP TABLE checked(position INTEGER PRIMARY KEY, node INTEGER NOT NULL, proved INTEGER NOT NULL);
            CREATE TEMP TABLE authenticated_node(id INTEGER PRIMARY KEY, hash BLOB NOT NULL, free INTEGER NOT NULL, required INTEGER NOT NULL);
            CREATE TEMP TABLE verified(source INTEGER NOT NULL, depth INTEGER NOT NULL, result INTEGER NOT NULL, PRIMARY KEY(source,depth)) WITHOUT ROWID;
            CREATE TEMP TABLE stack(sequence INTEGER PRIMARY KEY, source INTEGER NOT NULL, depth INTEGER NOT NULL);"))?;
        File::open(path.parent().expect("proof parent"))
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        let data_version = sql(connection.pragma_query_value(None, "data_version", |r| r.get(0)))?;
        Ok(Self {
            connection,
            path,
            _lock: lock,
            identity: (metadata.dev(), metadata.ino()),
            data_version,
            cursor: 0,
            checked_hash: [0; 32],
            active: None,
            accepted: None,
            last_budget: None,
            last_recorded_budget: None,
            cache_budget: 0,
        })
    }
    fn live(&self) -> Result<(), String> {
        let metadata = crate::storage::owned_file(&self.path)?;
        let version: i64 = sql(self
            .connection
            .pragma_query_value(None, "data_version", |r| r.get(0)))?;
        if self.identity != (metadata.dev(), metadata.ino()) || version != self.data_version {
            return Err("proof work changed outside its owner".into());
        }
        Ok(())
    }
    pub fn directory(&self) -> &Path {
        self.path.parent().expect("proof work parent")
    }
    pub fn append(&mut self, command: &Command) -> Result<u64, String> {
        self.append_group(std::slice::from_ref(command))
            .map(|p| p.expect("one appended command"))
    }
    fn append_group(&mut self, commands: &[Command]) -> Result<Option<u64>, String> {
        self.live()?;
        let _disk = crate::resources::DiskLease::acquire(
            self.directory(),
            commands.len() as u64 * 32 * 1024,
        )
        .map_err(|e| e.to_string())?;
        sql(self.connection.execute_batch("BEGIN IMMEDIATE"))?;
        let outcome = (|| {
            let mut first = None;
            for command in commands {
                let position = self.append_record(command)?;
                first.get_or_insert(position);
            }
            sql(self.connection.execute_batch("COMMIT"))?;
            Ok(first)
        })();
        if outcome.is_err() {
            let _ = self.connection.execute_batch("ROLLBACK");
        } else {
            self.accepted = None;
        }
        outcome
    }
    fn append_record(&mut self, command: &Command) -> Result<u64, String> {
        if self.active.is_some() {
            return Err("cannot append during an uncommitted instruction".into());
        }
        let (position, sealed, previous): (u64, bool, Vec<u8>) = sql(self.connection.query_row(
            "SELECT commands,sealed,hash FROM state WHERE id=1",
            [],
            |r| Ok((unsigned(r, 0)?, r.get(1)?, r.get(2)?)),
        ))?;
        if sealed {
            return Err("proof program is sealed".into());
        }
        let bytes = serde_json::to_vec(command).map_err(|e| e.to_string())?;
        if bytes.len() > RECORD_BYTES {
            return Err("proof command byte capacity".into());
        }
        let previous = previous.try_into().map_err(|_| "program hash corruption")?;
        let hash = command_hash(previous, &bytes);
        sql(self.connection.execute(
            "INSERT INTO input VALUES(?1,?2,?3)",
            params![number(position)?, bytes, hash.as_slice()],
        ))?;
        sql(self.connection.execute(
            "UPDATE state SET commands=?1,sealed=?2,hash=?3 WHERE id=1",
            params![
                number(position.checked_add(1).ok_or("program address exhausted")?)?,
                matches!(command, Command::Seal { .. }),
                hash.as_slice()
            ],
        ))?;
        Ok(position)
    }
    /// Bounded import groups commit atomically. The next durable ordinal is
    /// observable after interruption; committed input is never discarded.
    pub fn append_reader(&mut self, reader: &mut impl BufRead) -> Result<u64, String> {
        let mut count = 0;
        let mut pending = Vec::new();
        loop {
            let mut line = Vec::new();
            let bytes = (&mut *reader)
                .take((RECORD_BYTES + 1) as u64)
                .read_until(b'\n', &mut line)
                .map_err(|e| e.to_string())?;
            if bytes == 0 {
                self.append_group(&pending)?;
                return Ok(count + pending.len() as u64);
            }
            if bytes > RECORD_BYTES {
                self.append_group(&pending)?;
                return Err("proof command byte capacity; split construction into records".into());
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let command = match serde_json::from_slice(&line) {
                Ok(command) => command,
                Err(e) => {
                    self.append_group(&pending)?;
                    return Err(format!(
                        "proof command after {} appended records: {e}",
                        count + pending.len() as u64
                    ));
                }
            };
            pending.push(command);
            if pending.len() >= crate::resources::adaptive::batch(64).max(1) {
                self.append_group(&pending)?;
                count += pending.len() as u64;
                pending.clear();
            }
        }
    }
    pub fn record_budget(&mut self, snapshot: &Snapshot) -> Result<(), String> {
        self.live()?;
        let changed = self.last_recorded_budget.as_ref().is_none_or(|last| {
            last.selection != snapshot.selection
                || last.budget != snapshot.budget
                || snapshot.timestamp_ms.saturating_sub(last.timestamp_ms) >= 60_000
        });
        if changed {
            let bytes = serde_json::to_vec(snapshot).map_err(|e| e.to_string())?;
            if bytes.len() > 4096 {
                return Err("budget snapshot capacity".into());
            }
            sql(self.connection.execute("INSERT INTO budget(snapshot,command,equation) SELECT ?1,?2,coalesce(max(sequence),0) FROM equation",params![bytes,number(self.cursor)?]))?;
            self.last_recorded_budget = Some(snapshot.clone());
        }
        self.last_budget = Some(snapshot.clone());
        Ok(())
    }
    /// Advances at most one adaptive quantum. A shortage is a recoverable pause,
    /// never a mathematical rejection and never a permanent size exclusion.
    pub fn advance(&mut self, budget: &Budget) -> Result<bool, String> {
        self.live()?;
        if budget.cache_bytes < 4096
            || budget.cache_bytes > (budget.memory_bytes / 4).max(4096)
            || budget.cache_bytes > crate::resources::limits().memory_bytes as u64 / 4
        {
            return Err("invalid effective cache budget".into());
        }
        // Trimming must still run while admission is paused, otherwise a live
        // profile reduction could keep its old cache resident indefinitely.
        if budget.cache_bytes >= 4096 && self.cache_budget != budget.cache_bytes {
            let kib =
                -i64::try_from((budget.cache_bytes / 2048).max(1)).map_err(|e| e.to_string())?;
            sql(self.connection.pragma_update(None, "cache_size", kib))?;
            sql(self
                .connection
                .pragma_update(Some("temp"), "cache_size", kib))?;
            sql(self.connection.execute_batch("PRAGMA shrink_memory"))?;
            self.cache_budget = budget.cache_bytes;
        }
        if budget.paused.is_some() || budget.batch_steps == 0 {
            return Ok(false);
        }
        if budget.memory_bytes < 8 * 1024 * 1024
            || budget.cache_bytes < 4096
            || budget.cache_bytes > budget.memory_bytes / 4
            || budget.batch_steps > budget.memory_bytes as usize / 8192
            || budget.concurrency == 0
        {
            return Err("invalid effective proof budget".into());
        }
        let _disk = crate::resources::DiskLease::acquire(
            self.directory(),
            (budget.batch_steps as u64).saturating_mul(16 * 1024),
        )
        .map_err(|e| e.to_string())?;
        let before = (self.cursor, self.checked_hash, self.accepted);
        sql(self.connection.execute_batch("BEGIN IMMEDIATE"))?;
        let result = self.advance_batch(budget.batch_steps);
        match result {
            Ok(progress) => match sql(self.connection.execute_batch("COMMIT")) {
                Ok(()) => Ok(progress),
                Err(error) => {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    self.active = None;
                    (self.cursor, self.checked_hash, self.accepted) = before;
                    Err(error)
                }
            },
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                self.active = None;
                (self.cursor, self.checked_hash, self.accepted) = before;
                Err(error)
            }
        }
    }
    fn advance_batch(&mut self, steps: usize) -> Result<bool, String> {
        let mut progress = false;
        for _ in 0..steps {
            if self.active.is_none() {
                let input:Option<(Vec<u8>,Vec<u8>)>=sql(self.connection.query_row("SELECT substr(command,1,4097),substr(hash,1,33) FROM input WHERE position=?1",[number(self.cursor)?],|r|Ok((r.get(0)?,r.get(1)?))).optional())?;
                let Some((bytes, stored_hash)) = input else {
                    break;
                };
                if bytes.len() > RECORD_BYTES {
                    return Err("stored command capacity".into());
                }
                let source_hash = command_hash(self.checked_hash, &bytes);
                if stored_hash != source_hash {
                    return Err("program input hash mismatch".into());
                }
                let command: Command = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                if serde_json::to_vec(&command).map_err(|e| e.to_string())? != bytes {
                    return Err("noncanonical stored program command".into());
                }
                let plan = checker::prepare(&command, self.cursor, self)?;
                let mut operations = Vec::new();
                for (predicate, from, to) in plan.absent {
                    let input = operations.len();
                    operations.push(Operation::Input(predicate));
                    let transformed = operations.len();
                    operations.push(Operation::Substitute(input, from, to));
                    operations.push(Operation::AssertEqual(transformed, predicate));
                }
                compile(plan.expression, &mut operations);
                self.active = Some(Evaluation {
                    operations,
                    registers: Vec::new(),
                    position: 0,
                    proved: plan.proved,
                    seal: plan.seal,
                    source_hash,
                    restore_sequence: 0,
                    restoring: true,
                });
                sql(self
                    .connection
                    .execute_batch("DELETE FROM verified; DELETE FROM stack;"))?;
            }
            let mut active = self.active.take().expect("active command");
            if let Some(value) = self.operation(&mut active)? {
                active.registers.push(value);
                active.position += 1;
                active.restore_sequence = 0;
                active.restoring = true;
                sql(self
                    .connection
                    .execute_batch("DELETE FROM verified; DELETE FROM stack;"))?;
            }
            if active.position == active.operations.len() {
                let node = *active.registers.last().ok_or("empty proof recipe")?;
                let previous: Option<(u64, bool)> = sql(self
                    .connection
                    .query_row(
                        "SELECT node,proved FROM result WHERE position=?1",
                        [number(self.cursor)?],
                        |r| Ok((unsigned(r, 0)?, r.get(1)?)),
                    )
                    .optional())?;
                if previous.is_some_and(|value| value != (node, active.proved)) {
                    return Err("saved proof result differs from mathematical replay".into());
                }
                sql(self.connection.execute(
                    "INSERT OR IGNORE INTO result VALUES(?1,?2,?3)",
                    params![number(self.cursor)?, number(node)?, active.proved],
                ))?;
                sql(self.connection.execute(
                    "INSERT INTO checked VALUES(?1,?2,?3)",
                    params![number(self.cursor)?, number(node)?, active.proved],
                ))?;
                self.cursor = self
                    .cursor
                    .checked_add(1)
                    .ok_or("proof address exhausted")?;
                self.checked_hash = active.source_hash;
                sql(self.connection.execute(
                    "UPDATE state SET committed=max(committed,?1) WHERE id=1",
                    [number(self.cursor)?],
                ))?;
                if active.seal {
                    let (commands, hash, sealed): (u64, Vec<u8>, bool) =
                        sql(self.connection.query_row(
                            "SELECT commands,hash,sealed FROM state WHERE id=1",
                            [],
                            |r| Ok((unsigned(r, 0)?, r.get(1)?, r.get(2)?)),
                        ))?;
                    if !sealed || commands != self.cursor || hash != self.checked_hash {
                        return Err("seal is not the complete program".into());
                    }
                    self.accepted = Some(node);
                }
            } else {
                self.active = Some(active);
            }
            progress = true;
        }
        Ok(progress)
    }
    fn operation(&mut self, evaluation: &mut Evaluation) -> Result<Option<u64>, String> {
        let r = &evaluation.registers;
        let node = match evaluation.operations[evaluation.position] {
            Operation::Input(id) => {
                self.load(id)?;
                return Ok(Some(id));
            }
            Operation::Equal(a, b) => Node::Equal(Variable::Free(a), Variable::Free(b)),
            Operation::Member(a, b) => Node::Member(Variable::Free(a), Variable::Free(b)),
            Operation::Not(a) => Node::Not(r[a]),
            Operation::Implies(a, b) => Node::Implies(r[a], r[b]),
            Operation::Vacuous(a) => Node::ForAll(r[a]),
            Operation::AssertEqual(a, expected) => {
                if r[a] != expected {
                    return Err("schema freshness violation".into());
                }
                return Ok(Some(expected));
            }
            Operation::Bind(a, v) => {
                let source = r[a];
                let transform = Transform::Bind(v);
                return self
                    .transform(evaluation, source, transform)
                    .and_then(|value| value.map(|v| self.intern(Node::ForAll(v))).transpose());
            }
            Operation::Substitute(a, from, to) => {
                let source = r[a];
                return self.transform(evaluation, source, Transform::Substitute { from, to });
            }
        };
        self.intern(node).map(Some)
    }
    fn memo(&self, source: u64, depth: u64) -> Result<Option<u64>, String> {
        sql(self
            .connection
            .query_row(
                "SELECT result FROM verified WHERE source=?1 AND depth=?2",
                params![number(source)?, number(depth)?],
                |r| unsigned(r, 0),
            )
            .optional())
    }
    fn transformed_node(
        &self,
        source: u64,
        depth: u64,
        transform: Transform,
    ) -> Result<Option<Node<u64>>, String> {
        let (node, _, properties) = self.load(source)?;
        // `load` derives properties from nodes authenticated by this owner's
        // replay, rather than trusting persisted flags. These transforms only
        // replace free variables, so a free-variable-free subgraph is unchanged
        // at every binder depth and needs no recursive transformation evidence.
        if !properties.has_free_variables {
            return Ok(Some(node));
        }
        let nested = node
            .nested_depth(depth)
            .ok_or("physical binder address exhausted")?;
        let mut children = [None, None];
        for (i, child) in node.children().into_iter().enumerate() {
            if let Some(child) = child {
                let Some(result) = self.memo(child, nested)? else {
                    return Ok(None);
                };
                children[i] = Some(result);
            }
        }
        Ok(Some(node.transformed(transform, depth, children)))
    }
    fn transform(
        &mut self,
        active: &mut Evaluation,
        source: u64,
        transform: Transform,
    ) -> Result<Option<u64>, String> {
        let position = number(self.cursor)?;
        let operation = active.position as i64;
        if active.restoring {
            let row:Option<(i64,u64,u64,u64)>=sql(self.connection.query_row("SELECT sequence,source,depth,result FROM equation WHERE position=?1 AND operation=?2 AND sequence>?3 ORDER BY sequence LIMIT 1",params![position,operation,active.restore_sequence],|r|Ok((r.get(0)?,unsigned(r,1)?,unsigned(r,2)?,unsigned(r,3)?))).optional())?;
            if let Some((sequence, input, depth, result)) = row {
                let node = self
                    .transformed_node(input, depth, transform)?
                    .ok_or("saved transformation is not dependency ordered")?;
                let expected = self.intern(node)?;
                if expected != result {
                    return Err("saved formula transformation failed replay".into());
                }
                sql(self.connection.execute(
                    "INSERT INTO verified VALUES(?1,?2,?3)",
                    params![number(input)?, number(depth)?, number(result)?],
                ))?;
                active.restore_sequence = sequence;
                return Ok(None);
            }
            active.restoring = false;
        }
        if let Some(result) = self.memo(source, 0)? {
            return Ok(Some(result));
        }
        let top: Option<(i64, u64, u64)> = sql(self
            .connection
            .query_row(
                "SELECT sequence,source,depth FROM stack ORDER BY sequence DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, unsigned(r, 1)?, unsigned(r, 2)?)),
            )
            .optional())?;
        let Some((sequence, input, depth)) = top else {
            sql(self.connection.execute(
                "INSERT INTO stack(source,depth) VALUES(?1,0)",
                [number(source)?],
            ))?;
            return Ok(None);
        };
        if self.memo(input, depth)?.is_some() {
            sql(self
                .connection
                .execute("DELETE FROM stack WHERE sequence=?1", [sequence]))?;
            return Ok(None);
        }
        if let Some(node) = self.transformed_node(input, depth, transform)? {
            let result = self.intern(node)?;
            sql(self.connection.execute("INSERT INTO equation(position,operation,source,depth,result) VALUES(?1,?2,?3,?4,?5)",params![position,operation,number(input)?,number(depth)?,number(result)?]))?;
            sql(self.connection.execute(
                "INSERT INTO verified VALUES(?1,?2,?3)",
                params![number(input)?, number(depth)?, number(result)?],
            ))?;
            sql(self
                .connection
                .execute("DELETE FROM stack WHERE sequence=?1", [sequence]))?;
        } else {
            let (node, _, _) = self.load(input)?;
            let nested = node
                .nested_depth(depth)
                .ok_or("physical binder address exhausted")?;
            for child in node.children().into_iter().flatten() {
                if self.memo(child, nested)?.is_none() {
                    sql(self.connection.execute(
                        "INSERT INTO stack(source,depth) VALUES(?1,?2)",
                        params![number(child)?, number(nested)?],
                    ))?;
                    break;
                }
            }
        }
        Ok(None)
    }
    fn raw(&self, id: u64) -> Result<(Node<u64>, [u8; 32], Properties), String> {
        type Row = (i64, i64, i64, i64, i64, bool, u64, Vec<u8>);
        let (tag, a, b, ak, bk, free, required, hash): Row = sql(self.connection.query_row(
            "SELECT tag,a,b,ak,bk,free,required,hash FROM node WHERE id=?1",
            [number(id)?],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    unsigned(r, 6)?,
                    r.get(7)?,
                ))
            },
        ))?;
        let variable = |kind, value: i64| -> Result<Variable, String> {
            match (kind, value) {
                (0, 0..) => u32::try_from(value)
                    .map(Variable::Free)
                    .map_err(|e| e.to_string()),
                (1, 0..) => Ok(Variable::Bound(value as u64)),
                _ => Err("invalid graph variable".into()),
            }
        };
        let child = |value: i64| -> Result<u64, String> {
            if value > 0 && (value as u64) < id {
                Ok(value as u64)
            } else {
                Err("formula graph is not acyclic".into())
            }
        };
        let node = match tag {
            0 => Node::Equal(variable(ak, a)?, variable(bk, b)?),
            1 => Node::Member(variable(ak, a)?, variable(bk, b)?),
            2 => Node::Not(child(a)?),
            3 => Node::Implies(child(a)?, child(b)?),
            4 => Node::ForAll(child(a)?),
            _ => return Err("invalid formula graph tag".into()),
        };
        Ok((
            node,
            hash.try_into()
                .map_err(|_| "formula graph digest corruption")?,
            Properties {
                has_free_variables: free,
                required_binders: required,
            },
        ))
    }
    fn representation(&self, node: Node<u64>) -> Result<([u8; 32], Properties), String> {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(b"naome:formula-graph:v1\0");
        let mut properties = [None, None];
        for (i, child) in node.children().into_iter().enumerate() {
            if let Some(child) = child {
                let (_, hash, p) = self.raw(child)?;
                if self.authenticated(child)? != Some((hash, p)) {
                    return Err("formula child has not passed current-owner authentication".into());
                }
                bytes.extend_from_slice(&hash);
                properties[i] = Some(p);
            }
        }
        let variable = |bytes: &mut Vec<u8>, v| match v {
            Variable::Free(v) => {
                bytes.push(0);
                bytes.extend_from_slice(&u64::from(v).to_be_bytes());
            }
            Variable::Bound(v) => {
                bytes.push(1);
                bytes.extend_from_slice(&v.to_be_bytes());
            }
        };
        bytes.push(match node {
            Node::Equal(..) => 0,
            Node::Member(..) => 1,
            Node::Not(_) => 2,
            Node::Implies(..) => 3,
            Node::ForAll(_) => 4,
        });
        if let Node::Equal(a, b) | Node::Member(a, b) = node {
            variable(&mut bytes, a);
            variable(&mut bytes, b);
        }
        let p = node
            .properties(properties)
            .ok_or("formula graph property overflow")?;
        bytes.push(u8::from(p.has_free_variables));
        bytes.extend_from_slice(&p.required_binders.to_be_bytes());
        Ok((digest(&bytes), p))
    }
    fn load(&self, id: u64) -> Result<(Node<u64>, [u8; 32], Properties), String> {
        let (node, hash, p) = self.raw(id)?;
        if self.representation(node)? != (hash, p) {
            return Err("formula graph content authentication failed".into());
        }
        self.remember_authenticated(id, hash, p)?;
        Ok((node, hash, p))
    }
    fn authenticated(&self, id: u64) -> Result<Option<([u8; 32], Properties)>, String> {
        let row: Option<(Vec<u8>, bool, u64)> = sql(self
            .connection
            .query_row(
                "SELECT hash,free,required FROM authenticated_node WHERE id=?1",
                [number(id)?],
                |row| Ok((row.get(0)?, row.get(1)?, unsigned(row, 2)?)),
            )
            .optional())?;
        row.map(|(hash, has_free_variables, required_binders)| {
            Ok((
                hash.try_into()
                    .map_err(|_| "authenticated formula digest corruption")?,
                Properties {
                    has_free_variables,
                    required_binders,
                },
            ))
        })
        .transpose()
    }
    fn remember_authenticated(
        &self,
        id: u64,
        hash: [u8; 32],
        properties: Properties,
    ) -> Result<(), String> {
        sql(self.connection.execute(
            "INSERT OR IGNORE INTO authenticated_node VALUES(?1,?2,?3,?4)",
            params![
                number(id)?,
                hash.as_slice(),
                properties.has_free_variables,
                number(properties.required_binders)?
            ],
        ))?;
        if self.authenticated(id)? != Some((hash, properties)) {
            return Err("authenticated formula changed within its owner".into());
        }
        Ok(())
    }
    fn intern(&mut self, node: Node<u64>) -> Result<u64, String> {
        let (hash, properties) = self.representation(node)?;
        let previous: Option<u64> = sql(self
            .connection
            .query_row(
                "SELECT id FROM node WHERE hash=?1",
                [hash.as_slice()],
                |r| unsigned(r, 0),
            )
            .optional())?;
        if let Some(id) = previous {
            if self.load(id)? != (node, hash, properties) {
                return Err("formula graph identity collision or corruption".into());
            }
            return Ok(id);
        }
        let var = |v| match v {
            Variable::Free(v) => (0, i64::from(v)),
            Variable::Bound(v) => (1, v as i64),
        };
        let (tag, a, b, ak, bk) = match node {
            Node::Equal(a, b) | Node::Member(a, b) => {
                let (ak, a) = var(a);
                let (bk, b) = var(b);
                (
                    if matches!(node, Node::Equal(..)) {
                        0
                    } else {
                        1
                    },
                    a,
                    b,
                    ak,
                    bk,
                )
            }
            Node::Not(a) => (2, number(a)?, 0, 0, 0),
            Node::Implies(a, b) => (3, number(a)?, number(b)?, 0, 0),
            Node::ForAll(a) => (4, number(a)?, 0, 0, 0),
        };
        sql(self.connection.execute(
            "INSERT INTO node(hash,tag,a,b,ak,bk,free,required) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                hash.as_slice(),
                tag,
                a,
                b,
                ak,
                bk,
                properties.has_free_variables,
                number(properties.required_binders)?
            ],
        ))?;
        let id = u64::try_from(self.connection.last_insert_rowid()).map_err(|e| e.to_string())?;
        self.remember_authenticated(id, hash, properties)?;
        Ok(id)
    }
    pub fn status(&self) -> Result<Status, String> {
        self.live()?;
        let (commands, committed, sealed, hash): (u64, u64, bool, Vec<u8>) =
            sql(self.connection.query_row(
                "SELECT commands,committed,sealed,hash FROM state WHERE id=1",
                [],
                |r| Ok((unsigned(r, 0)?, unsigned(r, 1)?, r.get(2)?, r.get(3)?)),
            ))?;
        let nodes =
            sql(self
                .connection
                .query_row("SELECT coalesce(max(id),0) FROM node", [], |r| {
                    unsigned(r, 0)
                }))?;
        let equations = sql(self.connection.query_row(
            "SELECT coalesce(max(sequence),0) FROM equation",
            [],
            |r| unsigned(r, 0),
        ))?;
        let pages: u64 = sql(self
            .connection
            .pragma_query_value(None, "page_count", |r| unsigned(r, 0)))?;
        let page_size: u64 = sql(self
            .connection
            .pragma_query_value(None, "page_size", |r| unsigned(r, 0)))?;
        Ok(Status {
            format: naome_proof::program::FORMAT,
            commands,
            committed_commands: committed,
            checked_commands: self.cursor,
            formula_nodes: nodes,
            transformation_equations: equations,
            sealed,
            fully_checked: self.accepted.is_some() && self.cursor == commands,
            program_hash: crate::hex(&hash),
            conclusion: self
                .accepted
                .map(|id| self.load(id).map(|(_, hash, _)| crate::hex(&hash)))
                .transpose()?,
            database_bytes: pages.saturating_mul(page_size),
            budget: self.last_budget.clone(),
        })
    }
}
impl checker::Context for Work {
    type Formula = u64;
    fn previous(&self, index: u64) -> Result<Value<u64>, String> {
        let (formula, proved) = sql(self.connection.query_row(
            "SELECT node,proved FROM checked WHERE position=?1",
            [number(index)?],
            |r| Ok((unsigned(r, 0)?, r.get(1)?)),
        ))?;
        let (_, _, p) = self.load(formula)?;
        if p.required_binders != 0 {
            return Err("program formula has dangling bound variables".into());
        }
        Ok(Value { formula, proved })
    }
    fn implication(&self, formula: u64) -> Result<Option<(u64, u64)>, String> {
        Ok(match self.load(formula)?.0 {
            Node::Implies(a, b) => Some((a, b)),
            _ => None,
        })
    }
    fn closed(&self, formula: u64) -> Result<bool, String> {
        Ok(self.load(formula)?.2.closed())
    }
    fn fixed(&mut self, formula: &Formula) -> Result<u64, String> {
        formula.fold_graph(|node| self.intern(node))
    }
}

#[cfg(test)]
mod tests;
