//! Checker-owned incremental evaluation against an owner-provided connection.
//! Reopening reconstructs trust by replay; persisted flags grant no validity.
use super::{self as checker, Error, Value};
use crate::{ArtifactState, ContextView, context::ProgramSource};
use naome_foundation::{
    Formula,
    construction::Expression,
    graph::{Node, Properties, Transform, Variable},
};
use naome_proof::program::{self as format, Manifest};
use naome_proof::program::{Command, RECORD_BYTES};
use naome_proof::{DerivationId, ProofId, StatementId};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

pub const APPLICATION_ID: i64 = 0x4e415057;
pub const SCHEMA_VERSION: u32 = 2;
fn sql<T>(value: rusqlite::Result<T>) -> Result<T, Error> {
    value.map_err(Error::Storage)
}
fn number(n: u64) -> Result<i64, Error> {
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
use format::{ChunkReader, command_hash, decode_command, encode_command};
mod diagnostics;
mod materialization;
mod references;
use materialization::{Finalization, Shape};
pub use references::ProgramDependency;

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
}

pub struct Engine {
    connection: Connection,
    data_version: i64,
    cursor: u64,
    checked_hash: [u8; 32],
    active: Option<Evaluation>,
    accepted: Option<u64>,
    cache_budget: u64,
    last_quantum_steps: usize,
    export: Option<Export>,
    finalization: Option<Finalization>,
    context_snapshot: Option<[u8; 32]>,
    context_consistent: bool,
    reference_snapshot: Option<[u8; 32]>,
}
#[derive(Clone, Copy)]
struct Export {
    before: u64,
    hash: [u8; 32],
    bytes: u64,
}

/// A complete mathematical check in this live evaluator. Storage cannot
/// construct this value from persisted flags or a manifest received from a peer.
pub struct CheckedProgram {
    engine: Engine,
    manifest: Manifest,
    canonical: Option<Formula>,
}
impl CheckedProgram {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn conclusion(&self) -> Option<&Formula> {
        self.canonical.as_ref()
    }
    /// Changes only volatile SQLite caches; the complete checked result remains immutable.
    pub fn restrict_cache(&mut self, bytes: u64) -> Result<(), Error> {
        self.engine
            .advance(0, bytes, &ArtifactState::new())
            .map(|_| ())
    }
    pub fn input_chunk(
        &self,
        start: u64,
        records: usize,
        maximum: usize,
    ) -> Result<format::Chunk, Error> {
        self.engine.input_chunk(start, records, maximum)
    }
    /// Number of unique nodes reachable from this checked conclusion.
    pub fn node_count(&self) -> Result<u64, Error> {
        self.engine.live()?;
        Ok(self
            .engine
            .finalization
            .as_ref()
            .ok_or("program export incomplete")?
            .reachable)
    }
    /// Ascending replay-authenticated nodes of the conclusion's reachable DAG.
    pub fn nodes_after(
        &self,
        start: u64,
    ) -> impl Iterator<Item = Result<(u64, [u8; 32], Vec<u8>), Error>> + '_ {
        let mut after = start;
        std::iter::from_fn(move || {
            let result = (|| {
                self.engine.live()?;
                let next: Option<u64> = sql(self
                    .engine
                    .connection
                    .query_row(
                        "SELECT id FROM export_node WHERE id>?1 ORDER BY id LIMIT 1",
                        [number(after)?],
                        |row| unsigned(row, 0),
                    )
                    .optional())?;
                let Some(id) = next else { return Ok(None) };
                after = id;
                let (node, hash, properties) = self.engine.load(id)?;
                let mut hashes = [None, None];
                for (i, child) in node.children().into_iter().enumerate() {
                    if let Some(child) = child {
                        hashes[i] = Some(self.engine.load(child)?.1);
                    }
                }
                let mut i = 0;
                let node = node.map(|_| {
                    let hash = hashes[i].expect("graph child");
                    i += 1;
                    hash
                });
                Ok(Some((id, hash, format::graph_node_bytes(node, properties))))
            })();
            match result {
                Ok(None) => None,
                Ok(Some(value)) => Some(Ok(value)),
                Err(error) => Some(Err(error)),
            }
        })
    }
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
    reference: Option<ProgramSource>,
    reference_depth: u64,
}
enum Operation {
    Reference(ProofId),
    Input(u64),
    Equal(u32, u32),
    Member(u32, u32),
    Not(usize),
    Implies(usize, usize),
    Bind(usize, u32),
    Vacuous(usize),
    Substitute(usize, u32, u32),
    AssertEqual {
        register: usize,
        expected: u64,
        variable: u32,
        role: crate::diagnostics::OperandRole,
    },
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

impl Engine {
    pub fn input_chunk(
        &self,
        start: u64,
        records: usize,
        maximum: usize,
    ) -> Result<format::Chunk, Error> {
        self.live()?;
        let commands: u64 =
            sql(self
                .connection
                .query_row("SELECT commands FROM state WHERE id=1", [], |row| {
                    unsigned(row, 0)
                }))?;
        if start > commands {
            return Err("program cursor exceeds input".into());
        }
        let previous = if start == 0 {
            [0; 32]
        } else {
            let bytes: Vec<u8> = sql(self.connection.query_row(
                "SELECT substr(hash,1,33) FROM input WHERE position=?1",
                [number(start - 1)?],
                |row| row.get(0),
            ))?;
            bytes.try_into().map_err(|_| "program prefix hash width")?
        };
        let mut statement=sql(self.connection.prepare_cached("SELECT position,substr(command,1,4097),substr(hash,1,33) FROM input WHERE position>=?1 ORDER BY position LIMIT ?2"))?;
        let mut rows = sql(statement.query(params![number(start)?, records as i64]))?;
        let mut reader = ChunkReader::new(start, previous, records, maximum)?;
        while let Some(row) = sql(rows.next())? {
            let position = sql(unsigned(row, 0))?;
            let encoded: Vec<u8> = sql(row.get(1))?;
            let stored: Vec<u8> = sql(row.get(2))?;
            let stored = stored.try_into().map_err(|_| "program input hash width")?;
            if !reader.push(position, &encoded, stored)? {
                break;
            }
        }
        let end = reader.end();
        let next = if end < commands {
            let bytes: Vec<u8> = sql(self.connection.query_row(
                "SELECT suffix FROM stream WHERE position=?1",
                [number(end)?],
                |row| row.get(0),
            ))?;
            bytes
                .try_into()
                .map_err(|_| "program stream suffix width")?
        } else {
            [0; 32]
        };
        reader.finish(commands, next).map_err(Into::into)
    }
    /// Build the export commitment, reachable-node index and bounded conclusion
    /// projection in quanta after mathematical replay. All derived state belongs
    /// to this evaluator; stored digests or flags never restore mathematical trust.
    pub fn prepare_export(&mut self, steps: usize) -> Result<bool, Error> {
        self.live()?;
        if !self.status()?.fully_checked {
            return Err("program has not been completely checked".into());
        }
        if self.export.is_some_and(|export| export.before == 0) {
            return self.prepare_conclusion(steps);
        }
        if self.export.is_none() {
            self.export = Some(Export {
                before: self.cursor,
                hash: [0; 32],
                bytes: 0,
            });
        }
        let before = self.export.expect("export cursor");
        let mut cursor = before;
        sql(self.connection.execute_batch("BEGIN IMMEDIATE"))?;
        let result = (|| {
            for _ in 0..steps {
                if cursor.before == 0 {
                    break;
                }
                let position = cursor.before - 1;
                let bytes: Vec<u8> = sql(self.connection.query_row(
                    "SELECT substr(command,1,4097) FROM input WHERE position=?1",
                    [number(position)?],
                    |row| row.get(0),
                ))?;
                if bytes.len() > RECORD_BYTES {
                    return Err(Error::from("stored command capacity"));
                }
                cursor.hash = format::stream_hash(&bytes, cursor.hash);
                cursor.bytes = cursor
                    .bytes
                    .checked_add(bytes.len() as u64)
                    .ok_or("program byte width")?;
                sql(self.connection.execute(
                    "INSERT OR REPLACE INTO stream VALUES(?1,?2)",
                    params![number(position)?, cursor.hash.as_slice()],
                ))?;
                cursor.before = position;
            }
            sql(self.connection.execute_batch("COMMIT"))?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = self.connection.execute_batch("ROLLBACK");
            self.export = Some(before);
            return Err(error);
        }
        self.export = Some(cursor);
        Ok(false)
    }
    pub fn checked(mut self) -> Result<CheckedProgram, Error> {
        self.live()?;
        let root = self
            .accepted
            .ok_or("program has not been completely checked")?;
        let status = self.status()?;
        if !status.fully_checked {
            return Err("program has not been completely checked".into());
        }
        let canonical = self
            .finalization
            .as_mut()
            .and_then(|state| state.canonical.take())
            .ok_or("program conclusion export is incomplete")?;
        let conclusion = self.load(root)?.1;
        let statement = match &canonical {
            Some(formula) => naome_proof::StatementId::of_canonical_formula(
                &formula.encode_canonical().map_err(|e| e.to_string())?,
            )
            .ok_or("statement address width")?,
            None => format::graph_statement_id(conclusion),
        };
        let export = self
            .export
            .filter(|export| export.before == 0)
            .ok_or("program export index is incomplete")?;
        let manifest = Manifest {
            commands: status.commands,
            input_bytes: export.bytes,
            program_hash: self.checked_hash,
            stream_root: export.hash,
            conclusion,
            statement: *statement.as_bytes(),
        };
        Ok(CheckedProgram {
            engine: self,
            canonical,
            manifest,
        })
    }
    pub fn result_digest(&self, position: u64) -> Result<([u8; 32], bool), Error> {
        self.live()?;
        let value = checker::Context::previous(self, position)?;
        Ok((self.load(value.formula)?.1, value.proved))
    }
    /// The caller owns file locks, native identity, resource leases and SQL
    /// connection configuration. Only this evaluator can issue CheckedProgram.
    pub fn open(connection: Connection) -> Result<Self, Error> {
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
                PRAGMA application_id=1312903255; PRAGMA user_version=2; COMMIT;"))?;
        } else if app != APPLICATION_ID {
            return Err("proof work format mismatch".into());
        }
        let version: i64 = sql(connection.pragma_query_value(None, "user_version", |r| r.get(0)))?;
        if version != i64::from(SCHEMA_VERSION) {
            return Err("unsupported proof work version".into());
        }
        // The minimum evaluator budget splits into sub-page cache allowances.
        // Small temporary pages keep its disk-backed cache from rounding to zero.
        sql(connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA temp.page_size=512;
            CREATE TEMP TABLE checked(position INTEGER PRIMARY KEY, node INTEGER NOT NULL, proved INTEGER NOT NULL);
            CREATE TEMP TABLE authenticated_node(id INTEGER PRIMARY KEY, hash BLOB NOT NULL, free INTEGER NOT NULL, required INTEGER NOT NULL, nodes INTEGER NOT NULL, bytes INTEGER NOT NULL, depth INTEGER NOT NULL);
            CREATE TEMP TABLE verified(source INTEGER NOT NULL, depth INTEGER NOT NULL, result INTEGER NOT NULL, PRIMARY KEY(source,depth)) WITHOUT ROWID;
            CREATE TEMP TABLE stack(sequence INTEGER PRIMARY KEY, source INTEGER NOT NULL, depth INTEGER NOT NULL);"))?;
        sql(connection.execute_batch("CREATE TEMP TABLE stream(position INTEGER PRIMARY KEY,suffix BLOB NOT NULL CHECK(length(suffix)=32)); CREATE TEMP TABLE export_pending(id INTEGER PRIMARY KEY); CREATE TEMP TABLE export_node(id INTEGER PRIMARY KEY);"))?;
        sql(connection.execute_batch("CREATE TEMP TABLE checked_reference(proof BLOB PRIMARY KEY CHECK(length(proof)=32), statement BLOB NOT NULL CHECK(length(statement)=32), derivation BLOB NOT NULL CHECK(length(derivation)=32)) WITHOUT ROWID;
            CREATE TEMP TABLE reference_pending(sequence INTEGER PRIMARY KEY,address BLOB NOT NULL CHECK(length(address)=32));"))?;
        let data_version = sql(connection.pragma_query_value(None, "data_version", |r| r.get(0)))?;
        Ok(Self {
            connection,
            data_version,
            cursor: 0,
            checked_hash: [0; 32],
            active: None,
            accepted: None,
            cache_budget: 0,
            last_quantum_steps: 0,
            export: None,
            finalization: None,
            context_snapshot: None,
            context_consistent: true,
            reference_snapshot: None,
        })
    }
    fn live(&self) -> Result<(), Error> {
        let version: i64 = sql(self
            .connection
            .pragma_query_value(None, "data_version", |r| r.get(0)))?;
        if version != self.data_version {
            return Err("proof work changed outside its owner".into());
        }
        Ok(())
    }
    pub fn append(&mut self, command: &Command) -> Result<u64, Error> {
        self.append_group(std::slice::from_ref(command))
            .map(|p| p.expect("one appended command"))
    }
    pub fn append_group(&mut self, commands: &[Command]) -> Result<Option<u64>, Error> {
        self.live()?;
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
            self.finalization = None;
            self.export = None;
        }
        outcome
    }
    fn append_record(&mut self, command: &Command) -> Result<u64, Error> {
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
        let bytes = encode_command(command)?;
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
    pub fn record_budget(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.live()?;
        if bytes.len() > 4096 {
            return Err("budget snapshot capacity".into());
        }
        sql(self.connection.execute("INSERT INTO budget(snapshot,command,equation) SELECT ?1,?2,coalesce(max(sequence),0) FROM equation",params![bytes,number(self.cursor)?]))?;
        Ok(())
    }
    /// Advances at most one adaptive quantum. A shortage is a recoverable pause,
    /// never a mathematical rejection and never a permanent size exclusion.
    pub fn advance(
        &mut self,
        steps: usize,
        cache_bytes: u64,
        context: &dyn ContextView,
    ) -> Result<bool, Error> {
        self.advance_impl(steps, cache_bytes, context, None)
    }
    /// Runs the ordinary bounded quantum and captures a requested fragment if
    /// it encounters a proof failure. It does not retain or trust failed work.
    pub fn advance_with_inspection(
        &mut self,
        steps: usize,
        cache_bytes: u64,
        context: &dyn ContextView,
        query: &crate::diagnostics::FormulaQuery,
    ) -> Result<bool, Error> {
        query.validate().map_err(Error::Inspection)?;
        self.advance_impl(steps, cache_bytes, context, Some(query))
    }
    fn advance_impl(
        &mut self,
        steps: usize,
        cache_bytes: u64,
        context: &dyn ContextView,
        query: Option<&crate::diagnostics::FormulaQuery>,
    ) -> Result<bool, Error> {
        self.last_quantum_steps = 0;
        self.live()?;
        if cache_bytes < 4096 {
            return Err("invalid effective cache budget".into());
        }
        // Trimming must still run while admission is paused, otherwise a live
        // profile reduction could keep its old cache resident indefinitely.
        if self.cache_budget != cache_bytes {
            // Main/temp SQLite caches and the bounded projection cache share
            // one effective byte budget, including live downward adjustments.
            let sqlite_bytes = cache_bytes - materialization::Tree::cache_bytes(cache_bytes);
            let kib = -i64::try_from((sqlite_bytes / 2048).max(1)).map_err(|e| e.to_string())?;
            sql(self.connection.pragma_update(None, "cache_size", kib))?;
            sql(self
                .connection
                .pragma_update(Some("temp"), "cache_size", kib))?;
            // A growing allowance needs no eviction. Preserve the live temp
            // evaluator while still trimming on initialization and every cut.
            if self.cache_budget == 0 || cache_bytes < self.cache_budget {
                sql(self.connection.execute_batch("PRAGMA shrink_memory"))?;
            }
            if let Some(tree) = self
                .finalization
                .as_mut()
                .and_then(|state| state.tree.as_mut())
            {
                tree.restrict_cache(cache_bytes);
            }
            self.cache_budget = cache_bytes;
        }
        if steps == 0 {
            return Ok(false);
        }
        let snapshot = context.snapshot_id();
        self.context_snapshot = Some(snapshot);
        let before = (self.cursor, self.checked_hash, self.accepted);
        sql(self.connection.execute_batch("BEGIN IMMEDIATE"))?;
        let result = self.advance_batch(steps, context, query);
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
    /// Operations actually executed by the most recent quantum, including a
    /// failed quantum. This observation grants no mathematical authority.
    pub fn last_quantum_steps(&self) -> usize {
        self.last_quantum_steps
    }

    fn advance_batch(
        &mut self,
        steps: usize,
        context: &dyn ContextView,
        query: Option<&crate::diagnostics::FormulaQuery>,
    ) -> Result<bool, Error> {
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
                let command: Command = decode_command(&bytes)?;
                let plan = match checker::prepare(&command, self.cursor, self) {
                    Ok(plan) => plan,
                    Err(checker::PrepareError::Context(error)) => return Err(error),
                    Err(checker::PrepareError::Check(failure)) => {
                        return Err(Error::Check(Box::new(
                            self.proof_diagnostic(&command, failure, context, query)?,
                        )));
                    }
                };
                let mut operations = Vec::new();
                for freshness in plan.absent {
                    let input = operations.len();
                    operations.push(Operation::Input(freshness.predicate));
                    let transformed = operations.len();
                    operations.push(Operation::Substitute(
                        input,
                        freshness.variable,
                        freshness.replacement,
                    ));
                    operations.push(Operation::AssertEqual {
                        register: transformed,
                        expected: freshness.predicate,
                        variable: freshness.variable,
                        role: freshness.role,
                    });
                }
                match plan.construction {
                    checker::Construction::Formula(expression) => {
                        compile(expression, &mut operations);
                    }
                    checker::Construction::Reference(proof) => {
                        operations.push(Operation::Reference(proof));
                    }
                }
                self.active = Some(Evaluation {
                    operations,
                    registers: Vec::new(),
                    position: 0,
                    proved: plan.proved,
                    seal: plan.seal,
                    source_hash,
                    restore_sequence: 0,
                    restoring: true,
                    reference: None,
                    reference_depth: 0,
                });
                sql(self
                    .connection
                    .execute_batch("DELETE FROM verified; DELETE FROM stack;"))?;
            }
            self.last_quantum_steps += 1;
            let mut active = self.active.take().expect("active command");
            if let Some(value) = self.operation(&mut active, context, query)? {
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
    fn operation(
        &mut self,
        evaluation: &mut Evaluation,
        context: &dyn ContextView,
        query: Option<&crate::diagnostics::FormulaQuery>,
    ) -> Result<Option<u64>, Error> {
        let r = &evaluation.registers;
        let node = match evaluation.operations[evaluation.position] {
            Operation::Reference(proof) => {
                return self.import_reference(evaluation, context, proof, query);
            }
            Operation::Input(id) => {
                self.load(id)?;
                return Ok(Some(id));
            }
            Operation::Equal(a, b) => Node::Equal(Variable::Free(a), Variable::Free(b)),
            Operation::Member(a, b) => Node::Member(Variable::Free(a), Variable::Free(b)),
            Operation::Not(a) => Node::Not(r[a]),
            Operation::Implies(a, b) => Node::Implies(r[a], r[b]),
            Operation::Vacuous(a) => Node::ForAll(r[a]),
            Operation::AssertEqual {
                register,
                expected,
                variable,
                role,
            } => {
                if r[register] != expected {
                    let command = self.current_command()?;
                    return Err(Error::Check(Box::new(self.proof_diagnostic(
                        &command,
                        crate::diagnostics::Failure::ForbiddenPredicateVariable { variable, role },
                        context,
                        query,
                    )?)));
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
    fn memo(&self, source: u64, depth: u64) -> Result<Option<u64>, Error> {
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
    ) -> Result<Option<Node<u64>>, Error> {
        let (node, _, properties) = self.load(source)?;
        // Properties come from this owner's replay, including authenticated
        // children. These transforms only replace free variables.
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
    ) -> Result<Option<u64>, Error> {
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
    fn raw(&self, id: u64) -> Result<(Node<u64>, [u8; 32], Properties), Error> {
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
        let variable = |kind, value: i64| -> Result<Variable, Error> {
            match (kind, value) {
                (0, 0..) => u32::try_from(value)
                    .map(Variable::Free)
                    .map_err(|e| Error::from(e.to_string())),
                (1, 0..) => Ok(Variable::Bound(value as u64)),
                _ => Err("invalid graph variable".into()),
            }
        };
        let child = |value: i64| -> Result<u64, Error> {
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
    fn representation(&self, node: Node<u64>) -> Result<([u8; 32], Properties, Shape), Error> {
        let mut properties = [None, None];
        let mut shapes = [None, None];
        let mut hashes = [None, None];
        for (i, child) in node.children().into_iter().enumerate() {
            if let Some(child) = child {
                let (_, hash, p) = self.raw(child)?;
                let authenticated = self
                    .authenticated(child)?
                    .filter(|(expected, properties, _)| *expected == hash && *properties == p)
                    .ok_or("formula child has not passed current-owner authentication")?;
                shapes[i] = Some(authenticated.2);
                hashes[i] = Some(hash);
                properties[i] = Some(p);
            }
        }
        let p = node
            .properties(properties)
            .ok_or("formula graph property overflow")?;
        let shape = Shape::of(node, shapes);
        let mut i = 0;
        let node = node.map(|_| {
            let hash = hashes[i].expect("graph child");
            i += 1;
            hash
        });
        Ok((format::graph_node_hash(node, p), p, shape))
    }
    fn load(&self, id: u64) -> Result<(Node<u64>, [u8; 32], Properties), Error> {
        let (node, hash, p) = self.raw(id)?;
        let (expected, properties, shape) = self.representation(node)?;
        if (expected, properties) != (hash, p) {
            return Err("formula graph content authentication failed".into());
        }
        self.remember_authenticated(id, hash, p, shape)?;
        Ok((node, hash, p))
    }
    fn authenticated(&self, id: u64) -> Result<Option<([u8; 32], Properties, Shape)>, Error> {
        let row: Option<(Vec<u8>, bool, u64, u64, u64, u64)> = sql(self
            .connection
            .query_row(
                "SELECT hash,free,required,nodes,bytes,depth FROM authenticated_node WHERE id=?1",
                [number(id)?],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        unsigned(row, 2)?,
                        unsigned(row, 3)?,
                        unsigned(row, 4)?,
                        unsigned(row, 5)?,
                    ))
                },
            )
            .optional())?;
        row.map(
            |(hash, has_free_variables, required_binders, nodes, bytes, depth)| {
                Ok((
                    hash.try_into()
                        .map_err(|_| "authenticated formula digest corruption")?,
                    Properties {
                        has_free_variables,
                        required_binders,
                    },
                    Shape {
                        nodes,
                        bytes,
                        depth,
                    },
                ))
            },
        )
        .transpose()
    }
    fn remember_authenticated(
        &self,
        id: u64,
        hash: [u8; 32],
        properties: Properties,
        shape: Shape,
    ) -> Result<(), Error> {
        sql(self.connection.execute(
            "INSERT OR IGNORE INTO authenticated_node VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                number(id)?,
                hash.as_slice(),
                properties.has_free_variables,
                number(properties.required_binders)?,
                number(shape.nodes)?,
                number(shape.bytes)?,
                number(shape.depth)?
            ],
        ))?;
        if self.authenticated(id)? != Some((hash, properties, shape)) {
            return Err("authenticated formula changed within its owner".into());
        }
        Ok(())
    }
    fn intern(&mut self, node: Node<u64>) -> Result<u64, Error> {
        let (hash, properties, shape) = self.representation(node)?;
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
        let id = u64::try_from(self.connection.last_insert_rowid())
            .map_err(|e| Error::from(e.to_string()))?;
        self.remember_authenticated(id, hash, properties, shape)?;
        Ok(id)
    }
    pub fn status(&self) -> Result<Status, Error> {
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
            program_hash: hex(&hash),
            conclusion: self
                .accepted
                .map(|id| self.load(id).map(|(_, hash, _)| hex(&hash)))
                .transpose()?,
            database_bytes: pages.saturating_mul(page_size),
        })
    }
}
impl checker::Context for Engine {
    type Formula = u64;
    type Error = Error;
    fn previous(&self, index: u64) -> Result<Value<u64>, Error> {
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
    fn implication(&self, formula: u64) -> Result<Option<(u64, u64)>, Error> {
        Ok(match self.load(formula)?.0 {
            Node::Implies(a, b) => Some((a, b)),
            _ => None,
        })
    }
    fn closed(&self, formula: u64) -> Result<bool, Error> {
        Ok(self.load(formula)?.2.closed())
    }
    fn fixed(&mut self, formula: &Formula) -> Result<u64, Error> {
        formula.fold_graph(|node| self.intern(node))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
