use crate::lean::{Checked, Lean, Rejection, Step};
use crate::{Action, Reference, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

const LEAN_TOOLCHAIN: &str = include_str!("../lean-toolchain");
const LEAN_LIBRARIES: &str = include_str!("../lake-manifest.json");

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EntryId([u8; 32]);

impl EntryId {
    pub fn lean_name(self) -> String {
        format!("NaomeArchive.e_{self}")
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for EntryId {
    type Err = Box<dyn std::error::Error>;

    fn from_str(text: &str) -> Result<Self> {
        if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("archive IDs have 64 hexadecimal digits".into());
        }
        let mut id = [0; 32];
        for (byte, offset) in id.iter_mut().zip((0..64).step_by(2)) {
            *byte = u8::from_str_radix(&text[offset..offset + 2], 16)?;
        }
        Ok(Self(id))
    }
}

impl TryFrom<String> for EntryId {
    type Error = Box<dyn std::error::Error>;

    fn try_from(text: String) -> Result<Self> {
        text.parse()
    }
}

impl From<EntryId> for String {
    fn from(id: EntryId) -> Self {
        id.to_string()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Artifact {
    Proof {
        target: String,
        steps: Vec<Action>,
        #[serde(default)]
        dependencies: Vec<EntryId>,
    },
    Definition {
        target: String,
        value: String,
        #[serde(default)]
        dependencies: Vec<EntryId>,
    },
}

impl Artifact {
    pub fn target(&self) -> &str {
        match self {
            Self::Proof { target, .. } | Self::Definition { target, .. } => target,
        }
    }

    pub fn dependencies(&self) -> &[EntryId] {
        match self {
            Self::Proof { dependencies, .. } | Self::Definition { dependencies, .. } => {
                dependencies
            }
        }
    }

    pub fn normalize(&mut self) -> Result<()> {
        let (dependencies, steps) = match self {
            Self::Proof {
                dependencies,
                steps,
                ..
            } => (dependencies, Some(steps)),
            Self::Definition { dependencies, .. } => (dependencies, None),
        };
        let mut ids: BTreeSet<_> = dependencies.iter().copied().collect();
        if let Some(steps) = steps {
            for step in steps {
                step.validate()?;
                match step.argument {
                    Some(Reference::Archived(id)) => {
                        ids.insert(id);
                    }
                    Some(Reference::Catalog(_)) => {
                        return Err(
                            "archive proofs require durable IDs for catalog arguments".into()
                        );
                    }
                    _ => {}
                }
            }
        }
        *dependencies = ids.into_iter().collect();
        Ok(())
    }

    pub fn id(&self) -> Result<EntryId> {
        let mut hash = Sha256::new();
        for part in [
            LEAN_TOOLCHAIN.as_bytes(),
            LEAN_LIBRARIES.as_bytes(),
            &serde_json::to_vec(self)?,
        ] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part);
        }
        Ok(EntryId(hash.finalize().into()))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Verification {
    pub id: EntryId,
    pub checker_calls: usize,
    pub axioms: Vec<String>,
}

pub struct Archive {
    connection: Connection,
    pub(crate) lean: Lean,
    verified: HashMap<EntryId, Vec<String>>,
}

impl Archive {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS declaration (
                id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 32),
                artifact BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS declaration_symbols (
                id BLOB PRIMARY KEY REFERENCES declaration(id) ON DELETE CASCADE,
                symbols TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS symbol_entry (
                symbol TEXT NOT NULL,
                id BLOB NOT NULL REFERENCES declaration_symbols(id) ON DELETE CASCADE,
                PRIMARY KEY (symbol, id)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS symbol_entry_id ON symbol_entry(id, symbol);",
        )?;
        Self::connect(connection)
    }

    pub fn open_for_replay(path: &Path) -> Result<Self> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        Self::connect(connection)
    }

    fn connect(connection: Connection) -> Result<Self> {
        Ok(Self {
            connection,
            lean: Lean::spawn()?,
            verified: HashMap::new(),
        })
    }

    pub fn read(&self, id: EntryId) -> Result<Artifact> {
        let bytes: Vec<u8> = self
            .connection
            .prepare_cached("SELECT artifact FROM declaration WHERE id = ?1")?
            .query_row([id.0.as_slice()], |row| row.get(0))
            .optional()?
            .ok_or_else(|| format!("missing archived declaration {id}"))?;
        let mut artifact: Artifact = serde_json::from_slice(&bytes)?;
        artifact.normalize()?;
        if serde_json::to_vec(&artifact)? != bytes || artifact.id()? != id {
            return Err(format!("invalid archived declaration {id}").into());
        }
        Ok(artifact)
    }

    pub fn replay(&mut self, id: EntryId) -> Result<Verification> {
        let before = self.lean.checker_calls();
        self.load(&[id])?;
        Ok(Verification {
            id,
            checker_calls: self.lean.checker_calls() - before,
            axioms: self.verified[&id].clone(),
        })
    }

    pub fn compile(&mut self, mut artifact: Artifact) -> Result<Verification> {
        artifact.normalize()?;
        let id = artifact.id()?;
        if let Some(axioms) = self.verified.get(&id) {
            return Ok(Verification {
                id,
                checker_calls: 0,
                axioms: axioms.clone(),
            });
        }
        let before = self.lean.checker_calls();
        self.load(artifact.dependencies())?;
        let Checked { axioms, symbols } = self.verify(id, &artifact)?;
        self.store(id, &artifact, &axioms, symbols)?;
        Ok(Verification {
            id,
            checker_calls: self.lean.checker_calls() - before,
            axioms,
        })
    }

    pub(crate) fn try_compile_fragment(
        &mut self,
        artifact: Artifact,
    ) -> Result<Option<Verification>> {
        match self.compile(artifact) {
            Ok(verified) => Ok(Some(verified)),
            Err(error) if error.is::<Rejection>() => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn finish_search(
        &mut self,
        mut artifact: Artifact,
        state: usize,
    ) -> Result<Option<Verification>> {
        artifact.normalize()?;
        let id = artifact.id()?;
        if let Some(axioms) = self.verified.get(&id) {
            return Ok(Some(Verification {
                id,
                checker_calls: 0,
                axioms: axioms.clone(),
            }));
        }
        let names = names(artifact.dependencies());
        let Some(Checked { axioms, symbols }) =
            self.lean.finish_candidate(state, &id.lean_name(), &names)?
        else {
            return Ok(None);
        };
        self.store(id, &artifact, &axioms, symbols)?;
        Ok(Some(Verification {
            id,
            checker_calls: 1,
            axioms,
        }))
    }

    pub(crate) fn load(&mut self, roots: &[EntryId]) -> Result<()> {
        enum Load {
            Read(EntryId),
            Verify(EntryId, Artifact),
        }
        let mut stack: Vec<_> = roots.iter().rev().copied().map(Load::Read).collect();
        let mut visiting = HashSet::new();
        while let Some(work) = stack.pop() {
            match work {
                Load::Read(id) => {
                    if self.verified.contains_key(&id) {
                        continue;
                    }
                    if !visiting.insert(id) {
                        return Err(format!("cyclic archive dependency {id}").into());
                    }
                    let artifact = self.read(id)?;
                    let dependencies = artifact.dependencies().to_vec();
                    stack.push(Load::Verify(id, artifact));
                    stack.extend(dependencies.into_iter().rev().map(Load::Read));
                }
                Load::Verify(id, artifact) => {
                    let checked = self.verify(id, &artifact)?;
                    self.verified.insert(id, checked.axioms);
                    visiting.remove(&id);
                }
            }
        }
        Ok(())
    }

    fn verify(&mut self, id: EntryId, artifact: &Artifact) -> Result<Checked> {
        let name = id.lean_name();
        let names = names(artifact.dependencies());
        match artifact {
            Artifact::Proof { target, steps, .. } => {
                let mut view = self.lean.start(target)?;
                for (offset, step) in steps.iter().enumerate() {
                    match self.lean.step(view.state, step)? {
                        Step::Accepted(next) => view = next,
                        Step::Rejected(error) => {
                            return Err(Rejection(format!(
                                "Lean rejected action {}: {error}",
                                offset + 1
                            ))
                            .into());
                        }
                    }
                }
                self.lean.finish(view.state, &name, &names)
            }
            Artifact::Definition { target, value, .. } => {
                self.lean.define(target, value, &name, &names)
            }
        }
    }

    fn store(
        &mut self,
        id: EntryId,
        artifact: &Artifact,
        axioms: &[String],
        mut symbols: Vec<String>,
    ) -> Result<()> {
        symbols.sort_unstable();
        symbols.dedup();
        let bytes = serde_json::to_vec(artifact)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT OR IGNORE INTO declaration(id, artifact) VALUES (?1, ?2)",
            params![id.0.as_slice(), &bytes],
        )?;
        let existing: Vec<u8> = transaction.query_row(
            "SELECT artifact FROM declaration WHERE id = ?1",
            [id.0.as_slice()],
            |row| row.get(0),
        )?;
        if existing != bytes {
            return Err(format!("archive identity conflict for {id}").into());
        }
        let signature = serde_json::to_string(&symbols)?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO declaration_symbols(id, symbols) VALUES (?1, ?2)",
            params![id.0.as_slice(), signature],
        )?;
        if inserted != 0 {
            let mut insert =
                transaction.prepare("INSERT INTO symbol_entry(symbol, id) VALUES (?1, ?2)")?;
            for symbol in symbols {
                insert.execute(params![symbol, id.0.as_slice()])?;
            }
        }
        transaction.commit()?;
        self.verified.insert(id, axioms.to_vec());
        Ok(())
    }

    pub(crate) fn has_entries(&self) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM declaration_symbols)",
            [],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn retrieve(&self, query: &[String], limit: usize) -> Result<Vec<EntryId>> {
        if query.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let query = query.iter().map(String::as_str).collect::<BTreeSet<_>>();
        let snapshot = self.connection.unchecked_transaction()?;
        let population: i64 =
            snapshot.query_row("SELECT count(*) FROM declaration_symbols", [], |row| {
                row.get(0)
            })?;
        let mut candidates = snapshot.prepare(
            "SELECT DISTINCT posting.id
             FROM json_each(?1) query JOIN symbol_entry posting ON posting.symbol = query.value
             ORDER BY posting.id",
        )?;
        let mut ids = candidates.query([serde_json::to_string(&query)?])?;
        let mut signatures =
            snapshot.prepare_cached("SELECT symbols FROM declaration_symbols WHERE id = ?1")?;
        let mut frequency =
            snapshot.prepare_cached("SELECT count(*) FROM symbol_entry WHERE symbol = ?1")?;
        let mut weights = HashMap::new();
        let mut ranked = Vec::<(EntryId, f64)>::new();
        while let Some(row) = ids.next()? {
            let id = EntryId(row.get(0)?);
            let encoded: String = signatures.query_row([id.0.as_slice()], |row| row.get(0))?;
            let signature: Vec<String> = serde_json::from_str(&encoded)?;
            let mut shared = 0.0;
            let mut extra = 0.0;
            for symbol in &signature {
                let weight = if let Some(&weight) = weights.get(symbol) {
                    weight
                } else {
                    let occurrences: i64 = frequency.query_row([symbol], |row| row.get(0))?;
                    if occurrences == 0 {
                        return Err("missing archive symbol posting".into());
                    }
                    let weight = (1.0 + population as f64 / occurrences as f64).ln();
                    if weights.len() < 4_096 {
                        weights.insert(symbol.clone(), weight);
                    }
                    weight
                };
                if query.contains(symbol.as_str()) {
                    shared += weight;
                } else {
                    extra += weight;
                }
            }
            let score = shared / (1.0 + 0.35 * extra);
            let index = ranked
                .binary_search_by(|(previous, value)| {
                    score.total_cmp(value).then_with(|| previous.cmp(&id))
                })
                .unwrap_or_else(|index| index);
            if index < limit {
                ranked.insert(index, (id, score));
                ranked.truncate(limit);
            }
        }
        Ok(ranked.into_iter().map(|(id, _)| id).collect())
    }
}

fn names(ids: &[EntryId]) -> Vec<String> {
    ids.iter().map(|id| id.lean_name()).collect()
}
