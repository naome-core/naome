//! One current proof-work schema, shared by evaluation and cache retirement.
use super::Error;
use rusqlite::{Connection, TransactionBehavior};

pub const APPLICATION_ID: i64 = 0x4e415057;

const OBJECTS: [(&str, &str, &str); 7] = [
    (
        "table",
        "state",
        "CREATE TABLE state(id INTEGER PRIMARY KEY CHECK(id=1), commands INTEGER NOT NULL, committed INTEGER NOT NULL, sealed INTEGER NOT NULL, hash BLOB NOT NULL CHECK(length(hash)=32)) STRICT",
    ),
    (
        "table",
        "input",
        "CREATE TABLE input(position INTEGER PRIMARY KEY, command BLOB NOT NULL CHECK(length(command)<=4096), hash BLOB NOT NULL CHECK(length(hash)=32)) STRICT",
    ),
    (
        "table",
        "result",
        "CREATE TABLE result(position INTEGER PRIMARY KEY, node INTEGER NOT NULL, proved INTEGER NOT NULL CHECK(proved IN (0,1))) STRICT",
    ),
    (
        "table",
        "node",
        "CREATE TABLE node(id INTEGER PRIMARY KEY, hash BLOB NOT NULL UNIQUE CHECK(length(hash)=32), tag INTEGER NOT NULL, a INTEGER NOT NULL, b INTEGER NOT NULL, ak INTEGER NOT NULL, bk INTEGER NOT NULL, free INTEGER NOT NULL, required INTEGER NOT NULL) STRICT",
    ),
    (
        "table",
        "equation",
        "CREATE TABLE equation(sequence INTEGER PRIMARY KEY, position INTEGER NOT NULL, operation INTEGER NOT NULL, source INTEGER NOT NULL, depth INTEGER NOT NULL, result INTEGER NOT NULL, UNIQUE(position,operation,source,depth)) STRICT",
    ),
    (
        "index",
        "equation_order",
        "CREATE INDEX equation_order ON equation(position,operation,sequence)",
    ),
    (
        "table",
        "budget",
        "CREATE TABLE budget(sequence INTEGER PRIMARY KEY, snapshot BLOB NOT NULL CHECK(length(snapshot)<=4096), command INTEGER NOT NULL, equation INTEGER NOT NULL) STRICT",
    ),
];

pub(super) fn initialize(connection: &mut Connection) -> Result<(), Error> {
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if application == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let objects: i64 =
            transaction.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
        if objects != 0 {
            return Err("unknown proof work database".into());
        }
        for (_, _, sql) in OBJECTS {
            transaction.execute_batch(sql)?;
        }
        transaction.execute("INSERT INTO state VALUES(1,0,0,0,zeroblob(32))", [])?;
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        transaction.commit()?;
    }
    verify_database(connection)
}

/// Checks the current proof-work identity and schema without initializing or
/// changing the database. This grants no mathematical validity to its records.
pub fn verify_database(connection: &Connection) -> Result<(), Error> {
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if application != APPLICATION_ID {
        return Err("proof work format mismatch".into());
    }
    let mut statement = connection.prepare(
        "SELECT substr(type,1,17), substr(name,1,65), substr(sql,1,4097)
         FROM main.sqlite_schema WHERE sql IS NOT NULL ORDER BY name",
    )?;
    let mut rows = statement.query([])?;
    let mut found = 0;
    while let Some(row) = rows.next()? {
        let kind: String = row.get(0)?;
        let name: String = row.get(1)?;
        let sql: String = row.get(2)?;
        let expected = OBJECTS
            .iter()
            .find(|(expected_kind, expected_name, _)| {
                *expected_kind == kind && *expected_name == name
            })
            .ok_or("unexpected proof work schema object")?;
        if sql.len() > 4096 || normalize_sql(&sql) != normalize_sql(expected.2) {
            return Err("proof work schema differs from the current contract".into());
        }
        found += 1;
    }
    if found != OBJECTS.len() {
        return Err("incomplete proof work schema".into());
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests;
