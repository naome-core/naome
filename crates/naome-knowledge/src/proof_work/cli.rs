use super::*;
use crate::resources::adaptive::{self, Snapshot};
use std::{
    ffi::OsString,
    io::BufReader,
    time::{Duration, Instant},
};

pub(crate) async fn execute(arguments: &[OsString], policy_directory: &Path) -> Result<(), String> {
    let (json, args) = if arguments.first().is_some_and(|a| a == "--json") {
        (true, &arguments[1..])
    } else {
        (false, arguments)
    };
    if args == [OsString::from("help")] {
        println!(
            "Incremental proof work: new <work.sqlite3>; append <work.sqlite3> <commands.ndjson>; run <work.sqlite3>; status <work.sqlite3>; history <work.sqlite3> [after].\nEach record produces a zero-based result. Formula construction is separate from proved results. References point backward, including across appended files. A final seal requires a proved, closed conclusion.\nExample NDJSON:\n{{\"op\":\"reflexivity\",\"variable\":0}}\n{{\"op\":\"generalization\",\"premise\":0,\"variable\":0}}\n{{\"op\":\"seal\",\"proof\":1}}\nUse naome resources dynamic|heavy|light|custom <limits.json> to change profiles while running. Interrupt run with Ctrl-C; committed input and transformation equations remain durable. Reopening rechecks saved work before accepting a proof. Program hashes use naome:proof-program:v1; they are not the bounded gossip certificate format."
        );
        return Ok(());
    }
    let usage = "usage: naome [--json] proof new|status|run <work.sqlite3> | proof append <work.sqlite3> <commands.ndjson> | proof history <work.sqlite3> [after]";
    let [command, path, rest @ ..] = args else {
        return Err(usage.into());
    };
    let path = Path::new(path);
    if command == "status" && rest.is_empty() {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspect(path)?).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if command == "history" && rest.len() <= 1 {
        let after = rest
            .first()
            .map(|v| {
                v.to_str()
                    .ok_or("history cursor must be UTF-8")?
                    .parse::<i64>()
                    .map_err(|e| e.to_string())
            })
            .transpose()?
            .unwrap_or(0);
        println!(
            "{}",
            serde_json::to_string_pretty(&history(path, after)?).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if !matches!(command.to_str(), Some("new" | "append" | "run")) {
        return Err(usage.into());
    }
    if command == "new" && path.exists() {
        return Err("proof work already exists".into());
    }
    if command != "new" && !path.exists() {
        return Err("proof work does not exist".into());
    }
    let mut work = Work::open(path)?;
    if command == "append" {
        let [source] = rest else {
            return Err(usage.into());
        };
        let file = File::open(source).map_err(|e| e.to_string())?;
        work.append_reader(&mut BufReader::new(file))?;
    } else if command == "run" {
        if !rest.is_empty() {
            return Err(usage.into());
        }
        let stopped = tokio::signal::ctrl_c();
        tokio::pin!(stopped);
        let mut next = Instant::now();
        let mut snapshot = None;
        loop {
            if Instant::now() >= next {
                let value = Snapshot::derive(
                    adaptive::load(policy_directory)?,
                    adaptive::sample(work.directory())?,
                    crate::resources::limits().memory_bytes as u64,
                )?;
                work.record_budget(&value)?;
                adaptive::publish(value.clone());
                snapshot = Some(value);
                next = Instant::now() + Duration::from_secs(1);
            }
            let budget = &snapshot
                .as_ref()
                .expect("initial budget observation")
                .budget;
            let mut shortage = false;
            let progress = match work.advance(budget) {
                Ok(progress) => progress,
                Err(error)
                    if error.starts_with("disk overload:")
                        || error.contains("database or disk is full") =>
                {
                    shortage = true;
                    false
                }
                Err(error) => return Err(error),
            };
            if !progress && budget.paused.is_none() && !shortage {
                break;
            }
            let delay = Duration::from_millis(if budget.paused.is_some() || shortage {
                250
            } else {
                budget.yield_ms.max(1)
            });
            tokio::select! {_=&mut stopped=>break,_=tokio::time::sleep(delay)=>{}}
        }
    } else if !rest.is_empty() {
        return Err(usage.into());
    }
    let status = work.status()?;
    if json {
        println!(
            "{}",
            serde_json::to_string(&status).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&status).map_err(|e| e.to_string())?
        );
    }
    Ok(())
}

fn reader(path: &Path) -> Result<Connection, String> {
    crate::storage::owned_file(path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let path = fs::canonicalize(parent)
        .map_err(|e| e.to_string())?
        .join(path.file_name().ok_or("proof work filename missing")?);
    let connection = sql(Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    ))?;
    let app: i64 = sql(connection.pragma_query_value(None, "application_id", |r| r.get(0)))?;
    if app != APPLICATION_ID {
        return Err("proof work format mismatch".into());
    }
    crate::storage::sqlite_common(&connection, 64 * 1024).map_err(|e| e.to_string())?;
    Ok(connection)
}
pub(super) fn inspect(path: &Path) -> Result<serde_json::Value, String> {
    let connection = reader(path)?;
    let (commands, committed, sealed, hash): (i64, i64, bool, Vec<u8>) = sql(connection
        .query_row(
            "SELECT commands,committed,sealed,substr(hash,1,33) FROM state WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ))?;
    let budget: Option<Vec<u8>> = sql(connection
        .query_row(
            "SELECT substr(snapshot,1,4097) FROM budget ORDER BY sequence DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional())?;
    let budget = budget
        .map(|bytes| {
            if bytes.len() > 4096 {
                return Err("budget snapshot capacity".into());
            }
            serde_json::from_slice::<Snapshot>(&bytes).map_err(|e| e.to_string())
        })
        .transpose()?;
    Ok(
        serde_json::json!({"format":naome_proof::program::FORMAT,"commands":commands,"committed_commands":committed,"sealed":sealed,"program_hash":crate::hex(&hash),"fully_checked":false,"requires_recheck":true,"last_recorded_budget":budget,"transformation_equations":sql(connection.query_row("SELECT coalesce(max(sequence),0) FROM equation",[],|r|r.get::<_,i64>(0)))?}),
    )
}
fn history(path: &Path, after: i64) -> Result<Vec<serde_json::Value>, String> {
    if after < 0 {
        return Err("history cursor must be nonnegative".into());
    }
    let connection = reader(path)?;
    let mut query=sql(connection.prepare("SELECT sequence,substr(snapshot,1,4097),command,equation FROM budget WHERE sequence>?1 ORDER BY sequence LIMIT 64"))?;
    let mut rows = sql(query.query([after]))?;
    let mut output = Vec::new();
    while let Some(row) = sql(rows.next())? {
        let bytes: Vec<u8> = sql(row.get(1))?;
        if bytes.len() > 4096 {
            return Err("budget snapshot capacity".into());
        }
        let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        output.push(serde_json::json!({"sequence":sql(row.get::<_,i64>(0))?,"snapshot":snapshot,"command":sql(row.get::<_,i64>(2))?,"equation":sql(row.get::<_,i64>(3))?}));
    }
    Ok(output)
}
