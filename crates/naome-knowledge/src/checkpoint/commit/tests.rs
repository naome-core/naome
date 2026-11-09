use super::*;
use crate::checkpoint::tests::Directory;

fn checkpoint(directory: &Directory) -> Checkpoint {
    Checkpoint::create(
        &directory.0.join("checkpoint.sqlite3"),
        "test",
        &1u64,
        vec![Update::put("record", "one", &1u64).unwrap()],
    )
    .unwrap()
}

#[test]
fn rejected_input_and_busy_begin_are_known_unwritten_and_retryable_only_when_transient() {
    let directory = Directory::new();
    let mut checkpoint = checkpoint(&directory);
    let error = checkpoint
        .commit(&"x".repeat(MAX_HEADER), vec![])
        .unwrap_err();
    assert!(matches!(
        error,
        CommitError::NotWritten(crate::Error::InputLimit(_))
    ));
    assert!(!crate::Error::from(error).retryable());
    assert_eq!(checkpoint.header::<u64>().unwrap(), 1);

    checkpoint
        .connection
        .busy_timeout(std::time::Duration::ZERO)
        .unwrap();
    let writer = Connection::open(&checkpoint.path).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let error = checkpoint.commit(&2u64, vec![]).unwrap_err();
    assert!(matches!(
        error,
        CommitError::NotWritten(crate::Error::ExecutionLimit)
    ));
    assert!(crate::Error::from(error).retryable());
    drop(writer);
    checkpoint.commit(&2u64, vec![]).unwrap();
    assert_eq!(checkpoint.header::<u64>().unwrap(), 2);
}

#[test]
fn confirmed_rollback_restores_every_staged_row_and_allows_the_same_operation_again() {
    let directory = Directory::new();
    let mut checkpoint = checkpoint(&directory);
    CUT.with(|cut| cut.set(Some(Cut::BeforeCommit)));
    let error = checkpoint
        .commit(&2u64, vec![Update::put("record", "one", &2u64).unwrap()])
        .unwrap_err();
    assert!(matches!(
        error,
        CommitError::RolledBack(crate::Error::ExecutionLimit)
    ));
    assert_eq!(checkpoint.header::<u64>().unwrap(), 1);
    assert_eq!(checkpoint.get::<u64>("record", "one", 32).unwrap(), Some(1));
    checkpoint
        .commit(&2u64, vec![Update::put("record", "one", &2u64).unwrap()])
        .unwrap();
    assert_eq!(checkpoint.header::<u64>().unwrap(), 2);
    assert_eq!(checkpoint.get::<u64>("record", "one", 32).unwrap(), Some(2));
}

#[test]
fn busy_commit_is_retryable_after_its_rollback_is_confirmed() {
    let directory = Directory::new();
    let mut checkpoint = checkpoint(&directory);
    checkpoint
        .connection
        .busy_timeout(std::time::Duration::ZERO)
        .unwrap();
    let reader = Connection::open(&checkpoint.path).unwrap();
    reader
        .execute_batch("BEGIN DEFERRED; SELECT header FROM checkpoint")
        .unwrap();
    let error = checkpoint
        .commit(&2u64, vec![Update::put("record", "one", &2u64).unwrap()])
        .unwrap_err();
    assert!(matches!(
        error,
        CommitError::RolledBack(crate::Error::ExecutionLimit)
    ));
    drop(reader);
    assert_eq!(checkpoint.header::<u64>().unwrap(), 1);
    assert_eq!(checkpoint.get::<u64>("record", "one", 32).unwrap(), Some(1));
    checkpoint
        .commit(&2u64, vec![Update::put("record", "one", &2u64).unwrap()])
        .unwrap();
    assert_eq!(checkpoint.header::<u64>().unwrap(), 2);
    assert_eq!(checkpoint.get::<u64>("record", "one", 32).unwrap(), Some(2));
}

#[test]
fn uncertain_commit_blocks_the_old_owner_and_reopen_recovers_the_durable_result() {
    let directory = Directory::new();
    let mut checkpoint = checkpoint(&directory);
    fail_after_commit();
    let error = checkpoint
        .commit(&2u64, vec![Update::put("record", "one", &2u64).unwrap()])
        .unwrap_err();
    assert!(matches!(
        error,
        CommitError::Uncertain(naome_storage::UncertainCommit::Commit { sqlite_code: None })
    ));
    let error = crate::Error::from(error);
    assert!(error.fatal() && !error.retryable());
    assert_eq!(
        serde_json::to_value(error).unwrap(),
        serde_json::json!({
            "code": 0x0003_0001,
            "retryable": false,
            "fatal": true,
        })
    );
    assert!(checkpoint.header::<u64>().is_err());
    assert!(checkpoint.require_kinds(&["record"]).is_err());
    assert!(matches!(
        checkpoint.commit(&3u64, vec![]),
        Err(CommitError::Uncertain(_))
    ));
    drop(checkpoint);
    let checkpoint = Checkpoint::open(&directory.0.join("checkpoint.sqlite3"), "test").unwrap();
    assert_eq!(checkpoint.header::<u64>().unwrap(), 2);
    assert_eq!(checkpoint.get::<u64>("record", "one", 32).unwrap(), Some(2));
}

#[test]
fn an_unconfirmed_rollback_never_becomes_a_known_rejection() {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    let directory = Directory::new();
    let mut checkpoint = checkpoint(&directory);
    checkpoint
        .connection
        .authorizer(Some(|context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Transaction {
                    operation: TransactionOperation::Rollback
                }
            ) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }))
        .unwrap();
    CUT.with(|cut| cut.set(Some(Cut::BeforeCommit)));
    assert!(matches!(
        checkpoint.commit(&2u64, vec![Update::put("record", "one", &2u64).unwrap()]),
        Err(CommitError::Uncertain(_))
    ));
    assert!(checkpoint.header::<u64>().is_err());
    checkpoint
        .connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
    drop(checkpoint);
    let checkpoint = Checkpoint::open(&directory.0.join("checkpoint.sqlite3"), "test").unwrap();
    assert_eq!(checkpoint.header::<u64>().unwrap(), 1);
    assert_eq!(checkpoint.get::<u64>("record", "one", 32).unwrap(), Some(1));
}

#[test]
fn fatal_write_error_preserves_sqlite_cause_and_remains_nonretryable() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY); INSERT INTO t VALUES (1);")
        .unwrap();
    let source = db.execute("INSERT INTO t VALUES (1)", []).unwrap_err();
    let (reason, sqlite_code) = crate::error::sqlite_fault(&source);
    let failure = write_error(source);
    assert!(failure.fatal());
    assert!(!failure.retryable());
    assert_eq!(
        failure,
        crate::Error::Stored(Box::new(crate::Error::CheckpointSql {
            reason,
            sqlite_code
        }))
    );
    let value = serde_json::to_value(failure).unwrap();
    assert_eq!(
        value["cause_code"],
        u32::from(crate::outcome::OperationCode::CheckpointSql)
    );
    assert_eq!(value["sqlite_code"], sqlite_code.unwrap().get());
}
