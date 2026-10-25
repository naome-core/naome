use super::*;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

fn database() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch("CREATE TABLE item (value INTEGER); INSERT INTO item VALUES (1)")
        .unwrap();
    connection
}

#[test]
fn rejection_restores_every_staged_write_before_returning() {
    let mut connection = database();
    let result = write(
        &mut connection,
        TransactionBehavior::Immediate,
        |error| error.to_string(),
        |transaction| {
            transaction.execute("UPDATE item SET value=2", []).unwrap();
            Err::<(), _>("rejected".to_owned())
        },
    );
    assert!(matches!(result, Err(CommitError::RolledBack(error)) if error == "rejected"));
    assert_eq!(
        connection
            .query_row("SELECT value FROM item", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    write(
        &mut connection,
        TransactionBehavior::Immediate,
        |error| error.to_string(),
        |transaction| {
            transaction
                .execute("UPDATE item SET value=3", [])
                .map_err(|error| error.to_string())?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        connection
            .query_row("SELECT value FROM item", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        3
    );
}

#[test]
fn a_denied_rollback_is_uncertain_even_if_drop_later_attempts_it_again() {
    let mut connection = database();
    connection
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
    let result = write(
        &mut connection,
        TransactionBehavior::Immediate,
        |error| error.to_string(),
        |transaction| {
            transaction.execute("UPDATE item SET value=2", []).unwrap();
            Err::<(), _>("rejected".to_owned())
        },
    );
    assert!(matches!(result, Err(CommitError::Uncertain(_))));
    connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
    connection.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        connection
            .query_row("SELECT value FROM item", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}
