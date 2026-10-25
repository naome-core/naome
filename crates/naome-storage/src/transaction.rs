use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::fmt::Display;

/// Whether a failed write is known to have left the previous state intact.
#[derive(Debug)]
pub enum CommitError<E> {
    NotWritten(E),
    RolledBack(E),
    Uncertain(String),
}

/// Stages and commits one write, observing rollback before returning a rejection.
///
/// `classify` belongs to the store: contention and resource exhaustion need not
/// mean corruption. A successful return establishes commit, not domain validity.
/// An uncertain result requires the owner to stop reads and writes until replay.
/// The staging closure must leave COMMIT/ROLLBACK control to this function.
pub fn write<T, E: Display>(
    connection: &mut Connection,
    behavior: TransactionBehavior,
    classify: impl Fn(rusqlite::Error) -> E,
    stage: impl FnOnce(&Transaction<'_>) -> Result<T, E>,
) -> Result<T, CommitError<E>> {
    let transaction = connection
        .transaction_with_behavior(behavior)
        .map_err(|error| CommitError::NotWritten(classify(error)))?;
    let value = match stage(&transaction) {
        Ok(value) => value,
        Err(error) => return Err(rollback(transaction, error)),
    };
    // Keep ownership after COMMIT fails so rollback is observed explicitly.
    if let Err(error) = transaction.execute_batch("COMMIT") {
        if transaction.is_autocommit() {
            return Err(CommitError::Uncertain(error.to_string()));
        }
        return Err(rollback(transaction, classify(error)));
    }
    Ok(value)
}

fn rollback<E: Display>(transaction: Transaction<'_>, error: E) -> CommitError<E> {
    if transaction.is_autocommit() {
        return CommitError::RolledBack(error);
    }
    match transaction.rollback() {
        Ok(()) => CommitError::RolledBack(error),
        Err(rollback) => {
            CommitError::Uncertain(format!("{error}; rollback is unconfirmed: {rollback}"))
        }
    }
}

#[cfg(test)]
mod tests;
