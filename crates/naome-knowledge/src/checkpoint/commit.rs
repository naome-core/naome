//! Write outcomes belong to the transaction owner, before domain error handling.
use super::*;

#[derive(Debug)]
pub(crate) enum CommitError {
    NotWritten(crate::Error),
    RolledBack(crate::Error),
    Uncertain(String),
}

impl From<CommitError> for crate::Error {
    fn from(error: CommitError) -> Self {
        match error {
            CommitError::NotWritten(error) | CommitError::RolledBack(error) => error,
            CommitError::Uncertain(error) => Self::UncertainDurability(error),
        }
    }
}
impl From<CommitError> for String {
    fn from(error: CommitError) -> Self {
        // String-returning domain owners stop after a failed save because their
        // in-memory delta may already have changed. Retry-capable consumers keep
        // the operation error instead of guessing durability from its text.
        crate::Error::from(error).to_string()
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cut {
    BeforeWrite,
    BeforeCommit,
    AfterCommit,
}
#[cfg(test)]
thread_local! { static CUT: std::cell::Cell<Option<Cut>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
pub(crate) fn fail_next_commit() {
    CUT.with(|cut| cut.set(Some(Cut::BeforeWrite)));
}
#[cfg(test)]
pub(crate) fn fail_after_commit() {
    CUT.with(|cut| cut.set(Some(Cut::AfterCommit)));
}

impl Checkpoint {
    pub(crate) fn commit(
        &mut self,
        header: &impl Serialize,
        updates: Vec<Update>,
    ) -> Result<(), super::CommitError> {
        #[cfg(test)]
        let cut = CUT.with(|cut| cut.take());
        if let Some(error) = &self.uncertain {
            return Err(CommitError::Uncertain(error.clone()));
        }
        #[cfg(test)]
        if cut == Some(Cut::BeforeWrite) {
            return Err(CommitError::NotWritten(crate::Error::ExecutionLimit));
        }
        self.ensure_generation()
            .map_err(|error| CommitError::NotWritten(crate::Error::CorruptStorage(error)))?;
        let payload = encode(header)
            .map_err(|error| CommitError::NotWritten(crate::Error::InvalidInput(error)))?;
        if payload.len() > MAX_HEADER {
            return Err(CommitError::NotWritten(crate::Error::InputLimit(
                "checkpoint header capacity",
            )));
        }
        let result =
            (|| {
                let transaction = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|error| CommitError::NotWritten(write_error(error)))?;
                let staged =
                    (|| -> Result<(), crate::Error> {
                        if version_of(&transaction).map_err(crate::Error::CorruptStorage)?
                            != self.data_version
                        {
                            return Err(crate::Error::CorruptStorage(
                                "transactional checkpoint changed outside its owner".into(),
                            ));
                        }
                        apply(&transaction, self.domain, &updates)?;
                        transaction
                    .execute(
                        "UPDATE checkpoint SET header = ?1, digest = ?2 WHERE singleton = 1",
                        params![payload, digest(self.domain, "header", "1", &payload).as_slice()],
                    )
                    .map_err(write_error)?;
                        #[cfg(test)]
                        if cut == Some(Cut::BeforeCommit) {
                            return Err(crate::Error::ExecutionLimit);
                        }
                        Ok(())
                    })();
                if let Err(error) = staged {
                    return Err(rollback(transaction, error));
                }
                // Keep the transaction after a failed COMMIT so rollback can be
                // observed. Transaction::commit consumes it and hides Drop errors.
                if let Err(error) = transaction.execute_batch("COMMIT") {
                    if transaction.is_autocommit() {
                        return Err(CommitError::Uncertain(sql(error)));
                    }
                    return Err(rollback(transaction, write_error(error)));
                }
                drop(transaction);
                #[cfg(test)]
                if cut == Some(Cut::AfterCommit) {
                    return Err(CommitError::Uncertain(
                        "injected failure after durable checkpoint commit".into(),
                    ));
                }
                Ok(())
            })();
        if let Err(CommitError::Uncertain(error)) = &result {
            // No read or later write may infer which version won. A fresh
            // checkpoint owner must replay the canonical records after reopen.
            self.uncertain = Some(error.clone());
        }
        result?;
        #[cfg(test)]
        {
            self.last_write = (
                updates.len() + 1,
                payload.len()
                    + updates
                        .iter()
                        .map(|update| match update {
                            Update::Put { payload, .. } => payload.len(),
                            _ => 0,
                        })
                        .sum::<usize>(),
            );
        }
        Ok(())
    }
}

fn rollback(transaction: rusqlite::Transaction<'_>, error: crate::Error) -> CommitError {
    if transaction.is_autocommit() {
        // Staging may fail after SQLite has already rolled back. No COMMIT was
        // attempted on that branch, so the old records are still authoritative.
        return CommitError::RolledBack(error);
    }
    match transaction.rollback() {
        Ok(()) => CommitError::RolledBack(error),
        Err(rollback) => CommitError::Uncertain(format!(
            "{error}; checkpoint rollback is unconfirmed: {rollback}"
        )),
    }
}

pub(super) fn write_error(error: rusqlite::Error) -> crate::Error {
    if matches!(&error, rusqlite::Error::SqliteFailure(code, _) if matches!(code.code,
        rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
        | rusqlite::ErrorCode::DiskFull | rusqlite::ErrorCode::OutOfMemory))
    {
        crate::Error::ExecutionLimit
    } else {
        crate::Error::CorruptStorage(sql(error))
    }
}

#[cfg(test)]
mod tests;
