//! Write outcomes belong to the transaction owner, before domain error handling.
use super::*;

pub(crate) type CommitError = naome_storage::CommitError<crate::Error>;

impl From<CommitError> for crate::Error {
    fn from(error: CommitError) -> Self {
        match error {
            CommitError::NotWritten(error) | CommitError::RolledBack(error) => error,
            CommitError::Uncertain(error) => Self::UncertainDurability(error),
        }
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
        let result = naome_storage::write(
            &mut self.connection,
            TransactionBehavior::Immediate,
            write_error,
            |transaction| {
                if version_of(transaction).map_err(crate::Error::CorruptStorage)?
                    != self.data_version
                {
                    return Err(crate::Error::CorruptStorage(
                        "transactional checkpoint changed outside its owner".into(),
                    ));
                }
                apply(transaction, self.domain, &updates)?;
                transaction
                    .execute(
                        "UPDATE checkpoint SET header = ?1, digest = ?2 WHERE singleton = 1",
                        params![
                            payload,
                            digest(self.domain, "header", "1", &payload).as_slice()
                        ],
                    )
                    .map_err(write_error)?;
                #[cfg(test)]
                if cut == Some(Cut::BeforeCommit) {
                    return Err(crate::Error::ExecutionLimit);
                }
                Ok(())
            },
        );
        #[cfg(test)]
        let result = result.and_then(|()| {
            if cut == Some(Cut::AfterCommit) {
                Err(CommitError::Uncertain(
                    "injected failure after durable checkpoint commit".into(),
                ))
            } else {
                Ok(())
            }
        });
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
