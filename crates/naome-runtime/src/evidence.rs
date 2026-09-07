//! Persistence fences for retained raw custody, separate from signer journals.
use super::*;
use crate::evidence_journal::{
    EvidenceJournal, FixedValidatorEvidenceJournalErrorV0 as EvidenceError,
};

impl<'node> FixedValidatorRuntimeV0<'node> {
    /// Opts a fresh runtime into bounded durable inbox custody. Reopen verifies
    /// the complete saved image before the first arm or publication can transfer.
    /// Any failure consumes this runtime and releases its owned journal locks.
    pub fn with_evidence_journal(
        mut self,
        directory: &Path,
        create: bool,
    ) -> Result<Self, EvidenceError> {
        if self.evidence_journal.is_some()
            || self.timer.is_some()
            || self.publication.is_some()
            || self.pending_input.is_some()
            || self.pending_arm.is_some()
        {
            return Err(EvidenceError::AlreadyEnabled);
        }
        let driver = self.driver.as_ref().ok_or(EvidenceError::Invalid)?;
        let limit = driver.retained_evidence_image_limit()?;
        let initial = driver.retained_evidence_image()?;
        let journal = EvidenceJournal::open(directory, create, initial, limit)?;
        let driver = self
            .driver
            .take()
            .ok_or(EvidenceError::Invalid)?
            .restore_retained_evidence(journal.image())?;
        self.driver = Some(driver);
        self.evidence_journal = Some(journal);
        Ok(self)
    }
    pub const fn evidence_journal_enabled(&self) -> bool {
        self.evidence_journal.is_some()
    }
    pub(super) fn persist_evidence(&mut self) -> Result<(), EvidenceError> {
        if let Some(journal) = &mut self.evidence_journal {
            let driver = self.driver.as_ref().ok_or(EvidenceError::Invalid)?;
            journal.save(driver.retained_evidence_image()?)?;
        }
        Ok(())
    }
    pub(super) fn fail_evidence(&mut self, error: EvidenceError) -> Event<'node> {
        self.driver.take();
        Event::Fatal(Box::new(Failure::Evidence(error)))
    }
    pub(super) fn persist_disposal(&mut self) -> bool {
        if let Err(error) = self.persist_evidence() {
            self.driver.take();
            self.evidence_failure = Some(error);
            false
        } else {
            true
        }
    }
}
