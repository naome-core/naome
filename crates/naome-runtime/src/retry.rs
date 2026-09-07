//! Volatile scheduling over the existing durable publication source.

use super::*;
use crate::FixedValidatorPublicationRetryIntervalV0;

pub(super) struct PublicationRetry {
    interval: FixedValidatorPublicationRetryIntervalV0,
    // None while a finite pass drains: missed ticks never accumulate.
    deadline: Option<Instant>,
    input_polled: bool,
}

pub(super) async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

impl<'node> FixedValidatorRuntimeV0<'node> {
    pub(super) fn recover_next_publication(&mut self) -> Option<Event<'node>> {
        if self.publication.is_none()
            && let Some((state_id, admit_locally)) = self.recovery.front().copied()
        {
            let recovered = (|| {
                let history = self.driver.as_ref().unwrap().publication_history()?;
                let entry = history
                    .entries()
                    .find(|entry| entry.state_id() == state_id)
                    .ok_or(PublicationError::Invalid)?;
                let mut publication = Publication::from_history(
                    entry,
                    &self.peers,
                    self.publication_journal.as_ref().unwrap(),
                )?;
                if !admit_locally {
                    publication.local_admission = crate::publication::LocalAdmission::Skipped;
                }
                Ok::<_, PublicationError>(publication)
            })();
            match recovered {
                Ok(publication) => {
                    self.recovery.pop_front();
                    let size = publication.message().size();
                    self.publication = Some(publication);
                    return Some(Event::PublicationRecovered { state_id, size });
                }
                Err(error) => return Some(self.publication_failure(error)),
            }
        }
        None
    }

    /// Enables explicitly configured periodic delivery retries before polling.
    /// Requires the durable publication journal. Restart starts a fresh interval;
    /// no timer, missed tick, or transport ticket is restored from storage.
    pub fn with_publication_retry_interval(
        mut self,
        interval: FixedValidatorPublicationRetryIntervalV0,
    ) -> Result<Self, PublicationError> {
        if self.publication_journal.is_none() {
            return Err(PublicationError::RetryRequiresJournal);
        }
        if self.retry.is_some()
            || self.publication.is_some()
            || self.timer.is_some()
            || self.pending_input.is_some()
            || self.driver.is_none()
        {
            return Err(PublicationError::AlreadyEnabled);
        }
        let deadline = interval.deadline().map_err(PublicationError::Timing)?;
        self.retry = Some(PublicationRetry {
            interval,
            deadline: Some(deadline),
            input_polled: false,
        });
        Ok(self)
    }

    pub(super) fn queue_publication_debt(
        &mut self,
        peer_mask: u8,
    ) -> Result<usize, PublicationError> {
        let journal = self.publication_journal.as_ref().unwrap();
        let history = self.driver.as_ref().unwrap().publication_history()?;
        let mut entries = Vec::new();
        for entry in history.entries() {
            let id = entry.state_id();
            let missing = (0..self.peers.len())
                .any(|peer| peer_mask & (1 << peer) != 0 && !journal.received(id, peer));
            if missing
                && !self.recovery.iter().any(|queued| queued.0 == id)
                && !self
                    .publication
                    .as_ref()
                    .is_some_and(|active| active.message.state_id() == id)
            {
                entries.try_reserve(1)?;
                let phase = match entry.phase() {
                    FixedValidatorLockPhaseV0::Proposal => 0,
                    FixedValidatorLockPhaseV0::Prevote => 1,
                    FixedValidatorLockPhaseV0::Precommit => 2,
                };
                entries.push((
                    (
                        entry.position().height().value(),
                        entry.position().round().value(),
                        phase,
                    ),
                    id,
                ));
            }
        }
        entries.sort_unstable_by_key(|entry| entry.0);
        self.recovery.try_reserve(entries.len())?;
        let count = entries.len();
        self.recovery
            .extend(entries.into_iter().map(|entry| (entry.1, false)));
        Ok(count)
    }

    pub(super) fn queue_reconnected_debt(&mut self) -> Result<(), PublicationError> {
        if self.publication.is_none() && self.recovery.is_empty() && self.reconnected_peers != 0 {
            self.queue_publication_debt(self.reconnected_peers)?;
            self.reconnected_peers = 0;
        }
        Ok(())
    }

    pub(super) fn finish_retry_pass(&mut self) -> Result<(), PublicationError> {
        if self.publication.is_none()
            && self.recovery.is_empty()
            && let Some(retry) = &mut self.retry
            && retry.deadline.is_none()
        {
            retry.deadline = Some(
                retry
                    .interval
                    .deadline()
                    .map_err(PublicationError::Timing)?,
            );
            retry.input_polled = false;
        }
        Ok(())
    }

    pub(super) fn retry_deadline(&self) -> Option<Instant> {
        if self.publication.is_some() || !self.recovery.is_empty() {
            return None;
        }
        self.retry.as_ref().and_then(|retry| retry.deadline)
    }

    pub(super) async fn retry_or_input(&mut self) -> Result<PendingInput, Event<'node>> {
        if !self.retry.as_ref().unwrap().input_polled {
            // A ready transport event gets one opportunity before each pass,
            // even when the configured interval is shorter than one poll.
            let _ = self.poll_transport_once().await;
            self.retry.as_mut().unwrap().input_polled = true;
        }
        if self
            .observable_timer()
            .is_some_and(|timer| Instant::now() >= timer.deadline())
        {
            return Err(self.observe_due());
        }
        if let Some(input) = self.pending_input.take() {
            return Ok(input);
        }
        let queued = match self.queue_publication_debt(u8::MAX) {
            Ok(queued) => queued,
            Err(error) => return Err(self.publication_failure(error)),
        };
        self.retry.as_mut().unwrap().deadline = None;
        if let Err(error) = self.finish_retry_pass() {
            return Err(self.publication_failure(error));
        }
        Err(Event::PublicationRetryScheduled { queued })
    }
}
