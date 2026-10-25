//! One local sampling lifecycle. The native node publishes its live budget;
//! program consumers borrow it or retain this same conservative observer.
use super::*;
use std::time::Instant;

#[derive(Debug)]
pub(crate) enum ObservationError {
    Settings(String),
    Unavailable(String),
}
impl std::fmt::Display for ObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Settings(message) | Self::Unavailable(message) => f.write_str(message),
        }
    }
}
impl From<ObservationError> for crate::Error {
    fn from(error: ObservationError) -> Self {
        match error {
            ObservationError::Unavailable(_) => Self::ExecutionLimit,
            ObservationError::Settings(message) => Self::InvalidInput(message),
        }
    }
}

pub(crate) struct Observer {
    snapshot: Option<Snapshot>,
    next: Instant,
    governor: Governor,
}
impl Default for Observer {
    fn default() -> Self {
        Self {
            snapshot: None,
            next: Instant::now(),
            governor: Governor::default(),
        }
    }
}
impl Observer {
    pub(crate) fn due(&self, now: Instant) -> bool {
        now >= self.next
    }
    pub(crate) fn refresh(&mut self, directory: &Path) -> Result<&Snapshot, crate::Error> {
        if let Some(active) = current() {
            self.snapshot = Some(active);
        } else {
            self.poll(directory)?;
        }
        self.snapshot.as_ref().ok_or(crate::Error::ExecutionLimit)
    }
    pub(crate) fn poll(&mut self, directory: &Path) -> Result<Option<&Snapshot>, ObservationError> {
        self.poll_with(
            Instant::now(),
            || load(directory),
            || sample_node(directory),
        )
    }
    fn poll_with(
        &mut self,
        now: Instant,
        selection: impl FnOnce() -> Result<Selection, String>,
        sample: impl FnOnce() -> Result<observation::Sample, String>,
    ) -> Result<Option<&Snapshot>, ObservationError> {
        if !self.due(now) {
            return Ok(None);
        }
        let started = Instant::now();
        let selection = selection().map_err(ObservationError::Settings)?;
        let observed = sample().and_then(|sample| {
            self.governor.observe(
                selection.clone(),
                sample,
                super::super::limits().memory_bytes as u64,
                now,
            )
        });
        let (snapshot, valid) = match observed {
            Ok(snapshot) => (snapshot, true),
            Err(error) => (
                self.governor
                    .unavailable(selection)
                    .ok_or(ObservationError::Unavailable(error))?,
                false,
            ),
        };
        let elapsed = started.elapsed();
        self.governor.sampled(elapsed);
        let interval = self.governor.interval();
        self.next = now
            + elapsed
            + if valid {
                interval
            } else {
                interval.min(std::time::Duration::from_secs(1))
            };
        self.snapshot = Some(snapshot);
        Ok(self.snapshot.as_ref())
    }
}

#[cfg(test)]
mod tests;
