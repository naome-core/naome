//! One local sampling lifecycle. The native node publishes its live budget;
//! program consumers borrow it or retain this same conservative observer.
use super::*;
use std::time::Instant;

#[derive(Debug)]
pub(crate) enum ObservationError {
    Settings(crate::Error),
    Unavailable(crate::Error),
}
impl std::fmt::Display for ObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Settings(error) => error.fmt(f),
            Self::Unavailable(error) => error.fmt(f),
        }
    }
}
impl From<ObservationError> for crate::Error {
    fn from(error: ObservationError) -> Self {
        match error {
            ObservationError::Unavailable(cause) => Self::ObservationUnavailable(Box::new(cause)),
            ObservationError::Settings(error) => error,
        }
    }
}

pub(crate) struct Observer {
    snapshot: Option<Snapshot>,
    next: Instant,
    governor: Governor,
    failure_reported: bool,
}
impl Default for Observer {
    fn default() -> Self {
        Self {
            snapshot: None,
            next: Instant::now(),
            governor: Governor::default(),
            failure_reported: false,
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
        selection: impl FnOnce() -> Result<Selection, crate::Error>,
        sample: impl FnOnce() -> Result<observation::Sample, crate::Error>,
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
            Ok(snapshot) => {
                self.failure_reported = false;
                (snapshot, true)
            }
            Err(error) => {
                let snapshot = match self.governor.unavailable(selection) {
                    Some(snapshot) => snapshot,
                    None => return Err(ObservationError::Unavailable(error)),
                };
                if !self.failure_reported {
                    crate::runtime::emit_log(&failure_event(&error));
                    self.failure_reported = true;
                }
                (snapshot, false)
            }
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

fn failure_event(error: &crate::Error) -> serde_json::Value {
    serde_json::json!({
        "event": crate::outcome::NodeEvent::ResourceObservationFailure,
        "error": error,
    })
}

#[cfg(test)]
mod tests;
