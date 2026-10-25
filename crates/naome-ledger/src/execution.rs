//! Host execution policy; these limits never change transaction validity.
use crate::Error;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// Conservative charged state and SQLite cache ceilings for one ledger session.
/// Larger valid histories may require a larger host budget or a different store.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub state_bytes: usize,
    pub sqlite_cache_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            state_bytes: 8 * 1024 * 1024,
            sqlite_cache_bytes: 1024 * 1024,
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<Self, Error> {
        if self.state_bytes == 0
            || self.state_bytes > isize::MAX as usize
            || self.sqlite_cache_bytes < 1024
            || self.sqlite_cache_bytes > isize::MAX as usize
        {
            return Err(Error::Invalid("invalid ledger execution budget"));
        }
        Ok(self)
    }
}

/// One operation's absolute deadline and shared cancellation signal.
/// Clones cancel the same operation. Create a fresh control for each session call.
#[derive(Debug, Clone)]
pub struct Control {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}
impl Default for Control {
    fn default() -> Self {
        Self::until(Instant::now() + Duration::from_secs(30))
    }
}
impl Control {
    pub fn until(deadline: Instant) -> Self {
        Self {
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn check(&self) -> Result<(), Error> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    }
}
