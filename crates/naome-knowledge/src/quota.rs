//! Fixed-window accounting only. Traffic owners keep their own keys, table
//! capacities, fairness policy and installed protection limits.
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(crate) struct Rate {
    pub(crate) burst: usize,
    pub(crate) period: Duration,
}

pub(crate) struct Quota {
    since: Instant,
    used: usize,
}
impl Quota {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            since: now,
            used: 0,
        }
    }
    pub(crate) fn expired(&self, now: Instant, rate: Rate) -> bool {
        now.saturating_duration_since(self.since) >= rate.period
    }
    pub(crate) fn available(&self, now: Instant, rate: Rate) -> bool {
        rate.burst > 0 && (self.used < rate.burst || self.expired(now, rate))
    }
    pub(crate) fn try_take(&mut self, now: Instant, rate: Rate) -> bool {
        if self.expired(now, rate) {
            self.since = now;
            self.used = 0;
        }
        if self.used >= rate.burst {
            return false;
        }
        self.used += 1;
        true
    }
}

#[cfg(test)]
mod tests;
