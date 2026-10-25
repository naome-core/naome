//! One calculation for original wall-time, charged-time and work-unit bounds.
//! Callers retain their distinct launch, reservation and recovery transitions.
use super::{Limits, Record, journal::Account};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Allowance {
    pub remaining_ms: u64,
    pub remaining_units: u32,
}

impl Allowance {
    fn at(limits: Limits, expires_ms: u64, spent_ms: u64, reserved_units: u32, now: u64) -> Self {
        Self {
            remaining_ms: expires_ms
                .saturating_sub(now)
                .min(limits.horizon_ms.saturating_sub(spent_ms)),
            remaining_units: limits.work_units.saturating_sub(reserved_units),
        }
    }
    pub(super) fn time_expired(self) -> bool {
        self.remaining_ms == 0
    }
    pub(super) fn can_reserve(self) -> bool {
        !self.time_expired() && self.remaining_units > 0
    }
    fn intersect(self, other: Self) -> Self {
        Self {
            remaining_ms: self.remaining_ms.min(other.remaining_ms),
            remaining_units: self.remaining_units.min(other.remaining_units),
        }
    }
}

impl Account {
    pub(super) fn allowance(&self, now: u64) -> Allowance {
        Allowance::at(
            self.settings.limits,
            self.expires_ms,
            self.spent_ms,
            self.reserved_units,
            now,
        )
    }
}

impl Record {
    pub(super) fn allowance(&self, original: Option<&Account>, now: u64) -> Allowance {
        let own = Allowance::at(
            self.settings.limits,
            self.expires_ms,
            self.spent_ms,
            self.reserved_units,
            now,
        );
        original.map_or(own, |account| own.intersect(account.allowance(now)))
    }
}

#[cfg(test)]
mod tests;
