//! Canonical record reservations. Call sites derive use from actual transitions.

use crate::{ResearchError, codec::Writer, profile::Profile};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Capacity {
    remaining: u64,
    active: u64,
    remaining_bytes: u64,
    active_bytes: u64,
    record_bytes: u64,
    terminated: bool,
}

impl Capacity {
    pub(crate) fn new(profile: &Profile) -> Self {
        Self {
            remaining: profile.limits().run_records,
            active: 0,
            remaining_bytes: profile.limits().run_records * profile.limits().record_bytes,
            active_bytes: 0,
            record_bytes: profile.limits().record_bytes,
            terminated: false,
        }
    }
    pub(crate) fn remaining(&self) -> u64 {
        self.remaining
    }
    pub(crate) fn reserved(&self) -> u64 {
        self.active
    }
    pub(crate) fn remaining_bytes(&self) -> u64 {
        self.remaining_bytes
    }
    pub(crate) fn reserved_bytes(&self) -> u64 {
        self.active_bytes
    }
    pub(crate) fn can_open(&self, profile: &Profile) -> bool {
        !self.terminated
            && self.active == 0
            && self.remaining
                >= profile.limits().completion_records + profile.limits().terminal_records
    }
    pub(crate) fn open(&mut self, profile: &Profile) -> Result<(), ResearchError> {
        if !self.can_open(profile) {
            return Err(ResearchError::Invalid("no completion reservation"));
        }
        self.active = profile.limits().completion_records;
        self.active_bytes = self.active * self.record_bytes;
        self.active_record()
    }
    pub(crate) fn active_record(&mut self) -> Result<(), ResearchError> {
        if self.terminated || self.active == 0 || self.remaining <= 1 {
            return Err(ResearchError::Invalid("active completion capacity"));
        }
        self.active -= 1;
        self.remaining -= 1;
        self.active_bytes -= self.record_bytes;
        self.remaining_bytes -= self.record_bytes;
        Ok(())
    }
    pub(crate) fn ordinary_record(&mut self) -> Result<(), ResearchError> {
        if self.terminated || self.remaining <= self.active + 1 {
            return Err(ResearchError::Invalid("unreserved record capacity"));
        }
        self.remaining -= 1;
        self.remaining_bytes -= self.record_bytes;
        Ok(())
    }
    pub(crate) fn release(&mut self) {
        self.active = 0;
        self.active_bytes = 0;
    }
    pub(crate) fn terminate(&mut self, profile: &Profile) -> Result<(), ResearchError> {
        if self.terminated || self.active != 0 || self.remaining == 0 || self.can_open(profile) {
            return Err(ResearchError::Invalid("premature run termination"));
        }
        self.remaining -= 1;
        self.remaining_bytes -= self.record_bytes;
        self.terminated = true;
        Ok(())
    }
    pub(crate) fn encode_into(&self, writer: &mut Writer) {
        writer.u64(self.remaining);
        writer.u64(self.active);
        writer.u64(self.remaining_bytes);
        writer.u64(self.active_bytes);
        writer.u64(self.record_bytes);
        writer.u8(u8::from(self.terminated));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Limits, TimingKind};

    #[test]
    fn exact_minimum_run_protects_all_reserved_records_and_terminal_slot() {
        let profile = Profile::with_limits(
            TimingKind::ShortTest,
            Limits {
                run_records: 65,
                ..Limits::default()
            },
        )
        .unwrap();
        let mut capacity = Capacity::new(&profile);
        capacity.open(&profile).unwrap();
        assert_eq!(capacity.remaining(), 64);
        assert_eq!(capacity.reserved(), 63);
        assert!(capacity.ordinary_record().is_err());
        assert!(capacity.terminate(&profile).is_err());
        for _ in 0..63 {
            capacity.active_record().unwrap();
        }
        assert_eq!(capacity.remaining(), 1);
        assert!(capacity.active_record().is_err());
        capacity.release();
        capacity.terminate(&profile).unwrap();
        assert_eq!(capacity.remaining(), 0);
        assert!(capacity.ordinary_record().is_err());
        assert!(capacity.terminate(&profile).is_err());
    }

    #[test]
    fn queue_work_cannot_consume_active_reservation() {
        let profile = Profile::with_limits(
            TimingKind::ShortTest,
            Limits {
                run_records: 70,
                ..Limits::default()
            },
        )
        .unwrap();
        let mut capacity = Capacity::new(&profile);
        capacity.open(&profile).unwrap();
        for _ in 0..5 {
            capacity.ordinary_record().unwrap();
        }
        let before = capacity.clone();
        assert!(capacity.ordinary_record().is_err());
        assert_eq!(capacity, before);
        capacity.active_record().unwrap();
        assert_eq!(capacity.remaining(), 63);
        assert_eq!(capacity.reserved(), 62);
        capacity.release();
        assert!(!capacity.can_open(&profile));
        capacity.terminate(&profile).unwrap();
    }
}
