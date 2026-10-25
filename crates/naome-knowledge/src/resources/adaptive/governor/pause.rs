//! One pause decision with sustained CPU pressure and a quiet recovery window.
use super::*;
const HIGH_CPU: u16 = 85;
const CLEAR_CPU: u16 = 60;
const CPU_CONFIRM: Duration = Duration::from_secs(10);
const RECOVERY: Duration = Duration::from_secs(30);

#[derive(Default)]
pub(super) struct Pause {
    reason: Option<String>,
    high_since: Option<Instant>,
    clear_since: Option<Instant>,
    needs_cpu: bool,
    needs_power: bool,
    needs_thermal: bool,
}
impl Pause {
    pub(super) fn unavailable(&mut self) {
        self.reason = Some("hardware observation unavailable".into());
        self.clear_since = None;
        self.high_since = None;
    }
    pub(super) fn apply(
        &mut self,
        next: &mut Snapshot,
        pressure: Pressure,
        descendants: u64,
        capacity: u64,
        now: Instant,
    ) {
        let high = pressure
            .cpu
            .is_some_and(|cpu| cpu.external_percent >= HIGH_CPU);
        if !high {
            self.high_since = None;
        }
        let cpu_pressure = high
            && now.saturating_duration_since(*self.high_since.get_or_insert(now)) >= CPU_CONFIRM;
        let trigger = next.budget.paused.clone().or_else(|| {
            if pressure.low_power == Some(true) {
                Some("operating system power saving".into())
            } else if pressure.thermal == Some(true) {
                Some("operating system thermal pressure".into())
            } else if cpu_pressure {
                Some("sustained external CPU pressure".into())
            } else {
                None
            }
        });
        self.needs_cpu |= cpu_pressure;
        self.needs_power |= pressure.low_power == Some(true);
        self.needs_thermal |= pressure.thermal == Some(true);
        if let Some(reason) = trigger {
            self.reason = Some(reason);
            self.clear_since = None;
        } else if self.reason.is_some() {
            let memory_margin = (next.budget.memory_bytes / 10).max(MIB);
            let disk_margin = (super::super::super::limits().disk_reserve_bytes / 2).max(2 * MIB);
            let clear = next.observed.process_rss.saturating_add(memory_margin)
                <= next.budget.memory_bytes
                && next
                    .observed
                    .process_rss
                    .saturating_add(descendants)
                    .saturating_add(capacity / 10)
                    <= capacity
                && next.observed.disk_available
                    >= super::super::super::limits()
                        .disk_reserve_bytes
                        .saturating_add(2 * MIB)
                        .saturating_add(disk_margin)
                && (!self.needs_cpu
                    || pressure
                        .cpu
                        .is_some_and(|cpu| cpu.external_percent < CLEAR_CPU))
                && (!self.needs_power || pressure.low_power == Some(false))
                && (!self.needs_thermal || pressure.thermal == Some(false));
            if clear {
                if now.saturating_duration_since(*self.clear_since.get_or_insert(now)) >= RECOVERY {
                    self.reason = None;
                    self.clear_since = None;
                    self.needs_cpu = false;
                    self.needs_power = false;
                    self.needs_thermal = false;
                }
            } else {
                self.clear_since = None;
            }
        }
        next.budget.paused = self.reason.clone();
    }
}
