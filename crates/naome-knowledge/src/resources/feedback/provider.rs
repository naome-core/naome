//! Bounded scheduling observations. These are not job accounting or validity.
use super::*;
use nix::sys::time::TimeValLike;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Finding,
    Solving,
    LocalInterest,
    PeerInterest,
}
impl Role {
    pub(crate) const ALL: [Self; 4] = [
        Self::Finding,
        Self::Solving,
        Self::LocalInterest,
        Self::PeerInterest,
    ];
    pub(crate) const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum Phase {
    Setup,
    Unit { unit: u32 },
    Finalization,
}

/// The provider worker's own CPU/peak RSS. Live descendants are independently
/// observed by the node's process-tree sampler and retain their existing limits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub elapsed_nanos: u64,
    pub blocked_nanos: u64,
    pub cpu_nanos: Option<u64>,
    pub peak_rss_bytes: Option<u64>,
    pub check: Work,
    pub succeeded: bool,
}
impl Sample {
    pub(crate) fn validate(self, elapsed: Duration) -> bool {
        self.blocked_nanos <= self.elapsed_nanos
            && u128::from(self.elapsed_nanos) <= elapsed.as_nanos()
            && self
                .peak_rss_bytes
                .is_none_or(|bytes| bytes > 0 && bytes <= isize::MAX as u64)
            && (self.check.units != 0 || self.check.nanos == 0)
    }
}

pub(crate) struct Meter {
    start: Instant,
    cpu: Option<u64>,
    check: Work,
}
impl Meter {
    pub(crate) fn start() -> Self {
        Self {
            start: Instant::now(),
            cpu: usage().0,
            check: statistics().check,
        }
    }
    pub(crate) fn finish(self, blocked_nanos: u64, succeeded: bool) -> Sample {
        let (cpu, peak_rss_bytes) = usage();
        let check = statistics().check;
        let elapsed_nanos = nanos(self.start.elapsed());
        let units = check.units.saturating_sub(self.check.units);
        Sample {
            elapsed_nanos,
            blocked_nanos: blocked_nanos.min(elapsed_nanos),
            cpu_nanos: cpu
                .zip(self.cpu)
                .and_then(|(after, before)| after.checked_sub(before)),
            peak_rss_bytes,
            check: Work {
                units,
                nanos: if units == 0 {
                    0
                } else {
                    check.nanos.saturating_sub(self.check.nanos)
                },
            },
            succeeded,
        }
    }
}
fn usage() -> (Option<u64>, Option<u64>) {
    let Ok(usage) = nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_SELF) else {
        return (None, None);
    };
    let cpu = usage
        .user_time()
        .num_microseconds()
        .checked_add(usage.system_time().num_microseconds())
        .and_then(|value| u64::try_from(value).ok())
        .and_then(|value| value.checked_mul(1000));
    let peak = u64::try_from(usage.max_rss()).ok();
    #[cfg(target_os = "linux")]
    let peak = peak.and_then(|value| value.checked_mul(1024));
    (cpu, peak.filter(|value| *value > 0))
}
pub(crate) fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cost {
    pub samples: u64,
    pub elapsed_nanos: u64,
    pub blocked_nanos: u64,
    pub cpu_nanos: u64,
    pub cpu_samples: u64,
    pub peak_rss_bytes: u64,
    pub check: Work,
}
impl Cost {
    fn record(&mut self, sample: Sample) {
        self.samples = self.samples.saturating_add(1);
        self.elapsed_nanos = self.elapsed_nanos.saturating_add(sample.elapsed_nanos);
        self.blocked_nanos = self.blocked_nanos.saturating_add(sample.blocked_nanos);
        if let Some(cpu) = sample.cpu_nanos {
            self.cpu_nanos = self.cpu_nanos.saturating_add(cpu);
            self.cpu_samples = self.cpu_samples.saturating_add(1);
        }
        self.peak_rss_bytes = self.peak_rss_bytes.max(sample.peak_rss_bytes.unwrap_or(0));
        self.check.units = self.check.units.saturating_add(sample.check.units);
        self.check.nanos = self.check.nanos.saturating_add(sample.check.nanos);
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provider {
    pub setup: Cost,
    pub work: Cost,
    pub finalization: Cost,
    pub checkpointed_units: u64,
    pub admission_wait_nanos: u64,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub expired: u64,
    pub uncertain: u64,
    /// Recent complete-attempt service time, including startup/cleanup and
    /// durable IPC, excluding waits at the computation admission gate.
    pub service_nanos: u64,
    /// Paired recent phase costs from complete attempts. Unknown CPU falls
    /// back to hardware concurrency and can recover on the next valid sample.
    pub active_nanos: u64,
    pub cpu_nanos: Option<u64>,
    pub queued: u64,
    pub running: u64,
}
#[derive(Clone, Copy)]
pub(crate) enum Disposition {
    Complete,
    Failed,
    Cancelled,
    Expired,
    Uncertain,
}
impl Provider {
    pub(super) fn record(&mut self, phase: Phase, sample: Sample) {
        match phase {
            Phase::Setup => &mut self.setup,
            Phase::Unit { .. } => &mut self.work,
            Phase::Finalization => &mut self.finalization,
        }
        .record(sample);
    }
    pub(super) fn finish(&mut self, disposition: Disposition, service: Duration, sample: Sample) {
        let count = match disposition {
            Disposition::Complete => {
                let measured = nanos(service).max(1);
                let active = sample.elapsed_nanos.saturating_sub(sample.blocked_nanos);
                let paired = self.cpu_nanos.zip(sample.cpu_nanos);
                self.active_nanos = if self.completed > 0 && paired.is_some() {
                    average(self.active_nanos, active)
                } else {
                    active
                };
                self.cpu_nanos = match paired {
                    Some((before, after)) if self.completed > 0 => Some(average(before, after)),
                    _ => sample.cpu_nanos,
                };
                self.service_nanos = if self.completed == 0 {
                    measured
                } else {
                    average(self.service_nanos, measured)
                };
                &mut self.completed
            }
            Disposition::Failed => &mut self.failed,
            Disposition::Cancelled => &mut self.cancelled,
            Disposition::Expired => &mut self.expired,
            Disposition::Uncertain => &mut self.uncertain,
        };
        *count = count.saturating_add(1);
    }
    pub(crate) fn interval(self, slots: usize, minimum: Duration, ceiling: Duration) -> Duration {
        if self.completed == 0 {
            return ceiling;
        }
        Duration::from_nanos(self.service_nanos.div_ceil(slots.max(1) as u64))
            .max(minimum)
            .min(ceiling)
    }
}
fn average(before: u64, after: u64) -> u64 {
    ((u128::from(before) * 3 + u128::from(after)) / 4) as u64
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Providers {
    pub finding: Provider,
    pub solving: Provider,
    pub local_interest: Provider,
    pub peer_interest: Provider,
}
impl Providers {
    /// Measured CPU duty permits I/O overlap only after every demanding role
    /// has known CPU observations spanning at least one scheduling quantum.
    pub(crate) fn cpu_slots(&self, available_millis: u64, quantum: Duration) -> Option<usize> {
        let mut per_job = 0;
        for role in Role::ALL {
            let provider = self.get(role);
            if provider.queued == 0 && provider.running == 0 {
                continue;
            }
            let cpu = provider.cpu_nanos?;
            let active = u128::from(provider.active_nanos);
            if provider.completed == 0 || active < quantum.as_nanos() {
                return None;
            }
            per_job = per_job.max((u128::from(cpu).saturating_mul(1000).div_ceil(active)).max(1));
        }
        (per_job > 0).then(|| {
            (u128::from(available_millis) / per_job)
                .max(1)
                .min(usize::MAX as u128) as usize
        })
    }
    pub(crate) fn peak_worker_bytes(&self) -> u64 {
        Role::ALL
            .into_iter()
            .filter_map(|role| {
                let provider = self.get(role);
                (provider.queued > 0 || provider.running > 0).then_some(
                    provider
                        .setup
                        .peak_rss_bytes
                        .max(provider.work.peak_rss_bytes)
                        .max(provider.finalization.peak_rss_bytes),
                )
            })
            .max()
            .unwrap_or(0)
    }
    pub(super) const fn empty() -> Self {
        const COST: Cost = Cost {
            samples: 0,
            elapsed_nanos: 0,
            blocked_nanos: 0,
            cpu_nanos: 0,
            cpu_samples: 0,
            peak_rss_bytes: 0,
            check: Work { units: 0, nanos: 0 },
        };
        const ROLE: Provider = Provider {
            setup: COST,
            work: COST,
            finalization: COST,
            checkpointed_units: 0,
            admission_wait_nanos: 0,
            completed: 0,
            failed: 0,
            cancelled: 0,
            expired: 0,
            uncertain: 0,
            service_nanos: 0,
            active_nanos: 0,
            cpu_nanos: None,
            queued: 0,
            running: 0,
        };
        Self {
            finding: ROLE,
            solving: ROLE,
            local_interest: ROLE,
            peer_interest: ROLE,
        }
    }
    pub(crate) fn get(&self, role: Role) -> &Provider {
        match role {
            Role::Finding => &self.finding,
            Role::Solving => &self.solving,
            Role::LocalInterest => &self.local_interest,
            Role::PeerInterest => &self.peer_interest,
        }
    }
    pub(super) fn get_mut(&mut self, role: Role) -> &mut Provider {
        match role {
            Role::Finding => &mut self.finding,
            Role::Solving => &mut self.solving,
            Role::LocalInterest => &mut self.local_interest,
            Role::PeerInterest => &mut self.peer_interest,
        }
    }
}

#[cfg(test)]
mod tests;
