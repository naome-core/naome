//! Process-local observations only. They influence scheduling, never validity,
//! durable obligation allowances, peer authority or external custody deadlines.
use serde::{Deserialize, Serialize};
use std::{
    sync::Mutex,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
mod provider;
pub(crate) use provider::{Disposition, Meter};
pub use provider::{Phase, Providers, Role, Sample};

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Check,
    Compact,
    Network,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Work {
    pub units: u64,
    pub nanos: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statistics {
    pub check: Work,
    pub compact: Work,
    pub network: Work,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub queued_jobs: u64,
    pub running_jobs: u64,
    pub descendant_rss: u64,
    pub pending_requests: u64,
    pub failed_requests: u64,
    pub empty_finding_streak: u64,
    pub providers: Providers,
}

struct Counter {
    units: AtomicU64,
    nanos: AtomicU64,
}
impl Counter {
    const fn new() -> Self {
        Self {
            units: AtomicU64::new(0),
            nanos: AtomicU64::new(0),
        }
    }
    fn read(&self) -> Work {
        Work {
            units: self.units.load(Ordering::Relaxed),
            nanos: self.nanos.load(Ordering::Relaxed),
        }
    }
}
static CHECK: Counter = Counter::new();
static COMPACT: Counter = Counter::new();
static NETWORK: Counter = Counter::new();
static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static PROVIDERS: Mutex<Providers> = Mutex::new(Providers::empty());
static DESCENDANTS: AtomicU64 = AtomicU64::new(0);
static PENDING: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);
static EMPTY_FINDING: AtomicU64 = AtomicU64::new(0);

pub(crate) fn record(kind: Kind, units: usize, elapsed: Duration) {
    let counter = match kind {
        Kind::Check => &CHECK,
        Kind::Compact => &COMPACT,
        Kind::Network => &NETWORK,
    };
    counter.units.fetch_add(units as u64, Ordering::Relaxed);
    counter.nanos.fetch_add(
        elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
}
pub(crate) fn cache(hit: bool) {
    (if hit { &HITS } else { &MISSES }).fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn jobs(queued: [usize; 4], running: [usize; 4]) {
    let mut providers = PROVIDERS.lock().unwrap_or_else(|error| error.into_inner());
    for role in Role::ALL {
        let entry = providers.get_mut(role);
        entry.queued = queued[role.index()] as u64;
        entry.running = running[role.index()] as u64;
    }
}
pub(crate) fn provider_sample(role: Role, phase: Phase, sample: Sample) {
    PROVIDERS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get_mut(role)
        .record(phase, sample);
}
pub(crate) fn provider_checkpoint(role: Role) {
    let mut providers = PROVIDERS.lock().unwrap_or_else(|error| error.into_inner());
    let entry = providers.get_mut(role);
    entry.checkpointed_units = entry.checkpointed_units.saturating_add(1);
}
pub(crate) fn provider_wait(role: Role, elapsed: Duration) {
    let mut providers = PROVIDERS.lock().unwrap_or_else(|error| error.into_inner());
    let entry = providers.get_mut(role);
    entry.admission_wait_nanos = entry
        .admission_wait_nanos
        .saturating_add(provider::nanos(elapsed));
}
pub(crate) fn provider_finished(
    role: Role,
    disposition: Disposition,
    service: Duration,
    sample: Sample,
) {
    PROVIDERS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get_mut(role)
        .finish(disposition, service, sample);
}
pub(crate) fn network_backlog(pending: usize) {
    PENDING.store(pending as u64, Ordering::Relaxed);
}
pub(crate) fn finding_result(found: bool) {
    if found {
        EMPTY_FINDING.store(0, Ordering::Relaxed);
    } else {
        let _ = EMPTY_FINDING.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(1))
        });
    }
}
pub(crate) fn network_failure() {
    FAILED.fetch_add(1, Ordering::Relaxed);
}
pub(super) fn descendants(rss: u64) {
    DESCENDANTS.store(rss, Ordering::Relaxed);
}
pub fn statistics() -> Statistics {
    let providers = *PROVIDERS.lock().unwrap_or_else(|error| error.into_inner());
    Statistics {
        check: CHECK.read(),
        compact: COMPACT.read(),
        network: NETWORK.read(),
        cache_hits: HITS.load(Ordering::Relaxed),
        cache_misses: MISSES.load(Ordering::Relaxed),
        queued_jobs: Role::ALL.iter().fold(0u64, |count, role| {
            count.saturating_add(providers.get(*role).queued)
        }),
        running_jobs: Role::ALL.iter().fold(0u64, |count, role| {
            count.saturating_add(providers.get(*role).running)
        }),
        descendant_rss: DESCENDANTS.load(Ordering::Relaxed),
        pending_requests: PENDING.load(Ordering::Relaxed),
        failed_requests: FAILED.load(Ordering::Relaxed),
        empty_finding_streak: EMPTY_FINDING.load(Ordering::Relaxed),
        providers,
    }
}
