//! Feedback changes execution quanta and new admission only. A pressure event
//! reduces immediately; growth requires observed work and is damped.
use super::*;
use crate::resources::feedback::{self, Statistics};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct Governor {
    previous: Option<(Instant, Snapshot, Statistics)>,
    stable: u32,
    sample_cost: Duration,
    network_rate: u64,
    network_latency: u64,
}

impl Governor {
    pub(crate) fn observe(
        &mut self,
        selection: Selection,
        observed: Observed,
        capacity: u64,
    ) -> Result<Snapshot, String> {
        self.update(
            selection,
            observed,
            capacity,
            feedback::statistics(),
            observation::pressure(),
            Instant::now(),
        )
    }

    fn update(
        &mut self,
        selection: Selection,
        observed: Observed,
        capacity: u64,
        statistics: Statistics,
        pressure: [bool; 3],
        now: Instant,
    ) -> Result<Snapshot, String> {
        let mut next = Snapshot::derive(selection, observed, capacity)?;
        let quantum = super::super::limits().transport_busy_grace;
        if let Some((before_time, before, previous)) = &self.previous {
            let elapsed = now
                .saturating_duration_since(*before_time)
                .as_millis()
                .max(1) as u64;
            let cpu = next
                .observed
                .process_cpu_ms
                .saturating_sub(before.observed.process_cpu_ms)
                .saturating_mul(1000)
                / elapsed;
            let external = next.observed.load_millis.saturating_sub(cpu);
            let cpu_available = next
                .observed
                .cpu_millis
                .saturating_sub(external)
                .div_ceil(1000)
                .max(1) as usize;
            if next.selection.profile != Profile::Custom && next.selection.profile != Profile::Light
            {
                let demand =
                    statistics.queued_jobs > 0 || statistics.check.units > previous.check.units;
                let target = if demand {
                    cpu_available
                } else {
                    before.budget.concurrency.max(1).min(cpu_available)
                };
                next.budget.concurrency = approach(before.budget.concurrency.max(1), target);
                if next.selection.profile == Profile::Dynamic {
                    let quota_delay = quantum.as_millis() as u64
                        * 1000u64.saturating_sub(next.observed.cpu_millis)
                        / next.observed.cpu_millis.max(1);
                    next.budget.yield_ms = quantum.as_millis() as u64
                        * external.min(next.observed.cpu_millis)
                        / next.observed.cpu_millis.max(1)
                        + quota_delay;
                }
                let per_job = statistics.descendant_rss / statistics.running_jobs.max(1);
                if per_job > 0 {
                    next.budget.concurrency = next.budget.concurrency.min(
                        (next
                            .budget
                            .memory_bytes
                            .saturating_sub(next.observed.process_rss)
                            / per_job)
                            .max(1) as usize,
                    );
                }
            }
            if next.selection == before.selection && next.selection.profile != Profile::Custom {
                let units = statistics.check.units.saturating_sub(previous.check.units);
                let nanos = statistics.check.nanos.saturating_sub(previous.check.nanos);
                if units > 0 && nanos > 0 {
                    let target = (quantum.as_nanos().saturating_mul(u128::from(units))
                        / u128::from(nanos))
                    .max(1) as usize;
                    next.budget.batch_steps = approach(before.budget.batch_steps.max(1), target)
                        .min((next.budget.memory_bytes as usize / 8192).max(1));
                } else {
                    next.budget.batch_steps = before
                        .budget
                        .batch_steps
                        .max(1)
                        .min((next.budget.memory_bytes as usize / 8192).max(1));
                }
                let hits = statistics.cache_hits.saturating_sub(previous.cache_hits);
                let misses = statistics
                    .cache_misses
                    .saturating_sub(previous.cache_misses);
                let cache = before.budget.cache_bytes;
                next.budget.cache_bytes =
                    if hits > 0 && misses > hits && !pressure[1] && !pressure[2] {
                        cache.saturating_add((cache / 4).max(4096))
                    } else {
                        cache
                    }
                    .min(next.budget.memory_bytes / 4)
                    .max(4096);
                // Request latency, rather than CPU count, sets the pipeline.
                let requests = statistics
                    .network
                    .units
                    .saturating_sub(previous.network.units);
                let latency = statistics
                    .network
                    .nanos
                    .saturating_sub(previous.network.nanos);
                let failures = statistics
                    .failed_requests
                    .saturating_sub(previous.failed_requests);
                if failures > 0 {
                    next.budget.network_requests = (before.budget.network_requests / 2).max(1);
                } else if requests > 0 && latency > 0 {
                    let average = latency / requests;
                    let rate = requests.saturating_mul(1_000_000) / elapsed;
                    let cadence = quantum.as_nanos().max(1);
                    let pipeline = (u128::from(average)).div_ceil(cadence).max(1) as usize;
                    next.budget.network_requests = if self.network_latency > 0
                        && average > self.network_latency
                        && rate <= self.network_rate
                    {
                        (before.budget.network_requests / 2).max(1)
                    } else if statistics.pending_requests > 0
                        && (self.network_rate == 0 || rate > self.network_rate)
                    {
                        approach(before.budget.network_requests.max(1), pipeline)
                    } else {
                        before.budget.network_requests.max(1)
                    }
                    .min(super::super::limits().flights);
                    self.network_rate = rate;
                    self.network_latency = average;
                }
            }
            let constrained =
                pressure.iter().any(|pressed| *pressed) || next.budget.paused.is_some();
            self.stable = if constrained || next.selection != before.selection {
                0
            } else {
                self.stable.saturating_add(1)
            };
            if pressure[2] {
                next.budget.concurrency = next
                    .budget
                    .concurrency
                    .min((before.budget.concurrency / 2).max(1));
                next.budget.batch_steps = next
                    .budget
                    .batch_steps
                    .min((before.budget.batch_steps / 2).max(1));
                next.budget.network_requests = next
                    .budget
                    .network_requests
                    .min((before.budget.network_requests / 2).max(1));
            }
            if pressure[1] {
                next.budget.paused = Some("operating system memory pressure".into());
            }
        }
        next.budget.concurrency = next
            .budget
            .concurrency
            .min(super::super::limits().workers.iter().sum());
        if next
            .observed
            .process_rss
            .saturating_add(statistics.descendant_rss)
            > capacity
        {
            next.budget.paused = Some("node process tree memory pressure".into());
        }
        if pressure[1] {
            next.budget.paused = Some("operating system memory pressure".into());
            next.budget.cache_bytes = (next.budget.cache_bytes / 2).max(4096);
        }
        if next.budget.paused.is_some() {
            next.budget.concurrency = 0;
            next.budget.batch_steps = 0;
            next.budget.network_requests = 0;
        }
        self.previous = Some((now, next.clone(), statistics));
        Ok(next)
    }

    pub(crate) fn sampled(&mut self, elapsed: Duration) {
        self.sample_cost = elapsed;
    }

    pub(crate) fn interval(&self) -> Duration {
        let limits = super::super::limits();
        limits
            .transport_busy_grace
            .saturating_mul(self.stable.saturating_add(1))
            .max(self.sample_cost.saturating_mul(16))
            .min(
                limits
                    .control_request_timeout
                    .min(limits.replay_guard_freshness),
            )
            .max(limits.transport_busy_grace)
    }
}

fn approach(current: usize, target: usize) -> usize {
    if target < current {
        target.max(1)
    } else {
        target.min(current.saturating_add((current / 4).max(1)))
    }
}

#[cfg(test)]
mod tests;
