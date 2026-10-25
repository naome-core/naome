//! Native two-point CPU accounting. Host busy time and node CPU time use the
//! same interval; load average is deliberately not used as CPU utilization.
use std::{
    sync::{Mutex, OnceLock},
    time::Instant,
};

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::resources::adaptive) struct Load {
    pub external_percent: u16,
    pub available_millis: u64,
}

#[derive(Default)]
struct Sampler {
    system: sysinfo::System,
    previous: Option<(Instant, u64)>,
    last: Option<Load>,
}

pub(super) fn sample(node_cpu_ms: u64, capacity_millis: u64) -> Option<Load> {
    static SAMPLER: OnceLock<Mutex<Sampler>> = OnceLock::new();
    let mut sampler = SAMPLER
        .get_or_init(|| Mutex::new(Sampler::default()))
        .lock()
        .ok()?;
    let now = Instant::now();
    if sampler.previous.is_some_and(|(before, _)| {
        now.saturating_duration_since(before) < sysinfo::MINIMUM_CPU_UPDATE_INTERVAL
    }) {
        return sampler.last;
    }
    sampler.system.refresh_cpu_usage();
    let previous = sampler.previous.replace((now, node_cpu_ms));
    sampler.last = previous.and_then(|(before, own)| {
        let elapsed = now.saturating_duration_since(before).as_millis();
        let node_delta = node_cpu_ms.checked_sub(own)?;
        let cores = sampler.system.cpus().len() as u64;
        let busy = sampler.system.global_cpu_usage();
        account(cores, busy, node_delta, elapsed, capacity_millis)
    });
    sampler.last
}

fn account(
    cores: u64,
    busy_percent: f32,
    node_delta_ms: u64,
    elapsed_ms: u128,
    capacity_millis: u64,
) -> Option<Load> {
    if cores == 0
        || elapsed_ms == 0
        || !busy_percent.is_finite()
        || !(0.0..=100.0).contains(&busy_percent)
    {
        return None;
    }
    let host = cores.checked_mul(1000)?;
    let busy = (f64::from(busy_percent) * host as f64 / 100.0) as u64;
    let own = (u128::from(node_delta_ms) * 1000 / elapsed_ms).min(u128::from(host)) as u64;
    let external = busy.saturating_sub(own);
    Some(Load {
        external_percent: (external.saturating_mul(100) / host) as u16,
        available_millis: capacity_millis.min(host.saturating_sub(external)),
    })
}

#[cfg(test)]
mod tests;
