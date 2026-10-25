//! One projection from the live budget to bounded local working sets. Capacity
//! and format validation deliberately do not call this projection.
use super::{Limits, adaptive::Budget};

pub(super) fn derive(capacity: &Limits, budget: &Budget) -> Limits {
    derive_with_statistics(capacity, budget, super::feedback::statistics())
}

fn derive_with_statistics(
    capacity: &Limits,
    budget: &Budget,
    statistics: super::feedback::Statistics,
) -> Limits {
    let mut work = capacity.clone();
    let memory = usize::try_from(budget.memory_bytes).unwrap_or(usize::MAX);
    let batch = budget.batch_steps.max(1);
    let slots = budget.concurrency.max(1);
    let cache = usize::try_from(budget.cache_bytes).unwrap_or(usize::MAX);
    let caches = cache_capacity(capacity);
    let share = |ceiling: usize| {
        ((ceiling as u128 * cache as u128 / caches as u128) as usize)
            .max(1024)
            .min(ceiling)
    };
    macro_rules! cache_fields { ($($field:ident),+ $(,)?) => { $(work.$field = share(capacity.$field);)+ }; }
    cache_fields!(
        registry_index_cache_bytes,
        checked_index_cache_bytes,
        checkpoint_cache_bytes,
        catalog_cache_bytes,
        checked_cache_bytes,
        checker_cache_bytes,
        question_cache_bytes
    );
    work.checker_cache_entries = capacity
        .checker_cache_entries
        .min(work.checker_cache_bytes / 512);
    macro_rules! pages { ($($field:ident),+ $(,)?) => { $(work.$field = capacity.$field.min(batch);)+ }; }
    pages!(
        pending_page,
        replay_page,
        id_page,
        inventory_page,
        status_page,
        question_page,
        terminal_job_page,
        compaction_records
    );
    macro_rules! queues { ($($field:ident),+ $(,)?) => { $(work.$field = capacity.$field.min(slots.saturating_add(batch));)+ }; }
    queues!(
        transport_events,
        supervisor_commands,
        provider_events,
        question_commands,
        job_commands,
        cli_commands,
        control_clients,
        inbound_frames,
        queued_jobs_per_role,
        queued_metadata,
        waiters_per_job
    );
    macro_rules! concurrency { ($($field:ident),+ $(,)?) => { $(work.$field = capacity.$field.min(slots);)+ }; }
    concurrency!(
        finding_admissions,
        interest_decisions,
        solving_jobs,
        publications,
        application_queries,
        dht_parallelism
    );
    work.active_job_bytes = capacity.active_job_bytes.min(memory / 8).max(1);
    work.batch_objects = capacity.batch_objects.min(batch).max(1);
    work.batch_bytes = capacity.batch_bytes.min(memory / 8).max(1);
    work.compaction_bytes = capacity
        .compaction_bytes
        .min(memory / 8)
        .max(naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES);
    work.fetches = capacity
        .fetches
        .min(batch.max(budget.network_requests))
        .max(1);
    work.flights = capacity.flights.min(budget.network_requests);
    work.flights_per_peer = capacity.flights_per_peer.min(work.flights.max(1));
    work.exchange_streams = capacity.exchange_streams.min(work.flights.max(1));
    work.inbound_streams = capacity
        .inbound_streams
        .min(work.flights.saturating_add(slots).max(1));
    let quantum = capacity.transport_busy_grace;
    let check_nanos = statistics.check.nanos / statistics.check.units.max(1);
    let compact_nanos = statistics.compact.nanos / statistics.compact.units.max(1);
    if compact_nanos > 0 {
        work.compaction_records = work
            .compaction_records
            .min((quantum.as_nanos() / u128::from(compact_nanos)).max(1) as usize);
    }
    // Check feedback is process-local, while autonomous work runs in child
    // providers. Until this owner has a measurement, preserve the configured
    // cadence instead of interpreting a zero sample as the minimum quantum.
    let measured = (statistics.check.units > 0).then(|| {
        std::time::Duration::from_nanos(check_nanos.saturating_mul(batch as u64)).max(quantum)
    });
    let base_interval = measured.unwrap_or(capacity.finding_interval);
    let busy = statistics.queued_jobs > 0 || statistics.running_jobs > 0;
    work.tick_interval = if busy {
        base_interval.min(capacity.tick_interval)
    } else {
        capacity.tick_interval
    };
    work.job_tick_interval = if busy {
        base_interval.min(capacity.job_tick_interval)
    } else {
        capacity.job_tick_interval
    };
    work.finding_interval = base_interval
        .saturating_mul(
            1u32.checked_shl(statistics.empty_finding_streak.min(31) as u32)
                .unwrap_or(u32::MAX),
        )
        .min(capacity.finding_interval)
        .max(quantum);
    work.solving_interval = measured
        .unwrap_or(capacity.solving_interval)
        .min(capacity.solving_interval)
        .max(quantum);
    work.production_interval = measured
        .unwrap_or(capacity.production_interval)
        .min(capacity.production_interval)
        .max(quantum);
    // Existing buffers/requests retain their admission. Smaller limits only
    // pace new work; callers must never truncate a retained row to fit them.
    work.resident_jobs = capacity.resident_jobs;
    work
}

#[cfg(test)]
mod tests;

fn cache_capacity(capacity: &Limits) -> usize {
    capacity
        .registry_index_cache_bytes
        .saturating_mul(capacity.retained_generations + 2)
        .saturating_add(
            capacity
                .checked_index_cache_bytes
                .saturating_mul(capacity.retained_generations + 2),
        )
        .saturating_add(capacity.checkpoint_cache_bytes.saturating_mul(3))
        .saturating_add(capacity.catalog_cache_bytes)
        .saturating_add(capacity.checked_cache_bytes)
        .saturating_add(capacity.checker_cache_bytes)
        .saturating_add(capacity.question_cache_bytes)
        .saturating_add(
            capacity
                .checked_cache_bytes
                .saturating_mul(capacity.publications.saturating_mul(2).saturating_add(4)),
        )
        .max(1)
}

pub(super) fn program_cache(capacity: &Limits, budget: u64) -> u64 {
    ((u128::from(budget) * capacity.checked_cache_bytes as u128 / cache_capacity(capacity) as u128)
        .min(u128::from(u64::MAX)) as u64)
        .max(4096)
        .min(budget)
}
