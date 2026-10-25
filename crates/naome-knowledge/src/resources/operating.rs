//! One projection from the live budget to bounded local working sets. Capacity
//! and format validation deliberately do not call this projection.
use super::{Limits, OperatingLimits, adaptive::Budget};

// The existing capacity table marks the work fields. Consume two entries per
// step so the complete policy remains below Rust's default macro depth.
macro_rules! operating_fields {
    (@select [$($field:ident: $ty:ty;)*]) => {
        /// Process-local working sets only; format, authority and custody
        /// ceilings are available exclusively from the installed Limits.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(crate) struct OperatingLimits { $(pub(crate) $field: $ty,)* }
        impl OperatingLimits {
            fn at_capacity(capacity: &Limits) -> Self {
                Self { $($field: capacity.$field,)* }
            }
        }
    };
    (@select [$($selected:tt)*] work $a:ident: $ta:ty; work $b:ident: $tb:ty; $($rest:tt)*) => {
        operating::operating_fields!(@select [$($selected)* $a: $ta; $b: $tb;] $($rest)*);
    };
    (@select [$($selected:tt)*] work $a:ident: $ta:ty; capacity $b:ident: $tb:ty; $($rest:tt)*) => {
        operating::operating_fields!(@select [$($selected)* $a: $ta;] $($rest)*);
    };
    (@select [$($selected:tt)*] capacity $a:ident: $ta:ty; work $b:ident: $tb:ty; $($rest:tt)*) => {
        operating::operating_fields!(@select [$($selected)* $b: $tb;] $($rest)*);
    };
    (@select [$($selected:tt)*] capacity $a:ident: $ta:ty; capacity $b:ident: $tb:ty; $($rest:tt)*) => {
        operating::operating_fields!(@select [$($selected)*] $($rest)*);
    };
    (@select [$($selected:tt)*] work $a:ident: $ta:ty;) => {
        operating::operating_fields!(@select [$($selected)* $a: $ta;]);
    };
    (@select [$($selected:tt)*] capacity $a:ident: $ta:ty;) => {
        operating::operating_fields!(@select [$($selected)*]);
    };
}
pub(super) use operating_fields;

pub(super) fn derive(capacity: &Limits, budget: &Budget) -> OperatingLimits {
    derive_with_statistics(capacity, budget, super::feedback::statistics())
}

pub(super) fn derive_with_statistics(
    capacity: &Limits,
    budget: &Budget,
    statistics: super::feedback::Statistics,
) -> OperatingLimits {
    let mut work = OperatingLimits::at_capacity(capacity);
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
        status_page,
        question_page,
        terminal_job_page,
        compaction_records
    );
    // ID and inventory pages are bounded metadata batches, not checker
    // quanta. Keep them at configured size while respecting live memory.
    work.id_page = capacity.id_page.min(memory / 32).max(1);
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
    work.compaction_bytes = capacity
        .compaction_bytes
        .min(memory / 8)
        .max(naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES);
    // Wanted proof IDs are a bounded admission queue, not CPU work or
    // simultaneous requests. Keep enough room for one configured inventory
    // page; the shared adaptive request budget limits network concurrency.
    work.fetches = capacity.fetches.min(memory / 512).max(1);
    work.inventory_page = capacity
        .inventory_page
        .min(work.fetches)
        .min(work.id_page)
        .max(1);
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
    let provider_interval = super::feedback::Role::ALL
        .into_iter()
        .map(|role| statistics.providers.get(role))
        .filter(|provider| provider.completed > 0 && (provider.queued > 0 || provider.running > 0))
        .map(|provider| provider.interval(slots, quantum, capacity.job_tick_interval))
        .min();
    let base_interval = measured
        .or(provider_interval)
        .unwrap_or(capacity.finding_interval);
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
    work.finding_interval = statistics
        .providers
        .finding
        .interval(
            slots.min(capacity.workers[0]),
            quantum,
            capacity.finding_interval,
        )
        .saturating_mul(
            1u32.checked_shl(statistics.empty_finding_streak.min(31) as u32)
                .unwrap_or(u32::MAX),
        )
        .min(capacity.finding_interval)
        .max(quantum);
    work.solving_interval = statistics.providers.solving.interval(
        slots.min(capacity.workers[1]),
        quantum,
        capacity.solving_interval,
    );
    work.production_interval = measured
        .unwrap_or(capacity.production_interval)
        .min(capacity.production_interval)
        .max(quantum);
    // Existing buffers/requests retain their admission. Smaller limits only
    // pace new work; callers must never truncate a retained row to fit them.
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
