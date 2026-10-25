use super::*;
use std::time::Duration;

#[test]
fn missing_check_feedback_preserves_configured_work_cadence() {
    let mut capacity = crate::resources::ResourceProfile::default()
        .resolve()
        .unwrap();
    capacity.finding_interval = Duration::from_secs(3);
    capacity.solving_interval = Duration::from_secs(7);
    capacity.production_interval = Duration::from_secs(9);
    let budget = Budget {
        memory_bytes: capacity.memory_bytes as u64,
        concurrency: 1,
        cache_bytes: 64 * 1024,
        batch_steps: 4,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };

    let work = derive_with_statistics(
        &capacity,
        &budget,
        crate::resources::feedback::Statistics::default(),
    );

    assert_eq!(work.finding_interval, capacity.finding_interval);
    assert_eq!(work.solving_interval, capacity.solving_interval);
    assert_eq!(work.production_interval, capacity.production_interval);
}

#[test]
fn smaller_live_budgets_reduce_work_without_redefining_formats_or_custody() {
    let capacity = crate::resources::ResourceProfile::default()
        .resolve()
        .unwrap();
    let budget = Budget {
        memory_bytes: 32 * 1024 * 1024,
        concurrency: 1,
        cache_bytes: 256 * 1024,
        batch_steps: 2,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };
    let work = derive(&capacity, &budget);
    assert_eq!(work.pending_page, 2);
    assert_eq!(work.compaction_records, 2);
    assert_eq!(work.solving_jobs, 1);
    assert!(work.checked_cache_bytes < capacity.checked_cache_bytes);
    assert_eq!(work.proof_bytes, capacity.proof_bytes);
    assert_eq!(work.closure_objects, capacity.closure_objects);
    assert_eq!(work.assessment_operations, capacity.assessment_operations);
    assert_eq!(work.job_work_units, capacity.job_work_units);
    assert_eq!(work.job_horizon, capacity.job_horizon);
    assert_eq!(work.replay_guard_bytes, capacity.replay_guard_bytes);
    assert_eq!(work.request_burst, capacity.request_burst);
    assert_eq!(work.workers, capacity.workers);
    assert_eq!(work.identify_protocols, capacity.identify_protocols);
    assert_eq!(work.identify_addresses, capacity.identify_addresses);
}

#[test]
fn provider_cadence_uses_its_own_complete_cost_and_installed_role_lanes() {
    let capacity = crate::resources::ResourceProfile::default()
        .resolve()
        .unwrap();
    let budget = Budget {
        memory_bytes: capacity.memory_bytes as u64,
        concurrency: capacity.workers.iter().sum(),
        cache_bytes: 64 * 1024,
        batch_steps: 4,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };
    let mut statistics = super::super::feedback::Statistics::default();
    statistics.providers.finding.completed = 1;
    statistics.providers.finding.service_nanos = 800_000_000;
    let finding = derive_with_statistics(&capacity, &budget, statistics);
    assert_eq!(
        finding.finding_interval,
        Duration::from_millis(800 / capacity.workers[0] as u64)
    );
    assert_eq!(finding.solving_interval, capacity.solving_interval);
    statistics.providers.solving.completed = 1;
    statistics.providers.solving.service_nanos = 2_000_000_000;
    let mixed = derive_with_statistics(&capacity, &budget, statistics);
    assert_eq!(mixed.finding_interval, finding.finding_interval);
    assert_eq!(
        mixed.solving_interval,
        Duration::from_millis(2000 / capacity.workers[1] as u64)
    );
    statistics.empty_finding_streak = 2;
    let backoff = derive_with_statistics(&capacity, &budget, statistics);
    assert_eq!(
        backoff.finding_interval,
        (finding.finding_interval * 4).min(capacity.finding_interval)
    );
    assert_eq!(backoff.solving_interval, mixed.solving_interval);
}
