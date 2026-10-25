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
