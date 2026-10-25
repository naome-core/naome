use super::*;

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
}
