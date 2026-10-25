use super::*;
use std::time::Duration;

fn isolated(test: &str) -> bool {
    if std::env::var("NAOME_OPERATING_LIMITS_TEST").as_deref() == Ok(test) {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("NAOME_OPERATING_LIMITS_TEST", test)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    true
}

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
    if isolated(
        "resources::operating::tests::smaller_live_budgets_reduce_work_without_redefining_formats_or_custody",
    ) {
        return;
    }
    let capacity = crate::resources::limits().clone();
    let budget = Budget {
        memory_bytes: 32 * 1024 * 1024,
        concurrency: 1,
        cache_bytes: 256 * 1024,
        batch_steps: 2,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };
    let mut snapshot = super::super::tests::snapshot(false);
    snapshot.budget = budget;
    super::super::adaptive::publish(snapshot);
    let work = super::super::active_limits();
    let installed = super::super::limits();
    assert_eq!(work.pending_page, 2);
    assert_eq!(work.compaction_records, 2);
    assert_eq!(work.solving_jobs, 1);
    assert!(work.checked_cache_bytes < capacity.checked_cache_bytes);
    assert_eq!(installed.proof_bytes, capacity.proof_bytes);
    assert_eq!(installed.closure_objects, capacity.closure_objects);
    assert_eq!(
        installed.assessment_operations,
        capacity.assessment_operations
    );
    assert_eq!(installed.job_work_units, capacity.job_work_units);
    assert_eq!(installed.job_horizon, capacity.job_horizon);
    assert_eq!(installed.replay_guard_bytes, capacity.replay_guard_bytes);
    assert_eq!(installed.request_burst, capacity.request_burst);
    assert_eq!(installed.workers, capacity.workers);
    assert_eq!(installed.identify_protocols, capacity.identify_protocols);
    assert_eq!(installed.identify_addresses, capacity.identify_addresses);
}

#[test]
fn small_compute_batches_preserve_bounded_inventory_admission() {
    if isolated(
        "resources::operating::tests::small_compute_batches_preserve_bounded_inventory_admission",
    ) {
        return;
    }
    let capacity = crate::resources::ResourceProfile::default()
        .resolve()
        .unwrap();
    let budget = Budget {
        memory_bytes: capacity.memory_bytes as u64,
        concurrency: 1,
        cache_bytes: capacity.checked_cache_bytes as u64,
        batch_steps: 1,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };

    let mut snapshot = super::super::tests::snapshot(false);
    snapshot.budget = budget.clone();
    super::super::adaptive::publish(snapshot);
    let work = super::super::active_limits();

    assert_eq!(work.id_page, capacity.id_page);
    assert_eq!(work.inventory_page, capacity.inventory_page);
    assert_eq!(work.fetches, capacity.fetches);
    assert_eq!(super::super::adaptive::network(capacity.flights), 1);
    assert!(work.inventory_page <= work.fetches);
    assert!(work.inventory_page <= work.id_page);
    assert!(work.fetches <= budget.memory_bytes as usize / 512);
    assert!(work.id_page <= budget.memory_bytes as usize / 32);
}
