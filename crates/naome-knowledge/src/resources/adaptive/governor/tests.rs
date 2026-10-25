use super::*;

fn hardware() -> Observed {
    Observed {
        memory_total: 8 * 1024 * MIB,
        memory_limit: 8 * 1024 * MIB,
        memory_available: 6 * 1024 * MIB,
        process_rss: 16 * MIB,
        cpu_millis: 8000,
        disk_available: 1024 * MIB,
        ..Observed::default()
    }
}

#[test]
fn measured_expensive_quanta_shrink_and_observed_fast_work_grows_gradually() {
    let mut governor = Governor::default();
    let now = Instant::now();
    let first = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            Statistics::default(),
            [false; 3],
            now,
        )
        .unwrap();
    let mut stats = Statistics {
        check: crate::resources::feedback::Work {
            units: 8,
            nanos: 80_000_000,
        },
        ..Statistics::default()
    };
    let slow = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            stats,
            [false; 3],
            now + Duration::from_secs(1),
        )
        .unwrap();
    assert!(slow.budget.batch_steps < first.budget.batch_steps);
    assert_eq!(slow.budget.batch_steps, 1);
    stats.check.units += 100;
    stats.check.nanos += 1_000_000;
    stats.cache_misses += 100;
    stats.cache_hits += 10;
    let fast = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            stats,
            [false; 3],
            now + Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(fast.budget.batch_steps, 2);
    assert!(fast.budget.cache_bytes > slow.budget.cache_bytes);
    let pressure = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            stats,
            [false, true, false],
            now + Duration::from_secs(3),
        )
        .unwrap();
    assert_eq!(pressure.budget.concurrency, 0);
    assert_eq!(pressure.budget.batch_steps, 0);
    let resumed = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            stats,
            [false; 3],
            now + Duration::from_secs(4),
        )
        .unwrap();
    assert!(resumed.budget.concurrency > 0);
    assert!(resumed.budget.paused.is_none());
}

#[test]
fn live_memory_reduction_pauses_without_extending_custom_allowances() {
    let selection = Selection {
        profile: Profile::Custom,
        custom: Some(Custom {
            memory_bytes: 32 * MIB,
            concurrency: 1,
            cache_bytes: 4096,
            batch_steps: 1,
            network_requests: 1,
        }),
    };
    let mut governor = Governor::default();
    let mut observed = hardware();
    observed.process_rss = 40 * MIB;
    let snapshot = governor
        .update(
            selection,
            observed,
            512 * MIB,
            Statistics::default(),
            [false; 3],
            Instant::now(),
        )
        .unwrap();
    assert_eq!(snapshot.budget.memory_bytes, 32 * MIB);
    assert_eq!(snapshot.budget.network_requests, 0);
    assert!(snapshot.budget.paused.is_some());
}

#[test]
fn streaming_misses_do_not_spend_more_memory_without_observed_reuse() {
    let mut governor = Governor::default();
    let now = Instant::now();
    let first = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            Statistics::default(),
            [false; 3],
            now,
        )
        .unwrap();
    let stats = Statistics {
        cache_misses: 10_000,
        ..Statistics::default()
    };
    let streamed = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            stats,
            [false; 3],
            now + Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(streamed.budget.cache_bytes, first.budget.cache_bytes);
}

#[test]
fn slower_network_without_more_throughput_reduces_the_pipeline() {
    let mut governor = Governor::default();
    let now = Instant::now();
    governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            Statistics::default(),
            [false; 3],
            now,
        )
        .unwrap();
    let mut stats = Statistics {
        network: crate::resources::feedback::Work {
            units: 10,
            nanos: 1_000_000_000,
        },
        pending_requests: 100,
        ..Statistics::default()
    };
    let first = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            stats,
            [false; 3],
            now + Duration::from_secs(1),
        )
        .unwrap();
    stats.network.units += 10;
    stats.network.nanos += 2_000_000_000;
    let congested = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            stats,
            [false; 3],
            now + Duration::from_secs(2),
        )
        .unwrap();
    assert!(congested.budget.network_requests < first.budget.network_requests);
    stats.failed_requests = 1;
    let failed = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            stats,
            [false; 3],
            now + Duration::from_secs(3),
        )
        .unwrap();
    assert!(failed.budget.network_requests <= congested.budget.network_requests);
}

#[test]
fn descendant_memory_obeys_node_capacity_without_redefining_a_local_work_target() {
    let selection = Selection {
        profile: Profile::Custom,
        custom: Some(Custom {
            memory_bytes: 48 * MIB,
            concurrency: 1,
            cache_bytes: 4096,
            batch_steps: 1,
            network_requests: 1,
        }),
    };
    let mut governor = Governor::default();
    let now = Instant::now();
    let stats = Statistics {
        descendant_rss: 64 * MIB,
        ..Statistics::default()
    };
    let admitted = governor
        .update(
            selection.clone(),
            hardware(),
            512 * MIB,
            stats,
            [false; 3],
            now,
        )
        .unwrap();
    assert_eq!(admitted.budget.memory_bytes, 48 * MIB);
    assert!(admitted.budget.paused.is_none());
    let pressure = governor
        .update(
            selection,
            hardware(),
            512 * MIB,
            Statistics {
                descendant_rss: 512 * MIB,
                ..Statistics::default()
            },
            [false; 3],
            now + Duration::from_secs(1),
        )
        .unwrap();
    assert!(pressure.budget.paused.is_some());
    assert_eq!(pressure.budget.concurrency, 0);
}
