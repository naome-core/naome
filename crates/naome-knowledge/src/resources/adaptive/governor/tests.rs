use super::*;
mod comparison;

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
            Pressure::default(),
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
            Pressure::default(),
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
            Pressure::default(),
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
            Pressure {
                memory: Some(true),
                ..Pressure::default()
            },
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
            Pressure {
                memory: Some(false),
                ..Pressure::default()
            },
            now + Duration::from_secs(4),
        )
        .unwrap();
    assert_eq!(resumed.budget.concurrency, 0);
    let resumed = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            stats,
            Pressure {
                memory: Some(false),
                ..Pressure::default()
            },
            now + Duration::from_secs(34),
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
            Pressure::default(),
            Instant::now(),
        )
        .unwrap();
    assert_eq!(snapshot.budget.memory_bytes, 32 * MIB);
    assert_eq!(snapshot.budget.network_requests, 1);
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
            Pressure::default(),
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
            Pressure::default(),
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
            Pressure::default(),
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
            Pressure::default(),
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
            Pressure::default(),
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
            Pressure::default(),
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
            Pressure::default(),
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
            Pressure::default(),
            now + Duration::from_secs(1),
        )
        .unwrap();
    assert!(pressure.budget.paused.is_some());
    assert_eq!(pressure.budget.concurrency, 0);
}

fn cpu_pressure(percent: u16) -> Pressure {
    Pressure {
        cpu: Some(observation::cpu::Load {
            external_percent: percent,
            available_millis: 8000 * (100 - u64::from(percent)) / 100,
        }),
        ..Pressure::default()
    }
}

#[test]
fn external_cpu_requires_sustained_pressure_and_a_quiet_recovery_window() {
    let mut governor = Governor::default();
    let now = Instant::now();
    let mut at = |seconds, percent| {
        governor
            .update(
                Selection::default(),
                hardware(),
                512 * MIB,
                Statistics::default(),
                cpu_pressure(percent),
                now + Duration::from_secs(seconds),
            )
            .unwrap()
    };
    assert!(at(0, 95).budget.paused.is_none());
    assert!(at(9, 95).budget.paused.is_none());
    assert!(at(10, 20).budget.paused.is_none());
    assert!(at(11, 95).budget.paused.is_none());
    let paused = at(21, 95);
    assert_eq!(
        paused.budget.paused.as_deref(),
        Some("sustained external CPU pressure")
    );
    assert_eq!(paused.budget.batch_steps, 0);
    assert_eq!(paused.budget.network_requests, 1);
    assert!(at(22, 20).budget.paused.is_some());
    assert!(at(40, 70).budget.paused.is_some());
    assert!(at(41, 20).budget.paused.is_some());
    assert!(at(70, 20).budget.paused.is_some());
    let clear = at(71, 20);
    assert!(clear.budget.paused.is_none());
    assert!(clear.budget.concurrency > 0);
}

#[test]
fn energy_thermal_and_observation_failures_hold_until_confirmed_recovery() {
    let mut governor = Governor::default();
    let now = Instant::now();
    let pressure = Pressure {
        low_power: Some(true),
        thermal: Some(true),
        ..Pressure::default()
    };
    let paused = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            Statistics::default(),
            pressure,
            now,
        )
        .unwrap();
    assert!(paused.budget.paused.is_some());
    let unknown = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            Statistics::default(),
            Pressure::default(),
            now + Duration::from_secs(60),
        )
        .unwrap();
    assert!(unknown.budget.paused.is_some());
    let clear = Pressure {
        low_power: Some(false),
        thermal: Some(false),
        ..Pressure::default()
    };
    let last_good = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            Statistics::default(),
            clear,
            now + Duration::from_secs(61),
        )
        .unwrap();
    let unavailable = governor.unavailable(Selection::default()).unwrap();
    assert_eq!(unavailable.timestamp_ms, last_good.timestamp_ms);
    assert_eq!(
        unavailable.budget.paused.as_deref(),
        Some("hardware observation unavailable")
    );
    let waiting = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            Statistics::default(),
            clear,
            now + Duration::from_secs(90),
        )
        .unwrap();
    assert!(waiting.budget.paused.is_some());
    assert!(
        governor
            .update(
                Selection::default(),
                hardware(),
                512 * MIB,
                Statistics::default(),
                clear,
                now + Duration::from_secs(120)
            )
            .unwrap()
            .budget
            .paused
            .is_none()
    );
}

#[test]
fn observation_failure_applies_new_smaller_owner_ceilings_without_freshness_or_capacity_growth() {
    let mut governor = Governor::default();
    let valid = governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            Statistics::default(),
            Pressure::default(),
            Instant::now(),
        )
        .unwrap();
    let selection = Selection {
        profile: Profile::Custom,
        custom: Some(Custom {
            memory_bytes: 8 * MIB,
            concurrency: 1,
            cache_bytes: 4096,
            batch_steps: 1,
            network_requests: 1,
        }),
    };
    let stale = governor.unavailable(selection.clone()).unwrap();
    assert_eq!(stale.selection, selection);
    assert_eq!(stale.timestamp_ms, valid.timestamp_ms);
    assert_eq!(stale.budget.memory_bytes, 8 * MIB);
    assert_eq!(stale.budget.cache_bytes, 4096);
    assert_eq!(stale.budget.concurrency, 0);
    assert_eq!(stale.budget.batch_steps, 0);
    assert_eq!(stale.budget.network_requests, 1);
}

#[test]
fn a_missing_memory_pressure_signal_cannot_clear_a_previously_asserted_warning() {
    let mut governor = Governor::default();
    let now = Instant::now();
    governor
        .update(
            Selection::default(),
            hardware(),
            512 * MIB,
            Statistics::default(),
            Pressure {
                memory: Some(true),
                ..Pressure::default()
            },
            now,
        )
        .unwrap();
    assert!(
        governor
            .update(
                Selection::default(),
                hardware(),
                512 * MIB,
                Statistics::default(),
                Pressure::default(),
                now + Duration::from_secs(60)
            )
            .unwrap()
            .budget
            .paused
            .is_some()
    );
    let clear = Pressure {
        memory: Some(false),
        ..Pressure::default()
    };
    assert!(
        governor
            .update(
                Selection::default(),
                hardware(),
                512 * MIB,
                Statistics::default(),
                clear,
                now + Duration::from_secs(61)
            )
            .unwrap()
            .budget
            .paused
            .is_some()
    );
    assert!(
        governor
            .update(
                Selection::default(),
                hardware(),
                512 * MIB,
                Statistics::default(),
                clear,
                now + Duration::from_secs(91)
            )
            .unwrap()
            .budget
            .paused
            .is_none()
    );
}
