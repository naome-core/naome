use super::*;
use std::time::Duration;

impl std::fmt::Debug for Observer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observer")
            .field("snapshot", &self.snapshot)
            .field(
                "sample_due_in",
                &self.next.saturating_duration_since(Instant::now()),
            )
            .finish()
    }
}

impl Observer {
    // Local input tests own the pause boundary without consulting native host
    // observations. An active node budget still has the same precedence.
    pub(crate) fn fixed_for_test(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Some(snapshot),
            next: Instant::now() + super::super::super::limits().profile_poll_interval,
            governor: Governor::default(),
        }
    }
}

fn hardware() -> observation::Sample {
    observation::Sample {
        observed: Observed {
            memory_total: 8 * 1024 * MIB,
            memory_limit: 8 * 1024 * MIB,
            memory_available: 6 * 1024 * MIB,
            process_rss: 16 * MIB,
            cpu_millis: 8000,
            disk_available: 1024 * MIB,
            ..Observed::default()
        },
        pressure: observation::Pressure {
            memory: Some(false),
            low_power: Some(false),
            thermal: Some(false),
            ..observation::Pressure::default()
        },
    }
}

#[test]
fn missing_initial_telemetry_never_fabricates_an_admission_budget() {
    let mut observer = Observer::default();
    let now = Instant::now();
    let error = observer
        .poll_with(
            now,
            || Ok(Selection::default()),
            || Err("probe failed".into()),
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "probe failed");
    assert!(crate::Error::from(error).retryable());
    assert!(observer.snapshot.is_none());
    assert!(observer.due(now));
}

#[test]
fn failed_observations_pause_retained_work_and_recover_only_after_the_quiet_window() {
    let mut observer = Observer::default();
    let now = Instant::now();
    let first = observer
        .poll_with(now, || Ok(Selection::default()), || Ok(hardware()))
        .unwrap()
        .unwrap()
        .clone();
    assert!(first.budget.paused.is_none());
    let failure_time = now + Duration::from_secs(2);
    let paused = observer
        .poll_with(
            failure_time,
            || Ok(Selection::default()),
            || Err("probe failed".into()),
        )
        .unwrap()
        .unwrap()
        .clone();
    assert_eq!(paused.timestamp_ms, first.timestamp_ms);
    assert_eq!(
        paused.budget.paused.as_deref(),
        Some("hardware observation unavailable")
    );
    assert_eq!(paused.budget.batch_steps, 0);
    assert_eq!(paused.budget.concurrency, 0);
    assert!(paused.budget.cache_bytes <= first.budget.cache_bytes);
    assert!(paused.budget.memory_bytes <= first.budget.memory_bytes);
    assert!(paused.budget.network_requests <= first.budget.network_requests);
    assert!(
        observer
            .poll_with(failure_time, || panic!("not due"), || panic!("not due"))
            .unwrap()
            .is_none()
    );
    let recovering = observer
        .poll_with(
            now + Duration::from_secs(4),
            || Ok(Selection::default()),
            || Ok(hardware()),
        )
        .unwrap()
        .unwrap();
    assert!(recovering.budget.paused.is_some());
    let recovered = observer
        .poll_with(
            now + Duration::from_secs(35),
            || Ok(Selection::default()),
            || Ok(hardware()),
        )
        .unwrap()
        .unwrap();
    assert!(recovered.budget.paused.is_none());
    assert!(recovered.budget.batch_steps > 0 && recovered.budget.concurrency > 0);
}

#[test]
fn invalid_settings_are_distinct_from_a_retryable_telemetry_failure() {
    let mut observer = Observer::default();
    let error = observer
        .poll_with(
            Instant::now(),
            || Err("invalid profile".into()),
            || panic!("invalid settings must not sample"),
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "invalid profile");
    assert!(!crate::Error::from(error).retryable());
    assert!(observer.snapshot.is_none());
}
