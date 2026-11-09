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
            next: Instant::now() + Duration::from_secs(1),
            governor: Governor::default(),
            failure_reported: false,
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
            || Err(crate::InputFault::ProbeDeadline.into()),
        )
        .unwrap_err();
    let error = crate::Error::from(error);
    assert!(error.retryable());
    let value = serde_json::to_value(&error).unwrap();
    assert_eq!(
        value["cause"]["code"],
        u32::from(crate::InputFault::ProbeDeadline)
    );
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
            || Err(crate::InputFault::ProbeDeadline.into()),
        )
        .unwrap()
        .unwrap()
        .clone();
    assert!(observer.failure_reported);
    let event = failure_event(&crate::Error::from(crate::InputFault::ProbeDeadline));
    assert_eq!(
        event["event"],
        u32::from(crate::outcome::NodeEvent::ResourceObservationFailure)
    );
    assert_eq!(
        event["error"]["code"],
        u32::from(crate::InputFault::ProbeDeadline)
    );
    assert_eq!(paused.timestamp_ms, first.timestamp_ms);
    assert_eq!(
        paused.budget.paused,
        Some(crate::PauseReason::HardwareObservationUnavailable)
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
    assert!(!observer.failure_reported);
}

#[test]
fn invalid_settings_are_distinct_from_a_retryable_telemetry_failure() {
    let mut observer = Observer::default();
    let error = observer
        .poll_with(
            Instant::now(),
            || Err(crate::InputFault::ResourceCustomInvalid.into()),
            || panic!("invalid settings must not sample"),
        )
        .unwrap_err();
    let error = crate::Error::from(error);
    assert_eq!(
        error.code(),
        u32::from(crate::InputFault::ResourceCustomInvalid)
    );
    assert!(!error.retryable());
    assert!(observer.snapshot.is_none());
}

#[test]
fn invalid_observed_values_preserve_derived_failure() {
    let mut observer = Observer::default();
    let error = observer
        .poll_with(
            Instant::now(),
            || Ok(Selection::default()),
            || {
                let mut sample = hardware();
                sample.observed.memory_total = 0;
                Ok(sample)
            },
        )
        .unwrap_err();
    let error = crate::Error::from(error);
    assert!(
        matches!(error, crate::Error::ObservationUnavailable(cause) if *cause == crate::Error::from(crate::InputFault::ObservationIncomplete))
    );
}
