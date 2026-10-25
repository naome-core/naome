use super::*;

#[test]
fn observations_are_bounded_and_missing_native_metrics_are_explicit() {
    let sample = Sample {
        elapsed_nanos: 100,
        blocked_nanos: 40,
        succeeded: true,
        ..Sample::default()
    };
    assert!(sample.validate(Duration::from_nanos(100)));
    assert_eq!(sample.elapsed_nanos - sample.blocked_nanos, 60);
    assert_eq!(sample.cpu_nanos, None);
    assert!(
        !Sample {
            blocked_nanos: 101,
            ..sample
        }
        .validate(Duration::from_nanos(100))
    );
    assert!(!sample.validate(Duration::from_nanos(99)));
    assert!(
        !Sample {
            peak_rss_bytes: Some(0),
            ..sample
        }
        .validate(Duration::from_nanos(100))
    );
    assert!(
        !Sample {
            check: Work { units: 0, nanos: 1 },
            ..sample
        }
        .validate(Duration::from_nanos(100))
    );
    let bytes = serde_json::to_vec(&sample).unwrap();
    assert_eq!(serde_json::from_slice::<Sample>(&bytes).unwrap(), sample);
    let mut forged = serde_json::to_value(sample).unwrap();
    forged["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Sample>(forged).is_err());
}

#[test]
fn only_complete_attempts_train_service_cost_and_roles_remain_separate() {
    let mut providers = Providers::default();
    let finding = providers.get_mut(Role::Finding);
    finding.finish(
        Disposition::Failed,
        Duration::from_secs(100),
        Sample::default(),
    );
    finding.finish(
        Disposition::Cancelled,
        Duration::from_secs(100),
        Sample::default(),
    );
    finding.finish(
        Disposition::Expired,
        Duration::from_secs(100),
        Sample::default(),
    );
    finding.finish(
        Disposition::Uncertain,
        Duration::from_secs(100),
        Sample::default(),
    );
    assert_eq!(
        finding.interval(4, Duration::from_millis(10), Duration::from_secs(5)),
        Duration::from_secs(5)
    );
    finding.finish(
        Disposition::Complete,
        Duration::from_millis(800),
        Sample::default(),
    );
    assert_eq!(
        finding.interval(4, Duration::from_millis(10), Duration::from_secs(5)),
        Duration::from_millis(200)
    );
    finding.finish(
        Disposition::Complete,
        Duration::from_millis(400),
        Sample::default(),
    );
    assert_eq!(finding.service_nanos, 700_000_000);
    assert_eq!(finding.completed, 2);
    assert_eq!(
        (
            finding.failed,
            finding.cancelled,
            finding.expired,
            finding.uncertain
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(providers.solving, Provider::default());
    assert_eq!(providers.local_interest, Provider::default());
    assert_eq!(providers.peer_interest, Provider::default());
}

#[test]
fn failed_work_is_visible_but_does_not_claim_durable_progress() {
    let mut provider = Provider::default();
    provider.record(
        Phase::Unit { unit: 3 },
        Sample {
            elapsed_nanos: 1000,
            blocked_nanos: 100,
            cpu_nanos: Some(400),
            peak_rss_bytes: Some(8192),
            succeeded: false,
            check: Work {
                units: 2,
                nanos: 300,
            },
        },
    );
    assert_eq!(provider.work.samples, 1);
    assert_eq!(provider.work.cpu_nanos, 400);
    assert_eq!(provider.work.blocked_nanos, 100);
    assert_eq!(
        provider.work.check,
        Work {
            units: 2,
            nanos: 300
        }
    );
    assert_eq!(provider.checkpointed_units, 0);
    assert_eq!(provider.completed, 0);
}

#[test]
fn cpu_overlap_requires_complete_known_demand_and_recovers_after_missing_measurements() {
    let mut providers = Providers::default();
    providers.finding.queued = 1;
    let quantum = Duration::from_millis(10);
    assert_eq!(providers.cpu_slots(2000, quantum), None);
    let sample = Sample {
        elapsed_nanos: 1_000_000_000,
        blocked_nanos: 800_000_000,
        cpu_nanos: Some(20_000_000),
        succeeded: true,
        ..Sample::default()
    };
    providers
        .finding
        .finish(Disposition::Complete, Duration::from_secs(1), sample);
    assert_eq!(providers.finding.active_nanos, 200_000_000);
    assert_eq!(providers.cpu_slots(2000, quantum), Some(20));
    // An unknown demanding role prevents extrapolation from an unrelated one.
    providers.solving.queued = 1;
    assert_eq!(providers.cpu_slots(2000, quantum), None);
    providers.solving.queued = 0;
    providers.finding.finish(
        Disposition::Complete,
        Duration::from_secs(1),
        Sample {
            cpu_nanos: None,
            ..sample
        },
    );
    assert_eq!(providers.cpu_slots(2000, quantum), None);
    providers
        .finding
        .finish(Disposition::Complete, Duration::from_secs(1), sample);
    assert_eq!(providers.cpu_slots(2000, quantum), Some(20));
    // Failed work remains diagnostic; it cannot retrain completed-attempt duty.
    providers.finding.finish(
        Disposition::Failed,
        Duration::from_secs(1),
        Sample {
            cpu_nanos: Some(1),
            ..sample
        },
    );
    assert_eq!(providers.cpu_slots(2000, quantum), Some(20));
    providers.finding.finish(
        Disposition::Complete,
        Duration::from_secs(1),
        Sample {
            elapsed_nanos: 1,
            blocked_nanos: 0,
            cpu_nanos: Some(1),
            ..sample
        },
    );
    assert!(providers.cpu_slots(2000, quantum).unwrap() <= 20);
    providers.finding = Provider {
        queued: 1,
        completed: 1,
        active_nanos: 1,
        cpu_nanos: Some(0),
        ..Provider::default()
    };
    assert_eq!(providers.cpu_slots(2000, quantum), None);
}
