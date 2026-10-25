use super::*;

fn sample(succeeded: bool) -> Sample {
    Sample {
        succeeded,
        ..Sample::default()
    }
}

#[test]
fn reports_cannot_skip_duplicate_or_reorder_the_owned_unit_lifecycle() {
    let mut attempt = Attempt::new(Role::Finding);
    assert!(
        attempt
            .observe(Phase::Unit { unit: 1 }, sample(true), Some(1), false)
            .is_err()
    );
    assert!(
        attempt
            .observe(Phase::Setup, sample(true), None, false)
            .is_ok()
    );
    assert!(
        attempt
            .observe(Phase::Setup, sample(true), None, false)
            .is_err()
    );
    assert!(
        attempt
            .observe(Phase::Unit { unit: 2 }, sample(true), Some(1), false)
            .is_err()
    );
    assert!(
        attempt
            .observe(Phase::Finalization, sample(true), None, false)
            .is_err()
    );
    assert!(
        attempt
            .observe(Phase::Unit { unit: 1 }, sample(true), Some(1), false)
            .is_ok()
    );
    assert!(
        attempt
            .observe(Phase::Unit { unit: 1 }, sample(true), Some(1), false)
            .is_err()
    );
    assert!(!attempt.finished());
    assert!(attempt.checkpoint(2).is_err());
    assert!(attempt.checkpoint(1).is_ok());
    assert!(attempt.checkpoint(1).is_err());
    assert!(
        attempt
            .observe(Phase::Finalization, sample(true), None, true)
            .is_ok()
    );
    assert!(attempt.finished());
    assert!(!attempt.ready());
    assert!(
        attempt
            .observe(Phase::Finalization, sample(true), None, true)
            .is_err()
    );
}

#[test]
fn failed_work_and_forged_time_cannot_authorize_checkpoint_or_result() {
    let mut attempt = Attempt::new(Role::Solving);
    assert!(
        attempt
            .observe(
                Phase::Setup,
                Sample {
                    elapsed_nanos: u64::MAX,
                    ..sample(true)
                },
                None,
                false
            )
            .is_err()
    );
    attempt
        .observe(Phase::Setup, sample(true), None, false)
        .unwrap();
    attempt
        .observe(Phase::Unit { unit: 1 }, sample(false), Some(1), false)
        .unwrap();
    assert!(attempt.checkpoint(1).is_err());
    assert!(
        attempt
            .observe(Phase::Finalization, sample(true), None, true)
            .is_err()
    );
    assert!(!attempt.finished());
}

#[test]
fn phase_times_must_fit_the_same_owned_attempt_without_overlapping_claims() {
    let mut attempt = Attempt::new(Role::Finding);
    attempt.started = Instant::now() - Duration::from_secs(3600);
    let measured = Sample {
        elapsed_nanos: 2_700_000_000_000,
        ..sample(true)
    };
    attempt
        .observe(Phase::Setup, measured, None, false)
        .unwrap();
    assert!(
        attempt
            .observe(Phase::Unit { unit: 1 }, measured, Some(1), false)
            .is_err()
    );
    assert!(!attempt.unit_ready(1));
}

#[test]
fn ending_an_interrupted_admission_wait_reports_it_once_without_advancing_work() {
    let mut attempt = Attempt::new(Role::LocalInterest);
    attempt.wait();
    assert!(attempt.waiting.is_some());
    attempt.waiting = Some(Instant::now() - Duration::from_secs(1));
    attempt.resume();
    assert!(attempt.waiting.is_none());
    assert!(attempt.paused >= Duration::from_secs(1));
    let retained = attempt.paused;
    attempt.resume();
    assert_eq!(attempt.paused, retained);
    assert!(!attempt.ready());
    assert!(!attempt.unit_ready(1));
    assert!(!attempt.finished());
}
