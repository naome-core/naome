use super::*;

#[test]
fn burst_exhaustion_and_the_exact_window_boundary_preserve_every_charge() {
    let start = Instant::now();
    let rate = Rate {
        burst: 2,
        period: Duration::from_secs(3),
    };
    let mut quota = Quota::new(start);
    assert!(quota.try_take(start, rate));
    assert!(quota.try_take(start + Duration::from_secs(1), rate));
    assert!(!quota.try_take(start + Duration::from_millis(2999), rate));
    assert!(!quota.expired(start + Duration::from_millis(2999), rate));
    assert!(quota.expired(start + Duration::from_secs(3), rate));
    assert!(quota.try_take(start + Duration::from_secs(3), rate));
    assert!(quota.try_take(start + Duration::from_secs(3), rate));
    assert!(!quota.try_take(start + Duration::from_secs(3), rate));
}

#[test]
fn availability_does_not_spend_or_restart_an_expired_window() {
    let start = Instant::now();
    let rate = Rate {
        burst: 1,
        period: Duration::from_secs(2),
    };
    let mut quota = Quota::new(start);
    for _ in 0..10 {
        assert!(quota.available(start, rate));
    }
    assert!(quota.try_take(start, rate));
    assert!(!quota.available(start + Duration::from_secs(1), rate));
    for _ in 0..10 {
        assert!(quota.available(start + Duration::from_secs(2), rate));
    }
    // The first actual charge starts the next window at t=3, not the t=2 peek.
    assert!(quota.try_take(start + Duration::from_secs(3), rate));
    assert!(!quota.try_take(start + Duration::from_secs(4), rate));
    assert!(quota.try_take(start + Duration::from_secs(5), rate));
}

#[test]
fn older_observations_and_other_quotas_cannot_renew_spent_allowance() {
    let start = Instant::now();
    let rate = Rate {
        burst: 1,
        period: Duration::from_secs(2),
    };
    let mut first = Quota::new(start);
    let mut other = Quota::new(start);
    assert!(first.try_take(start + Duration::from_secs(2), rate));
    assert!(!first.try_take(start, rate));
    assert!(!first.available(start, rate));
    assert!(other.try_take(start + Duration::from_secs(2), rate));
    assert!(!first.try_take(start + Duration::from_secs(3), rate));
}
