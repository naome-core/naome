use super::*;

#[test]
fn wall_clock_spent_time_and_reserved_units_bound_independent_allowances() {
    let limits = Limits {
        horizon_ms: 100,
        work_units: 5,
    };
    for (now, spent, reserved, expected_ms, expected_units) in [
        (150, 20, 1, 50, 4),
        (150, 99, 1, 1, 4),
        (200, 0, 0, 0, 5),
        (150, 100, 0, 0, 5),
        (150, 0, 5, 50, 0),
        (250, 200, 8, 0, 0),
    ] {
        let allowance = Allowance::at(limits, 200, spent, reserved, now);
        assert_eq!(allowance.remaining_ms, expected_ms);
        assert_eq!(allowance.remaining_units, expected_units);
        assert_eq!(allowance.time_expired(), expected_ms == 0);
        assert_eq!(
            allowance.can_reserve(),
            expected_ms > 0 && expected_units > 0
        );
    }
    assert_eq!(
        Allowance {
            remaining_ms: 50,
            remaining_units: 4
        }
        .intersect(Allowance {
            remaining_ms: 7,
            remaining_units: 1
        }),
        Allowance {
            remaining_ms: 7,
            remaining_units: 1
        }
    );
}
