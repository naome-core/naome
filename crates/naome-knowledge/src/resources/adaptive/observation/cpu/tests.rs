use super::*;
#[test]
fn own_busy_workers_are_excluded_from_host_pressure_in_the_same_interval() {
    let own = account(8, 100.0, 8000, 1000, 8000).unwrap();
    assert_eq!(own.external_percent, 0);
    assert_eq!(own.available_millis, 8000);
    let mixed = account(8, 100.0, 2000, 1000, 4000).unwrap();
    assert_eq!(mixed.external_percent, 75);
    assert_eq!(mixed.available_millis, 2000);
    let external = account(8, 90.0, 0, 1000, 8000).unwrap();
    assert_eq!(external.external_percent, 90);
    assert_eq!(external.available_millis, 800);
    assert!(account(0, 80.0, 0, 1000, 8000).is_none());
    assert!(account(8, f32::NAN, 0, 1000, 8000).is_none());
    assert!(account(8, 80.0, 0, 0, 8000).is_none());
}
