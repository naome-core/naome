use super::*;
#[test]
fn mac_power_queries_distinguish_supported_clear_pressure_and_unknown() {
    assert_eq!(
        mac_low_power("Battery Power:\n lowpowermode 1\n"),
        Some(true)
    );
    assert_eq!(mac_low_power(" lowpowermode 0\n"), Some(false));
    assert_eq!(mac_low_power(" lowpowermode 2\n"), None);
    assert_eq!(mac_low_power("Error"), None);
    assert_eq!(mac_thermal("Thermal Warning Level = 1\n"), Some(true));
    assert_eq!(mac_thermal("Thermal Warning Level = 0\n"), Some(false));
    assert_eq!(
        mac_thermal("Note: No thermal warning level has been recorded\n"),
        Some(false)
    );
    assert_eq!(mac_thermal("Error: query failed"), None);
}
#[test]
fn linux_thermal_policy_uses_firmware_trip_points_and_preserves_unknown() {
    let dir = crate::checkpoint::tests::Directory::new();
    assert_eq!(
        linux_power(&dir.0, Instant::now() + Duration::from_secs(1)).thermal,
        None
    );
    let zone = dir.0.join("class/thermal/thermal_zone0");
    std::fs::create_dir_all(&zone).unwrap();
    std::fs::write(zone.join("temp"), "80000").unwrap();
    std::fs::write(zone.join("trip_point_0_type"), "passive").unwrap();
    std::fs::write(zone.join("trip_point_0_temp"), "85000").unwrap();
    assert_eq!(
        linux_power(&dir.0, Instant::now() + Duration::from_secs(1)).thermal,
        Some(false)
    );
    std::fs::write(zone.join("temp"), "86000").unwrap();
    assert_eq!(
        linux_power(&dir.0, Instant::now() + Duration::from_secs(1)).thermal,
        Some(true)
    );
}
