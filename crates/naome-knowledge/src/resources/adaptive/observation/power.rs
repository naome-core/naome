//! Read-only, platform-owned power and thermal indications. Unsupported
//! sensors stay unknown; battery operation alone does not suspend computation.
#[cfg(target_os = "macos")]
use super::probe;
#[cfg(any(test, target_os = "linux"))]
use std::path::Path;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Power {
    pub low_power: Option<bool>,
    pub thermal: Option<bool>,
}

pub(super) fn sample(deadline: Instant) -> Power {
    static LAST: Mutex<Option<(Instant, Power)>> = Mutex::new(None);
    let Ok(mut last) = LAST.lock() else {
        return Power::default();
    };
    if let Some((before, power)) = *last
        && before.elapsed() < Duration::from_secs(1)
    {
        return power;
    }
    #[cfg(target_os = "macos")]
    let power = Power {
        low_power: probe::run("/usr/bin/pmset", &["-g"], 16 * 1024, deadline)
            .ok()
            .and_then(|text| mac_low_power(&text)),
        thermal: probe::run("/usr/bin/pmset", &["-g", "therm"], 16 * 1024, deadline)
            .ok()
            .and_then(|text| mac_thermal(&text)),
    };
    #[cfg(target_os = "linux")]
    let power = linux_power(Path::new("/sys"), deadline);
    *last = Some((Instant::now(), power));
    power
}

#[cfg(any(test, target_os = "macos"))]
fn mac_low_power(text: &str) -> Option<bool> {
    let mut values = text.lines().filter_map(|line| {
        let mut words = line.split_whitespace();
        (words.next()? == "lowpowermode")
            .then(|| words.next())
            .flatten()
    });
    let value = match values.next()? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    values.next().is_none().then_some(value)
}

#[cfg(any(test, target_os = "macos"))]
fn mac_thermal(text: &str) -> Option<bool> {
    // Apple's pmset reports the IOPM thermal-warning notification value.
    // No recorded warning is explicitly different from a failed query.
    let mut values = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Thermal Warning Level = "));
    if let Some(value) = values.next() {
        let warning = value.trim().parse::<u32>().ok()?;
        return values.next().is_none().then_some(warning > 0);
    }
    text.lines()
        .any(|line| line.trim() == "Note: No thermal warning level has been recorded")
        .then_some(false)
}

#[cfg(any(test, target_os = "linux"))]
fn linux_power(root: &Path, deadline: Instant) -> Power {
    let low_power = super::read_optional(&root.join("firmware/acpi/platform_profile"))
        .ok()
        .flatten()
        .and_then(|value| match value.trim() {
            "low-power" => Some(true),
            "quiet" | "cool" | "balanced" | "balanced-performance" | "performance" => Some(false),
            _ => None,
        });
    let mut thermal = None;
    if let Ok(zones) = std::fs::read_dir(root.join("class/thermal")) {
        for zone in zones.take(256).flatten() {
            if Instant::now() >= deadline {
                return Power {
                    low_power,
                    thermal: None,
                };
            }
            if !zone
                .file_name()
                .to_string_lossy()
                .starts_with("thermal_zone")
            {
                continue;
            }
            let read_number = |path: &Path| {
                super::read_optional(path)
                    .ok()
                    .flatten()?
                    .trim()
                    .parse::<i64>()
                    .ok()
            };
            let Some(temperature) = read_number(&zone.path().join("temp")) else {
                continue;
            };
            for index in 0..64 {
                if Instant::now() >= deadline {
                    return Power {
                        low_power,
                        thermal: None,
                    };
                }
                let name = format!("trip_point_{index}");
                let Ok(Some(kind)) =
                    super::read_optional(&zone.path().join(format!("{name}_type")))
                else {
                    continue;
                };
                if !matches!(kind.trim(), "passive" | "hot" | "critical") {
                    continue;
                }
                let Some(limit) = read_number(&zone.path().join(format!("{name}_temp"))) else {
                    continue;
                };
                if limit > 0 {
                    thermal = Some(thermal.unwrap_or(false) || temperature >= limit);
                }
            }
        }
    }
    Power { low_power, thermal }
}

#[cfg(test)]
mod tests;
