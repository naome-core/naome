//! Bounded OS observations for one node and its owned descendants.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
};

static MEMORY_PRESSURE: AtomicBool = AtomicBool::new(false);
static CPU_PRESSURE: AtomicBool = AtomicBool::new(false);
static IO_PRESSURE: AtomicBool = AtomicBool::new(false);

pub(super) fn pressure() -> [bool; 3] {
    [
        CPU_PRESSURE.load(Ordering::Relaxed),
        MEMORY_PRESSURE.load(Ordering::Relaxed),
        IO_PRESSURE.load(Ordering::Relaxed),
    ]
}

pub(super) fn sample(directory: &Path) -> Result<Observed, String> {
    use nix::sys::time::TimeValLike;
    let (total, available, _, load) = platform_sample()?;
    let usage = nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_SELF)
        .map_err(|e| e.to_string())?;
    let children = nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_CHILDREN)
        .map_err(|e| e.to_string())?;
    let (rss, cpu, own_rss) = process_tree(
        &run("/bin/ps", &["-axo", "pid=,ppid=,rss=,time="], 512 * 1024)?,
        std::process::id(),
    )?;
    super::super::feedback::descendants(rss.saturating_sub(own_rss));
    let peak = u64::try_from(usage.max_rss()).map_err(|e| e.to_string())?;
    #[cfg(target_os = "linux")]
    let peak = peak.saturating_mul(1024);
    let mut observed = Observed {
        memory_total: total,
        memory_available: available,
        memory_limit: total,
        process_rss: own_rss,
        peak_rss: peak.max(own_rss),
        process_cpu_ms: cpu.saturating_add(
            u64::try_from(
                children
                    .user_time()
                    .num_milliseconds()
                    .saturating_add(children.system_time().num_milliseconds()),
            )
            .map_err(|e| e.to_string())?,
        ),
        cpu_millis: std::thread::available_parallelism()
            .map_err(|e| e.to_string())?
            .get() as u64
            * 1000,
        load_millis: load,
        disk_available: 0,
    };
    for resource in [
        nix::sys::resource::Resource::RLIMIT_AS,
        nix::sys::resource::Resource::RLIMIT_DATA,
    ] {
        let (limit, _) = nix::sys::resource::getrlimit(resource).map_err(|e| e.to_string())?;
        if limit != nix::sys::resource::RLIM_INFINITY {
            observed.memory_limit = observed.memory_limit.min(limit);
        }
    }
    #[cfg(target_os = "linux")]
    {
        cgroups(&mut observed)?;
        let read_pressure = |name: &str| {
            fs::read_to_string(format!("/proc/pressure/{name}"))
                .ok()
                .and_then(|text| {
                    text.lines()
                        .find(|line| line.starts_with("some "))
                        .and_then(|line| {
                            line.split_whitespace()
                                .find_map(|field| field.strip_prefix("avg10="))
                        })
                        .and_then(|value| value.parse::<f64>().ok())
                })
                .is_some_and(|value| value > 0.0)
        };
        CPU_PRESSURE.store(read_pressure("cpu"), Ordering::Relaxed);
        MEMORY_PRESSURE.store(read_pressure("memory"), Ordering::Relaxed);
        IO_PRESSURE.store(read_pressure("io"), Ordering::Relaxed);
    }
    #[cfg(target_os = "macos")]
    MEMORY_PRESSURE.store(mac_memory_pressure()?, Ordering::Relaxed);
    let stats = nix::sys::statvfs::statvfs(directory).map_err(|e| e.to_string())?;
    observed.disk_available = (u128::from(stats.blocks_available())
        * u128::from(stats.fragment_size()))
    .min(u128::from(u64::MAX)) as u64;
    Ok(observed)
}

fn run(path: &str, arguments: &[&str], maximum: usize) -> Result<String, String> {
    let mut child = Command::new(path)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut output = Vec::new();
    let read = child
        .stdout
        .take()
        .ok_or("hardware observation output absent")?
        .take(maximum as u64 + 1)
        .read_to_end(&mut output);
    if read.is_err() || output.len() > maximum {
        let _ = child.kill();
        let _ = child.wait();
        return Err("hardware observation capacity".into());
    }
    if !child.wait().map_err(|e| e.to_string())?.success() {
        return Err("hardware observation failed".into());
    }
    String::from_utf8(output).map_err(|e| e.to_string())
}

fn process_tree(text: &str, root: u32) -> Result<(u64, u64, u64), String> {
    let mut processes = BTreeMap::new();
    let mut children = BTreeMap::<u32, Vec<u32>>::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let mut next = || fields.next().ok_or("incomplete process observation");
        let pid = next()?
            .parse::<u32>()
            .map_err(|_| "process identity width")?;
        let parent = next()?.parse::<u32>().map_err(|_| "process parent width")?;
        let rss = next()?
            .parse::<u64>()
            .map_err(|_| "process resident width")?
            .checked_mul(1024)
            .ok_or("process resident overflow")?;
        let cpu = cpu_time(next()?)?;
        if processes.insert(pid, (rss, cpu)).is_some() {
            return Err("duplicate process observation".into());
        }
        children.entry(parent).or_default().push(pid);
    }
    let own = processes
        .get(&root)
        .ok_or("node process observation absent")?
        .0;
    let mut queue = VecDeque::from([root]);
    let mut seen = BTreeSet::new();
    let (mut rss, mut cpu) = (0u64, 0u64);
    while let Some(pid) = queue.pop_front() {
        if !seen.insert(pid) {
            return Err("cyclic process observation".into());
        }
        let (resident, time) = processes[&pid];
        rss = rss
            .checked_add(resident)
            .ok_or("process tree resident overflow")?;
        cpu = cpu.checked_add(time).ok_or("process tree CPU overflow")?;
        if let Some(descendants) = children.get(&pid) {
            queue.extend(descendants);
        }
    }
    Ok((rss, cpu, own))
}

fn cpu_time(value: &str) -> Result<u64, String> {
    let (days, time) = value
        .split_once('-')
        .map_or(Ok((0u64, value)), |(days, time)| {
            days.parse::<u64>()
                .map(|days| (days, time))
                .map_err(|_| "process CPU day width")
        })?;
    let fields = time.split(':').collect::<Vec<_>>();
    let (hours, minutes, seconds) = match fields.as_slice() {
        [minutes, seconds] => ("0", *minutes, *seconds),
        [hours, minutes, seconds] => (*hours, *minutes, *seconds),
        _ => return Err("process CPU format".into()),
    };
    let hours = hours.parse::<u64>().map_err(|_| "process CPU hour width")?;
    let minutes = minutes
        .parse::<u64>()
        .map_err(|_| "process CPU minute width")?;
    let seconds = seconds
        .parse::<f64>()
        .map_err(|_| "process CPU second width")?;
    if !seconds.is_finite() || !(0.0..60.0).contains(&seconds) || fields.len() == 3 && minutes >= 60
    {
        return Err("process CPU format".into());
    }
    days.checked_mul(24)
        .and_then(|value| value.checked_add(hours))
        .and_then(|value| value.checked_mul(60))
        .and_then(|value| value.checked_add(minutes))
        .and_then(|value| value.checked_mul(60_000))
        .and_then(|value| value.checked_add((seconds * 1000.0) as u64))
        .ok_or_else(|| "process CPU overflow".into())
}

#[cfg(target_os = "macos")]
fn mac_memory_pressure() -> Result<bool, String> {
    let value = run(
        "/usr/sbin/sysctl",
        &["-n", "kern.memorystatus_vm_pressure_level"],
        64,
    )?;
    match value
        .trim()
        .parse::<u32>()
        .map_err(|_| "invalid macOS memory pressure observation")?
    {
        1 => Ok(false),
        2 | 4 => Ok(true),
        _ => Err("unknown macOS memory pressure observation".into()),
    }
}

#[cfg(any(test, target_os = "linux"))]
fn read_small(path: &Path) -> Result<String, String> {
    let mut text = String::new();
    fs::File::open(path)
        .and_then(|f| f.take(65537).read_to_string(&mut text))
        .map_err(|e| e.to_string())?;
    if text.len() > 65536 {
        return Err("hardware observation capacity".into());
    }
    Ok(text)
}
#[cfg(target_os = "linux")]
fn platform_sample() -> Result<(u64, u64, u64, u64), String> {
    let memory = read_small(Path::new("/proc/meminfo"))?;
    let field = |text: &str, name: &str| -> Result<u64, String> {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
            .and_then(|v| v.checked_mul(1024))
            .ok_or_else(|| format!("missing {name}"))
    };
    let status = read_small(Path::new("/proc/self/status"))?;
    let load = read_small(Path::new("/proc/loadavg"))?
        .split_whitespace()
        .next()
        .ok_or("missing load")?
        .parse::<f64>()
        .map_err(|e| e.to_string())?;
    Ok((
        field(&memory, "MemTotal:")?,
        field(&memory, "MemAvailable:")?,
        field(&status, "VmRSS:")?,
        (load * 1000.0) as u64,
    ))
}
#[cfg(target_os = "macos")]
fn platform_sample() -> Result<(u64, u64, u64, u64), String> {
    let command = |path: &str, args: &[&str]| -> Result<String, String> {
        let output = std::process::Command::new(path)
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() || output.stdout.len() > 65536 {
            return Err("hardware observation failed".into());
        }
        String::from_utf8(output.stdout).map_err(|e| e.to_string())
    };
    let total = command("/usr/sbin/sysctl", &["-n", "hw.memsize"])?
        .trim()
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    let vm = command("/usr/bin/vm_stat", &[])?;
    let page = vm
        .lines()
        .next()
        .and_then(|s| s.split("page size of ").nth(1))
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or("missing VM page size")?;
    let mut available = 0u64;
    for name in ["Pages free:", "Pages inactive:", "Pages speculative:"] {
        let pages = vm
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|s| s.trim().trim_end_matches('.').parse::<u64>().ok())
            .ok_or("missing VM pages")?;
        available = available.saturating_add(pages.saturating_mul(page));
    }
    let load = command("/usr/sbin/sysctl", &["-n", "vm.loadavg"])?;
    let load = load
        .split_whitespace()
        .nth(1)
        .ok_or("missing system load")?
        .parse::<f64>()
        .map_err(|e| e.to_string())?;
    Ok((total, available, 0, (load * 1000.0) as u64))
}
#[cfg(target_os = "linux")]
fn cgroups(observed: &mut Observed) -> Result<(), String> {
    let membership = read_small(Path::new("/proc/self/cgroup"))?;
    apply_cgroups(observed, Path::new("/sys/fs/cgroup"), &membership)
}
#[cfg(any(test, target_os = "linux"))]
pub(super) fn apply_cgroups(
    observed: &mut Observed,
    root: &Path,
    membership: &str,
) -> Result<(), String> {
    // Walk every ancestor: a container's effective ceiling may be imposed by
    // its parent, even when its own file says `max`.
    for line in membership.lines() {
        let fields: Vec<_> = line.splitn(3, ':').collect();
        if fields.len() != 3 {
            return Err("invalid cgroup membership".into());
        }
        let relative = Path::new(fields[2].trim_start_matches('/'));
        if relative
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err("invalid cgroup path".into());
        }
        let (base, v2) = if fields[1].is_empty() {
            (root.to_path_buf(), true)
        } else if fields[1].split(',').any(|v| v == "memory") {
            (root.join("memory"), false)
        } else if fields[1].split(',').any(|v| v == "cpu") {
            (
                if root.join("cpu").exists() {
                    root.join("cpu")
                } else {
                    root.join("cpu,cpuacct")
                },
                false,
            )
        } else {
            continue;
        };
        let mut path = base.join(relative);
        loop {
            let limit_path = path.join(if v2 {
                "memory.max"
            } else {
                "memory.limit_in_bytes"
            });
            if limit_path.exists() {
                let text = read_small(&limit_path)?;
                if text.trim() != "max" {
                    let limit = text.trim().parse::<u64>().map_err(|e| e.to_string())?;
                    let used = read_small(&path.join(if v2 {
                        "memory.current"
                    } else {
                        "memory.usage_in_bytes"
                    }))?
                    .trim()
                    .parse::<u64>()
                    .map_err(|e| e.to_string())?;
                    observed.memory_limit = observed.memory_limit.min(limit);
                    observed.memory_available =
                        observed.memory_available.min(limit.saturating_sub(used));
                }
            }
            if v2 && path.join("cpu.max").exists() {
                let text = read_small(&path.join("cpu.max"))?;
                let mut parts = text.split_whitespace();
                if let (Some(quota), Some(period)) = (parts.next(), parts.next())
                    && quota != "max"
                {
                    let quota = quota.parse::<u64>().map_err(|e| e.to_string())?;
                    let period = period.parse::<u64>().map_err(|e| e.to_string())?;
                    if period == 0 || quota == 0 {
                        return Err("invalid cgroup CPU quota".into());
                    }
                    observed.cpu_millis = observed
                        .cpu_millis
                        .min(quota.saturating_mul(1000) / period)
                        .max(1);
                }
            }
            if !v2 && path.join("cpu.cfs_quota_us").exists() {
                let quota = read_small(&path.join("cpu.cfs_quota_us"))?;
                if quota.trim() != "-1" {
                    let quota = quota.trim().parse::<u64>().map_err(|e| e.to_string())?;
                    let period = read_small(&path.join("cpu.cfs_period_us"))?
                        .trim()
                        .parse::<u64>()
                        .map_err(|e| e.to_string())?;
                    if quota == 0 || period == 0 {
                        return Err("invalid cgroup CPU quota".into());
                    }
                    observed.cpu_millis = observed
                        .cpu_millis
                        .min(quota.saturating_mul(1000) / period)
                        .max(1);
                }
            }
            if path == base {
                break;
            }
            if !path.pop() || !path.starts_with(&base) {
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
