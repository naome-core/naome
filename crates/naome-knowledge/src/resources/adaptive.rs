//! Live admission budgets below the immutable process capacity. Reductions
//! drain existing work; they never revoke leases or erase durable input.
//!
//! The memory target includes sampled process RSS. New tracked reservations
//! use the sampled headroom plus the charges already represented by that RSS,
//! always below the immutable allocation ceiling. Local control ingress and
//! bounded readback inside an existing publication may drain at that ceiling.
//! A target reduction pauses new mathematical work while retained work drains;
//! it does not require the operating system's RSS to fall synchronously.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::Path,
    sync::{OnceLock, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
const MIB: u64 = 1024 * 1024;
pub(crate) mod history;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    Dynamic,
    Heavy,
    Light,
    Custom,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Custom {
    pub memory_bytes: u64,
    pub concurrency: usize,
    pub cache_bytes: u64,
    pub batch_steps: usize,
    pub network_requests: usize,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub profile: Profile,
    pub custom: Option<Custom>,
}
impl Selection {
    pub fn validate(&self) -> Result<(), String> {
        match (&self.profile,&self.custom) {
            (Profile::Custom,Some(c)) if c.memory_bytes>=8*MIB
                && c.memory_bytes<=isize::MAX as u64 && c.concurrency>0
                && c.concurrency<=c.memory_bytes as usize/65536
                && c.cache_bytes>=4096 && c.cache_bytes<=c.memory_bytes/4
                && c.batch_steps>0 && c.batch_steps<=c.memory_bytes as usize/8192
                && c.network_requests>0 && c.network_requests<=c.memory_bytes as usize/65536=>Ok(()),
            (Profile::Custom,_)=>Err("custom requires positive, internally consistent memory, concurrency, cache, batch and network limits".into()),
            (_,None)=>Ok(()),
            _=>Err("custom settings require the custom profile".into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observed {
    pub memory_total: u64,
    pub memory_available: u64,
    pub memory_limit: u64,
    pub process_rss: u64,
    pub peak_rss: u64,
    pub process_cpu_ms: u64,
    pub cpu_millis: u64,
    pub load_millis: u64,
    pub disk_available: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub memory_bytes: u64,
    pub concurrency: usize,
    pub cache_bytes: u64,
    pub batch_steps: usize,
    pub network_requests: usize,
    pub yield_ms: u64,
    pub paused: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub selection: Selection,
    pub budget: Budget,
    pub observed: Observed,
    pub timestamp_ms: u64,
    pub pid: u32,
}
impl Snapshot {
    pub fn derive(selection: Selection, observed: Observed, capacity: u64) -> Result<Self, String> {
        selection.validate()?;
        if observed.memory_total == 0 || observed.memory_limit == 0 || observed.cpu_millis == 0 {
            return Err("hardware observation is incomplete".into());
        }
        let heavy = selection.profile == Profile::Heavy;
        let light = selection.profile == Profile::Light;
        let reserve = memory_reserve(selection.profile, observed.memory_limit);
        let safe = observed.memory_limit.saturating_sub(reserve).min(
            observed
                .process_rss
                .saturating_add(observed.memory_available)
                .saturating_sub(reserve),
        );
        let desired = match selection.profile {
            Profile::Light => 64 * MIB,
            Profile::Dynamic => (observed.memory_limit / 8).max(32 * MIB),
            Profile::Heavy => observed.memory_limit,
            Profile::Custom => {
                selection
                    .custom
                    .as_ref()
                    .expect("validated custom")
                    .memory_bytes
            }
        };
        let memory = desired.min(safe).min(capacity);
        let cpus = (observed.cpu_millis / 1000).max(1) as usize;
        let idle = observed
            .cpu_millis
            .saturating_sub(observed.load_millis)
            .max(1000);
        let slots = if light {
            1
        } else if heavy {
            // Providers also wait for I/O. Allow bounded oversubscription and
            // one lane per role; installed worker and OS CPU ceilings remain.
            cpus.saturating_mul(2)
                .max(super::limits().workers.len())
                .min((memory / (16 * MIB)).max(1) as usize)
        } else if selection.profile == Profile::Custom {
            ((idle / 1000).max(1) as usize)
                .min(cpus)
                .min((memory / (16 * MIB)).max(1) as usize)
        } else {
            ((idle / 2000).max(1) as usize).min(cpus)
        };
        let concurrency = selection
            .custom
            .as_ref()
            .map_or(slots, |c| c.concurrency.min(slots));
        let cache = selection
            .custom
            .as_ref()
            .map_or(memory / if heavy { 8 } else { 16 }, |c| c.cache_bytes)
            .min(memory / 4)
            .max(4096);
        let batch = if light {
            16
        } else if heavy {
            512
        } else {
            64
        };
        let batch = selection
            .custom
            .as_ref()
            .map_or(batch, |c| c.batch_steps)
            .min((memory as usize / 8192).max(1));
        let network = if light {
            1
        } else {
            concurrency.saturating_mul(if heavy { 4 } else { 2 })
        };
        let network = selection
            .custom
            .as_ref()
            .map_or(network, |c| c.network_requests)
            .min(super::limits().flights);
        let paused = if memory < 8 * MIB || observed.process_rss > memory {
            Some("memory pressure".into())
        } else if observed.disk_available
            < super::limits().disk_reserve_bytes.saturating_add(2 * MIB)
        {
            Some("disk pressure".into())
        } else {
            None
        };
        let pressure = paused.is_some();
        Ok(Self {
            selection,
            budget: Budget {
                memory_bytes: memory,
                concurrency: if pressure { 0 } else { concurrency },
                cache_bytes: cache,
                batch_steps: if pressure { 0 } else { batch },
                network_requests: if pressure { 0 } else { network },
                yield_ms: if heavy {
                    0
                } else if light {
                    100
                } else if observed.load_millis >= observed.cpu_millis {
                    50
                } else {
                    5
                },
                paused,
            },
            observed,
            timestamp_ms: now_ms()?,
            pid: std::process::id(),
        })
    }
}
fn now_ms() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis(),
    )
    .map_err(|e| e.to_string())
}
struct Live {
    snapshot: Snapshot,
    // Observed RSS already includes existing charged allocations. Retain this
    // baseline so the live headroom does not charge those bytes a second time.
    charged: usize,
}
static LIVE: OnceLock<RwLock<Option<Live>>> = OnceLock::new();
pub fn current() -> Option<Snapshot> {
    let live = LIVE.get()?.read().ok()?;
    live.as_ref().map(|live| live.snapshot.clone())
}
pub(crate) fn publish(snapshot: Snapshot) {
    let mut live = LIVE
        .get_or_init(|| RwLock::new(None))
        .write()
        .expect("budget owner");
    *live = Some(Live {
        snapshot,
        charged: super::memory_usage().0,
    });
}
pub(crate) fn work_available() -> bool {
    live_limit(1, |budget| {
        usize::from(budget.paused.is_none() && budget.batch_steps > 0 && budget.concurrency > 0)
    }) > 0
}

fn memory_reserve(profile: Profile, limit: u64) -> u64 {
    (limit / if profile == Profile::Heavy { 20 } else { 8 }).max(64 * MIB)
}

/// The model is a separately installed process allocation. Its initial full
/// allowance must fit without consuming the existing hardware safety reserve.
pub(crate) fn model_memory_available(bytes: u64) -> bool {
    current().is_none_or(|live| {
        live.budget.paused.is_none()
            && live.budget.concurrency > 0
            && bytes
                <= live
                    .observed
                    .memory_available
                    .saturating_sub(memory_reserve(
                        live.selection.profile,
                        live.observed.memory_limit,
                    ))
    })
}
/// Hold the live read boundary through the atomic reservation. A reduction
/// cannot race past admission; already admitted leases remain valid and drain.
pub(crate) fn reserve_memory<R>(capacity: usize, reserve: impl FnOnce(usize) -> R) -> R {
    let Some(live) = LIVE.get() else {
        return reserve(capacity);
    };
    let Ok(live) = live.read() else {
        return reserve(0);
    };
    let limit = live.as_ref().map_or(capacity, |live| {
        let snapshot = &live.snapshot;
        if snapshot.budget.paused.is_some() {
            return 0;
        }
        let target = usize::try_from(snapshot.budget.memory_bytes).unwrap_or(usize::MAX);
        let headroom = usize::try_from(
            snapshot
                .budget
                .memory_bytes
                .saturating_sub(snapshot.observed.process_rss),
        )
        .unwrap_or(usize::MAX);
        capacity
            .min(target)
            .min(live.charged.saturating_add(headroom))
    });
    reserve(limit)
}
pub(crate) fn slots(capacity: usize) -> usize {
    live_limit(capacity, |b| b.concurrency)
}
pub(crate) fn network(capacity: usize) -> usize {
    live_limit(capacity, |b| b.network_requests)
}
pub(crate) fn cache(capacity: usize) -> usize {
    live_limit(capacity, |b| b.cache_bytes as usize)
}
pub(crate) fn batch(capacity: usize) -> usize {
    live_limit(capacity, |b| b.batch_steps)
}
fn live_limit(capacity: usize, limit: impl FnOnce(&Budget) -> usize) -> usize {
    let Some(live) = LIVE.get() else {
        return capacity;
    };
    let Ok(live) = live.read() else {
        return 0;
    };
    live.as_ref()
        .map_or(capacity, |s| limit(&s.snapshot.budget).min(capacity))
}

pub fn load(directory: &Path) -> Result<Selection, String> {
    let path = directory.join("resource-profile.json");
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Selection::default()),
        Err(e) => return Err(e.to_string()),
    };
    crate::storage::owned_file(&path)?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 4096 {
        return Err("resource selection capacity".into());
    }
    let selection: Selection = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    selection.validate()?;
    Ok(selection)
}
use std::os::unix::fs::OpenOptionsExt;
pub fn save(directory: &Path, selection: &Selection) -> Result<(), String> {
    selection.validate()?;
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    let path = directory.join("resource-profile.json");
    if path.exists() {
        crate::storage::owned_file(&path)?;
    }
    let temporary = directory.join(format!(
        ".resource-profile-{}-{}.tmp",
        std::process::id(),
        now_ms()?
    ));
    crate::storage::write_marker(
        &temporary,
        &serde_json::to_vec(selection).map_err(|e| e.to_string())?,
    )?;
    fs::rename(&temporary, &path).map_err(|e| e.to_string())?;
    fs::File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}
pub fn sample(directory: &Path) -> Result<Observed, String> {
    use nix::sys::time::TimeValLike;
    let (total, available, rss, load) = platform_sample()?;
    let usage = nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_SELF)
        .map_err(|e| e.to_string())?;
    let peak = u64::try_from(usage.max_rss()).map_err(|e| e.to_string())?;
    #[cfg(target_os = "linux")]
    let peak = peak.saturating_mul(1024);
    let mut observed = Observed {
        memory_total: total,
        memory_available: available,
        memory_limit: total,
        process_rss: rss,
        peak_rss: peak,
        process_cpu_ms: u64::try_from(
            usage
                .user_time()
                .num_milliseconds()
                .saturating_add(usage.system_time().num_milliseconds()),
        )
        .map_err(|e| e.to_string())?,
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
    cgroups(&mut observed)?;
    let stats = nix::sys::statvfs::statvfs(directory).map_err(|e| e.to_string())?;
    observed.disk_available = (u128::from(stats.blocks_available())
        * u128::from(stats.fragment_size()))
    .min(u128::from(u64::MAX)) as u64;
    Ok(observed)
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
    let rss = command(
        "/bin/ps",
        &["-o", "rss=", "-p", &std::process::id().to_string()],
    )?
    .trim()
    .parse::<u64>()
    .map_err(|e| e.to_string())?
    .saturating_mul(1024);
    let load = command("/usr/sbin/sysctl", &["-n", "vm.loadavg"])?;
    let load = load
        .split_whitespace()
        .nth(1)
        .ok_or("missing system load")?
        .parse::<f64>()
        .map_err(|e| e.to_string())?;
    Ok((total, available, rss, (load * 1000.0) as u64))
}
#[cfg(target_os = "linux")]
fn cgroups(observed: &mut Observed) -> Result<(), String> {
    let membership = read_small(Path::new("/proc/self/cgroup"))?;
    apply_cgroups(observed, Path::new("/sys/fs/cgroup"), &membership)
}
#[cfg(any(test, target_os = "linux"))]
fn apply_cgroups(observed: &mut Observed, root: &Path, membership: &str) -> Result<(), String> {
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
