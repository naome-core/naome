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
#[cfg(any(test, target_os = "linux"))]
use std::io::Read;
use std::{
    fs,
    path::Path,
    sync::{Arc, OnceLock, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
const MIB: u64 = 1024 * 1024;
mod governor;
pub(crate) mod history;
mod observation;
pub(crate) use governor::Governor;
pub(crate) use observation::sample_node;

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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observed {
    pub memory_total: u64,
    pub memory_available: u64,
    pub memory_limit: u64,
    /// Resident bytes of the state-owner process. Descendants are reported
    /// separately so a local work target is not reinterpreted on upgrade.
    pub process_rss: u64,
    pub peak_rss: u64,
    /// Live process-tree CPU time plus reaped child CPU time.
    pub process_cpu_ms: u64,
    pub cpu_millis: u64,
    pub load_millis: u64,
    pub disk_available: u64,
}
impl Observed {
    pub(crate) fn resident_bytes(&self) -> u64 {
        self.process_rss
    }
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
        let reserve = (observed.memory_limit / if heavy { 20 } else { 8 }).max(64 * MIB);
        let safe = observed.memory_limit.saturating_sub(reserve).min(
            observed
                .process_rss
                .saturating_add(observed.memory_available)
                .saturating_sub(reserve),
        );
        let cpus = observed.cpu_millis.div_ceil(1000).max(1) as usize;
        let worker_bytes = (super::limits().provider_stream_bytes as u64).saturating_mul(4);
        let slots = if light {
            1
        } else if heavy {
            cpus
        } else {
            // Begin below the host ceiling; measured demand may grow later.
            cpus.saturating_sub(1).max(1)
        };
        let desired = match selection.profile {
            Profile::Light => observed
                .process_rss
                .saturating_add(super::CHECKER_RESERVE as u64)
                .saturating_add(worker_bytes),
            Profile::Dynamic => observed
                .process_rss
                .saturating_add(super::CHECKER_RESERVE as u64)
                .saturating_add(worker_bytes.saturating_mul(slots as u64)),
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
        let slots = slots.min((memory / worker_bytes.max(1)).max(1) as usize);
        let concurrency = selection
            .custom
            .as_ref()
            .map_or(slots, |c| c.concurrency.min(slots));
        let cache = selection
            .custom
            .as_ref()
            .map_or(
                observed.process_rss.max(worker_bytes)
                    / if light {
                        8
                    } else if heavy {
                        2
                    } else {
                        4
                    },
                |custom| custom.cache_bytes,
            )
            .min(memory / 4)
            .max(4096);
        let batch = selection
            .custom
            .as_ref()
            .map_or(
                if light {
                    1
                } else if heavy {
                    cpus.saturating_mul(2)
                } else {
                    slots.max(2)
                },
                |custom| custom.batch_steps,
            )
            .min((memory as usize / 8192).max(1));
        let network = selection
            .custom
            .as_ref()
            .map_or(if light { 1 } else { concurrency.max(1) }, |custom| {
                custom.network_requests
            })
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
                network_requests: if pressure { network.min(1) } else { network },
                yield_ms: if heavy {
                    0
                } else {
                    let quantum = super::limits().transport_busy_grace.as_millis() as u64;
                    let quota_delay = quantum
                        .saturating_mul(1000u64.saturating_sub(observed.cpu_millis))
                        / observed.cpu_millis.max(1);
                    if light {
                        quantum.saturating_add(quota_delay)
                    } else {
                        quota_delay
                    }
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
    operating: Arc<super::OperatingLimits>,
}
static LIVE: OnceLock<RwLock<Option<Live>>> = OnceLock::new();
static CHANGED: OnceLock<tokio::sync::watch::Sender<()>> = OnceLock::new();

pub(crate) fn work_changes() -> tokio::sync::watch::Receiver<()> {
    CHANGED
        .get_or_init(|| tokio::sync::watch::channel(()).0)
        .subscribe()
}
pub fn current() -> Option<Snapshot> {
    let live = LIVE.get()?.read().ok()?;
    live.as_ref().map(|live| live.snapshot.clone())
}
pub(crate) fn publish(snapshot: Snapshot) {
    let mut live = LIVE
        .get_or_init(|| RwLock::new(None))
        .write()
        .expect("budget owner");
    let operating = Arc::new(super::operating::derive(super::limits(), &snapshot.budget));
    *live = Some(Live {
        operating,
        snapshot,
        charged: super::memory_usage().0,
    });
    if let Some(changed) = CHANGED.get() {
        changed.send_replace(());
    }
}
pub(crate) fn work_available() -> bool {
    inspect_work(|available, _| available)
}

pub(crate) fn inspect_work<R>(inspect: impl FnOnce(bool, Option<&str>) -> R) -> R {
    let Some(live) = LIVE.get() else {
        return inspect(true, None);
    };
    let Ok(live) = live.read() else {
        return inspect(false, Some("resource state unavailable"));
    };
    let Some(live) = live.as_ref() else {
        return inspect(true, None);
    };
    let budget = &live.snapshot.budget;
    let available = budget.paused.is_none() && budget.batch_steps > 0 && budget.concurrency > 0;
    inspect(
        available,
        budget
            .paused
            .as_deref()
            .or((!available).then_some("no computation budget")),
    )
}

/// Keep the budget read boundary through permit creation. A concurrent pause
/// either precedes this admission or observes its already admitted work.
pub(crate) fn admit_work<R>(admit: impl FnOnce() -> R) -> Option<R> {
    inspect_work(|available, _| available.then(admit))
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
        if snapshot.observed.process_rss >= snapshot.budget.memory_bytes {
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
    let Some(bytes) = crate::storage::read_owned(&path, 4096)? else {
        return Ok(Selection::default());
    };
    let selection: Selection = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    selection.validate()?;
    Ok(selection)
}
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
    observation::sample(directory)
}

pub(crate) fn operating_limits() -> Arc<super::OperatingLimits> {
    static CAPACITY: OnceLock<Arc<super::OperatingLimits>> = OnceLock::new();
    LIVE.get()
        .and_then(|live| live.read().ok())
        .and_then(|live| live.as_ref().map(|live| live.operating.clone()))
        .unwrap_or_else(|| {
            CAPACITY
                .get_or_init(|| Arc::new(super::OperatingLimits::at_capacity(super::limits())))
                .clone()
        })
}

#[cfg(test)]
use observation::apply_cgroups;

#[cfg(test)]
mod tests;
