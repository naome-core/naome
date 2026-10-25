//! Canonical startup capacity, live work admission and resource custody.
//! Native startup calibrates capacity once; explicit owner profiles remain
//! ceilings. Live budgets may shrink without redefining stored/protocol formats.
//! See `resources/README.md` for the ownership and calibration contract.
use serde::{Deserialize, Serialize};
#[cfg(unix)]
pub mod adaptive;
mod calibration;
mod computation;
pub(crate) mod feedback;
mod operating;
pub use computation::ComputationState;
pub(crate) use computation::{Computation, ComputationPermit};
use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

pub const PROFILE_VERSION: u8 = 1;
const MIB: usize = 1024 * 1024;
// The state owner runs one checker at a time. This covers decoded trees,
// reconstruction temporaries and per-step vectors under its canonical work cap.
const CHECKER_RESERVE: usize = 64 * naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES;
pub(crate) const COMMAND_PARSE_OVERHEAD: usize = 32 * 1024;
// An execution budget, not an estimate of arbitrary JSON expansion. The CLI
// counts tree allocations before parsing and rejects work beyond this budget.
const COMMAND_PARSE_BUDGET_RATIO: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceProfile {
    pub version: u8,
    /// Charged working memory for one process, including conservative overhead.
    pub memory_bytes: usize,
    /// Physical provider slots: finding, solving, local interest, peer interest.
    pub workers: [usize; 4],
    pub tuning: Tuning,
}
impl Default for ResourceProfile {
    fn default() -> Self {
        Self {
            version: PROFILE_VERSION,
            memory_bytes: 512 * MIB,
            workers: [1, 2, 2, 2],
            tuning: Tuning::default(),
        }
    }
}

// One table owns defaults, optional operator overrides and resolved limits.
// Scaled fields follow process memory; fixed fields are per-operation defaults.
macro_rules! resource_policy {
    (scaled {$($scaled:ident: $sty:ty = $svalue:expr;)*}
     fixed {$($fixed:ident: $fty:ty = $fvalue:expr;)*}
     timers {$($timer:ident, $milliseconds:ident = $tvalue:expr;)*}) => {
        #[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct Tuning {
            $(pub $scaled: Option<$sty>,)*
            $(pub $fixed: Option<$fty>,)*
            $(pub $milliseconds: Option<u64>,)*
        }
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct Limits {
            pub memory_bytes: usize,
            pub workers: [usize;4],
            pub resident_jobs: usize,
            $(pub $scaled: $sty,)*
            $(pub $fixed: $fty,)*
            $(pub $timer: Duration,)*
        }
        /// Reference defaults; all active allocations use limits().
        pub const DEFAULT: Limits = Limits {
            memory_bytes:512*MIB,workers:[1,2,2,2],resident_jobs:7+4*8+32,
            $($scaled:$svalue,)* $($fixed:$fvalue,)* $($timer:$tvalue,)*
        };
        impl ResourceProfile {
            pub fn resolve(&self)->Result<Limits,String>{
                if self.version!=PROFILE_VERSION{return Err("unsupported resource profile version".into());}
                if self.memory_bytes==0||self.memory_bytes>isize::MAX as usize{return Err("invalid process memory budget".into());}
                let scale=|value:usize|usize::try_from(value as u128 * self.memory_bytes as u128 / DEFAULT.memory_bytes as u128).map(|n|n.max(1)).map_err(|_| "resource scaling overflow");
                let mut limits=Limits{
                    memory_bytes:self.memory_bytes,workers:self.workers,resident_jobs:0,
                    $($scaled:match self.tuning.$scaled {Some(value)=>value,None=><$sty>::try_from(scale(DEFAULT.$scaled as usize)?).map_err(|_|concat!(stringify!($scaled)," width"))?},)*
                    $($fixed:self.tuning.$fixed.unwrap_or(DEFAULT.$fixed),)*
                    $($timer:self.tuning.$milliseconds.map(Duration::from_millis).unwrap_or(DEFAULT.$timer),)*
                };
                limits.solving_jobs=self.tuning.solving_jobs.unwrap_or(self.workers[1]);
                limits.resident_jobs=self.workers.iter().try_fold(0usize,|n,w|n.checked_add(*w)).and_then(|n|n.checked_add(limits.queued_jobs_per_role.checked_mul(self.workers.len())?)).and_then(|n|n.checked_add(limits.terminal_job_page)).ok_or("resident working-set overflow")?;
                limits.validate()?;Ok(limits)
            }
        }
        impl Limits {
            fn validate_positive(&self)->Result<(),String>{
                $(if self.$scaled==0 || self.$scaled as u128 > self.memory_bytes as u128 {return Err(concat!(stringify!($scaled)," exceeds its allocation budget or is zero").into());})*
                $(if self.$fixed==0{return Err(concat!(stringify!($fixed)," must be positive").into());})*
                $(if self.$timer.is_zero()||self.$timer.as_millis()>u128::from(u64::MAX)||Instant::now().checked_add(self.$timer).is_none(){return Err(concat!("invalid ",stringify!($timer)).into());})*
                Ok(())
            }
        }
    };
}
resource_policy! {
    scaled {
        registry_index_cache_bytes: usize = 4 * 1024 * 1024;
        checked_index_cache_bytes: usize = 4 * 1024 * 1024;
        checkpoint_cache_bytes: usize = 2 * 1024 * 1024;
        catalog_cache_bytes: usize = 8 * 1024 * 1024;
        pending_page: usize = 128;
        checked_cache_bytes: usize = 32 * 1024 * 1024;
        batch_objects: usize = 4096;
        batch_bytes: usize = 64 * 1024 * 1024;
        replay_page: usize = 64;
        id_page: usize = 128;
        configured_peers: usize = 16;
        network_config_bytes: usize = 524_288;
        fetches: usize = 128;
        flights: usize = 16;
        flights_per_peer: usize = 2;
        command_bytes: usize = 524_288;
        inventory_page: usize = 64;
        status_page: usize = 64;
        transport_events: usize = 64;
        contacts: usize = 16;
        addresses_per_contact: usize = 4;
        application_queries: usize = 2;
        dht_parallelism: usize = 2;
        dht_replication: usize = 8;
        dht_bucket_size: usize = 8;
        discovery_interfaces:usize = 8;
        bootstrap_peers: usize = 4;
        relay_peers: usize = 2;
        relay_circuits: usize = 16;
        relay_reservations: usize = 16;
        relay_circuits_per_peer: usize = 4;
        queued_metadata: usize = 8;
        closure_objects: usize = 128;
        closure_bytes: usize = 512 * 1024;
        closure_steps: usize = 4096;
        interest_decisions: usize = 4;
        question_page: usize = 128;
        question_commands: usize = 8;
        finding_admissions: usize = 4;
        job_commands: usize = 32;
        active_job_bytes: usize = 32 * 1024 * 1024;
        queued_jobs_per_role: usize = 8;
        terminal_job_page: usize = 32;
        provider_stream_bytes: usize = 4 * 1024 * 1024;
    }
    fixed {
        disk_reserve_bytes: u64 = 128 * 1024 * 1024;
        diagnostic_bytes: usize = 4096;
        dht_packet_bytes: usize = 4096;
        relay_request_burst: usize = 4;
        relay_reservations_per_peer: usize = 1;
        failure_detail_bytes: usize = 512;
        supervisor_commands: usize = 8;
        provider_events: usize = 16;
        developer_objects: usize = 8;
        developer_questions: usize = 128;
        retained_generations: usize = 4;
        compaction_bytes: usize = naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES;
        compaction_records: usize = 128;
        checker_cache_bytes: usize = 2 * 1024 * 1024;
        question_cache_bytes: usize = 256 * 1024;
        checker_cache_entries: usize = 64;
        owner_text_bytes: usize = 1024;
        request_burst: usize = 8;
        wanted_attempts: usize = 16;
        gossip_packet_bytes: usize = 1024;
        producer_bytes: usize = 65_536;
        producer_sources: usize = 32;
        exchange_streams: usize = 4;
        inbound_streams: usize = 16;
        identify_protocol_bytes: usize = 256;
        replay_guard_bytes: usize = 384 * 1024 * 1024;
        upgrade_connections_per_peer: u32 = 3;
        connections_per_peer: u32 = 2;
        established_connections: u32 = 32;
        pending_connections: u32 = 16;
        cli_commands: usize = 8;
        control_clients: usize = 8;
        inbound_frames: usize = 32;
        proof_bytes: usize = 65_536;
        proof_dependencies: usize = 32;
        address_bytes: usize = 512;
        relay_circuit_bytes: u64 = 8 * 1024 * 1024;
        closure_work_bytes: usize = 128 * naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES;
        solving_jobs: usize = 2;
        publications: usize = 4;
        publication_retries: u32 = 8;
        waiters_per_job: usize = 4;
        log_segment_bytes: u64 = 1024 * 1024;
        assessment_formula_nodes:usize = naome_checker::question::AssessmentLimits::MAXIMUM.formula_nodes;
        assessment_dependencies:usize = naome_checker::question::AssessmentLimits::MAXIMUM.dependencies;
        assessment_operations:usize = naome_checker::question::AssessmentLimits::MAXIMUM.operations;
        assessment_work_bytes:usize = naome_checker::question::AssessmentLimits::MAXIMUM.formula_work_bytes;
        assessment_certificate_steps:usize = naome_checker::question::AssessmentLimits::MAXIMUM.certificate_steps;
        assessment_certificate_bytes:usize = naome_checker::question::AssessmentLimits::MAXIMUM.certificate_bytes;
        job_work_units:u32 = 4096;
    }
    timers {
        transport_busy_grace, transport_busy_grace_ms = Duration::from_millis(10);
        custody_poll_interval, custody_poll_interval_ms = Duration::from_millis(10);
        replay_guard_timeout, replay_guard_timeout_ms = Duration::from_secs(1800);
        replay_guard_freshness, replay_guard_freshness_ms = Duration::from_secs(2);
        finding_interval, finding_interval_ms = Duration::from_secs(5);
        solving_interval, solving_interval_ms = Duration::from_secs(1);
        job_horizon, job_horizon_ms = Duration::from_secs(24*60*60);
        request_rate_window, request_rate_window_ms = Duration::from_secs(1);
        relay_rate_window, relay_rate_window_ms = Duration::from_secs(2);
        publication_backoff, publication_backoff_ms = Duration::from_secs(1);
        lifecycle_poll_interval, lifecycle_poll_interval_ms = Duration::from_millis(50);
        lifecycle_abort_timeout, lifecycle_abort_timeout_ms = Duration::from_secs(10);
        detach_poll_interval, detach_poll_interval_ms = Duration::from_millis(5);
        detach_confirm_timeout, detach_confirm_timeout_ms = Duration::from_millis(150);
        cleanup_poll_interval, cleanup_poll_interval_ms = Duration::from_millis(20);
        supervisor_cleanup_timeout, supervisor_cleanup_timeout_ms = Duration::from_secs(1);
        supervisor_poll_interval, supervisor_poll_interval_ms = Duration::from_millis(50);
        provider_drain_timeout, provider_drain_timeout_ms = Duration::from_secs(3);
        provider_announce_interval, provider_announce_interval_ms = Duration::from_secs(10);
        profile_poll_interval, profile_poll_interval_ms = Duration::from_secs(1);
        production_interval, production_interval_ms = Duration::from_secs(1);
        gossip_heartbeat, gossip_heartbeat_ms = Duration::from_secs(1);
        idle_connection_timeout, idle_connection_timeout_ms = Duration::from_secs(60);
        job_flush_interval, job_flush_interval_ms = Duration::from_secs(30);
        job_tick_interval, job_tick_interval_ms = Duration::from_secs(1);
        tick_interval, tick_interval_ms = Duration::from_millis(250);
        sqlite_busy_timeout, sqlite_busy_timeout_ms = Duration::from_millis(100);
        pending_retry, pending_retry_ms = Duration::from_secs(30);
        request_timeout, request_timeout_ms = Duration::from_secs(5);
        reconcile_interval, reconcile_interval_ms = Duration::from_secs(2);
        automatic_request_interval, automatic_request_interval_ms = Duration::from_millis(150);
        contact_ttl, contact_ttl_ms = Duration::from_secs(30);
        identify_timeout, identify_timeout_ms = Duration::from_secs(10);
        discovery_interval, discovery_interval_ms = Duration::from_secs(5);
        query_timeout, query_timeout_ms = Duration::from_secs(10);
        provider_ttl, provider_ttl_ms = Duration::from_secs(30);
        mdns_ttl, mdns_ttl_ms = Duration::from_secs(20);
        relay_circuit_duration, relay_circuit_duration_ms = Duration::from_secs(120);
        root_timeout, root_timeout_ms = Duration::from_secs(60);
        interest_timeout, interest_timeout_ms = Duration::from_secs(30);
        control_timeout, control_timeout_ms = Duration::from_secs(2);
        control_request_timeout, control_request_timeout_ms = Duration::from_secs(1);
        lifecycle_timeout, lifecycle_timeout_ms = Duration::from_secs(15);
        startup_timeout, startup_timeout_ms = Duration::from_secs(1800);
    }
}
static LIMITS: OnceLock<Limits> = OnceLock::new();

pub fn limits() -> &'static Limits {
    LIMITS.get_or_init(|| {
        ResourceProfile::default()
            .resolve()
            .expect("valid built-in resource profile")
    })
}

pub fn configure(profile: ResourceProfile) -> Result<&'static Limits, String> {
    let proposed = profile.resolve()?;
    if let Some(current) = LIMITS.get() {
        if current != &proposed {
            return Err(
                "resource profile is immutable after initialization; restart required".into(),
            );
        }
    } else {
        LIMITS
            .set(proposed.clone())
            .map_err(|_| "concurrent resource profile initialization")?;
    }
    Ok(LIMITS.get().expect("initialized resource limits"))
}

/// Native daemons inherit this absolute path from their launching command.
/// Library callers can call configure explicitly before constructing nodes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectiveProfile {
    version: u8,
    limits: Limits,
}
pub fn initialize_from_environment() -> Result<&'static Limits, String> {
    initialize(
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .as_path(),
    )
}

pub(crate) fn initialize_for(directory: &std::path::Path) -> Result<&'static Limits, String> {
    initialize(directory)
}

fn initialize(directory: &std::path::Path) -> Result<&'static Limits, String> {
    if let Some(snapshot) = std::env::var_os("NAOME_EFFECTIVE_RESOURCES") {
        let snapshot = snapshot
            .to_str()
            .ok_or("effective resource profile is not UTF-8")?;
        if snapshot.len() > 64 * 1024 {
            return Err("effective resource profile capacity".into());
        }
        let effective: EffectiveProfile = serde_json::from_str(snapshot)
            .map_err(|e| format!("effective resource profile: {e}"))?;
        if effective.version != PROFILE_VERSION {
            return Err("unsupported effective resource profile".into());
        }
        effective.limits.validate()?;
        if let Some(current) = LIMITS.get() {
            if current != &effective.limits {
                return Err("resource profile changed after initialization".into());
            }
        } else {
            LIMITS
                .set(effective.limits)
                .map_err(|_| "concurrent resource initialization")?;
        }
        return Ok(limits());
    }
    let mut automatic = None;
    let profile = match std::env::var_os("NAOME_RESOURCE_CONFIG") {
        Some(path) => {
            let path = std::fs::canonicalize(path).map_err(|e| format!("resource profile: {e}"))?;
            let bytes = crate::store::read_bounded(&path, 64 * 1024)?;
            serde_json::from_slice(&bytes).map_err(|e| format!("resource profile: {e}"))?
        }
        None => {
            let location = directory
                .ancestors()
                .find(|path| path.is_dir())
                .ok_or("resource observation directory is unavailable")?;
            let observed = adaptive::sample(location)?;
            let profile = calibration::capacity(&observed)?;
            let selection = if directory.is_dir() {
                adaptive::load(directory)?
            } else {
                adaptive::Selection::default()
            };
            automatic = Some((selection, observed));
            profile
        }
    };
    let capacity = configure(profile)?;
    if let Some((selection, observed)) = automatic {
        adaptive::publish(adaptive::Snapshot::derive(
            selection,
            observed,
            capacity.memory_bytes as u64,
        )?);
    }
    Ok(capacity)
}

/// Live work admission below the installed capacity. Stored formats, external
/// custody and already admitted leases always use their owning fixed contracts.
pub(crate) fn active_limits() -> Arc<Limits> {
    adaptive::operating_limits()
}

pub(crate) fn program_cache(bytes: u64) -> u64 {
    if adaptive::current().is_some() {
        operating::program_cache(limits(), bytes)
    } else {
        bytes
    }
}
/// Spawned daemons/providers inherit exact resolved values rather than reloading
/// a file that an operator might have edited while their parent was running.
pub(crate) fn child_snapshot() -> Result<String, String> {
    serde_json::to_string(&EffectiveProfile {
        version: PROFILE_VERSION,
        limits: limits().clone(),
    })
    .map_err(|e| e.to_string())
}

#[cfg(test)]
thread_local! {
    static TEST_DISK: std::cell::Cell<Option<(u64, u128)>> = const { std::cell::Cell::new(None) };
    static TEST_MEMORY_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn with_disk_available<T>(available: u128, action: impl FnOnce() -> T) -> T {
    static VOLUME: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
    let volume = VOLUME.fetch_sub(1, Ordering::Relaxed);
    struct Reset(Option<(u64, u128)>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_DISK.with(|value| value.set(self.0));
        }
    }
    let _reset = Reset(TEST_DISK.with(|value| value.replace(Some((volume, available)))));
    action()
}
#[cfg(test)]
pub(crate) fn fail_next_memory_allocation() {
    TEST_MEMORY_FAILURE.with(|value| value.set(true));
}

static DISK_RESERVATIONS: std::sync::Mutex<std::collections::BTreeMap<u64, u128>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());
/// Transferable custody for concurrent preparations on the same filesystem.
/// Closing/recovery writes may consume the separately preserved emergency reserve.
#[derive(Debug)]
pub(crate) struct DiskLease {
    volume: u64,
    bytes: u128,
}
impl DiskLease {
    pub(crate) fn recheck(&self, path: &std::path::Path) -> Result<(), crate::Error> {
        let stats = nix::sys::statvfs::statvfs(path).map_err(|e| e.to_string())?;
        let available = u128::from(stats.blocks_available()) * u128::from(stats.fragment_size());
        #[cfg(test)]
        let available = TEST_DISK
            .with(|value| value.get())
            .map_or(available, |(_, available)| available);
        let held = *DISK_RESERVATIONS
            .lock()
            .map_err(|_| "disk reservation lock poisoned")?
            .get(&self.volume)
            .unwrap_or(&0);
        let required = u128::from(limits().disk_reserve_bytes) + held;
        if available < required {
            return Err(crate::Error::DiskOverload {
                available,
                required,
            });
        }
        Ok(())
    }
    pub(crate) fn acquire(path: &std::path::Path, additional: u64) -> Result<Self, crate::Error> {
        use std::os::unix::fs::MetadataExt;
        let volume = std::fs::metadata(path).map_err(|e| e.to_string())?.dev();
        let stats = nix::sys::statvfs::statvfs(path).map_err(|e| e.to_string())?;
        let available = u128::from(stats.blocks_available()) * u128::from(stats.fragment_size());
        #[cfg(test)]
        let (volume, available) = TEST_DISK
            .with(|value| value.get())
            .unwrap_or((volume, available));
        let mut reservations = DISK_RESERVATIONS
            .lock()
            .map_err(|_| "disk reservation lock poisoned")?;
        let held = reservations.entry(volume).or_default();
        let next = held
            .checked_add(u128::from(additional))
            .ok_or("disk reservation overflow")?;
        let required = u128::from(limits().disk_reserve_bytes) + next;
        if available < required {
            return Err(crate::Error::DiskOverload {
                available,
                required,
            });
        }
        *held = next;
        Ok(Self {
            volume,
            bytes: u128::from(additional),
        })
    }
}
impl Drop for DiskLease {
    fn drop(&mut self) {
        let mut reservations = DISK_RESERVATIONS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(held) = reservations.get_mut(&self.volume) {
            *held -= self.bytes;
            if *held == 0 {
                reservations.remove(&self.volume);
            }
        }
    }
}
pub(crate) fn require_disk_space(
    path: &std::path::Path,
    additional: u64,
) -> Result<(), crate::Error> {
    DiskLease::acquire(path, additional).map(drop)
}

impl Limits {
    pub fn validate(&self) -> Result<(), String> {
        self.validate_positive()?;
        if self.memory_bytes == 0 || self.memory_bytes > isize::MAX as usize {
            return Err("invalid process memory budget".into());
        }
        // These external custody ceilings can only be narrowed. The caller
        // retains two 64 MiB reserves and the original 30 minute window.
        if self.replay_guard_bytes > 384 * MIB
            || self
                .replay_guard_bytes
                .checked_add(128 * MIB)
                .is_none_or(|n| n > self.memory_bytes)
            || self.replay_guard_timeout > Duration::from_secs(1800)
            || self.replay_guard_freshness > Duration::from_secs(2)
            || self.custody_poll_interval > self.replay_guard_freshness
            || self.transport_busy_grace > self.control_timeout
        {
            return Err("resource profile would weaken replay custody guarantees".into());
        }
        let workers = self
            .workers
            .iter()
            .try_fold(
                0usize,
                |n, w| if *w == 0 { None } else { n.checked_add(*w) },
            )
            .ok_or("invalid provider worker allocation")?;
        naome_checker::ReadCacheLimits::new(self.checker_cache_entries, self.checker_cache_bytes)
            .map_err(|_| "checker read cache exceeds its byte budget")?;
        for count in [
            self.inbound_frames,
            self.control_clients,
            self.cli_commands,
            self.pending_page,
            self.resident_jobs,
            self.queued_jobs_per_role,
            self.waiters_per_job,
            self.transport_events,
            self.inbound_streams,
            self.producer_sources,
            self.developer_questions,
            self.developer_objects,
            self.provider_events,
            self.supervisor_commands,
            self.question_page,
            self.question_commands,
            self.job_commands,
            self.application_queries,
            self.dht_parallelism,
            self.dht_replication,
            self.dht_bucket_size,
            self.relay_request_burst,
            self.relay_reservations_per_peer,
            self.batch_objects,
            self.id_page,
            self.inventory_page,
            self.status_page,
            self.configured_peers,
            self.fetches,
            self.flights,
            self.flights_per_peer,
            self.contacts,
            self.addresses_per_contact,
            self.bootstrap_peers,
            self.relay_peers,
            self.relay_circuits,
            self.relay_reservations,
            self.relay_circuits_per_peer,
            self.queued_metadata,
            self.closure_objects,
            self.closure_steps,
            self.interest_decisions,
            self.finding_admissions,
            self.solving_jobs,
            self.publications,
            self.compaction_records,
            self.checker_cache_entries,
            self.wanted_attempts,
            self.exchange_streams,
            self.producer_sources,
            self.request_burst,
        ] {
            if count > self.memory_bytes / 512 {
                return Err("resource count exceeds process allocation budget".into());
            }
        }
        for bytes in [
            self.diagnostic_bytes,
            self.dht_packet_bytes,
            self.failure_detail_bytes,
            self.producer_bytes,
            self.owner_text_bytes,
            self.command_bytes,
            self.identify_protocol_bytes,
            self.gossip_packet_bytes,
            self.address_bytes,
            self.compaction_bytes,
        ] {
            if bytes > self.memory_bytes {
                return Err("single buffer exceeds process memory budget".into());
            }
        }
        let contact_bytes = self
            .addresses_per_contact
            .checked_mul(
                self.address_bytes
                    .checked_add(128)
                    .ok_or("contact allocation overflow")?,
            )
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(1024))
            .ok_or("contact allocation overflow")?;
        if self
            .contacts
            .checked_mul(contact_bytes)
            .is_none_or(|n| n > self.memory_bytes / 4)
            || self.configured_peers > self.contacts
            || self.bootstrap_peers > self.contacts
            || self.relay_peers > self.contacts
            || self.dht_parallelism > self.contacts
            || self.dht_replication > self.contacts
            || self.dht_bucket_size > self.contacts
            || self.relay_reservations_per_peer > self.relay_reservations
            || self.producer_bytes > self.memory_bytes / 8
            || self.owner_text_bytes > self.memory_bytes / 16
            || self.gossip_packet_bytes > self.memory_bytes / 16
            || self.exchange_streams > self.inbound_streams
            || self.compaction_bytes < naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES
            || self.closure_bytes
                < self
                    .proof_bytes
                    .saturating_add(self.proof_dependencies.saturating_mul(32))
                    .saturating_add(256)
        {
            return Err("inconsistent contact, parser, compaction or closure allocation".into());
        }
        let provider_frames = workers
            .checked_mul(self.provider_stream_bytes)
            .ok_or("provider memory overflow")?;
        let transport_frames = self
            .flights
            .checked_mul(self.proof_bytes)
            .and_then(|n| n.checked_mul(4))
            .ok_or("transport memory overflow")?;
        let index_caches = self
            .checked_index_cache_bytes
            .checked_mul(
                self.retained_generations
                    .checked_add(2)
                    .ok_or("retained index count overflow")?,
            )
            .and_then(|n| {
                n.checked_add(
                    self.registry_index_cache_bytes
                        .checked_mul(self.retained_generations + 2)?,
                )
            })
            .and_then(|n| n.checked_add(self.catalog_cache_bytes))
            .and_then(|n| n.checked_add(self.checkpoint_cache_bytes.checked_mul(3)?))
            .and_then(|n| n.checked_add(self.checker_cache_bytes))
            .and_then(|n| n.checked_add(self.question_cache_bytes))
            .and_then(|n| n.checked_add(self.checked_cache_bytes / 4))
            .ok_or("index cache allocation overflow")?;
        let queued_commands = self
            .cli_commands
            .checked_add(2)
            .and_then(|n| n.checked_mul(self.command_bytes.checked_mul(2)?.checked_add(2)?))
            .and_then(|n| n.checked_add(self.command_parse_budget()?))
            .ok_or("command queue memory overflow")?;
        let charged = self
            .checked_cache_bytes
            .checked_add(self.active_job_bytes)
            .and_then(|n| n.checked_add(self.closure_bytes.checked_mul(64)?))
            .and_then(|n| n.checked_add(provider_frames))
            .and_then(|n| n.checked_add(transport_frames))
            .and_then(|n| n.checked_add(queued_commands))
            .and_then(|n| n.checked_add(index_caches))
            .and_then(|n| n.checked_add(CHECKER_RESERVE))
            .ok_or("resource allocation overflow")?;
        if charged > self.memory_bytes {
            return Err(format!(
                "resource allocations {charged} exceed memory budget {}",
                self.memory_bytes
            ));
        }
        if self.proof_bytes > naome_proof::CERTIFICATE_MAX_BYTES
            || self.proof_dependencies > naome_proof::CERTIFICATE_MAX_STEPS
            || self
                .proof_bytes
                .checked_mul(8)
                .is_none_or(|n| n > self.memory_bytes)
            || self.closure_bytes < self.proof_bytes
            || self.flights_per_peer > self.flights
            || self.relay_circuits_per_peer > self.relay_circuits
            || self.resident_jobs < workers
            || self.id_page > self.memory_bytes / 32
            || self.replay_page > self.memory_bytes / self.proof_bytes
            || self.terminal_job_page > self.resident_jobs
            || self.solving_jobs > self.workers[1]
            || self.discovery_interfaces > self.memory_bytes / (64 * 1024)
            || self.provider_stream_bytes < self.closure_bytes.saturating_mul(8)
            || self.inventory_page > self.id_page
            || self.inventory_page > self.fetches
            || self
                .inventory_page
                .checked_mul(128)
                .is_none_or(|n| n > self.proof_bytes * 2)
            || self.connections_per_peer > self.upgrade_connections_per_peer
            || self.upgrade_connections_per_peer > self.established_connections
            || self.resident_jobs
                != workers + self.workers.len() * self.queued_jobs_per_role + self.terminal_job_page
            || self.resident_jobs > crate::checkpoint::MAX_HEADER / 24
            || self
                .closure_bytes
                .checked_mul(8)
                .is_none_or(|n| n > crate::checkpoint::MAX_ROW)
            || self.command_bytes < 6 * self.owner_text_bytes + 512
        {
            return Err("inconsistent resource limits or unsupported canonical proof size".into());
        }
        let maximum = naome_checker::question::AssessmentLimits::MAXIMUM;
        for (value, max) in [
            (self.assessment_formula_nodes, maximum.formula_nodes),
            (self.assessment_dependencies, maximum.dependencies),
            (self.assessment_operations, maximum.operations),
            (self.assessment_work_bytes, maximum.formula_work_bytes),
            (self.assessment_certificate_steps, maximum.certificate_steps),
            (self.assessment_certificate_bytes, maximum.certificate_bytes),
        ] {
            if value > max {
                return Err("assessment policy exceeds supported deterministic work format".into());
            }
        }
        Ok(())
    }
    pub(crate) fn assessment_policy(&self) -> naome_checker::question::PrefilterPolicy {
        naome_checker::question::PrefilterPolicy {
            limits: naome_checker::question::AssessmentLimits {
                formula_nodes: self.assessment_formula_nodes,
                dependencies: self.assessment_dependencies,
                operations: self.assessment_operations,
                formula_work_bytes: self.assessment_work_bytes,
                certificate_steps: self.assessment_certificate_steps,
                certificate_bytes: self.assessment_certificate_bytes,
            },
            ..Default::default()
        }
    }
    fn resident_reservation(&self) -> usize {
        let workers = self.workers.iter().sum::<usize>();
        CHECKER_RESERVE
            + self.checked_cache_bytes
            + self.active_job_bytes
            + workers * self.provider_stream_bytes
            + self.checked_index_cache_bytes * (self.retained_generations + 2)
            + self.registry_index_cache_bytes * (self.retained_generations + 2)
            + self.catalog_cache_bytes
            + 3 * self.checkpoint_cache_bytes
            + self.checker_cache_bytes
            + self.question_cache_bytes
            + self.checked_cache_bytes / 4
    }
    fn allocation_budget(&self) -> usize {
        self.memory_bytes - self.resident_reservation()
    }
    pub(crate) fn command_parse_budget(&self) -> Option<usize> {
        self.command_bytes
            .checked_mul(COMMAND_PARSE_BUDGET_RATIO)?
            .checked_add(COMMAND_PARSE_OVERHEAD)
    }
}

#[derive(Debug)]
struct Memory {
    limit: usize,
    used: AtomicUsize,
}
static MEMORY: OnceLock<Arc<Memory>> = OnceLock::new();
/// Shared physical allocation charge; cloning an Arc lease does not charge
/// immutable shared bytes twice. Failure is explicit and never drops history.
#[derive(Debug)]
pub(crate) struct MemoryLease {
    memory: Arc<Memory>,
    bytes: usize,
}
impl MemoryLease {
    pub(crate) fn acquire(bytes: usize) -> Result<Arc<Self>, crate::Error> {
        #[cfg(test)]
        if TEST_MEMORY_FAILURE.with(|value| value.replace(false)) {
            return Err(crate::Error::MemoryOverload {
                requested: bytes,
                charged: 0,
                budget: 0,
            });
        }
        let memory = Self::pool();
        if bytes == 0 {
            return Self::allocate(memory, 0);
        }
        adaptive::reserve_memory(memory.limit, |budget| {
            Self::allocate_with_limit(memory, bytes, budget)
        })
    }
    /// Bounded local command ingress and parsing must remain available during
    /// a live work pause. These bytes still obey the immutable shared capacity;
    /// the command's actual work requires separate owner-side admission.
    pub(crate) fn acquire_control(bytes: usize) -> Result<Arc<Self>, crate::Error> {
        Self::allocate(Self::pool(), bytes)
    }
    /// A bounded readback needed to finish an already checked publication may
    /// drain under a reduced target. It still shares the immutable capacity;
    /// this does not admit a new checker operation or external work request.
    pub(crate) fn acquire_drain(bytes: usize) -> Result<Arc<Self>, crate::Error> {
        Self::allocate(Self::pool(), bytes)
    }
    fn pool() -> Arc<Memory> {
        MEMORY
            .get_or_init(|| {
                Arc::new(Memory {
                    limit: limits().allocation_budget(),
                    used: AtomicUsize::new(0),
                })
            })
            .clone()
    }
    fn allocate(memory: Arc<Memory>, bytes: usize) -> Result<Arc<Self>, crate::Error> {
        let limit = memory.limit;
        Self::allocate_with_limit(memory, bytes, limit)
    }
    fn allocate_with_limit(
        memory: Arc<Memory>,
        bytes: usize,
        limit: usize,
    ) -> Result<Arc<Self>, crate::Error> {
        let limit = limit.min(memory.limit);
        memory
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= limit)
            })
            .map_err(|charged| crate::Error::MemoryOverload {
                requested: bytes,
                charged,
                budget: limit,
            })?;
        Ok(Arc::new(Self { memory, bytes }))
    }
}
impl Drop for MemoryLease {
    fn drop(&mut self) {
        self.memory.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

pub(crate) fn require_work_admission() -> Result<(), crate::Error> {
    if adaptive::work_available() {
        Ok(())
    } else {
        Err(crate::Error::ExecutionLimit)
    }
}

pub fn memory_usage() -> (usize, usize) {
    MEMORY.get().map_or((0, limits().allocation_budget()), |m| {
        (m.used.load(Ordering::Acquire), m.limit)
    })
}

#[cfg(test)]
mod tests;
