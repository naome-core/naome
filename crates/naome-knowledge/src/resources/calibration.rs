//! Hardware-derived startup capacities. Explicit operator profiles bypass this
//! policy; their immutable resolved ceiling is inherited by every child.
use super::adaptive::Observed;
use super::{CHECKER_RESERVE, DEFAULT, MIB, ResourceProfile, Tuning};

pub(super) fn capacity(observed: &Observed) -> Result<ResourceProfile, String> {
    capacity_with_descriptors(observed, descriptor_budget()?)
}

// Preserve descriptors for the state owner's SQLite generations, control,
// shutdown and recovery. Provider lanes receive only half the remaining pool;
// the other half covers connections, listeners and proof-work files.
const DESCRIPTOR_RESERVE: usize = 64;
const DESCRIPTORS_PER_WORKER: usize = 8;

fn descriptor_budget() -> Result<usize, String> {
    use nix::sys::resource::{Resource, getrlimit};
    let (limit, _) = getrlimit(Resource::RLIMIT_NOFILE).map_err(|error| error.to_string())?;
    #[cfg(target_os = "linux")]
    let directory = "/proc/self/fd";
    #[cfg(not(target_os = "linux"))]
    let directory = "/dev/fd";
    let occupied = std::fs::read_dir(directory)
        .map_err(|error| format!("descriptor observation: {error}"))?
        .count();
    Ok(usize::try_from(limit)
        .unwrap_or(usize::MAX)
        .saturating_sub(occupied)
        .saturating_sub(DESCRIPTOR_RESERVE))
}

fn capacity_with_descriptors(
    observed: &Observed,
    descriptors: usize,
) -> Result<ResourceProfile, String> {
    if descriptors < DESCRIPTOR_RESERVE * 2 {
        return Err(
            "available descriptors cannot preserve provider, transport and recovery reserves"
                .into(),
        );
    }
    let reserve = (observed
        .memory_limit
        .saturating_sub(observed.memory_available)
        / 8)
    .max(128 * MIB as u64);
    let memory = observed
        .memory_limit
        .saturating_sub(reserve)
        .min(
            observed
                .resident_bytes()
                .saturating_add(observed.memory_available)
                .saturating_sub(reserve),
        )
        .min(isize::MAX as u64) as usize;
    // The checker reconstruction allowance and external replay reserves remain
    // hard requirements. Insufficient hardware is explicit, never overcommitted.
    if memory < DEFAULT.replay_guard_bytes + 128 * MIB {
        return Err("available hardware cannot preserve checker and replay reserves".into());
    }
    let working = memory - CHECKER_RESERVE;
    let unit = (working / 128).max(4096);
    let available_cores = usize::try_from(observed.cpu_millis.div_ceil(1000))
        .map_err(|_| "CPU capacity width")?
        .max(1);
    let worker_bytes = DEFAULT.provider_stream_bytes * 4;
    let slots = available_cores
        .min((working / worker_bytes / 4).max(1))
        .min(descriptors / 2 / (4 * DESCRIPTORS_PER_WORKER));
    let cores = slots;
    let pages = (working / DEFAULT.proof_bytes / 64).max(1);
    let wire_page = (DEFAULT.proof_bytes * 2 / 128).max(1);
    let peers = cores
        .saturating_mul(DEFAULT.contacts)
        .min(working / 4096)
        .max(DEFAULT.dht_replication);
    let resident_room = crate::checkpoint::MAX_HEADER / 24;
    let terminal_page = pages
        .min(resident_room.saturating_sub(slots.saturating_mul(8)))
        .max(1);
    let mut tuning = Tuning {
        registry_index_cache_bytes: Some(unit),
        checked_index_cache_bytes: Some(unit),
        checkpoint_cache_bytes: Some(unit),
        catalog_cache_bytes: Some(unit * 2),
        checked_cache_bytes: Some(unit * 8),
        checker_cache_bytes: Some(unit),
        question_cache_bytes: Some((unit / 4).max(4096)),
        checker_cache_entries: Some(unit / 512),
        pending_page: Some(pages),
        replay_page: Some(pages),
        id_page: Some(pages.max(wire_page)),
        inventory_page: Some(pages.min(wire_page)),
        status_page: Some(pages),
        question_page: Some(pages),
        terminal_job_page: Some(terminal_page),
        batch_objects: Some(pages.saturating_mul(4)),
        batch_bytes: Some(working / 8),
        active_job_bytes: Some(working / 16),
        queued_jobs_per_role: Some(cores.max(1)),
        provider_stream_bytes: Some(DEFAULT.provider_stream_bytes),
        configured_peers: Some(peers),
        contacts: Some(peers),
        addresses_per_contact: Some(DEFAULT.addresses_per_contact),
        fetches: Some(pages.max(wire_page)),
        flights: Some(cores.saturating_mul(2).max(1)),
        flights_per_peer: Some(DEFAULT.flights_per_peer),
        application_queries: Some(cores),
        dht_parallelism: Some(cores.min(peers)),
        dht_replication: Some(DEFAULT.dht_replication),
        dht_bucket_size: Some(DEFAULT.dht_bucket_size),
        discovery_interfaces: Some(cores.min(peers)),
        bootstrap_peers: Some(DEFAULT.bootstrap_peers),
        relay_peers: Some(DEFAULT.relay_peers),
        relay_circuits: Some(cores.saturating_mul(DEFAULT.relay_circuits)),
        relay_reservations: Some(cores.saturating_mul(DEFAULT.relay_reservations)),
        relay_circuits_per_peer: Some(DEFAULT.relay_circuits_per_peer),
        transport_events: Some(pages),
        queued_metadata: Some(cores),
        interest_decisions: Some(cores),
        question_commands: Some(cores),
        finding_admissions: Some(cores),
        job_commands: Some(pages),
        network_config_bytes: Some(DEFAULT.network_config_bytes),
        command_bytes: Some(DEFAULT.command_bytes),
        closure_objects: Some(DEFAULT.closure_objects),
        closure_bytes: Some(DEFAULT.closure_bytes),
        closure_steps: Some(DEFAULT.closure_steps),
        supervisor_commands: Some(cores),
        provider_events: Some(pages),
        cli_commands: Some(cores),
        control_clients: Some(cores),
        compaction_records: Some(pages),
        compaction_bytes: Some(DEFAULT.compaction_bytes.max(unit)),
        publications: Some(cores),
        waiters_per_job: Some(cores),
        established_connections: Some(
            u32::try_from(peers.min(descriptors / 2 / 4)).unwrap_or(u32::MAX),
        ),
        pending_connections: Some(u32::try_from(cores.saturating_mul(2)).unwrap_or(u32::MAX)),
        exchange_streams: Some(cores.saturating_mul(2)),
        inbound_streams: Some(cores.saturating_mul(4)),
        inbound_frames: Some(pages),
        ..Tuning::default()
    };
    // Largest cache/copy buffers remain fractions of the shared envelope even
    // on hosts with many cores. Validation owns all coupled allocation checks.
    tuning.compaction_bytes = Some(tuning.compaction_bytes.unwrap().min(working / 8));
    let mut profile = ResourceProfile {
        memory_bytes: memory,
        workers: [slots; 4],
        tuning,
        ..ResourceProfile::default()
    };
    loop {
        match profile.resolve() {
            Ok(_) => return Ok(profile),
            Err(_) if profile.workers[0] > 1 => {
                profile.workers = [profile.workers[0].div_ceil(2); 4];
                profile.tuning.cli_commands = Some(profile.workers[0]);
            }
            Err(error) => return Err(format!("hardware resource allocation: {error}")),
        }
    }
}

#[cfg(test)]
mod tests;
