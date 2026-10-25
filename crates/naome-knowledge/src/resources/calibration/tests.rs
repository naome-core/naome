use super::*;

fn host(memory: u64, cpu: u64) -> Observed {
    Observed {
        memory_total: memory,
        memory_limit: memory,
        memory_available: memory * 3 / 4,
        process_rss: 16 * MIB as u64,
        cpu_millis: cpu,
        disk_available: memory,
        ..Observed::default()
    }
}

#[test]
fn hardware_capacities_fit_small_large_and_fractional_cpu_hosts() {
    for gib in [1, 2, 8, 32, 128, 1024] {
        for cpu in [250, 1000, 8000, 64_000] {
            let observed = host(gib * 1024 * MIB as u64, cpu);
            let profile =
                capacity(&observed).unwrap_or_else(|error| panic!("{gib} GiB, CPU {cpu}: {error}"));
            let limits = profile.resolve().unwrap();
            assert!(limits.memory_bytes as u64 <= observed.memory_available + observed.process_rss);
            assert!(limits.workers.iter().all(|slots| *slots > 0));
            assert_eq!(limits.replay_guard_bytes, DEFAULT.replay_guard_bytes);
            assert_eq!(limits.proof_bytes, DEFAULT.proof_bytes);
            assert_eq!(limits.request_burst, DEFAULT.request_burst);
            assert_eq!(limits.dht_replication, DEFAULT.dht_replication);
        }
    }
    let small = capacity(&host(2 * 1024 * MIB as u64, 1000))
        .unwrap()
        .resolve()
        .unwrap();
    let large = capacity(&host(32 * 1024 * MIB as u64, 16_000))
        .unwrap()
        .resolve()
        .unwrap();
    assert!(large.memory_bytes > small.memory_bytes);
    assert!(large.workers[1] > small.workers[1]);
    assert!(large.catalog_cache_bytes > small.catalog_cache_bytes);
}

#[test]
fn unavailable_reserves_are_explicit_instead_of_overcommitting() {
    assert!(capacity(&host(256 * MIB as u64, 1000)).is_err());
}

#[test]
fn descriptor_shortage_reduces_lanes_and_sockets_before_opening_the_node() {
    let observed = host(32 * 1024 * MIB as u64, 64_000);
    let small = capacity_with_descriptors(&observed, 128)
        .unwrap()
        .resolve()
        .unwrap();
    let large = capacity_with_descriptors(&observed, 4096)
        .unwrap()
        .resolve()
        .unwrap();
    assert!(small.workers.iter().sum::<usize>() * DESCRIPTORS_PER_WORKER <= 64);
    assert!(small.established_connections <= 16);
    assert!(small.discovery_interfaces <= small.workers[0]);
    assert!(large.workers[0] > small.workers[0]);
    assert!(large.established_connections > small.established_connections);
    assert!(capacity_with_descriptors(&observed, 127).is_err());
}
