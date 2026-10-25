use super::*;

#[test]
fn defaults_scaling_and_independent_overrides_are_validated_before_allocation() {
    let default = ResourceProfile::default().resolve().unwrap();
    assert_eq!(default, DEFAULT);
    let maximum_envelope = crate::Envelope {
        compatibility: "00".repeat(32),
        proof_id: "00".repeat(32),
        statement_id: "00".repeat(32),
        proof: "00".repeat(default.proof_bytes),
    };
    let command = serde_json::json!({"command":"ingest","object":maximum_envelope});
    assert!(serde_json::to_vec(&command).unwrap().len() < default.command_bytes);
    let mut profile = ResourceProfile {
        memory_bytes: 1024 * MIB,
        ..ResourceProfile::default()
    };
    profile.tuning.proof_bytes = Some(128 * 1024);
    profile.tuning.inventory_page = Some(17);
    profile.tuning.request_timeout_ms = Some(4321);
    let limits = profile.resolve().unwrap();
    assert_eq!(limits.checked_cache_bytes, 2 * DEFAULT.checked_cache_bytes);
    assert_eq!(limits.proof_bytes, 128 * 1024);
    assert_eq!(limits.inventory_page, 17);
    assert_eq!(limits.request_timeout, Duration::from_millis(4321));
    assert_eq!(
        limits.resident_jobs,
        limits.workers.iter().sum::<usize>()
            + 4 * limits.queued_jobs_per_role
            + limits.terminal_job_page
    );
    assert!(limits.allocation_budget() < limits.memory_bytes);
    assert!(serde_json::from_str::<ResourceProfile>(r#"{"tuning":{"unknown":1}}"#).is_err());
    assert!(serde_json::from_str::<ResourceProfile>(r#"{"version":-1}"#).is_err());
}

#[test]
fn zero_overflow_codec_and_inconsistent_allocations_are_rejected() {
    for change in [
        serde_json::json!({"version":2}),
        serde_json::json!({"memory_bytes":0}),
        serde_json::json!({"workers":[1,0,2,2]}),
        serde_json::json!({"workers":[usize::MAX,2,2,2]}),
        serde_json::json!({"tuning":{"question_page":usize::MAX}}),
        serde_json::json!({"tuning":{"request_timeout_ms":0}}),
        serde_json::json!({"tuning":{"proof_bytes":naome_proof::CERTIFICATE_MAX_BYTES+1}}),
        serde_json::json!({"tuning":{"proof_dependencies":naome_proof::CERTIFICATE_MAX_STEPS+1}}),
        serde_json::json!({"tuning":{"inventory_page":DEFAULT.fetches+1}}),
        serde_json::json!({"tuning":{"checked_cache_bytes":DEFAULT.memory_bytes}}),
        serde_json::json!({"tuning":{"contacts":usize::MAX}}),
        serde_json::json!({"tuning":{"assessment_operations":usize::MAX}}),
        serde_json::json!({"tuning":{"network_config_bytes":usize::MAX}}),
        serde_json::json!({"tuning":{"command_bytes":64*MIB,"cli_commands":8}}),
        serde_json::json!({"tuning":{"failure_detail_bytes":usize::MAX}}),
        serde_json::json!({"tuning":{"identify_protocols":DEFAULT.identify_protocols+1}}),
        serde_json::json!({"tuning":{"identify_addresses":DEFAULT.identify_addresses+1}}),
        serde_json::json!({"tuning":{"replay_guard_bytes":385*MIB}}),
        serde_json::json!({"tuning":{"replay_guard_timeout_ms":1_800_001}}),
        serde_json::json!({"tuning":{"replay_guard_freshness_ms":2001}}),
    ] {
        let profile: ResourceProfile = serde_json::from_value(change.clone()).unwrap();
        assert!(profile.resolve().is_err(), "accepted {change}");
    }
}

#[test]
fn shared_allocation_custody_releases_exactly_once_and_rejects_overflow() {
    let memory = Arc::new(Memory {
        limit: 1024,
        used: AtomicUsize::new(0),
    });
    let lease = MemoryLease::allocate(memory.clone(), 1024).unwrap();
    let alias = lease.clone();
    assert!(MemoryLease::allocate(memory.clone(), 1).is_err());
    assert!(MemoryLease::allocate(memory.clone(), usize::MAX).is_err());
    drop(lease);
    assert_eq!(memory.used.load(Ordering::Acquire), 1024);
    drop(alias);
    assert_eq!(memory.used.load(Ordering::Acquire), 0);
    assert!(MemoryLease::allocate(memory.clone(), 1024).is_ok());
    assert_eq!(memory.used.load(Ordering::Acquire), 0);
}

#[test]
fn disk_pressure_is_explicit_before_new_persistent_work() {
    let directory = crate::checkpoint::tests::Directory::new();
    assert!(require_disk_space(&directory.0, 0).is_ok());
    assert!(
        require_disk_space(&directory.0, u64::MAX)
            .unwrap_err()
            .starts_with("disk overload:")
    );
}

#[test]
fn process_profile_and_child_snapshot_are_immutable_after_initialization() {
    const TEST: &str =
        "resources::tests::process_profile_and_child_snapshot_are_immutable_after_initialization";
    if let Some(path) = std::env::var_os("NAOME_RESOURCE_PROFILE_TEST") {
        let original = initialize_from_environment().unwrap().clone();
        assert_eq!(original.memory_bytes, 1024 * MIB);
        assert_eq!(original.workers, [1, 1, 1, 1]);
        let snapshot: EffectiveProfile = serde_json::from_str(&child_snapshot().unwrap()).unwrap();
        assert_eq!(snapshot.version, PROFILE_VERSION);
        assert_eq!(snapshot.limits, original);
        let changed = ResourceProfile {
            memory_bytes: 2048 * MIB,
            ..ResourceProfile::default()
        };
        std::fs::write(path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(initialize_from_environment().is_err());
        assert_eq!(limits(), &original);
        return;
    }
    let directory = crate::checkpoint::tests::Directory::new();
    let path = directory.0.join("resources.json");
    let profile = ResourceProfile {
        memory_bytes: 1024 * MIB,
        workers: [1, 1, 1, 1],
        ..ResourceProfile::default()
    };
    std::fs::write(&path, serde_json::to_vec(&profile).unwrap()).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture"])
        .env("NAOME_RESOURCE_CONFIG", &path)
        .env("NAOME_RESOURCE_PROFILE_TEST", &path)
        .env_remove("NAOME_EFFECTIVE_RESOURCES")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn simultaneous_disk_preparations_share_custody_and_release_it() {
    let directory = crate::checkpoint::tests::Directory::new();
    with_disk_available(u128::from(limits().disk_reserve_bytes) + 1024, || {
        let first = DiskLease::acquire(&directory.0, 800).unwrap();
        assert!(matches!(
            DiskLease::acquire(&directory.0, 225),
            Err(crate::Error::DiskOverload { .. })
        ));
        let second = DiskLease::acquire(&directory.0, 224).unwrap();
        drop(first);
        assert!(DiskLease::acquire(&directory.0, 800).is_ok());
        drop(second);
    });
}
