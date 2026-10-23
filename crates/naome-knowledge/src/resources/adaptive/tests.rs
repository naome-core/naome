use super::*;
fn hardware() -> Observed {
    Observed {
        memory_total: 8 * 1024 * MIB,
        memory_available: 6 * 1024 * MIB,
        memory_limit: 8 * 1024 * MIB,
        process_rss: 16 * MIB,
        peak_rss: 16 * MIB,
        process_cpu_ms: 100,
        cpu_millis: 8000,
        load_millis: 1000,
        disk_available: 1024 * MIB,
    }
}
#[test]
fn profiles_have_distinct_semantics_and_never_exceed_safe_hardware_capacity() {
    let derive = |profile| {
        Snapshot::derive(
            Selection {
                profile,
                custom: None,
            },
            hardware(),
            4 * 1024 * MIB,
        )
        .unwrap()
    };
    let light = derive(Profile::Light);
    let dynamic = derive(Profile::Dynamic);
    let heavy = derive(Profile::Heavy);
    assert_eq!(Selection::default().profile, Profile::Dynamic);
    assert!(light.budget.memory_bytes < dynamic.budget.memory_bytes);
    assert!(dynamic.budget.memory_bytes < heavy.budget.memory_bytes);
    assert_eq!(light.budget.concurrency, 1);
    assert!(heavy.budget.concurrency > dynamic.budget.concurrency);
    assert!(light.budget.batch_steps < dynamic.budget.batch_steps);
    assert!(dynamic.budget.batch_steps < heavy.budget.batch_steps);
    assert!(light.budget.yield_ms > dynamic.budget.yield_ms);
    assert_eq!(heavy.budget.yield_ms, 0);
    let mut limited = hardware();
    limited.memory_limit = 256 * MIB;
    limited.memory_available = 16 * MIB;
    let pressured = Snapshot::derive(Selection::default(), limited, 512 * MIB).unwrap();
    assert!(pressured.budget.paused.is_some());
    assert_eq!(pressured.budget.concurrency, 0);
    assert_eq!(pressured.budget.network_requests, 0);
    let resumed = Snapshot::derive(Selection::default(), hardware(), 512 * MIB).unwrap();
    assert!(resumed.budget.paused.is_none());
}
#[test]
fn custom_limits_validate_and_live_switches_respect_reserves() {
    let mut selection = Selection {
        profile: Profile::Custom,
        custom: Some(Custom {
            memory_bytes: 128 * MIB,
            concurrency: 2,
            cache_bytes: MIB,
            batch_steps: 5,
            network_requests: 1,
        }),
    };
    let snapshot = Snapshot::derive(selection.clone(), hardware(), 512 * MIB).unwrap();
    assert_eq!(snapshot.budget.batch_steps, 5);
    assert_eq!(snapshot.budget.memory_bytes, 128 * MIB);
    selection.custom.as_mut().unwrap().cache_bytes = 128 * MIB;
    assert!(selection.validate().is_err());
    selection.custom.as_mut().unwrap().cache_bytes = MIB;
    selection.custom.as_mut().unwrap().concurrency = 0;
    assert!(selection.validate().is_err());
    assert!(
        Selection {
            profile: Profile::Custom,
            custom: None
        }
        .validate()
        .is_err()
    );
    assert!(
        serde_json::from_str::<Selection>(r#"{"profile":"custom","custom":{"unknown":1}}"#)
            .is_err()
    );
}
#[test]
fn actual_supported_host_observations_include_memory_cpu_load_and_disk() {
    let observed = sample(&std::env::temp_dir()).unwrap();
    assert!(observed.memory_total > 0);
    assert!(observed.memory_limit <= observed.memory_total);
    assert!(observed.process_rss > 0);
    assert!(observed.cpu_millis > 0);
    assert!(observed.disk_available > 0);
}

#[test]
fn container_ancestors_and_v1_cpu_quotas_reduce_effective_hardware() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "naome-cgroup-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("child")).unwrap();
    let put = |name: &str, text: &str| fs::write(root.join(name), text).unwrap();
    put("memory.max", "536870912");
    put("memory.current", "134217728");
    put("cpu.max", "200000 100000");
    put("child/memory.max", "268435456");
    put("child/memory.current", "67108864");
    put("child/cpu.max", "50000 100000");
    let mut observed = hardware();
    apply_cgroups(&mut observed, &root, "0::/child").unwrap();
    assert_eq!(observed.memory_limit, 256 * MIB);
    assert_eq!(observed.memory_available, 192 * MIB);
    assert_eq!(observed.cpu_millis, 500);
    fs::create_dir_all(root.join("memory/child")).unwrap();
    fs::create_dir_all(root.join("cpu/child")).unwrap();
    put("memory/child/memory.limit_in_bytes", "134217728");
    put("memory/child/memory.usage_in_bytes", "33554432");
    put("cpu/child/cpu.cfs_quota_us", "25000");
    put("cpu/child/cpu.cfs_period_us", "100000");
    let mut observed = hardware();
    apply_cgroups(
        &mut observed,
        &root,
        "2:memory:/child\n3:cpu,cpuacct:/child",
    )
    .unwrap();
    assert_eq!(observed.memory_limit, 128 * MIB);
    assert_eq!(observed.memory_available, 96 * MIB);
    assert_eq!(observed.cpu_millis, 250);
    fs::remove_dir_all(root).unwrap();
}
