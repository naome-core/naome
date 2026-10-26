use super::*;
mod files;
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
fn live_memory_targets_reject_new_over_budget_leases_without_revoking_existing_work() {
    const TEST: &str = "resources::adaptive::tests::live_memory_targets_reject_new_over_budget_leases_without_revoking_existing_work";
    if std::env::var_os("NAOME_LIVE_MEMORY_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_LIVE_MEMORY_TEST", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let selection = |memory_bytes| Selection {
        profile: Profile::Custom,
        custom: Some(Custom {
            memory_bytes,
            concurrency: 1,
            cache_bytes: 4096,
            batch_steps: 1,
            network_requests: 1,
        }),
    };
    let capacity = super::super::memory_usage().1;
    let existing = super::super::MemoryLease::acquire(20 * MIB as usize).unwrap();
    let alias = existing.clone();
    publish(Snapshot::derive(selection(32 * MIB), hardware(), capacity as u64).unwrap());
    assert!(super::super::MemoryLease::acquire(40 * MIB as usize).is_err());
    assert_eq!(super::super::memory_usage().0, 20 * MIB as usize);
    let extra = super::super::MemoryLease::acquire(12 * MIB as usize).unwrap();
    assert!(super::super::MemoryLease::acquire(1).is_err());
    let mut observed = hardware();
    observed.process_rss = 40 * MIB;
    publish(Snapshot::derive(selection(8 * MIB), observed, capacity as u64).unwrap());
    assert!(super::super::MemoryLease::acquire(1).is_err());
    drop(existing);
    assert_eq!(super::super::memory_usage().0, 32 * MIB as usize);
    drop(alias);
    drop(extra);
    assert_eq!(super::super::memory_usage().0, 0);
    assert!(super::super::MemoryLease::acquire(1).is_err());
    let control = super::super::MemoryLease::acquire_control(1024).unwrap();
    assert_eq!(super::super::memory_usage().0, 1024);
    drop(control);
    let mut tight = hardware();
    tight.process_rss = 30 * MIB;
    publish(Snapshot::derive(selection(32 * MIB), tight, capacity as u64).unwrap());
    let remaining = super::super::MemoryLease::acquire(2 * MIB as usize).unwrap();
    assert!(super::super::MemoryLease::acquire(1).is_err());
    drop(remaining);
    publish(Snapshot::derive(selection(64 * MIB), hardware(), capacity as u64).unwrap());
    assert!(super::super::MemoryLease::acquire(40 * MIB as usize).is_ok());
    assert_eq!(super::super::memory_usage().1, capacity);
}

#[tokio::test]
async fn live_pause_defers_ready_backlog_and_question_work_but_preserves_commit_and_control() {
    const TEST: &str = "resources::adaptive::tests::live_pause_defers_ready_backlog_and_question_work_but_preserves_commit_and_control";
    if std::env::var_os("NAOME_LIVE_WORK_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_LIVE_WORK_TEST", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    use crate::{Graph, question::LocalQuestions, runtime::Control};
    use naome_authoring::CompiledQuestion;
    use serde_json::{Value, json};
    use std::time::{Duration, Instant};
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::UnixStream,
    };
    const SOURCE: &str = "goal=all(x,eq(x,x)) proof: p0=refl(x) p1=gen(p0,x) return p1";
    let mut producer = Graph::default();
    let parent = producer.author(SOURCE).unwrap();
    producer.ingest(parent.clone(), Instant::now()).unwrap();
    let child = producer
        .author(&format!(
            "goal=all(x,eq(x,x)) proof: p0=cite(\"{}\") return p0",
            crate::hex(parent.proof_id().unwrap().unwrap().as_bytes())
        ))
        .unwrap();
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    assert_eq!(
        graph.ingest(child, Instant::now()).unwrap().status,
        "waiting"
    );
    let target = CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let (id, batch) = graph.prepare_generated(SOURCE, &[], &target).unwrap();
    graph
        .commit_batch(id, batch, Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(graph.pending_count().unwrap(), 1);
    let target = CompiledQuestion::compile(&crate::mocks::create_question(0)).unwrap();
    let source = crate::mocks::create_proof(&target).unwrap();
    let (prepared, batch) = graph.prepare_generated(&source, &[], &target).unwrap();
    let mut questions = LocalQuestions::new(Some(crate::mocks::assess_interest as fn(_) -> _));
    let unanswered = CompiledQuestion::compile("goal=all(x,mem(x,x))").unwrap();
    assert!(questions.generation_decision(&graph, &unanswered).passed());
    let (_, selected) = questions.begin_exchange(
        &graph,
        unanswered.clone(),
        Instant::now() + Duration::from_secs(30),
    );
    let interest = questions.completed().await;
    questions.finish(&graph, interest);
    let selected = selected.await.unwrap();
    let computations = questions.computation_count();
    let checks = graph.checker_calls();
    let control = Control::bind_test(&directory.0, graph.ownership()).unwrap();
    let endpoint: Value =
        serde_json::from_slice(&fs::read(directory.0.join("control.json")).unwrap()).unwrap();
    let selection = |memory_bytes| Selection {
        profile: Profile::Custom,
        custom: Some(Custom {
            memory_bytes,
            concurrency: 1,
            cache_bytes: 4096,
            batch_steps: 1,
            network_requests: 1,
        }),
    };
    let mut observed = hardware();
    observed.process_rss = 40 * MIB;
    publish(Snapshot::derive(selection(8 * MIB), observed.clone(), 512 * MIB).unwrap());
    assert!(matches!(
        questions.prepare_exchange(&graph, &unanswered, &selected),
        Err(crate::Error::ExecutionLimit)
    ));
    for _ in 0..10 {
        assert_eq!(graph.resolve_pending().unwrap(), (vec![], vec![]));
        assert!(
            questions
                .generation_decision(&graph, &unanswered)
                .inconclusive()
        );
    }
    assert_eq!(graph.checker_calls(), checks);
    assert_eq!(questions.computation_count(), computations);
    assert_eq!(graph.pending_count().unwrap(), 1);
    assert!(graph.storage_error().is_none());
    assert!(matches!(
        graph.author(SOURCE),
        Err(crate::Error::ExecutionLimit)
    ));
    assert!(matches!(
        graph.produce(SOURCE),
        Err(crate::Error::ExecutionLimit)
    ));
    assert!(matches!(
        graph.prepare_generated(&source, &[], &target),
        Err(crate::Error::ExecutionLimit)
    ));
    // Finishing a previously checked, reserved batch is drain, not new work.
    graph
        .commit_batch(prepared, batch, Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(graph.accepted_count(), 2);
    async fn exchange(
        control: &Control,
        endpoint: &Value,
        operation: Value,
        count: usize,
    ) -> Value {
        let client = async {
            let mut stream = UnixStream::connect(endpoint["socket"].as_str().unwrap())
                .await
                .unwrap();
            let mut bytes = serde_json::to_vec(
                &json!({"version":1,"token":endpoint["token"],"operation":operation}),
            )
            .unwrap();
            bytes.push(b'\n');
            stream.write_all(&bytes).await.unwrap();
            let mut response = Vec::new();
            BufReader::new(stream)
                .read_until(b'\n', &mut response)
                .await
                .unwrap();
            serde_json::from_slice::<Value>(&response).unwrap()
        };
        let server = async {
            control
                .respond(control.accept().await.unwrap(), count, true)
                .await
                .unwrap()
        };
        let (_, response) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .unwrap();
        response
    }
    assert_eq!(
        exchange(&control, &endpoint, json!("status"), 2).await["report"]["status"]["accepted_artifacts"],
        2
    );
    assert!(
        exchange(&control, &endpoint, json!("status"), 2).await["report"]["status"]
            ["computation_reason"]
            .is_string()
    );
    publish(Snapshot::derive(selection(128 * MIB), hardware(), 512 * MIB).unwrap());
    assert_eq!(graph.resolve_pending().unwrap().0.len(), 1);
    assert_eq!(graph.pending_count().unwrap(), 0);
    assert!(questions.generation_decision(&graph, &unanswered).passed());
    publish(Snapshot::derive(selection(8 * MIB), observed, 512 * MIB).unwrap());
    assert_eq!(
        exchange(&control, &endpoint, json!("stop"), 3).await["report"]["status"]["running"],
        false
    );
    assert!(control.stopping());
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
    assert_eq!(pressured.budget.network_requests, 1);
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
fn validated_custom_budgets_above_dynamic_defaults_are_honored() {
    let selection = Selection {
        profile: Profile::Custom,
        custom: Some(Custom {
            memory_bytes: 128 * MIB,
            concurrency: 6,
            cache_bytes: 16 * MIB,
            batch_steps: 512,
            network_requests: 8,
        }),
    };
    let snapshot = Snapshot::derive(selection, hardware(), 512 * MIB).unwrap();
    assert_eq!(snapshot.budget.memory_bytes, 128 * MIB);
    assert_eq!(snapshot.budget.concurrency, 6);
    assert_eq!(snapshot.budget.cache_bytes, 16 * MIB);
    assert_eq!(snapshot.budget.batch_steps, 512);
    assert_eq!(snapshot.budget.network_requests, 8);
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
