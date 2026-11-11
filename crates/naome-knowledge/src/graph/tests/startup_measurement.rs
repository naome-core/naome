use super::*;
use nix::sys::{
    resource::{UsageWho, getrusage},
    time::TimeValLike,
};
fn cpu_us() -> i64 {
    let r = getrusage(UsageWho::RUSAGE_SELF).unwrap();
    r.user_time().num_microseconds() + r.system_time().num_microseconds()
}
#[test]
#[ignore = "Manual matched startup measurement"]
fn measure_startup_context_build() {
    let sizes = std::env::var("NAOME_STARTUP_MEASURE_SIZES").unwrap_or("0,128,512,2048".into());
    let repeats = std::env::var("NAOME_STARTUP_MEASURE_REPEATS")
        .unwrap_or("9".into())
        .parse::<usize>()
        .unwrap();
    for size in sizes.split(',').map(|n| n.parse::<usize>().unwrap()) {
        let directory = startup_prune_directory(&format!("measure-{size}"));
        let peak = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sampler = {
            let (directory, peak, done) = (directory.clone(), peak.clone(), done.clone());
            std::thread::spawn(move || {
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    peak.fetch_max(
                        directory_bytes(&directory),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            })
        };
        let write_cpu = cpu_us();
        let write_start = Instant::now();
        let mut writer = Graph::open(&directory).unwrap();
        let mut last = None;
        for _ in 0..size {
            let next = last
                .as_ref()
                .map(|p| citation(&writer, p))
                .unwrap_or_else(|| writer.author(SOURCE).unwrap());
            writer.ingest(next.clone(), Instant::now()).unwrap();
            last = Some(next);
        }
        let root = writer.content_root();
        let snapshot = writer.context.snapshot_id();
        let write_ms = write_start.elapsed().as_secs_f64() * 1000.0;
        let write_cpu_ms = (cpu_us() - write_cpu) as f64 / 1000.0;
        let steady_bytes = directory_bytes(&directory);
        let read_start = Instant::now();
        if let Some(proof) = &last {
            for _ in 0..128 {
                assert!(
                    writer
                        .object(ArtifactId::from_bytes(
                            crate::object::id_bytes(&proof.artifact_id).unwrap()
                        ))
                        .unwrap()
                        .is_some()
                );
            }
        }
        let read_ms = read_start.elapsed().as_secs_f64() * 1000.0;
        drop(writer);
        for repeat in 0..repeats {
            let inserts = storage::sql_inserts();
            let cpu = cpu_us();
            let started = Instant::now();
            let graph = Graph::open(&directory).unwrap();
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            let cpu = (cpu_us() - cpu) as f64 / 1000.0;
            let inserts = storage::sql_inserts() - inserts;
            assert_eq!(graph.accepted_count(), size);
            assert_eq!(graph.content_root(), root);
            assert_eq!(graph.context.snapshot_id(), snapshot);
            println!(
                "startup_build {}",
                serde_json::json!({"size":size,"repeat":repeat,"wall_ms":elapsed,"cpu_ms":cpu,"sqlite_inserts":inserts,"index_page_bytes":graph.checked_storage.allocated_bytes().unwrap(),"root":crate::hex(&root),"snapshot":crate::hex(&snapshot),"last_proof_id":last.as_ref().map(|p|p.artifact_id.as_str())})
            );
            drop(graph);
        }
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        sampler.join().unwrap();
        println!(
            "storage_workload {}",
            serde_json::json!({"size":size,"write_ms":write_ms,"write_cpu_ms":write_cpu_ms,"read_128_ms":read_ms,"steady_allocated_bytes":steady_bytes,"sampled_peak_allocated_bytes":peak.load(std::sync::atomic::Ordering::Relaxed)})
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}

fn directory_bytes(path: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::read_dir(path)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.blocks().saturating_mul(512))
        .sum()
}
