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
                serde_json::json!({"size":size,"repeat":repeat,"wall_ms":elapsed,"cpu_ms":cpu,"sqlite_inserts":inserts,"index_page_bytes":graph.checked_storage.allocated_bytes().unwrap(),"root":crate::hex(&root),"snapshot":crate::hex(&snapshot),"last_proof_id":last.as_ref().map(|p|p.proof_id.as_str())})
            );
            drop(graph);
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
