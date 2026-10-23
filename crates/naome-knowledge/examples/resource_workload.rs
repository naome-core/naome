//! Matched public-API storage workload. Use a fresh directory and Release.
//! No networking, provider processes, migration or stored validity shortcuts.
use naome_foundation::{Formula, FreeVariable};
use naome_knowledge::{Envelope, Graph, compatibility, hex};
use naome_proof::{ProofCertificate, ProofStep};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Instant};

const OBJECTS: usize = 2048;
const WINDOW: usize = 512;

fn disk_bytes(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                disk_bytes(&entry.path())
            } else {
                metadata.len()
            }
        })
        .sum()
}

// Keep this example independent of new internal APIs for matched baseline runs.
fn peak_rss_bytes() -> Result<u64, String> {
    #[cfg(target_os = "linux")]
    {
        // getrusage also retains a pre-exec launcher's high-water mark.
        let status = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
        let mut fields = status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .ok_or("current-image RSS high-water mark is missing")?
            .split_whitespace();
        let kib: u64 = fields
            .next()
            .ok_or("missing RSS value")?
            .parse::<u64>()
            .map_err(|e| e.to_string())?;
        if fields.next() != Some("kB") || fields.next().is_some() {
            return Err("RSS units differ".into());
        }
        kib.checked_mul(1024).ok_or_else(|| "RSS byte width".into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let usage = nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_SELF)
            .map_err(|e| e.to_string())?;
        u64::try_from(usage.max_rss()).map_err(|e| e.to_string())
    }
}

fn main() -> Result<(), String> {
    let directory = std::env::args_os()
        .nth(1)
        .ok_or("fresh output directory required")?;
    let directory = Path::new(&directory);
    std::fs::create_dir(directory).map_err(|e| e.to_string())?;
    let prepare = Instant::now();
    let x = FreeVariable::new(0);
    let mut objects = Vec::new();
    for index in 0..OBJECTS {
        let mut formula = Formula::equal(x, x);
        // Equal lengths, distinct closed targets, fixed depth and step count.
        for bit in 0..12 {
            let atom = if index & (1 << bit) == 0 {
                Formula::equal(x, x)
            } else {
                Formula::member(x, x)
            };
            formula = Formula::implies(atom, formula);
        }
        let formula = Formula::for_all(x, formula);
        let checked = naome_checker::normalize_and_check(
            ProofCertificate::new(vec![ProofStep::Simplification {
                antecedent: formula.clone().into(),
                consequent: formula.into(),
            }])
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        objects.push(Envelope {
            compatibility: hex(&compatibility()),
            proof_id: hex(checked.proof_id().as_bytes()),
            statement_id: hex(checked.statement_id().as_bytes()),
            proof: hex(checked.normal_form().canonical_bytes()),
        });
    }
    let workload_id = hex(&Sha256::digest(
        serde_json::to_vec(&objects).map_err(|e| e.to_string())?,
    ));
    let prepare_seconds = prepare.elapsed().as_secs_f64();
    let mut graph = Graph::open(directory)?;
    let commit = Instant::now();
    let mut windows = Vec::new();
    let mut window = Instant::now();
    for (index, object) in objects.into_iter().enumerate() {
        let result = graph.ingest(object, Instant::now())?;
        assert_eq!(result.status, "accepted");
        assert_eq!(graph.accepted_count(), index + 1);
        if (index + 1).is_multiple_of(WINDOW) {
            windows.push(window.elapsed().as_secs_f64());
            window = Instant::now();
        }
    }
    let commit_seconds = commit.elapsed().as_secs_f64();
    let root = graph.content_root();
    drop(graph);
    let replay = Instant::now();
    let graph = Graph::open(directory)?;
    assert_eq!(graph.accepted_count(), OBJECTS);
    assert_eq!(graph.content_root(), root);
    let replay_seconds = replay.elapsed().as_secs_f64();
    let peak = peak_rss_bytes()?;
    let canonical_bytes = std::fs::metadata(directory.join("proof-corpus.sqlite3"))
        .map_err(|e| e.to_string())?
        .len();
    println!(
        "{}",
        serde_json::json!({
            "workload_id":workload_id,"objects":OBJECTS,"window_objects":WINDOW,"window_seconds":windows,
            "prepare_seconds":prepare_seconds,"commit_seconds":commit_seconds,
            "replay_seconds":replay_seconds,"peak_rss_bytes":peak,
            "canonical_file_bytes":canonical_bytes,"all_retained_file_bytes":disk_bytes(directory),
            "profile":if cfg!(debug_assertions){"test"}else{"release"}
        })
    );
    Ok(())
}
