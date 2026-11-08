//! Exact control replay observes consumed decision graphs without changing training.
use super::super::observation::{Decisions, consumed, coverage, own_sources};
use super::*;
use crate::learning::{Job, digest, meta};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ops::Range, path::Path, time::Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    context: usize,
    cold_job: String,
    warm_job: String,
    parent_checkpoint: String,
    candidate_checkpoint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    source_commit: String,
    missing_contexts: Vec<usize>,
    original_sha256: BTreeMap<String, String>,
    cases: Vec<Case>,
}

#[derive(Default)]
struct Store {
    inner: MemoryStore,
    reads: u64,
    writes: u64,
}
impl Store {
    fn limit(&self) {
        assert!(self.reads + self.writes <= REQUIREMENTS.io_bytes as u64);
    }
    fn keep(&mut self, parent: &Checkpoint, candidate: &Checkpoint) {
        self.inner.0.retain(|(hash, _), _| {
            parent
                .blobs()
                .chain(candidate.blobs())
                .any(|b| &b.sha256 == hash)
        });
    }
}
impl ArtifactIo for Store {
    fn read(&mut self, blob: &Blob, range: Range<usize>) -> Result<Vec<u8>, String> {
        let bytes = self.inner.read(blob, range)?;
        self.reads += bytes.len() as u64;
        self.limit();
        Ok(bytes)
    }
    fn write(&mut self, blob: &Blob, range: Range<usize>, bytes: Vec<u8>) -> Result<(), String> {
        self.writes += bytes.len() as u64;
        self.limit();
        self.inner.write(blob, range, bytes)
    }
}

fn read<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> T {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn write(path: impl AsRef<Path>, value: &impl Serialize) {
    let bytes = serde_json::to_vec_pretty(value).unwrap();
    std::fs::write(path, bytes).unwrap();
}
fn checkpoint(path: &str, mut store: Option<&mut Store>) -> Checkpoint {
    let path = Path::new(path);
    let checkpoint: Checkpoint = read(path.join("checkpoint.json"));
    checkpoint.validate().unwrap();
    for (name, blob) in [
        ("model", &checkpoint.model),
        ("optimizer", &checkpoint.optimizer),
    ] {
        let blob = blob.as_ref().unwrap();
        let bytes = std::fs::read(path.join(format!("{name}.bpk"))).unwrap();
        assert_eq!(Blob::of(&bytes), *blob);
        if let Some(store) = store.as_deref_mut() {
            assert_eq!(artifact::save(store, &bytes).unwrap(), *blob);
        }
    }
    checkpoint
}
fn inputs() -> Inputs {
    use sha2::{Digest, Sha256};
    let inputs: Inputs = read(std::env::var("NAOME_COVERAGE_INPUT").unwrap());
    assert_eq!(
        inputs.source_commit,
        "f62d3871db7b2427225c346bb207d793dcd7ac15"
    );
    assert_eq!(inputs.missing_contexts, [4]);
    assert_eq!(
        inputs.cases.iter().map(|c| c.context).collect::<Vec<_>>(),
        [0, 1, 2, 3, 5]
    );
    for (path, hash) in &inputs.original_sha256 {
        assert_eq!(
            crate::hex(&Sha256::digest(std::fs::read(path).unwrap())),
            *hash
        );
    }
    for case in &inputs.cases {
        assert!(inputs.original_sha256.contains_key(&case.cold_job));
        assert!(inputs.original_sha256.contains_key(&case.warm_job));
        for folder in [&case.parent_checkpoint, &case.candidate_checkpoint] {
            for name in ["checkpoint.json", "model.bpk", "optimizer.bpk"] {
                assert!(
                    inputs
                        .original_sha256
                        .contains_key(Path::new(folder).join(name).to_str().unwrap())
                );
            }
        }
        let cold: Job = read(&case.cold_job);
        let warm: Job = read(&case.warm_job);
        cold.validate().unwrap();
        warm.validate().unwrap();
        let parent = checkpoint(&case.parent_checkpoint, None);
        let candidate = checkpoint(&case.candidate_checkpoint, None);
        assert_eq!(cold.progress.as_ref().unwrap().model, parent);
        assert_eq!(warm.base.model, parent);
        let progress = warm.progress.as_ref().unwrap();
        assert_eq!(progress.model, parent);
        assert!(
            progress.candidate.is_none(),
            "rejected trial releases its candidate lifetime"
        );
        assert_eq!(progress.rejections, warm.base.rejections + 1);
        let experience = &progress.meta_update.as_ref().unwrap().experience;
        assert_eq!(experience.source_model, digest(&parent));
        assert_eq!(experience.candidate_model, Some(digest(&candidate)));
        assert_eq!([parent.updates, candidate.updates], [250, 500]);
        assert_eq!(
            cold.progress.as_ref().unwrap().promotions,
            cold.base.promotions + 1
        );
        own_sources(&cold);
        own_sources(&warm);
    }
    inputs
}

fn limits(started: Instant, cpu: u64) {
    assert!(started.elapsed().as_secs_f64() < 120.0);
    assert!(meta::cpu_micros().unwrap() - cpu < 90_000_000);
}

#[test]
#[ignore = "Explicit own-source coverage input/native-proof preflight; no neural inference or optimizer"]
fn consumed_decision_coverage_preflight() {
    inputs();
}

#[test]
#[ignore = "Exact five warm controls/1250 updates; consumed-decision observation only"]
fn consumed_decision_coverage_replay() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "Release only"
    );
    let path = std::env::var("NAOME_COVERAGE_OUTPUT").unwrap();
    let path = Path::new(&path);
    assert!(!path.exists(), "preserve prior observations");
    std::fs::create_dir_all(path).unwrap();
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let meter = crate::resources::feedback::Meter::start();
    let inputs = inputs();
    let mut results = Vec::new();
    for case in &inputs.cases {
        let clock = (Instant::now(), meta::cpu_micros().unwrap());
        let cold: Job = read(&case.cold_job);
        let job: Job = read(&case.warm_job);
        let base_hash = digest(&job.base);
        let evidence_hash = digest(&job.evidence);
        let earlier = own_sources(&cold);
        let current = own_sources(&job);
        let expected = job.progress.as_ref().unwrap();
        let plan = &expected.plan.as_ref().unwrap().plan;
        let mut store = Store::default();
        let parent = checkpoint(&case.parent_checkpoint, Some(&mut store));
        let original = checkpoint(&case.candidate_checkpoint, None);
        let mut candidate = parent.clone();
        let mut engine = Engine {
            preservation_mode: PreservationMode::Unmasked,
            ..Engine::default()
        };
        let mut cursor = job.base.draws;
        let mut losses = [0f32; 2];
        let mut sampled = Decisions::new();
        let mut available = Decisions::new();
        let mut units = Vec::new();
        let directory = path.join(format!("context-{}", case.context));
        std::fs::create_dir_all(&directory).unwrap();
        eprintln!("coverage_control_started {}", case.context);
        for unit in 0..TRAINING_UNITS {
            limits(clock.0, clock.1);
            let before = cursor;
            let (next, first, last) = engine
                .train_replay_using(
                    &candidate,
                    &job.base,
                    (&job.evidence, &[]),
                    &mut cursor,
                    plan.phase(unit),
                    &mut store,
                )
                .unwrap()
                .unwrap();
            let batches = consumed(&engine, before, cursor, &mut available, &mut sampled);
            if unit == 0 {
                losses[0] = first;
            }
            losses[1] = last;
            candidate = next;
            store.keep(&parent, &candidate);
            units.push(serde_json::json!({"unit":unit+1,"phase":plan.phase(unit),
                "cursor_before":before,"cursor_after":cursor,"batches":batches,
                "first_loss_bits":first.to_bits(),"last_loss_bits":last.to_bits(),
                "checkpoint":candidate,"training_cost":engine.cost}));
            write(directory.join("units.json"), &units);
        }
        assert_eq!(candidate, original);
        assert_eq!(cursor, expected.rng);
        assert_eq!(
            losses.map(f32::to_bits),
            [
                expected.first_loss.unwrap().to_bits(),
                expected.last_loss.unwrap().to_bits()
            ]
        );
        assert_eq!(engine.snapshot(&parent, &mut store).unwrap(), parent);
        assert_eq!(engine.snapshot(&candidate, &mut store).unwrap(), candidate);
        assert_eq!(digest(&job.base), base_hash);
        assert_eq!(digest(&job.evidence), evidence_hash);
        assert_eq!(
            sampled.values().map(|s| s.occurrences).sum::<u64>(),
            250 * 16
        );
        for (name, blob) in [
            ("model", &candidate.model),
            ("optimizer", &candidate.optimizer),
        ] {
            let bytes = artifact::load(&mut store, blob.as_ref().unwrap()).unwrap();
            std::fs::write(directory.join(format!("{name}.bpk")), bytes).unwrap();
        }
        write(directory.join("checkpoint.json"), &candidate);
        write(directory.join("sampled.json"), &sampled);
        write(directory.join("available.json"), &available);
        let row = serde_json::json!({"context":case.context,"original_control_exact":true,
            "candidate":candidate,"cursor":cursor,"loss_bits":losses.map(f32::to_bits),
            "earlier":coverage(&earlier,&available,&sampled),"current":coverage(&current,&available,&sampled),
            "sampled_decision_occurrences":4000,"lower_updates":250,"upper_updates":0,
            "new_final_queries":0,"native_search_queries":0,"read_bytes":store.reads,"written_bytes":store.writes,
            "cpu_micros":meta::cpu_micros().unwrap()-clock.1,"wall_micros":clock.0.elapsed().as_micros()});
        write(directory.join("result.json"), &row);
        limits(clock.0, clock.1);
        results.push(row);
        write(path.join("partial.json"), &results);
        eprintln!("coverage_control_completed {}", case.context);
    }
    let measured = meter.finish(0, true);
    assert!(measured.peak_rss_bytes.unwrap() <= REQUIREMENTS.work_bytes as u64);
    assert!(
        started.elapsed().as_secs() < 10_800 && meta::cpu_micros().unwrap() - cpu < 7_200_000_000
    );
    write(
        path.join("completed.json"),
        &serde_json::json!({"cases":results,"missing_original_contexts":inputs.missing_contexts,
        "lower_updates":1250,"upper_updates":0,"new_final_queries":0,"native_search_queries":0,
        "peak_rss_bytes":measured.peak_rss_bytes,"cpu_micros":meta::cpu_micros().unwrap()-cpu,
        "wall_micros":started.elapsed().as_micros(),"diagnostic_only":true,"goal_complete":false}),
    );
}
