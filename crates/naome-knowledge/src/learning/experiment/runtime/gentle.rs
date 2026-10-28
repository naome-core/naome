//! One fixed existing-rate intervention on every genuinely warm owned case.
use super::*;

#[test]
#[ignore = "Exact12 warm input preflight; no inference or optimizer updates"]
fn warm_gentle_preflight() {
    super::warm::inputs("NAOME_GENTLE_INPUT");
}

#[test]
#[ignore = "Fixed24 warm branches and6000updates; no upper, final or installation"]
fn warm_gentle_intervention() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "Release only"
    );
    let output = std::env::var("NAOME_GENTLE_OUTPUT").expect("fresh gentle output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve previous diagnostics");
    let inputs = super::warm::inputs("NAOME_GENTLE_INPUT");
    let meter = crate::resources::feedback::Meter::start();
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let mut rows = Vec::new();
    let mut updates = 0u64;
    // Every original trajectory must reproduce before any intervention update.
    for branch in ["original", "gentle"] {
        for case in &inputs.cases {
            let clock = (Instant::now(), meta::cpu_micros().unwrap());
            let job: Job = read(&case.original_job);
            let base = &job.base;
            let expected = job.progress.as_ref().unwrap();
            let base_binding = digest(base);
            let evidence_binding = digest(&job.evidence);
            let mut plan = expected.plan.as_ref().unwrap().plan.clone();
            if branch == "gentle" {
                for phase in &mut plan.phases {
                    phase.gentle_rate = true;
                }
            }
            plan.validate().unwrap();
            let directory = output.join(&case.name).join(branch);
            std::fs::create_dir_all(&directory).unwrap();
            let mut store = Store::default();
            let parent = checkpoint(&case.parent_checkpoint, &mut store);
            let original: Checkpoint = read(
                Path::new(&case.candidate_checkpoint)
                    .join("checkpoint.json")
                    .to_str()
                    .unwrap(),
            );
            let mut candidate = parent.clone();
            let mut engine = Engine::default();
            let mut cursor = base.draws;
            let mut losses = [0f32; 2];
            let mut units = Vec::new();
            eprintln!("gentle_branch_started {} {branch}", case.name);
            for unit in 0..model::TRAINING_UNITS {
                limits(clock.0, clock.1);
                let (next, first, last) = engine
                    .train_replay_using(
                        &candidate,
                        base,
                        &job.evidence,
                        &mut cursor,
                        plan.phase(unit),
                        &mut store,
                    )
                    .unwrap()
                    .expect("same genuinely checked own pool");
                if unit == 0 {
                    losses[0] = first;
                }
                losses[1] = last;
                candidate = next;
                updates += model::UPDATES_PER_UNIT;
                units.push(serde_json::json!({"unit":unit+1,"checkpoint":candidate,
                    "cursor":cursor,"phase":plan.phase(unit),"first_loss_bits":first.to_bits(),
                    "last_loss_bits":last.to_bits(),"training_cost":engine.cost}));
                let keep = parent
                    .blobs()
                    .chain(candidate.blobs())
                    .map(|b| &b.sha256)
                    .collect::<BTreeSet<_>>();
                store.inner.0.retain(|(hash, _), _| keep.contains(hash));
                write(&directory.join("units.json"), &units);
            }
            assert_eq!(candidate.updates, 500);
            assert_eq!(cursor, expected.rng);
            if branch == "original" {
                assert_eq!(candidate, original);
                assert_eq!(losses[0].to_bits(), expected.first_loss.unwrap().to_bits());
                assert_eq!(losses[1].to_bits(), expected.last_loss.unwrap().to_bits());
            }
            export_model(&directory.join("candidate"), &candidate, &store.inner);
            let q =
                qualification_screen(base, &candidate, &mut engine, &mut store, case.job, clock);
            assert_eq!(q["before"], expected.incumbent_score);
            assert_eq!(q["transfer"]["before"], expected.transfer.before);
            if branch == "original" {
                assert_eq!(q["after"], expected.candidate_score);
                assert_eq!(q["protected_loss"], expected.development_regression);
                assert_eq!(q["anchor_loss"], expected.anchor_regression);
                assert_eq!(
                    q["transfer"],
                    serde_json::to_value(expected.transfer).unwrap()
                );
                let counts = ["before", "after"].map(|key| {
                    q["native_evaluations"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .take(curriculum::CORPUS_DEVELOPMENT)
                        .filter(|r| r[key].as_bool().unwrap())
                        .count() as u32
                });
                assert_eq!(counts, expected.original_score);
            }
            assert_eq!(
                engine.snapshot(&candidate, &mut store.inner).unwrap(),
                candidate
            );
            assert_eq!(engine.snapshot(&parent, &mut store.inner).unwrap(), parent);
            assert_eq!(digest(base), base_binding);
            assert_eq!(digest(&job.evidence), evidence_binding);
            limits(clock.0, clock.1);
            assert!(store.read_bytes + store.written_bytes <= model::REQUIREMENTS.io_bytes as u64);
            let row = serde_json::json!({"case":case.name,"job":case.job,"branch":branch,
                "candidate":candidate,"cursor":cursor,"loss_bits":losses.map(f32::to_bits),
                "base_binding":base_binding,"evidence_binding":evidence_binding,"plan":plan,
                "qualification":q,"original_exact":branch=="original",
                "cpu_micros":meta::cpu_micros().unwrap()-clock.1,"wall_micros":clock.0.elapsed().as_micros(),
                "artifact_read_bytes":store.read_bytes,"artifact_written_bytes":store.written_bytes,
                "lower_optimizer_updates":250,"upper_optimizer_updates":0,
                "installed_resumed_or_promoted":false});
            write(&directory.join("result.json"), &row);
            rows.push(row);
            write(&output.join("partial.json"), &rows);
            eprintln!("gentle_branch_completed {} {branch}", case.name);
        }
    }
    let resources = meter.finish(0, true);
    assert!(resources.peak_rss_bytes.unwrap() <= model::REQUIREMENTS.work_bytes as u64);
    assert_eq!(updates, 6000);
    write(
        &output.join("completed.json"),
        &serde_json::json!({"cases":rows,
        "lower_optimizer_updates":updates,"upper_optimizer_updates":0,"new_final_queries":0,
        "cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":started.elapsed().as_micros(),
        "peak_rss_bytes":resources.peak_rss_bytes,"diagnostic_only":true,
        "no_native_state_installation_promotion_or_continuation":true}),
    );
}
