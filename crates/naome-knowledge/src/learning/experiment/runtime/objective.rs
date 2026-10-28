//! Fixed cold-start objective diagnosis on exact self-checked Node inputs.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    job: u64,
    original_job: String,
    expected_candidate: Checkpoint,
    completed_original: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Diagnosis {
    original_sha256: BTreeMap<String, String>,
    cases: Vec<Case>,
}

fn inputs() -> Diagnosis {
    let path = std::env::var("NAOME_OBJECTIVE_INPUT").expect("frozen cold owned inputs");
    let diagnosis: Diagnosis = read(&path);
    assert_eq!(diagnosis.cases.len(), 3);
    for (path, hash) in &diagnosis.original_sha256 {
        assert_eq!(
            crate::hex(&Sha256::digest(std::fs::read(path).unwrap())),
            *hash
        );
    }
    for case in &diagnosis.cases {
        assert!(diagnosis.original_sha256.contains_key(&case.original_job));
        let job: Job = read(&case.original_job);
        job.validate().unwrap();
        let base = &job.base;
        assert!(job.training && base.needs_training());
        assert_eq!(base.model.updates, 0);
        assert!(base.model.model.is_none() && base.model.optimizer.is_none());
        let expected = job.progress.as_ref().unwrap();
        assert_eq!(base.model, expected.model);
        case.expected_candidate.validate().unwrap();
        assert_eq!(case.expected_candidate.updates, 250);
        assert_eq!(case.expected_candidate.seed, base.model.seed);
        assert_eq!(
            case.expected_candidate.specification,
            base.model.specification
        );
        let experience = &expected.meta_update.as_ref().unwrap().experience;
        assert_eq!(experience.job, case.job);
        assert_eq!(experience.source_model, digest(&base.model));
        assert_eq!(
            experience.candidate_model,
            Some(digest(&case.expected_candidate))
        );
        let plan = &expected.plan.as_ref().unwrap().plan;
        plan.validate().unwrap();
        for rehearsal in [false, true] {
            assert!(
                !base
                    .training_pool_for(&job.evidence, rehearsal)
                    .unwrap()
                    .is_empty()
            );
        }
        if let Some(path) = &case.completed_original {
            for file in [
                "units.json",
                "candidate/checkpoint.json",
                "candidate/model.bpk",
                "candidate/optimizer.bpk",
            ] {
                assert!(
                    diagnosis
                        .original_sha256
                        .contains_key(&format!("{path}/{file}"))
                );
            }
            let units: Vec<serde_json::Value> = read(&format!("{path}/units.json"));
            assert_eq!(units.len(), model::TRAINING_UNITS as usize);
            for (index, unit) in units.iter().enumerate() {
                assert_eq!(unit["unit"], index + 1);
                assert_eq!(unit["checkpoint"]["updates"], (index + 1) * 10);
                assert_eq!(unit["cursor"], base.draws + (index as u64 + 1) * 160);
                assert_eq!(
                    unit["phase"],
                    serde_json::to_value(plan.phase(index as u32)).unwrap()
                );
            }
            assert_eq!(
                units.last().unwrap()["checkpoint"],
                serde_json::to_value(&case.expected_candidate).unwrap()
            );
            assert_eq!(
                checkpoint(&format!("{path}/candidate"), &mut Store::default()),
                case.expected_candidate
            );
        }
    }
    diagnosis
}

#[test]
#[ignore = "Explicit current-format owned-input preflight; no inference or updates"]
fn cold_objective_input_preflight() {
    let diagnosis = inputs();
    assert_eq!(diagnosis.cases.len(), 3);
}

#[test]
#[ignore = "Read-only native source coverage; no inference, search or optimizer updates"]
fn cold_objective_source_coverage() {
    let output = std::env::var("NAOME_OBJECTIVE_OUTPUT").expect("fresh coverage output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve previous coverage exports");
    let diagnosis = inputs();
    let mut rows = Vec::new();
    for case in &diagnosis.cases {
        let job: Job = read(&case.original_job);
        let directory = output.join(&case.name);
        std::fs::create_dir_all(&directory).unwrap();
        for rehearsal in [false, true] {
            let pool = job
                .base
                .training_pool_for(&job.evidence, rehearsal)
                .unwrap();
            let graphs = pool.graphs();
            assert!(!graphs.is_empty());
            let mut rules = BTreeMap::<i32, usize>::new();
            for graph in graphs {
                for selected in &graph.successes {
                    *rules
                        .entry(graph.nodes[graph.candidates[*selected]].kind)
                        .or_default() += 1;
                }
            }
            let filename = if rehearsal {
                "rehearsal.json"
            } else {
                "replay.json"
            };
            write(&directory.join(filename), &graphs);
            rows.push(serde_json::json!({"case":case.name,"rehearsal":rehearsal,
                "graphs":graphs.len(),"native_checked_sources":job.base.training_sources().count(),
                "known_successes_by_rule":rules,"base_binding":digest(&job.base),
                "pool_binding":digest(&graphs)}));
        }
    }
    write(
        &output.join("completed.json"),
        &serde_json::json!({"cases":rows,
        "inference_calls":0,"native_searches":0,"optimizer_updates":0,
        "unknown_actions_are_not_negative_labels":true}),
    );
}

#[test]
#[ignore = "Six fixed objective branches; no upper updates, final queries or installation"]
fn cold_objective_intervention() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "Release only"
    );
    let output = std::env::var("NAOME_OBJECTIVE_OUTPUT").expect("fresh objective output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve prior measurements");
    let diagnosis = inputs();
    let meter = crate::resources::feedback::Meter::start();
    let whole = Instant::now();
    let whole_cpu = meta::cpu_micros().unwrap();
    let mut rows = Vec::new();
    let mut new_updates = 0u64;
    let mut recovered_updates = 0u64;
    // Complete all exact controls before the first intervention optimizer call.
    for name in ["original", "marginal_only"] {
        for case in &diagnosis.cases {
            let started = Instant::now();
            let cpu = meta::cpu_micros().unwrap();
            let job: Job = read(&case.original_job);
            let base = &job.base;
            let base_binding = digest(base);
            let evidence_binding = digest(&job.evidence);
            let expected = job.progress.as_ref().unwrap();
            let mut plan = expected.plan.as_ref().unwrap().plan.clone();
            if name == "marginal_only" {
                for phase in &mut plan.phases {
                    phase.ranking_quarters = 0;
                }
            }
            plan.validate().unwrap();
            let directory = output.join(&case.name).join(name);
            std::fs::create_dir_all(&directory).unwrap();
            let mut store = Store::default();
            let mut candidate = base.model.clone();
            let mut engine = Engine::default();
            // Export materializes fresh weights and empty Adam state. Compare
            // that initialized snapshot, rather than its lazy input descriptor.
            let parent_snapshot = Engine::default()
                .snapshot(&base.model, &mut Store::default().inner)
                .unwrap();
            let mut cursor = base.draws;
            let mut losses = [0f32; 2];
            let mut units: Vec<serde_json::Value> = Vec::new();
            eprintln!("objective_branch_started {} {name}", case.name);
            let recovered = if name == "original" {
                case.completed_original.as_ref()
            } else {
                None
            };
            if let Some(path) = recovered {
                candidate = checkpoint(&format!("{path}/candidate"), &mut store);
                units = read(&format!("{path}/units.json"));
                losses = [
                    serde_json::from_value(units[0]["first_loss"].clone()).unwrap(),
                    serde_json::from_value(units.last().unwrap()["last_loss"].clone()).unwrap(),
                ];
                cursor = units.last().unwrap()["cursor"].as_u64().unwrap();
                recovered_updates += candidate.updates;
                write(&directory.join("units.json"), &units);
            } else {
                for unit in 0..model::TRAINING_UNITS {
                    limits(started, cpu);
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
                        .expect("same genuine checked pool");
                    if unit == 0 {
                        losses[0] = first;
                    }
                    losses[1] = last;
                    candidate = next;
                    new_updates += 10;
                    units.push(serde_json::json!({"unit":unit+1,"checkpoint":candidate,
                    "cursor":cursor,"phase":plan.phase(unit),"first_loss":first,
                    "last_loss":last,"training_cost":engine.cost}));
                    let keep = candidate
                        .blobs()
                        .map(|b| &b.sha256)
                        .collect::<BTreeSet<_>>();
                    store.inner.0.retain(|(hash, _), _| keep.contains(hash));
                    write(&directory.join("units.json"), &units);
                }
            }
            assert_eq!(candidate.updates, 250);
            assert_eq!(cursor, expected.rng);
            if name == "original" {
                assert_eq!(candidate, case.expected_candidate);
                assert_eq!(losses[0].to_bits(), expected.first_loss.unwrap().to_bits());
                assert_eq!(losses[1].to_bits(), expected.last_loss.unwrap().to_bits());
            }
            export_model(&directory.join("candidate"), &candidate, &store.inner);
            let qualification = qualification_screen(
                base,
                &candidate,
                &mut engine,
                &mut store,
                case.job,
                (started, cpu),
            );
            assert_eq!(qualification["before"], expected.incumbent_score);
            assert_eq!(
                qualification["transfer"]["before"],
                expected.transfer.before
            );
            if name == "original" {
                assert_eq!(qualification["after"], expected.candidate_score);
                assert_eq!(
                    qualification["protected_loss"],
                    expected.development_regression
                );
                assert_eq!(qualification["anchor_loss"], expected.anchor_regression);
                assert_eq!(
                    qualification["transfer"],
                    serde_json::to_value(expected.transfer).unwrap()
                );
                let mut counts = [0u64; 2];
                for row in qualification["native_evaluations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .take(curriculum::CORPUS_DEVELOPMENT)
                {
                    counts[0] += u64::from(row["before"].as_bool().unwrap());
                    counts[1] += u64::from(row["after"].as_bool().unwrap());
                }
                assert_eq!(counts, expected.original_score.map(u64::from));
            }
            assert_eq!(
                engine.snapshot(&candidate, &mut store.inner).unwrap(),
                candidate
            );
            assert_eq!(
                engine.snapshot(&base.model, &mut store.inner).unwrap(),
                parent_snapshot
            );
            assert_eq!(digest(base), base_binding);
            assert_eq!(digest(&job.evidence), evidence_binding);
            limits(started, cpu);
            assert!(store.read_bytes + store.written_bytes <= model::REQUIREMENTS.io_bytes as u64);
            let result = serde_json::json!({"branch":name,"candidate":candidate,"cursor":cursor,
                "losses":losses,"loss_bits":losses.map(f32::to_bits),"qualification":qualification,
                "base_binding":base_binding,"evidence_binding":evidence_binding,"plan":plan,
                "parent_materialized_snapshot":parent_snapshot,"recovered_original_updates":if recovered.is_some() {250} else {0},
                "cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":started.elapsed().as_micros(),
                "read_bytes":store.read_bytes,"written_bytes":store.written_bytes,
                "original_exact":name=="original","installed_or_promoted":false});
            write(&directory.join("result.json"), &result);
            rows.push(serde_json::json!({"case":case.name,"job":case.job,"result":result}));
            write(&output.join("partial.json"), &rows);
            eprintln!("objective_branch_completed {} {name}", case.name);
        }
    }
    let resources = meter.finish(0, true);
    assert!(resources.peak_rss_bytes.unwrap() <= model::REQUIREMENTS.work_bytes as u64);
    assert_eq!(new_updates + recovered_updates, 1500);
    write(
        &output.join("completed.json"),
        &serde_json::json!({"cases":rows,
        "lower_optimizer_updates":1500,"upper_optimizer_updates":0,"new_final_queries":0,
        "new_lower_optimizer_updates":new_updates,"recovered_lower_optimizer_updates":recovered_updates,
        "cpu_micros":meta::cpu_micros().unwrap()-whole_cpu,"wall_micros":whole.elapsed().as_micros(),
        "peak_rss_bytes":resources.peak_rss_bytes,"diagnostic_only":true}),
    );
}
