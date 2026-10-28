//! Explicit replay of exact owned trial inputs for finite runtime measurements.
//! Previously revealed outcomes are regression diagnostics, not new holdout data.
use super::*;
use knowledge::Store;
use serde::Deserialize;

#[derive(Deserialize)]
struct Input {
    name: String,
    job: u64,
    source: String,
    sha256: String,
    blobs: Vec<(Blob, String)>,
    candidate: Checkpoint,
}

#[derive(Deserialize)]
struct Inputs {
    jobs: Vec<Input>,
}

fn current_base(expected: &Job) -> State {
    let mut base = expected.base.clone();
    base.model.specification = Checkpoint::fresh().specification;
    base.meta.model.specification = meta::Checkpoint::fresh().specification;
    let binding = digest(&base.model);
    base.feedback.checkpoint = binding.clone();
    base.feedback.attempts.checkpoint = binding.clone();
    base.feedback.development.checkpoint = binding;
    base
}

fn observation_micros(profile: &crate::training::ability::Profile) -> u64 {
    // Logic is present exactly once for every recorded question, so its cells
    // measure actual solve time without summing overlapping syntax families.
    let value = serde_json::to_value(profile).unwrap();
    value["cells"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(key, _)| key.parse::<u32>().unwrap() % 24 < 4)
        .map(|(_, cells)| cells[2].as_u64().unwrap())
        .sum()
}

#[test]
#[ignore = "Explicit finite exact-input Release runtime profile; revealed diagnostic corpus"]
fn exact_owned_trial_runtime_profile() {
    assert!(!cfg!(debug_assertions), "Release measurement only");
    let input = std::env::var("NAOME_RUNTIME_INPUT").expect("frozen runtime inputs");
    let output = std::env::var("NAOME_RUNTIME_OUTPUT").expect("fresh runtime output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve earlier measurements");
    std::fs::create_dir_all(output).unwrap();
    let inputs: Inputs = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let filter = std::env::var("NAOME_RUNTIME_FILTER").unwrap_or_default();
    let meter = crate::resources::feedback::Meter::start();
    let mut summaries = Vec::new();
    for input in inputs
        .jobs
        .iter()
        .filter(|j| filter.is_empty() || j.name.contains(&filter))
    {
        eprintln!(
            "runtime_trial_started {} pid={}",
            input.name,
            std::process::id()
        );
        let started = Instant::now();
        let cpu = meta::cpu_micros().unwrap();
        let source = std::fs::read(&input.source).unwrap();
        assert_eq!(crate::hex(&Sha256::digest(&source)), input.sha256);
        let expected: Job = serde_json::from_slice(&source).unwrap();
        let expected_progress = expected.progress.as_ref().unwrap();
        // Construct a current-contract diagnostic fixture from exact frozen
        // tensor/Adam bytes. Product loading never accepts a different source
        // fingerprint. Historical evidence stays unchanged and SHA-bound.
        let specification = Checkpoint::fresh().specification;
        let base = current_base(&expected);
        base.validate().unwrap();
        let mut candidate = input.candidate.clone();
        candidate.specification = specification.clone();
        let mut selected = expected_progress.model.clone();
        selected.specification = specification;
        let mut job = base.job();
        job.training = true;
        job.evidence = expected.evidence.clone();
        let mut store = Store::default();
        for (blob, path) in &input.blobs {
            let bytes = std::fs::read(path).unwrap();
            assert_eq!(Blob::of(&bytes), *blob);
            assert_eq!(artifact::save(&mut store.inner, &bytes).unwrap(), *blob);
        }
        let mut engine = Engine::default();
        let mut units = Vec::new();
        for unit in 1..=job.units() {
            assert!(
                started.elapsed() < Duration::from_secs(120)
                    && meta::cpu_micros().unwrap() - cpu < 90_000_000,
                "original outer-trial CPU/wall allowance ended; incomplete runtime diagnostic"
            );
            let before_cpu = meta::cpu_micros().unwrap();
            let before_wall = Instant::now();
            job.execute(unit, None, input.job, &mut engine, &mut store)
                .unwrap();
            let execute_cpu = meta::cpu_micros().unwrap() - before_cpu;
            let execute_wall = before_wall.elapsed().as_micros();
            let validation_cpu = meta::cpu_micros().unwrap();
            let validation_wall = Instant::now();
            job.validate().unwrap();
            let validation_cpu = meta::cpu_micros().unwrap() - validation_cpu;
            let validation_wall = validation_wall.elapsed().as_micros();
            if unit == model::TRAINING_UNITS {
                assert_eq!(
                    job.progress.as_ref().unwrap().candidate.as_ref().unwrap(),
                    &candidate
                );
                export_model(
                    &output.join(&input.name).join("candidate"),
                    &candidate,
                    &store.inner,
                );
                eprintln!("runtime_qualification_started {}", input.name);
            }
            let p = job.progress.as_ref().unwrap();
            units.push(
                serde_json::json!({"unit":unit,"execute_cpu_micros":execute_cpu,
                "execute_wall_micros":execute_wall,"validation_cpu_micros":validation_cpu,
                "validation_wall_micros":validation_wall,"training":p.training_cost,
                "incumbent_observation_micros":observation_micros(&p.development_before),
                "candidate_observation_micros":observation_micros(&p.development_after)}),
            );
            if unit.is_multiple_of(10) {
                std::fs::create_dir_all(output.join(&input.name)).unwrap();
                write(
                    &output.join(&input.name).join("partial.json"),
                    &serde_json::json!({
                    "unit":unit,"elapsed_wall_micros":started.elapsed().as_micros(),
                    "elapsed_cpu_micros":meta::cpu_micros().unwrap()-cpu,
                    "progress":p,
                    "units":units}),
                );
            }
            let keep = job
                .blobs()
                .iter()
                .map(|b| b.sha256.clone())
                .collect::<BTreeSet<_>>();
            store.inner.0.retain(|(hash, _), _| keep.contains(hash));
        }
        let p = job.progress.as_ref().unwrap();
        assert_eq!(p.model, selected);
        assert_eq!(p.first_loss, expected_progress.first_loss);
        assert_eq!(p.last_loss, expected_progress.last_loss);
        assert_eq!(p.rng, expected_progress.rng);
        assert_eq!(p.plan, expected_progress.plan);
        assert_eq!(p.incumbent_score, expected_progress.incumbent_score);
        assert_eq!(p.candidate_score, expected_progress.candidate_score);
        assert_eq!(p.transfer, expected_progress.transfer);
        assert_eq!(p.diagnostic, expected_progress.diagnostic);
        assert_eq!(p.anchor_regression, expected_progress.anchor_regression);
        assert_eq!(
            p.development_regression,
            expected_progress.development_regression
        );
        let summary = serde_json::json!({"name":input.name,"job":input.job,"units":job.units(),
            "cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":started.elapsed().as_micros(),
            "progress":p,"read_bytes":store.read_bytes,"written_bytes":store.written_bytes,
            "read_operations":store.reads,"write_operations":store.writes});
        std::fs::create_dir_all(output.join(&input.name)).unwrap();
        write(&output.join(&input.name).join("units.json"), &units);
        write(&output.join(&input.name).join("summary.json"), &summary);
        write(&output.join(&input.name).join("job.json"), &job);
        eprintln!(
            "runtime_trial_completed {} cpu={} wall={}",
            input.name, summary["cpu_micros"], summary["wall_micros"]
        );
        summaries.push(summary);
    }
    assert!(!summaries.is_empty(), "at least one exact owned trial");
    write(
        &output.join("completed.json"),
        &serde_json::json!({"trials":summaries,
        "resources":format!("{:?}",meter.finish(0,true))}),
    );
}

#[test]
#[ignore = "Finite owner-validation profile on frozen owned replay; no model inference or updates"]
fn owned_replay_working_set_profile() {
    let input = std::env::var("NAOME_RUNTIME_INPUT").expect("frozen runtime inputs");
    let output = std::env::var("NAOME_RUNTIME_OUTPUT").expect("fresh runtime output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve earlier measurements");
    std::fs::create_dir_all(output).unwrap();
    let inputs: Inputs = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let filter = std::env::var("NAOME_RUNTIME_FILTER").expect("one declared working set");
    let mut selected = None;
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    for input in &inputs.jobs {
        let source = std::fs::read(&input.source).unwrap();
        assert_eq!(crate::hex(&Sha256::digest(&source)), input.sha256);
        let expected: Job = serde_json::from_slice(&source).unwrap();
        let base = current_base(&expected);
        base.validate().unwrap();
        if input.name.contains(&filter) {
            assert!(selected.is_none());
            selected = Some(base);
        }
    }
    let priming = serde_json::json!({"cpu_micros":meta::cpu_micros().unwrap()-cpu,
        "wall_micros":started.elapsed().as_micros(),"other_owned_states":inputs.jobs.len()});
    let base = selected.expect("exact declared working set");
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let checking = proof::checking_work();
    let mut rows = Vec::new();
    for pass in 0..150 {
        assert!(
            started.elapsed() < Duration::from_secs(120)
                && meta::cpu_micros().unwrap() - cpu < 90_000_000
        );
        let checked = proof::checking_work();
        let elapsed = Instant::now();
        let tick = meta::cpu_micros().unwrap();
        base.validate().unwrap();
        rows.push(
            serde_json::json!({"pass":pass,"cpu_micros":meta::cpu_micros().unwrap()-tick,
            "wall_micros":elapsed.elapsed().as_micros(),
            "checker_calls":proof::checking_work().calls-checked.calls,
            "checker_steps":proof::checking_work().steps-checked.steps}),
        );
    }
    let result = serde_json::json!({"scope":"Existing owner validation only; no model inference, optimizer updates or new quality queries",
        "priming":priming,"working_set":filter,"repeated_validations":150,
        "cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":started.elapsed().as_micros(),
        "checker_calls":proof::checking_work().calls-checking.calls,
        "checker_steps":proof::checking_work().steps-checking.steps,"passes":rows});
    write(&output.join("completed.json"), &result);
    eprintln!(
        "runtime_replay_validation cpu={} wall={} checks={}",
        result["cpu_micros"], result["wall_micros"], result["checker_calls"]
    );
}
