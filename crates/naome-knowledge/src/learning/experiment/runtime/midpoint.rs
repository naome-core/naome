//! Fixed inference-only displacement probe; never a trained or installed state.
use super::warm::inputs;
use super::*;

fn midpoint(parent: &Path, candidate: &Path) -> Vec<u8> {
    let a = burn_pack::Reader::from_file_exact(parent).unwrap();
    let b = burn_pack::Reader::from_file_exact(candidate).unwrap();
    assert_eq!(a.metadata(), b.metadata());
    assert_eq!(a.scalars(), b.scalars());
    let metadata = b.metadata().clone();
    let scalars = b.scalars().clone();
    let mut a = a.into_tensors().unwrap();
    let mut b = b.into_tensors().unwrap();
    a.sort_by(|a, b| a.name.cmp(&b.name));
    b.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(a.len(), b.len());
    let mut result = Vec::new();
    let mut parameters = 0usize;
    for (a, b) in a.into_iter().zip(b) {
        assert_eq!(
            (&a.name, &a.shape, a.dtype, a.param_id),
            (&b.name, &b.shape, b.dtype, b.param_id)
        );
        assert_eq!(a.dtype, burn_pack::DType::F32);
        let (name, dtype, shape, id) = (b.name.clone(), b.dtype, b.shape.clone(), b.param_id);
        let x = a.into_bytes().unwrap();
        let y = b.into_bytes().unwrap();
        assert_eq!(x.len(), y.len());
        assert_eq!(x.len() % 4, 0);
        let mut bytes = Vec::with_capacity(x.len());
        for (a, b) in x.chunks_exact(4).zip(y.chunks_exact(4)) {
            let a = f32::from_le_bytes(a.try_into().unwrap());
            let b = f32::from_le_bytes(b.try_into().unwrap());
            let value = 0.5f32 * a + 0.5f32 * b;
            assert!(a.is_finite() && b.is_finite() && value.is_finite());
            bytes.extend_from_slice(&value.to_le_bytes());
            parameters += 1;
        }
        result.push(burn_pack::Tensor::new(
            name,
            dtype,
            shape,
            id,
            burn_pack::Bytes::from_bytes_vec(bytes),
        ));
    }
    assert_eq!(parameters, model::PARAMETERS);
    let mut writer = burn_pack::Writer::new(result);
    for (key, value) in metadata {
        writer = writer.with_metadata(&key, &value);
    }
    for (key, value) in scalars {
        writer = writer.with_scalar(&key, value);
    }
    writer.into_bytes().unwrap().to_vec()
}

#[test]
#[ignore = "Twelve-source midpoint format preflight; no inference or updates"]
fn warm_midpoint_preflight() {
    for case in inputs("NAOME_MIDPOINT_INPUT").cases {
        for directory in [case.parent_checkpoint, case.candidate_checkpoint] {
            let path = Path::new(&directory).join("model.bpk");
            assert_eq!(midpoint(&path, &path), std::fs::read(path).unwrap());
        }
    }
}

#[test]
#[ignore = "Fixed24-branch inference-only midpoint probe; no optimizer or final queries"]
fn warm_midpoint_diagnosis() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "Release only"
    );
    let output = std::env::var("NAOME_MIDPOINT_OUTPUT").expect("fresh midpoint output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve prior probes");
    let inputs = inputs("NAOME_MIDPOINT_INPUT");
    let meter = crate::resources::feedback::Meter::start();
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let mut rows = Vec::new();
    for branch in ["original", "midpoint"] {
        for case in &inputs.cases {
            let clock = (Instant::now(), meta::cpu_micros().unwrap());
            let job: Job = read(&case.original_job);
            let base = &job.base;
            let expected = job.progress.as_ref().unwrap();
            let base_binding = digest(base);
            let mut store = Store::default();
            let parent = checkpoint(&case.parent_checkpoint, &mut store);
            let candidate = checkpoint(&case.candidate_checkpoint, &mut store);
            let mut probe = candidate.clone();
            let directory = output.join(&case.name).join(branch);
            std::fs::create_dir_all(&directory).unwrap();
            if branch == "midpoint" {
                let bytes = midpoint(
                    &Path::new(&case.parent_checkpoint).join("model.bpk"),
                    &Path::new(&case.candidate_checkpoint).join("model.bpk"),
                );
                let blob = artifact::save(&mut store.inner, &bytes).unwrap();
                std::fs::write(directory.join("counterfactual-weights.bpk"), &bytes).unwrap();
                probe.model = Some(blob);
            }
            eprintln!("midpoint_branch_started {} {branch}", case.name);
            let mut engine = Engine::default();
            let q = qualification_screen(base, &probe, &mut engine, &mut store, case.job, clock);
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
                let mut counts = [0u64; 2];
                for row in q["native_evaluations"]
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
            assert_eq!(engine.snapshot(&probe, &mut store.inner).unwrap(), probe);
            assert_eq!(engine.snapshot(&parent, &mut store.inner).unwrap(), parent);
            assert_eq!(digest(base), base_binding);
            limits(clock.0, clock.1);
            assert!(store.read_bytes + store.written_bytes <= model::REQUIREMENTS.io_bytes as u64);
            let row = serde_json::json!({"case":case.name,"job":case.job,"branch":branch,
                "base_binding":base_binding,"qualification":q,"policy_weights":probe.model,
                "loader_optimizer":probe.optimizer,"not_a_trained_checkpoint":branch=="midpoint",
                "cpu_micros":meta::cpu_micros().unwrap()-clock.1,"wall_micros":clock.0.elapsed().as_micros(),
                "artifact_read_bytes":store.read_bytes,"artifact_written_bytes":store.written_bytes,
                "optimizer_updates":0,"installed_resumed_or_promoted":false});
            write(&directory.join("result.json"), &row);
            rows.push(row);
            write(&output.join("partial.json"), &rows);
            eprintln!("midpoint_branch_completed {} {branch}", case.name);
        }
    }
    let resources = meter.finish(0, true);
    assert!(resources.peak_rss_bytes.unwrap() <= model::REQUIREMENTS.work_bytes as u64);
    write(
        &output.join("completed.json"),
        &serde_json::json!({"cases":rows,
        "cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":started.elapsed().as_micros(),
        "peak_rss_bytes":resources.peak_rss_bytes,"optimizer_updates":0,"new_final_queries":0,
        "diagnostic_only":true,"no_continuation_checkpoint_created":true}),
    );
}
