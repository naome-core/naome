//! Independent fixed-reference calibration, never a candidate training label.
use super::*;

pub(super) fn bands(rates: &[[f64; 6]; 3]) -> Result<[[usize; 3]; 3], String> {
    let mut result = [[0; 3]; 3];
    for (track, values) in rates.iter().enumerate() {
        if values
            .iter()
            .any(|v| !v.is_finite() || !(0.0..=1.0).contains(v))
        {
            return Err("invalid calibration coverage or probability".into());
        }
        let mut selected = None;
        'triples: for easy in 0..6 {
            for medium in easy + 1..6 {
                for hard in medium + 1..6 {
                    if (0.65..=0.95).contains(&values[easy])
                        && (0.25..=0.65).contains(&values[medium])
                        && (0.05..=0.35).contains(&values[hard])
                        && values[easy] - values[medium] >= 0.15
                        && values[medium] - values[hard] >= 0.15
                    {
                        selected = Some([easy + 1, medium + 1, hard + 1]);
                        break 'triples;
                    }
                }
            }
        }
        result[track] = selected
            .ok_or_else(|| format!("track {} lacks three calibrated bands", TRACKS[track]))?;
    }
    Ok(result)
}

#[test]
#[ignore = "fixed-reference operational difficulty calibration; no candidate learning"]
fn calibrate_longitudinal_tracks() {
    let output = std::path::PathBuf::from(std::env::var("NAOME_FRONTIER_OUTPUT").unwrap());
    assert!(!output.exists());
    std::fs::create_dir_all(&output).unwrap();
    let mut meter = Meter::start().unwrap();
    let bytes = meter
        .read(
            &std::path::PathBuf::from(std::env::var("NAOME_FRONTIER_BANK").unwrap()),
            crate::resources::limits().native_model_blob_bytes,
        )
        .unwrap();
    let bank: Bank = serde_json::from_slice(&bytes).unwrap();
    let (reference, store) = meter
        .import(&std::path::PathBuf::from(
            std::env::var("NAOME_FRONTIER_REFERENCE").unwrap(),
        ))
        .unwrap();
    assert_eq!(reference.model.updates, 250);
    let mut io = sources::history::Io::journal(store, &output);
    let mut engine = Engine::default();
    let mut cold = Checkpoint::fresh();
    cold.seed = 2_903_003;
    cold = engine.snapshot(&cold, &mut io).unwrap();
    let models = [cold, reference.model];
    let mut observer = crate::resources::adaptive::Observer::default();
    let mut rows = Vec::new();
    let mut totals = [[[0u32; 2]; 6]; 3];
    for (reference, model) in models.iter().enumerate() {
        for (index, case) in bank.calibration.iter().enumerate() {
            run::available(&mut meter, &io, &mut observer, &output).unwrap();
            let before = meter.report(&io);
            assert!(before["charged_cpu_micros"].as_u64().unwrap() <= 90_000_000);
            assert!(before["charged_wall_micros"].as_u64().unwrap() <= 120_000_000);
            let cpu = meta::cpu_micros().unwrap();
            let wall = Instant::now();
            let result = engine
                .with(model, &mut io, |runtime| {
                    solve_with_report(
                        &case.source,
                        runtime,
                        32,
                        7_000_000 + index as u64,
                        SolveContext::default(),
                    )
                })
                .unwrap();
            if let Some(solution) = &result.solution {
                assert!(
                    !solution.refuted,
                    "intended entailment was refuted; reject construction"
                );
                let checked = solution.checked().unwrap().into_checked_proof();
                let q = CompiledQuestion::compile(&case.source).unwrap();
                assert_eq!(checked.conclusion(), q.proved_target());
                meter
                    .write(
                        &output.join(format!("reference-{reference}-proof-{index}.json")),
                        solution,
                    )
                    .unwrap();
            }
            let elapsed_cpu = meta::cpu_micros().unwrap() - cpu;
            let elapsed_wall = wall.elapsed().as_micros();
            let timely = elapsed_cpu <= 2_500_000 && elapsed_wall <= 5_000_000;
            let solved = result.solution.is_some() && timely;
            let cell = &mut totals[case.track][case.recipe - 1];
            cell[0] += u32::from(solved);
            cell[1] += 1;
            rows.push(json!({"reference":reference,"case":case,"solved":solved,
                "late_checked_proof":result.solution.is_some()&&!timely,
                "terminal":result.terminal,"diagnostic":result.diagnostic,
                "cpu_micros":elapsed_cpu,"wall_micros":elapsed_wall,"cost":result.cost}));
            meter.write(&output.join("partial.json"), &rows).unwrap();
        }
    }
    let rates = totals.map(|track| {
        track.map(|[successes, count]| {
            assert_eq!(
                count, 24,
                "each recipe requires six families/two variants/two fixed references"
            );
            f64::from(successes) / f64::from(count)
        })
    });
    let selected = bands(&rates);
    for model in &models {
        assert_eq!(engine.snapshot(model, &mut io).unwrap(), *model);
    }
    run::available(&mut meter, &io, &mut observer, &output).unwrap();
    let cost = meter.report(&io);
    assert!(cost["charged_cpu_micros"].as_u64().unwrap() <= 90_000_000);
    assert!(cost["charged_wall_micros"].as_u64().unwrap() <= 120_000_000);
    meter.write(&output.join("result.json"), &json!({"complete":true,
        "feasible":selected.is_ok(),"reason":selected.as_ref().err(),"bands":selected.as_ref().ok(),
        "rates":rates,"rows":rows,"reference_models":models,"cost":cost,
        "candidate_optimizer_updates":0,"assessment_model_calls":0,
        "scope":"Operational reference-conditional difficulty, not intrinsic mathematical complexity or candidate quality"})).unwrap();
    meter.check(&io).unwrap();
    let sealed = meter.report(&io);
    assert!(sealed["charged_cpu_micros"].as_u64().unwrap() <= 90_000_000);
    assert!(sealed["charged_wall_micros"].as_u64().unwrap() <= 120_000_000);
    meter
        .write(&output.join("cost-seal.json"), &sealed)
        .unwrap();
}
