//! Paired inference at an actually retained checkpoint, without optimizer work.
use super::*;

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Spent {
    cpu_micros: u64,
    wall_micros: u64,
    io_bytes: u64,
}
impl Spent {
    fn available(
        &self,
        observer: &mut crate::resources::adaptive::Observer,
        started: Instant,
        cpu: u64,
        output: &Path,
    ) -> Result<(), String> {
        available(observer, started, cpu, output)?;
        if meta::cpu_micros()?
            .saturating_sub(cpu)
            .checked_add(self.cpu_micros)
            .is_none_or(|n| n > TRAIN_CPU)
            || started.elapsed().as_micros() + u128::from(self.wall_micros) > u128::from(TRAIN_WALL)
        {
            return Err("carry/reset exhausted its original cumulative allowance".into());
        }
        Ok(())
    }
}

fn admitted(round: &Value, state: &State) -> Result<(), String> {
    let trial = &round["trial"];
    if trial["status"] != "complete"
        || trial["retained_update"] != true
        || state.promotions == 0
        || state.model.updates == 0
        || trial["source_model"]["updates"]
            .as_u64()
            .and_then(|n| n.checked_add(250))
            != Some(state.model.updates)
        // A job made from the already qualified State has no new epoch left.
        // Check the completed training phase, not that new job's one-unit idle path.
        || trial["progress"]["unit"] != model::TRAINING_UNITS + crate::learning::EVALUATIONS + 1
        || round["state_sha256"] != digest(state)
        || round["selected_model"] != serde_json::to_value(&state.model).unwrap()
        || trial["selected_model"] != round["selected_model"]
        || trial["progress"]["model"] != round["selected_model"]
    {
        return Err("carry/reset requires the exact fully retained native update".into());
    }
    Ok(())
}

#[test]
fn rejected_incomplete_and_substituted_updates_cannot_authorize_inference() {
    // Synthetic metadata only. These bytes never reach a model or proof loader.
    let mut state = State::fresh();
    state.promotions = 1;
    state.epoch = 12;
    state.trained = 12;
    state.model.updates = 250;
    state.model.model = Some(Blob::of(b"synthetic model descriptor"));
    state.model.optimizer = Some(Blob::of(b"synthetic Adam descriptor"));
    let mut job = state.job();
    job.training = true;
    assert_eq!(job.units(), 1);
    let original = json!({"state_sha256":digest(&state),"selected_model":state.model,
        "trial":{"status":"complete","retained_update":true,"source_model":{"updates":0},
        "selected_model":state.model,"progress":{"unit":model::TRAINING_UNITS+crate::learning::EVALUATIONS+1,"model":state.model}}});
    admitted(&original, &state).unwrap();
    for (pointer, value) in [
        ("/trial/retained_update", json!(false)),
        ("/trial/status", json!("interrupted")),
        ("/trial/progress/unit", json!(25)),
        ("/trial/source_model/updates", json!(250)),
        ("/trial/selected_model/seed", json!(999)),
        ("/state_sha256", json!("00".repeat(32))),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(admitted(&changed, &state).is_err(), "{pointer}");
    }
}

#[test]
#[ignore = "prospectively bounded Carry/Reset inference at a retained native checkpoint"]
fn compare_retained_carry_and_reset() {
    let input = PathBuf::from(std::env::var("NAOME_CARRY_SOURCES").unwrap());
    let original = PathBuf::from(std::env::var("NAOME_CARRY_ARM").unwrap());
    let output = PathBuf::from(std::env::var("NAOME_CARRY_OUTPUT").unwrap());
    let epoch: usize = std::env::var("NAOME_CARRY_EPOCH").unwrap().parse().unwrap();
    let checkpoint_index: usize = std::env::var("NAOME_CARRY_INDEX").unwrap().parse().unwrap();
    assert!(epoch < 3 && checkpoint_index < 2 && !output.exists());
    std::fs::create_dir_all(&output).unwrap();
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let mut meter = Meter::start().unwrap();
    let mut observer = crate::resources::adaptive::Observer::default();
    let mut spent = Spent::default();
    let mut metadata_bytes = 0;
    let mut bindings = Vec::new();
    let mut rows = Vec::new();
    let outcome = (|| -> Result<Value, String> {
        available(&mut observer, started, cpu, &output)?;
        if let Ok(path) = std::env::var("NAOME_CARRY_PREVIOUS_COST") {
            spent = read(Path::new(&path), &mut metadata_bytes, &mut bindings)?;
        }
        spent.available(&mut observer, started, cpu, &output)?;
        let bank = read_bytes(
            Path::new(&std::env::var("NAOME_FINDER_CONFIRMATION_INPUTS").unwrap()),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        let holdout = lineage::Holdout::read(
            &bank,
            &std::env::var("NAOME_EXPERIENCE_HOLDOUT_SHA256").unwrap(),
        )?;
        let (frozen, restored) = sources::Frozen::read(&input, &holdout)?;
        spent.available(&mut observer, started, cpu, &output)?;
        let source: Value = read(
            &original.join("input.json"),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        let result: Value = read(
            &original.join("result.json"),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        let seal: Value = read(
            &original.join("cost-seal.json"),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        let path = original.join(format!("epoch-{epoch}"));
        let state: State = read(
            &path.join("selected-state.json"),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        state.validate()?;
        let round: Value = read(
            &path.join("result.json"),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        if source["arm"] != "latent"
            || result["arm"] != source["arm"]
            || result["seed"] != source["seed"]
            || source["seed"] != frozen.initial.model.seed
            || result["complete"] != true
            || seal["complete"] != true
            || source["initial_state_sha256"] != digest(&frozen.initial)
            || source["input_sources_sha256"] != frozen.cost["source_sha256"]
            || source["specification"] != input_specification()
            || result["rounds"][epoch] != round
            || round["source_state_sha256"]
                != digest(frozen.epochs.get(epoch).ok_or("source epoch absent")?)
        {
            return Err("carry/reset source, complete arm or retained round differs".into());
        }
        admitted(&round, &state)?;
        let model_path = path.join("candidate-model");
        let saved: Checkpoint = read(
            &model_path.join("checkpoint.json"),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        saved.validate()?;
        if saved != state.model {
            return Err("carry/reset checkpoint is not the actual retained candidate".into());
        }
        let mut import_bytes = std::fs::metadata(model_path.join("checkpoint.json"))
            .map_err(|e| e.to_string())?
            .len();
        for (name, blob) in [("model", &saved.model), ("optimizer", &saved.optimizer)] {
            let blob = blob.as_ref().ok_or("trained checkpoint blob absent")?;
            let bytes = std::fs::metadata(model_path.join(format!("{name}.bpk")))
                .map_err(|e| e.to_string())?
                .len();
            if bytes != blob.bytes as u64 {
                return Err("retained blob file size differs".into());
            }
            import_bytes += bytes;
        }
        // The canonical importer checks every complete model/Adam blob hash.
        let (imported, store) = super::super::super::confirmation::import_model(&model_path)?;
        if imported != saved {
            return Err("retained importer changed its descriptor".into());
        }
        let mut selected = Vec::new();
        let mut seen = BTreeSet::new();
        for episode in frozen.episodes.iter().take(48) {
            let q = CompiledQuestion::compile(&episode.observation.question)
                .map_err(|e| e.to_string())?;
            holdout.question(&q, Some(&episode.authored_lineage))?;
            if State::eligible(q.source()) && seen.insert(crate::hex(q.resolution_id())) {
                selected.push((episode.observation.summary.job, q));
            }
            if selected.len() == 24 {
                break;
            }
        }
        if selected.len() != 24 {
            return Err("diagnosis lacks its predeclared24 own questions".into());
        }
        // No inference occurs until the entire selected source set passed its split.
        let state_binding = digest(&state);
        let mut io = sources::history::Io::new(&frozen, &input);
        io.store.inner.0.extend(store.0);
        let restored_bytes = restored["source_read_bytes"]
            .as_u64()
            .ok_or("restore cost absent")?;
        meter.common(
            &json!({"cpu_micros":spent.cpu_micros,"wall_micros":spent.wall_micros,"model_io_bytes":spent.io_bytes,"archive_written_bytes":0}),
            &json!({"source_read_bytes":restored_bytes+metadata_bytes+import_bytes}),
        )?;
        let mut engines = [
            Engine::default().with_recurrence(model::Recurrence::Carry),
            Engine::default().with_recurrence(model::Recurrence::Reset),
        ];
        for engine in &mut engines {
            if engine.snapshot(&saved, &mut io)? != saved {
                return Err("diagnostic load changed the model or Adam".into());
            }
        }
        meter.write(&output.join("input.json"), &json!({"checkpoint":saved,"checkpoint_binding":digest(&saved),
            "source_state":state_binding,"source_bindings":bindings,"source_restore":restored,
            "import_read_bytes":import_bytes,"original_source_collection":frozen.cost,"checkpoint_index":checkpoint_index,
            "search_limit":32,"tasks":selected.iter().map(|(job,q)|json!({"job":job,"source":q.source(),"resolution":crate::hex(q.resolution_id())})).collect::<Vec<_>>(),
            "context":digest(&(&frozen.initial.definitions,&frozen.initial.knowledge)),"optimizer_updates":0}))?;
        for (index, (job, q)) in selected.iter().enumerate() {
            let mut pair = [Value::Null, Value::Null];
            let first = (index + checkpoint_index) % 2;
            for mode in [first, 1 - first] {
                spent.available(&mut observer, started, cpu, &output)?;
                super::super::run::available(&mut meter, &io, &mut observer, &output)?;
                let before_cpu = meta::cpu_micros()?;
                let before_wall = Instant::now();
                let before_io = io.store.bytes;
                let generated = engines[mode].with(&saved, &mut io, |runtime| {
                    solve_with_report(
                        q.source(),
                        runtime,
                        32,
                        *job,
                        SolveContext {
                            definitions: &frozen.initial.definitions,
                            theorems: &frozen.initial.knowledge,
                            ..Default::default()
                        },
                    )
                })?;
                if let Some(solution) = &generated.solution {
                    let checked = solution.checked()?.into_checked_proof();
                    let expected = if solution.refuted {
                        q.refuted_target()
                    } else {
                        q.proved_target()
                    };
                    if checked.conclusion() != expected {
                        return Err("diagnostic solution has another conclusion".into());
                    }
                    meter.write(
                        &output.join(format!("case-{index}-{mode}-proof.json")),
                        solution,
                    )?;
                }
                let used_cpu = meta::cpu_micros()?.saturating_sub(before_cpu);
                let used_wall = before_wall.elapsed().as_micros();
                let timely = used_cpu <= 2_500_000 && used_wall <= 5_000_000;
                let traces = json!({"executions":generated.executions});
                let trace_blob =
                    Blob::of(&serde_json::to_vec_pretty(&traces).map_err(|e| e.to_string())?);
                meter.write(
                    &output.join(format!("case-{index}-{mode}-traces.json")),
                    &traces,
                )?;
                pair[mode] = json!({"solved":generated.solution.is_some()&&timely,"late_checked_solution":generated.solution.is_some()&&!timely,
                    "terminal":generated.terminal,"diagnostic":generated.diagnostic,"cost":generated.cost,"traces":trace_blob,
                    "cpu_micros":used_cpu,"wall_micros":used_wall,"model_io_bytes":io.store.bytes-before_io});
            }
            rows.push(json!({"source_job":job,"resolution":crate::hex(q.resolution_id()),"carry":pair[0],"reset":pair[1],"first_mode":if first==0{"carry"}else{"reset"}}));
            meter.write(&output.join("cases.json"), &rows)?;
        }
        for engine in &mut engines {
            if engine.snapshot(&saved, &mut io)? != saved {
                return Err("inference changed weights, Adam or attenuation state".into());
            }
        }
        if digest(&state) != state_binding {
            return Err("inference changed the retained source state".into());
        }
        spent.available(&mut observer, started, cpu, &output)?;
        super::super::run::available(&mut meter, &io, &mut observer, &output)?;
        let wins = rows
            .iter()
            .filter(|r| r["carry"]["solved"] == true && r["reset"]["solved"] == false)
            .count();
        let losses = rows
            .iter()
            .filter(|r| r["carry"]["solved"] == false && r["reset"]["solved"] == true)
            .count();
        Ok(
            json!({"checkpoint":saved,"cases":rows,"carry_only":wins,"reset_only":losses,"optimizer_updates":0,
            "model_adam_unchanged":true,"state_unchanged":true,"cost":meter.report(&io),
            "interpretation":"Paired immediate inference effect on known own tasks; not independent generalization or proof that missing training context caused a difference."}),
        )
    })();
    let report = json!({"complete":outcome.is_ok(),"error":outcome.as_ref().err(),"measurement":outcome.as_ref().ok(),"completed_cases":rows.len()});
    meter.write(&output.join("result.json"), &report).unwrap();
    let final_io = outcome
        .as_ref()
        .ok()
        .and_then(|value| value["cost"]["charged_io_bytes"].as_u64())
        .and_then(|bytes| {
            bytes.checked_add(std::fs::metadata(output.join("result.json")).ok()?.len())
        });
    let final_limit = spent
        .available(&mut observer, started, cpu, &output)
        .and_then(|()| {
            if outcome.is_ok()
                && final_io.is_none_or(|bytes| bytes + 4096 > model::REQUIREMENTS.io_bytes as u64)
            {
                return Err("carry/reset reporting exhausted its original IO allowance".into());
            }
            Ok(())
        });
    let seal_bytes = serde_json::to_vec_pretty(&json!({"complete":outcome.is_ok()&&final_limit.is_ok(),
        "result":Blob::of(&std::fs::read(output.join("result.json")).unwrap()),"cpu_micros":meta::cpu_micros().unwrap().saturating_sub(cpu)+spent.cpu_micros,
        "wall_micros":started.elapsed().as_micros()+u128::from(spent.wall_micros),"metadata_read_bytes":metadata_bytes,"previous_io_charge":spent.io_bytes,"peak_rss_bytes":crate::resources::feedback::Meter::start().finish(0,true).peak_rss_bytes,
        "charged_io_bytes_before_seal":final_io,"reserved_seal_write_bytes":4096,"seal_write_is_reporting_overhead":true})).unwrap();
    assert!(seal_bytes.len() <= 4096);
    std::fs::write(output.join("cost-seal.json"), seal_bytes).unwrap();
    outcome.unwrap();
    final_limit.unwrap();
}
