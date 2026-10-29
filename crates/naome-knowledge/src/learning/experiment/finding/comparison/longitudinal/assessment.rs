//! Sealed, feedback-free inference on saved states, including causal probes.
use super::*;

pub(super) fn selected(design: &design::Design, pilot: bool) -> Result<Vec<Value>, String> {
    let rows = if pilot {
        &design.bank.pilot
    } else {
        &design.bank.assessment
    };
    let mut selected = Vec::new();
    for track in 0..3 {
        for band in 0..3 {
            let mut groups: BTreeMap<&str, Vec<&Case>> = BTreeMap::new();
            for case in rows
                .iter()
                .filter(|c| c.track == track && c.recipe == design.bands[track][band])
            {
                groups.entry(&case.construction).or_default().push(case);
            }
            let count = if pilot { 6 } else { 12 };
            if groups.len() != count {
                return Err("sealed assessment family coverage differs".into());
            }
            for (family, cases) in groups.values().enumerate() {
                if cases.len() != 2 {
                    return Err("assessment whole family lacks two variants".into());
                }
                for case in cases {
                    selected.push(json!({"case":case,"band":band,"half":family/(count/2),"family_index":family%(count/2)}));
                }
            }
        }
    }
    Ok(selected)
}

// Follow actual native references transitively, not offered knowledge or text.
fn dependencies(verified: &proof::Verified) -> Result<BTreeSet<String>, String> {
    let context = proof::lemma_context(&verified.definitions, &verified.lemmas)?;
    let mut available = BTreeMap::new();
    for lemma in &verified.lemmas {
        let id = proof::check(lemma.clone(), &context)
            .map_err(|e| e.to_string())?
            .proof_id();
        available.insert(crate::hex(id.as_bytes()), lemma);
    }
    let mut pending = vec![&verified.certificate];
    let mut found = BTreeSet::new();
    while let Some(certificate) = pending.pop() {
        for step in certificate.steps() {
            if let naome_proof::ProofStep::ProofReference { proof_id } = step {
                let id = crate::hex(proof_id.as_bytes());
                if found.insert(id.clone()) {
                    pending.push(
                        available
                            .get(&id)
                            .ok_or("checked dependency closure incomplete")?,
                    );
                }
            }
        }
    }
    Ok(found)
}

pub(super) fn early_knowledge(
    state: &State,
    first_acquired: &BTreeMap<String, usize>,
) -> Result<BTreeSet<String>, String> {
    state
        .knowledge
        .iter()
        .filter_map(|entry| match entry.verified() {
            Err(error) => Some(Err(error)),
            Ok(v) => {
                let id = crate::hex(v.native_id.as_bytes());
                match first_acquired.get(&id) {
                    Some(1 | 2) => Some(Ok(id)),
                    Some(_) => None,
                    None => Some(Err("retained theorem lacks acquisition provenance".into())),
                }
            }
        })
        .collect()
}

fn provenance(directory: &Path, meter: &mut Meter) -> Result<BTreeMap<String, usize>, String> {
    let mut first = BTreeMap::new();
    for phase in 0..=PHASES {
        let receipt: Value = serde_json::from_slice(&meter.read(
            &directory.join(format!("phase-{phase}/phase.json")),
            crate::resources::limits().native_model_blob_bytes,
        )?)
        .map_err(|e| e.to_string())?;
        for source in receipt["sources"]
            .as_array()
            .ok_or("phase source history absent")?
        {
            let job = source["job"].as_u64().ok_or("source job absent")?;
            let episode: sources::Episode = serde_json::from_slice(&meter.read(
                &directory.join(format!("episode-{job}.json")),
                crate::resources::limits().native_model_blob_bytes,
            )?)
            .map_err(|e| e.to_string())?;
            if let Some(solution) = episode.solution {
                let q = CompiledQuestion::compile(&episode.observation.question)
                    .map_err(|e| e.to_string())?;
                if let Some(entry) = solution.theorem(&q)? {
                    first
                        .entry(crate::hex(entry.verified()?.native_id.as_bytes()))
                        .or_insert(phase);
                }
            }
        }
    }
    Ok(first)
}

pub(super) fn without_early(
    state: &State,
    early: &BTreeSet<String>,
) -> Result<Vec<crate::learning::knowledge::Entry>, String> {
    state
        .knowledge
        .iter()
        .filter_map(|e| match e.verified() {
            Err(error) => Some(Err(error)),
            Ok(v) if early.contains(&crate::hex(v.native_id.as_bytes())) => None,
            Ok(_) => Some(Ok(e.clone())),
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn evaluate(
    state: &State,
    model: &Checkpoint,
    knowledge: &[crate::learning::knowledge::Entry],
    cases: &[Value],
    engine: &mut Engine,
    io: &mut sources::history::Io<'_>,
    meter: &mut Meter,
    observer: &mut crate::resources::adaptive::Observer,
    output: &Path,
    label: &str,
) -> Result<Vec<Value>, String> {
    let before = digest(state);
    let mut rows = Vec::new();
    for (index, cell) in cases.iter().enumerate() {
        run::available(meter, io, observer, output)?;
        let case: Case = serde_json::from_value(cell["case"].clone()).map_err(|e| e.to_string())?;
        let q = CompiledQuestion::compile(&case.source).map_err(|e| e.to_string())?;
        let cpu = meta::cpu_micros()?;
        let wall = Instant::now();
        let generation = engine.with(model, io, |runtime| {
            solve_with_report(
                q.source(),
                runtime,
                32,
                8_000_000 + index as u64,
                SolveContext {
                    definitions: &state.definitions,
                    theorems: knowledge,
                    ..Default::default()
                },
            )
        })?;
        let mut refs = BTreeSet::new();
        if let Some(solution) = &generation.solution {
            if solution.refuted
                || solution.checked()?.into_checked_proof().conclusion() != q.proved_target()
            {
                return Err("assessment proof does not establish its intended target".into());
            }
            let (_, _, verified) = search::core::checked(q.proved_target(), &solution.tree)?;
            refs = dependencies(&verified)?;
            meter.write(
                &output.join(format!("{label}-proof-{index}.json")),
                solution,
            )?;
        }
        let cpu = meta::cpu_micros()?.saturating_sub(cpu);
        let wall = wall.elapsed().as_micros();
        let timely = cpu <= 2_500_000 && wall <= 5_000_000;
        rows.push(json!({"cell":cell,"solved":generation.solution.is_some()&&timely,
            "late_checked_solution":generation.solution.is_some()&&!timely,"native_dependencies":refs,
            "terminal":generation.terminal,"diagnostic":generation.diagnostic,"cost":generation.cost,
            "cpu_micros":cpu,"wall_micros":wall}));
        meter.write(&output.join(format!("{label}.json")), &rows)?;
        run::available(meter, io, observer, output)?;
    }
    if digest(state) != before || engine.snapshot(model, io)? != *model {
        return Err("read-only assessment changed a selected State or model/Adam".into());
    }
    Ok(rows)
}

pub(super) fn execute(
    root: &Path,
    design: &design::Design,
    pilot: bool,
    output: &Path,
) -> Result<(), String> {
    if output.exists() {
        return Err("assessment cannot replace an earlier attempt".into());
    }
    std::fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let mut barrier_meter = Meter::start()?;
    let sealed = barrier::read(root, design, pilot, &mut barrier_meter)?;
    let barrier_io = sources::history::Io::journal(MemoryStore::default(), output);
    barrier_meter.check(&barrier_io)?;
    let barrier_cost = barrier_meter.report(&barrier_io);
    write(
        &output.join("barrier.json"),
        &json!({"complete":true,"trajectories":sealed.len(),"cost":barrier_cost,"assessment_model_calls":0}),
    );
    let cases = selected(design, pilot)?;
    let mut higher = cases
        .iter()
        .filter(|c| c["band"] != 0)
        .map(|c| c["case"]["construction"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    higher.truncate(24);
    let probe = cases
        .iter()
        .filter(|c| higher.iter().any(|h| c["case"]["construction"] == *h))
        .cloned()
        .collect::<Vec<_>>();
    let mut results = Vec::new();
    for sealed in sealed {
        let arm_output = output.join(format!(
            "{}-{}",
            sealed.result["seed"],
            sealed.result["arm"].as_str().unwrap()
        ));
        std::fs::create_dir(&arm_output).map_err(|e| e.to_string())?;
        let mut meter = Meter::start()?;
        let mut prior = sealed.cost.clone();
        for (to, from) in [
            ("cpu_micros", "physical_arm_cpu_micros"),
            ("wall_micros", "physical_arm_wall_micros"),
            ("model_io_bytes", "charged_io_bytes"),
        ] {
            prior[to] = json!(
                prior[to]
                    .as_u64()
                    .ok_or("cost absent")?
                    .checked_add(barrier_cost[from].as_u64().ok_or("barrier cost absent")?)
                    .ok_or("cost overflow")?
            );
        }
        meter.common(&prior, &json!({"source_read_bytes":0}))?;
        let mut states = Vec::new();
        let mut store = MemoryStore::default();
        for phase in 0..=PHASES {
            let (state, blobs) =
                meter.import(&sealed.directory.join(format!("phase-{phase}/learning")))?;
            store.0.extend(blobs.0);
            states.push(state);
        }
        let mut io = sources::history::Io::journal(store, &arm_output);
        let mut engine = Engine::default();
        let mut observer = crate::resources::adaptive::Observer::default();
        let mut phases = Vec::new();
        for (phase, state) in states.iter().enumerate() {
            phases.push(json!({"phase":phase,"state_sha256":digest(state),"rows":evaluate(state,&state.model,&state.knowledge,&cases,&mut engine,&mut io,&mut meter,&mut observer,&arm_output,&format!("phase-{phase}"))?}));
        }
        let final_state = &states[PHASES];
        let first_acquired = provenance(&sealed.directory, &mut meter)?;
        let early = early_knowledge(final_state, &first_acquired)?;
        let reduced = without_early(final_state, &early)?;
        let old = evaluate(
            final_state,
            &states[0].model,
            &final_state.knowledge,
            &probe,
            &mut engine,
            &mut io,
            &mut meter,
            &mut observer,
            &arm_output,
            "initial-weights-final-knowledge",
        )?;
        let removed = if early.is_empty() {
            None
        } else {
            Some(evaluate(
                final_state,
                &final_state.model,
                &reduced,
                &probe,
                &mut engine,
                &mut io,
                &mut meter,
                &mut observer,
                &arm_output,
                "removed-early-knowledge",
            )?)
        };
        let dependence = removed.as_ref().map(|rows| {
            rows.iter()
                .filter(|ablation| {
                    let original = phases[PHASES]["rows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|r| r["cell"] == ablation["cell"])
                        .unwrap();
                    original["solved"] == true
                        && ablation["solved"] == false
                        && original["native_dependencies"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|id| early.contains(id.as_str().unwrap()))
                })
                .count()
        });
        run::available(&mut meter, &io, &mut observer, &arm_output)?;
        let result = json!({"complete":true,"seed":sealed.result["seed"],"arm":sealed.result["arm"],"phases":phases,"early_retained_knowledge":early,
            "initial_weights_final_knowledge":old,"removed_early_knowledge":removed,"trajectory_learning_phases":sealed.result["phases"],"learning_cost":sealed.cost,"bounded_cumulative_dependence_cases":dependence,
            "cost":meter.report(&io),"optimizer_updates":0,"feedback_events":0,"inference_only_context_override":true});
        meter.write(&arm_output.join("result.json"), &result)?;
        meter.check(&io)?;
        let mut result = result;
        result["cost"] = meter.report(&io);
        results.push(result);
    }
    let analysis_cpu = meta::cpu_micros()?;
    let analysis_wall = Instant::now();
    let analysis = if pilot {
        Value::Null
    } else {
        analysis::summarize(&results)?
    };
    write(
        &output.join("result.json"),
        &json!({"complete":true,"pilot":pilot,"design":design.identity,"results":results,
        "analysis":analysis,"barrier_cost":barrier_cost,
        "physical_process_overhead":"External terminal process timing remains required; no efficiency qualification from internal counters alone."}),
    );
    let cpu = meta::cpu_micros()?.saturating_sub(analysis_cpu);
    let wall = analysis_wall
        .elapsed()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64;
    let bytes = std::fs::metadata(output.join("result.json"))
        .map_err(|e| e.to_string())?
        .len();
    let mut charged = Vec::new();
    // Shared terminal analysis/serialization is conservatively charged in
    // full to each arm's remaining grant, after every assessment is finished.
    // It cannot affect any learned plan or source-cost label.
    for result in &results {
        let mut meter = Meter::start()?;
        let get = |key: &str| {
            result["cost"][key]
                .as_u64()
                .ok_or("terminal arm cost absent")
        };
        meter.common(&json!({"cpu_micros":get("charged_cpu_micros")?.checked_add(cpu).ok_or("cost overflow")?,
            "wall_micros":get("charged_wall_micros")?.checked_add(wall).ok_or("cost overflow")?,
            "model_io_bytes":get("charged_io_bytes")?.checked_add(bytes).ok_or("cost overflow")?,"archive_written_bytes":0}),&json!({"source_read_bytes":0}))?;
        let io = sources::history::Io::journal(MemoryStore::default(), output);
        meter.check(&io)?;
        charged.push(json!({"seed":result["seed"],"arm":result["arm"],"cost":meter.report(&io)}));
    }
    write(
        &output.join("terminal-cost.json"),
        &json!({"complete":true,"shared_analysis_and_output_cpu_micros":cpu,
        "shared_analysis_and_output_wall_micros":wall,"output_bytes":bytes,"conservatively_charged_arms":charged,
        "external_whole_process_seal_required":true,"complete_physical_sqlite_io_bytes":null}),
    );
    Ok(())
}
