//! A bounded schedule over the current native owners, with no assessment calls.
use super::*;

pub(super) fn execute(
    seed: u64,
    arm: Arm,
    design: &design::Design,
    common: &Path,
    output: &Path,
) -> Result<Value, String> {
    if output.exists() {
        return Err("trajectory would replace an earlier attempt".into());
    }
    std::fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let mut meter = Meter::start()?;
    let (frozen, rechecks) = sources::Frozen::read(common, &design.holdout)?;
    if frozen.epochs.len() != 1 || frozen.initial.model.seed != seed {
        return Err("trajectory common initialization differs".into());
    }
    meter.common(&frozen.cost, &rechecks)?;
    let mut io = sources::history::Io::journal(MemoryStore(frozen.store.0.clone()), output);
    let mut state = frozen.epochs[0].clone();
    let mut graph = crate::Graph::default();
    let mut seen_questions = BTreeSet::new();
    let mut seen_proofs = BTreeSet::new();
    for episode in &frozen.episodes {
        io.append(episode.clone(), frozen.initial.clone())?;
        if let Some(solution) = &episode.solution {
            let q = CompiledQuestion::compile(&episode.observation.question)
                .map_err(|e| e.to_string())?;
            crate::learning::experiment::knowledge::admit_discovery(&mut graph, &q, solution)
                .map_err(|e| e.to_string())?;
            seen_questions.insert(crate::hex(q.resolution_id()));
            seen_proofs.insert(solution.proof_id.clone());
            if let Some(theorem) = solution.theorem(&q)? {
                state.remember_theorem(theorem)?;
            }
        }
    }
    if state.meta.model.updates != 0 || state.meta.model.weights.is_some() {
        return Err("common source already trained a controller".into());
    }
    state.meta.model.seed = seed ^ 0x6d657461;
    let mut engine = Engine::default();
    state.meta.model = engine.meta.snapshot(&state.meta.model, &mut io)?;
    state.compact()?;
    state.validate()?;
    let initial_model = state.model.clone();
    let initial_meta = state.meta.clone();
    let initial_state = digest(&state);
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    std::fs::create_dir(output.join("finder")).map_err(|e| e.to_string())?;
    let mut finder = Frontier::open(&output.join("finder"), &graph, seed, settings)
        .map_err(|e| e.to_string())?;
    finder
        .initial_parameters(seed ^ 0x66696e646572)
        .map_err(|e| e.to_string())?;
    arm.finder(&mut finder);
    let initial_finder = finder.learning_snapshot()["model"].clone();
    finder = checkpoint::save(
        &mut state,
        &mut graph,
        &mut io,
        &mut meter,
        finder,
        output,
        &output.join("phase-0"),
        0,
        arm,
    )?;
    let mut observer = crate::resources::adaptive::Observer::default();
    let mut owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let mut cursor = 0u64;
    let mut job = 48u64;
    let mut phases = Vec::new();
    for phase in 1..=PHASES {
        let path = output.join(format!("phase-{phase}"));
        std::fs::create_dir(&path).map_err(|e| e.to_string())?;
        let mut ledger = lineage::Ledger::new(&design.holdout);
        let mut events = Vec::new();
        let opportunities = if arm == Arm::FrozenWeights { 19 } else { 12 };
        for opportunity in 0..opportunities {
            run::available(&mut meter, &io, &mut observer, output)?;
            finder.feedback(Some(state.feedback()));
            let mut allowed = |q: &CompiledQuestion| {
                State::eligible(q.source())
                    && design.holdout.question(q, None).is_ok()
                    && owner.assess(&graph, q).passed()
            };
            finder
                .refresh(&graph, &mut allowed)
                .map_err(|e| e.to_string())?;
            let mut candidates = finder
                .candidate_page(cursor, &mut allowed)
                .into_iter()
                .take(4)
                .collect::<Vec<_>>();
            for offset in 0..4 {
                let case = &design.bank.acquisition
                    [(cursor as usize * 4 + offset) % design.bank.acquisition.len()];
                let q = CompiledQuestion::compile(&case.source).map_err(|e| e.to_string())?;
                if allowed(&q)
                    && !candidates
                        .iter()
                        .any(|c| c.resolution_id() == q.resolution_id())
                {
                    candidates.push(q);
                }
            }
            cursor += 1;
            let refs = candidates.iter().collect::<Vec<_>>();
            let Some(index) = finder
                .choose(&refs, &graph, settings.solving, false)
                .map_err(|e| e.to_string())?
            else {
                events.push(json!({"opportunity":opportunity,"empty_page":true}));
                continue;
            };
            let q = &candidates[index];
            job += 1;
            let (generation, completion) =
                closed_loop::generate(&state, &mut engine, &mut io, q, job)?;
            finder
                .attempted(
                    q,
                    &graph,
                    &completion,
                    if generation.solution.is_some() {
                        Outcome::Candidate
                    } else {
                        Outcome::NoCandidate
                    },
                )
                .map_err(|e| e.to_string())?;
            let proof_id = generation.solution.as_ref().map(|s| s.proof_id.clone());
            let authored = lineage::normalized_family(q);
            let event = closed_loop::record(
                &mut state,
                &mut graph,
                &mut io,
                &mut meter,
                q,
                generation,
                completion,
                job,
                &authored,
                &mut ledger,
                &design.holdout,
                &mut seen_questions,
                &mut seen_proofs,
                output,
            )?;
            if let Some(id) = proof_id {
                let root = crate::object::proof_address(&id)?;
                finder.prepared(q, job, root).map_err(|e| e.to_string())?;
                finder
                    .verified(q, &graph, job, root)
                    .map_err(|e| e.to_string())?;
            }
            events.push(event);
            meter.write(&path.join("events.json"), &events)?;
            meter.write(&path.join("lineage.json"), &ledger)?;
        }
        job += 1;
        let training = if arm == Arm::FrozenWeights || phase.is_multiple_of(2) {
            json!({"status":"scheduled_no_update","selected_model":state.model})
        } else {
            state.preparation = if arm == Arm::FixedChoices {
                Preparation::Balanced
            } else {
                Preparation::Meta
            };
            let episodes = io.episodes();
            run::train(
                &mut state,
                &mut engine,
                &mut io,
                &mut meter,
                &mut observer,
                &episodes,
                job,
                &path,
            )?
        };
        if arm == Arm::FrozenWeights
            && (state.model != initial_model || digest(&state.meta) != digest(&initial_meta))
        {
            return Err("no-update control changed native or Meta parameters/Adam".into());
        }
        if arm != Arm::Adaptive && finder.learning_snapshot()["model"] != initial_finder {
            return Err("frozen Finder control changed parameters".into());
        }
        finder = checkpoint::save(
            &mut state, &mut graph, &mut io, &mut meter, finder, output, &path, phase, arm,
        )?;
        engine = Engine::default();
        phases.push(json!({"phase":phase,"training":training,"state_sha256":digest(&state),"model":state.model,"cost":meter.report(&io)}));
        meter.write(&output.join("phases.json"), &phases)?;
    }
    run::available(&mut meter, &io, &mut observer, output)?;
    let result = json!({"complete":true,"seed":seed,"arm":arm.name(),"design":design.identity,"phases":phases,
        "initial_state_sha256":initial_state,"initial_model":initial_model,"initial_meta":initial_meta,
        "initial_finder":initial_finder,"bands":design.bands,"assessment_model_calls":0,"cost":meter.report(&io)});
    meter.write(&output.join("result.json"), &result)?;
    meter.check(&io)?;
    meter.write(&output.join("cost-seal.json"), &meter.report(&io))?;
    Ok(result)
}
