//! Finite current-owner continuation with actual per-execution source states.
//! Controls ablate Solver training or the whole learned Finder policy. Neither
//! a completed run nor a successful promotion establishes indefinite learning.
use super::*;
mod advance;
mod continuation;

const ROUNDS: usize = 3;
const OPPORTUNITIES: usize = 24;

pub(super) fn context(state: &State) -> SolveContext<'_> {
    SolveContext {
        definitions: &state.definitions,
        theorems: &state.knowledge,
        ..Default::default()
    }
}

pub(super) fn generate(
    state: &State,
    engine: &mut Engine,
    io: &mut sources::history::Io<'_>,
    q: &CompiledQuestion,
    job: u64,
) -> Result<(Generation, jobs::Completion), String> {
    let wall = Instant::now();
    let generation = engine.with(&state.model, io, |runtime| {
        solve_with_report(q.source(), runtime, SEARCH, job, context(state))
    })?;
    let completion = completed_search(
        state,
        q,
        job,
        &generation,
        context(state),
        SEARCH,
        wall.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
    );
    Ok((generation, completion))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record(
    state: &mut State,
    graph: &mut crate::Graph,
    io: &mut sources::history::Io<'_>,
    meter: &mut Meter,
    q: &CompiledQuestion,
    generation: Generation,
    completion: jobs::Completion,
    job: u64,
    authored: &str,
    ledger: &mut lineage::Ledger,
    holdout: &lineage::Holdout,
    seen_questions: &mut BTreeSet<String>,
    seen_proofs: &mut BTreeSet<String>,
    path: &Path,
) -> Result<Value, String> {
    let acquisition = state.clone();
    holdout.question(q, Some(authored))?;
    let observation = experience::Observation {
        question: q.source().to_owned(),
        summary: completion
            .experience
            .ok_or("native execution lacks its observation")?,
        frontier: generation.frontier,
        executions: generation.executions,
        knowledge: acquisition.knowledge.clone(),
    };
    let lineage = ledger.original(q, authored, &observation.summary)?;
    let episode = sources::Episode {
        lineage,
        authored_lineage: authored.into(),
        observation,
        solution: generation.solution,
    };
    episode.validate(&acquisition, ledger, holdout)?;
    let mut sampled = false;
    let mut retained_theorem = false;
    let mut new_resolution = false;
    if let Some(solution) = &episode.solution {
        // Match the journal: deterministic graph admission precedes sampling
        // and theorem registration; both are independent of model promotion.
        crate::learning::experiment::knowledge::admit_discovery(graph, q, solution)
            .map_err(|e| e.to_string())?;
        new_resolution = seen_questions.insert(crate::hex(q.resolution_id()));
        if seen_proofs.insert(solution.proof_id.clone()) {
            sampled = state.consider(
                Example {
                    origin: Origin::Local,
                    job,
                    question: q.source().into(),
                    proof_id: solution.proof_id.clone(),
                    refuted: solution.refuted,
                    tree: solution.tree.clone(),
                },
                new_resolution,
            )?;
        }
        if let Some(theorem) = solution.theorem(q)? {
            retained_theorem = state.remember_theorem(theorem)?;
        }
        state.compact()?;
        meter.write(&path.join(format!("accepted-{job}.json")), solution)?;
    }
    state.observe_result(
        q.source(),
        episode.solution.is_some(),
        &generation.diagnostic,
        generation.cost.generation_micros,
        SEARCH as u32,
    );
    // The ordinary journal compacts after recording completion feedback in
    // Disk::save_with. Its growth must be paid before the next source snapshot.
    state.compact()?;
    state.validate()?;
    let row = json!({"job":job,"question":q.source(),"resolution":crate::hex(q.resolution_id()),
        "family":curriculum::owned::family(q.proved_target()),"acquisition_model":acquisition.model,
        "acquisition_state_sha256":digest(&acquisition),"solved":episode.solution.is_some(),
        "proof_id":episode.solution.as_ref().map(|s| &s.proof_id),"new_resolution":new_resolution,
        "accepted_training":sampled,"retained_theorem":retained_theorem,
        "knowledge_entries":state.knowledge.len(),"cost":generation.cost,
        "terminal":generation.terminal,"diagnostic":generation.diagnostic});
    io.append(episode, acquisition)?;
    Ok(row)
}

fn execute(
    seed: u64,
    arm: &str,
    holdout: &lineage::Holdout,
    output: &Path,
) -> Result<Value, String> {
    if output.exists() || !matches!(arm, "joint" | "frozen_solver" | "uniform_finder") {
        return Err("closed-loop output or arm differs".into());
    }
    std::fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let mut meter = Meter::start()?;
    // Every possible authored bootstrap and native qualification input is
    // checked before initialization. Generated candidates cross the same split.
    let mut bootstrap_seen = BTreeSet::new();
    let bootstrap = shuffled_learning(seed)
        .into_iter()
        .filter(|case| State::eligible(&case.source))
        .filter(|case| {
            CompiledQuestion::compile(&case.source)
                .is_ok_and(|q| holdout.question(&q, Some(&case.dependency)).is_ok())
        })
        .filter(|case| {
            CompiledQuestion::compile(&case.source)
                .is_ok_and(|q| bootstrap_seen.insert(crate::hex(q.resolution_id())))
        })
        .take(48)
        .collect::<Vec<_>>();
    if bootstrap.len() != 48 {
        return Err("closed-loop bootstrap lacks 48 eligible sources".into());
    }
    for case in curriculum::development()
        .into_iter()
        .chain(&curriculum::adaptive::BANK.transfer)
    {
        let q = CompiledQuestion::compile(&case.source).map_err(|e| e.to_string())?;
        holdout.question(&q, Some(&case.dependency))?;
    }
    let mut state = State::fresh();
    state.model.seed = seed;
    let mut io = sources::history::Io::journal(MemoryStore::default(), output);
    let mut engine = Engine::default();
    let mut observer = crate::resources::adaptive::Observer::default();
    run::available(&mut meter, &io, &mut observer, output)?;
    state.model = engine.snapshot(&state.model, &mut io)?;
    state.feedback = crate::training::ability::Feedback::fresh(digest(&state.model));
    let initial_model = state.model.clone();
    meter.export(
        &output.join("initial-model"),
        &initial_model,
        &io.store.inner,
    )?;
    let mut graph = crate::Graph::default();
    let mut seen_questions = BTreeSet::new();
    let mut seen_proofs = BTreeSet::new();
    let mut ledger = lineage::Ledger::new(holdout);
    let mut preparation = Vec::new();
    let mut job = 0;
    for case in bootstrap {
        job += 1;
        run::available(&mut meter, &io, &mut observer, output)?;
        let q = CompiledQuestion::compile(&case.source).map_err(|e| e.to_string())?;
        let (generation, completion) = generate(&state, &mut engine, &mut io, &q, job)?;
        preparation.push(record(
            &mut state,
            &mut graph,
            &mut io,
            &mut meter,
            &q,
            generation,
            completion,
            job,
            &case.dependency,
            &mut ledger,
            holdout,
            &mut seen_questions,
            &mut seen_proofs,
            output,
        )?);
        meter.write(&output.join("preparation.json"), &preparation)?;
    }
    meter.write(&output.join("bootstrap-lineage.json"), &ledger)?;
    meter.write(&output.join("prepared-state.json"), &state)?;
    let common_questions = seen_questions.clone();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let directory = output.join("finder");
    std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let mut finder =
        Frontier::open(&directory, &graph, seed, settings).map_err(|e| e.to_string())?;
    let treatment = if arm == "uniform_finder" {
        Treatment::Uniform
    } else {
        Treatment::Full
    };
    finder.treatment(treatment);
    let initial_finder = finder.learning_snapshot();
    let initial = run::evaluate(
        &state,
        &mut engine,
        &mut io,
        &mut meter,
        &mut observer,
        output,
        "initial",
        holdout,
    )?;
    let mut progress = advance::Progress {
        questions: seen_questions,
        proofs: seen_proofs,
        cursor: 0,
        job,
        rounds: Vec::new(),
        finder: initial_finder.clone(),
    };
    let outcome = advance::advance(
        &mut state,
        &mut graph,
        &mut io,
        &mut engine,
        &mut meter,
        &mut observer,
        finder,
        holdout,
        &mut progress,
        output,
        arm,
        (ROUNDS, OPPORTUNITIES),
    );
    // The actual runtime export also detects accidental frozen-control updates.
    let actual = engine.snapshot(&state.model, &mut io)?;
    if actual != state.model || arm == "frozen_solver" && actual != initial_model {
        return Err("closed-loop actual selected weights or Adam differ".into());
    }
    if outcome.is_ok() {
        meter.checkpoint(&output.join("final-checkpoint"), &mut state, &mut io)?;
    }
    let result = json!({"seed":seed,"arm":arm,"complete":outcome.is_ok(),"error":outcome.as_ref().err(),
        "initial_model":initial_model,"final_model":actual,"initial_finder":initial_finder,
        "final_finder":progress.finder,"initial_evaluation":initial,"preparation":preparation,
        "common_resolutions":common_questions,"rounds":progress.rounds,"knowledge_entries":state.knowledge.len(),
        "cost":meter.report(&io),"independent_confirmation_calls":0});
    meter.write(&output.join("final-state.json"), &state)?;
    meter.write(&output.join("result.json"), &result)?;
    let bounded = meter.check(&io);
    meter.write(
        &output.join("cost-seal.json"),
        &json!({"complete":outcome.is_ok() && bounded.is_ok(),
        "cost":meter.report(&io),"seal_write_is_reporting_overhead":true}),
    )?;
    outcome?;
    bounded?;
    Ok(result)
}

#[test]
#[ignore = "finite current-owner closed-loop comparison; requires explicit frozen protocol"]
fn matched_current_owner_continuation() {
    let bank = std::fs::read(std::env::var("NAOME_FINDER_CONFIRMATION_INPUTS").unwrap()).unwrap();
    let holdout = lineage::Holdout::read(
        &bank,
        &std::env::var("NAOME_EXPERIENCE_HOLDOUT_SHA256").unwrap(),
    )
    .unwrap();
    let output = std::path::PathBuf::from(std::env::var("NAOME_JOINT_OUTPUT").unwrap());
    let seed = std::env::var("NAOME_JOINT_SEED").unwrap().parse().unwrap();
    let arm = std::env::var("NAOME_JOINT_ARM").unwrap();
    let result = execute(seed, &arm, &holdout, &output);
    if let Err(error) = &result {
        write(
            &output.join("interrupted.json"),
            &json!({"error":error,"partial_resume":false}),
        );
    }
    result.unwrap();
}

#[cfg(test)]
mod tests;
