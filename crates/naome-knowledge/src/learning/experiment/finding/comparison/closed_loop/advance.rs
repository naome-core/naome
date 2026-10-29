//! The same bounded execution path serves fresh and actual warm starts.
use super::*;

pub(super) struct Progress {
    pub questions: BTreeSet<String>,
    pub proofs: BTreeSet<String>,
    pub cursor: u64,
    pub job: u64,
    pub rounds: Vec<Value>,
    pub finder: Value,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn advance(
    state: &mut State,
    graph: &mut crate::Graph,
    io: &mut sources::history::Io<'_>,
    engine: &mut Engine,
    meter: &mut Meter,
    observer: &mut crate::resources::adaptive::Observer,
    mut finder: Frontier,
    holdout: &lineage::Holdout,
    progress: &mut Progress,
    output: &Path,
    arm: &str,
    schedule: (usize, usize),
) -> Result<(), String> {
    let seed = state.model.seed;
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let treatment = if arm == "uniform_finder" {
        Treatment::Uniform
    } else {
        Treatment::Full
    };
    finder.treatment(treatment);
    let directory = output.join("finder");
    let Progress {
        questions: seen_questions,
        proofs: seen_proofs,
        cursor,
        job,
        rounds,
        finder: final_finder,
    } = progress;
    let mut owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    for round in 0..schedule.0 {
        let mut ledger = lineage::Ledger::new(holdout);
        let round_path = output.join(format!("round-{round}"));
        std::fs::create_dir_all(&round_path).map_err(|e| e.to_string())?;
        let mut events = Vec::new();
        for opportunity in 0..schedule.1 {
            run::available(meter, io, observer, output)?;
            finder.feedback(Some(state.feedback()));
            finder
                .refresh(graph, |q| {
                    State::eligible(q.source())
                        && holdout.question(q, None).is_ok()
                        && owner.assess(graph, q).passed()
                })
                .map_err(|e| e.to_string())?;
            let candidates = finder.candidate_page(*cursor, |q| {
                State::eligible(q.source())
                    && holdout.question(q, None).is_ok()
                    && owner.assess(graph, q).passed()
            });
            *cursor += 1;
            let refs = candidates.iter().collect::<Vec<_>>();
            let Some(index) = finder
                .choose(&refs, graph, settings.solving, false)
                .map_err(|e| e.to_string())?
            else {
                events.push(json!({"opportunity":opportunity,"empty_page":true}));
                continue;
            };
            let q = &candidates[index];
            *job += 1;
            let (generation, completion) = generate(state, engine, io, q, *job)?;
            finder
                .attempted(
                    q,
                    graph,
                    &completion,
                    if generation.solution.is_some() {
                        Outcome::Candidate
                    } else {
                        Outcome::NoCandidate
                    },
                )
                .map_err(|e| e.to_string())?;
            let proof_id = generation.solution.as_ref().map(|s| s.proof_id.clone());
            let authored = format!("generated:{}", curriculum::owned::family(q.proved_target()));
            let mut event = record(
                state,
                graph,
                io,
                meter,
                q,
                generation,
                completion,
                *job,
                &authored,
                &mut ledger,
                holdout,
                seen_questions,
                seen_proofs,
                output,
            )?;
            if let Some(id) = proof_id {
                let root = crate::object::proof_address(&id)?;
                finder.prepared(q, *job, root).map_err(|e| e.to_string())?;
                finder
                    .verified(q, graph, *job, root)
                    .map_err(|e| e.to_string())?;
            }
            event["cumulative_cost"] = meter.report(io);
            events.push(event);
            meter.write(&round_path.join("events.json"), &events)?;
            meter.write(&round_path.join("lineage.json"), &ledger)?;
            run::available(meter, io, observer, output)?;
        }
        *job += 1;
        let episodes = io.episodes();
        let training = if arm == "frozen_solver" {
            json!({"status":"frozen_solver","retained_update":false,"selected_model":state.model})
        } else {
            run::train(
                state,
                engine,
                io,
                meter,
                observer,
                &episodes,
                *job,
                &round_path,
            )?
        };
        let evaluation = run::evaluate(
            state,
            engine,
            io,
            meter,
            observer,
            &round_path,
            "selected",
            holdout,
        )?;
        let before_reopen = finder.learning_snapshot();
        drop(finder);
        finder = Frontier::open(&directory, graph, seed, settings).map_err(|e| e.to_string())?;
        finder.treatment(treatment);
        if finder.learning_snapshot() != before_reopen {
            return Err("closed-loop Finder model or learning state changed on reopen".into());
        }
        *final_finder = finder.learning_snapshot();
        state.validate()?;
        meter.export(
            &round_path.join("selected-model"),
            &state.model,
            &io.store.inner,
        )?;
        meter.write(&round_path.join("selected-state.json"), state)?;
        meter.checkpoint(&round_path.join("selected-checkpoint"), state, io)?;
        *engine = Engine::default();
        meter.write(&round_path.join("history-pages.json"), &io.pages)?;
        rounds.push(json!({"round":round,"events":events,"training":training,
                "evaluation":evaluation,"model":state.model,"finder_learning":finder.learning_snapshot(),
                "feedback":state.feedback(),"cost":meter.report(io)}));
        meter.write(&output.join("rounds.json"), &rounds)?;
        eprintln!(
            "closed loop seed {seed} {arm} round {}: actual updates={}, knowledge={}",
            round + 1,
            state.model.updates,
            state.knowledge.len()
        );
    }
    Ok(())
}
