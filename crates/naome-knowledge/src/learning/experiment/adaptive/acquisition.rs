//! One checked input producer per lower seed. No optimizer runs here.
use super::*;
pub(super) struct FrozenRound {
    pub(super) state: State,
    pub(super) evidence: Vec<Evidence>,
    pub(super) rows: Vec<serde_json::Value>,
}
pub(super) struct Frozen {
    pub(super) rounds: Vec<FrozenRound>,
    pub(super) store: Store,
    pub(super) cost: serde_json::Value,
}
pub(super) fn bind(input: &FrozenRound, previous: &State) -> State {
    let mut state = input.state.clone();
    state.model = previous.model.clone();
    state.meta = previous.meta.clone();
    state.preparation = previous.preparation;
    state.trained = previous.trained;
    state.attempted = previous.attempted;
    state.draws = previous.draws;
    state.promotions = previous.promotions;
    state.rejections = previous.rejections;
    state.feedback = previous.feedback.clone();
    if input.state.feedback.checkpoint == digest(&previous.model) {
        state.feedback.attempts = input.state.feedback.attempts.clone();
        state.feedback.revision = input
            .state
            .feedback
            .revision
            .saturating_add(previous.promotions)
            .saturating_add(previous.rejections);
    }
    state
}
pub(super) fn freeze(seed: u64, common: &Common, rounds: usize, path: &Path) -> Frozen {
    std::fs::create_dir_all(path).unwrap();
    let clock = Clock::start();
    let mut state = common.state.clone();
    let mut store = fork_store(&common.store);
    let mut engine = Engine::default();
    let mut graph = crate::Graph::default();
    for row in &common.rows {
        if !row["solution"].is_null() {
            let solution: Solution = serde_json::from_value(row["solution"].clone()).unwrap();
            let q = CompiledQuestion::compile(row["question"].as_str().unwrap()).unwrap();
            admit_discovery(&mut graph, &q, &solution).unwrap();
        }
    }
    let settings = crate::jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    std::fs::create_dir_all(path.join("frontier")).unwrap();
    let mut frontier = Frontier::open(&path.join("frontier"), &graph, seed, settings).unwrap();
    let mut formal =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let mut all = common.evidence.clone();
    let mut seen = common
        .rows
        .iter()
        .map(|row| {
            let q = CompiledQuestion::compile(row["question"].as_str().unwrap()).unwrap();
            crate::hex(q.resolution_id())
        })
        .collect::<BTreeSet<_>>();
    let mut inputs = Vec::new();
    for round in 0..rounds {
        let mut rows = Vec::new();
        for index in 0..48 {
            if clock.exhausted() {
                panic!("common acquisition exhausted the unchanged arm ceiling");
            }
            frontier.feedback(Some(state.feedback()));
            let mut eligible = |q: &CompiledQuestion| {
                !seen.contains(&crate::hex(q.resolution_id()))
                    && meta_partition(q.source(), false)
                    && State::eligible(q.source())
                    && formal.assess(&graph, q).passed()
            };
            frontier.refresh(&graph, &mut eligible).unwrap();
            let candidates = frontier
                .candidates(round as u64 * 48 + index as u64)
                .into_iter()
                .filter(&mut eligible)
                .collect::<Vec<_>>();
            let references = candidates.iter().collect::<Vec<_>>();
            let Some(selected) = frontier
                .choose(&references, &graph, settings.solving, true)
                .unwrap()
            else {
                panic!("common acquisition lacks a complete question round");
            };
            let q = &candidates[selected];
            let id = crate::hex(q.resolution_id());
            assert!(seen.insert(id.clone()));
            let feedback_before = state.feedback();
            let job = 10_000 + round as u64 * 48 + index as u64;
            let mut row = acquire(
                &mut state,
                q.source(),
                job,
                &mut engine,
                &mut store,
                &mut graph,
                (&mut all, false),
            );
            let solution: Option<Solution> =
                serde_json::from_value(row["solution"].clone()).unwrap();
            let experience: experience::ExperienceSummary =
                serde_json::from_value(row["experience"].clone()).unwrap();
            experience.validate().unwrap();
            let output = crate::jobs::Output::Native {
                terminal: experience.terminal.clone().into(),
                solution: solution.clone(),
                diagnostic: row["diagnostic"].as_str().unwrap().into(),
                frontier: serde_json::from_value(row["frontier"].clone()).unwrap(),
            };
            let completion = crate::jobs::Completion {
                model_checkpoint: Some(experience.checkpoint.clone()),
                id: job,
                binding: crate::jobs::Binding::new([0; 32], [0; 32]),
                spent_ms: experience.spent_ms,
                reserved_units: experience.reserved_units,
                experience: Some(experience),
                state: crate::jobs::State::Complete,
                result: Ok(output),
            };
            frontier
                .attempted(
                    q,
                    &graph,
                    &completion,
                    if solution.is_some() {
                        Outcome::Candidate
                    } else {
                        Outcome::NoCandidate
                    },
                )
                .unwrap();
            if let Some(solution) = &solution {
                let root = crate::object::proof_address(&solution.proof_id).unwrap();
                // The shared acquisition helper already committed the checked
                // artifact; acknowledge that exact candidate through both
                // canonical frontier receipts before selecting more work.
                frontier.prepared(q, job, root).unwrap();
                frontier.verified(q, &graph, job, root).unwrap();
            }
            state.observe_result(
                q.source(),
                solution.is_some(),
                row["diagnostic"].as_str().unwrap(),
                row["elapsed_micros"].as_u64().unwrap(),
                128,
            );
            state.compact().unwrap();
            state.validate().unwrap();
            let case = curriculum::owned::case(q.source()).unwrap();
            row["id"] = serde_json::json!(id);
            row["family"] = serde_json::json!(case.family);
            row["dependency"] = serde_json::json!(case.dependency);
            row["candidate_page"] = serde_json::json!(
                candidates
                    .iter()
                    .map(|q| crate::hex(q.resolution_id()))
                    .collect::<Vec<_>>()
            );
            row["feedback_before"] = serde_json::to_value(feedback_before).unwrap();
            rows.push(row);
            write(
                &path.join(format!("round-{round}-acquisitions.json")),
                &rows,
            );
        }
        write(
            &path.join(format!("round-{round}-acquisitions.json")),
            &rows,
        );

        assert_eq!(rows.len(), 48);
        let mut snapshot = state.clone();
        snapshot
            .compact_with_meta_headroom(outer_metadata_headroom(&snapshot))
            .unwrap();
        snapshot.validate().unwrap();
        assert!(
            snapshot.needs_training(),
            "fixed source must retain original diverse minimum"
        );
        write(&path.join(format!("round-{round}-state.json")), &snapshot);
        write(&path.join(format!("round-{round}-evidence.json")), &all);
        write(
            &path.join(format!("round-{round}-manifest.json")),
            &serde_json::json!({"source_sha256":digest(&(&snapshot.replay,&snapshot.anchors,&all)),
                "model":snapshot.model,"optimizer_updates":0,"queries":rows.len()}),
        );
        inputs.push(FrozenRound {
            state: snapshot,
            evidence: all.clone(),
            rows,
        });
    }
    let cost = clock.elapsed();
    write(&path.join("cost.json"), &cost);
    Frozen {
        rounds: inputs,
        store,
        cost,
    }
}

#[cfg(test)]
mod tests;
