//! Preregistered, aggregate-budget native comparison. Never run by ordinary CI.
use super::knowledge::{Store, admit_discovery};
use super::*;
use serde_json::{Value, json};
mod adjudicate;
mod budget;
mod inputs;
mod run;
mod sequential;
use budget::{EXPANSIONS, Meter, SLICE};
use inputs::Inputs;

#[test]
#[ignore = "explicit finite five-arm recursive lemma experiment"]
fn matched_recursive_lemma_loop() {
    let path = std::path::PathBuf::from(
        std::env::var("NAOME_LEMMA_LOOP_OUTPUT").expect("explicit output directory"),
    );
    let input_path = std::path::PathBuf::from(
        std::env::var("NAOME_LEMMA_LOOP_INPUTS").expect("frozen question input list"),
    );
    assert!(
        !path.join("results.json").exists(),
        "preserve earlier attempts in separate output directories"
    );
    std::fs::create_dir_all(&path).unwrap();
    let raw = std::fs::read(&input_path).unwrap();
    let input: Inputs = serde_json::from_slice(&raw).unwrap();
    assert_eq!(input.model_seeds, [41, 73, 101, 137, 211]);
    assert_eq!(input.cases.len(), 24);
    let questions = input
        .cases
        .iter()
        .map(|c| CompiledQuestion::compile(&c.source).unwrap())
        .collect::<Vec<_>>();
    let gate_graph = crate::Graph::default();
    let mut gate_owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let gates = questions
        .iter()
        .map(|q| {
            let gate = gate_owner.assess(&gate_graph, q);
            json!({"passed":gate.passed(),"rule":gate.rule,"reason":format!("{:?}",gate.reason)})
        })
        .collect::<Vec<_>>();
    let manifest = json!({"input_sha256":crate::hex(&Sha256::digest(&raw)),"questions":questions.iter().enumerate().map(|(i,q)|json!({"source":q.source(),"resolution_id":crate::hex(q.resolution_id()),"family":input.cases[i].family,"shape":input.cases[i].shape,"eligible":State::eligible(q.source()),"initial_admission":gates[i]})).collect::<Vec<_>>(),"model_seeds":input.model_seeds,"arms":run::ARMS,"aggregate_limits":budget::limits(),"shared_live_resource_limits":format!("{:?}",crate::resources::active_limits()),"job_seeds":{"initial":1,"helpers_start":10,"retry":100,"multi_restart":[1,100,101,102]},"first_slice":SLICE,"helper_slice":SLICE,"max_helpers":4,"max_depth":2,"stopping_rule":"one pass over the frozen cases and seeds, no replacement or parameter search","primary_criterion":"recursive checked wins minus losses against the union of direct/restart/multi-restart; helper-assisted successes audited at identical remaining total budget","controls":"All arms use the same native model and independently checked calculus. Flat retains the one-level scheduler. Current recursive planning exposes exact conjunction leaves before a composite neural attempt and composes temporary complete canonical prerequisites within existing caps. The separate test-only recursive control freezes the 441531bc scheduler.","limitations":"Six grouped synthetic families; five fresh checkpoints, no lower weight training or cross-question knowledge transfer; in-process owner cycle rather than a physical distributed deployment"});
    write(&path.join("frozen-manifest.json"), &manifest);
    let mut rows = Vec::new();
    for (seed_index, &seed) in input.model_seeds.iter().enumerate() {
        let seed_path = path.join(seed.to_string());
        let (common, common_io) = inputs::checkpoint(seed, &seed_path.join("common-model"));
        for (index, q) in questions.iter().enumerate() {
            let id = crate::hex(q.resolution_id());
            let case = &input.cases[index];
            if !State::eligible(q.source()) || gates[index]["passed"] != true {
                rows.push(json!({"id":id,"seed":seed,"family":case.family,"shape":case.shape,"excluded":"protected split or initial formal admission","admission":gates[index]}));
                write(&path.join("results.json"), &rows);
                continue;
            }
            let case_path = seed_path.join(&id);
            let mut results = BTreeMap::new();
            for offset in 0..run::ARMS.len() {
                let kind = run::ARMS[(index + seed_index + offset) % run::ARMS.len()];
                let result = run::arm(q, kind, seed, &common, &common_io, &case_path.join(kind));
                assert_eq!(result["initial_model"], result["final_model"]);
                assert_eq!(result["retained_weight_updates"], 0);
                results.insert(kind, result);
            }
            let mut removals = BTreeMap::new();
            for kind in ["flat_loop", "recursive_loop"] {
                let candidate = &results[kind];
                if candidate["counted_solution"] == true
                    && !candidate["used_helpers"].as_array().unwrap().is_empty()
                {
                    removals.insert(
                        kind,
                        run::removal(
                            q,
                            candidate,
                            &common,
                            &common_io,
                            &case_path.join(format!("{kind}-removal")),
                        ),
                    );
                }
            }
            let controls = ["direct", "restart", "multi_restart"]
                .iter()
                .any(|k| results[k]["counted_solution"] == true);
            let recursive = results["recursive_loop"]["counted_solution"] == true;
            let win = recursive && !controls;
            let loss = !recursive && controls;
            let gain = win
                && removals
                    .get("recursive_loop")
                    .is_some_and(|r| r["counted_solution"] == false);
            let row = json!({"id":id,"seed":seed,"family":case.family,"shape":case.shape,"question":q.source(),"arms":results,"helper_removal":removals,"additional_win":win,"control_loss":loss,"qualifying_gain":gain});
            rows.push(row);
            write(&path.join("results.json"), &rows);
            eprintln!(
                "{}",
                json!({"event":"matched_recursive_goal","seed":seed,"case":index+1,"id":id,"win":win,"loss":loss,"qualifying_gain":gain})
            );
        }
    }
    let eligible = rows.iter().filter(|r| r.get("arms").is_some()).count();
    let wins = rows.iter().filter(|r| r["additional_win"] == true).count();
    let losses = rows.iter().filter(|r| r["control_loss"] == true).count();
    let gains = rows.iter().filter(|r| r["qualifying_gain"] == true).count();
    let counts = run::ARMS
        .iter()
        .map(|k| {
            (
                *k,
                rows.iter()
                    .filter(|r| r["arms"][k]["counted_solution"] == true)
                    .count(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let summary = json!({"frozen_questions":questions.len(),"model_seeds":input.model_seeds,"planned_pairs":questions.len()*input.model_seeds.len(),"eligible_pairs":eligible,"counted_by_arm":counts,"additional_wins":wins,"control_losses":losses,"net_wins":wins as i64-losses as i64,"qualifying_gains":gains,"rows":rows,"claim":if gains>losses {"bounded paired helper gain on the reported grouped inputs only"}else{"no net qualifying helper gain measured"}});
    write(&path.join("summary.json"), &summary);
    eprintln!(
        "{}",
        json!({"event":"matched_recursive_complete","eligible_pairs":eligible,"counts":counts,"wins":wins,"losses":losses,"gains":gains})
    );
}

#[cfg(test)]
mod tests;
