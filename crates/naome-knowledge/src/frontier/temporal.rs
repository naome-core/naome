//! Known fixed-outcome temporal comparison; no solver training or execution.
use super::*;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
struct Inputs {
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    source: String,
    family: String,
    observations: Vec<Observation>,
}
#[derive(Deserialize)]
struct Observation {
    seed: u64,
    resolved: bool,
    millis: u64,
    usable: bool,
}

#[test]
#[ignore = "explicit finite chronological finder comparison; no native solver execution"]
fn family_held_out_temporal_comparison() {
    let output = std::path::PathBuf::from(std::env::var("NAOME_FINDER_TEMPORAL_OUTPUT").unwrap());
    assert!(!output.exists());
    let input: Inputs =
        serde_json::from_str(include_str!("../../tests/fixtures/finder-feedback.json")).unwrap();
    let questions = input
        .cases
        .iter()
        .map(|c| CompiledQuestion::compile(&c.source).unwrap())
        .collect::<Vec<_>>();
    let families = input
        .cases
        .iter()
        .map(|c| c.family.clone())
        .collect::<BTreeSet<_>>();
    let mut rows = Vec::new();
    for seed in [41, 73, 101] {
        let checkpoint = crate::learning::digest(&(seed, "bce55366-fixed-solver"));
        for held in &families {
            let mut groups = BTreeMap::new();
            for (index, case) in input
                .cases
                .iter()
                .enumerate()
                .filter(|(_, c)| &c.family != held)
            {
                groups
                    .entry(case.family.clone())
                    .or_insert_with(Vec::new)
                    .push(index);
            }
            let mut order = groups.keys().cloned().collect::<Vec<_>>();
            let mut random = Random::new(seed);
            for i in (1..order.len()).rev() {
                let j = random.below((i + 1) as u64) as usize;
                order.swap(i, j);
            }
            for treatment in [
                Treatment::Previous,
                Treatment::FamilyReplay,
                Treatment::OutcomeReplay,
                Treatment::Full,
            ] {
                let mut model = finder::Model::fresh();
                let mut memory = finder::Learning::fresh(checkpoint.clone());
                memory.treatment = treatment;
                let mut seen = BTreeSet::new();
                for round in 0..6 {
                    for offset in 0..2 {
                        let family = &order[(round * 2 + offset) % order.len()];
                        seen.insert(family.clone());
                        for index in &groups[family] {
                            let observation = input.cases[*index]
                                .observations
                                .iter()
                                .find(|o| o.seed == seed)
                                .unwrap();
                            if !observation.usable {
                                continue;
                            }
                            let q = &questions[*index];
                            memory
                                .observe(&mut model, q, observation.resolved, observation.millis)
                                .unwrap();
                            memory
                                .remember(
                                    &mut model,
                                    q,
                                    Some(&checkpoint),
                                    observation.resolved,
                                    observation.millis,
                                    round as u64 + 1,
                                )
                                .unwrap();
                        }
                    }
                    let mut predictions = Vec::new();
                    for (index, case) in input
                        .cases
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| &c.family == held || seen.contains(&c.family))
                    {
                        let observation =
                            case.observations.iter().find(|o| o.seed == seed).unwrap();
                        if !observation.usable {
                            continue;
                        }
                        predictions.push(json!({"resolution":crate::hex(questions[index].resolution_id()),"family":case.family,"held_out":&case.family==held,"prediction":model.predictions(&questions[index]),"resolved":observation.resolved,"millis":observation.millis,"weight":model.weight(&questions[index])}));
                    }
                    rows.push(json!({"seed":seed,"held_out_family":held,"arm":match treatment{Treatment::Full=>"rehearsal",Treatment::FamilyReplay=>"family_replay",Treatment::OutcomeReplay=>"outcome_replay",_=>"previous"},"round":round+1,"fresh_observations":model.updates,"rehearsals":model.rehearsals,"predictions":predictions}));
                }
            }
        }
    }
    let result = json!({"scope":"Known development archive, chronological family exposure and leave-one-whole-family-out evaluation. Original native solver seeds stay separate. No gradient utility labels are available in this archive; this experiment isolates rehearsal, not generation or solver learning.","seeds":[41,73,101],"rounds":6,"native_solver_calls":0,"native_weight_updates":0,"rows":rows});
    std::fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
}
