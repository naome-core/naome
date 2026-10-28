//! Finder-only development comparison against fixed archived solver responses.
use super::*;
use crate::checkpoint::tests::Directory;
use nix::sys::{
    resource::{UsageWho, getrusage},
    time::TimeValLike,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

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
    resolved: bool,
    millis: u64,
    usable: bool,
}
fn cpu() -> i64 {
    let u = getrusage(UsageWho::RUSAGE_SELF).unwrap();
    u.user_time().num_microseconds() + u.system_time().num_microseconds()
}
fn questions(input: &Inputs) -> Vec<CompiledQuestion> {
    input
        .cases
        .iter()
        .map(|c| CompiledQuestion::compile(&c.source).unwrap())
        .collect()
}

#[test]
#[ignore = "explicit finite finder-only comparison; no solver execution or training"]
fn fixed_solver_finder_comparison() {
    let output = std::path::PathBuf::from(std::env::var("NAOME_FINDER_COMPARISON_OUTPUT").unwrap());
    assert!(!output.exists());
    let input: Inputs =
        serde_json::from_str(include_str!("../../tests/fixtures/finder-feedback.json")).unwrap();
    let all = questions(&input);
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let graph = Graph::default();
    let mut representatives = BTreeMap::new();
    for (q, c) in all.iter().zip(&input.cases) {
        representatives.entry(&c.family).or_insert(q);
    }
    let pool = representatives.values().copied().collect::<Vec<_>>();
    let mut selection = Vec::new();
    for seed in [41, 73, 101] {
        let directory = Directory::new();
        let mut f = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
        for q in pool.iter().take(4) {
            f.focus((*q).clone());
        }
        let start = Instant::now();
        let started = cpu();
        let mut decisions = Vec::new();
        for _ in 0..128 {
            decisions.push(
                f.choose(&pool, &graph, settings.solving, false)
                    .unwrap()
                    .unwrap(),
            );
        }
        selection.push(json!({"seed":seed,"cpu_micros":cpu()-started,"wall_micros":start.elapsed().as_micros(),"decisions":decisions,"pool":pool.iter().map(|q|crate::hex(q.resolution_id())).collect::<Vec<_>>()}));
    }
    let mut pages = Vec::new();
    for regime in ["cold", "relations", "mixed"] {
        let directory = Directory::new();
        let mut f = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
        if regime != "cold" {
            for source in [
                "mem(a,b)",
                "not(mem(a,b))",
                "imp(mem(a,b),eq(a,b))",
                "and(mem(a,b),mem(b,a))",
                "or(mem(a,b),mem(b,a))",
                "imp(mem(a,b),mem(b,a))",
                "imp(eq(a,b),mem(a,b))",
                "iff(mem(a,b),mem(b,a))",
            ] {
                let q = CompiledQuestion::compile(&format!("goal=all(a,all(b,{source}))")).unwrap();
                let mut body = q.formula().clone();
                while let Some(opened) = Frontier::open_outer(&body) {
                    body = opened;
                }
                f.retain_predicate(body);
            }
        }
        if regime == "mixed" {
            for q in all.iter().take(4) {
                f.focus(q.clone());
            }
        }
        let mut owner =
            crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
        let start = Instant::now();
        let started = cpu();
        let mut unique = BTreeSet::new();
        let mut admitted = BTreeSet::new();
        let mut count = 0;
        for cursor in 0..96 {
            for q in f.candidate_page(cursor, |q| owner.assess(&graph, q).passed()) {
                count += 1;
                unique.insert(finder::key(&q));
                if owner.assess(&graph, &q).passed() {
                    admitted.insert(*q.resolution_id());
                }
            }
        }
        pages.push(json!({"regime":regime,"cpu_micros":cpu()-started,"wall_micros":start.elapsed().as_micros(),"candidates":count,"unique_interest_keys":unique.len(),"unique_formal_passes":admitted.len(),"retained_relations":f.predicates.len()}));
    }
    let families = input
        .cases
        .iter()
        .map(|c| c.family.as_str())
        .collect::<BTreeSet<_>>();
    let mut predictions = Vec::new();
    for family in families {
        let mut model = finder::Model::fresh();
        for _ in 0..8 {
            for (q, c) in all
                .iter()
                .zip(&input.cases)
                .filter(|(_, c)| c.family != family)
            {
                for o in c.observations.iter().filter(|o| o.usable) {
                    model.observe(q, o.resolved, o.millis).unwrap();
                }
            }
        }
        for (q, c) in all
            .iter()
            .zip(&input.cases)
            .filter(|(_, c)| c.family == family)
        {
            predictions.push(json!({"family":family,"resolution":crate::hex(q.resolution_id()),"prediction":model.predictions(q),"observations":c.observations.iter().map(|o|json!({"resolved":o.resolved,"millis":o.millis,"usable":o.usable})).collect::<Vec<_>>()}));
        }
    }
    std::fs::write(output,serde_json::to_vec_pretty(&json!({"selection":selection,"pages":pages,"predictions":predictions,"solver_execution_calls":0,"native_proof_policy_training_updates":0})).unwrap()).unwrap();
}
