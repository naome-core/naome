//! Paired comparisons of rank order inside a single native tableau search.
//!
//! Run the ignored developer-tools test with a frozen input and a model export
//! from the current specification. A ranked callback is the switch boundary;
//! the validated trace supplies the actual paid prefix expansions. The
//! positive tableau orientation is held constant across all arms.
use super::*;
use crate::learning::model::{Decision, Memory, Plan, Ranker, Rule};
use crate::resources::adaptive::{Budget, Observer};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum FixedOrder {
    Native,
    RulePriority,
}

impl Ranker for FixedOrder {
    fn scores(&mut self, decision: &Decision) -> Result<Vec<f32>, crate::Error> {
        let mut scores = match self {
            Self::Native => vec![0.; decision.candidates.len()],
            Self::RulePriority => decision
                .candidates
                .iter()
                .map(|candidate| match candidate.rule {
                    Rule::DoubleNegation => 7.,
                    Rule::NegatedImplication => 6.,
                    Rule::ModusPonens => 5.,
                    Rule::UniversalInstance => 4.,
                    Rule::EqualitySubstitution => 3.,
                    Rule::ExistentialWitness => 2.,
                    Rule::ImplicationBranch => 1.,
                    _ => 0.,
                })
                .collect(),
        };
        if matches!(self, Self::Native) {
            search::focus::rank(decision, &mut scores);
        }
        Ok(scores)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RankedMenu {
    state: String,
    offered: String,
    memory: Option<String>,
    learned: Vec<u32>,
    applied: Vec<u32>,
}

struct Continuation<'a> {
    learned: Exploring<'a>,
    fixed: Option<FixedOrder>,
    switch_after: usize,
    calls: usize,
    prefix: Vec<RankedMenu>,
    fixed_identity: String,
    plan_cpu_micros: u64,
}

impl Ranker for Continuation<'_> {
    fn scores(&mut self, decision: &Decision) -> Result<Vec<f32>, crate::Error> {
        self.learned.scores(decision)
    }

    fn identity(&self) -> Option<String> {
        if self.fixed.is_some() && self.calls >= self.switch_after {
            // Do not reuse the failed-state cache of a different ordering.
            Some(self.fixed_identity.clone())
        } else {
            self.learned.identity()
        }
    }

    fn plan(
        &mut self,
        decision: &Decision,
        graph: &graph::Graph,
        offered: &str,
        memory: Option<&Memory>,
    ) -> Result<Plan, crate::Error> {
        let started = meta::cpu_micros()?;
        let mut plan = self.learned.plan(decision, graph, offered, memory)?;
        self.plan_cpu_micros += meta::cpu_micros()?.saturating_sub(started);
        let bits = |values: &[f32]| values.iter().map(|value| value.to_bits()).collect();
        let record = self.calls <= self.switch_after;
        let learned = record.then(|| bits(&plan.scores));
        if let Some(mut fixed) = self.fixed.filter(|_| self.calls >= self.switch_after) {
            // Change ordering only. The native Plan still computes successor
            // memory for the action actually taken from this menu.
            plan.scores = fixed.scores(decision)?;
        }
        if let Some(learned) = learned {
            self.prefix.push(RankedMenu {
                state: graph.binding.clone(),
                offered: offered.to_owned(),
                memory: memory.map(digest),
                learned,
                applied: bits(&plan.scores),
            });
        }
        self.calls += 1;
        Ok(plan)
    }
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
struct Executed {
    state: String,
    offered: String,
    selected: usize,
    parent: Option<Parent>,
    start: usize,
    ranks: Option<Vec<u32>>,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
struct Parent {
    event: usize,
    child: usize,
}

#[derive(Deserialize)]
struct Execution {
    events: Vec<Executed>,
}

fn events(
    question: &ResearchQuestion,
    trace: Option<&SearchTrace>,
) -> Result<Vec<Executed>, String> {
    let Some(trace) = trace else {
        return Ok(Vec::new());
    };
    trace.validate_context(question, &[])?;
    let trace = serde_json::to_value(trace).map_err(|error| error.to_string())?;
    let view: Execution = serde_json::from_value(trace).map_err(|error| error.to_string())?;
    Ok(view.events)
}

fn boundary(menus: &[RankedMenu], events: &[Executed]) -> Option<usize> {
    let mut next = 0;
    for menu in menus {
        let selected = menu
            .applied
            .iter()
            .enumerate()
            .max_by(|(a, x), (b, y)| {
                f32::from_bits(**x)
                    .total_cmp(&f32::from_bits(**y))
                    .then(b.cmp(a))
            })?
            .0;
        let index = events.get(next..)?.iter().position(|event| {
            event.state == menu.state
                && event.offered == menu.offered
                && event.selected == selected
                && event.ranks.as_ref() == (menu.applied.len() > 1).then_some(&menu.applied)
        })?;
        next += index + 1;
    }
    next.checked_sub(1)
}

#[derive(Serialize)]
struct Prefix {
    expansions: usize,
    state: String,
    offered: String,
    memory: Option<String>,
    learned_choice: usize,
    fixed_choice: usize,
}

fn matched_prefix(learned: &Run, switched: &Run, after: usize) -> Option<Prefix> {
    let (left, right) = (&learned.prefix, &switched.prefix);
    if left.get(..after)? != right.get(..after)? {
        return None;
    }
    let (a, b) = (left.get(after)?, right.get(after)?);
    if a.state != b.state
        || a.offered != b.offered
        || a.memory != b.memory
        || a.learned != b.learned
    {
        return None;
    }
    let start = boundary(left, &learned.events)?;
    if start != boundary(right, &switched.events)?
        || learned.events[..start] != switched.events[..start]
        || learned.events[start].start != switched.events[start].start
        || learned.events[start].parent != switched.events[start].parent
    {
        return None;
    }
    Some(Prefix {
        expansions: learned.events[start].start,
        state: a.state.clone(),
        offered: a.offered.clone(),
        memory: a.memory.clone(),
        learned_choice: learned.events[start].selected,
        fixed_choice: switched.events[start].selected,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Protocol {
    search_limit: usize,
    switch_after: usize,
    combined_limit: usize,
    fixed: FixedOrder,
    cases: Vec<Source>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Split {
    Protected,
    Acquisition,
    Held,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    question: String,
    lineage: String,
    split: Split,
    seed: u64,
    expected_proof: Option<String>,
}

impl Protocol {
    fn validate(&self) -> Result<Vec<ResearchQuestion>, String> {
        if self.search_limit == 0
            || self.search_limit > 128
            || self.switch_after >= self.search_limit
            || self.combined_limit <= self.search_limit
            || self.combined_limit > 200_000
            || self.cases.is_empty()
        {
            return Err("invalid continuation evaluation limits".into());
        }
        let mut splits = BTreeMap::new();
        let mut distinct = BTreeSet::new();
        let mut questions = Vec::new();
        for case in &self.cases {
            let question = ResearchQuestion::from_hex(&case.question).map_err(|e| e.to_string())?;
            if case.lineage.is_empty()
                || question.to_hex() != case.question
                || !distinct.insert((*question.resolution_id(), case.seed))
                || (case.split == Split::Protected) != case.expected_proof.is_some()
            {
                return Err("invalid continuation evaluation source".into());
            }
            if let Some(id) = &case.expected_proof {
                crate::object::id_bytes(id)?;
            }
            for key in [
                (0, case.lineage.clone()),
                (1, curriculum::owned::family(question.proved_target())),
                (2, crate::hex(question.resolution_id())),
            ] {
                if splits
                    .insert(key, case.split)
                    .is_some_and(|old| old != case.split)
                {
                    return Err("continuation evaluation splits share a source family".into());
                }
            }
            questions.push(question);
        }
        if self.cases.iter().any(|case| case.split == Split::Held)
            && !self.cases.iter().any(|case| case.split == Split::Protected)
        {
            return Err("held continuation evaluation requires protected proof identities".into());
        }
        Ok(questions)
    }
}

#[derive(Serialize)]
struct Run {
    proof: Option<String>,
    expansions: usize,
    terminal: experience::TerminalEvidence,
    search_cpu_micros: u64,
    search_wall_micros: u128,
    native_plan_calls: usize,
    native_plan_cpu_micros: u64,
    checker_steps: usize,
    checker_cpu_micros: u64,
    checker_wall_micros: u128,
    check_error: Option<String>,
    events: Vec<Executed>,
    #[serde(skip)]
    prefix: Vec<RankedMenu>,
}

fn independent_check(
    question: &ResearchQuestion,
    tree: &search::Tree,
    path: &Path,
    budget: &Budget,
    maximum: usize,
    charged: &mut usize,
) -> Result<String, String> {
    let target = question.proved_target();
    let packet = search::compile(target, tree)
        .and_then(|(term, _)| proof::recipe(&term, target))
        .and_then(|recipe| construction::program_from_recipe(target, recipe))?
        .packet;
    let mut work = crate::proof_work::Work::open(path).map_err(|e| e.to_string())?;
    for group in packet
        .commands()?
        .chunks(naome_proof::program::CHUNK_RECORDS)
    {
        work.append_group(group).map_err(|e| e.to_string())?;
    }
    let context = naome_checker::ArtifactState::new();
    let mut budget = budget.clone();
    loop {
        budget.batch_steps = budget.batch_steps.min(maximum.saturating_sub(*charged));
        if budget.batch_steps == 0 {
            return Err("continuation checker work limit".into());
        }
        let more = work.advance(&budget, &context).map_err(|e| e.to_string())?;
        *charged += work.last_quantum_steps();
        if *charged > maximum {
            return Err("continuation checker work limit".into());
        }
        if !more {
            break;
        }
    }
    while !work.prepare_export(&budget).map_err(|e| e.to_string())? {}
    let checked = work.into_checked().map_err(|e| e.to_string())?;
    let proof = checked.proof().map_err(|e| e.to_string())?;
    if proof.manifest() != &packet.manifest || proof.conclusion() != Some(target) {
        return Err("continuation checker returned a different proof".into());
    }
    Ok(crate::hex(proof.manifest().proof_id().as_bytes()))
}

#[derive(Clone, Copy)]
enum Arm {
    Learned,
    Fixed(FixedOrder),
    Switch,
}

fn run(
    question: &ResearchQuestion,
    seed: u64,
    arm: Arm,
    protocol: &Protocol,
    runtime: &mut model::Runtime,
    budget: &Budget,
    path: &Path,
) -> Result<Run, String> {
    let started = Instant::now();
    let before = meta::cpu_micros()?;
    let fixed = matches!(arm, Arm::Switch).then_some(protocol.fixed);
    let fixed_identity = digest(&("continuation fixed order", runtime.identity(), fixed));
    let mut controller = Continuation {
        learned: Exploring {
            model: runtime,
            seed: seed.max(1),
            explore: false,
        },
        fixed,
        switch_after: protocol.switch_after,
        calls: 0,
        prefix: Vec::new(),
        fixed_identity,
        plan_cpu_micros: 0,
    };
    let found = match arm {
        Arm::Fixed(mut fixed) => {
            search::solve(question.proved_target(), &mut fixed, protocol.search_limit)
        }
        _ => search::solve(
            question.proved_target(),
            &mut controller,
            protocol.search_limit,
        ),
    }?;
    let search_cpu_micros = meta::cpu_micros()?.saturating_sub(before);
    let search_wall_micros = started.elapsed().as_micros();
    if found.expansions > protocol.search_limit {
        return Err("continuation search exceeded its expansion grant".into());
    }
    let events = events(question, found.execution.as_ref())?;
    let started = Instant::now();
    let before = meta::cpu_micros()?;
    let mut checker_steps = 0;
    let (proof, check_error) = match found.tree.as_ref().map(|tree| {
        independent_check(
            question,
            tree,
            path,
            budget,
            protocol.combined_limit - found.expansions,
            &mut checker_steps,
        )
    }) {
        Some(Ok(proof)) => (Some(proof), None),
        Some(Err(error)) => (None, Some(error)),
        None => (None, None),
    };
    Ok(Run {
        proof,
        expansions: found.expansions,
        terminal: found.terminal,
        search_cpu_micros,
        search_wall_micros,
        native_plan_calls: controller.calls,
        native_plan_cpu_micros: controller.plan_cpu_micros,
        checker_steps,
        checker_cpu_micros: meta::cpu_micros()?.saturating_sub(before),
        checker_wall_micros: started.elapsed().as_micros(),
        check_error,
        events,
        prefix: controller.prefix,
    })
}

#[test]
#[ignore = "bounded native continuation comparison; set NAOME_CONTINUATION_INPUT, NAOME_CONTINUATION_MODEL and NAOME_CONTINUATION_OUTPUT"]
fn evaluate_native_continuation() {
    let input = std::path::PathBuf::from(std::env::var_os("NAOME_CONTINUATION_INPUT").unwrap());
    let model = std::path::PathBuf::from(std::env::var_os("NAOME_CONTINUATION_MODEL").unwrap());
    let output = std::path::PathBuf::from(std::env::var_os("NAOME_CONTINUATION_OUTPUT").unwrap());
    use std::io::Read;
    let mut bytes = Vec::new();
    let input_limit = crate::resources::limits().closure_bytes;
    std::fs::File::open(input)
        .unwrap()
        .take(input_limit as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes.len() <= input_limit,
        "continuation input exceeds its byte limit"
    );
    let protocol: Protocol = serde_json::from_slice(&bytes).unwrap();
    let questions = protocol.validate().unwrap();
    let (checkpoint, mut store) = import_model(&model).unwrap();
    let mut engine = Engine::default();
    let mut observer = Observer::default();
    std::fs::create_dir(&output).unwrap();
    write(
        &output.join("manifest.json"),
        &json!({"input_sha256":crate::hex(&Sha256::digest(&bytes)), "checkpoint":digest(&checkpoint),
            "specification":input_specification(),"search_limit":protocol.search_limit,
            "combined_limit":protocol.combined_limit,"fixed":protocol.fixed,"switch_after":protocol.switch_after,
            "exploration":false,"scope":"positive native tableau",
            "initial_resources":observer.refresh(&output).unwrap()}),
    );
    let mut protected = true;
    for split in [Split::Protected, Split::Acquisition, Split::Held] {
        if split != Split::Protected && !protected {
            break;
        }
        for (index, (case, question)) in protocol.cases.iter().zip(&questions).enumerate() {
            if case.split != split {
                continue;
            }
            let mut runs = BTreeMap::new();
            let mut arms = [
                ("learned", Arm::Learned),
                ("native_fixed", Arm::Fixed(FixedOrder::Native)),
                ("rule_priority", Arm::Fixed(FixedOrder::RulePriority)),
                ("switch", Arm::Switch),
            ];
            let count = arms.len();
            arms.rotate_left(index % count);
            let order = arms.map(|(name, _)| name);
            for (name, arm) in arms {
                let resources = observer.refresh(&output).unwrap();
                assert!(resources.budget.paused.is_none());
                let result = engine
                    .with(&checkpoint, &mut store, |runtime| {
                        run(
                            question,
                            case.seed,
                            arm,
                            &protocol,
                            runtime,
                            &resources.budget,
                            &output.join(format!("{index}-{name}.proof-work")),
                        )
                    })
                    .unwrap();
                runs.insert(name, result);
            }
            let prefix = matched_prefix(&runs["learned"], &runs["switch"], protocol.switch_after);
            let label = if split == Split::Acquisition
                && prefix.is_some()
                && runs["learned"].check_error.is_none()
                && runs["switch"].check_error.is_none()
                && ![&runs["learned"], &runs["switch"]].into_iter().any(|run| {
                    matches!(
                        run.terminal,
                        experience::TerminalEvidence::TechnicalFailure
                            | experience::TerminalEvidence::Interrupted
                    )
                }) {
                match (
                    runs["learned"].proof.is_some(),
                    runs["switch"].proof.is_some(),
                ) {
                    (true, false) => Some("learned_only"),
                    (false, true) => Some("switch_only"),
                    _ => None,
                }
            } else {
                None
            };
            if let Some(expected) = &case.expected_proof {
                protected &= [&runs["learned"], &runs["switch"]]
                    .into_iter()
                    .all(|run| run.proof.as_ref() == Some(expected));
            }
            write(
                &output.join(format!("{index}.json")),
                &json!({"split":split,
                "resolution":crate::hex(question.resolution_id()),"seed":case.seed,"lineage":case.lineage,
                "family":curriculum::owned::family(question.proved_target()),"prefix":prefix,
                "label":label,"expected":case.expected_proof,"order":order,"runs":runs}),
            );
        }
    }
    write(
        &output.join("gate.json"),
        &json!({"protected_exact":protected}),
    );
}

mod tests;
