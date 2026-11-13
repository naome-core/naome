use crate::lean::{Signature, Step, View};
use crate::model::Rng;
use crate::value::{self, ActionValues, Experience, Features, Observation};
use crate::{
    ACTIONS, APPLY, Action, Archive, Artifact, CATALOG_SLOTS, CONSTRUCTOR, EXACT, EntryId, INTRO,
    RFL, Reference, Result, Verification,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

const CREDIT: u64 = 1 << 20;
const HALF_LIFE: usize = 32;
const FIRST_DEPTH_PAUSE: usize = 128;
const DEEP_TURN_STEPS: usize = 32;
const DEEP_TURN_CALLS: usize = 1024;
const SHALLOW_TURN_CALLS: usize = 64;
const OBSERVATION_WINDOW: usize = 128;
const MAX_ADMISSIONS: usize = 2;
const RECALL_SLOTS: usize = 8;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub target: String,
    #[serde(default)]
    pub hints: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<EntryId>,
    #[serde(default)]
    pub activate: Vec<EntryId>,
    pub seed: Option<u64>,
}

#[derive(Serialize)]
pub struct Outcome {
    pub solved: bool,
    pub checker_calls: usize,
    pub repeated_obligations: usize,
    pub model_before: String,
    pub model_after: String,
    pub proof: Option<Verification>,
    pub steps: Vec<Action>,
    pub admitted: Vec<(u8, EntryId)>,
    pub recalled: Vec<(u8, EntryId)>,
    pub active_entries: usize,
}

#[derive(Clone)]
struct Entry {
    id: EntryId,
    target: String,
    admitted: usize,
    uses: u64,
    recent_uses: u64,
    recent_opportunities: u64,
}

impl Entry {
    fn score(&self, task: usize) -> u128 {
        let rate = |uses, opportunities| (u128::from(uses) << 48) / u128::from(opportunities);
        3 * rate(self.uses, (task - self.admitted).max(1) as u64)
            + rate(self.recent_uses, self.recent_opportunities.max(1))
    }
}

type Catalog = [Option<Entry>; CATALOG_SLOTS];

pub struct AdaptiveSolver {
    archive: Archive,
    catalog: Catalog,
    tasks: usize,
    seen: VecDeque<(String, Vec<String>)>,
    observations: HashMap<String, usize>,
}

impl AdaptiveSolver {
    pub fn new(archive: Archive) -> Self {
        Self {
            archive,
            catalog: std::array::from_fn(|_| None),
            tasks: 0,
            seen: VecDeque::new(),
            observations: HashMap::new(),
        }
    }

    fn install(&mut self, id: EntryId, target: String, pinned: u64) -> Option<u8> {
        if self.catalog.iter().flatten().any(|entry| entry.id == id) {
            return None;
        }
        let slot = self.catalog.iter().position(Option::is_none).or_else(|| {
            self.catalog
                .iter()
                .enumerate()
                .filter_map(|(slot, entry)| {
                    let entry = entry.as_ref()?;
                    (pinned & (1u64 << slot) == 0).then_some((
                        entry.score(self.tasks + 1),
                        entry.admitted,
                        slot,
                    ))
                })
                .min()
                .map(|(_, _, slot)| slot)
        })?;
        self.catalog[slot] = Some(Entry {
            id,
            target,
            admitted: self.tasks,
            uses: 0,
            recent_uses: 0,
            recent_opportunities: 0,
        });
        Some(slot as u8)
    }

    pub fn prove(&mut self, task: Task, seed: u64) -> Result<Outcome> {
        self.prove_with_values(task, seed, ActionValues::bundled())
    }

    fn prepare_task(&mut self, task: &Task) -> Result<()> {
        for name in &task.hints {
            Action {
                id: APPLY,
                argument: Some(Reference::Declaration(name.clone())),
            }
            .validate()?;
        }
        let mut imports = task.dependencies.clone();
        imports.extend(task.activate.iter().copied());
        self.archive.load(&imports)
    }

    fn activate(&mut self, task: &Task) -> Result<()> {
        for id in &task.activate {
            let entry = self.archive.read(*id)?;
            self.install(*id, entry.target().to_owned(), 0);
        }
        Ok(())
    }

    fn recall(&mut self, target: &str, pinned: u64) -> Result<Vec<(u8, EntryId)>> {
        let query = self
            .archive
            .lean
            .start_search(target, &[], true)?
            .target_symbols;
        let best = self.archive.retrieve(query, RECALL_SLOTS)?;
        let mut pinned = self
            .catalog
            .iter()
            .enumerate()
            .fold(pinned, |mask, (slot, entry)| {
                if entry.as_ref().is_some_and(|entry| best.contains(&entry.id)) {
                    mask | (1 << slot)
                } else {
                    mask
                }
            });
        self.archive.load(&best)?;
        let mut recalled = Vec::new();
        for id in best {
            let entry = self.archive.read(id)?;
            if let Some(slot) = self.install(id, entry.target().to_owned(), pinned) {
                pinned |= 1 << slot;
                recalled.push((slot, id));
            }
        }
        Ok(recalled)
    }

    pub fn prove_with_values(
        &mut self,
        task: Task,
        seed: u64,
        values: &ActionValues,
    ) -> Result<Outcome> {
        let before = self.archive.lean.checker_calls();
        self.prepare_task(&task)?;
        let original_catalog = self.catalog.clone();
        let fingerprint = format!("{:016x}", values.fingerprint());
        let search = (|| {
            self.activate(&task)?;
            let pinned = self
                .catalog
                .iter()
                .enumerate()
                .fold(0, |mask, (slot, entry)| {
                    if entry
                        .as_ref()
                        .is_some_and(|entry| task.activate.contains(&entry.id))
                    {
                        mask | (1 << slot)
                    } else {
                        mask
                    }
                });
            let recalled = self.recall(&task.target, pinned)?;
            let (result, trace) = self.run_action_value_search(&task, seed, values, None)?;
            Ok((result, trace, recalled))
        })();
        let (result, trace, recalled) = match search {
            Ok(search) => search,
            Err(error) => {
                self.catalog = original_catalog;
                return Err(error);
            }
        };
        if self.tasks > 0 && self.tasks.is_multiple_of(HALF_LIFE) {
            for entry in self.catalog.iter_mut().flatten() {
                entry.recent_uses /= 2;
                entry.recent_opportunities /= 2;
            }
        }
        for entry in self.catalog.iter_mut().flatten() {
            entry.recent_opportunities += CREDIT;
        }
        let SearchResult {
            repeated_obligations,
            proof,
            steps,
            ..
        } = result;
        let solved = proof.is_some();
        let mut admitted = Vec::new();
        if solved {
            let mut pinned = 0u64;
            for step in &trace {
                if let Some(slot) = step.slot {
                    pinned |= 1u64 << slot;
                }
            }
            for (slot, entry) in self.catalog.iter_mut().enumerate() {
                if let Some(entry) = entry
                    && pinned & (1u64 << slot) != 0
                {
                    entry.uses += 1;
                    entry.recent_uses += CREDIT;
                }
            }
            admitted = self.learn(&task, &steps, &trace, pinned)?;
        }
        self.tasks += 1;
        Ok(Outcome {
            solved,
            checker_calls: self.archive.lean.checker_calls() - before,
            repeated_obligations,
            model_before: fingerprint.clone(),
            model_after: fingerprint,
            proof,
            steps,
            admitted,
            recalled,
            active_entries: self.catalog.iter().flatten().count(),
        })
    }

    fn learn(
        &mut self,
        task: &Task,
        steps: &[Action],
        trace: &[Trace],
        mut pinned: u64,
    ) -> Result<Vec<(u8, EntryId)>> {
        if self.seen.iter().any(|(goal, _)| goal == &task.target) {
            return Ok(Vec::new());
        }
        if self.seen.len() == OBSERVATION_WINDOW
            && let Some((_, targets)) = self.seen.pop_front()
        {
            for target in targets {
                let count = self
                    .observations
                    .get_mut(&target)
                    .expect("known observation");
                *count -= 1;
                if *count == 0 {
                    self.observations.remove(&target);
                }
            }
        }

        let mut unique = HashSet::new();
        let mut reusable = Vec::new();
        for (start, step) in trace.iter().enumerate().skip(1) {
            let Some(target) = &step.closed_target else {
                continue;
            };
            let Some(length) = trace[start..]
                .iter()
                .position(|next| next.after < step.before)
                .map(|end| end + 1)
            else {
                continue;
            };
            if length < 2 || !unique.insert(target.clone()) {
                continue;
            }
            let count = self.observations.entry(target.clone()).or_default();
            *count += 1;
            if *count >= 2
                && !self
                    .catalog
                    .iter()
                    .flatten()
                    .any(|entry| &entry.target == target)
            {
                reusable.push((*count, start, length, target.clone()));
            }
        }
        self.seen
            .push_back((task.target.clone(), unique.into_iter().collect()));
        reusable.sort_by_key(|(count, start, length, _)| {
            (
                std::cmp::Reverse(*count),
                std::cmp::Reverse(*length),
                *start,
            )
        });

        let mut admitted = Vec::new();
        for (_, start, length, target) in reusable {
            let artifact = Artifact::Proof {
                target: target.clone(),
                steps: steps[start..start + length].to_vec(),
                dependencies: task.dependencies.clone(),
            };
            // A closed goal printed by Lean can still depend on elaboration details.
            if let Some(proof) = self.archive.try_compile_fragment(artifact)?
                && let Some(slot) = self.install(proof.id, target, pinned)
            {
                pinned |= 1u64 << slot;
                admitted.push((slot, proof.id));
                if admitted.len() == MAX_ADMISSIONS {
                    break;
                }
            }
        }
        Ok(admitted)
    }
}

#[derive(Clone)]
struct Trace {
    before: usize,
    after: usize,
    slot: Option<u8>,
    closed_target: Option<String>,
}

fn candidates(
    view: &View,
    catalog: &Catalog,
    hints: &[String],
    order: [usize; ACTIONS],
) -> Vec<Action> {
    let mut preferred = Vec::new();
    let mut args = Vec::new();
    for (index, target) in view.locals.iter().enumerate().rev() {
        let reference = Reference::Local(index);
        if target == &view.target {
            preferred.push(Action {
                id: EXACT,
                argument: Some(reference.clone()),
            });
        }
        args.push(reference);
    }
    for (slot, entry) in catalog.iter().enumerate() {
        if let Some(entry) = entry {
            let reference = Reference::Catalog(slot as u8);
            if entry.target == view.target {
                preferred.push(Action {
                    id: EXACT,
                    argument: Some(reference.clone()),
                });
            }
            args.push(reference);
        }
    }
    args.splice(0..0, hints.iter().cloned().map(Reference::Declaration));
    let mut groups: [VecDeque<Action>; ACTIONS] = std::array::from_fn(|_| VecDeque::new());
    for id in [INTRO, CONSTRUCTOR, RFL] {
        groups[usize::from(id)].push_back(Action { id, argument: None });
    }
    for id in [EXACT, APPLY] {
        groups[usize::from(id)].extend(
            args.iter()
                .map(|reference| Action {
                    id,
                    argument: Some(reference.clone()),
                })
                .filter(|candidate| !preferred.contains(candidate)),
        );
    }
    while groups.iter().any(|group| !group.is_empty()) {
        for id in order {
            preferred.extend(groups[id].pop_front());
        }
    }
    preferred
}

#[derive(Serialize)]
pub struct SearchResult {
    pub checker_calls: usize,
    pub repeated_obligations: usize,
    pub proof: Option<Verification>,
    pub steps: Vec<Action>,
}

impl AdaptiveSolver {
    pub fn evaluate_action_values(
        &mut self,
        task: Task,
        seed: u64,
        values: &ActionValues,
    ) -> Result<SearchResult> {
        self.search_with_values(task, seed, values, None)
    }

    pub fn collect_experience(
        &mut self,
        task: Task,
        seed: u64,
        experience: &mut Experience,
    ) -> Result<SearchResult> {
        self.search_with_values(task, seed, &ActionValues::default(), Some(experience))
    }

    fn search_with_values(
        &mut self,
        task: Task,
        seed: u64,
        values: &ActionValues,
        experience: Option<&mut Experience>,
    ) -> Result<SearchResult> {
        let before = self.archive.lean.checker_calls();
        self.prepare_task(&task)?;
        let original = self.catalog.clone();
        let result = (|| {
            self.activate(&task)?;
            self.run_action_value_search(&task, seed, values, experience)
                .map(|(mut result, _)| {
                    result.checker_calls = self.archive.lean.checker_calls() - before;
                    result
                })
        })();
        self.catalog = original;
        result
    }

    fn run_action_value_search(
        &mut self,
        task: &Task,
        seed: u64,
        values: &ActionValues,
        experience: Option<&mut Experience>,
    ) -> Result<(SearchResult, Vec<Trace>)> {
        let before = self.archive.lean.checker_calls();
        let mut names = task.hints.clone();
        names.extend(
            self.catalog
                .iter()
                .flatten()
                .map(|entry| entry.id.lean_name()),
        );
        let mut initial = self.archive.lean.start_search(&task.target, &names, true)?;
        let mut signatures = std::mem::take(&mut initial.reference_signatures).into_iter();
        let declarations = task
            .hints
            .iter()
            .cloned()
            .zip(signatures.by_ref())
            .collect();
        let catalog_signatures =
            std::array::from_fn(|slot| self.catalog[slot].as_ref().and_then(|_| signatures.next()));
        let mut search = ValueSearch {
            archive: &mut self.archive,
            task,
            catalog: &self.catalog,
            declarations,
            catalog_signatures,
            rng: Rng::new(task.seed.unwrap_or(seed)),
            values,
            proof: None,
            steps: Vec::new(),
            trace: Vec::new(),
            experience,
            repeated_obligations: 0,
        };
        search.visit(initial)?;
        if let Some(experience) = search.experience.as_mut() {
            experience.evidence.attempts += 1;
            experience.evidence.checked_proofs += usize::from(search.proof.is_some());
        }
        Ok((
            SearchResult {
                checker_calls: search.archive.lean.checker_calls() - before,
                repeated_obligations: search.repeated_obligations,
                proof: search.proof,
                steps: search.steps,
            },
            search.trace,
        ))
    }
}

struct ValueSearch<'a> {
    archive: &'a mut Archive,
    task: &'a Task,
    catalog: &'a Catalog,
    declarations: HashMap<String, Signature>,
    catalog_signatures: [Option<Signature>; CATALOG_SLOTS],
    rng: Rng,
    values: &'a ActionValues,
    proof: Option<Verification>,
    steps: Vec<Action>,
    trace: Vec<Trace>,
    experience: Option<&'a mut Experience>,
    repeated_obligations: usize,
}

struct SearchNode {
    view: View,
    edge: Option<SearchEdge>,
    depth: usize,
}

struct SearchEdge {
    parent: usize,
    action: Action,
    trace: Trace,
}

struct SearchFrame {
    node: usize,
    actions: std::vec::IntoIter<(Action, Features)>,
}

#[derive(Default)]
struct TrainingTree {
    nodes: HashMap<usize, TrainingNode>,
}

#[derive(Default)]
struct TrainingNode {
    incoming: Option<Observation>,
    started_at: usize,
    parent: Option<usize>,
    open_children: usize,
    actions_exhausted: bool,
    failed_siblings: Vec<Observation>,
}

impl TrainingTree {
    fn accept(&mut self, node: usize, parent: usize, observation: Observation, started_at: usize) {
        self.nodes.entry(parent).or_default().open_children += 1;
        self.nodes.insert(
            node,
            TrainingNode {
                incoming: Some(observation),
                started_at,
                parent: Some(parent),
                ..TrainingNode::default()
            },
        );
    }

    fn exhaust(&mut self, mut node: usize, experience: &mut Experience) {
        self.nodes.entry(node).or_default().actions_exhausted = true;
        while self.nodes[&node].actions_exhausted && self.nodes[&node].open_children == 0 {
            let finished = self.nodes.remove(&node).expect("tracked search node");
            let Some(parent) = finished.parent else { break };
            let mut observation = finished.incoming.expect("accepted action");
            observation.continuation = Some(0.0);
            record(experience, observation);
            let parent_state = self.nodes.get_mut(&parent).expect("tracked parent");
            parent_state.open_children -= 1;
            parent_state.failed_siblings.push(observation);
            node = parent;
        }
    }

    fn finish(mut self, mut winner: usize, calls: usize, experience: &mut Experience) {
        while let Some(success) = self.nodes.remove(&winner) {
            let Some(parent) = success.parent else { break };
            let mut observation = success.incoming.expect("accepted action");
            observation.continuation = Some(0.9995_f64.powf((calls - success.started_at) as f64));
            record(experience, observation);
            let siblings = &self.nodes[&parent].failed_siblings;
            experience.evidence.compared_siblings += siblings.len();
            experience
                .preferences
                .extend(siblings.iter().map(|sibling| (observation, *sibling)));
            winner = parent;
        }
        // Search stops at the first proof. Outstanding accepted branches have no return yet.
        let mut unfinished: Vec<_> = self.nodes.into_iter().collect();
        unfinished.sort_unstable_by_key(|(node, _)| *node);
        for (_, node) in unfinished {
            if let Some(observation) = node.incoming {
                record(experience, observation);
            }
        }
    }
}

impl ValueSearch<'_> {
    fn visit(&mut self, initial: View) -> Result<()> {
        let mut nodes = vec![SearchNode {
            view: initial,
            edge: None,
            depth: 0,
        }];
        let mut shallow = vec![self.expand(&nodes, 0)];
        let mut deep = VecDeque::new();
        let mut prefer_deep = false;
        let mut training = self.experience.is_some().then(TrainingTree::default);
        while !shallow.is_empty() || !deep.is_empty() {
            let deep_turn = (prefer_deep || shallow.is_empty()) && !deep.is_empty();
            let mut stack = if deep_turn {
                deep.pop_front().expect("queued deep branch")
            } else {
                std::mem::take(&mut shallow)
            };
            prefer_deep = !deep_turn;
            let turn_start = self.archive.lean.checker_calls();
            let start_depth = nodes[stack.last().expect("nonempty branch").node].depth;
            while let Some(frame) = stack.last_mut() {
                let parent = frame.node;
                let depth = nodes[parent].depth;
                let calls = self.archive.lean.checker_calls();
                if deep_turn
                    && (calls - turn_start >= DEEP_TURN_CALLS
                        || depth.saturating_sub(start_depth) >= DEEP_TURN_STEPS)
                {
                    deep.push_back(stack);
                    break;
                }
                if !deep_turn && !deep.is_empty() && calls - turn_start >= SHALLOW_TURN_CALLS {
                    shallow = stack;
                    break;
                }
                let Some((mut action, features)) = frame.actions.next() else {
                    if let (Some(tree), Some(experience)) = (&mut training, &mut self.experience) {
                        tree.exhaust(parent, experience);
                    }
                    stack.pop();
                    continue;
                };
                let slot = match action.argument {
                    Some(Reference::Catalog(slot)) => {
                        let entry = self.catalog[usize::from(slot)]
                            .as_ref()
                            .expect("active catalog entry");
                        action.argument = Some(Reference::Archived(entry.id));
                        Some(slot)
                    }
                    _ => None,
                };
                let view = &nodes[parent].view;
                let response = self.archive.lean.search_step(view.state, &action, true)?;
                let mut observation = Observation {
                    action: action.id,
                    features,
                    accepted: false,
                    continuation: Some(0.0),
                };
                let Step::Accepted(next) = response else {
                    if let Some(experience) = &mut self.experience {
                        record(experience, observation);
                    }
                    continue;
                };
                let node = nodes.len();
                let child_depth = depth + 1;
                if let Some(tree) = &mut training {
                    observation.accepted = true;
                    observation.continuation = None;
                    tree.accept(node, parent, observation, calls);
                }
                let trace = Trace {
                    before: view.pending,
                    after: next.pending,
                    slot,
                    closed_target: view.locals.is_empty().then(|| view.target.clone()),
                };
                nodes.push(SearchNode {
                    view: next,
                    edge: Some(SearchEdge {
                        parent,
                        action,
                        trace,
                    }),
                    depth: child_depth,
                });
                if nodes[node].view.pending == 0 {
                    if self.finish_path(&nodes, node)? {
                        if let (Some(tree), Some(experience)) = (training, &mut self.experience) {
                            tree.finish(node, self.archive.lean.checker_calls(), experience);
                        }
                        return Ok(());
                    }
                    if let (Some(tree), Some(experience)) = (&mut training, &mut self.experience) {
                        tree.exhaust(node, experience);
                    }
                } else if !deep_turn && child_depth >= FIRST_DEPTH_PAUSE {
                    let first_pause = deep.is_empty();
                    deep.push_back(vec![self.expand(&nodes, node)]);
                    if first_pause {
                        shallow = stack;
                        break;
                    }
                } else {
                    stack.push(self.expand(&nodes, node));
                }
            }
        }
        Ok(())
    }

    fn finish_path(&mut self, nodes: &[SearchNode], node: usize) -> Result<bool> {
        let mut steps = Vec::with_capacity(nodes[node].depth);
        let mut trace = Vec::with_capacity(nodes[node].depth);
        let mut current = node;
        while let Some(edge) = &nodes[current].edge {
            steps.push(edge.action.clone());
            trace.push(edge.trace.clone());
            current = edge.parent;
        }
        steps.reverse();
        trace.reverse();
        let artifact = Artifact::Proof {
            target: self.task.target.clone(),
            steps: steps.clone(),
            dependencies: self.task.dependencies.clone(),
        };
        self.proof = self
            .archive
            .finish_search(artifact, nodes[node].view.state)?;
        if self.proof.is_none() {
            return Ok(false);
        }
        self.steps = steps;
        self.trace = trace;
        Ok(true)
    }

    fn expand(&mut self, nodes: &[SearchNode], node: usize) -> SearchFrame {
        let view = &nodes[node].view;
        let mut identical = 0;
        let mut related = 0;
        let mut pending_did_not_drop = false;
        let mut current = node;
        while let Some(edge) = &nodes[current].edge {
            current = edge.parent;
            let ancestor = &nodes[current].view;
            related += usize::from(ancestor.head == view.head);
            if ancestor.target == view.target && ancestor.locals == view.locals {
                identical += 1;
                pending_did_not_drop |= ancestor.pending <= view.pending;
            }
        }
        // Repeated obligations keep the existing backtracking behavior.
        let actions = if identical > 1 && pending_did_not_drop {
            self.repeated_obligations += 1;
            Vec::new()
        } else {
            self.rank_actions(view, nodes[node].depth, related, identical)
        };
        SearchFrame {
            node,
            actions: actions.into_iter(),
        }
    }

    fn rank_actions(
        &mut self,
        view: &View,
        depth: usize,
        related: usize,
        identical: usize,
    ) -> Vec<(Action, Features)> {
        let mut order = std::array::from_fn(|id| id);
        self.rng.shuffle(&mut order);
        let mut options: Vec<_> = candidates(view, self.catalog, &self.task.hints, order)
            .into_iter()
            .map(|action| {
                let signature = match action.argument.as_ref() {
                    Some(Reference::Local(index)) => view.local_signatures.get(*index),
                    Some(Reference::Declaration(name)) => self.declarations.get(name),
                    Some(Reference::Catalog(slot)) => {
                        self.catalog_signatures[*slot as usize].as_ref()
                    }
                    _ => None,
                };
                let features = value::features(view, &action, signature, depth, related, identical);
                let score =
                    prior(view, &action, &features) + self.values.score(action.id, &features);
                let exact_catalog_match = action.id == EXACT
                    && matches!(action.argument.as_ref(), Some(Reference::Catalog(slot))
                        if self.catalog[*slot as usize].as_ref()
                            .is_some_and(|entry| entry.target == view.target));
                (action, features, score, exact_catalog_match)
            })
            .collect();
        let noise = if self.experience.is_some() {
            1.4
        } else {
            0.015
        };
        for (_, _, score, _) in &mut options {
            *score += self.rng.unit() * noise;
        }
        options.sort_by(|left, right| {
            right
                .3
                .cmp(&left.3)
                .then_with(|| right.2.total_cmp(&left.2))
        });

        options
            .into_iter()
            .map(|(action, features, _, _)| (action, features))
            .collect()
    }
}

fn record(experience: &mut Experience, observation: Observation) {
    match (observation.accepted, observation.continuation) {
        (false, _) => experience.evidence.rejected_actions += 1,
        (true, Some(0.0)) => experience.evidence.exhausted_accepted_actions += 1,
        (true, Some(_)) => experience.evidence.proof_actions += 1,
        (true, None) => experience.evidence.censored_actions += 1,
    }
    experience.observations.push(observation);
}

fn prior(view: &View, action: &Action, features: &Features) -> f64 {
    match action.id {
        EXACT if features[16] > 0.0 => 9.0,
        INTRO if view.head == "forall" => 1.2,
        CONSTRUCTOR if matches!(view.head.as_str(), "And" | "Iff" | "True" | "Exists") => 1.0,
        APPLY | EXACT => 0.7 * features[19] + 0.3 * features[23] - 0.4 * features[20],
        _ => 0.0,
    }
}
