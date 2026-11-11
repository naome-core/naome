//! Experimental AND/OR planning over the ordinary typed tableau transitions.
use super::{super::model::Memory, *};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Strategy {
    BestFirst,
    Htps,
}

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Open(f64),
    Closed(usize, usize),
    Proved(usize),
    Exhausted,
}

impl Status {
    fn probability(self) -> f64 {
        match self {
            Self::Open(_) => 0.5,
            Self::Closed(..) | Self::Proved(_) => 1.0,
            Self::Exhausted => 0.0,
        }
    }

    fn open(self) -> bool {
        matches!(self, Self::Open(_))
    }
}

type NodeId = usize;

struct Edge {
    offer: Offer,
    policy_index: usize,
    prior: f64,
    children: Option<Vec<NodeId>>,
    visits: usize,
    value: f64,
}

struct Menu {
    plan: Option<Plan>,
    edges: Vec<Edge>,
}

struct Node {
    state: State,
    depth: usize,
    binding: String,
    memory: Option<Memory>,
    parents: Vec<NodeId>,
    status: Status,
    menu: Option<Menu>,
    prefetched: Option<(Vec<Offer>, String)>,
}

struct Planner<'a> {
    ranker: &'a mut dyn Ranker,
    clock: SearchClock,
    strategy: Strategy,
    maximum: usize,
    expansions: usize,
    prepared: usize,
    reused: usize,
    nodes: Vec<Node>,
    index: HashMap<(usize, String, Option<String>), NodeId>,
}

pub(super) struct Planned {
    pub tree: Option<Tree>,
    pub expansions: usize,
    pub states: usize,
    pub reused: usize,
}

pub(super) fn solve(
    target: &Formula,
    ranker: &mut dyn Ranker,
    maximum: usize,
    clock: SearchClock,
    knowledge: &[super::super::knowledge::Entry],
    strategy: Strategy,
) -> Result<Planned, crate::Error> {
    if maximum == 0 || clock.expired()? {
        return Ok(Planned {
            tree: None,
            expansions: 0,
            states: 0,
            reused: 0,
        });
    }
    if let Some(index) = AXIOMS.iter().position(|axiom| axiom.formula() == *target) {
        return Ok(Planned {
            tree: Some(Tree::Axiom(index as u8)),
            expansions: 1,
            states: 0,
            reused: 0,
        });
    }
    let checked = super::super::knowledge::checked_entries(knowledge)?;
    let mut state = prepare(target)?.state;
    state.knowledge_context = knowledge.iter().map(super::super::digest).collect();
    state.knowledge = checked.iter().map(|entry| entry.target.clone()).collect();
    let binding = trace::binding(&state)?;
    let mut planner = Planner {
        ranker,
        clock,
        strategy,
        maximum,
        expansions: 0,
        prepared: 0,
        reused: 0,
        nodes: Vec::new(),
        index: HashMap::new(),
    };
    let root = planner.intern(state, 0, binding, None, None);
    while planner.nodes[root].status.open() && planner.available()? {
        let before = (planner.expansions, planner.prepared);
        planner.visit(root)?;
        if before == (planner.expansions, planner.prepared) {
            break;
        }
    }
    // A shared subgoal can occur at several positions in the replay tree.
    // Keep materialization within the same number of proof actions available
    // to the recursive solver, regardless of the number of cached states.
    let mut remaining = maximum;
    let mut tree = planner.proof(root, &mut remaining);
    if !knowledge.is_empty() {
        let target = target.encode_canonical()?;
        tree = tree.map(|proof| Tree::Knowledge {
            entries: knowledge.to_vec(),
            target,
            proof: Box::new(proof),
        });
    }
    Ok(Planned {
        tree,
        expansions: planner.expansions,
        states: planner.nodes.len(),
        reused: planner.reused,
    })
}

impl Planner<'_> {
    fn available(&self) -> Result<bool, crate::Error> {
        Ok(self.expansions < self.maximum && !self.clock.expired()?)
    }

    fn intern(
        &mut self,
        state: State,
        depth: usize,
        binding: String,
        memory: Option<Memory>,
        prefetched: Option<(Vec<Offer>, String)>,
    ) -> NodeId {
        // Ordered facts, actions already used, context and domain are in the
        // binding. Depth and the exact recurrent state also affect search.
        let key = (
            depth,
            binding.clone(),
            memory.as_ref().map(super::super::digest),
        );
        if let Some(&id) = self.index.get(&key) {
            self.reused += 1;
            return id;
        }
        let id = self.nodes.len();
        self.index.insert(key, id);
        let status = if depth > MAX_DEPTH {
            Status::Exhausted
        } else if let Some((positive, negative)) = close(&state) {
            Status::Closed(positive, negative)
        } else if state.facts.len() > FACT_LIMIT {
            Status::Exhausted
        } else {
            Status::Open(1.0)
        };
        self.nodes.push(Node {
            state,
            depth,
            binding,
            memory,
            parents: Vec::new(),
            status,
            menu: None,
            prefetched,
        });
        id
    }

    fn prepare_menu(&mut self, id: NodeId) -> Result<(), crate::Error> {
        let node = &mut self.nodes[id];
        let (offers, offered) = match node.prefetched.take() {
            Some((offers, offered)) => (offers, Some(offered)),
            None => (offers(&node.state), None),
        };
        let remaining = self.maximum - self.expansions;
        let forced = forced_offer(&offers, node.depth, remaining);
        let menu = if let Some(index) = forced {
            Menu {
                plan: None,
                edges: vec![Edge::new(
                    offers.into_iter().nth(index).unwrap(),
                    index,
                    1.0,
                )],
            }
        } else if offers.is_empty() {
            Menu {
                plan: None,
                edges: Vec::new(),
            }
        } else {
            let offered = offered.unwrap_or_else(|| offer_binding(&offers));
            let decision = decision_for(&node.state.goal, &node.state, &offers, 0)?;
            match self
                .ranker
                .plan(&decision, &node.binding, &offered, node.memory.as_ref())
            {
                Ok(plan) => {
                    let prior = priors(&plan.scores, offers.len())?;
                    Menu {
                        plan: Some(plan),
                        edges: offers
                            .into_iter()
                            .zip(prior)
                            .enumerate()
                            .map(|(i, (offer, prior))| Edge::new(offer, i, prior))
                            .collect(),
                    }
                }
                Err(error) if decision_capacity(&error) => Menu {
                    plan: None,
                    edges: Vec::new(),
                },
                Err(error) => return Err(error),
            }
        };
        node.memory = None;
        node.menu = Some(menu);
        self.prepared += 1;
        self.refresh(id);
        Ok(())
    }

    fn expand(&mut self, id: NodeId, choice: usize) -> Result<(), crate::Error> {
        let node = &self.nodes[id];
        let menu = node.menu.as_ref().expect("prepared node");
        let edge = &menu.edges[choice];
        let children = edge.offer.delta.apply(&node.state, &edge.offer.action);
        let depth = node.depth + 1;
        let mut pending = Vec::with_capacity(children.len());
        for child in children {
            let binding = trace::binding(&child)?;
            let (memory, prefetched) = if let Some(plan) = &menu.plan
                && depth <= MAX_DEPTH
                && close(&child).is_none()
                && child.facts.len() <= FACT_LIMIT
            {
                let choices = offers(&child);
                let offered = offer_binding(&choices);
                let memory = if !choices.is_empty() && forced_offer(&choices, depth, 1).is_none() {
                    plan.child(edge.policy_index, binding.clone(), offered.clone())?
                } else {
                    None
                };
                (memory, Some((choices, offered)))
            } else {
                (None, None)
            };
            pending.push((child, binding, memory, prefetched));
        }
        self.expansions += 1;
        let children = pending
            .into_iter()
            .map(|(state, binding, memory, prefetched)| {
                let child = self.intern(state, depth, binding, memory, prefetched);
                if !self.nodes[child].parents.contains(&id) {
                    self.nodes[child].parents.push(id);
                }
                child
            })
            .collect();
        let menu = self.nodes[id].menu.as_mut().expect("prepared node");
        menu.edges[choice].children = Some(children);
        if menu.edges.iter().all(|edge| edge.children.is_some()) {
            menu.plan = None;
        }
        self.refresh(id);
        Ok(())
    }

    fn refresh(&mut self, id: NodeId) {
        let mut changed = vec![id];
        while let Some(id) = changed.pop() {
            let Some(menu) = &self.nodes[id].menu else {
                continue;
            };
            let status = menu
                .edges
                .iter()
                .enumerate()
                .filter_map(|(i, edge)| {
                    let children = edge.children.as_ref()?;
                    children
                        .iter()
                        .all(|&child| self.nodes[child].status.probability() == 1.0)
                        .then_some(Status::Proved(i))
                })
                .next()
                .unwrap_or_else(|| {
                    menu.edges
                        .iter()
                        .filter_map(|edge| edge.cost(&self.nodes))
                        .min_by(f64::total_cmp)
                        .map_or(Status::Exhausted, Status::Open)
                });
            if status != self.nodes[id].status {
                self.nodes[id].status = status;
                changed.extend(self.nodes[id].parents.iter().copied());
            }
        }
    }

    fn select(&self, id: NodeId) -> Option<usize> {
        let edges = &self.nodes[id].menu.as_ref()?.edges;
        let visits = (1.0 + edges.iter().map(|edge| edge.visits as f64).sum::<f64>()).sqrt();
        edges
            .iter()
            .enumerate()
            .filter_map(|(i, edge)| {
                let cost = edge.cost(&self.nodes)?;
                let score = match self.strategy {
                    Strategy::BestFirst => -cost,
                    Strategy::Htps => {
                        let value = if edge.visits == 0 {
                            0.5
                        } else {
                            edge.value / edge.visits as f64
                        };
                        value + 1.25 * edge.prior * visits / (1 + edge.visits) as f64
                    }
                };
                Some((i, score))
            })
            .max_by(|a, b| a.1.total_cmp(&b.1).then(b.0.cmp(&a.0)))
            .map(|(i, _)| i)
    }

    fn visit(&mut self, id: NodeId) -> Result<f64, crate::Error> {
        if !self.nodes[id].status.open() || !self.available()? {
            return Ok(self.nodes[id].status.probability());
        }
        if self.nodes[id].menu.is_none() {
            self.prepare_menu(id)?;
        }
        let Some(choice) = self.select(id) else {
            return Ok(self.nodes[id].status.probability());
        };
        let children = self.nodes[id].menu.as_ref().unwrap().edges[choice]
            .children
            .clone();
        let value = if let Some(children) = children {
            match self.strategy {
                Strategy::BestFirst => {
                    if let Some(child) = children
                        .into_iter()
                        .filter_map(|child| match self.nodes[child].status {
                            Status::Open(cost) => Some((child, cost)),
                            _ => None,
                        })
                        .max_by(|a, b| a.1.total_cmp(&b.1).then(b.0.cmp(&a.0)))
                        .map(|(child, _)| child)
                    {
                        self.visit(child)?;
                    }
                    0.5
                }
                Strategy::Htps => {
                    let mut product = 1.0;
                    for child in children {
                        product *= self.visit(child)?;
                        if product == 0.0 {
                            break;
                        }
                    }
                    product
                }
            }
        } else if self.available()? {
            self.expand(id, choice)?;
            self.nodes[id].menu.as_ref().unwrap().edges[choice]
                .children
                .as_ref()
                .expect("expanded edge")
                .iter()
                .map(|&child| self.nodes[child].status.probability())
                .product()
        } else {
            0.5
        };
        if self.strategy == Strategy::Htps {
            let edge = &mut self.nodes[id].menu.as_mut().unwrap().edges[choice];
            edge.visits += 1;
            edge.value += value;
        }
        Ok(if self.nodes[id].status.open() {
            value
        } else {
            self.nodes[id].status.probability()
        })
    }

    fn proof(&self, id: NodeId, remaining: &mut usize) -> Option<Tree> {
        match self.nodes[id].status {
            Status::Closed(a, b) => Some(Tree::Close(a, b)),
            Status::Proved(index) => {
                *remaining = remaining.checked_sub(1)?;
                let edge = &self.nodes[id].menu.as_ref()?.edges[index];
                Some(Tree::Step {
                    action: edge.offer.action.clone(),
                    children: edge
                        .children
                        .as_ref()?
                        .iter()
                        .map(|&child| self.proof(child, remaining))
                        .collect::<Option<Vec<_>>>()?,
                })
            }
            Status::Open(_) | Status::Exhausted => None,
        }
    }
}

impl Edge {
    fn new(offer: Offer, policy_index: usize, prior: f64) -> Self {
        Self {
            offer,
            policy_index,
            prior,
            children: None,
            visits: 0,
            value: 0.0,
        }
    }

    fn cost(&self, nodes: &[Node]) -> Option<f64> {
        let mut cost = 1.0 - self.prior.ln();
        if let Some(children) = &self.children {
            for &child in children {
                match nodes[child].status {
                    Status::Open(estimate) => cost += estimate,
                    Status::Exhausted => return None,
                    Status::Closed(..) | Status::Proved(_) => {}
                }
            }
        } else {
            cost += self.offer.delta.branches().len() as f64;
        }
        Some(cost)
    }
}

fn offer_binding(offers: &[Offer]) -> String {
    let actions = offers.iter().map(|offer| &offer.action).collect::<Vec<_>>();
    super::super::digest(&actions)
}

fn priors(scores: &[f32], expected: usize) -> Result<Vec<f64>, crate::Error> {
    if scores.len() != expected || scores.iter().any(|score| !score.is_finite()) {
        return Err(crate::ResearchFailure::InvalidActionScores.into());
    }
    let peak = scores
        .iter()
        .copied()
        .max_by(f32::total_cmp)
        .expect("nonempty menu");
    let mut weights = scores
        .iter()
        .map(|&score| (f64::from(score) - f64::from(peak)).max(-32.0).exp())
        .collect::<Vec<_>>();
    let total = weights.iter().sum::<f64>();
    for weight in &mut weights {
        *weight /= total;
    }
    Ok(weights)
}

#[cfg(test)]
mod tests;
