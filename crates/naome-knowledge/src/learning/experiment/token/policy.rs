//! Autoregressive policy over the legal typed action prefixes of one decision.
use crate::learning::{
    graph::Graph,
    model::{Decision, Memory, Plan, Ranker},
};
use crate::{Error, LearningGraphFailure as Failure, ResearchFailure};

const WEIGHTS: usize = 1 << 14;
const FEATURES: usize = 10;
const PAIR: i32 = 14;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Token {
    Rule(i32),
    Operand(usize),
    Replacement(i32),
    Effect(usize),
    End,
}

#[derive(Clone, Copy, Default)]
struct FormulaFeatures {
    shape: u64,
    syntax: u64,
}

fn mix(a: u64, b: u64) -> u64 {
    let value = (a ^ b.wrapping_mul(0x9e3779b97f4a7c15)).rotate_left(27);
    value.wrapping_mul(0x94d049bb133111eb) ^ (value >> 31)
}

struct Context<'a> {
    graph: &'a Graph,
    formulas: Vec<FormulaFeatures>,
    goal_part: Vec<bool>,
    context_shape: u64,
}

impl<'a> Context<'a> {
    fn new(graph: &'a Graph) -> Result<Self, Failure> {
        if graph.goal >= graph.nodes.len()
            || graph.candidates.is_empty()
            || graph.context.iter().any(|&i| i >= graph.nodes.len())
            || graph.candidates.iter().any(|&i| i >= graph.nodes.len())
        {
            return Err(Failure::NodeBinding);
        }
        let mut formulas = vec![FormulaFeatures::default(); graph.nodes.len()];
        for (i, node) in graph.nodes.iter().enumerate().skip(1) {
            if node.left >= i || node.right >= i {
                return Err(Failure::NodeOperandOrSymbol);
            }
            let [left, right] = [node.left, node.right].map(|j| formulas[j]);
            let kind = node.kind as u64;
            formulas[i] = FormulaFeatures {
                shape: mix(mix(kind, left.shape), right.shape),
                syntax: mix(
                    mix(mix(kind, node.symbol as u64), left.syntax),
                    right.syntax,
                ),
            };
        }
        let mut goal_part = vec![false; formulas.len()];
        goal_part[graph.goal] = true;
        for i in (1..=graph.goal).rev() {
            if goal_part[i] {
                let node = &graph.nodes[i];
                goal_part[node.left] = true;
                goal_part[node.right] = true;
            }
        }
        goal_part[0] = false;
        let context_shape = graph.context.iter().fold(0u64, |sum, &node| {
            sum.wrapping_add(mix(formulas[node].shape, 1))
        });
        Ok(Self {
            graph,
            formulas,
            goal_part,
            context_shape,
        })
    }

    fn tokens(&self, candidate: usize) -> Vec<Token> {
        fn operands(graph: &Graph, node: usize, tokens: &mut Vec<Token>) {
            let fact = &graph.nodes[node];
            if fact.kind == PAIR {
                operands(graph, fact.left, tokens);
                operands(graph, fact.right, tokens);
            } else {
                tokens.push(Token::Operand(node));
            }
        }
        let action = &self.graph.nodes[candidate];
        let mut tokens = vec![Token::Rule(action.kind)];
        operands(self.graph, action.left, &mut tokens);
        tokens.extend([
            Token::Replacement(action.symbol),
            Token::Effect(action.right),
            Token::End,
        ]);
        tokens
    }

    fn relation(&self, node: usize) -> u64 {
        let goal = self.graph.goal;
        u64::from(node == goal)
            | u64::from(self.goal_part[node]) << 1
            | u64::from(self.graph.context.contains(&node)) << 2
            | u64::from(self.formulas[node].shape == self.formulas[goal].shape) << 3
    }

    fn features(&self, rule: u64, prefix: u64, token: Token) -> ([usize; FEATURES - 1], u64) {
        let goal = self.graph.goal;
        let (tag, kind, shape, syntax, relation) = match token {
            Token::Rule(kind) => (1, kind as u64, 0, 0, 0),
            Token::Operand(node) | Token::Effect(node) => {
                let tag = if matches!(token, Token::Operand(_)) {
                    2
                } else {
                    4
                };
                let f = self.formulas[node];
                (
                    tag,
                    self.graph.nodes[node].kind as u64,
                    f.shape,
                    f.syntax,
                    self.relation(node),
                )
            }
            Token::Replacement(symbol) => (3, u64::from(symbol != 0), 0, symbol as u64, 0),
            Token::End => (5, 0, 0, 0, 0),
        };
        // Local fact addresses identify branches. Learned weights are shared
        // across addresses by using the referenced formula's structure.
        let head = mix(tag, kind);
        let detail = mix(head, mix(shape, relation));
        let goal_kind = self.graph.nodes[goal].kind as u64;
        let values = [
            head,
            detail,
            mix(head, goal_kind),
            mix(head, self.formulas[goal].shape),
            mix(detail, rule),
            mix(mix(head, relation), mix(rule, goal_kind)),
            mix(detail, prefix),
            mix(mix(detail, syntax), self.formulas[goal].syntax),
            mix(detail, self.context_shape),
        ];
        (
            std::array::from_fn(|i| (mix(i as u64 + 1, values[i]) as usize) & (WEIGHTS - 1)),
            mix(prefix, detail),
        )
    }
}

struct Edge {
    token: Token,
    child: usize,
    features: [usize; FEATURES],
}

#[derive(Default)]
struct Prefix {
    edges: Vec<Edge>,
    candidates: Vec<usize>,
    effects: u64,
}

struct Menu {
    prefixes: Vec<Prefix>,
    candidates: usize,
}

impl Menu {
    fn new(graph: &Graph) -> Result<Self, Failure> {
        let context = Context::new(graph)?;
        let mut prefixes = vec![Prefix::default()];
        for (index, &candidate) in graph.candidates.iter().enumerate() {
            let mut parent = 0;
            let mut prefix = 0;
            let rule = graph.nodes[candidate].kind as u64;
            let effect = context.relation(graph.nodes[candidate].right);
            for token in context.tokens(candidate) {
                let (features, next) = context.features(rule, prefix, token);
                prefix = next;
                let child = match prefixes[parent]
                    .edges
                    .iter()
                    .find(|edge| edge.token == token)
                {
                    Some(edge) => edge.child,
                    None => {
                        let child = prefixes.len();
                        prefixes.push(Prefix::default());
                        let mut edge_features = [0; FEATURES];
                        edge_features[..FEATURES - 1].copy_from_slice(&features);
                        prefixes[parent].edges.push(Edge {
                            token,
                            child,
                            features: edge_features,
                        });
                        child
                    }
                };
                parent = child;
                prefixes[parent].effects |= effect;
            }
            prefixes[parent].candidates.push(index);
        }
        let effects = prefixes
            .iter()
            .map(|prefix| prefix.effects)
            .collect::<Vec<_>>();
        for edge in prefixes.iter_mut().flat_map(|prefix| &mut prefix.edges) {
            // A token can distinguish legal completions even when the effect
            // token itself is forced by the preceding choices.
            edge.features[FEATURES - 1] =
                (mix(edge.features[0] as u64, effects[edge.child]) as usize) & (WEIGHTS - 1);
        }
        Ok(Self {
            prefixes,
            candidates: graph.candidates.len(),
        })
    }

    fn probabilities(&self, weights: &[f32]) -> Vec<f64> {
        let mut conditional = vec![1.; self.prefixes.len()];
        for prefix in &self.prefixes {
            if prefix.edges.len() <= 1 {
                continue;
            }
            for edge in &prefix.edges {
                conditional[edge.child] =
                    edge.features.iter().map(|&i| f64::from(weights[i])).sum();
            }
            let max = prefix
                .edges
                .iter()
                .map(|e| conditional[e.child])
                .fold(f64::NEG_INFINITY, f64::max);
            let mut total = 0.;
            for edge in &prefix.edges {
                conditional[edge.child] = (conditional[edge.child] - max).exp();
                total += conditional[edge.child];
            }
            for edge in &prefix.edges {
                conditional[edge.child] /= total;
            }
        }
        conditional
    }

    fn reach(&self, conditional: &[f64]) -> Vec<f64> {
        let mut reach = vec![1.; self.prefixes.len()];
        for (i, prefix) in self.prefixes.iter().enumerate() {
            for edge in &prefix.edges {
                reach[edge.child] = reach[i] * conditional[edge.child];
            }
        }
        reach
    }

    fn scores(&self, weights: &[f32]) -> Vec<f32> {
        let conditional = self.probabilities(weights);
        let reach = self.reach(&conditional);
        let mut scores = vec![0.; self.candidates];
        for (prefix, probability) in self.prefixes.iter().zip(reach) {
            for &candidate in &prefix.candidates {
                scores[candidate] = (probability / prefix.candidates.len() as f64).ln() as f32;
            }
        }
        scores
    }

    fn gradient(
        &self,
        weights: &[f32],
        successful: &[usize],
        gradient: &mut [f64],
    ) -> Result<f64, Failure> {
        let conditional = self.probabilities(weights);
        let reach = self.reach(&conditional);
        let mut success = vec![0.; self.prefixes.len()];
        for (i, prefix) in self.prefixes.iter().enumerate().rev() {
            success[i] = if prefix.edges.is_empty() {
                prefix
                    .candidates
                    .iter()
                    .filter(|index| successful.contains(index))
                    .count() as f64
                    / prefix.candidates.len() as f64
            } else {
                prefix
                    .edges
                    .iter()
                    .map(|edge| conditional[edge.child] * success[edge.child])
                    .sum()
            };
        }
        let mass = success[0];
        if mass <= 0. || !mass.is_finite() {
            return Err(Failure::MissingExpert);
        }
        for (i, prefix) in self
            .prefixes
            .iter()
            .enumerate()
            .filter(|(_, p)| p.edges.len() > 1)
        {
            for edge in &prefix.edges {
                // Derivative of the log probability mass of all checked choices.
                let slope = reach[edge.child] * (success[edge.child] - success[i]) / mass;
                for &feature in &edge.features {
                    gradient[feature] += slope;
                }
            }
        }
        Ok(-mass.ln())
    }
}

pub(super) struct Policy {
    weights: Vec<f32>,
    pub calls: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            weights: vec![0.; WEIGHTS],
            calls: 0,
        }
    }
}

impl Policy {
    pub fn update(&mut self, batch: &[&Graph]) -> Result<f64, Error> {
        if batch.is_empty() {
            return Err(Failure::EmptyBatch.into());
        }
        let mut gradient = vec![0.; WEIGHTS];
        let mut loss = 0.;
        for graph in batch {
            loss += Menu::new(graph)?.gradient(&self.weights, &graph.successes, &mut gradient)?;
        }
        for (weight, slope) in self.weights.iter_mut().zip(gradient) {
            *weight = (*weight + (0.15 * slope / batch.len() as f64) as f32).clamp(-4., 4.);
        }
        Ok(loss / batch.len() as f64)
    }

    fn scores_graph(&mut self, graph: &Graph) -> Result<Vec<f32>, Error> {
        let scores = Menu::new(graph)?.scores(&self.weights);
        self.calls += 1;
        Ok(scores)
    }
}

impl Ranker for Policy {
    fn scores(&mut self, decision: &Decision) -> Result<Vec<f32>, Error> {
        self.scores_graph(&Graph::encode(decision)?)
    }

    fn plan(
        &mut self,
        _: &Decision,
        graph: &Graph,
        _: &str,
        memory: Option<&Memory>,
    ) -> Result<Plan, Error> {
        if memory.is_some() {
            return Err(ResearchFailure::StatelessRankerMemory.into());
        }
        Ok(Plan::scores(self.scores_graph(graph)?))
    }
}

#[cfg(test)]
mod tests;
