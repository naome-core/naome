//! Decision-local typed prefixes shared by search and checked replay.
use crate::LearningGraphFailure as Failure;
use crate::learning::graph::{Graph, Node};
use std::ops::Range;

pub(super) const VOCABULARY: usize = 2048;
pub(super) const FEATURES: usize = 8;
const PAIR: i32 = 14;
const MAX_OPERANDS: usize = naome_proof::program::ACTION_PREMISES + 1;
pub(super) type Row = [i32; FEATURES];

fn mix(a: u64, b: u64) -> u64 {
    let value = (a ^ b.wrapping_mul(0x9e3779b97f4a7c15)).rotate_left(27);
    value.wrapping_mul(0x94d049bb133111eb) ^ (value >> 31)
}

fn row(features: [u64; FEATURES]) -> Row {
    std::array::from_fn(|i| (mix(i as u64 + 1, features[i]) % VOCABULARY as u64) as i32)
}

#[derive(Clone, Copy, Default)]
struct Signature {
    shape: u64,
    syntax: u64,
}

fn signatures(nodes: &[Node]) -> Vec<Signature> {
    let mut signatures = vec![Signature::default(); nodes.len()];
    for (index, node) in nodes.iter().enumerate().skip(1) {
        let [left, right] = [node.left, node.right].map(|child| signatures[child]);
        let kind = node.kind as u64;
        signatures[index] = Signature {
            shape: mix(mix(kind, left.shape), right.shape),
            syntax: mix(
                mix(mix(kind, node.symbol as u64), left.syntax),
                right.syntax,
            ),
        };
    }
    signatures
}

fn structural_rows(nodes: &[Node], signatures: &[Signature]) -> Vec<Row> {
    nodes
        .iter()
        .zip(signatures)
        .map(|(node, form)| {
            let kind = node.kind as u64;
            let symbol = node.symbol as u64;
            let left = &nodes[node.left];
            let right = &nodes[node.right];
            let left_kind = left.kind as u64;
            let right_kind = right.kind as u64;
            row([
                kind,
                mix(kind, symbol),
                mix(mix(kind, left_kind), right_kind),
                form.shape,
                form.syntax,
                mix(kind, signatures[node.left].shape),
                mix(kind, signatures[node.right].shape),
                mix(mix(kind, left.symbol as u64), right.symbol as u64),
            ])
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Token {
    Rule(i32),
    Premise(usize),
    Replacement(i32),
    Effect(usize),
    End,
}

fn operands(nodes: &[Node], root: usize) -> Result<Vec<usize>, Failure> {
    let mut stack = vec![root];
    let mut result = Vec::new();
    while let Some(index) = stack.pop() {
        if index == 0 {
            continue;
        }
        let node = &nodes[index];
        if node.kind == PAIR {
            stack.extend([node.right, node.left]);
        } else {
            result.push(index);
        }
        if result.len() + stack.len() > MAX_OPERANDS {
            return Err(Failure::ActionArity);
        }
    }
    Ok(result)
}

#[derive(Clone, Copy, Default)]
struct Step {
    head: u64,
    detail: u64,
    syntax: u64,
}

struct Input<'a> {
    graph: &'a Graph,
    signatures: Vec<Signature>,
    goal_parts: Vec<bool>,
    context: Vec<bool>,
    context_shape: u64,
}

impl<'a> Input<'a> {
    fn new(graph: &'a Graph) -> Self {
        let signatures = signatures(&graph.nodes);
        let mut goal_parts = vec![false; graph.nodes.len()];
        goal_parts[graph.goal] = true;
        for i in (1..=graph.goal).rev() {
            if goal_parts[i] {
                let node = &graph.nodes[i];
                goal_parts[node.left] = true;
                goal_parts[node.right] = true;
            }
        }
        goal_parts[0] = false;
        let mut context = vec![false; graph.nodes.len()];
        let mut context_shape = 0u64;
        for &index in &graph.context {
            if !context[index] {
                context_shape = context_shape.wrapping_add(mix(signatures[index].shape, 1));
                context[index] = true;
            }
        }
        Self {
            graph,
            signatures,
            goal_parts,
            context,
            context_shape,
        }
    }

    fn relationship(&self, index: usize) -> u64 {
        let goal = self.graph.goal;
        u64::from(index == goal)
            | (u64::from(self.goal_parts[index]) << 1)
            | (u64::from(self.context[index]) << 2)
            | (u64::from(self.signatures[index].shape == self.signatures[goal].shape) << 3)
    }

    fn describe(&self, token: Token) -> Step {
        let (tag, kind, shape, syntax, relation) = match token {
            Token::Rule(rule) => (1, rule as u64, 0, 0, 0),
            Token::Premise(index) | Token::Effect(index) => {
                let tag = if matches!(token, Token::Premise(_)) {
                    2
                } else {
                    4
                };
                let form = self.signatures[index];
                (
                    tag,
                    self.graph.nodes[index].kind as u64,
                    form.shape,
                    form.syntax,
                    self.relationship(index),
                )
            }
            Token::Replacement(symbol) => (3, u64::from(symbol != 0), 0, symbol as u64, 0),
            Token::End => (5, 0, 0, 0, 0),
        };
        let head = mix(tag, kind);
        let detail = mix(mix(head, shape), relation);
        Step {
            head,
            detail,
            syntax,
        }
    }

    fn edge(&self, step: Step, prefix: u64, rule: u64, suffix: u64) -> Row {
        let Step {
            head,
            detail,
            syntax,
        } = step;
        let field = self.graph.field as u64;
        let goal = self.signatures[self.graph.goal];
        row([
            mix(head, field),
            detail,
            mix(mix(head, field), goal.shape),
            mix(detail, rule),
            mix(detail, prefix),
            mix(mix(detail, syntax), goal.syntax),
            mix(detail, self.context_shape),
            mix(mix(head, rule), suffix),
        ])
    }
}

#[derive(Default)]
struct Prefix {
    parent: usize,
    children: Vec<(Token, usize)>,
    rule: u64,
    step: Step,
    digest: u64,
    effects: u64,
    aliases: usize,
}

/// All rows and branch masks come from the same allowed action set. Forced
/// tokens contribute log probability zero and require no model row.
pub(super) struct Menu {
    pub rows: Vec<Row>,
    pub edges: Vec<Row>,
    pub priors: Vec<f32>,
    pub groups: Vec<Range<usize>>,
    pub paths: Vec<Vec<usize>>,
    pub aliases: Vec<f32>,
}

impl Menu {
    /// The batch owner has validated topological node references and the menu.
    pub fn lower(graph: &Graph) -> Result<Self, Failure> {
        let input = Input::new(graph);
        let mut prefixes = vec![Prefix::default()];
        let mut leaves = Vec::with_capacity(graph.candidates.len());
        for &candidate in &graph.candidates {
            let action = &graph.nodes[candidate];
            let rule = action.kind as u64;
            let premises = operands(&graph.nodes, action.left)?;
            let effects = operands(&graph.nodes, action.right)?;
            let suffix = effects
                .iter()
                .fold(0, |flags, &index| flags | input.relationship(index));
            let tokens = std::iter::once(Token::Rule(action.kind))
                .chain(premises.into_iter().map(Token::Premise))
                .chain([Token::Replacement(action.symbol)])
                .chain(effects.into_iter().map(Token::Effect))
                .chain([Token::End]);
            let mut parent = 0;
            for token in tokens {
                let child = match prefixes[parent]
                    .children
                    .iter()
                    .find(|(value, _)| *value == token)
                {
                    Some((_, index)) => *index,
                    None => {
                        let step = input.describe(token);
                        let digest = mix(prefixes[parent].digest, mix(step.detail, step.syntax));
                        let index = prefixes.len();
                        prefixes.push(Prefix {
                            parent,
                            rule,
                            step,
                            digest,
                            ..Default::default()
                        });
                        prefixes[parent].children.push((token, index));
                        index
                    }
                };
                prefixes[child].effects |= suffix;
                parent = child;
            }
            prefixes[parent].aliases += 1;
            leaves.push(parent);
        }
        let mut edges = Vec::new();
        let mut priors = Vec::new();
        let mut groups = Vec::new();
        let mut indices = vec![None; prefixes.len()];
        let mut leaves_below = vec![0usize; prefixes.len()];
        for (index, prefix) in prefixes.iter().enumerate().rev() {
            leaves_below[index] = if prefix.children.is_empty() {
                1
            } else {
                prefix
                    .children
                    .iter()
                    .map(|&(_, child)| leaves_below[child])
                    .sum()
            };
        }
        for prefix in &prefixes {
            if prefix.children.len() <= 1 {
                continue;
            }
            let start = edges.len();
            for &(_, child) in &prefix.children {
                let next = &prefixes[child];
                indices[child] = Some(edges.len());
                edges.push(input.edge(next.step, prefix.digest, next.rule, next.effects));
                // A zero residual logit gives equal mass to every distinct
                // complete action, independent of the shape of the trie.
                priors.push((leaves_below[child] as f32).ln());
            }
            groups.push(start..edges.len());
        }
        // A trie with c leaves has at most 2c-2 edges leaving branch points.
        debug_assert!(edges.len() <= 2 * graph.candidates.len().saturating_sub(1));
        let paths = leaves
            .iter()
            .map(|&leaf| {
                let mut path = Vec::new();
                let mut node = leaf;
                while node != 0 {
                    path.extend(indices[node]);
                    node = prefixes[node].parent;
                }
                path
            })
            .collect();
        let aliases = leaves
            .iter()
            .map(|&leaf| (prefixes[leaf].aliases as f32).ln())
            .collect();
        Ok(Self {
            rows: structural_rows(&graph.nodes, &input.signatures),
            edges,
            priors,
            groups,
            paths,
            aliases,
        })
    }
}

#[cfg(test)]
mod tests;
