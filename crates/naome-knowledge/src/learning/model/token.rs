//! Decision-local typed prefixes shared by search and checked replay.
use crate::LearningGraphFailure as Failure;
use crate::learning::graph::{Encoded, Field, Graph, NEGATION, Node, NodeSink, PAIR};
use std::ops::Range;

pub(super) const VOCABULARY: usize = 2048;
pub(super) const FEATURES: usize = 10;
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

#[derive(Clone, Copy, Default)]
struct Form {
    kind: i32,
    symbol: i32,
    signature: Signature,
    negated: Option<usize>,
}

#[derive(Default)]
pub(super) struct TokenNodes {
    forms: Vec<Form>,
    rows: Vec<Row>,
    roles: Vec<i32>,
    actions: Vec<Operands>,
}

struct Operands {
    premises: Vec<usize>,
    effects: Vec<usize>,
}

impl NodeSink for TokenNodes {
    fn len(&self) -> usize {
        self.rows.len()
    }

    fn push(&mut self, node: Node) {
        self.lower_node(&node);
    }

    fn mark(&mut self, index: usize, role: i32) {
        self.roles[index] |= role;
    }

    fn action(&mut self, premises: Vec<usize>, effects: Vec<usize>) {
        self.actions.push(Operands { premises, effects });
    }
}

impl TokenNodes {
    fn lower_node(&mut self, node: &Node) {
        let [left, right] = if self.forms.is_empty() {
            [Form::default(); 2]
        } else {
            [self.forms[node.left], self.forms[node.right]]
        };
        let kind = node.kind as u64;
        let symbol = node.symbol as u64;
        let signature = if self.forms.is_empty() {
            Signature::default()
        } else {
            Signature {
                shape: mix(mix(kind, left.signature.shape), right.signature.shape),
                syntax: mix(
                    mix(mix(kind, symbol), left.signature.syntax),
                    right.signature.syntax,
                ),
            }
        };
        self.forms.push(Form {
            kind: node.kind,
            symbol: node.symbol,
            signature,
            negated: (node.kind == NEGATION).then_some(node.left),
        });
        let left_kind = left.kind as u64;
        let right_kind = right.kind as u64;
        self.rows.push(row([
            kind,
            mix(kind, symbol),
            mix(mix(kind, left_kind), right_kind),
            signature.shape,
            signature.syntax,
            mix(kind, left.signature.shape),
            mix(kind, right.signature.shape),
            mix(mix(kind, left.symbol as u64), right.symbol as u64),
            left_kind,
            right_kind,
        ]));
        self.roles.push(node.role);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Token {
    Rule(i32),
    Premise(usize),
    Replacement(i32),
    Variation(i32),
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
    relation: u64,
}

struct Input<'a> {
    forms: &'a [Form],
    field: Field,
    goal: usize,
    goal_parts: Vec<bool>,
    context: Vec<bool>,
    opposites: Vec<bool>,
    context_shape: u64,
}

impl<'a> Input<'a> {
    fn new(
        forms: &'a [Form],
        field: Field,
        goal: usize,
        goal_parts: Vec<bool>,
        roots: &[usize],
    ) -> Self {
        let mut context = vec![false; forms.len()];
        let mut context_shape = 0u64;
        for &index in roots {
            if !context[index] {
                context_shape = context_shape.wrapping_add(mix(forms[index].signature.shape, 1));
                context[index] = true;
            }
        }
        let mut opposites = vec![false; forms.len()];
        for (index, form) in forms.iter().enumerate().skip(1) {
            if let Some(body) = form.negated {
                // Compare exact local formula references before reducing
                // variable bindings to token features.
                opposites[index] |= context[body];
                opposites[body] |= context[index];
            }
        }
        Self {
            forms,
            field,
            goal,
            goal_parts,
            context,
            opposites,
            context_shape,
        }
    }

    fn relationship(&self, index: usize) -> u64 {
        let goal = self.goal;
        u64::from(index == goal)
            | (u64::from(self.goal_parts[index]) << 1)
            | (u64::from(self.context[index]) << 2)
            | (u64::from(self.forms[index].signature.shape == self.forms[goal].signature.shape)
                << 3)
            | (u64::from(self.opposites[index]) << 4)
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
                let form = self.forms[index];
                (
                    tag,
                    form.kind as u64,
                    form.signature.shape,
                    form.signature.syntax,
                    self.relationship(index),
                )
            }
            Token::Replacement(symbol) => (3, u64::from(symbol != 0), 0, symbol as u64, 0),
            Token::End => (5, 0, 0, 0, 0),
            Token::Variation(level) => (6, level as u64, 0, 0, 0),
        };
        let head = mix(tag, kind);
        let detail = mix(mix(head, shape), relation);
        Step {
            head,
            detail,
            syntax,
            relation,
        }
    }

    fn edge(&self, step: Step, prefix: u64, rule: u64, suffix: u64) -> Row {
        let Step {
            head,
            detail,
            syntax,
            relation,
        } = step;
        let field = self.field as u64;
        let goal = self.forms[self.goal].signature;
        row([
            mix(head, field),
            detail,
            mix(mix(head, field), goal.shape),
            mix(detail, rule),
            mix(detail, prefix),
            mix(mix(detail, syntax), goal.syntax),
            mix(detail, self.context_shape),
            mix(mix(head, rule), suffix),
            mix(head, self.forms[self.goal].kind as u64),
            mix(head, relation | (suffix << 5)),
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
#[cfg_attr(test, derive(Debug, PartialEq))]
pub(super) struct Menu {
    pub rows: Vec<Row>,
    pub roles: Vec<i32>,
    pub edges: Vec<Row>,
    pub priors: Vec<f32>,
    pub groups: Vec<Range<usize>>,
    pub paths: Vec<Vec<usize>>,
    pub aliases: Vec<f32>,
}

pub(super) struct Layout {
    pub goal: usize,
    pub context: Vec<usize>,
    pub candidates: Vec<usize>,
    pub successes: Vec<usize>,
}

impl Menu {
    /// The batch owner has validated topological node references and the menu.
    pub fn lower(graph: &Graph) -> Result<Self, Failure> {
        let mut nodes = TokenNodes::default();
        for node in &graph.nodes {
            nodes.lower_node(node);
        }
        for &candidate in &graph.candidates {
            let action = &graph.nodes[candidate];
            nodes.action(
                operands(&graph.nodes, action.left)?,
                operands(&graph.nodes, action.right)?,
            );
        }
        Ok(Self::from_nodes(
            nodes,
            graph.field,
            graph.goal,
            graph_goal_parts(graph),
            &graph.context,
            &graph.candidates,
        ))
    }

    pub fn from_typed(input: Encoded<TokenNodes>, field: Field) -> (Self, Layout) {
        let Encoded {
            nodes,
            goal,
            context,
            candidates,
            successes,
            ..
        } = input;
        // Typed construction emits the goal before any other formulas.
        let goal_parts = (0..nodes.len()).map(|i| i != 0 && i <= goal).collect();
        let menu = Self::from_nodes(nodes, field, goal, goal_parts, &context, &candidates);
        (
            menu,
            Layout {
                goal,
                context,
                candidates,
                successes,
            },
        )
    }

    fn from_nodes(
        nodes: TokenNodes,
        field: Field,
        goal: usize,
        goal_parts: Vec<bool>,
        context: &[usize],
        candidates: &[usize],
    ) -> Self {
        let input = Input::new(&nodes.forms, field, goal, goal_parts, context);
        let mut prefixes = vec![Prefix::default()];
        let mut leaves = Vec::with_capacity(candidates.len());
        for (&candidate, operands) in candidates.iter().zip(&nodes.actions) {
            let action = nodes.forms[candidate];
            let rule = action.kind as u64;
            let Operands { premises, effects } = operands;
            let suffix = effects
                .iter()
                .fold(0, |flags, &index| flags | input.relationship(index));
            let variant = if field == Field::QuestionRecipe {
                Token::Variation(action.symbol)
            } else {
                Token::Replacement(action.symbol)
            };
            let tokens = std::iter::once(Token::Rule(action.kind))
                .chain(premises.iter().copied().map(Token::Premise))
                .chain([variant])
                .chain(effects.iter().copied().map(Token::Effect))
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
        debug_assert!(edges.len() <= 2 * candidates.len().saturating_sub(1));
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
        Self {
            rows: nodes.rows,
            roles: nodes.roles,
            edges,
            priors,
            groups,
            paths,
            aliases,
        }
    }
}

fn graph_goal_parts(graph: &Graph) -> Vec<bool> {
    let mut parts = vec![false; graph.nodes.len()];
    parts[graph.goal] = true;
    for index in (1..=graph.goal).rev() {
        if parts[index] {
            let node = &graph.nodes[index];
            parts[node.left] = true;
            parts[node.right] = true;
        }
    }
    parts[0] = false;
    parts
}

#[cfg(test)]
mod tests;
