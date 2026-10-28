//! Structure-preserving native formula graphs. Identifiers are not model features.

use super::model::Decision;
use burn::tensor::{Bool, Device, Int, Tensor, TensorData};
use naome_foundation::{
    Formula, FormulaView,
    graph::{Node as FormulaNode, Variable},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const MAX_NODES: usize = 256;
pub const MAX_CONTEXT: usize = 48;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub kind: i32,
    pub left: usize,
    pub right: usize,
    pub role: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Graph {
    pub binding: String,
    pub nodes: Vec<Node>,
    pub goal: usize,
    pub context: Vec<usize>,
    pub candidates: Vec<usize>,
    pub expert: usize,
    pub successes: Vec<usize>,
}

struct Builder {
    nodes: Vec<Node>,
    formulas: HashMap<(Formula, Vec<usize>, u8), usize>,
    variables: HashMap<(u8, u64), usize>,
}

impl Builder {
    fn push(&mut self, node: Node) -> Result<usize, String> {
        if self.nodes.len() >= MAX_NODES {
            return Err("formula_graph_capacity".into());
        }
        let index = self.nodes.len();
        self.nodes.push(node);
        Ok(index)
    }
    fn pair(&mut self, roots: &[usize]) -> Result<usize, String> {
        match roots {
            [] => Ok(0),
            [root] => Ok(*root),
            [left, right] => self.push(Node {
                kind: 14,
                left: *left,
                right: *right,
                role: 0,
            }),
            _ => Err("action arity capacity".into()),
        }
    }

    fn variable(&mut self, variable: Variable, binders: &[usize]) -> Result<usize, String> {
        let (key, kind, binder) = match variable {
            Variable::Free(id) => ((0, u64::from(id)), 6, 0),
            Variable::Bound(index) => {
                let index = usize::try_from(index).map_err(|_| "bound index width")?;
                let position = binders
                    .len()
                    .checked_sub(index + 1)
                    .ok_or("dangling bound variable")?;
                let binder = binders[position];
                ((1, binder as u64), 7, binder)
            }
        };
        if let Some(index) = self.variables.get(&key) {
            return Ok(*index);
        }
        let index = self.push(Node {
            kind,
            left: binder,
            right: 0,
            role: 0,
        })?;
        self.variables.insert(key, index);
        Ok(index)
    }

    fn formula(&mut self, formula: FormulaView<'_>, binders: &[usize]) -> Result<usize, String> {
        let key = (formula.to_owned(), binders.to_vec(), 0);
        if let Some(index) = self.formulas.get(&key) {
            return Ok(*index);
        }
        let mut node = Node {
            kind: 0,
            left: 0,
            right: 0,
            role: 0,
        };
        if let FormulaNode::ForAll(body) = formula.graph_node() {
            node.kind = 5;
            let index = self.push(node)?;
            let mut nested = binders.to_vec();
            nested.push(index);
            self.nodes[index].left = self.formula(body, &nested)?;
            self.formulas.insert(key, index);
            return Ok(index);
        }
        match formula.graph_node() {
            FormulaNode::Equal(a, b) | FormulaNode::Member(a, b) => {
                node.kind = if matches!(formula.graph_node(), FormulaNode::Equal(..)) {
                    1
                } else {
                    2
                };
                node.left = self.variable(a, binders)?;
                node.right = self.variable(b, binders)?;
            }
            FormulaNode::Not(body) => {
                node.kind = 3;
                node.left = self.formula(body, binders)?;
            }
            FormulaNode::Implies(left, right) => {
                node.kind = 4;
                node.left = self.formula(left, binders)?;
                node.right = self.formula(right, binders)?;
            }
            FormulaNode::ForAll(_) => unreachable!(),
        }
        let index = self.push(node)?;
        self.formulas.insert(key, index);
        Ok(index)
    }
}

impl Graph {
    pub fn work_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.nodes.len() * std::mem::size_of::<Node>()
            + (self.context.len() + self.candidates.len() + self.successes.len())
                * std::mem::size_of::<usize>()
            + self.binding.len()
            + 1024
    }
    pub fn key(&self) -> String {
        super::digest(&(
            &self.binding,
            &self.nodes,
            self.goal,
            &self.context,
            &self.candidates,
        ))
    }
    pub fn encode(decision: &Decision) -> Result<Self, String> {
        if decision.context.len() > MAX_CONTEXT || decision.candidates.is_empty() {
            return Err("decision_capacity".into());
        }
        let witnessed = decision
            .candidates
            .get(decision.expert)
            .ok_or("successful action missing")?;
        // A vacuous universal can be instantiated with different variables
        // while retaining the exact premise and conclusion. The checked proof
        // step is the same observable choice, so share its successful mass.
        // Distinct conclusions and every other rule keep separate labels.
        let successes = decision
            .candidates
            .iter()
            .enumerate()
            .filter(|(i, candidate)| {
                *i == decision.expert
                    || witnessed.rule == super::model::Rule::UniversalInstance
                        && witnessed.premises.len() == 1
                        && witnessed.consequences.len() == 1
                        && candidate.rule == witnessed.rule
                        && candidate.premises == witnessed.premises
                        && candidate.consequences == witnessed.consequences
            })
            .map(|(i, _)| i)
            .collect();
        let mut builder = Builder {
            nodes: vec![Node {
                kind: 0,
                left: 0,
                right: 0,
                role: 0,
            }],
            formulas: HashMap::new(),
            variables: HashMap::new(),
        };
        let goal = builder.formula(decision.goal.view(), &[])?;
        let mut context = Vec::new();
        for binding in &decision.context {
            let root = builder.formula(binding.formula.view(), &[])?;
            builder.nodes[root].role |= 2;
            context.push(root);
        }
        builder.nodes[goal].role |= 1;
        let mut candidates = Vec::new();
        for candidate in &decision.candidates {
            let premises = candidate
                .premises
                .iter()
                .map(|i| {
                    context
                        .get(*i)
                        .copied()
                        .ok_or("action premise missing".into())
                })
                .collect::<Result<Vec<_>, String>>()?;
            if premises.is_empty() {
                return Err("action premise missing".into());
            }
            let conclusions = candidate
                .consequences
                .iter()
                .map(|formula| builder.formula(formula.view(), &[]))
                .collect::<Result<Vec<_>, _>>()?;
            let left = builder.pair(&premises)?;
            let right = builder.pair(&conclusions)?;
            candidates.push(builder.push(Node {
                kind: candidate.rule.kind(),
                left,
                right,
                role: 0,
            })?);
        }
        Ok(Self {
            binding: String::new(),
            nodes: builder.nodes,
            goal,
            context,
            candidates,
            expert: decision.expert,
            successes,
        })
    }
}

pub struct Batch {
    pub kinds: Tensor<2, Int>,
    pub roles: Tensor<2, Int>,
    pub left: Tensor<2, Int>,
    pub right: Tensor<2, Int>,
    pub parent_scale: Tensor<3>,
    pub valid: Tensor<3>,
    pub goal: Tensor<2, Int>,
    pub context: Tensor<3>,
    pub candidates: Tensor<2, Int>,
    pub invalid: Tensor<2, Bool>,
    pub successes: Tensor<2>,
}

impl Batch {
    pub fn from_graphs<G: std::borrow::Borrow<Graph>>(
        graphs: &[G],
        device: &Device,
    ) -> Result<Self, String> {
        let graphs = graphs
            .iter()
            .map(std::borrow::Borrow::borrow)
            .collect::<Vec<_>>();
        if graphs.is_empty() {
            return Err("empty graph batch".into());
        }
        if graphs.len() > 16
            || graphs.iter().any(|g| {
                g.nodes.is_empty()
                    || g.nodes.len() > MAX_NODES
                    || g.candidates.is_empty()
                    || g.candidates.len() > 16
            })
        {
            return Err("graph batch capacity".into());
        }
        let b = graphs.len();
        // One shared zero sentinel and disjoint ranges for the actual nodes.
        // No graph is padded to another graph's size.
        let n = 1 + graphs.iter().map(|g| g.nodes.len() - 1).sum::<usize>();
        let c = graphs.iter().map(|g| g.candidates.len()).max().unwrap();
        let mut kinds = vec![0i32; n];
        let mut roles = kinds.clone();
        let mut left = kinds.clone();
        let mut right = kinds.clone();
        let mut parents = vec![0f32; n];
        let mut valid = vec![0f32; n];
        let mut goal = vec![0i32; b];
        let mut context = vec![0f32; b * n];
        let mut candidates = vec![0i32; b * c];
        let mut invalid = vec![true; b * c];
        let mut successes = vec![0f32; b * c];
        let mut base = 1;
        for (batch, graph) in graphs.iter().enumerate() {
            let index = |i: usize| -> Result<usize, String> {
                if i >= graph.nodes.len() {
                    Err("graph node binding differs".into())
                } else {
                    Ok(if i == 0 { 0 } else { base + i - 1 })
                }
            };
            for (i, node) in graph.nodes.iter().enumerate().skip(1) {
                let offset = index(i)?;
                kinds[offset] = node.kind;
                roles[offset] = node.role;
                left[offset] = index(node.left)? as i32;
                right[offset] = index(node.right)? as i32;
                valid[offset] = 1.;
                for child in [node.left, node.right].into_iter().filter(|i| *i != 0) {
                    parents[index(child)?] += 1.;
                }
            }
            goal[batch] = index(graph.goal)? as i32;
            for root in &graph.context {
                context[batch * n + index(*root)?] += 1. / graph.context.len() as f32;
            }
            for (i, root) in graph.candidates.iter().enumerate() {
                candidates[batch * c + i] = index(*root)? as i32;
                invalid[batch * c + i] = false;
            }
            if graph.successes.is_empty()
                || graph.successes.iter().any(|i| *i >= graph.candidates.len())
            {
                return Err("successful action binding differs".into());
            }
            for i in &graph.successes {
                successes[batch * c + i] = 1.;
            }
            base += graph.nodes.len() - 1;
        }
        for count in &mut parents {
            if *count > 0. {
                *count = 1. / *count;
            }
        }
        Ok(Self {
            kinds: Tensor::from_data(TensorData::new(kinds, [1, n]), device),
            roles: Tensor::from_data(TensorData::new(roles, [1, n]), device),
            left: Tensor::from_data(TensorData::new(left, [1, n]), device),
            right: Tensor::from_data(TensorData::new(right, [1, n]), device),
            parent_scale: Tensor::from_data(TensorData::new(parents, [1, n, 1]), device),
            valid: Tensor::from_data(TensorData::new(valid, [1, n, 1]), device),
            goal: Tensor::from_data(TensorData::new(goal, [b, 1]), device),
            context: Tensor::from_data(TensorData::new(context, [b, 1, n]), device),
            candidates: Tensor::from_data(TensorData::new(candidates, [b, c]), device),
            invalid: Tensor::from_data(TensorData::new(invalid, [b, c]), device),
            successes: Tensor::from_data(TensorData::new(successes, [b, c]), device),
        })
    }
}
