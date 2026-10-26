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
    pub nodes: Vec<Node>,
    pub goal: usize,
    pub context: Vec<usize>,
    pub candidates: Vec<usize>,
    pub expert: usize,
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
    pub fn encode(decision: &Decision) -> Result<Self, String> {
        if decision.context.len() > MAX_CONTEXT || decision.candidates.is_empty() {
            return Err("decision_capacity".into());
        }
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
            nodes: builder.nodes,
            goal,
            context,
            candidates,
            expert: decision.expert,
        })
    }
}

pub struct Batch {
    pub kinds: Tensor<2, Int>,
    pub roles: Tensor<2, Int>,
    pub left: Tensor<2, Int>,
    pub right: Tensor<2, Int>,
    pub parents: Tensor<3>,
    pub valid: Tensor<3>,
    pub goal: Tensor<2, Int>,
    pub context: Tensor<3>,
    pub candidates: Tensor<2, Int>,
    pub invalid: Tensor<2, Bool>,
    pub targets: Tensor<1, Int>,
}

impl Batch {
    pub fn new(decisions: &[Decision], device: &Device) -> Result<Self, String> {
        if decisions.is_empty() {
            return Err("empty model batch".into());
        }
        let graphs = decisions
            .iter()
            .map(Graph::encode)
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_graphs(&graphs, device)
    }

    pub fn from_graphs(graphs: &[Graph], device: &Device) -> Result<Self, String> {
        if graphs.is_empty() {
            return Err("empty graph batch".into());
        }
        let b = graphs.len();
        let n = graphs
            .iter()
            .map(|g| g.nodes.len())
            .max()
            .unwrap()
            .next_power_of_two()
            .max(16);
        let c = graphs.iter().map(|g| g.candidates.len()).max().unwrap();
        let mut kinds = vec![0i32; b * n];
        let mut roles = kinds.clone();
        let mut left = kinds.clone();
        let mut right = kinds.clone();
        let mut parents = vec![0f32; b * n * n];
        let mut valid = vec![0f32; b * n];
        let mut goal = vec![0i32; b];
        let mut context = vec![0f32; b * n];
        let mut candidates = vec![0i32; b * c];
        let mut invalid = vec![true; b * c];
        let mut targets = vec![0i32; b];
        for (batch, graph) in graphs.iter().enumerate() {
            for (i, node) in graph.nodes.iter().enumerate().skip(1) {
                let offset = batch * n + i;
                kinds[offset] = node.kind;
                roles[offset] = node.role;
                left[offset] = node.left as i32;
                right[offset] = node.right as i32;
                valid[offset] = 1.;
                for child in [node.left, node.right]
                    .into_iter()
                    .filter(|child| *child != 0)
                {
                    parents[batch * n * n + child * n + i] += 1.;
                }
            }
            for i in 1..graph.nodes.len() {
                let row = &mut parents[batch * n * n + i * n..batch * n * n + (i + 1) * n];
                let total: f32 = row.iter().sum();
                if total > 0. {
                    row.iter_mut().for_each(|x| *x /= total);
                }
            }
            goal[batch] = graph.goal as i32;
            for root in &graph.context {
                context[batch * n + root] += 1. / graph.context.len() as f32;
            }
            for (i, root) in graph.candidates.iter().enumerate() {
                candidates[batch * c + i] = *root as i32;
                invalid[batch * c + i] = false;
            }
            targets[batch] = graph.expert as i32;
        }
        Ok(Self {
            kinds: Tensor::from_data(TensorData::new(kinds, [b, n]), device),
            roles: Tensor::from_data(TensorData::new(roles, [b, n]), device),
            left: Tensor::from_data(TensorData::new(left, [b, n]), device),
            right: Tensor::from_data(TensorData::new(right, [b, n]), device),
            parents: Tensor::from_data(TensorData::new(parents, [b, n, n]), device),
            valid: Tensor::from_data(TensorData::new(valid, [b, n, 1]), device),
            goal: Tensor::from_data(TensorData::new(goal, [b, 1]), device),
            context: Tensor::from_data(TensorData::new(context, [b, 1, n]), device),
            candidates: Tensor::from_data(TensorData::new(candidates, [b, c]), device),
            invalid: Tensor::from_data(TensorData::new(invalid, [b, c]), device),
            targets: Tensor::from_data(TensorData::new(targets, [b]), device),
        })
    }
}
