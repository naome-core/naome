//! Packed formula and action graphs with decision-local variable slots.

use super::model::Decision;
use crate::LearningGraphFailure as Failure;
use burn::tensor::{Bool, Device, Int, Tensor, TensorData};
use naome_foundation::{
    FormulaView,
    graph::{Node as FormulaNode, Variable},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const MAX_NODES: usize = 256;
pub const MAX_CONTEXT: usize = 48;
pub(super) const SYMBOLS: usize = 2 * MAX_NODES + 1;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Node {
    pub kind: i32,
    pub left: usize,
    pub right: usize,
    pub role: i32,
    pub symbol: i32,
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

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Capacity => "formula_graph_capacity",
            Self::ActionArity => "action arity capacity",
            Self::BoundIndexWidth => "bound index width",
            Self::DanglingBoundVariable => "dangling bound variable",
            Self::DecisionCapacity => "decision_capacity",
            Self::MissingExpert => "successful action missing",
            Self::MissingPremise => "action premise missing",
            Self::EmptyBatch => "empty graph batch",
            Self::BatchCapacity => "graph batch capacity",
            Self::NodeBinding => "graph node binding differs",
            Self::NodeOperandOrSymbol => "formula graph operand or symbol differs",
            Self::SuccessfulActionBinding => "successful action binding differs",
        })
    }
}

impl From<Failure> for String {
    fn from(error: Failure) -> Self {
        error.to_string()
    }
}

struct Builder<'a> {
    nodes: Vec<Node>,
    formulas: HashMap<(FormulaView<'a>, usize), usize>,
    variables: HashMap<i32, usize>,
    free: HashMap<u32, usize>,
}

impl<'a> Builder<'a> {
    fn push(&mut self, node: Node) -> Result<usize, Failure> {
        if self.nodes.len() >= MAX_NODES {
            return Err(Failure::Capacity);
        }
        let index = self.nodes.len();
        self.nodes.push(node);
        Ok(index)
    }
    fn pair(&mut self, roots: &[usize]) -> Result<usize, Failure> {
        if roots.len() > 1 + naome_proof::program::ACTION_PREMISES {
            return Err(Failure::ActionArity);
        }
        let Some((&first, rest)) = roots.split_first() else {
            return Ok(0);
        };
        rest.iter().try_fold(first, |left, &right| {
            self.push(Node {
                kind: 14,
                left,
                right,
                role: 0,
                symbol: 0,
            })
        })
    }

    fn free_slot(&mut self, id: u32) -> Result<i32, Failure> {
        let next = self.free.len() + 1;
        let slot = *self.free.entry(id).or_insert(next);
        if slot > MAX_NODES {
            return Err(Failure::Capacity);
        }
        Ok(slot as i32)
    }

    fn variable(&mut self, variable: Variable, binders: usize) -> Result<usize, Failure> {
        let (kind, symbol) = match variable {
            Variable::Free(id) => (6, self.free_slot(id)? as usize),
            Variable::Bound(index) => {
                let index = usize::try_from(index).map_err(|_| Failure::BoundIndexWidth)?;
                if index >= binders {
                    return Err(Failure::DanglingBoundVariable);
                }
                (7, MAX_NODES + 1 + index)
            }
        };
        if symbol >= SYMBOLS {
            return Err(Failure::Capacity);
        }
        let symbol = symbol as i32;
        if let Some(index) = self.variables.get(&symbol) {
            return Ok(*index);
        }
        let index = self.push(Node {
            kind,
            left: 0,
            right: 0,
            role: 0,
            symbol,
        })?;
        self.variables.insert(symbol, index);
        Ok(index)
    }

    fn formula(
        &mut self,
        formula: FormulaView<'a>,
        binders: usize,
        depth: usize,
    ) -> Result<usize, Failure> {
        if depth == 0 {
            return Ok(0);
        }
        let key = (formula, depth);
        let children = if depth == usize::MAX {
            depth
        } else {
            depth - 1
        };
        if let Some(index) = self.formulas.get(&key) {
            return Ok(*index);
        }
        let mut node = Node {
            kind: 0,
            left: 0,
            right: 0,
            role: 0,
            symbol: 0,
        };
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
                node.left = self.formula(body, binders, children)?;
            }
            FormulaNode::Implies(left, right) => {
                node.kind = 4;
                node.left = self.formula(left, binders, children)?;
                node.right = self.formula(right, binders, children)?;
            }
            FormulaNode::ForAll(body) => {
                node.kind = 5;
                node.left = self.formula(body, binders + 1, children)?;
            }
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
    pub fn encode(decision: &Decision) -> Result<Self, Failure> {
        Self::encode_at_depth(decision, usize::MAX)
    }

    /// A bounded view of existing checked operands, for replay choices whose
    /// full formulas cannot jointly fit the model's graph.
    pub(super) fn encode_at_depth(decision: &Decision, depth: usize) -> Result<Self, Failure> {
        if decision.context.len() > MAX_CONTEXT || decision.candidates.is_empty() {
            return Err(Failure::DecisionCapacity);
        }
        let witnessed = decision
            .candidates
            .get(decision.expert)
            .ok_or(Failure::MissingExpert)?;
        // Equivalent universal effects share the checked target mass and
        // the same model representation, including a vacuous instantiation.
        let equivalent = |a: &super::model::Candidate, b: &super::model::Candidate| {
            a.rule == super::model::Rule::UniversalInstance
                && a.rule == b.rule
                && a.premises == b.premises
                && a.consequences == b.consequences
        };
        let successes = decision
            .candidates
            .iter()
            .enumerate()
            .filter(|(i, candidate)| *i == decision.expert || equivalent(witnessed, candidate))
            .map(|(i, _)| i)
            .collect();
        let mut builder = Builder {
            nodes: vec![Node {
                kind: 0,
                left: 0,
                right: 0,
                role: 0,
                symbol: 0,
            }],
            formulas: HashMap::new(),
            variables: HashMap::new(),
            free: HashMap::new(),
        };
        let goal = builder.formula(decision.goal.view(), 0, depth)?;
        let mut context = Vec::new();
        for binding in &decision.context {
            let root = builder.formula(binding.formula.view(), 0, depth)?;
            builder.nodes[root].role |= 2;
            context.push(root);
        }
        builder.nodes[goal].role |= 1;
        let mut candidates = Vec::new();
        for (position, candidate) in decision.candidates.iter().enumerate() {
            let premises = candidate
                .premises
                .iter()
                .map(|i| context.get(*i).copied().ok_or(Failure::MissingPremise))
                .collect::<Result<Vec<_>, Failure>>()?;
            if premises.is_empty() {
                return Err(Failure::MissingPremise);
            }
            let conclusions = candidate
                .consequences
                .iter()
                .map(|formula| builder.formula(formula.view(), 0, depth))
                .collect::<Result<Vec<_>, _>>()?;
            let left = builder.pair(&premises)?;
            let right = builder.pair(&conclusions)?;
            let redundant = candidate.replacement.is_some()
                && decision
                    .candidates
                    .iter()
                    .enumerate()
                    .any(|(other, action)| position != other && equivalent(candidate, action));
            let symbol = if redundant {
                0
            } else {
                candidate
                    .replacement
                    .map(|v| builder.free_slot(v.identifier()))
                    .transpose()?
                    .unwrap_or(0)
            };
            candidates.push(builder.push(Node {
                kind: candidate.rule.kind(),
                left,
                right,
                role: 0,
                symbol,
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

enum ContextMask {
    Packed(Vec<bool>),
    #[cfg(test)]
    Dense(Vec<f32>),
}

impl ContextMask {
    fn include(&mut self, index: usize, _multiplicity: usize) {
        match self {
            Self::Packed(rows) => rows[index] = false,
            #[cfg(test)]
            Self::Dense(rows) => rows[index] += 1. / _multiplicity as f32,
        }
    }

    fn tensor(self, shape: [usize; 2], device: &Device) -> Tensor<2, Bool> {
        match self {
            Self::Packed(rows) => Tensor::from_data(TensorData::new(rows, shape), device),
            #[cfg(test)]
            Self::Dense(rows) => {
                Tensor::<2>::from_data(TensorData::new(rows, shape), device).equal_elem(0.)
            }
        }
    }
}

pub struct Batch {
    pub kinds: Tensor<2, Int>,
    pub roles: Tensor<2, Int>,
    pub left: Tensor<2, Int>,
    pub right: Tensor<2, Int>,
    pub symbols: Tensor<2, Int>,
    pub(super) nodes: Vec<Node>,
    pub valid: Tensor<3>,
    pub goal: Tensor<2, Int>,
    context_mask: Tensor<2, Bool>,
    pub candidates: Tensor<2, Int>,
    pub invalid: Tensor<2, Bool>,
    pub successes: Tensor<2>,
}

impl Batch {
    pub fn context_mask(&self) -> Tensor<2, Bool> {
        self.context_mask.clone()
    }

    pub fn from_graphs<G: std::borrow::Borrow<Graph>>(
        graphs: &[G],
        device: &Device,
    ) -> Result<Self, Failure> {
        Self::pack(
            graphs,
            device,
            #[cfg(test)]
            false,
        )
    }

    #[cfg(test)]
    pub fn from_dense_context<G: std::borrow::Borrow<Graph>>(
        graphs: &[G],
        device: &Device,
    ) -> Result<Self, Failure> {
        Self::pack(graphs, device, true)
    }

    fn pack<G: std::borrow::Borrow<Graph>>(
        graphs: &[G],
        device: &Device,
        #[cfg(test)] dense: bool,
    ) -> Result<Self, Failure> {
        let graphs = graphs
            .iter()
            .map(std::borrow::Borrow::borrow)
            .collect::<Vec<_>>();
        if graphs.is_empty() {
            return Err(Failure::EmptyBatch);
        }
        if graphs.len() > 16
            || graphs.iter().any(|g| {
                g.nodes.is_empty()
                    || g.nodes.len() > MAX_NODES
                    || g.candidates.is_empty()
                    || g.candidates.len() > 16
            })
        {
            return Err(Failure::BatchCapacity);
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
        let mut symbols = kinds.clone();
        let mut nodes = vec![graphs[0].nodes[0].clone()];
        let mut valid = vec![0f32; n];
        let mut goal = vec![0i32; b];
        // Attention uses only membership. Build the bool mask directly
        // from indexed context handles without materializing float weights.
        #[cfg(test)]
        let mut context = if dense {
            ContextMask::Dense(vec![0.; b * n])
        } else {
            ContextMask::Packed(vec![true; b * n])
        };
        #[cfg(not(test))]
        let mut context = ContextMask::Packed(vec![true; b * n]);
        let mut candidates = vec![0i32; b * c];
        let mut invalid = vec![true; b * c];
        let mut successes = vec![0f32; b * c];
        let mut base = 1;
        for (batch, graph) in graphs.iter().enumerate() {
            let index = |i: usize| -> Result<usize, Failure> {
                if i >= graph.nodes.len() {
                    Err(Failure::NodeBinding)
                } else {
                    Ok(if i == 0 { 0 } else { base + i - 1 })
                }
            };
            for (i, node) in graph.nodes.iter().enumerate().skip(1) {
                let offset = index(i)?;
                kinds[offset] = node.kind;
                roles[offset] = node.role;
                if node.left >= i || node.right >= i || !(0..SYMBOLS as i32).contains(&node.symbol)
                {
                    return Err(Failure::NodeOperandOrSymbol);
                }
                let left_index = index(node.left)?;
                let right_index = index(node.right)?;
                left[offset] = left_index as i32;
                right[offset] = right_index as i32;
                symbols[offset] = node.symbol;
                valid[offset] = 1.;
                nodes.push(Node {
                    left: left_index,
                    right: right_index,
                    ..node.clone()
                });
            }
            goal[batch] = index(graph.goal)? as i32;
            for root in &graph.context {
                context.include(batch * n + index(*root)?, graph.context.len());
            }
            for (i, root) in graph.candidates.iter().enumerate() {
                candidates[batch * c + i] = index(*root)? as i32;
                invalid[batch * c + i] = false;
            }
            if graph.successes.is_empty()
                || graph.successes.iter().any(|i| *i >= graph.candidates.len())
            {
                return Err(Failure::SuccessfulActionBinding);
            }
            for i in &graph.successes {
                successes[batch * c + i] = 1.;
            }
            base += graph.nodes.len() - 1;
        }
        Ok(Self {
            kinds: Tensor::from_data(TensorData::new(kinds, [1, n]), device),
            roles: Tensor::from_data(TensorData::new(roles, [1, n]), device),
            left: Tensor::from_data(TensorData::new(left, [1, n]), device),
            right: Tensor::from_data(TensorData::new(right, [1, n]), device),
            symbols: Tensor::from_data(TensorData::new(symbols, [1, n]), device),
            nodes,
            valid: Tensor::from_data(TensorData::new(valid, [1, n, 1]), device),
            goal: Tensor::from_data(TensorData::new(goal, [b, 1]), device),
            context_mask: context.tensor([b, n], device),
            candidates: Tensor::from_data(TensorData::new(candidates, [b, c]), device),
            invalid: Tensor::from_data(TensorData::new(invalid, [b, c]), device),
            successes: Tensor::from_data(TensorData::new(successes, [b, c]), device),
        })
    }
}
