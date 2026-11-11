//! Symbolic decision records with interned formulas and decision-local references.

use super::model::Decision;
use crate::LearningGraphFailure as Failure;
use naome_foundation::{
    FormulaView,
    graph::{Node as FormulaNode, Variable},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const MAX_NODES: usize = 256;
pub const MAX_CONTEXT: usize = 48;
pub(super) const SYMBOLS: usize = 2 * MAX_NODES + 1;
pub(super) const NEGATION: i32 = 3;
pub(super) const PAIR: i32 = 14;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Node {
    pub kind: i32,
    pub left: usize,
    pub right: usize,
    pub role: i32,
    pub symbol: i32,
}

/// The grammar slot the checker and search are supplying to the policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub(crate) enum Field {
    #[default]
    Action,
    Operation,
    ConjunctionLeft,
    ConjunctionRight,
    Universal,
    Replacement,
    Premise,
    Definition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Graph {
    pub binding: String,
    pub(crate) field: Field,
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
                kind: PAIR,
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
                node.kind = NEGATION;
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
            self.field,
            &self.nodes,
            self.goal,
            &self.context,
            &self.candidates,
        ))
    }
    pub fn encode(decision: &Decision) -> Result<Self, Failure> {
        Self::encode_at_depth(decision, usize::MAX)
    }

    pub(super) fn encode_field(decision: &Decision, field: Field) -> Result<Self, Failure> {
        let mut graph = Self::encode(decision)?;
        graph.field = field;
        Ok(graph)
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
            field: Field::Action,
            nodes: builder.nodes,
            goal,
            context,
            candidates,
            expert: decision.expert,
            successes,
        })
    }
}
