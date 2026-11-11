//! Validated, disjoint token inputs and legal prefix routing for a model batch.
use super::token::{FEATURES, Menu, Row};
use crate::LearningGraphFailure as Failure;
use crate::learning::graph::{Graph, MAX_NODES, SYMBOLS};
use burn::tensor::{Bool, Device, Int, Tensor, TensorData};

const MAX_BATCH: usize = 16;
const MAX_ACTIONS: usize = 16;

pub(super) struct Batch {
    pub rows: Vec<Row>,
    pub roles: Tensor<2, Int>,
    pub valid: Tensor<3>,
    pub goal: Tensor<2, Int>,
    context: Tensor<2, Bool>,
    pub candidates: Tensor<2, Int>,
    pub invalid: Tensor<2, Bool>,
    pub successes: Tensor<2>,
    pub edges: Vec<Row>,
    pub priors: Tensor<2>,
    pub siblings: Tensor<3, Bool>,
    pub paths: Tensor<3>,
    pub aliases: Tensor<2>,
}

impl Batch {
    pub fn device(&self) -> Device {
        self.goal.device()
    }

    pub fn context_mask(&self) -> Tensor<2, Bool> {
        self.context.clone()
    }

    pub fn from_graphs<G: std::borrow::Borrow<Graph>>(
        graphs: &[G],
        device: &Device,
    ) -> Result<Self, Failure> {
        Self::pack(graphs, device, false)
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
        dense: bool,
    ) -> Result<Self, Failure> {
        if graphs.is_empty() {
            return Err(Failure::EmptyBatch);
        }
        if graphs.len() > MAX_BATCH {
            return Err(Failure::BatchCapacity);
        }
        let graphs = graphs
            .iter()
            .map(std::borrow::Borrow::borrow)
            .collect::<Vec<_>>();
        let menus = graphs
            .iter()
            .map(|graph| {
                Self::validate(graph)?;
                Menu::lower(graph)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let b = graphs.len();
        let n = 1 + graphs
            .iter()
            .map(|graph| graph.nodes.len() - 1)
            .sum::<usize>();
        let c = graphs
            .iter()
            .map(|graph| graph.candidates.len())
            .max()
            .unwrap();
        let e = menus
            .iter()
            .map(|menu| menu.edges.len())
            .max()
            .unwrap()
            .max(1);
        let mut rows = Vec::with_capacity(n);
        rows.push([0; FEATURES]);
        let mut roles = vec![0i32; n];
        let mut valid = vec![1f32; n];
        valid[0] = 0.;
        let mut goal = vec![0i32; b];
        let mut context = vec![true; b * n];
        let mut dense_context = dense.then(|| vec![0f32; b * n]);
        let mut candidates = vec![0i32; b * c];
        let mut invalid = vec![true; b * c];
        let mut successes = vec![0f32; b * c];
        let mut edges = vec![[0; FEATURES]; b * e];
        let mut priors = vec![0f32; b * e];
        let mut siblings = vec![true; b * e * e];
        let mut paths = vec![0f32; b * c * e];
        let mut aliases = vec![0f32; b * c];
        for (batch, (graph, menu)) in graphs.iter().zip(menus).enumerate() {
            let base = rows.len();
            let index = |node| if node == 0 { 0 } else { base + node - 1 };
            rows.extend(menu.rows.into_iter().skip(1));
            for (i, node) in graph.nodes.iter().enumerate().skip(1) {
                roles[index(i)] = node.role;
            }
            goal[batch] = index(graph.goal) as i32;
            for &root in &graph.context {
                let offset = batch * n + index(root);
                if let Some(weights) = &mut dense_context {
                    weights[offset] += 1. / graph.context.len() as f32;
                } else {
                    context[offset] = false;
                }
            }
            for (i, &root) in graph.candidates.iter().enumerate() {
                candidates[batch * c + i] = index(root) as i32;
                invalid[batch * c + i] = false;
                aliases[batch * c + i] = menu.aliases[i];
                for &edge in &menu.paths[i] {
                    paths[(batch * c + i) * e + edge] = 1.;
                }
            }
            for &i in &graph.successes {
                successes[batch * c + i] = 1.;
            }
            edges[batch * e..batch * e + menu.edges.len()].copy_from_slice(&menu.edges);
            priors[batch * e..batch * e + menu.priors.len()].copy_from_slice(&menu.priors);
            for group in menu.groups {
                for i in group.clone() {
                    let offset = (batch * e + i) * e;
                    siblings[offset + group.start..offset + group.end].fill(false);
                }
            }
            // Every padded row has a defined normalizer and no action uses it.
            for i in menu.edges.len()..e {
                siblings[(batch * e + i) * e + i] = false;
            }
        }
        let context = if let Some(weights) = dense_context {
            Tensor::<2>::from_data(TensorData::new(weights, [b, n]), device).equal_elem(0.)
        } else {
            Tensor::from_data(TensorData::new(context, [b, n]), device)
        };
        Ok(Self {
            rows,
            roles: Tensor::from_data(TensorData::new(roles, [1, n]), device),
            valid: Tensor::from_data(TensorData::new(valid, [1, n, 1]), device),
            goal: Tensor::from_data(TensorData::new(goal, [b, 1]), device),
            context,
            candidates: Tensor::from_data(TensorData::new(candidates, [b, c]), device),
            invalid: Tensor::from_data(TensorData::new(invalid, [b, c]), device),
            successes: Tensor::from_data(TensorData::new(successes, [b, c]), device),
            edges,
            priors: Tensor::from_data(TensorData::new(priors, [b, e]), device),
            siblings: Tensor::from_data(TensorData::new(siblings, [b, e, e]), device),
            paths: Tensor::from_data(TensorData::new(paths, [b, c, e]), device),
            aliases: Tensor::from_data(TensorData::new(aliases, [b, c]), device),
        })
    }

    fn validate(graph: &Graph) -> Result<(), Failure> {
        let n = graph.nodes.len();
        let c = graph.candidates.len();
        if n == 0 || n > MAX_NODES || c == 0 || c > MAX_ACTIONS {
            return Err(Failure::BatchCapacity);
        }
        if graph.goal >= n
            || graph
                .context
                .iter()
                .chain(&graph.candidates)
                .any(|&i| i >= n)
        {
            return Err(Failure::NodeBinding);
        }
        let sentinel = &graph.nodes[0];
        if sentinel.kind != 0
            || sentinel.left != 0
            || sentinel.right != 0
            || sentinel.symbol != 0
            || graph.nodes.iter().enumerate().skip(1).any(|(i, node)| {
                node.left >= i
                    || node.right >= i
                    || !(0..SYMBOLS as i32).contains(&node.symbol)
                    || !(0..4).contains(&node.role)
            })
        {
            return Err(Failure::NodeOperandOrSymbol);
        }
        if graph.successes.is_empty() || graph.successes.iter().any(|&i| i >= c) {
            return Err(Failure::SuccessfulActionBinding);
        }
        Ok(())
    }
}
