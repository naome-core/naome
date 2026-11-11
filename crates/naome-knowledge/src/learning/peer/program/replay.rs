//! In-memory replay uses a shared table of exact local graph records.
use super::Graph;
use crate::learning::graph::Node;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(in crate::learning::peer) struct Decisions {
    nodes: Vec<Node>,
    ids: HashMap<Node, u32>,
    rows: Vec<Row>,
    unique: usize,
}

struct Row {
    shape: Graph,
    nodes: Box<[u32]>,
}

impl Decisions {
    pub(super) fn push(&mut self, mut graph: Graph) {
        let nodes = std::mem::take(&mut graph.nodes)
            .into_iter()
            .map(|node| {
                *self.ids.entry(node.clone()).or_insert_with(|| {
                    let id = self.nodes.len() as u32;
                    self.nodes.push(node);
                    id
                })
            })
            .collect();
        self.rows.push(Row {
            shape: graph,
            nodes,
        });
    }

    pub(super) fn finish(mut self) -> Self {
        self.ids = HashMap::new();
        // The local node IDs preserve exact node equality across every row.
        // Count the same fields as Graph::key using the already interned rows.
        self.unique = self
            .rows
            .iter()
            .map(|row| {
                let graph = &row.shape;
                (
                    graph.binding.as_str(),
                    graph.field as u8,
                    row.nodes.as_ref(),
                    graph.goal,
                    graph.context.as_slice(),
                    graph.candidates.as_slice(),
                )
            })
            .collect::<HashSet<_>>()
            .len();
        self
    }

    pub(in crate::learning::peer) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub(in crate::learning::peer) fn unique(&self) -> usize {
        self.unique
    }

    pub(in crate::learning::peer) fn materialize(&self) -> Vec<Graph> {
        self.rows
            .iter()
            .map(|row| Graph {
                nodes: row
                    .nodes
                    .iter()
                    .map(|id| self.nodes[*id as usize].clone())
                    .collect(),
                ..row.shape.clone()
            })
            .collect()
    }

    pub(super) fn work_bytes(&self) -> usize {
        self.nodes.capacity() * std::mem::size_of::<Node>()
            + self
                .rows
                .iter()
                .map(|row| row.shape.work_bytes() + row.nodes.len() * std::mem::size_of::<u32>())
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_program_decisions_share_exact_graph_records() {
        let example = crate::learning::tests::own_example();
        let question =
            naome_checker::question::ResearchQuestion::from_hex(&example.question).unwrap();
        let graph = crate::learning::search::compile(question.proved_target(), &example.tree)
            .unwrap()
            .1
            .remove(0);
        let mut second = graph.clone();
        second.binding = "01".repeat(32);
        let bytes = 2 * graph.work_bytes() + second.work_bytes();
        let mut tape = Decisions::default();
        tape.push(graph.clone());
        tape.push(second.clone());
        tape.push(graph.clone());
        let tape = tape.finish();
        assert!(tape.work_bytes() < bytes);
        assert_eq!(tape.unique(), 2);
        let materialized = tape.materialize();
        assert_eq!(materialized.len(), 3);
        for (actual, expected) in materialized.iter().zip([&graph, &second, &graph]) {
            assert_eq!(actual.key(), expected.key());
            assert_eq!(actual.successes, expected.successes);
            assert_eq!(actual.expert, expected.expert);
        }
    }
}
