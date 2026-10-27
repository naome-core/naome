//! Canonical bounded formula signals shared by research and training selection.
use naome_authoring::CompiledQuestion;
use naome_foundation::graph::Node;
use serde::{Deserialize, Serialize};

pub(crate) const SIGNALS: usize = 32;
pub(crate) const SCALE: u64 = 65_536;

/// Primitive syntax and parent/child relationships, independent of spelling,
/// source names and variable names. Similarity never establishes equivalence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Features {
    pub(crate) counts: [u16; SIGNALS],
    pub(crate) nodes: u16,
    pub(crate) depth: u16,
    pub(crate) family: u16,
}
impl Features {
    pub(crate) fn of(question: &CompiledQuestion) -> Self {
        let mut counts = [0u16; SIGNALS];
        let _: Result<u8, std::convert::Infallible> = question.core().fold_graph(|node| {
            let tag = match node {
                Node::Equal(a, b) => {
                    counts[25 + usize::from(a != b)] += 1;
                    0
                }
                Node::Member(a, b) => {
                    counts[27 + usize::from(a != b)] += 1;
                    1
                }
                Node::Not(_) => 2,
                Node::Implies(..) => 3,
                Node::ForAll(_) => 4,
            };
            for child in node.children().into_iter().flatten() {
                counts[usize::from(tag) * 5 + usize::from(child)] += 1;
            }
            if tag == 4 {
                counts[29] += 1;
            }
            if tag == 3 {
                counts[30] += 1;
            }
            if tag == 2 {
                counts[31] += 1;
            }
            Ok(tag)
        });
        let (nodes, depth) = question.core().view().node_count_and_depth();
        let atoms =
            u16::from(counts[25] + counts[26] > 0) + 2 * u16::from(counts[27] + counts[28] > 0);
        let family = atoms * 16
            + counts[29].min(3) * 4
            + u16::from(counts[30] > 0)
            + 2 * u16::from(counts[31] > 0);
        Self {
            counts,
            nodes: nodes as u16,
            depth: depth as u16,
            family,
        }
    }
    pub(crate) fn similarity(&self, other: &Self) -> u64 {
        let (intersection, union) = self
            .counts
            .iter()
            .zip(other.counts)
            .fold((0u64, 0u64), |(a, b), (&x, y)| {
                (a + u64::from(x.min(y)), b + u64::from(x.max(y)))
            });
        intersection * SCALE / union.max(1)
    }
}
