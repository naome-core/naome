//! Only checked contexts can issue a cited conclusion and its immutable reader.
use super::*;
use naome_foundation::graph::{FormulaGraphCursor, Node, Properties};
use std::sync::Arc;

pub struct ProgramSource {
    pub(crate) proof: ProofId,
    pub(crate) statement: StatementId,
    pub(crate) derivation: DerivationId,
    pub(crate) representation: ProgramRepresentation,
}

pub(crate) enum ProgramRepresentation {
    Formula(FormulaGraphCursor<u64>),
    Graph {
        root: [u8; 32],
        nodes: Arc<dyn ProgramNodes>,
    },
}

pub(crate) trait ProgramNodes: Send + Sync {
    fn read(&self, address: [u8; 32]) -> Result<(Node<[u8; 32]>, Properties), ContextError>;
}

impl ProgramSource {
    pub(crate) fn formula(proof: ProofId, header: ProofHeader, formula: Formula) -> Self {
        Self {
            proof,
            statement: header.statement,
            derivation: header.derivation,
            representation: ProgramRepresentation::Formula(formula.into_graph_cursor()),
        }
    }

    pub(crate) fn graph(
        proof: ProofId,
        header: ProofHeader,
        root: [u8; 32],
        nodes: Arc<dyn ProgramNodes>,
    ) -> Self {
        Self {
            proof,
            statement: header.statement,
            derivation: header.derivation,
            representation: ProgramRepresentation::Graph { root, nodes },
        }
    }
}
