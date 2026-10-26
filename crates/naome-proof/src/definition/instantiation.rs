use super::*;
use crate::{DefinitionAccessError, DefinitionExpansionError};
use naome_foundation::{FORMULA_MAX_DEPTH, FORMULA_MAX_NODES, graph::Node};

/// Bounded traversal of one immutable, primitive definition certificate.
/// Each call visits at most one syntax node; no expanded formula is retained.
pub struct DefinitionInstantiation {
    canonical: Arc<[u8]>,
    arguments: Box<[u32]>,
    position: usize,
    pending: Vec<(u32, u32)>,
    visited: usize,
    failed: bool,
}
impl DefinitionInstantiation {
    pub(super) fn new(
        certificate: &DefinitionCertificate,
        arguments: &[u32],
    ) -> Result<Self, DefinitionExpansionError> {
        let expected = certificate.relation_arity() as usize;
        if arguments.len() != expected {
            return Err(DefinitionExpansionError::ArityMismatch {
                definition_id: certificate.definition_id(),
                expected,
                actual: arguments.len(),
            });
        }
        Ok(Self {
            canonical: certificate.canonical.clone(),
            arguments: arguments.into(),
            position: 9,
            pending: vec![(0, 0)],
            // The selected application itself has the same logical charge as
            // ordinary definition expansion, in addition to the body nodes.
            visited: 1,
            failed: false,
        })
    }
    pub fn complete(&self) -> bool {
        !self.failed && self.pending.is_empty() && self.position == self.canonical.len()
    }
    fn step(&mut self, depth: u32, binders: u32) -> Result<Node<()>, DefinitionExpansionError> {
        if self.visited == FORMULA_MAX_NODES {
            return Err(DefinitionExpansionError::NodeLimitExceeded {
                maximum: FORMULA_MAX_NODES,
            });
        }
        if depth >= FORMULA_MAX_DEPTH {
            return Err(DefinitionExpansionError::DepthLimitExceeded {
                maximum: FORMULA_MAX_DEPTH,
            });
        }
        self.visited += 1;
        let node = crate::defined_formula::instantiate_prefix(
            &self.canonical,
            &mut self.position,
            binders,
            &self.arguments,
        )?;
        match node {
            Node::Not(()) => self.pending.push((depth + 1, binders)),
            Node::Implies((), ()) => {
                self.pending.push((depth + 1, binders));
                self.pending.push((depth + 1, binders));
            }
            Node::ForAll(()) => self.pending.push((depth + 1, binders + 1)),
            Node::Equal(..) | Node::Member(..) => {}
        }
        Ok(node)
    }
}
impl Iterator for DefinitionInstantiation {
    type Item = Result<Node<()>, DefinitionExpansionError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let result = match self.pending.pop() {
            Some((depth, binders)) => self.step(depth, binders),
            None if self.position == self.canonical.len() => return None,
            None => Err(DefinitionExpansionError::Access(
                DefinitionAccessError::Corrupt,
            )),
        };
        if result.is_err() {
            self.failed = true;
        }
        Some(result)
    }
}
