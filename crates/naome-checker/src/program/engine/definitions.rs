use super::*;
use naome_proof::{DefinitionExpansionError, DefinitionId, DefinitionInstantiation};

pub(super) struct DefinitionEvaluation {
    id: DefinitionId,
    nodes: DefinitionInstantiation,
    frames: Vec<Frame>,
    value: Option<u64>,
}
enum Frame {
    Not,
    ForAll,
    Implies(Option<u64>),
}
impl Engine {
    pub(super) fn begin_definition(
        &mut self,
        context: &dyn ContextView,
        id: DefinitionId,
        arguments: &[u32],
        command: &Command,
        query: Option<&crate::diagnostics::FormulaQuery>,
    ) -> Result<DefinitionEvaluation, Error> {
        self.observe_reference_context(context);
        let result = (|| {
            let certificate = context
                .definition_certificate(id)
                .map_err(|error| DefinitionExpansionError::Access(error.into()))?
                .ok_or(DefinitionExpansionError::UnknownDefinition { definition_id: id })?;
            certificate.instantiate(arguments)
        })();
        let nodes = match result {
            Ok(nodes) => nodes,
            Err(DefinitionExpansionError::Access(source)) => {
                return Err(crate::ContextError::from(source).into());
            }
            Err(source) => {
                return Err(Error::Check(Box::new(self.proof_diagnostic(
                    command,
                    crate::diagnostics::Failure::Expansion {
                        reason: (&source).into(),
                    },
                    context,
                    query,
                )?)));
            }
        };
        Ok(DefinitionEvaluation {
            id,
            nodes,
            frames: Vec::new(),
            value: None,
        })
    }

    pub(super) fn advance_definition(
        &mut self,
        evaluation: &mut Evaluation,
        context: &dyn ContextView,
        query: Option<&crate::diagnostics::FormulaQuery>,
    ) -> Result<Option<u64>, Error> {
        let definition = evaluation
            .definition
            .as_mut()
            .ok_or(crate::ContextError::Corrupt)?;
        if let Some(value) = definition.value.take() {
            let node = match definition.frames.pop() {
                None => {
                    if !definition.nodes.complete() {
                        return Err(crate::ContextError::Corrupt.into());
                    }
                    sql(self.connection.execute(
                        "INSERT OR IGNORE INTO checked_definition VALUES(?1)",
                        [definition.id.as_bytes().as_slice()],
                    ))?;
                    evaluation.definition = None;
                    return Ok(Some(value));
                }
                Some(Frame::Not) => Node::Not(value),
                Some(Frame::ForAll) => Node::ForAll(value),
                Some(Frame::Implies(None)) => {
                    definition.frames.push(Frame::Implies(Some(value)));
                    return Ok(None);
                }
                Some(Frame::Implies(Some(left))) => Node::Implies(left, value),
            };
            definition.value = Some(self.intern(node)?);
            return Ok(None);
        }
        let node = match definition
            .nodes
            .next()
            .ok_or(crate::ContextError::Corrupt)?
        {
            Ok(node) => node,
            Err(DefinitionExpansionError::Access(source)) => {
                return Err(crate::ContextError::from(source).into());
            }
            Err(source) => {
                return Err(Error::Check(Box::new(self.proof_diagnostic(
                    &self.current_command()?,
                    crate::diagnostics::Failure::Expansion {
                        reason: (&source).into(),
                    },
                    context,
                    query,
                )?)));
            }
        };
        match node {
            Node::Equal(left, right) => {
                definition.value = Some(self.intern(Node::Equal(left, right))?)
            }
            Node::Member(left, right) => {
                definition.value = Some(self.intern(Node::Member(left, right))?)
            }
            Node::Not(()) => definition.frames.push(Frame::Not),
            Node::ForAll(()) => definition.frames.push(Frame::ForAll),
            Node::Implies((), ()) => definition.frames.push(Frame::Implies(None)),
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
