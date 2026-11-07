use super::*;
use naome_proof::{DefinitionExpansionError, DefinitionId, DefinitionInstantiation};

pub(super) struct DefinitionEvaluation {
    id: DefinitionId,
    arguments: Vec<u32>,
    nodes: Option<DefinitionInstantiation>,
    frames: Vec<Frame>,
    value: Option<u64>,
}
impl DefinitionEvaluation {
    pub(super) fn new(id: DefinitionId, arguments: Vec<u32>) -> Self {
        Self {
            id,
            arguments,
            nodes: None,
            frames: Vec::new(),
            value: None,
        }
    }
}
enum Frame {
    Not,
    ForAll,
    Implies(Option<u64>),
}
impl Engine {
    fn load_definition(
        &mut self,
        context: &dyn ContextView,
        id: DefinitionId,
        arguments: &[u32],
        query: Option<&crate::diagnostics::FormulaQuery>,
    ) -> Result<DefinitionInstantiation, Error> {
        self.observe_reference_context(context);
        let result = (|| {
            let certificate = context
                .definition_certificate(id)
                .map_err(|error| DefinitionExpansionError::Access(error.into()))?
                .ok_or(DefinitionExpansionError::UnknownDefinition { definition_id: id })?;
            certificate.instantiate(arguments)
        })();
        match result {
            Ok(nodes) => Ok(nodes),
            Err(DefinitionExpansionError::Access(source)) => {
                Err(crate::ContextError::from(source).into())
            }
            Err(source) => Err(Error::Check(Box::new(self.proof_diagnostic(
                &self.current_command()?,
                crate::diagnostics::Failure::Expansion {
                    reason: (&source).into(),
                },
                context,
                query,
            )?))),
        }
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
        let Some(nodes) = &mut definition.nodes else {
            if ContextRead::charge(&mut evaluation.context_read, context, || {
                context.definition_canonical_length(definition.id)
            })? {
                definition.nodes = Some(self.load_definition(
                    context,
                    definition.id,
                    &definition.arguments,
                    query,
                )?);
                definition.arguments = Vec::new();
            }
            return Ok(None);
        };
        if let Some(value) = definition.value.take() {
            let node = match definition.frames.pop() {
                None => {
                    if !nodes.complete() {
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
        let node = match nodes.next().ok_or(crate::ContextError::Corrupt)? {
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
