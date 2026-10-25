use super::*;
use naome_checker::diagnostics::{
    Digest, Failure, MAX_SOURCE_ORIGINS, ProofDiagnostic, SourceOrigin, VariableOrigin,
};
use naome_proof::ProofStepOrigins;

impl Parser<'_> {
    pub(super) fn argument<T>(
        &mut self,
        role: OperandRole,
        parse: impl FnOnce(&mut Self) -> Result<T, CompileError>,
    ) -> Result<T, CompileError> {
        let start = self.next_offset();
        self.pending_expansions.clear();
        self.expansions_complete = true;
        let value = parse(self)?;
        self.pending_arguments.push(ArgumentOrigin {
            role,
            index: None,
            range: SourceRange::new(start, self.offset).expect("source offsets fit"),
            expansions: std::mem::take(&mut self.pending_expansions),
            expansions_complete: self.expansions_complete,
        });
        Ok(value)
    }
    pub(super) fn record_expansion(&mut self, name: &str, offset: usize) {
        if let Some(origin) = self.binding_origins.get(name) {
            let edge = ExpansionOrigin {
                kind: origin.kind,
                name_digest: Digest::of(name.as_bytes()),
                usage: SourceRange::new(offset, offset + name.len()).expect("source offsets fit"),
                declaration: origin.range,
                definition_id: origin.definition_id,
                proof_id: origin.proof_id,
            };
            let edges = std::iter::once(edge).chain(origin.expansions.iter().cloned());
            for edge in edges {
                if self.pending_expansions.contains(&edge) {
                    continue;
                }
                if self.pending_expansions.len() == 16 {
                    self.expansions_complete = false;
                    break;
                }
                self.pending_expansions.push(edge);
            }
            self.expansions_complete &= origin.expansions_complete;
        }
    }
}

pub(super) fn attach_source(
    diagnostic: &mut ProofDiagnostic,
    source: &str,
    bindings: &HashMap<&str, StepBinding>,
    origins: &ProofStepOrigins,
    variable_names: &[(&str, FreeVariable)],
) {
    diagnostic.input.source_digest = Some(Digest::of(source.as_bytes()));
    let offending_parameters = match diagnostic.failure {
        Failure::DuplicateParameter { first, second, .. } => vec![first, second],
        Failure::ParameterRoleCollision { parameter, .. } => vec![parameter],
        _ => Vec::new(),
    };
    let source_origins = |step: u64| {
        let mut entries = Vec::new();
        let mut complete = true;
        if let Ok(step) = u32::try_from(step) {
            for position in origins.source_steps(step) {
                if entries.len() == MAX_SOURCE_ORIGINS {
                    complete = false;
                    break;
                }
                if let Some((name, binding)) = bindings
                    .iter()
                    .find(|(_, binding)| binding.position == position)
                {
                    let arguments = binding
                        .arguments
                        .iter()
                        .filter(|argument| {
                            argument.index.is_none_or(|index| {
                                index < 32 || offending_parameters.contains(&index)
                            })
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    let arguments_complete = arguments.len() == binding.arguments.len();
                    entries.push(SourceOrigin {
                        source_step: position,
                        name: bounded_name(name),
                        assignment: SourceRange::new(binding.span.start(), binding.span.end())
                            .expect("source offsets fit"),
                        arguments,
                        arguments_complete,
                    });
                }
            }
        }
        (entries, complete)
    };
    (
        diagnostic.location.origins,
        diagnostic.location.origins_complete,
    ) = source_origins(diagnostic.location.step);
    for operand in &mut diagnostic.operands {
        if let Some(reference) = operand.reference {
            (operand.origins, operand.origins_complete) = source_origins(reference);
        }
    }
    let mut variables = std::collections::BTreeSet::new();
    for operand in &diagnostic.operands {
        if let Some(variable) = operand.variable {
            variables.insert(variable);
        }
        if let Some(formula) = &operand.formula {
            variables.extend(&formula.free_variables);
        }
    }
    match diagnostic.failure {
        Failure::RoleCollision { variable, .. }
        | Failure::ParameterRoleCollision { variable, .. }
        | Failure::DuplicateParameter { variable, .. }
        | Failure::ForbiddenPredicateVariable { variable, .. }
        | Failure::UndeclaredPredicateVariable { variable } => {
            variables.insert(variable);
        }
        _ => {}
    }
    for (source_identifier, normalized_identifier) in origins.variables() {
        if !variables.contains(&normalized_identifier) {
            continue;
        }
        if diagnostic.variable_origins.len() == 128 {
            diagnostic.variable_origins_complete = false;
            break;
        }
        if let Some((name, _)) = variable_names
            .iter()
            .find(|(_, variable)| variable.identifier() == source_identifier)
        {
            // Names are borrowed tokens of this exact source. Pointer addresses
            // are used only to recover byte offsets, never exposed as identity.
            let start = name.as_ptr().addr() - source.as_ptr().addr();
            if let Some(range) = SourceRange::new(start, start + name.len()) {
                diagnostic.variable_origins.push(VariableOrigin {
                    source_identifier,
                    normalized_identifier,
                    name_preview: bounded_name(name),
                    name_digest: Digest::of(name.as_bytes()),
                    range,
                });
            }
        }
    }
    diagnostic.variable_origins_complete &= variables.iter().all(|identifier| {
        diagnostic
            .variable_origins
            .iter()
            .any(|origin| origin.normalized_identifier == *identifier)
    });
}

fn bounded_name(name: &str) -> String {
    let mut result = name
        .chars()
        .take(DIAGNOSTIC_NAME_MAX_SCALARS)
        .collect::<String>();
    if result.len() < name.len() {
        result.push_str("...");
    }
    result
}
