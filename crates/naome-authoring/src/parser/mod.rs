//! One parser state, compilation order, and variable allocation.

use super::*;
use crate::CompileErrorKind as CompileError;
mod diagnostics;
use naome_checker::diagnostics::{
    ArgumentOrigin, ExpansionKind, ExpansionOrigin, OperandRole, SourceRange,
};

#[derive(Clone, Copy)]
pub(crate) enum FormulaContext {
    Binding,
    Statement,
    Certificate,
}

pub(crate) struct ParsedFormula {
    formula: DefinedFormula,
    expanded_nodes: u32,
    expanded_depth: u32,
}

struct ParsedTerm {
    variable: FreeVariable,
    graph_constraints: Vec<DefinedFormula>,
    witnesses: Vec<FreeVariable>,
}

impl ParsedTerm {
    fn variable(variable: FreeVariable) -> Self {
        Self {
            variable,
            graph_constraints: Vec::new(),
            witnesses: Vec::new(),
        }
    }
}

#[derive(Clone, Copy)]
struct DefinitionAlias {
    definition_id: DefinitionId,
    kind: DefinitionKind,
}

#[derive(Clone)]
struct StepBinding {
    position: u32,
    span: SourceSpan,
    arguments: Vec<ArgumentOrigin>,
}

struct BindingOrigin {
    range: SourceRange,
    kind: ExpansionKind,
    definition_id: Option<naome_checker::diagnostics::Digest>,
    proof_id: Option<naome_checker::diagnostics::Digest>,
    expansions: Vec<ExpansionOrigin>,
    expansions_complete: bool,
}

pub(super) struct Parser<'source> {
    source: &'source str,
    offset: usize,
    variables: syntax::Variables<'source>,
    definition_aliases: HashMap<&'source str, DefinitionAlias>,
    formula_bindings: HashMap<&'source str, ParsedFormula>,
    steps: HashMap<&'source str, StepBinding>,
    proof_references: HashMap<&'source str, ProofId>,
    formula_binding_nodes: usize,
    statement_nodes: usize,
    certificate_formula_nodes: usize,
    pending_arguments: Vec<ArgumentOrigin>,
    diagnostic_query: Option<naome_checker::diagnostics::FormulaQuery>,
    binding_origins: HashMap<&'source str, BindingOrigin>,
    pending_expansions: Vec<ExpansionOrigin>,
    expansions_complete: bool,
}

impl<'source> Parser<'source> {
    pub(super) fn new(source: &'source str) -> Self {
        Self {
            source,
            offset: 0,
            variables: syntax::Variables::default(),
            definition_aliases: HashMap::new(),
            formula_bindings: HashMap::new(),
            steps: HashMap::new(),
            proof_references: HashMap::new(),
            formula_binding_nodes: 0,
            statement_nodes: 0,
            certificate_formula_nodes: 0,
            pending_arguments: Vec::new(),
            diagnostic_query: None,
            binding_origins: HashMap::new(),
            pending_expansions: Vec::new(),
            expansions_complete: true,
        }
    }

    pub(super) fn with_query(mut self, query: &naome_checker::diagnostics::FormulaQuery) -> Self {
        self.diagnostic_query = Some(query.clone());
        self
    }

    pub(super) fn compile(
        mut self,
        artifact_state: &dyn ContextView,
    ) -> Result<CompiledArtifact, CompileError> {
        if self.peek_word("defs") {
            self.definition_aliases(artifact_state)?;
        }
        if self.peek_word("refs") {
            self.proof_references()?;
        }
        if self.peek_word("let") {
            self.keyword("let")?;
            self.punctuation(':')?;
            if self.peek_word("goal") || self.peek_word("def") {
                return Err(CompileError::Syntax {
                    offset: self.next_offset(),
                    expected: "at least one formula binding",
                });
            }
            loop {
                self.formula_binding()?;
                if self.peek_word("goal") {
                    break;
                }
                if self.peek_word("def") {
                    return Err(CompileError::Syntax {
                        offset: self.next_offset(),
                        expected: "a proof statement after formula bindings",
                    });
                }
            }
        }
        if self.peek_word("def") {
            return self.compile_definition(artifact_state);
        }
        self.keyword("goal")?;
        self.punctuation('=')?;
        let statement_offset = self.next_offset();
        let compact_statement = self.formula(1, FormulaContext::Statement)?;
        let statement = compact_statement
            .expand_with_node_limit(artifact_state, FORMULA_MAX_NODES)
            .map(|(formula, _)| formula)
            .map_err(|source| CompileError::DefinitionExpansion {
                offset: statement_offset,
                source,
            })?;
        let statement_span = SourceSpan::new(statement_offset, self.offset);
        let proof_offset = self.next_offset();
        self.keyword("proof")?;
        self.punctuation(':')?;

        let mut proof_steps = Vec::new();
        let mut last_step_name = None;
        while !self.peek_word("return") {
            if proof_steps.len() == CERTIFICATE_MAX_STEPS {
                let offset = self.next_offset();
                return Err(CompileError::Certificate {
                    offset,
                    source: ProofCertificateError::TooManySteps {
                        actual: CERTIFICATE_MAX_STEPS + 1,
                        maximum: CERTIFICATE_MAX_STEPS,
                    },
                });
            }
            let name_offset = self.next_offset();
            let name = self.name()?;
            if self.steps.contains_key(name) {
                return Err(CompileError::DuplicateStep {
                    offset: name_offset,
                    name: name.to_owned(),
                });
            }
            self.punctuation('=')?;
            let step = self.proof_step()?;
            let position = u32::try_from(proof_steps.len())
                .expect("the certificate step limit fits one local step index");
            self.steps.insert(
                name,
                StepBinding {
                    position,
                    span: SourceSpan::new(name_offset, self.offset),
                    arguments: std::mem::take(&mut self.pending_arguments),
                },
            );
            proof_steps.push(step);
            last_step_name = Some(name);
        }
        self.keyword("return")?;
        let result_offset = self.next_offset();
        let result = self.name()?;
        self.end()?;

        if last_step_name != Some(result) {
            return Err(CompileError::ReturnNotFinal {
                offset: result_offset,
            });
        }
        let step_bindings = std::mem::take(&mut self.steps);
        let variable_names = self.variables.names().collect::<Vec<_>>();
        let source_text = self.source;
        let diagnostic_query = self.diagnostic_query.take();
        drop(self);

        let certificate =
            ProofCertificate::new(proof_steps).map_err(|source| CompileError::Certificate {
                offset: proof_offset,
                source,
            })?;
        let (normal_form, step_origins) =
            certificate.into_unchecked_normal_form_with_step_origins();
        let checked = match &diagnostic_query {
            Some(query) => {
                naome_checker::check_normal_form_with_inspection(normal_form, artifact_state, query)
            }
            None => check_normal_form_with_state(normal_form, artifact_state),
        }
        .map_err(|mut source| {
            diagnostics::attach_source(
                source.diagnostic_mut(),
                source_text,
                &step_bindings,
                &step_origins,
                &variable_names,
            );
            source
                .diagnostic_mut()
                .bind_target(&statement)
                .expect("parsed source target obeys formula limits");
            source
                .diagnostic_mut()
                .target
                .as_mut()
                .expect("bound target")
                .variable_namespace = naome_checker::diagnostics::VariableNamespace::Source;
            source.diagnostic_mut().target_source_digest = source.diagnostic().input.source_digest;
            source.diagnostic_mut().target_source =
                SourceRange::new(statement_span.start(), statement_span.end());
            if let Some(query) = &diagnostic_query
                && query.operand == OperandRole::Target
            {
                source.diagnostic_mut().inspection =
                    naome_checker::diagnostics::inspect_formula_value(&statement, query)
                        .map(|mut fragment| {
                            fragment.variable_namespace =
                                naome_checker::diagnostics::VariableNamespace::Source;
                            fragment
                        })
                        .ok();
            }
            let source_step = step_origins.source_step(source.step());
            let origin = source_step.and_then(|position| {
                step_bindings
                    .iter()
                    .find(|(_, binding)| binding.position == position)
            });
            let span = origin.map_or(SourceSpan::point(proof_offset), |(_, binding)| binding.span);
            CompileError::Check {
                span,
                source: Box::new(source),
            }
        })?;
        if checked.conclusion() != &statement {
            let mut diagnostic = naome_checker::diagnostics::target_mismatch(
                checked.normal_form().certificate(),
                artifact_state,
                &statement,
                checked.conclusion(),
            )
            .expect("parsed target and checked conclusion obey formula limits");
            diagnostic
                .target
                .as_mut()
                .expect("bound target")
                .variable_namespace = naome_checker::diagnostics::VariableNamespace::Source;
            diagnostic.target_source_digest = Some(naome_checker::diagnostics::Digest::of(
                source_text.as_bytes(),
            ));
            diagnostic.target_source =
                SourceRange::new(statement_span.start(), statement_span.end());
            diagnostics::attach_source(
                &mut diagnostic,
                source_text,
                &step_bindings,
                &step_origins,
                &variable_names,
            );
            if let Some(query) = &diagnostic_query {
                diagnostic.inspection = match query.operand {
                    OperandRole::Target => {
                        naome_checker::diagnostics::inspect_formula_value(&statement, query)
                            .map(|mut fragment| {
                                fragment.variable_namespace =
                                    naome_checker::diagnostics::VariableNamespace::Source;
                                fragment
                            })
                            .ok()
                    }
                    OperandRole::Conclusion => naome_checker::diagnostics::inspect_formula_value(
                        checked.conclusion(),
                        query,
                    )
                    .map(|mut fragment| {
                        fragment.variable_namespace =
                            naome_checker::diagnostics::VariableNamespace::Input;
                        fragment
                    })
                    .ok(),
                    _ => None,
                };
            }
            return Err(CompileError::StatementMismatch {
                span: statement_span,
                diagnostic: std::sync::Arc::new(diagnostic),
                comparison: Box::new(
                    naome_foundation::FormulaMismatch::between(&statement, checked.conclusion())
                        .expect("the statement and conclusion differ"),
                ),
            });
        }
        Ok(CompiledArtifact::Proof(CompiledProof::from_checked(
            checked,
        )))
    }

    fn formula_binding(&mut self) -> Result<(), CompileError> {
        let name_offset = self.next_offset();
        let name = syntax::binding_name(self.source, &mut self.offset, |name| {
            self.formula_bindings.contains_key(name)
        })
        .map_err(|error| match error {
            syntax::BindingError::Name => CompileError::Syntax {
                offset: name_offset,
                expected: "a name",
            },
            syntax::BindingError::Reserved => CompileError::Syntax {
                offset: name_offset,
                expected: "a non-reserved formula binding name",
            },
            syntax::BindingError::Duplicate => CompileError::DuplicateFormulaBinding {
                offset: name_offset,
                name: self.source[name_offset..self.offset].to_owned(),
            },
        })?;
        if self.definition_aliases.contains_key(name) {
            return Err(CompileError::DuplicateDefinitionAlias {
                offset: name_offset,
                name: name.to_owned(),
            });
        }
        if self.proof_references.contains_key(name) {
            return Err(CompileError::DuplicateProofReference {
                offset: name_offset,
                name: name.to_owned(),
            });
        }
        self.punctuation('=')?;
        self.pending_expansions.clear();
        self.expansions_complete = true;
        let parsed = self.parsed_formula(1, FormulaContext::Binding)?;
        self.binding_origins.insert(
            name,
            BindingOrigin {
                range: SourceRange::new(name_offset, self.offset).expect("source offsets fit"),
                kind: ExpansionKind::FormulaBinding,
                definition_id: None,
                proof_id: None,
                expansions: std::mem::take(&mut self.pending_expansions),
                expansions_complete: self.expansions_complete,
            },
        );
        self.formula_bindings.insert(name, parsed);
        Ok(())
    }

    fn variable(&mut self) -> Result<FreeVariable, CompileError> {
        let name = self.name()?;
        Ok(self.variable_named(name))
    }

    fn reserved_binding_name(&self, name: &str) -> bool {
        syntax::is_reserved_binding_name(name)
    }

    fn definition_variable(&mut self) -> Result<FreeVariable, CompileError> {
        let offset = self.next_offset();
        let name = self.name()?;
        if self.variables.contains(name) {
            return Err(CompileError::Syntax {
                offset,
                expected: "a unique definition parameter",
            });
        }
        Ok(self.variable_named(name))
    }

    fn variable_named(&mut self, name: &'source str) -> FreeVariable {
        self.variables
            .named(name)
            .expect("source byte limit bounds presentation variables")
    }

    fn fresh_variable(&mut self) -> FreeVariable {
        self.variables
            .fresh()
            .expect("source byte limit bounds presentation variables")
    }
}

const fn lowercase_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

const fn proof_id_error_offset(start: usize, offset: usize, byte: u8) -> usize {
    if matches!(
        byte,
        b' ' | b'\t' | b'\r' | b'\n' | b'#' | b'"' | b',' | b')'
    ) {
        start
    } else {
        offset
    }
}

mod definition;
mod formula;
mod proof;
mod tokens;

#[cfg(test)]
mod tests;
