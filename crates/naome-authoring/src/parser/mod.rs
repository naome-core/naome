//! One parser state, compilation order, and variable allocation.

use super::*;

#[derive(Clone, Copy)]
enum FormulaContext {
    Binding,
    Statement,
    Certificate,
}

struct ParsedFormula {
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

#[derive(Clone, Copy)]
struct StepBinding {
    position: u32,
    span: SourceSpan,
}

pub(super) struct Parser<'source> {
    source: &'source str,
    offset: usize,
    variables: HashMap<&'source str, FreeVariable>,
    definition_aliases: HashMap<&'source str, DefinitionAlias>,
    formula_bindings: HashMap<&'source str, ParsedFormula>,
    steps: HashMap<&'source str, StepBinding>,
    formula_binding_nodes: usize,
    statement_nodes: usize,
    certificate_formula_nodes: usize,
    next_variable_identifier: u32,
}

impl<'source> Parser<'source> {
    pub(super) fn new(source: &'source str) -> Self {
        Self {
            source,
            offset: 0,
            variables: HashMap::new(),
            definition_aliases: HashMap::new(),
            formula_bindings: HashMap::new(),
            steps: HashMap::new(),
            formula_binding_nodes: 0,
            statement_nodes: 0,
            certificate_formula_nodes: 0,
            next_variable_identifier: 0,
        }
    }

    pub(super) fn compile(
        mut self,
        artifact_state: &ArtifactState,
    ) -> Result<CompiledArtifact, CompileError> {
        self.keyword("foundation")?;
        self.punctuation('=')?;
        let foundation_offset = self.next_offset();
        let foundation = self.string("a quoted Foundation identifier")?;
        if foundation != FOUNDATION_ID {
            return Err(CompileError::FoundationMismatch {
                offset: foundation_offset,
            });
        }
        if self.peek_word("definitions") {
            self.definition_aliases(artifact_state)?;
        }
        if self.peek_word("formulas") {
            self.keyword("formulas")?;
            self.punctuation(':')?;
            if self.peek_word("statement") || self.peek_word("definition") {
                return Err(CompileError::Syntax {
                    offset: self.next_offset(),
                    expected: "at least one formula binding",
                });
            }
            loop {
                self.formula_binding()?;
                if self.peek_word("statement") {
                    break;
                }
                if self.peek_word("definition") {
                    return Err(CompileError::Syntax {
                        offset: self.next_offset(),
                        expected: "a proof statement after formula bindings",
                    });
                }
            }
        }
        if self.peek_word("definition") {
            return self.compile_definition(artifact_state);
        }
        self.keyword("statement")?;
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
        drop(self);

        let certificate =
            ProofCertificate::new(proof_steps).map_err(|source| CompileError::Certificate {
                offset: proof_offset,
                source,
            })?;
        let (normal_form, step_origins) =
            certificate.into_unchecked_normal_form_with_step_origins();
        let checked =
            check_normal_form_with_state(normal_form, artifact_state).map_err(|source| {
                let source_step = step_origins.source_step(source.step());
                let origin = source_step.and_then(|position| {
                    step_bindings
                        .iter()
                        .find(|(_, binding)| binding.position == position)
                });
                let span =
                    origin.map_or(SourceSpan::point(proof_offset), |(_, binding)| binding.span);
                CompileError::Check {
                    span,
                    source: Box::new(source),
                }
            })?;
        drop(step_bindings);
        drop(step_origins);
        if checked.conclusion() != &statement {
            return Err(CompileError::StatementMismatch {
                span: statement_span,
            });
        }
        Ok(CompiledArtifact::Proof(CompiledProof::from_checked(
            checked,
        )))
    }

    fn formula_binding(&mut self) -> Result<(), CompileError> {
        let name_offset = self.next_offset();
        let name = self.name()?;
        if is_reserved_formula_binding_name(name) {
            return Err(CompileError::Syntax {
                offset: name_offset,
                expected: "a non-reserved formula binding name",
            });
        }
        if self.formula_bindings.contains_key(name) {
            return Err(CompileError::DuplicateFormulaBinding {
                offset: name_offset,
                name: name.to_owned(),
            });
        }
        if self.definition_aliases.contains_key(name) {
            return Err(CompileError::DuplicateDefinitionAlias {
                offset: name_offset,
                name: name.to_owned(),
            });
        }
        self.punctuation('=')?;
        let parsed = self.parsed_formula(1, FormulaContext::Binding)?;
        self.formula_bindings.insert(name, parsed);
        Ok(())
    }

    fn variable(&mut self) -> Result<FreeVariable, CompileError> {
        let name = self.name()?;
        Ok(self.variable_named(name))
    }

    fn definition_variable(&mut self) -> Result<FreeVariable, CompileError> {
        let offset = self.next_offset();
        let name = self.name()?;
        if self.variables.contains_key(name) {
            return Err(CompileError::Syntax {
                offset,
                expected: "a unique definition parameter",
            });
        }
        Ok(self.variable_named(name))
    }

    fn variable_named(&mut self, name: &'source str) -> FreeVariable {
        if let Some(variable) = self.variables.get(name) {
            return *variable;
        }
        let variable = self.fresh_variable();
        self.variables.insert(name, variable);
        variable
    }

    fn fresh_variable(&mut self) -> FreeVariable {
        let variable = FreeVariable::new(self.next_variable_identifier);
        self.next_variable_identifier = self
            .next_variable_identifier
            .checked_add(1)
            .expect("the source-byte limit bounds presentation variables");
        variable
    }
}

fn is_formula_operator_name(name: &str) -> bool {
    matches!(
        name,
        "equal"
            | "member"
            | "not_"
            | "implies"
            | "forall"
            | "and_"
            | "or_"
            | "iff"
            | "exists"
            | "not_equal"
    )
}

fn is_reserved_formula_binding_name(name: &str) -> bool {
    is_formula_operator_name(name)
        || matches!(
            name,
            "foundation"
                | "definitions"
                | "definition"
                | "relation"
                | "function"
                | "formulas"
                | "statement"
                | "proof"
                | "return"
                | "parameters"
                | "simplification"
                | "frege"
                | "classical_contraposition"
                | "universal_distribution"
                | "vacuous_universal"
                | "universal_instantiation"
                | "modus_ponens"
                | "equality_reflexivity"
                | "equality_substitution"
                | "zfc_axiom"
                | "separation"
                | "replacement"
                | "cite"
                | "generalization"
        )
}

fn is_reserved_definition_alias_name(name: &str) -> bool {
    is_reserved_formula_binding_name(name)
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
