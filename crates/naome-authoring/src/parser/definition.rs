//! Selected aliases and conservative definition lowering.

use super::*;

impl<'source> Parser<'source> {
    pub(super) fn definition_aliases(
        &mut self,
        artifact_state: &ArtifactState,
    ) -> Result<(), CompileError> {
        self.keyword("definitions")?;
        self.punctuation(':')?;
        if self.peek_word("formulas") || self.peek_word("statement") || self.peek_word("definition")
        {
            return Err(CompileError::Syntax {
                offset: self.next_offset(),
                expected: "at least one selected definition alias",
            });
        }
        loop {
            let offset = self.next_offset();
            let name = self.name()?;
            if is_reserved_definition_alias_name(name) {
                return Err(CompileError::Syntax {
                    offset,
                    expected: "a non-reserved definition alias",
                });
            }
            if self.definition_aliases.contains_key(name) {
                return Err(CompileError::DuplicateDefinitionAlias {
                    offset,
                    name: name.to_owned(),
                });
            }
            self.punctuation('=')?;
            let definition_id = self.definition_id()?;
            let kind = artifact_state.definition_kind(definition_id).ok_or(
                CompileError::DefinitionNotSelected {
                    offset,
                    definition_id,
                },
            )?;
            self.definition_aliases.insert(
                name,
                DefinitionAlias {
                    definition_id,
                    kind,
                },
            );
            if self.peek_word("formulas")
                || self.peek_word("statement")
                || self.peek_word("definition")
            {
                return Ok(());
            }
        }
    }

    pub(super) fn compile_definition(
        mut self,
        artifact_state: &ArtifactState,
    ) -> Result<CompiledArtifact, CompileError> {
        let definition_offset = self.next_offset();
        self.keyword("definition")?;
        let name_offset = self.next_offset();
        let source_name = self.name()?;
        if self.definition_aliases.contains_key(source_name) {
            return Err(CompileError::DuplicateDefinitionAlias {
                offset: name_offset,
                name: source_name.to_owned(),
            });
        }
        self.punctuation('=')?;
        let kind_offset = self.next_offset();
        let kind_name = self.name()?;
        self.punctuation('(')?;
        let kind = match kind_name {
            "relation" => {
                let parameters = self.definition_parameters()?;
                if parameters.is_empty() {
                    return Err(CompileError::Definition {
                        offset: kind_offset,
                        source: DefinitionCertificateError::ZeroRelationArity,
                    });
                }
                DefinitionKind::Relation {
                    arity: u32::try_from(parameters.len())
                        .expect("the source byte limit bounds definition arity"),
                }
            }
            "function" => {
                let parameters = self.definition_parameters()?;
                let input_arity = parameters
                    .len()
                    .checked_sub(1)
                    .filter(|arity| *arity > 0)
                    .ok_or(CompileError::Syntax {
                        offset: kind_offset,
                        expected: "at least one function input and one output",
                    })?;
                DefinitionKind::Function {
                    input_arity: u32::try_from(input_arity)
                        .expect("the source byte limit bounds definition arity"),
                }
            }
            _ => {
                return Err(CompileError::Syntax {
                    offset: kind_offset,
                    expected: "`relation` or `function`",
                });
            }
        };
        self.call_end()?;
        self.punctuation(':')?;
        let body_offset = self.next_offset();
        let body = self.formula(1, FormulaContext::Statement)?;
        self.end()?;
        let checked = normalize_and_check_definition_with_state(kind, body, artifact_state)
            .map_err(|source| match source {
                DefinitionCheckError::Expansion(source) => CompileError::DefinitionExpansion {
                    offset: body_offset,
                    source,
                },
                DefinitionCheckError::CanonicalBody(source) => CompileError::DefinitionFormula {
                    offset: body_offset,
                    source,
                },
                DefinitionCheckError::Certificate(source) => CompileError::Definition {
                    offset: body_offset,
                    source,
                },
                source => CompileError::DefinitionCheck {
                    span: SourceSpan::new(definition_offset, self.offset.max(name_offset)),
                    source: Box::new(source),
                },
            })?;
        Ok(CompiledArtifact::Definition(
            CompiledDefinition::from_checked(checked),
        ))
    }

    fn definition_parameters(&mut self) -> Result<Vec<FreeVariable>, CompileError> {
        let mut parameters = Vec::new();
        self.skip_trivia();
        if self.byte() == Some(b')') {
            return Ok(parameters);
        }
        loop {
            if parameters.len()
                == usize::try_from(DEFINITION_MAX_GRAPH_ARITY)
                    .expect("the definition graph-arity limit fits usize")
            {
                return Err(CompileError::Definition {
                    offset: self.next_offset(),
                    source: DefinitionCertificateError::ArityTooLarge {
                        actual: u64::from(DEFINITION_MAX_GRAPH_ARITY) + 1,
                        maximum: DEFINITION_MAX_GRAPH_ARITY,
                    },
                });
            }
            parameters.push(self.definition_variable()?);
            self.skip_trivia();
            if self.byte() == Some(b')') {
                return Ok(parameters);
            }
            self.punctuation(',')?;
            self.skip_trivia();
            if self.byte() == Some(b')') {
                return Ok(parameters);
            }
        }
    }
}
