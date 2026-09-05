//! Formula and term lowering with exact shared source budgets.

use super::*;

impl<'source> Parser<'source> {
    pub(super) fn formula(
        &mut self,
        depth: u32,
        context: FormulaContext,
    ) -> Result<DefinedFormula, CompileError> {
        self.parsed_formula(depth, context)
            .map(|parsed| parsed.formula)
    }

    pub(super) fn proof_formula(
        &mut self,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ProofFormula, CompileError> {
        let offset = self.next_offset();
        let formula = self.formula(depth, context)?;
        ProofFormula::from_defined(formula)
            .map_err(|source| CompileError::DefinitionFormula { offset, source })
    }

    pub(super) fn parsed_formula(
        &mut self,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let formula_offset = self.next_offset();
        let operator_offset = formula_offset;
        let operator = self.name()?;
        let offset_after_name = self.offset;
        self.skip_trivia();
        let opening_parenthesis_offset = self.offset;
        let has_call = self.byte() == Some(b'(');
        self.offset = offset_after_name;
        if !has_call && !is_reserved_formula_binding_name(operator) {
            return self.parsed_formula_binding_reference(
                operator_offset,
                operator,
                depth,
                context,
            );
        }
        self.charge_formula_nodes(context, 1, formula_offset)?;
        if depth > FORMULA_MAX_DEPTH {
            return Err(CompileError::FormulaDepthLimitExceeded {
                offset: formula_offset,
                maximum: FORMULA_MAX_DEPTH,
            });
        }
        if has_call {
            self.offset = opening_parenthesis_offset + 1;
        } else {
            self.punctuation('(')?;
        }
        let parsed = match operator {
            "equal" => self.parse_equal(formula_offset, depth, context, false)?,
            "member" => self.parse_member(formula_offset, depth, context)?,
            "not_equal" => self.parse_equal(formula_offset, depth, context, true)?,
            "not_" => self.parse_not(operator_offset, depth, context)?,
            "implies" => self.parse_implies(operator_offset, depth, context)?,
            "forall" => self.parse_for_all(operator_offset, depth, context)?,
            "and_" => self.parse_conjunction(operator_offset, depth, context)?,
            "or_" => self.parse_disjunction(operator_offset, depth, context)?,
            "iff" => self.parse_biconditional(operator_offset, depth, context)?,
            "exists" => self.parse_exists(operator_offset, depth, context)?,
            _ => self.parse_defined_relation(operator_offset, operator, context, depth)?,
        };
        self.call_end()?;
        Ok(parsed)
    }

    fn parse_equal(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
        negated: bool,
    ) -> Result<ParsedFormula, CompileError> {
        let left = self.term()?;
        self.punctuation(',')?;
        let right = self.term()?;
        self.relationalized_formula(
            [left, right],
            |variables| {
                let equality = DefinedFormula::equal(variables[0], variables[1]);
                if negated {
                    DefinedFormula::negate(equality)
                } else {
                    equality
                }
            },
            offset,
            context,
            depth,
            if negated { 2 } else { 1 },
        )
    }

    fn parse_member(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let element = self.term()?;
        self.punctuation(',')?;
        let set = self.term()?;
        self.relationalized_formula(
            [element, set],
            |variables| DefinedFormula::member(variables[0], variables[1]),
            offset,
            context,
            depth,
            1,
        )
    }

    fn parse_defined_relation(
        &mut self,
        offset: usize,
        name: &'source str,
        context: FormulaContext,
        depth: u32,
    ) -> Result<ParsedFormula, CompileError> {
        let alias = self.definition_aliases.get(name).copied().ok_or_else(|| {
            CompileError::UnknownDefinitionAlias {
                offset,
                name: name.to_owned(),
            }
        })?;
        let DefinitionKind::Relation { arity } = alias.kind else {
            return Err(CompileError::Syntax {
                offset,
                expected: "a relation definition alias in formula position",
            });
        };
        let arguments = self.term_arguments()?;
        self.ensure_definition_arity(offset, name, arity, arguments.len())?;
        self.relationalized_formula(
            arguments,
            |variables| {
                DefinedFormula::defined_relation(alias.definition_id, variables.iter().copied())
            },
            offset,
            context,
            depth,
            1,
        )
    }

    fn term(&mut self) -> Result<ParsedTerm, CompileError> {
        let offset = self.next_offset();
        let name = self.name()?;
        let offset_after_name = self.offset;
        self.skip_trivia();
        if self.byte() != Some(b'(') {
            self.offset = offset_after_name;
            return Ok(ParsedTerm::variable(self.variable_named(name)));
        }
        self.offset += 1;
        let alias = self.definition_aliases.get(name).copied().ok_or_else(|| {
            CompileError::UnknownDefinitionAlias {
                offset,
                name: name.to_owned(),
            }
        })?;
        let expected = match alias.kind {
            DefinitionKind::Function { input_arity } => input_arity,
            DefinitionKind::Relation { .. } => {
                return Err(CompileError::Syntax {
                    offset,
                    expected: "a function definition alias in term position",
                });
            }
        };
        let arguments = self.term_arguments()?;
        self.ensure_definition_arity(offset, name, expected, arguments.len())?;
        self.call_end()?;

        let mut variables = Vec::with_capacity(arguments.len() + 1);
        let mut graph_constraints = Vec::new();
        let mut witnesses = Vec::new();
        for argument in arguments {
            variables.push(argument.variable);
            graph_constraints.extend(argument.graph_constraints);
            witnesses.extend(argument.witnesses);
        }
        let output = self.fresh_variable();
        variables.push(output);
        graph_constraints.push(DefinedFormula::defined_relation(
            alias.definition_id,
            variables,
        ));
        witnesses.push(output);
        Ok(ParsedTerm {
            variable: output,
            graph_constraints,
            witnesses,
        })
    }

    fn term_arguments(&mut self) -> Result<Vec<ParsedTerm>, CompileError> {
        let mut arguments = Vec::new();
        self.skip_trivia();
        if self.byte() == Some(b')') {
            return Ok(arguments);
        }
        loop {
            arguments.push(self.term()?);
            self.skip_trivia();
            if self.byte() == Some(b')') {
                return Ok(arguments);
            }
            self.punctuation(',')?;
            self.skip_trivia();
            if self.byte() == Some(b')') {
                return Ok(arguments);
            }
        }
    }

    fn ensure_definition_arity(
        &self,
        offset: usize,
        name: &str,
        expected: u32,
        actual: usize,
    ) -> Result<(), CompileError> {
        if actual == expected as usize {
            Ok(())
        } else {
            Err(CompileError::DefinitionArityMismatch {
                offset,
                name: name.to_owned(),
                expected,
                actual,
            })
        }
    }

    fn relationalized_formula(
        &mut self,
        terms: impl IntoIterator<Item = ParsedTerm>,
        atom: impl FnOnce(&[FreeVariable]) -> DefinedFormula,
        offset: usize,
        context: FormulaContext,
        source_depth: u32,
        atom_depth: u32,
    ) -> Result<ParsedFormula, CompileError> {
        let mut variables = Vec::new();
        let mut graph_constraints = Vec::new();
        let mut witnesses = Vec::new();
        for term in terms {
            variables.push(term.variable);
            graph_constraints.extend(term.graph_constraints);
            witnesses.extend(term.witnesses);
        }
        let mut formula = atom(&variables);
        let constraint_count = graph_constraints.len();
        for constraint in graph_constraints.into_iter().rev() {
            formula = DefinedFormula::conjunction(constraint, formula);
        }
        let witness_count = witnesses.len();
        for witness in witnesses.into_iter().rev() {
            formula = DefinedFormula::exists(witness, formula);
        }
        let (_, nodes) = formula
            .encode_canonical_with_node_limit(FORMULA_MAX_NODES)
            .map_err(|source| CompileError::DefinitionFormula { offset, source })?;
        let additional = nodes.saturating_sub(1);
        self.charge_formula_nodes(
            context,
            u32::try_from(additional).expect("the formula node limit fits u32"),
            offset,
        )?;
        let relational_depth = (0..constraint_count).try_fold(atom_depth, |depth, _| {
            self.checked_depth_add(offset, depth, 3)
        })?;
        let expanded_depth = (0..witness_count).try_fold(relational_depth, |depth, _| {
            self.checked_depth_add(offset, depth, 3)
        })?;
        self.check_expanded_depth(offset, source_depth, expanded_depth)?;
        Ok(ParsedFormula {
            formula,
            expanded_nodes: u32::try_from(nodes).expect("the formula node limit fits u32"),
            expanded_depth,
        })
    }

    fn parsed_formula_binding_reference(
        &mut self,
        offset: usize,
        name: &'source str,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let (expanded_nodes, expanded_depth) = self
            .formula_bindings
            .get(name)
            .map(|binding| (binding.expanded_nodes, binding.expanded_depth))
            .ok_or_else(|| CompileError::UnknownFormulaBinding {
                offset,
                name: name.to_owned(),
            })?;
        self.charge_formula_nodes(context, expanded_nodes, offset)?;
        self.check_expanded_depth(offset, depth, expanded_depth)?;
        let formula = self
            .formula_bindings
            .get(name)
            .expect("a preflighted formula binding remains present")
            .formula
            .clone();
        Ok(ParsedFormula {
            formula,
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_not(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let body = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(context, &[1, body.expanded_nodes], offset)?;
        let expanded_depth = self.checked_depth_add(offset, body.expanded_depth, 1)?;
        self.check_expanded_depth(offset, depth, expanded_depth)?;
        Ok(ParsedFormula {
            formula: DefinedFormula::negate(body.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_implies(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let antecedent = self.parsed_formula(depth + 1, context)?;
        self.punctuation(',')?;
        let consequent = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(
            context,
            &[1, antecedent.expanded_nodes, consequent.expanded_nodes],
            offset,
        )?;
        let expanded_depth = self.checked_depth_add(
            offset,
            antecedent.expanded_depth.max(consequent.expanded_depth),
            1,
        )?;
        self.check_expanded_depth(offset, depth, expanded_depth)?;
        Ok(ParsedFormula {
            formula: DefinedFormula::implies(antecedent.formula, consequent.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_for_all(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let variable = self.variable()?;
        self.punctuation(',')?;
        let body = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(context, &[1, body.expanded_nodes], offset)?;
        let expanded_depth = self.checked_depth_add(offset, body.expanded_depth, 1)?;
        self.check_expanded_depth(offset, depth, expanded_depth)?;
        Ok(ParsedFormula {
            formula: DefinedFormula::for_all(variable, body.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_conjunction(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let left = self.parsed_formula(depth + 1, context)?;
        self.punctuation(',')?;
        let right = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(
            context,
            &[3, left.expanded_nodes, right.expanded_nodes],
            offset,
        )?;
        let left_depth = self.checked_depth_add(offset, left.expanded_depth, 2)?;
        let right_depth = self.checked_depth_add(offset, right.expanded_depth, 3)?;
        let expanded_depth = left_depth.max(right_depth);
        self.check_derived_expansion(offset, depth, context, expanded_depth, 2)?;
        Ok(ParsedFormula {
            formula: DefinedFormula::conjunction(left.formula, right.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_disjunction(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let left = self.parsed_formula(depth + 1, context)?;
        self.punctuation(',')?;
        let right = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(
            context,
            &[2, left.expanded_nodes, right.expanded_nodes],
            offset,
        )?;
        let left_depth = self.checked_depth_add(offset, left.expanded_depth, 2)?;
        let right_depth = self.checked_depth_add(offset, right.expanded_depth, 1)?;
        let expanded_depth = left_depth.max(right_depth);
        self.check_derived_expansion(offset, depth, context, expanded_depth, 1)?;
        Ok(ParsedFormula {
            formula: DefinedFormula::disjunction(left.formula, right.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_biconditional(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let left = self.parsed_formula(depth + 1, context)?;
        self.punctuation(',')?;
        let right = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(
            context,
            &[
                5,
                left.expanded_nodes,
                left.expanded_nodes,
                right.expanded_nodes,
                right.expanded_nodes,
            ],
            offset,
        )?;
        let additional_nodes = self.checked_node_sum(
            context,
            &[4, left.expanded_nodes, right.expanded_nodes],
            offset,
        )?;
        let expanded_depth =
            self.checked_depth_add(offset, left.expanded_depth.max(right.expanded_depth), 4)?;
        self.check_derived_expansion(offset, depth, context, expanded_depth, additional_nodes)?;
        Ok(ParsedFormula {
            formula: DefinedFormula::biconditional(left.formula, right.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_exists(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let variable = self.variable()?;
        self.punctuation(',')?;
        let body = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(context, &[3, body.expanded_nodes], offset)?;
        let expanded_depth = self.checked_depth_add(offset, body.expanded_depth, 3)?;
        self.check_derived_expansion(offset, depth, context, expanded_depth, 2)?;
        Ok(ParsedFormula {
            formula: DefinedFormula::exists(variable, body.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn check_derived_expansion(
        &mut self,
        operator_offset: usize,
        source_depth: u32,
        context: FormulaContext,
        expanded_depth: u32,
        additional_nodes: u32,
    ) -> Result<(), CompileError> {
        self.charge_formula_nodes(context, additional_nodes, operator_offset)?;
        self.check_expanded_depth(operator_offset, source_depth, expanded_depth)
    }

    fn check_expanded_depth(
        &self,
        operator_offset: usize,
        source_depth: u32,
        expanded_depth: u32,
    ) -> Result<(), CompileError> {
        let absolute_depth = source_depth
            .checked_sub(1)
            .and_then(|prefix| prefix.checked_add(expanded_depth));
        if absolute_depth.is_none_or(|depth| depth > FORMULA_MAX_DEPTH) {
            return Err(CompileError::FormulaDepthLimitExceeded {
                offset: operator_offset,
                maximum: FORMULA_MAX_DEPTH,
            });
        }
        Ok(())
    }

    fn checked_node_sum(
        &self,
        context: FormulaContext,
        terms: &[u32],
        offset: usize,
    ) -> Result<u32, CompileError> {
        terms
            .iter()
            .try_fold(0_u32, |sum, term| sum.checked_add(*term))
            .ok_or_else(|| Self::formula_node_limit(context, offset))
    }

    fn checked_depth_add(
        &self,
        offset: usize,
        depth: u32,
        additional: u32,
    ) -> Result<u32, CompileError> {
        depth
            .checked_add(additional)
            .ok_or(CompileError::FormulaDepthLimitExceeded {
                offset,
                maximum: FORMULA_MAX_DEPTH,
            })
    }

    fn charge_formula_nodes(
        &mut self,
        context: FormulaContext,
        additional: u32,
        offset: usize,
    ) -> Result<(), CompileError> {
        let (used, maximum) = match context {
            FormulaContext::Binding => (&mut self.formula_binding_nodes, FORMULA_BINDING_MAX_NODES),
            FormulaContext::Statement => (&mut self.statement_nodes, FORMULA_MAX_NODES),
            FormulaContext::Certificate => (
                &mut self.certificate_formula_nodes,
                CERTIFICATE_MAX_FORMULA_NODES,
            ),
        };
        let Some(total) = used.checked_add(additional as usize) else {
            return Err(Self::formula_node_limit(context, offset));
        };
        if total > maximum {
            return Err(Self::formula_node_limit(context, offset));
        }
        *used = total;
        Ok(())
    }

    fn formula_node_limit(context: FormulaContext, offset: usize) -> CompileError {
        match context {
            FormulaContext::Binding => CompileError::FormulaBindingNodeLimitExceeded {
                offset,
                maximum: FORMULA_BINDING_MAX_NODES,
            },
            FormulaContext::Statement => CompileError::Statement {
                offset,
                source: FormulaCodecError::NodeLimitExceeded {
                    maximum: FORMULA_MAX_NODES,
                },
            },
            FormulaContext::Certificate => CompileError::Certificate {
                offset,
                source: ProofCertificateError::FormulaNodeLimitExceeded {
                    maximum: CERTIFICATE_MAX_FORMULA_NODES,
                },
            },
        }
    }
}
