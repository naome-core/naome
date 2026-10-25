//! Formula and term lowering with exact shared source budgets.

use super::*;

struct TermBudget {
    context: FormulaContext,
    source_depth: u32,
    atom_depth: u32,
    functions: u32,
}

impl TermBudget {
    fn new(context: FormulaContext, source_depth: u32, atom_depth: u32) -> Self {
        Self {
            context,
            source_depth,
            atom_depth,
            functions: 0,
        }
    }
}

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
        syntax::formula::parse(self, depth as usize, context)
    }

    fn parse_equal(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
        negated: bool,
    ) -> Result<ParsedFormula, CompileError> {
        let mut terms = TermBudget::new(context, depth, if negated { 2 } else { 1 });
        let left = self.term(&mut terms)?;
        self.punctuation(',')?;
        let right = self.term(&mut terms)?;
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
        let mut terms = TermBudget::new(context, depth, 1);
        let element = self.term(&mut terms)?;
        self.punctuation(',')?;
        let set = self.term(&mut terms)?;
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
        self.record_expansion(name, offset);
        let mut terms = TermBudget::new(context, depth, 1);
        let arguments = self.term_arguments(offset, name, arity, &mut terms)?;
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

    fn term(&mut self, budget: &mut TermBudget) -> Result<ParsedTerm, CompileError> {
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
        self.record_expansion(name, offset);
        // Each function contributes one graph atom, a three-node conjunction
        // and a three-node existential. Preflight before recursive arguments
        // or constraint allocation; the same limit also bounds the call stack.
        budget.functions += 1;
        self.check_expanded_depth(
            offset,
            budget.source_depth,
            budget.atom_depth + 6 * budget.functions,
        )?;
        self.charge_formula_nodes(budget.context, 7, offset)?;
        let arguments = self.term_arguments(offset, name, expected, budget)?;
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

    fn term_arguments(
        &mut self,
        offset: usize,
        name: &str,
        arity: u32,
        budget: &mut TermBudget,
    ) -> Result<Vec<ParsedTerm>, CompileError> {
        let mut arguments = Vec::new();
        self.skip_trivia();
        if self.byte() == Some(b')') {
            return Ok(arguments);
        }
        loop {
            if arguments.len() == arity as usize {
                return Err(CompileError::DefinitionArityMismatch {
                    offset,
                    name: name.to_owned(),
                    expected: arity,
                    actual: arguments.len() + 1,
                });
            }
            arguments.push(self.term(budget)?);
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
        let constraint_count = graph_constraints.len();
        let witness_count = witnesses.len();
        debug_assert_eq!(constraint_count, witness_count);
        let expanded_depth =
            atom_depth + 6 * u32::try_from(witness_count).expect("preflighted term count fits u32");
        self.check_expanded_depth(offset, source_depth, expanded_depth)?;
        // Function contributions were charged before parsing their arguments.
        self.charge_formula_nodes(context, atom_depth - 1, offset)?;
        let mut formula = atom(&variables);
        for constraint in graph_constraints.into_iter().rev() {
            formula = DefinedFormula::conjunction(constraint, formula);
        }
        for witness in witnesses.into_iter().rev() {
            formula = DefinedFormula::exists(witness, formula);
        }
        let (_, nodes) = formula
            .encode_canonical_with_node_limit(FORMULA_MAX_NODES)
            .map_err(|source| CompileError::DefinitionFormula { offset, source })?;
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
        self.record_expansion(name, offset);
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

impl<'source> syntax::formula::FormulaBuilder<'source> for Parser<'source> {
    type Parsed = ParsedFormula;
    type Error = CompileError;
    type Mode = FormulaContext;
    fn start(
        &mut self,
        depth: usize,
        context: FormulaContext,
    ) -> Result<syntax::formula::Start<'source, ParsedFormula>, CompileError> {
        let depth = depth as u32;
        let formula_offset = self.next_offset();
        let operator = self.name()?;
        let offset_after_name = self.offset;
        self.skip_trivia();
        let opening_parenthesis_offset = self.offset;
        let has_call = self.byte() == Some(b'(');
        self.offset = offset_after_name;
        if !has_call && !self.reserved_binding_name(operator) {
            return self
                .parsed_formula_binding_reference(formula_offset, operator, depth, context)
                .map(syntax::formula::Start::Value);
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
        Ok(syntax::formula::Start::Call {
            name: operator,
            offset: formula_offset,
        })
    }
    fn atom(
        &mut self,
        op: syntax::formula::Operator,
        offset: usize,
        depth: usize,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        use syntax::formula::Operator;
        match op {
            Operator::Equal => self.parse_equal(offset, depth as u32, context, false),
            Operator::Unequal => self.parse_equal(offset, depth as u32, context, true),
            Operator::Member => self.parse_member(offset, depth as u32, context),
            _ => unreachable!(),
        }
    }
    fn binders(&mut self, offset: usize) -> Result<Vec<FreeVariable>, CompileError> {
        syntax::binders(self.source, &mut self.offset, &mut self.variables).map_err(|error| {
            match error {
                syntax::BinderError::Name(offset) => CompileError::Syntax {
                    offset,
                    expected: "a name",
                },
                syntax::BinderError::Comma(offset) => CompileError::Syntax {
                    offset,
                    expected: "`,`",
                },
                syntax::BinderError::Depth | syntax::BinderError::Overflow => {
                    CompileError::FormulaDepthLimitExceeded {
                        offset,
                        maximum: FORMULA_MAX_DEPTH,
                    }
                }
            }
        })
    }
    fn quantified_depth(
        &mut self,
        op: syntax::formula::Operator,
        count: usize,
        offset: usize,
        depth: usize,
        context: FormulaContext,
    ) -> Result<usize, CompileError> {
        let extra = count as u32
            * if op == syntax::formula::Operator::Exists {
                3
            } else {
                1
            };
        self.check_expanded_depth(offset, depth as u32, extra + 1)?;
        self.charge_formula_nodes(context, extra - 1, offset)?;
        Ok(depth + extra as usize)
    }
    fn quantified(
        &mut self,
        op: syntax::formula::Operator,
        variables: Vec<FreeVariable>,
        body: ParsedFormula,
        offset: usize,
        depth: usize,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let existential = op == syntax::formula::Operator::Exists;
        let extra = variables.len() as u32 * if existential { 3 } else { 1 };
        let expanded_nodes =
            self.checked_node_sum(context, &[extra, body.expanded_nodes], offset)?;
        let expanded_depth = self.checked_depth_add(offset, body.expanded_depth, extra)?;
        self.check_expanded_depth(offset, depth as u32, expanded_depth)?;
        let mut formula = body.formula;
        for variable in variables.into_iter().rev() {
            formula = if existential {
                DefinedFormula::exists(variable, formula)
            } else {
                DefinedFormula::for_all(variable, formula)
            };
        }
        Ok(ParsedFormula {
            formula,
            expanded_nodes,
            expanded_depth,
        })
    }
    fn negated(
        &mut self,
        body: ParsedFormula,
        offset: usize,
        depth: usize,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let expanded_nodes = self.checked_node_sum(context, &[1, body.expanded_nodes], offset)?;
        let expanded_depth = self.checked_depth_add(offset, body.expanded_depth, 1)?;
        self.check_expanded_depth(offset, depth as u32, expanded_depth)?;
        Ok(ParsedFormula {
            formula: DefinedFormula::negate(body.formula),
            expanded_nodes,
            expanded_depth,
        })
    }
    fn binary(
        &mut self,
        op: syntax::formula::Operator,
        [left, right]: [ParsedFormula; 2],
        offset: usize,
        depth: usize,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        use syntax::formula::Operator;
        let (nodes, height) = syntax::binary_shape(
            op.name(),
            (left.expanded_nodes as usize, left.expanded_depth as usize),
            (right.expanded_nodes as usize, right.expanded_depth as usize),
        )
        .ok_or_else(|| Self::formula_node_limit(context, offset))?;
        let expanded_nodes =
            u32::try_from(nodes).map_err(|_| Self::formula_node_limit(context, offset))?;
        let expanded_depth =
            u32::try_from(height).map_err(|_| Self::formula_node_limit(context, offset))?;
        let additional = match op {
            Operator::And => 2,
            Operator::Or => 1,
            Operator::Iff => self.checked_node_sum(
                context,
                &[4, left.expanded_nodes, right.expanded_nodes],
                offset,
            )?,
            Operator::Implies => 0,
            _ => unreachable!(),
        };
        self.check_derived_expansion(offset, depth as u32, context, expanded_depth, additional)?;
        let formula = match op {
            Operator::Implies => DefinedFormula::implies(left.formula, right.formula),
            Operator::And => DefinedFormula::conjunction(left.formula, right.formula),
            Operator::Or => DefinedFormula::disjunction(left.formula, right.formula),
            Operator::Iff => DefinedFormula::biconditional(left.formula, right.formula),
            _ => unreachable!(),
        };
        Ok(ParsedFormula {
            formula,
            expanded_nodes,
            expanded_depth,
        })
    }
    fn extension(
        &mut self,
        name: &'source str,
        offset: usize,
        depth: usize,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        self.parse_defined_relation(offset, name, context, depth as u32)
    }
    fn comma(&mut self) -> Result<(), CompileError> {
        self.punctuation(',')
    }
    fn finish(&mut self, parsed: ParsedFormula, _: usize) -> Result<ParsedFormula, CompileError> {
        self.call_end()?;
        Ok(parsed)
    }
}
