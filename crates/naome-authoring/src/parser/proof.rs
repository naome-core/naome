//! Proof-step and axiom lowering.

use super::*;

impl<'source> Parser<'source> {
    pub(super) fn proof_step(&mut self) -> Result<ProofStep, CompileError> {
        use OperandRole as R;
        self.pending_arguments.clear();
        let rule_offset = self.next_offset();
        let rule = self.name()?;
        self.punctuation('(')?;
        let step = match rule {
            "simp" => {
                let antecedent = self.argument(R::Antecedent, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                self.punctuation(',')?;
                let consequent = self.argument(R::Consequent, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                ProofStep::Simplification {
                    antecedent,
                    consequent,
                }
            }
            "frege" => {
                let first = self.argument(R::First, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                self.punctuation(',')?;
                let second = self.argument(R::Second, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                self.punctuation(',')?;
                let third = self.argument(R::Third, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                ProofStep::Frege {
                    first,
                    second,
                    third,
                }
            }
            "contra" => {
                let antecedent = self.argument(R::Antecedent, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                self.punctuation(',')?;
                let consequent = self.argument(R::Consequent, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                ProofStep::ClassicalContraposition {
                    antecedent,
                    consequent,
                }
            }
            "dist" => {
                let variable = self.argument(R::Variable, |parser| parser.variable())?;
                self.punctuation(',')?;
                let antecedent = self.argument(R::Antecedent, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                self.punctuation(',')?;
                let consequent = self.argument(R::Consequent, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                ProofStep::UniversalDistribution {
                    variable,
                    antecedent,
                    consequent,
                }
            }
            "vacuous" => {
                let formula = self.argument(R::Formula, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                ProofStep::VacuousUniversal { formula }
            }
            "inst" => {
                let variable = self.argument(R::Variable, |parser| parser.variable())?;
                self.punctuation(',')?;
                let replacement = self.argument(R::To, |parser| parser.variable())?;
                self.punctuation(',')?;
                let body = self.argument(R::Body, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                ProofStep::UniversalInstantiation {
                    variable,
                    replacement,
                    body,
                }
            }
            "mp" => {
                let premise = self.argument(R::Premise, |parser| parser.earlier_step())?;
                self.punctuation(',')?;
                let implication = self.argument(R::Implication, |parser| parser.earlier_step())?;
                ProofStep::ModusPonens {
                    premise,
                    implication,
                }
            }
            "refl" => {
                let variable = self.argument(R::Variable, |parser| parser.variable())?;
                ProofStep::EqualityReflexivity { variable }
            }
            "subst" => {
                let from = self.argument(R::From, |parser| parser.variable())?;
                self.punctuation(',')?;
                let to = self.argument(R::To, |parser| parser.variable())?;
                self.punctuation(',')?;
                let body = self.argument(R::Body, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?;
                ProofStep::EqualitySubstitution { from, to, body }
            }
            "axiom" => ProofStep::ZfcAxiom(self.zfc_axiom()?),
            "sep" => ProofStep::Separation(ProofSeparation {
                predicate: self.argument(R::Predicate, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?,
                element: {
                    self.punctuation(',')?;
                    self.argument(R::Element, |parser| parser.variable())?
                },
                source: {
                    self.punctuation(',')?;
                    self.argument(R::Source, |parser| parser.variable())?
                },
                result: {
                    self.punctuation(',')?;
                    self.argument(R::Result, |parser| parser.variable())?
                },
                parameters: {
                    self.punctuation(',')?;
                    self.schema_parameters()?
                },
            }),
            "replace" => ProofStep::Replacement(ProofReplacement {
                predicate: self.argument(R::Predicate, |parser| {
                    parser.proof_formula(1, FormulaContext::Certificate)
                })?,
                input: {
                    self.punctuation(',')?;
                    self.argument(R::Input, |parser| parser.variable())?
                },
                output: {
                    self.punctuation(',')?;
                    self.argument(R::Output, |parser| parser.variable())?
                },
                uniqueness_witness: {
                    self.punctuation(',')?;
                    self.argument(R::Witness, |parser| parser.variable())?
                },
                source: {
                    self.punctuation(',')?;
                    self.argument(R::Source, |parser| parser.variable())?
                },
                result: {
                    self.punctuation(',')?;
                    self.argument(R::Result, |parser| parser.variable())?
                },
                parameters: {
                    self.punctuation(',')?;
                    self.schema_parameters()?
                },
            }),
            "cite" => ProofStep::ProofReference {
                proof_id: self.argument(R::Proof, |parser| parser.citation())?,
            },
            "gen" => {
                let premise = self.argument(R::Premise, |parser| parser.earlier_step())?;
                self.punctuation(',')?;
                let variable = self.argument(R::Variable, |parser| parser.variable())?;
                ProofStep::Generalization { premise, variable }
            }
            _ => {
                return Err(CompileError::Syntax {
                    offset: rule_offset,
                    expected: "a supported proof expression",
                });
            }
        };
        self.call_end()?;
        Ok(step)
    }

    pub(super) fn proof_references(&mut self) -> Result<(), CompileError> {
        self.keyword("refs")?;
        self.punctuation(':')?;
        loop {
            let offset = self.next_offset();
            let name = self.name()?;
            if self.reserved_binding_name(name) {
                return Err(CompileError::Syntax {
                    offset,
                    expected: "a non-reserved proof reference name",
                });
            }
            if self.proof_references.contains_key(name) {
                return Err(CompileError::DuplicateProofReference {
                    offset,
                    name: name.to_owned(),
                });
            }
            if self.definition_aliases.contains_key(name) {
                return Err(CompileError::DuplicateDefinitionAlias {
                    offset,
                    name: name.to_owned(),
                });
            }
            self.punctuation('=')?;
            let id = self.proof_id()?;
            self.proof_references.insert(name, id);
            self.binding_origins.insert(
                name,
                BindingOrigin {
                    range: SourceRange::new(offset, self.offset).expect("source offsets fit"),
                    kind: ExpansionKind::ProofReference,
                    definition_id: None,
                    proof_id: Some(naome_checker::diagnostics::Digest(*id.as_bytes())),
                    expansions: Vec::new(),
                    expansions_complete: true,
                },
            );
            if self.peek_word("let") || self.peek_word("goal") || self.peek_word("def") {
                return Ok(());
            }
        }
    }

    fn citation(&mut self) -> Result<ProofId, CompileError> {
        self.skip_trivia();
        if self.byte() == Some(b'"') {
            return self.proof_id();
        }
        let offset = self.next_offset();
        let name = self.name()?;
        self.record_expansion(name, offset);
        self.proof_references.get(name).copied().ok_or_else(|| {
            CompileError::UnknownProofReference {
                offset,
                name: name.to_owned(),
            }
        })
    }

    fn zfc_axiom(&mut self) -> Result<ZfcAxiom, CompileError> {
        let offset = self.next_offset();
        let name = self.string("a quoted ZFC axiom selector")?;
        match name {
            "extensionality" => Ok(ZfcAxiom::Extensionality),
            "pairing" => Ok(ZfcAxiom::Pairing),
            "union" => Ok(ZfcAxiom::Union),
            "power_set" => Ok(ZfcAxiom::PowerSet),
            "infinity" => Ok(ZfcAxiom::Infinity),
            "foundation" => Ok(ZfcAxiom::Foundation),
            "choice" => Ok(ZfcAxiom::Choice),
            _ => Err(CompileError::Syntax {
                offset,
                expected: "a fixed ZFC axiom",
            }),
        }
    }

    fn schema_parameters(&mut self) -> Result<Vec<FreeVariable>, CompileError> {
        self.keyword("parameters")?;
        self.punctuation('=')?;
        self.punctuation('[')?;
        let mut parameters = Vec::new();
        self.skip_trivia();
        if self.byte() == Some(b']') {
            self.offset += 1;
            return Ok(parameters);
        }
        loop {
            let start = self.next_offset();
            let variable = self.variable()?;
            self.pending_arguments.push(ArgumentOrigin {
                role: OperandRole::Parameter,
                index: Some(parameters.len() as u32),
                range: SourceRange::new(start, self.offset).expect("source offsets fit"),
                expansions: Vec::new(),
                expansions_complete: true,
            });
            parameters.push(variable);
            self.skip_trivia();
            if self.byte() == Some(b']') {
                self.offset += 1;
                return Ok(parameters);
            }
            self.punctuation(',')?;
            self.skip_trivia();
            if self.byte() == Some(b']') {
                self.offset += 1;
                return Ok(parameters);
            }
        }
    }

    fn earlier_step(&mut self) -> Result<u32, CompileError> {
        let offset = self.next_offset();
        let name = self.name()?;
        self.steps
            .get(name)
            .map(|binding| binding.position)
            .ok_or_else(|| CompileError::UnknownStep {
                offset,
                name: name.to_owned(),
            })
    }
}
