//! Proof-step and axiom lowering.

use super::*;

impl<'source> Parser<'source> {
    pub(super) fn proof_step(&mut self) -> Result<ProofStep, CompileError> {
        let rule_offset = self.next_offset();
        let rule = self.name()?;
        self.punctuation('(')?;
        let step = match rule {
            "simplification" => {
                let antecedent = self.proof_formula(1, FormulaContext::Certificate)?;
                self.punctuation(',')?;
                let consequent = self.proof_formula(1, FormulaContext::Certificate)?;
                ProofStep::Simplification {
                    antecedent,
                    consequent,
                }
            }
            "frege" => {
                let first = self.proof_formula(1, FormulaContext::Certificate)?;
                self.punctuation(',')?;
                let second = self.proof_formula(1, FormulaContext::Certificate)?;
                self.punctuation(',')?;
                let third = self.proof_formula(1, FormulaContext::Certificate)?;
                ProofStep::Frege {
                    first,
                    second,
                    third,
                }
            }
            "classical_contraposition" => {
                let antecedent = self.proof_formula(1, FormulaContext::Certificate)?;
                self.punctuation(',')?;
                let consequent = self.proof_formula(1, FormulaContext::Certificate)?;
                ProofStep::ClassicalContraposition {
                    antecedent,
                    consequent,
                }
            }
            "universal_distribution" => {
                let variable = self.variable()?;
                self.punctuation(',')?;
                let antecedent = self.proof_formula(1, FormulaContext::Certificate)?;
                self.punctuation(',')?;
                let consequent = self.proof_formula(1, FormulaContext::Certificate)?;
                ProofStep::UniversalDistribution {
                    variable,
                    antecedent,
                    consequent,
                }
            }
            "vacuous_universal" => {
                let formula = self.proof_formula(1, FormulaContext::Certificate)?;
                ProofStep::VacuousUniversal { formula }
            }
            "universal_instantiation" => {
                let variable = self.variable()?;
                self.punctuation(',')?;
                let replacement = self.variable()?;
                self.punctuation(',')?;
                let body = self.proof_formula(1, FormulaContext::Certificate)?;
                ProofStep::UniversalInstantiation {
                    variable,
                    replacement,
                    body,
                }
            }
            "modus_ponens" => {
                let premise = self.earlier_step()?;
                self.punctuation(',')?;
                let implication = self.earlier_step()?;
                ProofStep::ModusPonens {
                    premise,
                    implication,
                }
            }
            "equality_reflexivity" => {
                let variable = self.variable()?;
                ProofStep::EqualityReflexivity { variable }
            }
            "equality_substitution" => {
                let from = self.variable()?;
                self.punctuation(',')?;
                let to = self.variable()?;
                self.punctuation(',')?;
                let body = self.proof_formula(1, FormulaContext::Certificate)?;
                ProofStep::EqualitySubstitution { from, to, body }
            }
            "zfc_axiom" => ProofStep::ZfcAxiom(self.zfc_axiom()?),
            "separation" => ProofStep::Separation(ProofSeparation {
                predicate: self.proof_formula(1, FormulaContext::Certificate)?,
                element: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                source: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                result: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                parameters: {
                    self.punctuation(',')?;
                    self.schema_parameters()?
                },
            }),
            "replacement" => ProofStep::Replacement(ProofReplacement {
                predicate: self.proof_formula(1, FormulaContext::Certificate)?,
                input: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                output: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                uniqueness_witness: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                source: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                result: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                parameters: {
                    self.punctuation(',')?;
                    self.schema_parameters()?
                },
            }),
            "cite" => ProofStep::ProofReference {
                proof_id: self.proof_id()?,
            },
            "generalization" => {
                let premise = self.earlier_step()?;
                self.punctuation(',')?;
                let variable = self.variable()?;
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
            parameters.push(self.variable()?);
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
