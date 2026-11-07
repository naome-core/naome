use super::{Axiom, Command};
use crate::{
    ProofFormula, ProofNormalForm, ProofStep,
    defined_formula::{Node as Defined, Variable as DefinedVariable},
};
use naome_foundation::{FormulaView, FreeVariable, ZfcAxiom};
use std::collections::{HashMap, hash_map::Entry};

/// A structural projection of a bounded certificate into a shared program.
/// The program requires independent checking and has its own manifest identity.
pub struct Projection {
    commands: Vec<Command>,
    results: Vec<StepResult>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepResult {
    Result(u64),
    InstantiationAxiom(u64),
}

impl Projection {
    pub fn from_normal_form(proof: &ProofNormalForm) -> Self {
        Self::with_instantiations(proof, &[]).expect("unfused projection")
    }

    /// Fold selected adjacent instantiation-axiom and modus-ponens pairs.
    /// Each listed index is the modus ponens step. Its axiom must have no
    /// other consumers or definition references. Independently replay the
    /// result and compare the checked trace before treating it as equivalent.
    pub fn with_instantiations(proof: &ProofNormalForm, sites: &[usize]) -> Result<Self, String> {
        let steps = proof.certificate().steps();
        let mut folds = vec![None; steps.len()];
        if !sites.is_empty() {
            let mut uses = vec![0u32; steps.len()];
            for step in steps {
                for reference in step.local_references().into_iter().flatten() {
                    uses[reference as usize] += 1;
                }
            }
            for &site in sites {
                let Some(ProofStep::ModusPonens {
                    premise,
                    implication,
                }) = steps.get(site)
                else {
                    return Err("instantiation site must select modus ponens".into());
                };
                let axiom = *implication as usize;
                let ProofStep::UniversalInstantiation {
                    replacement, body, ..
                } = &steps[axiom]
                else {
                    return Err("instantiation site has no instantiation axiom".into());
                };
                if axiom + 1 != site
                    || uses[axiom] != 1
                    || body.as_defined().is_some()
                    || folds[axiom].replace((*premise, *replacement)).is_some()
                {
                    return Err(
                        "instantiation site cannot be folded without losing a reference".into(),
                    );
                }
            }
        }

        let mut builder = Builder::default();
        let mut results = Vec::with_capacity(steps.len());
        let mut handles = Vec::with_capacity(steps.len());
        let mut index = 0;
        while index < steps.len() {
            if let Some((premise, replacement)) = folds[index] {
                let position = builder.push(Command::Instantiate {
                    premise: handles[premise as usize],
                    replacement: replacement.identifier(),
                });
                results.push(StepResult::InstantiationAxiom(position));
                handles.push(position);
                results.push(StepResult::Result(position));
                handles.push(position);
                index += 2;
            } else {
                let position = builder.step(&steps[index], &handles);
                results.push(StepResult::Result(position));
                handles.push(position);
                index += 1;
            }
        }
        builder.push(Command::Seal {
            proof: *handles.last().expect("a certificate is nonempty"),
        });
        Ok(Self {
            commands: builder.commands,
            results,
        })
    }

    pub fn commands(&self) -> &[Command] {
        &self.commands
    }

    /// Locations of normalized certificate results in the checked trace.
    /// Schema parameter closures map to the last enclosing generalization.
    pub fn results(&self) -> &[StepResult] {
        &self.results
    }
}

#[derive(Default)]
struct Builder {
    commands: Vec<Command>,
    formulas: HashMap<Command, u64>,
}

impl Builder {
    fn push(&mut self, command: Command) -> u64 {
        let position = self.commands.len() as u64;
        self.commands.push(command);
        position
    }

    fn intern(&mut self, command: Command) -> u64 {
        match self.formulas.entry(command) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let position = self.commands.len() as u64;
                self.commands.push(entry.key().clone());
                *entry.insert(position)
            }
        }
    }

    fn formula(&mut self, formula: &ProofFormula) -> u64 {
        if let Some(primitive) = formula.as_primitive() {
            self.primitive(primitive.view())
        } else {
            self.defined(
                formula
                    .as_defined()
                    .expect("definition-aware formula")
                    .graph_root(),
                0,
            )
        }
    }

    fn primitive(&mut self, formula: FormulaView<'_>) -> u64 {
        let node = formula.graph_node().map(|child| self.primitive(child));
        self.intern(Command::Graph { node })
    }

    fn defined(&mut self, formula: &Defined, depth: u32) -> u64 {
        let term = |variable| match variable {
            DefinedVariable::Free(id) => id.identifier(),
            DefinedVariable::Bound(index) => bound_identifier(depth, index),
        };
        let command = match formula {
            Defined::Equal(left, right) => Command::Equal {
                left: term(*left),
                right: term(*right),
            },
            Defined::Member(element, set) => Command::Member {
                element: term(*element),
                set: term(*set),
            },
            Defined::Not(body) => Command::Not {
                formula: self.defined(body, depth),
            },
            Defined::Implies(left, right) => Command::Implies {
                antecedent: self.defined(left, depth),
                consequent: self.defined(right, depth),
            },
            Defined::ForAll(body) => Command::ForAll {
                variable: binder(depth),
                body: self.defined(body, depth + 1),
            },
            Defined::DefinedRelation {
                definition_id,
                arguments,
            } => Command::DefinedRelation {
                definition_id: *definition_id.as_bytes(),
                arguments: arguments.iter().copied().map(term).collect(),
            },
        };
        self.intern(command)
    }

    fn step(&mut self, step: &ProofStep, results: &[u64]) -> u64 {
        let id = FreeVariable::identifier;
        let (command, parameters) = match step {
            ProofStep::Separation(schema) => (
                Command::Separation {
                    predicate: self.formula(&schema.predicate),
                    element: id(schema.element),
                    source: id(schema.source),
                    result: id(schema.result),
                },
                schema.parameters.as_slice(),
            ),
            ProofStep::Replacement(schema) => (
                Command::Replacement {
                    predicate: self.formula(&schema.predicate),
                    input: id(schema.input),
                    output: id(schema.output),
                    witness: id(schema.uniqueness_witness),
                    source: id(schema.source),
                    result: id(schema.result),
                },
                schema.parameters.as_slice(),
            ),
            step => {
                let command = self.inference(step, results);
                return self.push(command);
            }
        };
        let mut premise = self.push(command);
        for &variable in parameters.iter().rev() {
            premise = self.push(Command::Generalization {
                premise,
                variable: id(variable),
            });
        }
        premise
    }

    fn inference(&mut self, step: &ProofStep, results: &[u64]) -> Command {
        let id = FreeVariable::identifier;
        let result = |position: u32| results[position as usize];
        match step {
            ProofStep::Simplification {
                antecedent,
                consequent,
            } => Command::Simplification {
                antecedent: self.formula(antecedent),
                consequent: self.formula(consequent),
            },
            ProofStep::Frege {
                first,
                second,
                third,
            } => Command::Frege {
                first: self.formula(first),
                second: self.formula(second),
                third: self.formula(third),
            },
            ProofStep::ClassicalContraposition {
                antecedent,
                consequent,
            } => Command::Contraposition {
                antecedent: self.formula(antecedent),
                consequent: self.formula(consequent),
            },
            ProofStep::UniversalDistribution {
                variable,
                antecedent,
                consequent,
            } => Command::Distribution {
                variable: id(*variable),
                antecedent: self.formula(antecedent),
                consequent: self.formula(consequent),
            },
            ProofStep::VacuousUniversal { formula } => Command::Vacuous {
                formula: self.formula(formula),
            },
            ProofStep::UniversalInstantiation {
                variable,
                replacement,
                body,
            } => Command::Instantiation {
                variable: id(*variable),
                replacement: id(*replacement),
                body: self.formula(body),
            },
            ProofStep::EqualityReflexivity { variable } => Command::Reflexivity {
                variable: id(*variable),
            },
            ProofStep::EqualitySubstitution { from, to, body } => Command::Substitution {
                from: id(*from),
                to: id(*to),
                body: self.formula(body),
            },
            ProofStep::ZfcAxiom(axiom) => Command::Axiom {
                axiom: match axiom {
                    ZfcAxiom::Extensionality => Axiom::Extensionality,
                    ZfcAxiom::Pairing => Axiom::Pairing,
                    ZfcAxiom::Union => Axiom::Union,
                    ZfcAxiom::PowerSet => Axiom::PowerSet,
                    ZfcAxiom::Infinity => Axiom::Infinity,
                    ZfcAxiom::Foundation => Axiom::Foundation,
                    ZfcAxiom::Choice => Axiom::Choice,
                },
            },
            ProofStep::ProofReference { proof_id } => Command::ProofReference {
                proof_id: *proof_id.as_bytes(),
            },
            ProofStep::ModusPonens {
                premise,
                implication,
            } => Command::ModusPonens {
                premise: result(*premise),
                implication: result(*implication),
            },
            ProofStep::Generalization { premise, variable } => Command::Generalization {
                premise: result(*premise),
                variable: id(*variable),
            },
            ProofStep::Separation(_) | ProofStep::Replacement(_) => {
                unreachable!("schema handled before inference")
            }
        }
    }
}

// Certificate normalization assigns a dense sequence of free identifiers
// bounded by the certificate limits. Reserve the opposite end for binders.
// An open subtree keys on its actual binder identifiers, not tree shape alone.
fn binder(depth: u32) -> u32 {
    u32::MAX - depth
}

fn bound_identifier(depth: u32, index: u32) -> u32 {
    binder(depth - 1 - index)
}
