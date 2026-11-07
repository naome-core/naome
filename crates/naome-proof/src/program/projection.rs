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
    results: Vec<u64>,
}

impl Projection {
    pub fn from_normal_form(proof: &ProofNormalForm) -> Self {
        let mut builder = Builder::default();
        let mut results = Vec::with_capacity(proof.certificate().steps().len());
        for step in proof.certificate().steps() {
            let position = builder.step(step, &results);
            results.push(position);
        }
        builder.push(Command::Seal {
            proof: *results.last().expect("a certificate is nonempty"),
        });
        Self {
            commands: builder.commands,
            results,
        }
    }

    pub fn commands(&self) -> &[Command] {
        &self.commands
    }

    /// Program positions of the corresponding normalized certificate results.
    /// Schema parameter closures map to the last enclosing generalization.
    pub fn results(&self) -> &[u64] {
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
