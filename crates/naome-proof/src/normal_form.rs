use std::collections::{BTreeMap, btree_map::Entry};

use naome_foundation::{Formula, FreeVariable, Replacement, Separation};

use crate::{ProofCertificate, ProofStep, codec};

pub(super) fn normalize(certificate: ProofCertificate) -> ProofCertificate {
    let mut source = certificate.steps.into_iter().map(Some).collect::<Vec<_>>();
    let mut normalized_indices = vec![None; source.len()];
    let mut normalized_steps = Vec::new();
    let mut interned_steps = BTreeMap::new();
    let mut variables = VariableNormalizer::default();
    let mut traversal = vec![Visit::Enter(source.len() - 1)];

    while let Some(visit) = traversal.pop() {
        let position = match visit {
            Visit::Enter(position) | Visit::Exit(position) => position,
        };
        if normalized_indices[position].is_some() {
            continue;
        }

        match visit {
            Visit::Enter(_) => {
                traversal.push(Visit::Exit(position));
                let references = source[position]
                    .as_ref()
                    .expect("an unvisited proof step remains available")
                    .local_references();
                if let Some(reference) = references[1] {
                    traversal.push(Visit::Enter(reference as usize));
                }
                if let Some(reference) = references[0] {
                    traversal.push(Visit::Enter(reference as usize));
                }
            }
            Visit::Exit(_) => {
                let step = source[position]
                    .take()
                    .expect("an exiting proof step has not been consumed");
                let step = normalize_step(step, &normalized_indices, &mut variables);
                let mut key = Vec::new();
                codec::encode_step(&step, &mut key)
                    .expect("a certificate step remains canonically encodable");

                let normalized = match interned_steps.entry(key) {
                    Entry::Occupied(entry) => *entry.get(),
                    Entry::Vacant(entry) => {
                        let index = u32::try_from(normalized_steps.len())
                            .expect("the source certificate bounds normalized step indices");
                        entry.insert(index);
                        normalized_steps.push(step);
                        index
                    }
                };
                normalized_indices[position] = Some(normalized);
            }
        }
    }

    // Mapping fixed-width identifiers cannot enlarge a step; reachability and
    // interning only remove steps, so every source certificate limit remains.
    ProofCertificate {
        steps: normalized_steps,
    }
}

#[derive(Clone, Copy)]
enum Visit {
    Enter(usize),
    Exit(usize),
}

fn normalize_step(
    step: ProofStep,
    normalized_indices: &[Option<u32>],
    variables: &mut VariableNormalizer,
) -> ProofStep {
    match step {
        ProofStep::Simplification {
            antecedent,
            consequent,
        } => ProofStep::Simplification {
            antecedent: variables.formula(antecedent),
            consequent: variables.formula(consequent),
        },
        ProofStep::Frege {
            first,
            second,
            third,
        } => ProofStep::Frege {
            first: variables.formula(first),
            second: variables.formula(second),
            third: variables.formula(third),
        },
        ProofStep::ClassicalContraposition {
            antecedent,
            consequent,
        } => ProofStep::ClassicalContraposition {
            antecedent: variables.formula(antecedent),
            consequent: variables.formula(consequent),
        },
        ProofStep::UniversalDistribution {
            variable,
            antecedent,
            consequent,
        } => ProofStep::UniversalDistribution {
            variable: variables.variable(variable),
            antecedent: variables.formula(antecedent),
            consequent: variables.formula(consequent),
        },
        ProofStep::VacuousUniversal { formula } => ProofStep::VacuousUniversal {
            formula: variables.formula(formula),
        },
        ProofStep::UniversalInstantiation {
            variable,
            replacement,
            body,
        } => ProofStep::UniversalInstantiation {
            variable: variables.variable(variable),
            replacement: variables.variable(replacement),
            body: variables.formula(body),
        },
        ProofStep::EqualityReflexivity { variable } => ProofStep::EqualityReflexivity {
            variable: variables.variable(variable),
        },
        ProofStep::EqualitySubstitution { from, to, body } => ProofStep::EqualitySubstitution {
            from: variables.variable(from),
            to: variables.variable(to),
            body: variables.formula(body),
        },
        ProofStep::ZfcAxiom(axiom) => ProofStep::ZfcAxiom(axiom),
        ProofStep::Separation(instance) => {
            let Separation {
                predicate,
                element,
                source,
                result,
                parameters,
            } = instance;
            ProofStep::Separation(Separation {
                predicate: variables.formula(predicate),
                element: variables.variable(element),
                source: variables.variable(source),
                result: variables.variable(result),
                parameters: variables.variables(parameters),
            })
        }
        ProofStep::Replacement(instance) => {
            let Replacement {
                predicate,
                input,
                output,
                uniqueness_witness,
                source,
                result,
                parameters,
            } = instance;
            ProofStep::Replacement(Replacement {
                predicate: variables.formula(predicate),
                input: variables.variable(input),
                output: variables.variable(output),
                uniqueness_witness: variables.variable(uniqueness_witness),
                source: variables.variable(source),
                result: variables.variable(result),
                parameters: variables.variables(parameters),
            })
        }
        ProofStep::ProofReference { proof_id } => ProofStep::ProofReference { proof_id },
        ProofStep::ModusPonens {
            premise,
            implication,
        } => ProofStep::ModusPonens {
            premise: normalized_reference(premise, normalized_indices),
            implication: normalized_reference(implication, normalized_indices),
        },
        ProofStep::Generalization { premise, variable } => ProofStep::Generalization {
            premise: normalized_reference(premise, normalized_indices),
            variable: variables.variable(variable),
        },
    }
}

fn normalized_reference(reference: u32, normalized_indices: &[Option<u32>]) -> u32 {
    normalized_indices[reference as usize]
        .expect("dependency-first traversal normalizes every referenced step first")
}

#[derive(Default)]
struct VariableNormalizer {
    normalized: BTreeMap<FreeVariable, FreeVariable>,
    next_identifier: u32,
}

impl VariableNormalizer {
    fn formula(&mut self, formula: Formula) -> Formula {
        formula.map_free_variables(|variable| self.variable(variable))
    }

    fn variables(&mut self, variables: Vec<FreeVariable>) -> Vec<FreeVariable> {
        variables
            .into_iter()
            .map(|variable| self.variable(variable))
            .collect()
    }

    fn variable(&mut self, variable: FreeVariable) -> FreeVariable {
        match self.normalized.entry(variable) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let normalized = FreeVariable::new(self.next_identifier);
                self.next_identifier = self
                    .next_identifier
                    .checked_add(1)
                    .expect("the certificate byte limit bounds distinct free variables");
                entry.insert(normalized);
                normalized
            }
        }
    }
}

#[cfg(test)]
mod tests;
