//! Mathematical authority for incrementally evaluated disk-backed programs.
//! Storage never establishes proofhood: only an evaluated axiom or inference
//! can produce a proved result. Reopening must recheck the committed prefix.
use crate::diagnostics::{Failure, OperandRole};
use naome_foundation::{
    Formula, FreeVariable,
    construction::{self as recipe, Expression},
};
use naome_proof::program::Command;

mod engine;
mod error;
mod schema;
pub use engine::{CheckedProgram, Engine, ProgramDependency, Status};
pub use error::Error;
pub use schema::{APPLICATION_ID, verify_database};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Value<F> {
    pub formula: F,
    pub proved: bool,
}
pub type Implication<F> = (F, F);

/// Reads are restricted by the evaluator to the prefix checked in this run.
/// Formula handles denote structurally interned, well-formed roots.
pub trait Context {
    type Formula: Copy + Eq;
    type Error;
    fn previous(&self, index: u64) -> Result<Value<Self::Formula>, Self::Error>;
    fn implication(
        &self,
        formula: Self::Formula,
    ) -> Result<Option<Implication<Self::Formula>>, Self::Error>;
    fn closed(&self, formula: Self::Formula) -> Result<bool, Self::Error>;
    fn fixed(&mut self, formula: &Formula) -> Result<Self::Formula, Self::Error>;
}

/// A rule failure remains separate from a storage/context access failure.
#[derive(Debug)]
pub enum PrepareError<E> {
    Check(Failure),
    Context(E),
}

pub struct Freshness<F> {
    pub predicate: F,
    pub variable: u32,
    pub replacement: u32,
    pub role: OperandRole,
}

pub struct Plan<F> {
    pub construction: Construction<F>,
    pub proved: bool,
    pub seal: bool,
    /// Schema freshness is checked by a disk-backed substitution. Its result
    /// must equal its input; these are at most two fixed schema roles.
    pub absent: Vec<Freshness<F>>,
}

pub enum Construction<F> {
    Formula(Expression<F>),
    Reference(naome_proof::ProofId),
    Definition(naome_proof::DefinitionId, Vec<u32>),
}

/// Derive a fixed-size construction recipe from previously checked results.
pub fn prepare<C: Context>(
    command: &Command,
    position: u64,
    context: &mut C,
) -> Result<Plan<C::Formula>, PrepareError<C::Error>> {
    use OperandRole as R;
    let previous =
        |index, proof: bool, role| -> Result<Value<C::Formula>, PrepareError<C::Error>> {
            if index >= position {
                return Err(PrepareError::Check(Failure::ReferenceNotEarlier {
                    operand: role,
                    reference: index,
                }));
            }
            let value = context.previous(index).map_err(PrepareError::Context)?;
            if proof && !value.proved {
                return Err(PrepareError::Check(Failure::InputNotProved {
                    operand: role,
                    reference: index,
                }));
            }
            Ok(value)
        };
    let formula = |index, role| previous(index, false, role).map(|v| v.formula);
    let proved = |index, role| previous(index, true, role).map(|v| v.formula);
    let variable = FreeVariable::new;
    let mut absent = Vec::new();
    let mut is_proved = true;
    let mut seal = false;
    let expression = match *command {
        Command::DefinedRelation {
            definition_id,
            ref arguments,
        } => {
            return Ok(Plan {
                construction: Construction::Definition(
                    naome_proof::DefinitionId::from_bytes(definition_id),
                    arguments.clone(),
                ),
                proved: false,
                seal: false,
                absent,
            });
        }
        Command::Equal { left, right } => {
            is_proved = false;
            Expression::Equal(variable(left), variable(right))
        }
        Command::Member { element, set } => {
            is_proved = false;
            Expression::Member(variable(element), variable(set))
        }
        Command::Not { formula: input } => {
            is_proved = false;
            Expression::Input(formula(input, R::Formula)?).negate()
        }
        Command::Implies {
            antecedent,
            consequent,
        } => {
            is_proved = false;
            Expression::Input(formula(antecedent, R::Antecedent)?)
                .implies(Expression::Input(formula(consequent, R::Consequent)?))
        }
        Command::ForAll { variable: v, body } => {
            is_proved = false;
            Expression::Input(formula(body, R::Body)?).for_all(variable(v))
        }
        Command::Substitute { from, to, body } => {
            is_proved = false;
            Expression::Input(formula(body, R::Body)?).substitute(variable(from), variable(to))
        }
        Command::Simplification {
            antecedent,
            consequent,
        } => recipe::simplification(
            formula(antecedent, R::Antecedent)?,
            formula(consequent, R::Consequent)?,
        ),
        Command::Frege {
            first,
            second,
            third,
        } => recipe::frege(
            formula(first, R::First)?,
            formula(second, R::Second)?,
            formula(third, R::Third)?,
        ),
        Command::Contraposition {
            antecedent,
            consequent,
        } => recipe::contraposition(
            formula(antecedent, R::Antecedent)?,
            formula(consequent, R::Consequent)?,
        ),
        Command::Distribution {
            variable: v,
            antecedent,
            consequent,
        } => recipe::distribution(
            variable(v),
            formula(antecedent, R::Antecedent)?,
            formula(consequent, R::Consequent)?,
        ),
        Command::Vacuous { formula: input } => recipe::vacuous(formula(input, R::Formula)?),
        Command::Instantiation {
            variable: v,
            replacement,
            body,
        } => recipe::instantiation(variable(v), variable(replacement), formula(body, R::Body)?),
        Command::Reflexivity { variable: v } => Expression::Equal(variable(v), variable(v)),
        Command::Substitution { from, to, body } => {
            recipe::substitution(variable(from), variable(to), formula(body, R::Body)?)
        }
        Command::Axiom { axiom } => Expression::Input(
            context
                .fixed(&naome_foundation::ZfcAxiom::from(axiom).formula())
                .map_err(PrepareError::Context)?,
        ),
        Command::ProofReference { proof_id } => {
            return Ok(Plan {
                construction: Construction::Reference(naome_proof::ProofId::from_bytes(proof_id)),
                proved: true,
                seal: false,
                absent,
            });
        }
        Command::Separation {
            predicate,
            element,
            source,
            result,
        } => {
            distinct(&[
                (R::Element, element),
                (R::Source, source),
                (R::Result, result),
            ])
            .map_err(PrepareError::Check)?;
            let predicate = formula(predicate, R::Predicate)?;
            absent.push(Freshness {
                predicate,
                variable: result,
                replacement: element,
                role: R::Result,
            });
            recipe::separation(
                predicate,
                variable(element),
                variable(source),
                variable(result),
            )
        }
        Command::Replacement {
            predicate,
            input,
            output,
            witness,
            source,
            result,
        } => {
            distinct(&[
                (R::Input, input),
                (R::Output, output),
                (R::Witness, witness),
                (R::Source, source),
                (R::Result, result),
            ])
            .map_err(PrepareError::Check)?;
            let predicate = formula(predicate, R::Predicate)?;
            absent.push(Freshness {
                predicate,
                variable: witness,
                replacement: input,
                role: R::Witness,
            });
            absent.push(Freshness {
                predicate,
                variable: result,
                replacement: input,
                role: R::Result,
            });
            recipe::replacement(
                predicate,
                variable(input),
                variable(output),
                variable(witness),
                variable(source),
                variable(result),
            )
        }
        Command::ModusPonens {
            premise,
            implication,
        } => {
            let premise = proved(premise, R::Premise)?;
            let implication = proved(implication, R::Implication)?;
            let Some((antecedent, consequent)) = context
                .implication(implication)
                .map_err(PrepareError::Context)?
            else {
                return Err(PrepareError::Check(Failure::ExpectedImplication {
                    operand: R::Implication,
                }));
            };
            if antecedent != premise {
                return Err(PrepareError::Check(Failure::AntecedentMismatch));
            }
            Expression::Input(consequent)
        }
        Command::Generalization {
            premise,
            variable: v,
        } => Expression::Input(proved(premise, R::Premise)?).for_all(variable(v)),
        Command::Alias { input } => {
            let value = previous(input, false, R::Input)?;
            is_proved = value.proved;
            Expression::Input(value.formula)
        }
        Command::Seal { proof } => {
            let conclusion = proved(proof, R::Conclusion)?;
            if !context.closed(conclusion).map_err(PrepareError::Context)? {
                return Err(PrepareError::Check(Failure::OpenConclusion));
            }
            seal = true;
            Expression::Input(conclusion)
        }
    };
    Ok(Plan {
        construction: Construction::Formula(expression),
        proved: is_proved,
        seal,
        absent,
    })
}
fn distinct(variables: &[(OperandRole, u32)]) -> Result<(), Failure> {
    for (i, (_, variable)) in variables.iter().enumerate() {
        if variables[..i].iter().any(|(_, other)| other == variable) {
            return Err(Failure::RoleCollision {
                variable: *variable,
                roles: variables
                    .iter()
                    .filter(|(_, value)| value == variable)
                    .map(|(role, _)| *role)
                    .collect(),
            });
        }
    }
    Ok(())
}
