//! Mathematical authority for incrementally evaluated disk-backed programs.
//! Storage never establishes proofhood: only an evaluated axiom or inference
//! can produce a proved result. Reopening must recheck the committed prefix.
use naome_foundation::{
    Formula, FreeVariable,
    construction::{self as recipe, Expression},
};
use naome_proof::program::Command;

mod engine;
mod error;
pub use engine::{
    APPLICATION_ID, CheckedProgram, Engine, ProgramDependency, SCHEMA_VERSION, Status,
};
pub use error::Error;

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
    fn previous(&self, index: u64) -> Result<Value<Self::Formula>, String>;
    fn implication(
        &self,
        formula: Self::Formula,
    ) -> Result<Option<Implication<Self::Formula>>, String>;
    fn closed(&self, formula: Self::Formula) -> Result<bool, String>;
    fn fixed(&mut self, formula: &Formula) -> Result<Self::Formula, String>;
}

pub struct Plan<F> {
    pub construction: Construction<F>,
    pub proved: bool,
    pub seal: bool,
    /// Schema freshness is checked by a disk-backed substitution. Its result
    /// must equal its input; these are at most two fixed schema roles.
    pub absent: Vec<(F, u32, u32)>,
}

pub enum Construction<F> {
    Formula(Expression<F>),
    Reference(naome_proof::ProofId),
}

/// Derive a fixed-size construction recipe from previously checked results.
pub fn prepare<C: Context>(
    command: &Command,
    position: u64,
    context: &mut C,
) -> Result<Plan<C::Formula>, String> {
    let previous = |index, proof: bool| -> Result<Value<C::Formula>, String> {
        if index >= position {
            return Err("program references must point strictly backward".into());
        }
        let value = context.previous(index)?;
        if proof && !value.proved {
            return Err("inference input is a formula, not a proved result".into());
        }
        Ok(value)
    };
    let formula = |index| previous(index, false).map(|v| v.formula);
    let proved = |index| previous(index, true).map(|v| v.formula);
    let variable = FreeVariable::new;
    let mut absent = Vec::new();
    let mut is_proved = true;
    let mut seal = false;
    let expression = match *command {
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
            Expression::Input(formula(input)?).negate()
        }
        Command::Implies {
            antecedent,
            consequent,
        } => {
            is_proved = false;
            Expression::Input(formula(antecedent)?).implies(Expression::Input(formula(consequent)?))
        }
        Command::ForAll { variable: v, body } => {
            is_proved = false;
            Expression::Input(formula(body)?).for_all(variable(v))
        }
        Command::Substitute { from, to, body } => {
            is_proved = false;
            Expression::Input(formula(body)?).substitute(variable(from), variable(to))
        }
        Command::Simplification {
            antecedent,
            consequent,
        } => recipe::simplification(formula(antecedent)?, formula(consequent)?),
        Command::Frege {
            first,
            second,
            third,
        } => recipe::frege(formula(first)?, formula(second)?, formula(third)?),
        Command::Contraposition {
            antecedent,
            consequent,
        } => recipe::contraposition(formula(antecedent)?, formula(consequent)?),
        Command::Distribution {
            variable: v,
            antecedent,
            consequent,
        } => recipe::distribution(variable(v), formula(antecedent)?, formula(consequent)?),
        Command::Vacuous { formula: input } => recipe::vacuous(formula(input)?),
        Command::Instantiation {
            variable: v,
            replacement,
            body,
        } => recipe::instantiation(variable(v), variable(replacement), formula(body)?),
        Command::Reflexivity { variable: v } => Expression::Equal(variable(v), variable(v)),
        Command::Substitution { from, to, body } => {
            recipe::substitution(variable(from), variable(to), formula(body)?)
        }
        Command::Axiom { axiom } => {
            Expression::Input(context.fixed(&naome_foundation::ZfcAxiom::from(axiom).formula())?)
        }
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
            distinct(&[element, source, result])?;
            let predicate = formula(predicate)?;
            absent.push((predicate, result, element));
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
            distinct(&[input, output, witness, source, result])?;
            let predicate = formula(predicate)?;
            absent.push((predicate, witness, input));
            absent.push((predicate, result, input));
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
            let premise = proved(premise)?;
            let implication = proved(implication)?;
            let Some((antecedent, consequent)) = context.implication(implication)? else {
                return Err("modus ponens requires an implication".into());
            };
            if antecedent != premise {
                return Err("modus ponens antecedent mismatch".into());
            }
            Expression::Input(consequent)
        }
        Command::Generalization {
            premise,
            variable: v,
        } => Expression::Input(proved(premise)?).for_all(variable(v)),
        Command::Alias { input } => {
            let value = previous(input, false)?;
            is_proved = value.proved;
            Expression::Input(value.formula)
        }
        Command::Seal { proof } => {
            let conclusion = proved(proof)?;
            if !context.closed(conclusion)? {
                return Err("program conclusion is not closed".into());
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
fn distinct(variables: &[u32]) -> Result<(), String> {
    for (i, v) in variables.iter().enumerate() {
        if variables[..i].contains(v) {
            return Err("schema role variables must be distinct".into());
        }
    }
    Ok(())
}
