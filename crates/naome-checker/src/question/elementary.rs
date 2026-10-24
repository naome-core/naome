//! Bounded certificate synthesis for elementary Foundation theorems.
//!
//! Recognizes primitive logical axiom instances, A -> A, reflexivity, and the
//! seven fixed ZFC axioms, with outer universal closure. Recognition confers
//! no validity: the caller must check the entire resulting certificate.

use naome_foundation::{Formula, FreeVariable, Logic, ZfcAxiom};
use naome_proof::ProofStep;

use super::{
    Work,
    deduction::{Failure, LIMIT, Plan},
};

pub(super) fn plan(target: &Formula, work: &mut Work) -> Result<Option<Plan>, Failure> {
    let length = target.encode_canonical().map_err(|_| LIMIT)?.len();
    work.formula(length, 64)?;
    let mut plan = Plan::new();
    for axiom in [
        ZfcAxiom::Extensionality,
        ZfcAxiom::Pairing,
        ZfcAxiom::Union,
        ZfcAxiom::PowerSet,
        ZfcAxiom::Infinity,
        ZfcAxiom::Foundation,
        ZfcAxiom::Choice,
    ] {
        work.formula(length, 2)?;
        if axiom.formula() == *target {
            plan.axiom(ProofStep::ZfcAxiom(axiom), length, work)?;
            return Ok(Some(plan));
        }
    }
    let mut current = target.clone();
    let mut variables = Vec::new();
    for identifier in 0..super::instantiation::MAX_INSTANTIATIONS {
        work.formula(length, 4)?;
        let variable = fresh(&current, identifier as u32);
        let Some(body) = current.open_outer_universal(variable) else {
            break;
        };
        variables.push(variable);
        current = body;
    }
    let current_length = current.encode_canonical().map_err(|_| LIMIT)?.len();
    let root = if let Some((left, right)) = current.view().equality_variables()
        && left == right
    {
        plan.axiom(
            ProofStep::EqualityReflexivity { variable: left },
            current_length,
            work,
        )?
    } else if let Some((left, right)) = current.view().implication_parts()
        && left == right
    {
        identity(&mut plan, left.to_owned(), work)?
    } else if let Some(step) = axiom_instance(&current, work)? {
        plan.axiom(step, current_length, work)?
    } else {
        return Ok(None);
    };
    let mut root = root;
    for variable in variables.into_iter().rev() {
        root = plan.generalize(root, variable, work)?;
    }
    Ok(Some(plan))
}

fn fresh(formula: &Formula, start: u32) -> FreeVariable {
    let variables = formula.free_variables();
    (start..)
        .map(FreeVariable::new)
        .find(|variable| !variables.contains(variable))
        .expect("a bounded formula cannot exhaust u32 variables")
}

fn identity(plan: &mut Plan, formula: Formula, work: &mut Work) -> Result<u32, Failure> {
    let implies_self = Formula::implies(formula.clone(), formula.clone());
    let first = Logic::simplification(formula.clone(), implies_self.clone());
    let second = Logic::simplification(formula.clone(), formula.clone());
    let frege = Logic::frege(formula.clone(), implies_self.clone(), formula.clone());
    let intermediate = Formula::implies(second.clone(), implies_self.clone());
    let length = |formula: &Formula| {
        formula
            .encode_canonical()
            .map(|bytes| bytes.len())
            .map_err(|_| LIMIT)
    };
    let conclusion_length = length(&implies_self)?;
    let a = plan.axiom(
        ProofStep::Simplification {
            antecedent: formula.clone().into(),
            consequent: implies_self.clone().into(),
        },
        length(&first)?,
        work,
    )?;
    let b = plan.axiom(
        ProofStep::Simplification {
            antecedent: formula.clone().into(),
            consequent: formula.clone().into(),
        },
        length(&second)?,
        work,
    )?;
    let c = plan.axiom(
        ProofStep::Frege {
            first: formula.clone().into(),
            second: implies_self.into(),
            third: formula.into(),
        },
        length(&frege)?,
        work,
    )?;
    let d = plan.modus_ponens(a, c, length(&intermediate)?, work)?;
    plan.modus_ponens(b, d, conclusion_length, work)
}

fn axiom_instance(formula: &Formula, work: &mut Work) -> Result<Option<ProofStep>, Failure> {
    let Some((left, right)) = formula.view().implication_parts() else {
        return Ok(None);
    };
    if let Some((second, repeated)) = right.implication_parts()
        && repeated == left
    {
        return Ok(Some(ProofStep::Simplification {
            antecedent: left.to_owned().into(),
            consequent: second.to_owned().into(),
        }));
    }
    if let Some((a, bc)) = left.implication_parts()
        && let Some((b, c)) = bc.implication_parts()
        && let Some((ab, ac)) = right.implication_parts()
        && ab.implication_parts() == Some((a, b))
        && ac.implication_parts() == Some((a, c))
    {
        return Ok(Some(ProofStep::Frege {
            first: a.to_owned().into(),
            second: b.to_owned().into(),
            third: c.to_owned().into(),
        }));
    }
    if let Some((not_b, not_a)) = left.implication_parts()
        && let Some((a, b)) = right.implication_parts()
        && not_b.negated() == Some(b)
        && not_a.negated() == Some(a)
    {
        return Ok(Some(ProofStep::ClassicalContraposition {
            antecedent: a.to_owned().into(),
            consequent: b.to_owned().into(),
        }));
    }
    if let Some((from, to)) = left.equality_variables()
        && let Some((body, substituted)) = right.implication_parts()
        && body.to_owned().substitute_free(from, to) == substituted.to_owned()
    {
        return Ok(Some(ProofStep::EqualitySubstitution {
            from,
            to,
            body: body.to_owned().into(),
        }));
    }
    let variable = fresh(formula, 0);
    if let Some(body) = right.to_owned().open_outer_universal(variable)
        && body == left.to_owned()
    {
        return Ok(Some(ProofStep::VacuousUniversal {
            formula: left.to_owned().into(),
        }));
    }
    if let Some(body) = left.to_owned().open_outer_universal(variable) {
        let length = formula.encode_canonical().map_err(|_| LIMIT)?.len();
        let mut replacements = formula.free_variables();
        replacements.insert(variable);
        for replacement in replacements {
            work.formula(length, 8)?;
            if body.clone().substitute_free(variable, replacement) == right.to_owned() {
                return Ok(Some(ProofStep::UniversalInstantiation {
                    variable,
                    replacement,
                    body: body.into(),
                }));
            }
        }
        if let Some((antecedent, consequent)) = body.implication_parts()
            && Logic::universal_distribution(variable, antecedent.clone(), consequent.clone())
                == *formula
        {
            return Ok(Some(ProofStep::UniversalDistribution {
                variable,
                antecedent: antecedent.into(),
                consequent: consequent.into(),
            }));
        }
    }
    Ok(None)
}
