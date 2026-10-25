//! Finite structural candidates with separately checked proofs in both directions.
//! The index key is only a lookup hint; it never identifies a formal statement.
use super::*;
use deduction::{Failure, INVALID, LIMIT, Plan};
use naome_foundation::{FreeVariable, Logic};

mod certificate;

struct Theorem {
    root: u32,
    formula: Formula,
}

fn length(formula: &Formula) -> Result<usize, Failure> {
    formula
        .encode_canonical()
        .map(|bytes| bytes.len())
        .map_err(|_| LIMIT)
}

fn reserve(formulas: &[&Formula], work: &mut Work) -> Result<(), Failure> {
    let bytes = formulas.iter().try_fold(0usize, |sum, formula| {
        sum.checked_add(length(formula)?).ok_or(LIMIT)
    })?;
    work.formula(bytes, 32)
}

fn axiom(
    plan: &mut Plan,
    step: ProofStep,
    formula: Formula,
    work: &mut Work,
) -> Result<Theorem, Failure> {
    let root = plan.axiom(step, length(&formula)?, work)?;
    Ok(Theorem { root, formula })
}

fn apply(
    plan: &mut Plan,
    premise: &Theorem,
    implication: &Theorem,
    work: &mut Work,
) -> Result<Theorem, Failure> {
    reserve(&[&premise.formula, &implication.formula], work)?;
    let (antecedent, consequent) = implication.formula.implication_parts().ok_or(INVALID)?;
    if antecedent != premise.formula {
        return Err(INVALID);
    }
    let formula = consequent.clone();
    let root = plan.modus_ponens(premise.root, implication.root, length(&formula)?, work)?;
    Ok(Theorem { root, formula })
}

fn chain(
    plan: &mut Plan,
    first: Theorem,
    second: Theorem,
    work: &mut Work,
) -> Result<Theorem, Failure> {
    reserve(&[&first.formula, &second.formula], work)?;
    let (a, b) = first.formula.implication_parts().ok_or(INVALID)?;
    let (middle, c) = second.formula.implication_parts().ok_or(INVALID)?;
    if b != middle {
        return Err(INVALID);
    }
    let lifted = axiom(
        plan,
        ProofStep::Simplification {
            antecedent: second.formula.clone().into(),
            consequent: a.clone().into(),
        },
        Logic::simplification(second.formula.clone(), a.clone()),
        work,
    )?;
    let lifted = apply(plan, &second, &lifted, work)?;
    let distribution = axiom(
        plan,
        ProofStep::Frege {
            first: a.clone().into(),
            second: b.clone().into(),
            third: c.clone().into(),
        },
        Logic::frege(a.clone(), b.clone(), c.clone()),
        work,
    )?;
    let partial = apply(plan, &lifted, &distribution, work)?;
    apply(plan, &first, &partial, work)
}

fn extend(
    plan: &mut Plan,
    current: Option<Theorem>,
    next: Theorem,
    work: &mut Work,
) -> Result<Option<Theorem>, Failure> {
    Ok(Some(match current {
        Some(current) => chain(plan, current, next, work)?,
        None => next,
    }))
}

fn unwrapped(formula: &Formula) -> Vec<Formula> {
    let mut levels = vec![formula.clone()];
    while let Some(body) = levels
        .last()
        .and_then(|formula| formula.open_outer_universal(FreeVariable::new(0)))
    {
        if !body.is_closed() {
            break;
        }
        levels.push(body);
    }
    levels
}

fn parts(formula: &Formula) -> Option<(Formula, Formula, bool)> {
    let (inner, negative) = match formula.view().negated() {
        Some(inner) => (inner, true),
        None => (formula.view(), false),
    };
    let (left, right) = inner.implication_parts()?;
    Some((left.to_owned(), right.negated()?.to_owned(), negative))
}

fn swapped(a: Formula, b: Formula, negative: bool) -> Formula {
    let implication = Formula::implies(b, Formula::negate(a));
    if negative {
        Formula::negate(implication)
    } else {
        implication
    }
}

/// The complete derived registry bucket for outer vacuity and the single
/// root exchange `(A -> not(B)) <-> (B -> not(A))`, including its negation.
pub(super) fn key(formula: &Formula) -> Result<StatementId, ContextError> {
    let levels = unwrapped(formula);
    let core = levels.last().expect("initial equivalence level");
    let mut bytes = core.encode_canonical().map_err(|_| ContextError::Limit)?;
    if let Some((a, b, negative)) = parts(core) {
        let alternate = swapped(a, b, negative)
            .encode_canonical()
            .map_err(|_| ContextError::Limit)?;
        if alternate < bytes {
            bytes = alternate;
        }
    }
    let mut hash = Sha256::new();
    hash.update(b"naome:question:elementary-equivalence:v1\0");
    hash.update(bytes);
    Ok(StatementId::from_bytes(hash.finalize().into()))
}

pub(super) fn reserve_key(formula: &Formula, work: &mut Work) -> Result<(), Failure> {
    let (_, depth) = formula.view().node_count_and_depth();
    work.formula(
        length(formula)?,
        depth
            .checked_mul(8)
            .and_then(|n| n.checked_add(32))
            .ok_or(LIMIT)?,
    )
}

pub(super) struct ProvenEquivalence {
    pub(super) record: Identity,
    pub(super) certificates: [DeductionWitness; 2],
}

pub(super) fn assess(
    question: &AssessmentQuestion<'_>,
    snapshot: &KnowledgeSnapshot<'_>,
    work: &mut Work,
) -> Result<Option<ProvenEquivalence>, Failure> {
    // First-discovery filtering must not revoke previously admitted work when
    // a stronger finite rule set discovers equivalences after an upgrade.
    if question.registered_record.is_some() || snapshot.questions.is_empty() {
        return Ok(None);
    }
    reserve_key(question.formula, work)?;
    let key = key(question.formula).map_err(context_failure)?;
    work.index()?;
    for record in snapshot
        .questions
        .records_for(key)
        .map_err(context_failure)?
    {
        let record = record.map_err(context_failure)?;
        work.index()?;
        work.formula(
            length(question.formula)? + AssessmentLimits::MAXIMUM.formula_nodes,
            64,
        )?;
        let related = snapshot
            .questions
            .get(&record)
            .map_err(context_failure)?
            .ok_or((RejectionReason::InvalidRegistry, "Q02_EQUIVALENCE_INDEX"))?;
        if let Some(forward) = prove(question.formula, &related, snapshot.artifacts, work)? {
            let backward = prove(&related, question.formula, snapshot.artifacts, work)?.ok_or((
                RejectionReason::InvalidEvidence,
                "Q05_ELEMENTARY_EQUIVALENCE",
            ))?;
            return Ok(Some(ProvenEquivalence {
                record,
                certificates: [forward, backward],
            }));
        }
    }
    Ok(None)
}

/// Synthesizes one direction only for the declared finite structural rules.
/// The complete certificate is checked again against the actual receiver.
pub(super) fn prove(
    from: &Formula,
    to: &Formula,
    artifacts: &dyn ContextView,
    work: &mut Work,
) -> Result<Option<DeductionWitness>, Failure> {
    reserve_key(from, work)?;
    reserve_key(to, work)?;
    let from_levels = unwrapped(from);
    let to_levels = unwrapped(to);
    let from_core = from_levels.last().ok_or(INVALID)?;
    let to_core = to_levels.last().ok_or(INVALID)?;
    let exchange = if from_core == to_core {
        None
    } else if let Some((a, b, negative)) = parts(from_core)
        && swapped(a.clone(), b.clone(), negative) == *to_core
    {
        Some((a, b, negative))
    } else {
        return Ok(None);
    };
    let mut plan = Plan::new();
    let mut current = None;
    for levels in from_levels.windows(2) {
        reserve(&[&levels[0], &levels[1]], work)?;
        let next = axiom(
            &mut plan,
            ProofStep::UniversalInstantiation {
                variable: FreeVariable::new(0),
                replacement: FreeVariable::new(0),
                body: levels[1].clone().into(),
            },
            Formula::implies(levels[0].clone(), levels[1].clone()),
            work,
        )?;
        current = extend(&mut plan, current, next, work)?;
    }
    if let Some((a, b, negative)) = exchange {
        let next = if negative {
            // Exchange the unnegated implications in the reverse direction,
            // then use a separately derived contraposition theorem.
            reserve(&[&a, &b], work)?;
            let p = Formula::implies(a.clone(), Formula::negate(b.clone()));
            let q = Formula::implies(b.clone(), Formula::negate(a.clone()));
            let reverse = certificate::commutation(&mut plan, &b, &a, work)?;
            let contraposition = certificate::contraposition(&mut plan, &q, &p, work)?;
            apply(&mut plan, &reverse, &contraposition, work)?
        } else {
            certificate::commutation(&mut plan, &a, &b, work)?
        };
        current = extend(&mut plan, current, next, work)?;
    }
    for levels in to_levels.windows(2).rev() {
        reserve(&[&levels[0], &levels[1]], work)?;
        let next = axiom(
            &mut plan,
            ProofStep::VacuousUniversal {
                formula: levels[1].clone().into(),
            },
            Formula::implies(levels[1].clone(), levels[0].clone()),
            work,
        )?;
        current = extend(&mut plan, current, next, work)?;
    }
    let target = Formula::implies(from.clone(), to.clone());
    if let Some(current) = current {
        if current.formula != target {
            return Err(INVALID);
        }
        plan.finish(&target, artifacts, work).map(Some)
    } else {
        elementary::plan(&target, work)?
            .ok_or(INVALID)?
            .finish(&target, artifacts, work)
            .map(Some)
    }
}

#[cfg(test)]
mod tests;
