//! Untrusted proof recipes compiling classical reasoning to K/S/C and MP.
//! Every complete result must still pass the independent native checker.
use super::proof::{Kernel, Term};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::ProofStep;

#[derive(Default)]
pub struct Names(pub usize);
impl Names {
    pub fn assumption(&mut self, formula: Formula) -> (usize, Term) {
        let id = self.0;
        self.0 += 1;
        (id, Term::Variable(id, formula))
    }
}
pub fn not(formula: Formula) -> Formula {
    Formula::negate(formula)
}
pub fn app(function: Term, argument: Term) -> Result<Term, String> {
    Term::apply(function, argument)
}
pub fn axiom(step: ProofStep) -> Result<Term, String> {
    Ok(Term::Kernel(Kernel::new(step)?))
}
pub fn identity(formula: Formula, names: &mut Names) -> Term {
    let (id, value) = names.assumption(formula.clone());
    Term::Lambda(id, formula, Box::new(value))
}
pub fn classical(a: Formula, b: Formula) -> Result<Term, String> {
    axiom(ProofStep::ClassicalContraposition {
        antecedent: a.into(),
        consequent: b.into(),
    })
}

/// Derive arbitrary Q from P and not(P), using only K/C/MP.
pub fn explosion(
    positive: Term,
    negative: Term,
    goal: Formula,
    names: &mut Names,
) -> Result<Term, String> {
    let p = positive.formula();
    if negative.formula() != not(p.clone()) {
        return Err("contradiction operands differ".into());
    }
    let (id, _) = names.assumption(not(goal.clone()));
    let bridge = Term::Lambda(id, not(goal.clone()), Box::new(negative));
    app(app(classical(p, goal)?, bridge)?, positive)
}

/// Discharge not(T) after an actual contradiction; I=(T->T) is independently
/// derivable, and C turns (not(T)->not(I)) into (I->T).
pub fn raa(
    goal: Formula,
    assumption: usize,
    positive: Term,
    negative: Term,
    names: &mut Names,
) -> Result<Term, String> {
    let i = Formula::implies(goal.clone(), goal.clone());
    let not_i = explosion(positive, negative, not(i.clone()), names)?;
    let bridge = Term::Lambda(assumption, not(goal.clone()), Box::new(not_i));
    app(
        app(classical(i, goal.clone())?, bridge)?,
        identity(goal, names),
    )
}

pub fn double_elim(value: Term, names: &mut Names) -> Result<Term, String> {
    let formula = value.formula();
    let p = formula
        .view()
        .negated()
        .and_then(|f| f.negated())
        .ok_or("double negation expected")?
        .to_owned();
    let (id, np) = names.assumption(not(p.clone()));
    raa(p, id, np, value, names)
}

pub fn double_intro(value: Term, names: &mut Names) -> Result<Term, String> {
    let p = value.formula();
    let nnp = not(not(p.clone()));
    let (id, nnnp) = names.assumption(not(nnp.clone()));
    let np = double_elim(nnnp, names)?;
    raa(nnp, id, value, np, names)
}

/// Discharge P after a contradiction by replaying the branch under not(not P).
pub fn neg_intro(
    assumption: usize,
    p: Formula,
    positive: Term,
    negative: Term,
    names: &mut Names,
) -> Result<Term, String> {
    let (id, nnp) = names.assumption(not(not(p.clone())));
    let value = double_elim(nnp, names)?;
    let a = app(
        Term::Lambda(assumption, p.clone(), Box::new(positive)),
        value.clone(),
    )?;
    let b = app(
        Term::Lambda(assumption, p.clone(), Box::new(negative)),
        value,
    )?;
    raa(not(p), id, a, b, names)
}

pub fn not_implies(value: Term, names: &mut Names) -> Result<(Term, Term), String> {
    let f = value.formula();
    let (a, b) = f
        .view()
        .negated()
        .and_then(|f| f.implication_parts())
        .ok_or("negated implication expected")?;
    let a = a.to_owned();
    let b = b.to_owned();
    let (id, na) = names.assumption(not(a.clone()));
    let (j, av) = names.assumption(a.clone());
    let bv = explosion(av, na, b.clone(), names)?;
    let implication = Term::Lambda(j, a.clone(), Box::new(bv));
    let positive = raa(a.clone(), id, implication, value.clone(), names)?;
    let (k, bv) = names.assumption(b.clone());
    let (l, _) = names.assumption(a.clone());
    let implication = Term::Lambda(l, a, Box::new(bv));
    let negative = neg_intro(k, b, implication, value, names)?;
    Ok((positive, negative))
}

pub fn instantiate(value: Term, replacement: FreeVariable) -> Result<Term, String> {
    let formula = value.formula();
    let used = formula.free_variables();
    let variable = (0..=u32::MAX)
        .map(FreeVariable::new)
        .find(|v| *v != replacement && !used.contains(v))
        .ok_or("fresh variable space")?;
    let body = formula
        .open_outer_universal(variable)
        .ok_or("universal premise expected")?;
    let law = axiom(ProofStep::UniversalInstantiation {
        variable,
        replacement,
        body: body.into(),
    })?;
    app(law, value)
}

pub fn substitute(
    equality: Term,
    value: Term,
    from: FreeVariable,
    to: FreeVariable,
) -> Result<Term, String> {
    let law = axiom(ProofStep::EqualitySubstitution {
        from,
        to,
        body: value.formula().into(),
    })?;
    app(app(law, equality)?, value)
}
