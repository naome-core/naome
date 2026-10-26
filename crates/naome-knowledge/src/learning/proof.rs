//! Compile typed implication search into the existing primitive Hilbert calculus.

use naome_checker::ArtifactState;
use naome_foundation::{Formula, FreeVariable, Logic};
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;

mod kernel;
pub use kernel::Kernel;

pub const NATIVE_RESOURCE_LIMIT: &str =
    "native certificate or reconstructed formula resource limit";
pub const FORMULA_WORK_LIMIT: &str = "solver certificate formula-node limit";
pub const STEP_WORK_LIMIT: &str = "solver certificate work limit";

#[derive(Clone, Debug)]
pub enum Term {
    Variable(usize, Formula),
    Kernel(Kernel),
    Generalize(FreeVariable, Box<Self>),
    Apply(Box<Term>, Box<Term>, Formula),
    Lambda(usize, Formula, Box<Term>),
}

impl Term {
    pub fn free_assumptions(&self) -> std::collections::BTreeMap<usize, Formula> {
        fn visit(
            term: &Term,
            bound: &mut Vec<usize>,
            result: &mut std::collections::BTreeMap<usize, Formula>,
        ) {
            match term {
                Term::Variable(id, formula) if !bound.contains(id) => {
                    result.insert(*id, formula.clone());
                }
                Term::Apply(a, b, _) => {
                    visit(a, bound, result);
                    visit(b, bound, result);
                }
                Term::Generalize(_, body) => visit(body, bound, result),
                Term::Lambda(id, _, body) => {
                    bound.push(*id);
                    visit(body, bound, result);
                    bound.pop();
                }
                _ => {}
            }
        }
        let mut result = std::collections::BTreeMap::new();
        visit(self, &mut Vec::new(), &mut result);
        result
    }

    pub fn formula(&self) -> Formula {
        match self {
            Self::Variable(_, formula) | Self::Apply(_, _, formula) => formula.clone(),
            Self::Kernel(k) => k.formula(),
            Self::Generalize(variable, body) => Formula::for_all(*variable, body.formula()),
            Self::Lambda(_, argument, body) => Formula::implies(argument.clone(), body.formula()),
        }
    }

    pub fn apply(function: Self, argument: Self) -> Result<Self, String> {
        let formula = function.formula();
        let Some((expected, result)) = formula.view().implication_parts() else {
            return Err("application requires an implication".into());
        };
        if expected != argument.formula() {
            return Err("application antecedent differs".into());
        }
        Ok(Self::Apply(
            Box::new(function),
            Box::new(argument),
            result.to_owned(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Combinator {
    Variable(usize, Formula),
    Kernel(Kernel),
    Generalize(FreeVariable, Arc<Self>),
    K(Formula, Formula),
    S(Formula, Formula, Formula),
    Apply(Arc<Self>, Arc<Self>, Formula),
}

impl Combinator {
    fn formula(&self) -> Formula {
        match self {
            Self::Variable(_, formula) | Self::Apply(_, _, formula) => formula.clone(),
            Self::Kernel(k) => k.formula(),
            Self::Generalize(v, b) => Formula::for_all(*v, b.formula()),
            Self::K(a, b) => Logic::simplification(a.clone(), b.clone()),
            Self::S(a, b, c) => Logic::frege(a.clone(), b.clone(), c.clone()),
        }
    }

    fn contains(&self, variable: usize) -> bool {
        match self {
            Self::Variable(id, _) => *id == variable,
            Self::Apply(a, b, _) => a.contains(variable) || b.contains(variable),
            Self::Generalize(_, body) => body.contains(variable),
            _ => false,
        }
    }
}

fn apply(function: Arc<Combinator>, argument: Arc<Combinator>) -> Result<Arc<Combinator>, String> {
    let formula = function.formula();
    let Some((expected, result)) = formula.view().implication_parts() else {
        return Err("combinator application requires an implication".into());
    };
    if expected != argument.formula() {
        return Err("combinator application antecedent differs".into());
    }
    Ok(Arc::new(Combinator::Apply(
        function,
        argument,
        result.to_owned(),
    )))
}

fn abstract_variable(
    id: usize,
    argument: &Formula,
    body: Arc<Combinator>,
) -> Result<Arc<Combinator>, String> {
    if !body.contains(id) {
        return apply(
            Arc::new(Combinator::K(body.formula(), argument.clone())),
            body,
        );
    }
    match body.as_ref() {
        Combinator::Generalize(variable, inner) => {
            if argument.free_variables().contains(variable) {
                return Err("generalization eigenvariable occurs in an assumption".into());
            }
            let inner_formula = inner.formula();
            let abstracted = abstract_variable(id, argument, inner.clone())?;
            let quantified = Arc::new(Combinator::Generalize(*variable, abstracted));
            let distribution = Arc::new(Combinator::Kernel(Kernel::new(
                ProofStep::UniversalDistribution {
                    variable: *variable,
                    antecedent: argument.clone().into(),
                    consequent: inner_formula.into(),
                },
            )?));
            let lifted = apply(distribution, quantified)?;
            let vacuous = Arc::new(Combinator::Kernel(Kernel::new(
                ProofStep::VacuousUniversal {
                    formula: argument.clone().into(),
                },
            )?));
            let value = apply(
                vacuous,
                Arc::new(Combinator::Variable(id, argument.clone())),
            )?;
            abstract_variable(id, argument, apply(lifted, value)?)
        }
        Combinator::Variable(other, _) if *other == id => {
            let aa = Formula::implies(argument.clone(), argument.clone());
            let s = Arc::new(Combinator::S(
                argument.clone(),
                aa.clone(),
                argument.clone(),
            ));
            let first = Arc::new(Combinator::K(argument.clone(), aa));
            let second = Arc::new(Combinator::K(argument.clone(), argument.clone()));
            apply(apply(s, first)?, second)
        }
        Combinator::Apply(function, value, result) => {
            if matches!(value.as_ref(), Combinator::Variable(other, _) if *other == id)
                && !function.contains(id)
            {
                return Ok(function.clone());
            }
            let s = Arc::new(Combinator::S(
                argument.clone(),
                value.formula(),
                result.clone(),
            ));
            let function = abstract_variable(id, argument, function.clone())?;
            let value = abstract_variable(id, argument, value.clone())?;
            apply(apply(s, function)?, value)
        }
        _ => Err("unbound variable during bracket abstraction".into()),
    }
}

fn lower(term: &Term) -> Result<Arc<Combinator>, String> {
    match term {
        Term::Variable(id, formula) => Ok(Arc::new(Combinator::Variable(*id, formula.clone()))),
        Term::Kernel(k) => Ok(Arc::new(Combinator::Kernel(k.clone()))),
        Term::Generalize(v, body) => Ok(Arc::new(Combinator::Generalize(*v, lower(body)?))),
        Term::Apply(function, argument, _) => apply(lower(function)?, lower(argument)?),
        Term::Lambda(id, formula, body) => abstract_variable(*id, formula, lower(body)?),
    }
}

pub fn close(mut formula: Formula) -> Formula {
    for variable in formula.free_variables().into_iter().rev() {
        formula = Formula::for_all(variable, formula);
    }
    formula
}

pub struct Verified {
    pub certificate: ProofCertificate,
    pub target: Formula,
    pub native_id: ProofId,
    pub payload_bytes: usize,
}

/// No typed term is accepted as evidence until the existing checker accepts it.
pub fn verify(term: &Term, expected: &Formula) -> Result<Verified, String> {
    if term.formula() != *expected {
        return Err("search term differs from the requested target".into());
    }
    let root = lower(term)?;
    let mut steps = Vec::new();
    let mut cache = HashMap::new();
    let mut formula_nodes = 0usize;
    fn emit(
        term: &Arc<Combinator>,
        steps: &mut Vec<ProofStep>,
        cache: &mut HashMap<Arc<Combinator>, u32>,
        formula_nodes: &mut usize,
    ) -> Result<u32, String> {
        if let Some(index) = cache.get(term) {
            return Ok(*index);
        }
        let step = match term.as_ref() {
            Combinator::Variable(_, _) => return Err("certificate still has an assumption".into()),
            Combinator::Kernel(k) => k.step(),
            Combinator::Generalize(variable, body) => ProofStep::Generalization {
                premise: emit(body, steps, cache, formula_nodes)?,
                variable: *variable,
            },
            Combinator::K(a, b) => ProofStep::Simplification {
                antecedent: a.clone().into(),
                consequent: b.clone().into(),
            },
            Combinator::S(a, b, c) => ProofStep::Frege {
                first: a.clone().into(),
                second: b.clone().into(),
                third: c.clone().into(),
            },
            Combinator::Apply(function, argument, _) => {
                let implication = emit(function, steps, cache, formula_nodes)?;
                let premise = emit(argument, steps, cache, formula_nodes)?;
                ProofStep::ModusPonens {
                    premise,
                    implication,
                }
            }
        };
        *formula_nodes += match &step {
            ProofStep::Simplification {
                antecedent,
                consequent,
            } => [antecedent, consequent]
                .iter()
                .map(|formula| {
                    formula
                        .as_primitive()
                        .unwrap()
                        .view()
                        .node_count_and_depth()
                        .0
                })
                .sum::<usize>(),
            ProofStep::Frege {
                first,
                second,
                third,
            } => [first, second, third]
                .iter()
                .map(|formula| {
                    formula
                        .as_primitive()
                        .unwrap()
                        .view()
                        .node_count_and_depth()
                        .0
                })
                .sum::<usize>(),
            ProofStep::ClassicalContraposition {
                antecedent,
                consequent,
            }
            | ProofStep::UniversalDistribution {
                antecedent,
                consequent,
                ..
            } => [antecedent, consequent]
                .iter()
                .map(|f| f.as_primitive().unwrap().view().node_count_and_depth().0)
                .sum(),
            ProofStep::UniversalInstantiation { body, .. }
            | ProofStep::EqualitySubstitution { body, .. }
            | ProofStep::VacuousUniversal { formula: body } => {
                body.as_primitive().unwrap().view().node_count_and_depth().0
            }
            _ => 0,
        };
        if *formula_nodes > naome_proof::CERTIFICATE_MAX_FORMULA_NODES {
            return Err(FORMULA_WORK_LIMIT.into());
        }
        let index = u32::try_from(steps.len()).map_err(|_| "proof index width")?;
        steps.push(step);
        if steps.len() > crate::resources::limits().closure_steps.min(16_384) {
            return Err(STEP_WORK_LIMIT.into());
        }
        cache.insert(term.clone(), index);
        Ok(index)
    }
    let mut index = emit(&root, &mut steps, &mut cache, &mut formula_nodes)?;
    for variable in expected.free_variables().into_iter().rev() {
        steps.push(ProofStep::Generalization {
            premise: index,
            variable,
        });
        index = (steps.len() - 1) as u32;
    }
    let certificate = ProofCertificate::new(steps).map_err(|error| match error {
        naome_proof::ProofCertificateError::TooManySteps { .. }
        | naome_proof::ProofCertificateError::InputTooLong { .. }
        | naome_proof::ProofCertificateError::FormulaNodeLimitExceeded { .. } => {
            NATIVE_RESOURCE_LIMIT.into()
        }
        naome_proof::ProofCertificateError::Formula(
            naome_foundation::FormulaCodecError::NodeLimitExceeded { .. }
            | naome_foundation::FormulaCodecError::DepthLimitExceeded { .. },
        ) => NATIVE_RESOURCE_LIMIT.into(),
        error => error.to_string(),
    })?;
    let checked =
        naome_checker::normalize_and_check_with_state(certificate.clone(), &ArtifactState::new())
            .map_err(|error| match error.kind() {
            naome_checker::CheckErrorKind::DerivedFormula {
                source:
                    naome_foundation::FormulaCodecError::DepthLimitExceeded { .. }
                    | naome_foundation::FormulaCodecError::NodeLimitExceeded { .. },
                ..
            }
            | naome_checker::CheckErrorKind::FormulaWorkLimitExceeded { .. } => {
                NATIVE_RESOURCE_LIMIT.to_owned()
            }
            _ => error.to_string(),
        })?;
    let target = close(expected.clone());
    if checked.conclusion() != &target {
        return Err("checked certificate proves a different target".into());
    }
    let question = naome_authoring::CompiledQuestion::from_formula(target.clone())
        .map_err(|e| e.to_string())?;
    if question
        .classify_checked_proof(&checked)
        .map_err(|e| format!("{e:?}"))?
        != naome_authoring::QuestionOutcome::Proved
    {
        return Err("checked certificate does not positively resolve the question".into());
    }
    Ok(Verified {
        certificate,
        target,
        native_id: checked.proof_id(),
        payload_bytes: checked.normal_form().canonical_bytes().len(),
    })
}

pub fn source(proof: &Verified) -> Result<String, String> {
    let mut output = String::new();
    write!(output, "\ngoal = {}\n\nproof:\n", proof.target.to_source())
        .map_err(|e| e.to_string())?;
    let mut bindings = String::new();
    let mut names = HashMap::new();
    fn bind(
        f: &Formula,
        names: &mut HashMap<Formula, String>,
        bindings: &mut String,
    ) -> Result<String, String> {
        if let Some(name) = names.get(f) {
            return Ok(name.clone());
        }
        use naome_foundation::graph::Node;
        let expression = match f.view().graph_node() {
            Node::Not(body) => format!("not({})", bind(&body.to_owned(), names, bindings)?),
            Node::Implies(a, b) => format!(
                "imp({},{})",
                bind(&a.to_owned(), names, bindings)?,
                bind(&b.to_owned(), names, bindings)?
            ),
            Node::ForAll(_) => {
                let used = f.free_variables();
                let v = (0..=u32::MAX)
                    .map(FreeVariable::new)
                    .find(|v| !used.contains(v))
                    .ok_or("source binder space")?;
                let body = f.open_outer_universal(v).ok_or("source universal")?;
                format!("all(f{},{})", v.identifier(), bind(&body, names, bindings)?)
            }
            _ => f.to_source(),
        };
        let name = format!("a{}", names.len());
        writeln!(bindings, "    {name} = {expression}").map_err(|e| e.to_string())?;
        names.insert(f.clone(), name.clone());
        Ok(name)
    }
    let mut formula = |value: &naome_proof::ProofFormula| -> Result<String, String> {
        bind(
            value.as_primitive().ok_or("nonprimitive solver field")?,
            &mut names,
            &mut bindings,
        )
    };
    for (index, step) in proof.certificate.steps().iter().enumerate() {
        let rule = match step {
            ProofStep::Simplification {
                antecedent,
                consequent,
            } => format!("simp({}, {})", formula(antecedent)?, formula(consequent)?),
            ProofStep::Frege {
                first,
                second,
                third,
            } => format!(
                "frege({}, {}, {})",
                formula(first)?,
                formula(second)?,
                formula(third)?
            ),
            ProofStep::ModusPonens {
                premise,
                implication,
            } => format!("mp(p{premise}, p{implication})"),
            ProofStep::Generalization { premise, variable } => {
                format!("gen(p{premise}, f{})", variable.identifier())
            }
            ProofStep::ProofReference { proof_id } => {
                format!("cite(\"{}\")", crate::hex(proof_id.as_bytes()))
            }
            ProofStep::UniversalInstantiation {
                variable,
                replacement,
                body,
            } => format!(
                "inst(f{}, f{}, {})",
                variable.identifier(),
                replacement.identifier(),
                formula(body)?
            ),
            ProofStep::ClassicalContraposition {
                antecedent,
                consequent,
            } => format!("contra({}, {})", formula(antecedent)?, formula(consequent)?),
            ProofStep::EqualityReflexivity { variable } => {
                format!("refl(f{})", variable.identifier())
            }
            ProofStep::EqualitySubstitution { from, to, body } => format!(
                "subst(f{}, f{}, {})",
                from.identifier(),
                to.identifier(),
                formula(body)?
            ),
            ProofStep::UniversalDistribution {
                variable,
                antecedent,
                consequent,
            } => format!(
                "dist(f{}, {}, {})",
                variable.identifier(),
                formula(antecedent)?,
                formula(consequent)?
            ),
            ProofStep::VacuousUniversal { formula: body } => format!("vacuous({})", formula(body)?),
            ProofStep::ZfcAxiom(axiom) => {
                format!("axiom(\"{}\")", super::search::axiom_name(*axiom))
            }
            _ => return Err("unexpected solver proof step".into()),
        };
        writeln!(output, "    p{index} = {rule}").map_err(|e| e.to_string())?;
    }
    writeln!(
        output,
        "    return p{}",
        proof.certificate.steps().len() - 1
    )
    .map_err(|e| e.to_string())?;
    Ok(if bindings.is_empty() {
        output
    } else {
        format!("let:\n{bindings}\n{output}")
    })
}
