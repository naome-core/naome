//! Compile typed implication search into the existing primitive Hilbert calculus.

use naome_checker::ArtifactState;
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;

mod combinator;
use combinator::{Combinator, Kind};
mod kernel;
mod lemmas;
pub use kernel::Kernel;
pub(crate) use lemmas::{context as lemma_context, sources as lemma_sources};

/// Operational counters measure submitted native checker work, including
/// repeated closure checks. They never grant validity or change reservations.
#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CheckingWork {
    pub calls: u64,
    pub steps: u64,
}
std::thread_local! {
    static CHECKING: std::cell::Cell<CheckingWork> = const { std::cell::Cell::new(CheckingWork { calls: 0, steps: 0 }) };
}
pub fn checking_work() -> CheckingWork {
    CHECKING.with(std::cell::Cell::get)
}
pub fn check(
    certificate: ProofCertificate,
    context: &dyn naome_checker::ContextView,
) -> Result<naome_checker::CheckedProof, naome_checker::CheckError> {
    CHECKING.with(|counter| {
        let old = counter.get();
        counter.set(CheckingWork {
            calls: old.calls.saturating_add(1),
            steps: old.steps.saturating_add(certificate.steps().len() as u64),
        });
    });
    naome_checker::normalize_and_check_with_state(certificate, context)
}

pub const NATIVE_RESOURCE_LIMIT: &str =
    "native certificate or reconstructed formula resource limit";
pub const FORMULA_WORK_LIMIT: &str = "solver certificate formula-node limit";
pub const STEP_WORK_LIMIT: &str = "solver certificate work limit";

#[derive(Clone, Debug)]
pub enum Term {
    Lemma {
        certificate: ProofCertificate,
        dependencies: Vec<ProofCertificate>,
        target: Formula,
    },
    Native {
        lemmas: Vec<ProofCertificate>,
        certificate: ProofCertificate,
        target: Formula,
        definitions: Vec<super::definitions::Entry>,
    },
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
            Self::Native { target, .. } | Self::Lemma { target, .. } => target.clone(),
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

fn apply(function: Arc<Combinator>, argument: Arc<Combinator>) -> Result<Arc<Combinator>, String> {
    let formula = function.formula();
    let Some((expected, result)) = formula.view().implication_parts() else {
        return Err("combinator application requires an implication".into());
    };
    if expected != argument.formula() {
        return Err("combinator application antecedent differs".into());
    }
    Ok(Combinator::new(Kind::Apply(
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
            Combinator::new(Kind::K(body.formula(), argument.clone())),
            body,
        );
    }
    match body.kind() {
        Kind::Generalize(variable, inner) => {
            if argument.free_variables().contains(variable) {
                return Err("generalization eigenvariable occurs in an assumption".into());
            }
            let inner_formula = inner.formula();
            let abstracted = abstract_variable(id, argument, inner.clone())?;
            let quantified = Combinator::new(Kind::Generalize(*variable, abstracted));
            let distribution = Combinator::new(Kind::Kernel(Kernel::new(
                ProofStep::UniversalDistribution {
                    variable: *variable,
                    antecedent: argument.clone().into(),
                    consequent: inner_formula.into(),
                },
            )?));
            let lifted = apply(distribution, quantified)?;
            let vacuous =
                Combinator::new(Kind::Kernel(Kernel::new(ProofStep::VacuousUniversal {
                    formula: argument.clone().into(),
                })?));
            let value = apply(
                vacuous,
                Combinator::new(Kind::Variable(id, argument.clone())),
            )?;
            abstract_variable(id, argument, apply(lifted, value)?)
        }
        Kind::Variable(other, _) if *other == id => {
            let aa = Formula::implies(argument.clone(), argument.clone());
            let s = Combinator::new(Kind::S(argument.clone(), aa.clone(), argument.clone()));
            let first = Combinator::new(Kind::K(argument.clone(), aa));
            let second = Combinator::new(Kind::K(argument.clone(), argument.clone()));
            apply(apply(s, first)?, second)
        }
        Kind::Apply(function, value, result) => {
            if matches!(value.kind(), Kind::Variable(other, _) if *other == id)
                && !function.contains(id)
            {
                return Ok(function.clone());
            }
            let s = Combinator::new(Kind::S(argument.clone(), value.formula(), result.clone()));
            let function = abstract_variable(id, argument, function.clone())?;
            let value = abstract_variable(id, argument, value.clone())?;
            apply(apply(s, function)?, value)
        }
        _ => Err("unbound variable during bracket abstraction".into()),
    }
}

fn lower(term: &Term) -> Result<Arc<Combinator>, String> {
    match term {
        Term::Lemma {
            certificate,
            dependencies,
            target,
        } => {
            let context = lemma_context(&[], dependencies)?;
            let checked = crate::learning::proof::check(certificate.clone(), &context)
                .map_err(|e| e.to_string())?;
            if checked.conclusion() != target {
                return Err("construction lemma target differs".into());
            }
            Ok(Combinator::new(Kind::Lemma(
                dependencies
                    .iter()
                    .map(ProofCertificate::to_canonical_bytes)
                    .collect(),
                checked.normal_form().canonical_bytes().to_vec(),
                target.clone(),
                checked.proof_id(),
                Vec::new(),
            )))
        }
        Term::Native { target, .. } => {
            let verified = verify(term, target)?;
            Ok(Combinator::new(Kind::Lemma(
                verified
                    .lemmas
                    .iter()
                    .map(ProofCertificate::to_canonical_bytes)
                    .collect(),
                verified.certificate.to_canonical_bytes(),
                target.clone(),
                verified.native_id,
                verified.definitions,
            )))
        }
        Term::Variable(id, formula) => Ok(Combinator::new(Kind::Variable(*id, formula.clone()))),
        Term::Kernel(k) => Ok(Combinator::new(Kind::Kernel(k.clone()))),
        Term::Generalize(v, body) => Ok(Combinator::new(Kind::Generalize(*v, lower(body)?))),
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
    pub lemmas: Vec<ProofCertificate>,
    pub definitions: Vec<super::definitions::Entry>,
    pub certificate: ProofCertificate,
    pub target: Formula,
    pub native_id: ProofId,
    pub payload_bytes: usize,
}

/// The one native-DAG boundary also serves self-contained evidence packets.
/// Supplying an expected target binds it; otherwise the checker derives it.
pub(crate) fn verify_native(
    certificate: ProofCertificate,
    definitions: Vec<super::definitions::Entry>,
    lemmas: Vec<ProofCertificate>,
    expected: Option<&Formula>,
) -> Result<Verified, String> {
    let context = lemma_context(&definitions, &lemmas)?;
    let checked = check(certificate, &context).map_err(|e| e.to_string())?;
    if expected.is_some_and(|target| checked.conclusion() != target) {
        return Err("native DAG conclusion differs".into());
    }
    let retained = lemmas::retain(&checked, &definitions, &lemmas)?;
    Ok(Verified {
        lemmas: retained,
        definitions,
        certificate: checked.normal_form().certificate().clone(),
        target: checked.conclusion().clone(),
        native_id: checked.proof_id(),
        payload_bytes: checked.normal_form().canonical_bytes().len(),
    })
}

/// No typed term is accepted as evidence until the existing checker accepts it.
pub fn verify(term: &Term, expected: &Formula) -> Result<Verified, String> {
    if term.formula() != *expected {
        return Err("search term differs from the requested target".into());
    }
    if let Term::Native {
        certificate,
        definitions,
        lemmas,
        ..
    } = term
    {
        return verify_native(
            certificate.clone(),
            definitions.clone(),
            lemmas.clone(),
            Some(expected),
        );
    }
    let root = lower(term)?;
    let mut steps = Vec::new();
    let mut cache = HashMap::new();
    let mut formula_nodes = 0usize;
    let mut lemmas = Vec::new();
    let mut definitions = Vec::new();
    fn emit(
        term: &Arc<Combinator>,
        steps: &mut Vec<ProofStep>,
        cache: &mut HashMap<Arc<Combinator>, u32>,
        formula_nodes: &mut usize,
        lemmas: &mut Vec<ProofCertificate>,
        definitions: &mut Vec<super::definitions::Entry>,
    ) -> Result<u32, String> {
        if let Some(index) = cache.get(term) {
            return Ok(*index);
        }
        let step = match term.kind() {
            Kind::Lemma(dependencies, bytes, _, id, selected) => {
                for entry in selected {
                    if !definitions.contains(entry) {
                        definitions.push(entry.clone());
                    }
                }
                for bytes in dependencies.iter().chain(std::iter::once(bytes)) {
                    if !lemmas.iter().any(|c| c.to_canonical_bytes() == *bytes) {
                        lemmas.push(
                            ProofCertificate::from_canonical_bytes(bytes)
                                .map_err(|e| e.to_string())?,
                        );
                    }
                }
                ProofStep::ProofReference { proof_id: *id }
            }
            Kind::Variable(_, _) => return Err("certificate still has an assumption".into()),
            Kind::Kernel(k) => k.step(),
            Kind::Generalize(variable, body) => ProofStep::Generalization {
                premise: emit(body, steps, cache, formula_nodes, lemmas, definitions)?,
                variable: *variable,
            },
            Kind::K(a, b) => ProofStep::Simplification {
                antecedent: a.clone().into(),
                consequent: b.clone().into(),
            },
            Kind::S(a, b, c) => ProofStep::Frege {
                first: a.clone().into(),
                second: b.clone().into(),
                third: c.clone().into(),
            },
            Kind::Apply(function, argument, _) => {
                let implication = emit(function, steps, cache, formula_nodes, lemmas, definitions)?;
                let premise = emit(argument, steps, cache, formula_nodes, lemmas, definitions)?;
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
    let mut index = emit(
        &root,
        &mut steps,
        &mut cache,
        &mut formula_nodes,
        &mut lemmas,
        &mut definitions,
    )?;
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
        crate::learning::proof::check(certificate.clone(), &lemma_context(&definitions, &lemmas)?)
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
    // Internal closed lemmas are Foundation theorems, not new user questions.
    // Exact conclusion equality above and the independent checker establish
    // their claim; question-intake depth limits belong to the final question.
    let lemmas = lemmas::retain(&checked, &definitions, &lemmas)?;
    Ok(Verified {
        lemmas,
        definitions,
        certificate: checked.normal_form().certificate().clone(),
        target,
        native_id: checked.proof_id(),
        payload_bytes: checked.normal_form().canonical_bytes().len(),
    })
}

pub fn source(proof: &Verified) -> Result<String, String> {
    render(proof, &proof.definitions, false)
}
pub fn source_with_definitions(
    proof: &Verified,
    definitions: &[super::definitions::Entry],
) -> Result<String, String> {
    render(proof, definitions, true)
}
fn render(
    proof: &Verified,
    definitions: &[super::definitions::Entry],
    rewrite: bool,
) -> Result<String, String> {
    if proof
        .definitions
        .iter()
        .any(|existing| !definitions.contains(existing))
    {
        return Err("exact native references cannot be replaced during source export".into());
    }
    let context = lemma_context(definitions, &proof.lemmas)?;
    let mut output = String::new();
    write!(output, "\ngoal = {}\n\nproof:\n", proof.target.to_source())
        .map_err(|e| e.to_string())?;
    let mut bindings = String::new();
    let mut names = HashMap::new();
    fn bind(
        f: &Formula,
        names: &mut HashMap<Formula, String>,
        bindings: &mut String,
        definitions: &[super::definitions::Entry],
    ) -> Result<String, String> {
        if let Some(reference) = super::definitions::application(f, definitions)? {
            return Ok(reference);
        }
        if let Some(name) = names.get(f) {
            return Ok(name.clone());
        }
        use naome_foundation::graph::Node;
        let expression = match f.view().graph_node() {
            Node::Not(body) => format!(
                "not({})",
                bind(&body.to_owned(), names, bindings, definitions)?
            ),
            Node::Implies(a, b) => format!(
                "imp({},{})",
                bind(&a.to_owned(), names, bindings, definitions)?,
                bind(&b.to_owned(), names, bindings, definitions)?
            ),
            Node::ForAll(_) => {
                let used = f.free_variables();
                let v = (0..=u32::MAX)
                    .map(FreeVariable::new)
                    .find(|v| !used.contains(v))
                    .ok_or("source binder space")?;
                let body = f.open_outer_universal(v).ok_or("source universal")?;
                format!(
                    "all(f{},{})",
                    v.identifier(),
                    bind(&body, names, bindings, definitions)?
                )
            }
            _ => f.to_source(),
        };
        let name = format!("a{}", names.len());
        writeln!(bindings, "    {name} = {expression}").map_err(|e| e.to_string())?;
        names.insert(f.clone(), name.clone());
        Ok(name)
    }
    let mut formula = |value: &naome_proof::ProofFormula| -> Result<String, String> {
        if let Some(defined) = value.as_defined() {
            return super::definitions::exact_expression(defined, definitions);
        }
        bind(
            value
                .expand_with(&context)
                .map_err(|e| e.to_string())?
                .as_ref(),
            &mut names,
            &mut bindings,
            if rewrite { definitions } else { &[] },
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
            ProofStep::Separation(instance) => format!(
                "sep({}, f{}, f{}, f{}, parameters=[{}])",
                formula(&instance.predicate)?,
                instance.element.identifier(),
                instance.source.identifier(),
                instance.result.identifier(),
                instance
                    .parameters
                    .iter()
                    .map(|v| format!("f{}", v.identifier()))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            ProofStep::Replacement(instance) => format!(
                "replace({}, f{}, f{}, f{}, f{}, f{}, parameters=[{}])",
                formula(&instance.predicate)?,
                instance.input.identifier(),
                instance.output.identifier(),
                instance.uniqueness_witness.identifier(),
                instance.source.identifier(),
                instance.result.identifier(),
                instance
                    .parameters
                    .iter()
                    .map(|v| format!("f{}", v.identifier()))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        };
        writeln!(output, "    p{index} = {rule}").map_err(|e| e.to_string())?;
    }
    writeln!(
        output,
        "    return p{}",
        proof.certificate.steps().len() - 1
    )
    .map_err(|e| e.to_string())?;
    let output = if bindings.is_empty() {
        output
    } else {
        format!("let:\n{bindings}\n{output}")
    };
    Ok(format!(
        "{}{output}",
        super::definitions::aliases(definitions)?
    ))
}
