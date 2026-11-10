//! Compile typed implication search into the existing primitive Hilbert calculus.

use naome_checker::ArtifactState;
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ProofCertificate, ProofId, ProofNormalForm, ProofStep};
use std::collections::HashMap;
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
    record_checking_work(certificate.steps().len());
    naome_checker::normalize_and_check_with_state(certificate, context)
}

pub(super) fn check_normal_form(
    normal_form: ProofNormalForm,
    context: &dyn naome_checker::ContextView,
) -> Result<naome_checker::CheckedProof, naome_checker::CheckError> {
    record_checking_work(normal_form.certificate().steps().len());
    naome_checker::check_normal_form_with_state(normal_form, context)
}

fn record_checking_work(steps: usize) {
    CHECKING.with(|counter| {
        let old = counter.get();
        counter.set(CheckingWork {
            calls: old.calls.saturating_add(1),
            steps: old.steps.saturating_add(steps as u64),
        });
    });
}

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
    /// A proof already checked in the exact program input context.
    CheckedInput(ProofId, Formula),
    Sealed(Arc<Term>, Formula),
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
            Self::Variable(_, formula)
            | Self::Apply(_, _, formula)
            | Self::Sealed(_, formula)
            | Self::CheckedInput(_, formula) => formula.clone(),
            Self::Kernel(k) => k.formula(),
            Self::Native { target, .. } | Self::Lemma { target, .. } => target.clone(),
            Self::Generalize(variable, body) => Formula::for_all(*variable, body.formula()),
            Self::Lambda(_, argument, body) => Formula::implies(argument.clone(), body.formula()),
        }
    }

    pub fn apply(function: Self, argument: Self) -> Result<Self, crate::Error> {
        let formula = function.formula();
        let Some((expected, result)) = formula.view().implication_parts() else {
            return Err(crate::ResearchFailure::ProofApplicationShape.into());
        };
        if expected != argument.formula() {
            return Err(crate::ResearchFailure::ProofApplicationAntecedent.into());
        }
        Ok(Self::Apply(
            Box::new(function),
            Box::new(argument),
            result.to_owned(),
        ))
    }
}

fn apply(
    function: Arc<Combinator>,
    argument: Arc<Combinator>,
) -> Result<Arc<Combinator>, crate::Error> {
    let formula = function.formula();
    let Some((expected, result)) = formula.view().implication_parts() else {
        return Err(crate::ResearchFailure::ProofCombinatorShape.into());
    };
    if expected != argument.formula() {
        return Err(crate::ResearchFailure::ProofCombinatorAntecedent.into());
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
) -> Result<Arc<Combinator>, crate::Error> {
    if !body.contains(id) {
        return apply(
            Combinator::new(Kind::K(body.formula(), argument.clone())),
            body,
        );
    }
    match body.kind() {
        Kind::Generalize(variable, inner) => {
            if argument.free_variables().contains(variable) {
                return Err(crate::ResearchFailure::ProofGeneralizationCapture.into());
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
        _ => Err(crate::ResearchFailure::ProofUnboundVariable.into()),
    }
}

fn lower(term: &Term) -> Result<Arc<Combinator>, crate::Error> {
    match term {
        Term::Lemma {
            certificate,
            dependencies,
            target,
        } => {
            let context = lemma_context(&[], dependencies)?;
            let checked = crate::learning::proof::check(certificate.clone(), &context)
                .map_err(crate::Error::from)?;
            if checked.conclusion() != target {
                return Err(crate::ResearchFailure::ProofLemmaTarget.into());
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
        Term::CheckedInput(id, target) => {
            Ok(Combinator::new(Kind::CheckedInput(*id, target.clone())))
        }
        Term::Sealed(body, target) => {
            let body = lower(body)?;
            if body.formula() != *target {
                return Err(crate::ResearchFailure::ProofSealedTarget.into());
            }
            Ok(body)
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
) -> Result<Verified, crate::Error> {
    let context = lemma_context(&definitions, &lemmas)?;
    let checked = check(certificate, &context).map_err(crate::Error::from)?;
    if expected.is_some_and(|target| checked.conclusion() != target) {
        return Err(crate::ResearchFailure::NativeDagTargetMismatch.into());
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
pub fn verify(term: &Term, expected: &Formula) -> Result<Verified, crate::Error> {
    if term.formula() != *expected {
        return Err(crate::ResearchFailure::NativeTermTargetMismatch.into());
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
    let Recipe {
        steps,
        lemmas,
        definitions,
    } = lower_recipe(term, expected, true)?;
    let certificate = ProofCertificate::new(steps).map_err(|error| {
        crate::Error::CertificateConstruction(crate::FormatFailure::from(&error))
    })?;
    let checked =
        crate::learning::proof::check(certificate.clone(), &lemma_context(&definitions, &lemmas)?)
            .map_err(crate::Error::from)?;
    let target = close(expected.clone());
    if checked.conclusion() != &target {
        return Err(crate::ResearchFailure::NativeCheckedTargetMismatch.into());
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

pub(super) struct Recipe {
    pub steps: Vec<ProofStep>,
    pub lemmas: Vec<ProofCertificate>,
    pub definitions: Vec<super::definitions::Entry>,
}

/// Lower the actual search term into bounded inference operands. A program
/// consumer accounts for canonical commands after sharing identical formulas.
pub(super) fn recipe(term: &Term, expected: &Formula) -> Result<Recipe, crate::Error> {
    lower_recipe(term, expected, false)
}

#[expect(
    clippy::mutable_key_type,
    reason = "OnceLock memoizes immutable structure; hash and equality never change."
)]
fn lower_recipe(
    term: &Term,
    expected: &Formula,
    certificate: bool,
) -> Result<Recipe, crate::Error> {
    if term.formula() != *expected {
        return Err(crate::ResearchFailure::NativeTermTargetMismatch.into());
    }
    if let Term::Native {
        certificate,
        definitions,
        lemmas,
        ..
    } = term
    {
        return Ok(Recipe {
            steps: certificate.steps().to_vec(),
            lemmas: lemmas.clone(),
            definitions: definitions.clone(),
        });
    }
    let root = lower(term)?;
    let mut steps = Vec::new();
    let mut cache = HashMap::new();
    let mut formula_nodes = certificate.then_some(0usize);
    let mut lemmas = Vec::new();
    let mut definitions = Vec::new();
    fn emit(
        term: &Arc<Combinator>,
        steps: &mut Vec<ProofStep>,
        cache: &mut HashMap<Arc<Combinator>, u32>,
        formula_nodes: &mut Option<usize>,
        lemmas: &mut Vec<ProofCertificate>,
        definitions: &mut Vec<super::definitions::Entry>,
    ) -> Result<u32, crate::Error> {
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
                                .map_err(|e| crate::object::certificate_error(bytes, e))?,
                        );
                    }
                }
                ProofStep::ProofReference { proof_id: *id }
            }
            Kind::CheckedInput(id, _) => ProofStep::ProofReference { proof_id: *id },
            Kind::Variable(_, _) => {
                return Err(crate::ResearchFailure::ProofUndischargedAssumption.into());
            }
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
        if let Some(formula_nodes) = formula_nodes {
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
                return Err(crate::Error::CertificateConstruction(
                    crate::FormatFailure::Limit {
                        resource: crate::outcome::FormatResource::Nodes,
                        actual: Some(*formula_nodes as u64),
                        maximum: naome_proof::CERTIFICATE_MAX_FORMULA_NODES as u64,
                    },
                ));
            }
        }
        let index =
            u32::try_from(steps.len()).map_err(|_| crate::ResearchFailure::ProofIndexWidth)?;
        steps.push(step);
        if steps.len() > crate::resources::limits().closure_steps.min(16_384) {
            return Err(crate::Error::CertificateConstruction(
                crate::FormatFailure::Limit {
                    resource: crate::outcome::FormatResource::Steps,
                    actual: Some(steps.len() as u64),
                    maximum: crate::resources::limits().closure_steps.min(16_384) as u64,
                },
            ));
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
    Ok(Recipe {
        steps,
        lemmas,
        definitions,
    })
}

pub fn source(proof: &Verified) -> String {
    artifact(&proof.certificate)
}

pub(super) fn artifact(certificate: &ProofCertificate) -> String {
    crate::hex(&naome_proof::ArtifactPayload::Proof(certificate.clone()).to_canonical_bytes())
}

pub(crate) fn check_artifact(
    encoded: &str,
    context: &dyn naome_checker::ContextView,
) -> Result<naome_checker::CheckedProof, crate::Error> {
    let bytes = crate::unhex(encoded)?;
    let payload = crate::object::decode_payload(&bytes)?;
    let naome_proof::ArtifactPayload::Proof(certificate) = payload else {
        return Err(crate::ResearchFailure::ExpectedProofArtifact.into());
    };
    check_normal_form(certificate.into_unchecked_normal_form(), context).map_err(crate::Error::from)
}

pub(super) fn define_steps(
    steps: &[ProofStep],
    definitions: &[super::definitions::Entry],
) -> Result<Vec<ProofStep>, crate::Error> {
    let rewrite = |value: &naome_proof::ProofFormula| {
        if value.as_defined().is_some() {
            return Ok(value.clone());
        }
        let primitive = value
            .expand_with(&ArtifactState::new())
            .map_err(crate::Error::from)?;
        super::definitions::represent(primitive.as_ref(), definitions)
    };
    steps
        .iter()
        .map(|step| {
            Ok(match step {
                ProofStep::Simplification {
                    antecedent,
                    consequent,
                } => ProofStep::Simplification {
                    antecedent: rewrite(antecedent)?,
                    consequent: rewrite(consequent)?,
                },
                ProofStep::Frege {
                    first,
                    second,
                    third,
                } => ProofStep::Frege {
                    first: rewrite(first)?,
                    second: rewrite(second)?,
                    third: rewrite(third)?,
                },
                ProofStep::ClassicalContraposition {
                    antecedent,
                    consequent,
                } => ProofStep::ClassicalContraposition {
                    antecedent: rewrite(antecedent)?,
                    consequent: rewrite(consequent)?,
                },
                ProofStep::UniversalDistribution {
                    variable,
                    antecedent,
                    consequent,
                } => ProofStep::UniversalDistribution {
                    variable: *variable,
                    antecedent: rewrite(antecedent)?,
                    consequent: rewrite(consequent)?,
                },
                ProofStep::VacuousUniversal { formula } => ProofStep::VacuousUniversal {
                    formula: rewrite(formula)?,
                },
                ProofStep::UniversalInstantiation {
                    variable,
                    replacement,
                    body,
                } => ProofStep::UniversalInstantiation {
                    variable: *variable,
                    replacement: *replacement,
                    body: rewrite(body)?,
                },
                ProofStep::EqualitySubstitution { from, to, body } => {
                    ProofStep::EqualitySubstitution {
                        from: *from,
                        to: *to,
                        body: rewrite(body)?,
                    }
                }
                ProofStep::Separation(instance) => {
                    ProofStep::Separation(naome_proof::ProofSeparation {
                        predicate: rewrite(&instance.predicate)?,
                        ..instance.clone()
                    })
                }
                ProofStep::Replacement(instance) => {
                    ProofStep::Replacement(naome_proof::ProofReplacement {
                        predicate: rewrite(&instance.predicate)?,
                        ..instance.clone()
                    })
                }
                _ => step.clone(),
            })
        })
        .collect::<Result<Vec<_>, crate::Error>>()
}

pub fn source_with_definitions(
    proof: &Verified,
    definitions: &[super::definitions::Entry],
) -> Result<String, crate::Error> {
    if proof
        .definitions
        .iter()
        .any(|entry| !definitions.contains(entry))
    {
        return Err(crate::ResearchFailure::ProofReferenceReplacement.into());
    }
    let steps = define_steps(proof.certificate.steps(), definitions)?;
    let certificate = ProofCertificate::new(steps).map_err(|error| {
        crate::Error::CertificateConstruction(crate::FormatFailure::from(&error))
    })?;
    let context = lemma_context(definitions, &proof.lemmas)?;
    let checked = check(certificate, &context).map_err(crate::Error::from)?;
    if checked.conclusion() != &proof.target {
        return Err(crate::ResearchFailure::ProofRepresentationMismatch.into());
    }
    Ok(artifact(checked.normal_form().certificate()))
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn non_implication_application_has_registered_failure() {
        let formula = Formula::equal(FreeVariable::new(0), FreeVariable::new(0));
        let error = Term::apply(
            Term::Variable(0, formula.clone()),
            Term::Variable(1, formula),
        )
        .err()
        .unwrap();
        assert_eq!(
            serde_json::to_value(error).unwrap()["code"],
            u32::from(crate::ResearchFailure::ProofApplicationShape)
        );
    }

    #[test]
    fn native_proof_rejection_keeps_checker_diagnostic() {
        let certificate = ProofCertificate::new(vec![ProofStep::ProofReference {
            proof_id: naome_proof::ProofId::from_bytes([7; 32]),
        }])
        .unwrap();
        let error = verify_native(certificate, vec![], vec![], None)
            .err()
            .unwrap();
        assert!(error.diagnostic().is_some());
        assert!(
            serde_json::to_value(error)
                .unwrap()
                .get("diagnostic")
                .is_some()
        );
    }

    #[test]
    fn proof_target_mismatch_and_construction_reason_are_structured() {
        let variable = FreeVariable::new(0);
        let target = Formula::equal(variable, variable);
        let different = Formula::member(variable, variable);
        let error = verify(&Term::Variable(0, different), &target)
            .err()
            .unwrap();
        assert_eq!(
            serde_json::to_value(error).unwrap()["code"],
            u32::from(crate::ResearchFailure::NativeTermTargetMismatch)
        );
        let raw = ProofCertificate::new(Vec::new()).unwrap_err();
        let error = crate::Error::CertificateConstruction(crate::FormatFailure::from(&raw));
        let value = serde_json::to_value(error).unwrap();
        assert_eq!(value["code"], 0x0006_001b_u32);
        assert!(value["format_reason"]["code"].as_u64().is_some());
    }
}
