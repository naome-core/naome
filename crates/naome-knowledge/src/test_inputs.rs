use naome_checker::question::ResearchQuestion;
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ArtifactPayload, DefinitionCertificate, ProofCertificate, ProofId, ProofStep};

pub(crate) fn variable(index: usize) -> FreeVariable {
    FreeVariable::new(index.try_into().unwrap())
}

pub(crate) fn proof(steps: Vec<ProofStep>) -> String {
    let mut bytes = vec![ArtifactPayload::PROOF_TAG];
    bytes.extend(ProofCertificate::new(steps).unwrap().to_canonical_bytes());
    crate::hex(&bytes)
}

pub(crate) fn definition(certificate: &DefinitionCertificate) -> String {
    let mut bytes = vec![ArtifactPayload::DEFINITION_TAG];
    bytes.extend(certificate.canonical_bytes());
    crate::hex(&bytes)
}

pub(crate) fn question(formula: Formula) -> ResearchQuestion {
    ResearchQuestion::from_formula(formula).unwrap()
}

pub(crate) fn member_self() -> Formula {
    let x = variable(0);
    Formula::for_all(x, Formula::member(x, x))
}

pub(crate) fn cite(proof_id: ProofId) -> String {
    proof(vec![ProofStep::ProofReference { proof_id }])
}

pub(crate) fn weaken(
    mut steps: Vec<ProofStep>,
    premise: Formula,
    extra: Formula,
) -> Vec<ProofStep> {
    let prior = u32::try_from(steps.len()).unwrap() - 1;
    steps.push(ProofStep::Simplification {
        antecedent: premise.into(),
        consequent: extra.into(),
    });
    steps.push(ProofStep::ModusPonens {
        premise: prior,
        implication: prior + 1,
    });
    steps
}

pub(crate) fn weaken_citation(proof_id: ProofId, premise: Formula, extra: Formula) -> String {
    proof(weaken(
        vec![ProofStep::ProofReference { proof_id }],
        premise,
        extra,
    ))
}

pub(crate) fn reflexivity(binders: impl IntoIterator<Item = usize>) -> Vec<ProofStep> {
    let mut steps = vec![ProofStep::EqualityReflexivity {
        variable: variable(0),
    }];
    steps.extend(binders.into_iter().enumerate().map(|(premise, index)| {
        ProofStep::Generalization {
            premise: u32::try_from(premise).unwrap(),
            variable: variable(index),
        }
    }));
    steps
}

pub(crate) fn identity_function() -> String {
    let body = naome_proof::DefinedFormula::equal(variable(1), variable(0));
    definition(&DefinitionCertificate::function(1, body).unwrap())
}

pub(crate) fn relation_examples() -> [Formula; 8] {
    let (a, b) = (variable(0), variable(1));
    let ab = Formula::member(a, b);
    let ba = Formula::member(b, a);
    let equal = Formula::equal(a, b);
    [
        ab.clone(),
        Formula::negate(ab.clone()),
        Formula::implies(ab.clone(), equal.clone()),
        Formula::conjunction(ab.clone(), ba.clone()),
        Formula::disjunction(ab.clone(), ba.clone()),
        Formula::implies(ab.clone(), ba.clone()),
        Formula::implies(equal, ab.clone()),
        Formula::biconditional(ab, ba),
    ]
}
