use super::*;
use crate::{ArtifactState, normalize_and_check_with_state};
use naome_proof::ProofCertificate;

fn atom(negative: bool) -> Formula {
    let x = FreeVariable::new(0);
    Formula::for_all(
        x,
        if negative {
            Formula::negate(Formula::member(x, x))
        } else {
            Formula::member(x, x)
        },
    )
}

#[test]
fn elementary_equivalence_rejects_without_stored_bridges_and_rechecks_both_directions() {
    let a = atom(false);
    let b = atom(true);
    let core = Formula::implies(a.clone(), Formula::negate(b.clone()));
    let exchange = Formula::implies(b.clone(), Formula::negate(a.clone()));
    let wrap = |formula| Formula::for_all(FreeVariable::new(17), formula);
    for (question, related) in [
        (a.clone(), wrap(a.clone())),
        (wrap(wrap(a.clone())), a.clone()),
        (core.clone(), exchange.clone()),
        (wrap(core.clone()), wrap(wrap(exchange.clone()))),
        (
            Formula::negate(core.clone()),
            Formula::negate(exchange.clone()),
        ),
    ] {
        let state = ArtifactState::new();
        let mut registry = QuestionRegistry::new();
        registry
            .insert(RegisteredQuestion::new([1; 32], &related).unwrap())
            .unwrap();
        let snapshot = KnowledgeSnapshot::new([8; 32], &state, &registry);
        let request =
            AssessmentQuestion::new(FOUNDATION_ID, &question, b"equivalence", &[], None).unwrap();
        let result = assess_question(&request, &snapshot, &PrefilterPolicy::default());
        assert_eq!(
            result.reason,
            Some(RejectionReason::ProvenEquivalent),
            "{}: {result:?}",
            question.to_source()
        );
        assert_eq!(result.rule, "Q05_ELEMENTARY_EQUIVALENCE");
        assert_eq!(result.related_record, Some([1; 32]));
        assert!(!result.has_answer());
        assert!(result.novelty().is_none());
        let certificates = result.equivalence.unwrap();
        for (witness, (from, to)) in certificates
            .iter()
            .zip([(&question, &related), (&related, &question)])
        {
            let checked = normalize_and_check_with_state(
                ProofCertificate::from_canonical_bytes(witness.canonical_certificate()).unwrap(),
                &state,
            )
            .unwrap();
            assert_eq!(
                checked.conclusion(),
                &Formula::implies(from.clone(), to.clone())
            );
            assert!(witness.original_proofs().is_empty());
        }
        assert!(state.proof_conclusions().next().is_none());
        assert_eq!(registry.len(), 1);
    }
}

#[test]
fn nonvacuous_quantifiers_wrong_polarity_and_different_atoms_remain_distinct() {
    let a = atom(false);
    let b = atom(true);
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let captured = Formula::for_all(x, Formula::for_all(y, Formula::member(x, y)));
    let different = Formula::for_all(x, Formula::for_all(y, Formula::member(y, x)));
    for (question, related) in [
        (a.clone(), b.clone()),
        (a.clone(), Formula::negate(a.clone())),
        (
            Formula::implies(a.clone(), b.clone()),
            Formula::implies(b.clone(), a.clone()),
        ),
        (captured, different),
    ] {
        let state = ArtifactState::new();
        let mut registry = QuestionRegistry::new();
        registry
            .insert(RegisteredQuestion::new([1; 32], &related).unwrap())
            .unwrap();
        let request =
            AssessmentQuestion::new(FOUNDATION_ID, &question, b"distinct", &[], None).unwrap();
        let decision = assess_question(
            &request,
            &KnowledgeSnapshot::new([8; 32], &state, &registry),
            &PrefilterPolicy::default(),
        );
        assert!(decision.passed(), "{}: {decision:?}", question.to_source());
    }
}

#[test]
fn insufficient_equivalence_certificate_budget_is_inconclusive_and_has_no_partial_evidence() {
    let a = atom(false);
    let b = atom(true);
    let question = Formula::implies(a.clone(), Formula::negate(b.clone()));
    let related = Formula::implies(b, Formula::negate(a));
    let state = ArtifactState::new();
    let mut registry = QuestionRegistry::new();
    registry
        .insert(RegisteredQuestion::new([1; 32], &related).unwrap())
        .unwrap();
    let request = AssessmentQuestion::new(FOUNDATION_ID, &question, b"limited", &[], None).unwrap();
    let mut policy = PrefilterPolicy::default();
    policy.limits.certificate_steps = 52;
    let decision = assess_question(
        &request,
        &KnowledgeSnapshot::new([8; 32], &state, &registry),
        &policy,
    );
    assert!(decision.inconclusive());
    assert_eq!(decision.reason, Some(RejectionReason::ExecutionLimit));
    assert!(decision.equivalence.is_none());
    assert!(decision.novelty().is_none());
}

#[test]
fn stronger_first_discovery_rules_do_not_revoke_preexisting_owned_unanswered_work() {
    let original = atom(false);
    let related = Formula::for_all(FreeVariable::new(17), original.clone());
    let state = ArtifactState::new();
    let mut registry = QuestionRegistry::new();
    registry
        .insert(RegisteredQuestion::new([1; 32], &original).unwrap())
        .unwrap();
    registry
        .insert(RegisteredQuestion::new([2; 32], &related).unwrap())
        .unwrap();
    for (record, formula) in [([1; 32], &original), ([2; 32], &related)] {
        let request = AssessmentQuestion::new(
            FOUNDATION_ID,
            formula,
            b"preexisting work",
            &[],
            Some(record),
        )
        .unwrap();
        let decision = assess_question(
            &request,
            &KnowledgeSnapshot::new([8; 32], &state, &registry),
            &PrefilterPolicy::default(),
        );
        assert!(decision.passed());
        assert!(decision.novelty().is_none());
    }
}

#[test]
fn an_expensive_equivalence_candidate_cannot_hide_a_short_checked_answer() {
    let (mut state, n) = fixtures::budget_case(0, false);
    let x = FreeVariable::new(0);
    let e = Formula::for_all(x, Formula::equal(x, x));
    let a = Formula::for_all(FreeVariable::new(17), e.clone());
    let question = Formula::implies(a.clone(), n.clone());
    let premise = n.view().negated().unwrap().to_owned();
    let related = Formula::implies(premise, Formula::negate(a.clone()));
    let proof_id = |formula: &Formula| {
        crate::ContextView::statement_header(
            &state,
            statement_id(&formula.encode_canonical().unwrap()),
        )
        .unwrap()
        .unwrap()
        .proof_id()
    };
    let certificate = ProofCertificate::new(vec![
        ProofStep::ProofReference {
            proof_id: proof_id(&e),
        },
        ProofStep::ProofReference {
            proof_id: proof_id(&Formula::implies(e.clone(), n.clone())),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
        ProofStep::Simplification {
            antecedent: n.into(),
            consequent: a.into(),
        },
        ProofStep::ModusPonens {
            premise: 2,
            implication: 3,
        },
        ProofStep::Simplification {
            antecedent: question.clone().into(),
            consequent: e.into(),
        },
        ProofStep::ModusPonens {
            premise: 4,
            implication: 5,
        },
    ])
    .unwrap();
    let checked = normalize_and_check_with_state(certificate, &state).unwrap();
    state.register_proof(checked).unwrap();
    let mut policy = PrefilterPolicy::default();
    policy.limits.certificate_steps = 52;
    let request = AssessmentQuestion::new(
        FOUNDATION_ID,
        &question,
        b"answer before incomplete equivalence",
        &[],
        None,
    )
    .unwrap();
    let mut registry = QuestionRegistry::new();
    let without_candidate = assess_question(
        &request,
        &KnowledgeSnapshot::new([8; 32], &state, &registry),
        &policy,
    );
    assert_eq!(without_candidate.reason, Some(RejectionReason::KnownProof));
    registry
        .insert(RegisteredQuestion::new([1; 32], &related).unwrap())
        .unwrap();
    let result = assess_question(
        &request,
        &KnowledgeSnapshot::new([8; 32], &state, &registry),
        &policy,
    );
    assert_eq!(result.reason, Some(RejectionReason::KnownProof));
    assert_eq!(result.rule, "Q04_CHECKED_MP_CLOSURE");
    assert!(result.equivalence.is_none());
    assert!(result.novelty().is_none());
}
