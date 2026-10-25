use super::*;
use crate::{ArtifactState, normalize_and_check, normalize_and_check_with_state};
use naome_foundation::{FreeVariable, Logic, ZfcAxiom};
use naome_proof::ProofCertificate;

fn assess(
    target: &Formula,
    state: &dyn ContextView,
    policy: &PrefilterPolicy,
) -> PrefilterDecision {
    let registry = QuestionRegistry::new();
    assess_question(
        &AssessmentQuestion::new(FOUNDATION_ID, target, b"formal target", &[], None).unwrap(),
        &KnowledgeSnapshot::new([7; 32], state, &registry),
        policy,
    )
}

fn verify(decision: &PrefilterDecision, target: &Formula, state: &dyn ContextView) -> Vec<ProofId> {
    assert_eq!(decision.outcome, PrefilterOutcome::Reject);
    assert!(decision.novelty().is_none());
    let witness = decision
        .deduction
        .as_ref()
        .expect("every synthesized answer carries a certificate");
    let checked = normalize_and_check_with_state(
        ProofCertificate::from_canonical_bytes(witness.canonical_certificate()).unwrap(),
        state,
    )
    .unwrap();
    assert_eq!(checked.conclusion(), target);
    assert_eq!(checked.proof_id(), witness.proof_id());
    witness.original_proofs().to_vec()
}

#[test]
fn elementary_answers_have_independently_rechecked_certificates_without_stored_proofs() {
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let p = Formula::for_all(x, Formula::member(x, x));
    let q = Formula::for_all(x, Formula::negate(Formula::member(x, x)));
    let state = ArtifactState::new();
    let snapshot = state.snapshot_id();
    let cases = [
        Formula::for_all(x, Formula::equal(x, x)),
        Formula::for_all(
            x,
            Formula::implies(Formula::member(x, x), Formula::member(x, x)),
        ),
        Formula::implies(p.clone(), p.clone()),
        Logic::simplification(p.clone(), q.clone()),
        Logic::frege(p.clone(), q.clone(), p.clone()),
        Logic::classical_contraposition(p.clone(), q.clone()),
        Formula::for_all(
            y,
            Logic::universal_instantiation(x, y, Formula::member(x, y)),
        ),
        Formula::for_all(
            x,
            Formula::for_all(y, Logic::equality_substitution(x, y, Formula::member(x, y))),
        ),
        Logic::universal_distribution(x, Formula::equal(x, x), Formula::member(x, x)),
        Logic::vacuous_universal(p),
        ZfcAxiom::Extensionality.formula(),
        ZfcAxiom::Pairing.formula(),
        ZfcAxiom::Union.formula(),
        ZfcAxiom::PowerSet.formula(),
        ZfcAxiom::Infinity.formula(),
        ZfcAxiom::Foundation.formula(),
        ZfcAxiom::Choice.formula(),
    ];
    for target in cases {
        // Distribution's open inputs become closed in its quantified output.
        assert!(target.is_closed());
        let decision = assess(&target, &state, &PrefilterPolicy::default());
        assert_eq!(
            decision.reason,
            Some(RejectionReason::KnownProof),
            "{}: {decision:?}",
            target.to_source()
        );
        assert_eq!(decision.rule, "Q07_ELEMENTARY_CERTIFICATE");
        assert!(verify(&decision, &target, &state).is_empty());
    }
    assert_eq!(state.snapshot_id(), snapshot);
}

#[test]
fn elementary_refutations_carry_the_opposite_target_certificate() {
    let negative = ZfcAxiom::Infinity.formula();
    let bytes = negative.encode_canonical().unwrap();
    assert_eq!(bytes[0], 2);
    let positive = Formula::decode_canonical(&bytes[1..]).unwrap();
    let state = ArtifactState::new();
    let decision = assess(&positive, &state, &PrefilterPolicy::default());
    assert_eq!(decision.reason, Some(RejectionReason::KnownRefutation));
    assert!(decision.has_answer());
    assert!(verify(&decision, &negative, &state).is_empty());
}

fn universal_simplification(
    state: &mut ArtifactState,
    a: Formula,
    b: Formula,
    variables: &[FreeVariable],
) -> ProofId {
    let mut steps = vec![ProofStep::Simplification {
        antecedent: a.into(),
        consequent: b.into(),
    }];
    for variable in variables.iter().rev() {
        steps.push(ProofStep::Generalization {
            premise: (steps.len() - 1) as u32,
            variable: *variable,
        });
    }
    let proof = normalize_and_check(ProofCertificate::new(steps).unwrap()).unwrap();
    let id = proof.proof_id();
    state.register_proof(proof).unwrap();
    id
}

#[test]
fn specialized_universal_lemmas_combine_across_mp_and_preserve_all_original_citations() {
    let x = FreeVariable::new(4);
    let y = FreeVariable::new(8);
    let r = Formula::equal(x, x);
    let p = Formula::member(x, y);
    let s = Formula::member(y, x);
    let mut state = ArtifactState::new();
    let second = universal_simplification(
        &mut state,
        Formula::implies(p.clone(), r.clone()),
        s.clone(),
        &[x, y],
    );
    let first = universal_simplification(&mut state, r.clone(), p.clone(), &[x, y]);
    let target = Formula::for_all(
        x,
        Formula::for_all(y, Formula::implies(s, Formula::implies(p, r))),
    );
    let before = state.snapshot_id();
    let decision = assess(&target, &state, &PrefilterPolicy::default());
    assert_eq!(
        decision.reason,
        Some(RejectionReason::KnownProof),
        "{decision:?}"
    );
    assert_eq!(decision.rule, "Q07_CHECKED_INSTANTIATED_CLOSURE");
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(verify(&decision, &target, &state), expected);
    assert_eq!(state.snapshot_id(), before);
    let diagonal = Formula::for_all(
        x,
        Formula::implies(
            Formula::member(x, x),
            Formula::implies(Formula::member(x, x), Formula::equal(x, x)),
        ),
    );
    let result = assess(&diagonal, &state, &PrefilterPolicy::default());
    verify(&result, &diagonal, &state);
}

#[test]
fn unanswered_targets_are_not_synthesized_and_limits_are_explicitly_inconclusive() {
    let x = FreeVariable::new(0);
    let target = Formula::for_all(x, Formula::member(x, x));
    let state = ArtifactState::new();
    assert!(assess(&target, &state, &PrefilterPolicy::default()).passed());
    let mut limited = PrefilterPolicy::default();
    limited.limits.operations = 1;
    let incomplete = assess(&target, &state, &limited);
    assert_eq!(incomplete.outcome, PrefilterOutcome::Inconclusive);
    assert_eq!(incomplete.reason, Some(RejectionReason::ExecutionLimit));
    assert!(incomplete.novelty().is_none());
    assert!(incomplete.deduction.is_none());
    for reason in [
        RejectionReason::ExecutionLimit,
        RejectionReason::ReceivingLimit,
        RejectionReason::StaleContext,
        RejectionReason::InvalidPolicy,
        RejectionReason::InvalidEvidence,
    ] {
        let decision =
            assess(&target, &state, &PrefilterPolicy::default()).reject(reason, "INCOMPLETE");
        assert_eq!(decision.outcome, PrefilterOutcome::Inconclusive);
        assert!(!decision.passed());
        assert!(decision.novelty().is_none());
    }
}
