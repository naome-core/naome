use super::super::*;
use crate::normalize_and_check_with_state;

#[test]
fn nonuniversal_instantiated_goal_keeps_its_binder_attempt_charge() {
    let target = Formula::negate(naome_foundation::ZfcAxiom::Pairing.formula());
    let bytes = target.encode_canonical().unwrap();
    let search_target = (&target, crate::statement_id(&bytes), bytes.len());
    let state = crate::ArtifactState::new();
    let budget = |operations| Work {
        operations,
        bytes: usize::MAX,
        certificate_steps: 0,
        certificate_bytes: 0,
    };
    let mut ordinary = budget(5);
    super::search::Search::new(search_target, &state, false, &mut ordinary).unwrap();
    let mut instantiated = budget(5);
    super::search::Search::new(search_target, &state, true, &mut instantiated).unwrap();

    assert_eq!(ordinary.operations - instantiated.operations, 1);
    assert_eq!(ordinary.bytes - instantiated.bytes, 4 * bytes.len());
    assert!(matches!(
        super::search::Search::new(search_target, &state, true, &mut budget(4)),
        Err(super::LIMIT)
    ));
}

#[test]
fn opposite_short_answers_survive_a_dense_unprovable_direction_with_the_same_budget() {
    for short_negative in [false, true] {
        let (state, target) = fixtures::budget_case(128, short_negative);
        let before = state.snapshot_id();
        let registry = QuestionRegistry::new();
        let request =
            AssessmentQuestion::new(FOUNDATION_ID, &target, b"paired search", &[], None).unwrap();
        let mut policy = PrefilterPolicy::default();
        policy.limits.operations = 512;
        let result = assess_question(
            &request,
            &KnowledgeSnapshot::new([9; 32], &state, &registry),
            &policy,
        );
        assert_eq!(
            result.reason,
            Some(if short_negative {
                RejectionReason::KnownRefutation
            } else {
                RejectionReason::KnownProof
            })
        );
        assert_eq!(
            result.rule,
            crate::question::PrefilterRule::Q04CheckedMpClosure
        );
        assert!(result.novelty().is_none());
        let witness = result.deduction.unwrap();
        let checked = normalize_and_check_with_state(
            naome_proof::ProofCertificate::from_canonical_bytes(witness.canonical_certificate())
                .unwrap(),
            &state,
        )
        .unwrap();
        assert_eq!(
            checked.conclusion(),
            &if short_negative {
                Formula::negate(target)
            } else {
                target
            }
        );
        assert_eq!(witness.original_proofs().len(), 2);
        assert_eq!(state.snapshot_id(), before);
    }
}
