use super::*;
#[test]
fn incomplete_or_duplicate_observations_cannot_qualify() {
    let mut s = Summary::default();
    s.record(0, false, true).unwrap();
    assert!(!s.complete());
    assert_eq!(
        s.record(0, false, true).unwrap_err(),
        crate::ResearchFailure::TransferSequence.into()
    );
    assert_eq!(
        s.record(2, false, true).unwrap_err(),
        crate::ResearchFailure::TransferSequence.into()
    );
    s.observed |= 1 << CASES;
    assert!(s.validate().is_err());
    assert!(
        Summary {
            before: 1,
            ..Summary::default()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn transfer_preserves_invalid_question_failure() {
    let state = crate::learning::State::fresh();
    let mut engine = crate::learning::Engine::default();
    let mut io = crate::learning::tests::MemoryStore::default();
    let actual = evaluate("invalid", &state, &state.model, &mut engine, &mut io, 1)
        .err()
        .unwrap();
    let expected = crate::Error::from(
        naome_checker::question::ResearchQuestion::from_hex("invalid").unwrap_err(),
    );
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}
