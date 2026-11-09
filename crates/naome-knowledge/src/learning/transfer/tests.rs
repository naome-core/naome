use super::*;
fn summary(pairs: &[(bool, bool)]) -> Summary {
    let mut s = Summary::default();
    for index in 0..CASES {
        let (before, after) = pairs.get(index).copied().unwrap_or((false, false));
        s.record(index, before, after).unwrap();
    }
    s
}
#[test]
fn aggregate_gain_cannot_hide_a_lost_whole_family() {
    let s = summary(&[(true, false), (false, false), (false, true), (false, true)]);
    assert!(s.gain() > 0.);
    assert_eq!(s.families()[0], [1, 0]);
    assert_eq!(s.families()[1], [0, 2]);
    assert!(!s.accepts());
    let retained = summary(&[(true, true), (false, false), (false, true), (false, false)]);
    assert!(retained.accepts());
    assert!(!summary(&[(true, true)]).accepts());
}
#[test]
fn a_new_success_cannot_replace_an_incumbent_success_in_its_family() {
    let exchanged = summary(&[(true, false), (false, true), (false, true)]);
    assert_eq!(exchanged.families()[0], [1, 1]);
    assert!(exchanged.gain() > 0.);
    assert_eq!(exchanged.loss(), 1. / FAMILIES as f32);
    assert!(!exchanged.accepts());

    let retained = summary(&[(true, true), (false, false), (false, true)]);
    assert_eq!(retained.loss(), 0.);
    assert!(retained.accepts());
}
#[test]
fn incomplete_or_duplicate_observations_cannot_qualify() {
    let mut s = Summary::default();
    s.record(0, false, true).unwrap();
    assert!(!s.accepts());
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
