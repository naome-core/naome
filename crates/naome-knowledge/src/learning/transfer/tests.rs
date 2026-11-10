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

#[test]
fn an_oversized_recipe_is_a_paid_unsolved_pair() {
    let source = concat!(
        "040404030301010000000001000000020101000000000100000001030301010000000101000000000101000000000100000002",
        "0303010100000001010000000101010000000101000000000303010100000001010000000201010000000101000000010303",
        "01010000000201000000000101000000010100000002030301010000000201000000010101000000020100000000030301",
        "01000000020100000002010100000002010000000103030404040302030302020302010100000002010000000201010000",
        "00010100000001010100000000010000000002020203020101000000020100000002010100000001010000000101010000",
        "00000100000000010100000002010000000203030101000000010100000000010100000000010000000203030101000000",
        "00010000000101010000000101000000000101000000010100000000",
    );
    let mut state = crate::learning::State::fresh();
    for certificate in [
        "0000000002000000320403040300010000000001000000010001000000000000000000040300010000000001000000010001000000000000000001",
        "00000000030000003103040300010000000000000000000001000000000000000001040300010000000000000000000001000000000000000002",
    ] {
        assert!(
            state
                .remember_definition(crate::learning::definitions::Entry {
                    certificate: crate::unhex(certificate).unwrap(),
                    obligation: None,
                })
                .unwrap()
        );
    }
    let mut engine = crate::learning::Engine::default();
    let mut io = crate::learning::tests::MemoryStore::default();
    let pair = evaluate(source, &state, &state.model, &mut engine, &mut io, 347).unwrap();
    for outcome in [pair.before, pair.after] {
        assert!(!outcome.solved);
        assert!(outcome.expansions > 0 && outcome.expansions <= ALLOWANCE);
        assert_eq!(
            outcome.terminal,
            crate::learning::experience::TerminalEvidence::Unsupported(
                crate::learning::experience::Capacity::Certificate,
            )
        );
    }
}
