use super::*;

fn distinct_formula(index: usize) -> String {
    let variables = ['a', 'b', 'c', 'd', 'e', 'f'];
    let mut formula = format!("equal({},{})", variables[index / 6], variables[index % 6]);
    for variable in variables.into_iter().rev() {
        formula = format!("forall({variable},{formula})");
    }
    formula
}

#[test]
fn default_queue_accepts_32_in_finalized_order_and_rejects_33_without_mutation() {
    let mut state = LedgerState::new(genesis());
    assert_eq!(state.genesis().profile().limits().queued_questions, 32);
    let first = submit(&mut state, &distinct_formula(0));
    let now = state.time();
    apply(&mut state, now, vec![]);
    assert_eq!(
        state.question(first).unwrap().status(),
        QuestionStatus::Active
    );
    let mut expected = Vec::new();
    for index in 1..=32 {
        let id = submit(&mut state, &distinct_formula(index));
        expected.push(id);
        assert_eq!(state.question(id).unwrap().status(), QuestionStatus::Queued);
        assert!(state.receipt(id).is_some());
        assert_eq!(
            state
                .queued()
                .map(QuestionEntry::submission)
                .collect::<Vec<_>>(),
            expected
        );
    }
    let excess = signed(
        &state,
        4,
        OperationBody::Submit {
            purpose: "33rd waiting family must be rejected".into(),
            question: question(&state, &distinct_formula(33)),
        },
    );
    let id = excess.id();
    let before = state.commitment();
    let nonce = state.next_nonce(author(4));
    assert!(matches!(
        state.prepare_record(
            time(&state, state.time()),
            vec![excess],
            handoff_plan(&state)
        ),
        Err(LedgerError::Limit(_))
    ));
    assert_eq!(state.commitment(), before);
    assert_eq!(state.next_nonce(author(4)), nonce);
    assert!(state.receipt(id).is_none());
    assert!(state.question(id).is_none());
    assert_eq!(
        state
            .queued()
            .map(QuestionEntry::submission)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(state.library().len(), 0);
    assert_eq!(state.balances().paid_completions(), 0);
}
