use super::*;
use std::collections::BTreeSet;

#[test]
fn empty_graph_construction_produces_new_closed_questions_within_the_page_budget() {
    let model = Model::fresh();
    let mut unique = BTreeSet::new();
    let mocks = (0..3)
        .map(|i| CompiledQuestion::compile(&crate::mocks::create_question(i)).unwrap())
        .map(|q| *q.resolution_id())
        .collect::<BTreeSet<_>>();
    for cursor in 0..8 {
        let page = questions(cursor, &VecDeque::new(), &model, 12, 64 * 1024);
        assert!(!page.is_empty());
        assert!(
            page.iter()
                .map(|q| q.source().len() * 8 + 256)
                .sum::<usize>()
                <= 64 * 1024
        );
        for question in page {
            let compiled = CompiledQuestion::compile(question.source()).unwrap();
            assert_eq!(compiled.canonical_core(), question.canonical_core());
            assert!(question.formula().is_closed());
            assert!(crate::learning::State::eligible(question.source()));
            unique.insert(*question.resolution_id());
        }
    }
    assert!(unique.difference(&mocks).count() >= 24);
    assert!(questions(0, &VecDeque::new(), &model, 12, 1).is_empty());
}

#[test]
fn comprehension_preserves_existing_parameter_roles_instead_of_capturing_them() {
    let formula = comprehension(Formula::member(FreeVariable::new(8), FreeVariable::new(9)));
    assert_eq!(
        formula
            .free_variables()
            .into_iter()
            .map(FreeVariable::identifier)
            .collect::<Vec<_>>(),
        vec![8, 9]
    );
    let expected = CompiledQuestion::compile(
        "goal=all([p,q],all(a,ex(b,all(x,iff(mem(x,b),and(mem(x,a),mem(p,q)))))))",
    )
    .unwrap();
    let actual = CompiledQuestion::from_formula(close(formula)).unwrap();
    assert_eq!(actual.core(), expected.core());
}

#[test]
fn checked_and_unresolved_observations_train_distinct_solver_predictions() {
    let question = CompiledQuestion::compile(&crate::learning::tests::own_question()).unwrap();
    let initial = Model::fresh();
    let mut resolved = initial.clone();
    let mut unresolved = initial.clone();
    for _ in 0..32 {
        resolved.observe(&question, true, 10).unwrap();
        unresolved.observe(&question, false, 10).unwrap();
    }
    assert!(resolved.weight(&question) > initial.weight(&question));
    assert!(unresolved.weight(&question) < initial.weight(&question));
    assert_eq!(
        (resolved.updates, resolved.resolved, resolved.unresolved),
        (32, 32, 0)
    );
    assert_eq!(
        (
            unresolved.updates,
            unresolved.resolved,
            unresolved.unresolved
        ),
        (32, 0, 32)
    );
    let restored: Model = serde_json::from_slice(&serde_json::to_vec(&resolved).unwrap()).unwrap();
    assert_eq!(resolved, restored);
    assert_eq!(
        questions(41, &VecDeque::new(), &resolved, 12, 64 * 1024),
        questions(41, &VecDeque::new(), &restored, 12, 64 * 1024)
    );
    let mut invalid = serde_json::to_value(&resolved).unwrap();
    invalid["weights"] = serde_json::json!([]);
    assert!(
        serde_json::from_value::<Model>(invalid)
            .unwrap()
            .validate()
            .is_err()
    );
}
