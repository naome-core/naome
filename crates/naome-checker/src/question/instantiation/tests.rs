use super::*;

#[test]
fn specialization_preserves_parameter_aliasing_and_cannot_capture_inner_binders() {
    let p = FreeVariable::new(u32::MAX);
    let q = FreeVariable::new(u32::MAX - 1);
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let bytes = |formula: Formula| formula.encode_canonical().unwrap();
    assert!(
        match_variables(
            &bytes(Formula::member(p, p)),
            &bytes(Formula::member(x, y)),
            |_| true
        )
        .is_none()
    );
    let assignments = match_variables(
        &bytes(Formula::member(p, q)),
        &bytes(Formula::member(x, x)),
        |_| true,
    )
    .unwrap();
    assert_eq!(assignments.get(&p), Some(&x));
    assert_eq!(assignments.get(&q), Some(&x));
    let pattern = Formula::for_all(y, Formula::member(p, y));
    let captured = Formula::for_all(y, Formula::member(y, y));
    assert!(match_variables(&bytes(pattern.clone()), &bytes(captured), |_| true).is_none());
    let valid = Formula::for_all(y, Formula::member(x, y));
    assert_eq!(
        match_variables(&bytes(pattern), &bytes(valid), |_| true)
            .unwrap()
            .get(&p),
        Some(&x)
    );
}

#[test]
fn checked_pattern_candidates_require_exact_bounded_operands() {
    let a = FreeVariable::new(1);
    let b = FreeVariable::new(2);
    let source = Formula::for_all(a, Formula::for_all(b, Formula::member(b, a)));
    let target = Formula::member(a, b);
    assert_eq!(
        universal_operands(&source, &target, 2).unwrap(),
        Some(vec![b, a])
    );
    assert!(universal_operands(&source, &target, 1).unwrap().is_none());

    let repeated = Formula::for_all(a, Formula::member(a, a));
    assert!(projections(&repeated).contains(&universal_pattern(&target).unwrap()));
    assert!(universal_operands(&repeated, &target, 2).unwrap().is_none());
}

#[test]
fn projections_preserve_the_full_pattern_and_each_implication_suffix() {
    let x = FreeVariable::new(1);
    let atom = Formula::equal(x, x);
    let suffix = Formula::implies(Formula::member(x, x), atom.clone());
    let body = Formula::implies(atom.clone(), suffix.clone());
    let source = Formula::for_all(x, body.clone());

    assert_eq!(projections(&source), [key(&body), key(&suffix), key(&atom)]);
}

#[test]
fn an_open_local_rule_keeps_its_outer_variables_fixed() {
    let a = FreeVariable::new(0);
    let b = FreeVariable::new(1);
    let x = FreeVariable::new(2);
    let source = Formula::for_all(x, Formula::member(x, a));
    assert_eq!(
        universal_operands(&source, &Formula::member(b, a), 1).unwrap(),
        Some(vec![b])
    );
    assert!(
        universal_operands(&source, &Formula::member(b, b), 1)
            .unwrap()
            .is_none()
    );
}
