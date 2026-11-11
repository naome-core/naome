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
    assert!(universal_operands(&source, &target, 0).unwrap().is_none());
    assert!(universal_operands(&target, &target, 2).unwrap().is_none());

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
fn specialization_charges_each_attempt_through_the_last_suffix() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let atom = Formula::equal(x, x);
    let suffix = Formula::implies(atom.clone(), atom.clone());
    let source = Formula::for_all(x, Formula::implies(atom, suffix));
    let target = Formula::member(y, y);
    let artifacts = crate::state::ArtifactState::new();
    let proof = ProofId::from_bytes([0; 32]);
    let byte_budget = source.encode_canonical().unwrap().len() * (24 + 3 * 8);
    let budget = |operations, bytes| Work {
        operations,
        bytes,
        certificate_steps: 0,
        certificate_bytes: 0,
    };

    let mut exact = budget(4, byte_budget);
    assert!(
        specialize(proof, &source, &target, &artifacts, &mut exact)
            .unwrap()
            .is_none()
    );
    assert_eq!((exact.operations, exact.bytes), (0, 0));

    for mut limited in [budget(3, byte_budget), budget(4, byte_budget - 1)] {
        assert!(matches!(
            specialize(proof, &source, &target, &artifacts, &mut limited),
            Err(LIMIT)
        ));
    }
}

#[test]
fn opening_a_prefix_skips_free_and_excluded_identifiers() {
    let outer = FreeVariable::new(1);
    let inner = FreeVariable::new(2);
    let free = FreeVariable::new(u32::MAX - 1);
    let excluded = BTreeSet::from([FreeVariable::new(u32::MAX), FreeVariable::new(u32::MAX - 3)]);
    let body = Formula::implies(Formula::member(outer, free), Formula::equal(inner, free));
    let source = Formula::for_all(outer, Formula::for_all(inner, body));
    assert_eq!(source.outer_universal_count(), 2);
    assert_eq!(Formula::negate(source.clone()).outer_universal_count(), 0);
    let first = FreeVariable::new(u32::MAX - 2);
    let second = FreeVariable::new(u32::MAX - 4);
    let expected = Formula::implies(Formula::member(first, free), Formula::equal(second, free));

    assert_eq!(
        open(&source, &excluded, 2),
        Some((expected, vec![first, second]))
    );
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
