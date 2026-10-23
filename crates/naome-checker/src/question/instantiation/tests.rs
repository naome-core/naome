use super::*;

#[test]
fn specialization_preserves_parameter_aliasing_and_cannot_capture_inner_binders() {
    let p = FreeVariable::new(u32::MAX);
    let q = FreeVariable::new(u32::MAX - 1);
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let bytes = |formula: Formula| formula.encode_canonical().unwrap();
    assert!(
        match_variables(&bytes(Formula::member(p, p)), &bytes(Formula::member(x, y))).is_none()
    );
    let assignments =
        match_variables(&bytes(Formula::member(p, q)), &bytes(Formula::member(x, x))).unwrap();
    assert_eq!(assignments.get(&p), Some(&x));
    assert_eq!(assignments.get(&q), Some(&x));
    let pattern = Formula::for_all(y, Formula::member(p, y));
    let captured = Formula::for_all(y, Formula::member(y, y));
    assert!(match_variables(&bytes(pattern.clone()), &bytes(captured)).is_none());
    let valid = Formula::for_all(y, Formula::member(x, y));
    assert_eq!(
        match_variables(&bytes(pattern), &bytes(valid))
            .unwrap()
            .get(&p),
        Some(&x)
    );
}
