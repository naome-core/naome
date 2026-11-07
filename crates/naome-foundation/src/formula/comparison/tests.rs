use super::*;
use crate::FreeVariable;

#[test]
fn differences_preserve_binder_structure_and_locate_the_first_operand() {
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let expected = Formula::for_all(
        x,
        Formula::implies(Formula::equal(x, y), Formula::member(x, y)),
    );
    let renamed = Formula::for_all(
        FreeVariable::new(9),
        Formula::implies(
            Formula::equal(FreeVariable::new(9), y),
            Formula::member(FreeVariable::new(9), y),
        ),
    );
    assert!(FormulaMismatch::between(&expected, &renamed).is_none());
    let actual = Formula::for_all(
        x,
        Formula::implies(Formula::equal(y, x), Formula::member(x, y)),
    );
    let difference = FormulaMismatch::between(&expected, &actual).unwrap();
    assert_eq!(
        difference.path(),
        &[
            FormulaPathSegment::Quantified,
            FormulaPathSegment::Antecedent,
            FormulaPathSegment::LeftVariable
        ]
    );
}

#[test]
fn difference_path_reaches_a_deep_mismatch() {
    let x = FreeVariable::new(0);
    let mut expected = Formula::equal(x, x);
    let mut actual = Formula::member(x, x);
    for _ in 0..100 {
        expected = Formula::negate(expected);
        actual = Formula::negate(actual);
    }
    let difference = FormulaMismatch::between(&expected, &actual).unwrap();
    assert_eq!(difference.path().len(), 100);
}
