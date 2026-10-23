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
    assert_eq!(
        difference.expected(),
        "all(b0, imp(eq(b0, f1), mem(b0, f1)))"
    );
    assert_eq!(difference.actual(), "all(b0, imp(eq(f1, b0), mem(b0, f1)))");
}

#[test]
fn diagnostic_rendering_is_bounded_even_when_the_difference_is_beyond_the_preview() {
    let x = FreeVariable::new(0);
    let mut expected = Formula::equal(x, x);
    let mut actual = Formula::member(x, x);
    for _ in 0..100 {
        expected = Formula::negate(expected);
        actual = Formula::negate(actual);
    }
    let difference = FormulaMismatch::between(&expected, &actual).unwrap();
    assert_eq!(difference.path().len(), 100);
    assert_eq!(difference.expected().len(), 256);
    assert!(difference.expected().ends_with("..."));
    for maximum in 0..20 {
        assert!(expected.to_source_with_limit(maximum).len() <= maximum);
    }
    assert_eq!(Formula::equal(x, x).to_source_with_limit(100), "eq(f0, f0)");
}
