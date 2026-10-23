use super::*;
use crate::FreeVariable;
#[test]
fn source_keeps_nested_binders_vacuous_quantifiers_and_free_ids_distinct() {
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let free = FreeVariable::new(u32::MAX);
    let formula = Formula::for_all(
        x,
        Formula::for_all(
            y,
            Formula::implies(
                Formula::member(x, y),
                Formula::negate(Formula::equal(x, free)),
            ),
        ),
    );
    assert_eq!(
        formula.to_source(),
        "all(b0, all(b1, imp(mem(b0, b1), not(eq(b0, f4294967295)))))"
    );
    let vacuous = Formula::for_all(y, Formula::for_all(x, Formula::equal(x, x)));
    assert_eq!(vacuous.to_source(), "all(b0, all(b1, eq(b1, b1)))");
}
