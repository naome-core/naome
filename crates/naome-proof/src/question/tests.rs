use super::*;
use naome_foundation::FreeVariable;
#[test]
fn formal_targets_need_no_source_parser_and_preserve_orientation_and_family() {
    let x = FreeVariable::new(4);
    let formula = Formula::for_all(x, Formula::member(x, x));
    let positive = QuestionTarget::from_formula(formula.clone()).unwrap();
    let negative = QuestionTarget::from_formula(Formula::negate(formula.clone())).unwrap();
    assert_eq!(positive.resolution_id(), negative.resolution_id());
    assert_eq!(positive.canonical_core(), negative.canonical_core());
    assert!(!positive.negation_parity());
    assert!(negative.negation_parity());
    assert_eq!(negative.refuted_target(), &formula);
    assert!(QuestionTarget::from_formula(Formula::equal(x, x)).is_err());
}
