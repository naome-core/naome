use super::*;
use naome_foundation::FreeVariable;
#[test]
fn formal_targets_need_no_source_parser_and_preserve_orientation_and_family() {
    let x = FreeVariable::new(4);
    let formula = Formula::for_all(x, Formula::member(x, x));
    let positive = QuestionTarget::from_formula(formula.clone()).unwrap();
    let negated_source = Formula::negate(formula.clone());
    let expected_encoding = negated_source.encode_canonical().unwrap();
    let (negative, encoded) = QuestionTarget::from_formula_with_encoding(negated_source).unwrap();
    assert_eq!(encoded, expected_encoding);
    assert_eq!(positive.resolution_id(), negative.resolution_id());
    assert_eq!(positive.canonical_core(), negative.canonical_core());
    assert!(!positive.negation_parity());
    assert!(negative.negation_parity());
    assert_eq!(negative.refuted_target(), &formula);
    let double_negative =
        QuestionTarget::from_formula(Formula::negate(negative.formula().clone())).unwrap();
    assert!(!double_negative.negation_parity());
    assert_eq!(double_negative.resolution_id(), positive.resolution_id());
    assert_eq!(double_negative.negative_target(), negative.formula());
    assert!(QuestionTarget::from_formula(Formula::equal(x, x)).is_err());
}
