use super::*;
use naome_foundation::FreeVariable;

#[test]
fn canonical_record_binds_exact_formula_and_preserves_the_resolution_family() {
    let equality = |identifier| {
        let x = FreeVariable::new(identifier);
        Formula::for_all(x, Formula::equal(x, x))
    };
    let positive = ResearchQuestion::from_formula(equality(0)).unwrap();
    let alpha_variant = ResearchQuestion::from_formula(equality(9)).unwrap();
    assert_eq!(positive, alpha_variant);
    assert_eq!(positive.to_hex(), "040001000000000100000000");

    let negative = ResearchQuestion::from_formula(Formula::negate(equality(2))).unwrap();
    assert_ne!(positive.record_id(), negative.record_id());
    assert_eq!(positive.resolution_id(), negative.resolution_id());
    assert_eq!(positive.proved_target(), negative.refuted_target());
    assert_eq!(
        ResearchQuestion::from_canonical_bytes(negative.canonical_bytes()).unwrap(),
        negative
    );

    let mut extra = positive.canonical_bytes().to_vec();
    extra.push(0);
    assert!(ResearchQuestion::from_canonical_bytes(&extra).is_err());
    let x = FreeVariable::new(0);
    let open = Formula::equal(x, x).encode_canonical().unwrap();
    assert!(ResearchQuestion::from_canonical_bytes(&open).is_err());
}
