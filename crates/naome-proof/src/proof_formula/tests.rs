use super::*;
use crate::DefinitionResolution;

struct EmptyResolver;

impl DefinitionResolver for EmptyResolver {
    fn resolve_definition(
        &self,
        _definition_id: DefinitionId,
    ) -> Result<Option<DefinitionResolution<'_>>, crate::DefinitionAccessError> {
        Ok(None)
    }
}

#[test]
fn primitive_expansion_is_borrowed_and_charges_no_definition_work() {
    let formula = Formula::equal(FreeVariable::new(3), FreeVariable::new(3));
    let proof_formula = ProofFormula::from(formula);

    let (expanded, work) = proof_formula
        .expand_with_node_limit(&EmptyResolver, 0)
        .unwrap();

    assert!(matches!(expanded, Cow::Borrowed(_)));
    assert!(std::ptr::eq(
        expanded.as_ref(),
        proof_formula.as_primitive().unwrap()
    ));
    assert_eq!(work, 0);
}

#[test]
fn construction_and_codec_round_trip_have_one_canonical_representation() {
    let variable = FreeVariable::new(4);
    let primitive = ProofFormula::from_defined(DefinedFormula::equal(variable, variable))
        .expect("a primitive DefinedFormula has a Foundation representation");
    assert!(primitive.as_primitive().is_some());
    assert!(primitive.as_defined().is_none());

    let definition_id = DefinitionId::from_bytes([0x42; 32]);
    let defined =
        ProofFormula::from_defined(DefinedFormula::defined_relation(definition_id, [variable]))
            .unwrap();
    assert!(defined.as_primitive().is_none());
    assert!(defined.as_defined().is_some());

    for formula in [primitive, defined] {
        let bytes = formula
            .encode_canonical_with_node_limit(usize::MAX)
            .unwrap()
            .0;
        let decoded = ProofFormula::decode_canonical_with_node_limit(&bytes, usize::MAX)
            .unwrap()
            .0;
        assert_eq!(decoded, formula);
    }
}
