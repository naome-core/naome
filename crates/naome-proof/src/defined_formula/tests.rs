use super::*;
use crate::ProofId;

struct OneDefinition {
    id: DefinitionId,
    arity: u32,
    body: DefinedFormula,
}

impl DefinitionResolver for OneDefinition {
    fn resolve_definition(
        &self,
        definition_id: DefinitionId,
    ) -> Result<Option<DefinitionResolution<'_>>, crate::DefinitionAccessError> {
        Ok((definition_id == self.id).then(|| DefinitionResolution::new(self.arity, &self.body)))
    }
}

#[test]
fn primitive_subset_is_byte_identical_and_definition_tag_is_exact() {
    let x = FreeVariable::new(7);
    let y = FreeVariable::new(8);
    let primitive = Formula::for_all(
        x,
        Formula::for_all(
            y,
            Formula::implies(Formula::member(x, y), Formula::negate(Formula::equal(y, x))),
        ),
    );
    let defined = DefinedFormula::from_primitive(&primitive).unwrap();
    assert_eq!(
        defined.encode_canonical().unwrap(),
        primitive.encode_canonical().unwrap()
    );
    assert_eq!(defined.into_primitive().unwrap(), primitive);

    let id = DefinitionId::from_bytes([0x11; 32]);
    let application = DefinedFormula::for_all(x, DefinedFormula::defined_relation(id, [x]));
    let mut expected = vec![FOR_ALL, DEFINED_RELATION];
    expected.extend_from_slice(&[0x11; 32]);
    expected.extend_from_slice(&1_u32.to_be_bytes());
    expected.push(BOUND_VARIABLE);
    expected.extend_from_slice(&0_u32.to_be_bytes());
    assert_eq!(application.encode_canonical().unwrap(), expected);
    assert_eq!(
        DefinedFormula::decode_canonical(&expected).unwrap(),
        application
    );
    assert!(matches!(
        Formula::decode_canonical(&expected),
        Err(FormulaCodecError::UnknownFormulaTag(DEFINED_RELATION))
    ));
}

#[test]
fn primitive_conversion_preserves_the_canonical_depth_limit() {
    let x = FreeVariable::new(0);
    let mut too_deep = Formula::equal(x, x);
    for _ in 0..FORMULA_MAX_DEPTH {
        too_deep = Formula::negate(too_deep);
    }
    assert_eq!(
        DefinedFormula::from_primitive(&too_deep),
        Err(DefinedFormulaCodecError::Primitive(
            FormulaCodecError::DepthLimitExceeded {
                maximum: FORMULA_MAX_DEPTH,
            }
        ))
    );
}

#[test]
fn primitive_conversion_rejects_a_projected_dangling_bound_variable() {
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let quantified = Formula::for_all(y, Formula::member(x, y));
    let PrimitiveNode::ForAll(body) = quantified.view().graph_node() else {
        panic!("constructed formula must be universal");
    };
    let projected = body.to_owned();

    assert_eq!(
        DefinedFormula::from_primitive(&projected),
        Err(DefinedFormulaCodecError::DanglingBoundVariable {
            index: 0,
            binder_depth: 0,
        })
    );
}

#[test]
fn expansion_shifts_an_outer_bound_argument_beneath_body_binders() {
    let formal = FreeVariable::new(0);
    let inner = FreeVariable::new(1);
    let outer = FreeVariable::new(7);
    let body = DefinedFormula::for_all(inner, DefinedFormula::member(formal, inner));
    let id = DefinitionId::from_bytes([0x12; 32]);
    let resolver = OneDefinition { id, arity: 1, body };
    let compact = DefinedFormula::for_all(outer, DefinedFormula::defined_relation(id, [outer]));
    let expanded = compact.expand_with(&resolver).unwrap();
    let expected = Formula::for_all(
        outer,
        Formula::for_all(inner, Formula::member(outer, inner)),
    );
    assert_eq!(expanded, expected);
}

#[test]
fn shared_definition_expansion_preserves_identity_and_logical_work() {
    let x = FreeVariable::new(0);
    let id = DefinitionId::from_bytes([0x3a; 32]);
    let resolver = OneDefinition {
        id,
        arity: 1,
        body: DefinedFormula::equal(x, x),
    };
    let application = DefinedFormula::defined_relation(id, [x]);
    let source =
        DefinedFormula::for_all(x, DefinedFormula::implies(application.clone(), application));
    let atom = Formula::equal(x, x);
    let expected = Formula::for_all(x, Formula::implies(atom.clone(), atom));
    let (expanded, work) = source.expand_with_node_limit(&resolver, 6).unwrap();
    assert_eq!(work, 6);
    assert_eq!(expanded.encode_canonical(), expected.encode_canonical());
    assert_eq!(
        source.expand_with_node_limit(&resolver, 5),
        Err(DefinitionExpansionError::NodeLimitExceeded { maximum: 5 })
    );
}

#[test]
fn expansion_rejects_unknown_wrong_arity_cycle_and_work_exhaustion() {
    let id = DefinitionId::from_bytes([0x22; 32]);
    let x = FreeVariable::new(0);
    let missing = DefinedFormula::defined_relation(id, [x]);
    struct Empty;
    impl DefinitionResolver for Empty {
        fn resolve_definition(
            &self,
            _: DefinitionId,
        ) -> Result<Option<DefinitionResolution<'_>>, crate::DefinitionAccessError> {
            Ok(None)
        }
    }
    assert_eq!(
        missing.expand_with(&Empty),
        Err(DefinitionExpansionError::UnknownDefinition { definition_id: id })
    );

    let resolver = OneDefinition {
        id,
        arity: 1,
        body: DefinedFormula::equal(x, x),
    };
    let wrong = DefinedFormula::defined_relation(id, []);
    assert_eq!(
        wrong.expand_with(&resolver),
        Err(DefinitionExpansionError::ArityMismatch {
            definition_id: id,
            expected: 1,
            actual: 0,
        })
    );
    assert_eq!(
        missing.expand_with_node_limit(&resolver, 1),
        Err(DefinitionExpansionError::NodeLimitExceeded { maximum: 1 })
    );

    let resolver = OneDefinition {
        id,
        arity: 1,
        body: DefinedFormula::defined_relation(id, [x]),
    };
    assert_eq!(
        missing.expand_with(&resolver),
        Err(DefinitionExpansionError::CyclicDefinition { definition_id: id })
    );
}

#[test]
fn definition_applications_bind_normalize_and_round_trip_capture_safely() {
    let id = DefinitionId::from_bytes([0x33; 32]);
    let x = FreeVariable::new(99);
    let y = FreeVariable::new(7);
    let formula = DefinedFormula::for_all(
        x,
        DefinedFormula::implies(
            DefinedFormula::defined_relation(id, [x, y]),
            DefinedFormula::equal(y, y),
        ),
    );
    let renamed = formula.clone().map_free_variables(|_| FreeVariable::new(0));
    assert_eq!(
        formula.encode_free_variable_normalized().unwrap(),
        renamed.encode_free_variable_normalized().unwrap()
    );
    assert_eq!(formula.free_variables(), BTreeSet::from([y]));
    assert_eq!(formula.definition_references(), vec![id]);
    let bytes = formula.encode_canonical().unwrap();
    assert_eq!(DefinedFormula::decode_canonical(&bytes).unwrap(), formula);
}

#[test]
fn proof_id_shaped_values_do_not_resolve_as_definitions() {
    let proof = ProofId::from_bytes([0x44; 32]);
    let id = DefinitionId::from_bytes(*proof.as_bytes());
    let formula = DefinedFormula::defined_relation(id, []);
    struct Empty;
    impl DefinitionResolver for Empty {
        fn resolve_definition(
            &self,
            _: DefinitionId,
        ) -> Result<Option<DefinitionResolution<'_>>, crate::DefinitionAccessError> {
            Ok(None)
        }
    }
    assert!(matches!(
        formula.expand_with(&Empty),
        Err(DefinitionExpansionError::UnknownDefinition { definition_id })
            if definition_id == id
    ));
}
