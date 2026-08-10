use super::{
    EQUAL, FORMULA_MAX_BYTES, FORMULA_MAX_DEPTH, FORMULA_MAX_NODES, FormulaCodecError, IMPLIES, NOT,
};
use crate::{Formula, FreeVariable};

#[test]
fn alpha_equivalent_formulas_have_identical_golden_bytes() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let with_x = Formula::for_all(x, Formula::equal(x, x));
    let with_y = Formula::for_all(y, Formula::equal(y, y));
    let expected = [
        0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    assert_eq!(with_x.encode_canonical().unwrap(), expected);
    assert_eq!(with_y.encode_canonical().unwrap(), expected);
}

#[test]
fn primitive_formula_and_free_variable_tags_have_stable_golden_bytes() {
    let x = FreeVariable::new(0x0102_0304);
    let y = FreeVariable::new(0x0506_0708);
    let formula = Formula::negate(Formula::implies(
        Formula::equal(x, y),
        Formula::member(y, x),
    ));

    assert_eq!(
        formula.encode_canonical().unwrap(),
        [
            0x02, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x05, 0x06, 0x07, 0x08, 0x01,
            0x00, 0x05, 0x06, 0x07, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04,
        ]
    );
}

#[test]
fn free_variable_normalized_bytes_ignore_identifiers_but_preserve_aliasing() {
    let x = FreeVariable::new(7);
    let y = FreeVariable::new(42);
    let renamed_x = FreeVariable::new(900);
    let renamed_y = FreeVariable::new(3);
    let first = Formula::implies(Formula::equal(x, y), Formula::member(y, x));
    let renamed = Formula::implies(
        Formula::equal(renamed_x, renamed_y),
        Formula::member(renamed_y, renamed_x),
    );
    let distinct = Formula::implies(Formula::equal(x, x), Formula::member(y, x));

    let expected = [
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    assert_eq!(first.encode_free_variable_normalized().unwrap(), expected);
    assert_eq!(
        renamed.encode_free_variable_normalized(),
        first.encode_free_variable_normalized()
    );
    assert_ne!(
        distinct.encode_free_variable_normalized(),
        first.encode_free_variable_normalized()
    );
}

#[test]
fn free_variable_normalization_leaves_bound_indices_unchanged() {
    let x = FreeVariable::new(19);
    let y = FreeVariable::new(41);
    let normalized = Formula::for_all(x, Formula::member(y, x))
        .encode_free_variable_normalized()
        .unwrap();

    assert_eq!(
        normalized,
        [
            0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]
    );
}

#[test]
fn canonical_formula_round_trips_free_and_bound_variables() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let formula = Formula::for_all(x, Formula::member(y, x));

    let encoded = formula.encode_canonical().unwrap();
    let decoded = Formula::decode_canonical(&encoded).unwrap();

    assert_eq!(decoded, formula);
}

#[test]
fn caller_node_limits_are_counted_before_the_next_node() {
    let x = FreeVariable::new(1);
    let leaf = Formula::equal(x, x);
    let formula = Formula::negate(Formula::equal(x, x));
    let (encoded, encoded_nodes) = formula.encode_canonical_with_node_limit(2).unwrap();
    let (decoded, decoded_nodes) = Formula::decode_canonical_with_node_limit(&encoded, 2).unwrap();

    assert_eq!(encoded_nodes, 2);
    assert_eq!(decoded_nodes, 2);
    assert_eq!(decoded, formula);
    assert_eq!(
        formula.encode_canonical_with_node_limit(1),
        Err(FormulaCodecError::NodeLimitExceeded { maximum: 1 })
    );
    assert_eq!(
        Formula::decode_canonical_with_node_limit(&encoded, 1),
        Err(FormulaCodecError::NodeLimitExceeded { maximum: 1 })
    );
    assert_eq!(
        leaf.encode_canonical_with_node_limit(0),
        Err(FormulaCodecError::NodeLimitExceeded { maximum: 0 })
    );
    assert_eq!(
        Formula::decode_canonical_with_node_limit(&[EQUAL], 0),
        Err(FormulaCodecError::NodeLimitExceeded { maximum: 0 })
    );

    assert_eq!(
        Formula::decode_canonical_with_node_limit(&[NOT, 0xff], 1),
        Err(FormulaCodecError::NodeLimitExceeded { maximum: 1 })
    );

    let mut invalid_second_branch = vec![IMPLIES];
    invalid_second_branch.extend_from_slice(&leaf.encode_canonical().unwrap());
    invalid_second_branch.push(0xff);
    assert_eq!(
        Formula::decode_canonical_with_node_limit(&invalid_second_branch, 2),
        Err(FormulaCodecError::NodeLimitExceeded { maximum: 2 })
    );
}

#[test]
fn decoder_rejects_a_dangling_bound_variable() {
    let encoded = [
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    assert_eq!(
        Formula::decode_canonical(&encoded),
        Err(FormulaCodecError::DanglingBoundVariable {
            index: 0,
            binder_depth: 0,
        })
    );
}

#[test]
fn decoder_rejects_unknown_and_trailing_bytes() {
    assert_eq!(
        Formula::decode_canonical(&[0xff]),
        Err(FormulaCodecError::UnknownFormulaTag(0xff))
    );
    assert_eq!(
        Formula::decode_canonical(&[
            0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]),
        Err(FormulaCodecError::UnknownVariableTag(0xff))
    );

    let x = FreeVariable::new(1);
    let mut encoded = Formula::equal(x, x).encode_canonical().unwrap();
    encoded.push(0xff);
    assert_eq!(
        Formula::decode_canonical(&encoded),
        Err(FormulaCodecError::TrailingBytes { remaining: 1 })
    );
}

#[test]
fn codec_fails_closed_at_the_depth_limit() {
    let x = FreeVariable::new(1);
    let mut accepted = Formula::equal(x, x);
    for _ in 1..FORMULA_MAX_DEPTH {
        accepted = Formula::negate(accepted);
    }
    let mut rejected = accepted.clone();
    rejected = Formula::negate(rejected);

    assert!(accepted.encode_canonical().is_ok());
    assert_eq!(
        rejected.encode_canonical(),
        Err(FormulaCodecError::DepthLimitExceeded {
            maximum: FORMULA_MAX_DEPTH,
        })
    );

    let mut encoded = vec![0x02; FORMULA_MAX_DEPTH as usize];
    encoded.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
    ]);
    assert_eq!(
        Formula::decode_canonical(&encoded),
        Err(FormulaCodecError::DepthLimitExceeded {
            maximum: FORMULA_MAX_DEPTH,
        })
    );
}

#[test]
fn every_proper_prefix_of_a_formula_is_rejected() {
    let x = FreeVariable::new(1);
    let encoded = Formula::for_all(x, Formula::equal(x, x))
        .encode_canonical()
        .unwrap();

    for end in 0..encoded.len() {
        assert!(Formula::decode_canonical(&encoded[..end]).is_err());
    }
}

#[test]
fn codec_enforces_derived_node_and_byte_limits() {
    let x = FreeVariable::new(1);
    let mut accepted = Formula::equal(x, x);
    for _ in 0..15 {
        accepted = Formula::implies(accepted.clone(), accepted);
    }
    let accepted = Formula::negate(accepted);
    let rejected = Formula::negate(accepted.clone());

    assert_eq!(
        accepted.encode_canonical().unwrap().len(),
        FORMULA_MAX_BYTES
    );
    assert_eq!(
        rejected.encode_canonical(),
        Err(FormulaCodecError::NodeLimitExceeded {
            maximum: FORMULA_MAX_NODES,
        })
    );
    assert_eq!(
        rejected.encode_canonical_with_node_limit(usize::MAX),
        Err(FormulaCodecError::NodeLimitExceeded {
            maximum: FORMULA_MAX_NODES,
        })
    );

    let oversized = vec![0x02; FORMULA_MAX_BYTES + 1];
    assert_eq!(
        Formula::decode_canonical(&oversized),
        Err(FormulaCodecError::InputTooLong {
            actual: FORMULA_MAX_BYTES + 1,
            maximum: FORMULA_MAX_BYTES,
        })
    );
}
