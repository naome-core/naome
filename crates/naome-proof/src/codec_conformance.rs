use super::*;
use naome_foundation::{FORMULA_MAX_BYTES, Formula, FreeVariable};

#[test]
fn formula_definition_and_payload_codecs_cover_all_forms() {
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let primitive = Formula::for_all(
        x,
        Formula::implies(Formula::equal(x, y), Formula::negate(Formula::member(x, y))),
    );
    crate::codec_corpus::check(
        "primitive formula",
        &[primitive.encode_canonical().unwrap()],
        |bytes| {
            Formula::decode_canonical(bytes)
                .ok()?
                .encode_canonical()
                .ok()
        },
    );
    let defined = DefinedFormula::for_all(
        x,
        DefinedFormula::implies(
            DefinedFormula::equal(x, y),
            DefinedFormula::negate(DefinedFormula::implies(
                DefinedFormula::member(x, y),
                DefinedFormula::defined_relation(DefinitionId::from_bytes([0x5a; 32]), [x, y]),
            )),
        ),
    );
    crate::codec_corpus::check(
        "defined formula",
        &[defined.encode_canonical().unwrap()],
        |bytes| {
            DefinedFormula::decode_canonical(bytes)
                .ok()?
                .encode_canonical()
                .ok()
        },
    );
    let definitions = [
        DefinitionCertificate::relation(1, DefinedFormula::equal(x, x)).unwrap(),
        DefinitionCertificate::function(1, DefinedFormula::equal(x, y)).unwrap(),
    ];
    crate::codec_corpus::check(
        "definition kinds",
        &definitions
            .iter()
            .map(DefinitionCertificate::to_canonical_bytes)
            .collect::<Vec<_>>(),
        |bytes| {
            DefinitionCertificate::from_canonical_bytes(bytes)
                .ok()
                .map(|value| value.to_canonical_bytes())
        },
    );
    let mut payloads = definitions
        .into_iter()
        .map(ArtifactPayload::Definition)
        .map(|value| value.to_canonical_bytes())
        .collect::<Vec<_>>();
    payloads.push(
        ArtifactPayload::Proof(
            ProofCertificate::new(vec![ProofStep::EqualityReflexivity { variable: x }]).unwrap(),
        )
        .to_canonical_bytes(),
    );
    crate::codec_corpus::check("artifact payload kinds", &payloads, |bytes| {
        ArtifactPayload::from_canonical_bytes(bytes)
            .ok()
            .map(|value| value.to_canonical_bytes())
    });
}

#[test]
fn definition_byte_budget_rejects_before_unknown_tag_or_body_work() {
    let over = vec![0xff; DEFINITION_MAX_BYTES + 1];
    assert!(matches!(DefinitionCertificate::from_canonical_bytes(&over),
        Err(DefinitionCertificateError::InputTooLong { actual, maximum })
        if actual == over.len() && maximum == DEFINITION_MAX_BYTES));
    // An impossible declared body must fail without allocating that body.
    assert!(
        DefinitionCertificate::from_canonical_bytes(&[0, 0, 0, 0, 1, 255, 255, 255, 255]).is_err()
    );
    assert_eq!(DEFINITION_MAX_BYTES, 9 + FORMULA_MAX_BYTES);
}

#[test]
fn defined_formula_decoder_charges_real_node_depth_byte_and_argument_bounds() {
    use naome_foundation::{FORMULA_MAX_DEPTH, FORMULA_MAX_NODES};
    let x = FreeVariable::new(0);
    let formula = DefinedFormula::implies(
        DefinedFormula::equal(x, x),
        DefinedFormula::negate(DefinedFormula::member(x, x)),
    );
    let bytes = formula.encode_canonical().unwrap();
    let (decoded, used) = DefinedFormula::decode_canonical_with_node_limit(&bytes, 4).unwrap();
    assert_eq!(used, 4);
    assert_eq!(decoded.encode_canonical().unwrap(), bytes);
    assert_eq!(
        DefinedFormula::decode_canonical_with_node_limit(&bytes, 3),
        Err(DefinedFormulaCodecError::NodeLimitExceeded { maximum: 3 })
    );
    assert_eq!(
        DefinedFormula::decode_canonical_with_node_limit(&[0xff], 0),
        Err(DefinedFormulaCodecError::NodeLimitExceeded { maximum: 0 })
    );
    let mut missing_right = vec![3];
    missing_right.extend_from_slice(&DefinedFormula::equal(x, x).encode_canonical().unwrap());
    missing_right.push(0xff);
    assert_eq!(
        DefinedFormula::decode_canonical_with_node_limit(&missing_right, 2),
        Err(DefinedFormulaCodecError::NodeLimitExceeded { maximum: 2 })
    );
    let mut deepest = vec![2; FORMULA_MAX_DEPTH as usize - 1];
    deepest.extend_from_slice(&DefinedFormula::equal(x, x).encode_canonical().unwrap());
    assert_eq!(
        DefinedFormula::decode_canonical_with_node_limit(&deepest, FORMULA_MAX_NODES)
            .unwrap()
            .1,
        FORMULA_MAX_DEPTH as usize
    );
    deepest.insert(0, 2);
    assert!(
        matches!(DefinedFormula::decode_canonical(&deepest), Err(DefinedFormulaCodecError::DepthLimitExceeded { maximum }) if maximum == FORMULA_MAX_DEPTH)
    );
    assert!(matches!(
        DefinedFormula::decode_canonical(&vec![0xff; FORMULA_MAX_BYTES + 1]),
        Err(DefinedFormulaCodecError::InputTooLong { .. })
    ));
    let mut arguments = vec![5];
    arguments.extend_from_slice(&[0x5a; 32]);
    arguments.extend_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        DefinedFormula::decode_canonical(&arguments),
        Err(DefinedFormulaCodecError::UnexpectedEnd)
    );
}
