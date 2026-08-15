use naome_checker::{
    ArtifactState as ProofState, ArtifactStateError as ProofStateError, normalize_and_check,
};
use naome_foundation::{Formula, SchemaError};
use naome_proof::{DerivationId, ProofCertificate, ProofId, StatementId};

use super::*;

const SOURCE: &str = r#"
# Presentation-only comment and indentation.
foundation = "naome:zfc"
statement = forall(x, equal(x, x))
proof:
    p0 = equality_reflexivity(x)
    p1 = generalization(p0, x)
    return p1
"#;

const SELF_EQUALITY_PROOF_ID_HEX: &str =
    "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73";
const SELF_EQUALITY_STATEMENT_ID_HEX: &str =
    "f902f799c24f064ea98bf7fa33c12c5178f1722fdfd94b223c64ea1aa9ae3d19";
const SELF_EQUALITY_DERIVATION_ID_HEX: &str =
    "59219d63c7c2353dcb6ffd1e604153143380ae6602e04215703bc0ea043243fb";
const SELF_EQUALITY_REFERENCE_PROOF_ID_HEX: &str =
    "bfd427b447e1514686cfa31b0b5aa1dd5036464cd8c5d73d0c3112cb46b0519b";
const SELF_EQUALITY_REFERENCE_PROOF_HEX: &str =
    "0000000130c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73";
const SELF_EQUALITY_PROOF_HEX: &str = "000000020600000000210000000000000000";
const PROOF_ID_EXPECTED: &str = "a 64-digit lowercase hexadecimal ProofId";

const IMPLICATION_SOURCE: &str = include_str!("../../../examples/implication-identity.nao");
const INLINED_IMPLICATION_SOURCE: &str = r#"
foundation = "naome:zfc"
statement = forall(x, implies(equal(x, x), equal(x, x)))
proof:
    p0 = simplification(equal(x, x), equal(x, x))
    p1 = simplification(
        equal(x, x),
        implies(equal(x, x), equal(x, x)),
    )
    p2 = frege(
        equal(x, x),
        implies(equal(x, x), equal(x, x)),
        equal(x, x),
    )
    p3 = modus_ponens(p1, p2)
    p4 = modus_ponens(p0, p3)
    p5 = generalization(p4, x)
    return p5
"#;
const QUANTIFIER_SOURCE: &str = include_str!("../../../examples/quantifier-instantiation.nao");
const EQUALITY_SUBSTITUTION_SOURCE: &str =
    include_str!("../../../examples/equality-substitution.nao");
const EXTENSIONALITY_SOURCE: &str = include_str!("../../../examples/extensionality.nao");
const SEPARATION_SOURCE: &str = include_str!("../../../examples/separation.nao");
const REPLACEMENT_SOURCE: &str = include_str!("../../../examples/replacement.nao");

fn proof_reference_source(proof_id: &str) -> String {
    format!(
        "foundation = \"naome:zfc\" statement = forall(x, equal(x, x)) proof: known = cite(\"{proof_id}\") return known"
    )
}

fn complete_source(statement: &str, steps: &str, result: &str) -> String {
    format!("foundation = \"naome:zfc\" statement = {statement} proof: {steps} return {result}")
}

fn checked_state(source: &str) -> (ProofState, CompiledProof) {
    let compiled = compile(source).unwrap();
    let certificate =
        ProofCertificate::from_canonical_bytes(compiled.canonical_proof_bytes()).unwrap();
    let checked = normalize_and_check(certificate).unwrap();
    let mut state = ProofState::new();
    state.register_proof(checked).unwrap();
    (state, compiled)
}

fn compile_with_proof_state(
    source: &str,
    state: &ProofState,
) -> Result<CompiledProof, CompileError> {
    match compile_with_artifact_state(source, state)? {
        CompiledArtifact::Proof(proof) => Ok(proof),
        CompiledArtifact::Definition(_) => Err(CompileError::ExpectedProof { offset: 0 }),
    }
}

fn parse_formula(source: &str, context: FormulaContext) -> Result<ParsedFormula, CompileError> {
    let mut parser = Parser::new(source);
    let formula = parser.parsed_formula(1, context)?;
    parser.end()?;
    Ok(formula)
}

fn parse_step(source: &str) -> Result<ProofStep, CompileError> {
    parse_step_with_names(source, &[])
}

fn parse_bound_step(binding: &str, step: &str) -> Result<ProofStep, CompileError> {
    let source = format!("{binding} {step}");
    let mut parser = Parser::new(&source);
    parser.formula_binding()?;
    let step = parser.proof_step()?;
    parser.end()?;
    Ok(step)
}

fn parse_step_with_names(source: &str, names: &[&'static str]) -> Result<ProofStep, CompileError> {
    let mut parser = Parser::new(source);
    for (index, name) in names.iter().copied().enumerate() {
        parser.steps.insert(
            name,
            StepBinding {
                position: u32::try_from(index).unwrap(),
                span: SourceSpan::point(0),
            },
        );
    }
    let step = parser.proof_step()?;
    parser.end()?;
    Ok(step)
}

fn assert_check_error(result: Result<CompiledProof, CompileError>, expected: CheckError) {
    match result {
        Err(CompileError::Check { source, .. }) => assert_eq!(source.as_ref(), &expected),
        other => panic!("expected checker error {expected:?}, got {other:?}"),
    }
}

fn compile_schema_step(step: &str) -> Result<CompiledProof, CompileError> {
    compile(&complete_source(
        "forall(closed, equal(closed, closed))",
        &format!("schema = {step}"),
        "schema",
    ))
}

#[test]
fn minimal_source_preserves_the_exact_checked_identity_vector() {
    let proof = compile(SOURCE).unwrap();
    assert_eq!(
        proof.statement_id(),
        StatementId::from_bytes(hex32(SELF_EQUALITY_STATEMENT_ID_HEX))
    );
    assert_eq!(
        proof.derivation_id(),
        DerivationId::from_bytes(hex32(SELF_EQUALITY_DERIVATION_ID_HEX))
    );
    assert_eq!(
        proof.proof_id(),
        ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX))
    );
    assert_eq!(
        proof.canonical_proof_bytes(),
        hex_bytes(SELF_EQUALITY_PROOF_HEX)
    );
}

#[test]
fn every_repository_example_preserves_its_checked_identities_and_bytes() {
    for (source, statement, derivation, proof, bytes) in [
        (
            SOURCE,
            SELF_EQUALITY_STATEMENT_ID_HEX,
            SELF_EQUALITY_DERIVATION_ID_HEX,
            SELF_EQUALITY_PROOF_ID_HEX,
            SELF_EQUALITY_PROOF_HEX,
        ),
        (
            IMPLICATION_SOURCE,
            "6c7296d3c7adb7ee99b71caec2e6851c31360e2811bd1335b526c7b74525a48b",
            "fd46e6233815bd4cb5188f5358b8afb852179c62b7fb512b798302b0f01fdd94",
            "dad1eccea41c54d5618a35bff0bc3b8fb52e0489017fd9a444cdae14355b6285",
            "00000006000000000b00000000000000000000000000000b0000000000000000000000000000000b0000000000000000000000000000170300000000000000000000000000000000000000000000010000000b00000000000000000000000000001703000000000000000000000000000000000000000000000000000b0000000000000000000000200000000100000002200000000000000003210000000400000000",
        ),
        (
            QUANTIFIER_SOURCE,
            SELF_EQUALITY_STATEMENT_ID_HEX,
            "a85928e52c4c2833d30640cb2eaba82602ccbc39b6afea340b5b0b8d06061972",
            "6e35a728527633573509b24fa20cb2359a14c1f93e9f6b6f1500f8650f731720",
            "0000000506000000002100000000000000000500000000000000010000000b0000000000000000000000200000000100000002210000000300000001",
        ),
        (
            EQUALITY_SUBSTITUTION_SOURCE,
            "0d6570e2a5031b6a1b3664fb990c1cdf4ff4079364ad9dd08e4f9123662c5772",
            "107a35fa6ec1677c01560c743c627a5d231315d605fa50083e18dd529a8861b5",
            "e89dcbf998af185fd368a2531e2f0ee4953cc2232ec93da38ed3e89e21cede71",
            "000000040700000000000000010000000b0100000000000000000002210000000000000002210000000100000001210000000200000000",
        ),
        (
            EXTENSIONALITY_SOURCE,
            "d5badb94fde79367c1ee93516c9260d031335c23502e3fcf36513ac768cc9db9",
            "5507c036519883b871a080036e5e9a5332784501f1982e17e4f9a363b7369b9c",
            "7db633cf3f2a73749e143c3f26a0083b17c39e8a24c8940f64471cf6b49d515d",
            "000000011000",
        ),
        (
            SEPARATION_SOURCE,
            "cdc8f561c1e6d36cb437da9cfce5f97ab9079f5985f769c02c67ab2ff803f9a3",
            "073ae5f13c159cda79b6fe31ed033eb8bb1b79ffcd21fa617adc5aea139408a6",
            "426fcca7bbf116adebfa819e0eaf7c465c0215d3b367d5446c3882b1f1a7697c",
            "00000001110000000b01000000000000000000010000000000000002000000030000000100000001",
        ),
        (
            REPLACEMENT_SOURCE,
            "4d12c8f960638ff317e561e8861808875f18dfd22910c38712e05112e26724f5",
            "72d5c8f81af4a2bcbe1eb7ed9fc1963ecbc1fedf91edf20d85f55c84051c93ec",
            "7c5a06a3e764c6b6e372334645050bd314f8a7e64c96633e3d3aff90ca2bd156",
            "00000001120000000b0000000000000000000001000000000000000100000002000000030000000400000000",
        ),
    ] {
        let compiled = compile(source).unwrap();
        assert_eq!(
            compiled.statement_id(),
            StatementId::from_bytes(hex32(statement))
        );
        assert_eq!(
            compiled.derivation_id(),
            DerivationId::from_bytes(hex32(derivation))
        );
        assert_eq!(compiled.proof_id(), ProofId::from_bytes(hex32(proof)));
        assert_eq!(compiled.canonical_proof_bytes(), hex_bytes(bytes));
    }
}

#[test]
fn formula_bindings_preserve_the_exact_inlined_checked_artifact() {
    let bound = r#"
foundation = "naome:zfc"
formulas:
    unused = equal(z, z)
    reflexive = equal(x, x)
    identity = implies(reflexive, reflexive)
statement = forall(x, identity)
proof:
    p0 = simplification(reflexive, reflexive)
    p1 = simplification(reflexive, identity)
    p2 = frege(reflexive, identity, reflexive)
    p3 = modus_ponens(p1, p2)
    p4 = modus_ponens(p0, p3)
    p5 = generalization(p4, x)
    return p5
"#;
    let baseline = compile(INLINED_IMPLICATION_SOURCE).unwrap();
    assert_eq!(compile(IMPLICATION_SOURCE).unwrap(), baseline);
    assert_eq!(compile(bound).unwrap(), baseline);

    let reordered = bound.replace(
        "    unused = equal(z, z)\n    reflexive = equal(x, x)",
        "    reflexive = equal(x, x)\n    unused = equal(z, z)",
    );
    assert_eq!(compile(&reordered).unwrap(), baseline);

    let renamed = bound
        .replace("reflexive", "r")
        .replace("identity", "i")
        .replace("unused = equal(z, z)", "other = equal(y, y)");
    assert_eq!(compile(&renamed).unwrap(), baseline);
}

#[test]
fn binding_expansion_uses_the_global_variable_namespace_and_enclosing_binders() {
    let captured = r#"
foundation = "naome:zfc"
formulas:
    reflexive = equal(x, x)
    closed = forall(x, reflexive)
statement = closed
proof:
    p0 = equality_reflexivity(x)
    p1 = generalization(p0, x)
    return p1
"#;
    assert_eq!(compile(captured).unwrap(), compile(SOURCE).unwrap());

    let independent_namespaces = r#"
foundation = "naome:zfc"
formulas:
    x = equal(x, x)
    p0 = x
statement = forall(x, p0)
proof:
    p0 = equality_reflexivity(x)
    p1 = generalization(p0, x)
    return p1
"#;
    assert_eq!(
        compile(independent_namespaces).unwrap(),
        compile(SOURCE).unwrap()
    );

    let step_position = r#"
foundation = "naome:zfc"
formulas:
    premise = equal(x, x)
statement = forall(x, premise)
proof:
    p0 = equality_reflexivity(x)
    p1 = modus_ponens(premise, p0)
    return p1
"#;
    assert!(matches!(
        compile(step_position),
        Err(CompileError::UnknownStep { name, .. }) if name == "premise"
    ));
}

#[test]
fn bindings_are_accepted_in_every_formula_bearing_proof_operand() {
    for (bound, inlined) in [
        (
            "simplification(refl, refl)",
            "simplification(equal(x, x), equal(x, x))",
        ),
        (
            "frege(refl, refl, refl)",
            "frege(equal(x, x), equal(x, x), equal(x, x))",
        ),
        (
            "classical_contraposition(refl, refl)",
            "classical_contraposition(equal(x, x), equal(x, x))",
        ),
        (
            "universal_distribution(x, refl, refl)",
            "universal_distribution(x, equal(x, x), equal(x, x))",
        ),
        ("vacuous_universal(refl)", "vacuous_universal(equal(x, x))"),
        (
            "universal_instantiation(x, x, refl)",
            "universal_instantiation(x, x, equal(x, x))",
        ),
        (
            "equality_substitution(x, x, refl)",
            "equality_substitution(x, x, equal(x, x))",
        ),
        (
            "separation(refl, x, x, x, parameters=[refl])",
            "separation(equal(x, x), x, x, x, parameters=[refl])",
        ),
        (
            "replacement(refl, x, x, x, x, x, parameters=[])",
            "replacement(equal(x, x), x, x, x, x, x, parameters=[])",
        ),
    ] {
        assert_eq!(
            parse_bound_step("refl = equal(x, x)", bound).unwrap(),
            parse_step(inlined).unwrap(),
            "binding changed {bound}"
        );
    }
}

#[test]
fn every_derived_formula_lowers_to_the_existing_primitive_structure() {
    for (derived, primitive) in [
        (
            "and_(equal(x, x), member(y, z))",
            "not_(implies(equal(x, x), not_(member(y, z))))",
        ),
        (
            "or_(equal(x, x), member(y, z))",
            "implies(not_(equal(x, x)), member(y, z))",
        ),
        (
            "iff(equal(x, x), member(y, z))",
            "not_(implies(implies(equal(x, x), member(y, z)), not_(implies(member(y, z), equal(x, x)))))",
        ),
        (
            "exists(x, member(x, set))",
            "not_(forall(x, not_(member(x, set))))",
        ),
        ("not_equal(x, y)", "not_(equal(x, y))"),
    ] {
        let derived = parse_formula(derived, FormulaContext::Statement).unwrap();
        let primitive = parse_formula(primitive, FormulaContext::Statement).unwrap();
        assert_eq!(derived.formula, primitive.formula);
        assert_eq!(derived.expanded_nodes, primitive.expanded_nodes);
        assert_eq!(derived.expanded_depth, primitive.expanded_depth);
    }
}

#[test]
fn derived_and_primitive_sources_have_exactly_the_same_checked_artifact() {
    const A: &str = "forall(x, not_equal(x, x))";
    const B: &str =
        "exists(y, and_(equal(y, y), or_(member(y, y), iff(equal(y, y), member(y, y)))))";
    const PRIMITIVE_A: &str = "forall(x, not_(equal(x, x)))";
    const PRIMITIVE_B: &str = "not_(forall(y, not_(not_(implies(equal(y, y), not_(implies(not_(member(y, y)), not_(implies(implies(equal(y, y), member(y, y)), not_(implies(member(y, y), equal(y, y))))))))))))";
    let source = |a: &str, b: &str| {
        complete_source(
            &format!("implies({a}, implies({b}, {a}))"),
            &format!("p0 = simplification({a}, {b})"),
            "p0",
        )
    };

    assert_eq!(
        parse_formula(A, FormulaContext::Statement).unwrap().formula,
        parse_formula(PRIMITIVE_A, FormulaContext::Statement)
            .unwrap()
            .formula
    );
    assert_eq!(
        parse_formula(B, FormulaContext::Statement).unwrap().formula,
        parse_formula(PRIMITIVE_B, FormulaContext::Statement)
            .unwrap()
            .formula
    );
    assert_eq!(
        compile(&source(A, B)).unwrap(),
        compile(&source(PRIMITIVE_A, PRIMITIVE_B)).unwrap()
    );
}

#[test]
fn derived_operands_retain_order_and_exists_binds_capture_free() {
    let left = parse_formula(
        "and_(equal(left, left), member(right, set))",
        FormulaContext::Certificate,
    )
    .unwrap();
    let swapped = parse_formula(
        "and_(member(right, set), equal(left, left))",
        FormulaContext::Certificate,
    )
    .unwrap();
    assert_ne!(left.formula, swapped.formula);

    let exists = parse_formula(
        "exists(x, and_(member(x, set), forall(x, member(x, x))))",
        FormulaContext::Certificate,
    )
    .unwrap();
    let x = FreeVariable::new(0);
    let set = FreeVariable::new(1);
    assert_eq!(
        exists.formula,
        DefinedFormula::exists(
            x,
            DefinedFormula::conjunction(
                DefinedFormula::member(x, set),
                DefinedFormula::for_all(x, DefinedFormula::member(x, x)),
            ),
        )
    );
}

#[test]
fn call_commas_arity_and_trailing_commas_are_exact() {
    for source in [
        "equal(x, y,)",
        "not_(equal(x, x),)",
        "implies(equal(x, x), equal(y, y),)",
        "forall(x, equal(x, x),)",
        "and_(equal(x, x), equal(y, y),)",
        "or_(equal(x, x), equal(y, y),)",
        "iff(equal(x, x), equal(y, y),)",
        "exists(x, equal(x, x),)",
        "not_equal(x, y,)",
    ] {
        assert!(
            parse_formula(source, FormulaContext::Statement).is_ok(),
            "{source}"
        );
    }

    for source in [
        "equal(x y)",
        "equal(x,, y)",
        "equal(x, y, z)",
        "equal(x, y,,)",
        "equal(x)",
        "not_()",
        "not_(equal(x, x), equal(y, y))",
        "forall(x equal(x, x))",
        "exists(x,)",
        "not_equal(x)",
    ] {
        assert!(
            matches!(
                parse_formula(source, FormulaContext::Statement),
                Err(CompileError::Syntax { .. })
            ),
            "accepted {source:?}"
        );
    }

    for source in ["and_(broken, equal(x, x))", "and_(equal(x, x), broken)"] {
        assert!(matches!(
            parse_formula(source, FormulaContext::Statement),
            Err(CompileError::UnknownFormulaBinding { name, .. }) if name == "broken"
        ));
    }

    for (source, expected) in [
        ("or_(equal(x, x))", "`,`"),
        ("iff(equal(x, x), equal(y, y), extra)", "`)`"),
        ("exists(1bad, equal(x, x))", "a name"),
        ("not_equal(x)", "`,`"),
    ] {
        assert!(matches!(
            parse_formula(source, FormulaContext::Statement),
            Err(CompileError::Syntax {
                expected: actual,
                ..
            }) if actual == expected
        ));
    }
}

#[test]
fn formula_and_rule_spellings_have_one_python_shaped_form() {
    for source in [
        "(equal x x)",
        "not(equal(x, x))",
        "and(equal(x, x), equal(y, y))",
        "or(equal(x, x), equal(y, y))",
        "not-equal(x, y)",
        "not_equal(x-y, z)",
    ] {
        assert!(parse_formula(source, FormulaContext::Statement).is_err());
    }

    for source in [
        "(equality-reflexivity x)",
        "equality-reflexivity(x)",
        "proof_reference(\"c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73\")",
        "cite(c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73)",
    ] {
        assert!(matches!(
            parse_step(source),
            Err(CompileError::Syntax { .. })
        ));
    }
}

#[test]
fn every_proof_call_maps_to_the_existing_protocol_step() {
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let z = FreeVariable::new(2);

    assert_eq!(
        parse_step("simplification(equal(x, x), member(y, z))").unwrap(),
        ProofStep::Simplification {
            antecedent: Formula::equal(x, x).into(),
            consequent: Formula::member(y, z).into(),
        }
    );
    assert_eq!(
        parse_step("frege(equal(x, x), member(y, z), equal(z, y))").unwrap(),
        ProofStep::Frege {
            first: Formula::equal(x, x).into(),
            second: Formula::member(y, z).into(),
            third: Formula::equal(z, y).into(),
        }
    );
    assert_eq!(
        parse_step("classical_contraposition(equal(x, x), member(y, z))").unwrap(),
        ProofStep::ClassicalContraposition {
            antecedent: Formula::equal(x, x).into(),
            consequent: Formula::member(y, z).into(),
        }
    );
    assert_eq!(
        parse_step("universal_distribution(x, equal(x, x), member(y, z))").unwrap(),
        ProofStep::UniversalDistribution {
            variable: x,
            antecedent: Formula::equal(x, x).into(),
            consequent: Formula::member(y, z).into(),
        }
    );
    assert_eq!(
        parse_step("vacuous_universal(equal(x, x))").unwrap(),
        ProofStep::VacuousUniversal {
            formula: Formula::equal(x, x).into(),
        }
    );
    assert_eq!(
        parse_step("universal_instantiation(x, y, member(x, z))").unwrap(),
        ProofStep::UniversalInstantiation {
            variable: x,
            replacement: y,
            body: Formula::member(x, z).into(),
        }
    );
    assert_eq!(
        parse_step_with_names("modus_ponens(p0, p1)", &["p0", "p1"]).unwrap(),
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        }
    );
    assert_eq!(
        parse_step("equality_reflexivity(x)").unwrap(),
        ProofStep::EqualityReflexivity { variable: x }
    );
    assert_eq!(
        parse_step("equality_substitution(x, y, member(x, z))").unwrap(),
        ProofStep::EqualitySubstitution {
            from: x,
            to: y,
            body: Formula::member(x, z).into(),
        }
    );
    assert_eq!(
        parse_step(
            "separation(member(element, filter), element, source, result, parameters=[filter])"
        )
        .unwrap(),
        ProofStep::Separation(ProofSeparation {
            predicate: Formula::member(FreeVariable::new(0), FreeVariable::new(1)).into(),
            element: FreeVariable::new(0),
            source: FreeVariable::new(2),
            result: FreeVariable::new(3),
            parameters: vec![FreeVariable::new(1)],
        })
    );
    assert_eq!(
        parse_step(
            "replacement(equal(input, output), input, output, witness, source, result, parameters=[])"
        )
        .unwrap(),
        ProofStep::Replacement(ProofReplacement {
            predicate: Formula::equal(FreeVariable::new(0), FreeVariable::new(1)).into(),
            input: FreeVariable::new(0),
            output: FreeVariable::new(1),
            uniqueness_witness: FreeVariable::new(2),
            source: FreeVariable::new(3),
            result: FreeVariable::new(4),
            parameters: Vec::new(),
        })
    );
    assert_eq!(
        parse_step(&format!("cite(\"{SELF_EQUALITY_PROOF_ID_HEX}\")")).unwrap(),
        ProofStep::ProofReference {
            proof_id: ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX)),
        }
    );
    assert_eq!(
        parse_step_with_names("generalization(p0, x)", &["p0"]).unwrap(),
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        }
    );
}

#[test]
fn equality_substitution_preserves_roles_and_avoids_capture_under_a_binder() {
    let source = r#"
foundation = "naome:zfc"
statement = forall(x, forall(y,
    implies(equal(x, y),
        implies(forall(bound, member(x, bound)),
            forall(bound, member(y, bound))))))
proof:
    substitute = equality_substitution(x, y, forall(y, member(x, y)))
    for_y = generalization(substitute, y)
    for_x = generalization(for_y, x)
    return for_x
"#;
    let proof = compile(source).unwrap();
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let decoded = ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps()[0],
        ProofStep::EqualitySubstitution {
            from: x,
            to: y,
            body: Formula::for_all(y, Formula::member(x, y)).into(),
        }
    );

    for mutated in [
        source.replace(
            "equality_substitution(x, y, forall(y, member(x, y)))",
            "equality_substitution(y, x, forall(y, member(x, y)))",
        ),
        source.replace(
            "equality_substitution(x, y, forall(y, member(x, y)))",
            "equality_substitution(x, y, forall(y, member(y, y)))",
        ),
    ] {
        assert!(matches!(
            compile(&mutated),
            Err(CompileError::StatementMismatch { .. })
        ));
    }
}

#[test]
fn every_fixed_zfc_axiom_uses_one_quoted_snake_case_selector() {
    for (selector, expected) in [
        ("extensionality", ZfcAxiom::Extensionality),
        ("pairing", ZfcAxiom::Pairing),
        ("union", ZfcAxiom::Union),
        ("power_set", ZfcAxiom::PowerSet),
        ("infinity", ZfcAxiom::Infinity),
        ("foundation", ZfcAxiom::Foundation),
        ("choice", ZfcAxiom::Choice),
    ] {
        assert_eq!(
            parse_step(&format!("zfc_axiom(\"{selector}\")")).unwrap(),
            ProofStep::ZfcAxiom(expected)
        );
        assert_eq!(
            parse_step(&format!("zfc_axiom(\"{selector}\",)")).unwrap(),
            ProofStep::ZfcAxiom(expected)
        );
    }

    for source in [
        "zfc_axiom(extensionality)",
        "zfc_axiom(\"power-set\")",
        "zfc-axiom(\"extensionality\")",
        "zfc_axiom(\"Extensionality\")",
        "zfc_axiom(\"unsupported\")",
        "zfc_axiom(\"extensionality\", \"pairing\")",
    ] {
        assert!(matches!(
            parse_step(source),
            Err(CompileError::Syntax { .. })
        ));
    }
}

#[test]
fn proof_call_arity_and_commas_are_exact() {
    for source in [
        "simplification(equal(x, x) equal(y, y))",
        "simplification(equal(x, x),)",
        "frege(equal(x, x), equal(y, y))",
        "universal_distribution(x, equal(x, x) equal(y, y))",
        "universal_instantiation(x, y)",
        "equality_substitution(x, y, member(x, y), extra)",
        "generalization(p0 x)",
        "modus_ponens(p0,, p1)",
        "equality_reflexivity(x, y)",
        "cite()",
    ] {
        let names = ["p0", "p1"];
        assert!(
            matches!(
                parse_step_with_names(source, &names),
                Err(CompileError::Syntax { .. })
            ),
            "accepted {source:?}"
        );
    }

    for source in [
        "simplification(equal(x, x), equal(y, y),)",
        "frege(equal(x, x), equal(y, y), equal(z, z),)",
        "classical_contraposition(equal(x, x), equal(y, y),)",
        "universal_distribution(x, equal(x, x), equal(y, y),)",
        "vacuous_universal(equal(x, x),)",
        "universal_instantiation(x, y, equal(x, x),)",
        "modus_ponens(p0, p1,)",
        "equality_reflexivity(x,)",
        "equality_substitution(x, y, equal(x, x),)",
        "generalization(p0, x,)",
    ] {
        let names = ["p0", "p1"];
        assert!(parse_step_with_names(source, &names).is_ok(), "{source}");
    }
}

#[test]
fn schema_parameter_lists_are_named_comma_delimited_and_trailing_comma_tolerant() {
    for source in [
        "separation(equal(element, element), element, source, result, parameters=[]) ",
        "separation(equal(element, element), element, source, result, parameters=[first])",
        "separation(equal(element, element), element, source, result, parameters=[first, second,],)",
        "replacement(equal(input, output), input, output, witness, source, result, parameters=[])",
        "replacement(equal(input, output), input, output, witness, source, result, parameters=[first, second],)",
    ] {
        assert!(parse_step(source).is_ok(), "{source}");
    }

    for source in [
        "separation(equal(element, element), element, source, result)",
        "separation(equal(element, element), element, source, result, parameters())",
        "separation(equal(element, element), element, source, result, parameters=())",
        "separation(equal(element, element), element, source, result, parameter=[])",
        "separation(equal(element, element), element, source, result, parameters=[first second])",
        "separation(equal(element, element), element, source, result, parameters=[,])",
        "separation(equal(element, element), element, source, result, parameters=[first,, second])",
        "separation(equal(element, element), element, source, result, parameters=[], extra)",
        "replacement(equal(input, output), input, output, witness, source, result, extra, parameters=[])",
    ] {
        assert!(
            matches!(parse_step(source), Err(CompileError::Syntax { .. })),
            "accepted {source:?}"
        );
    }

    let separation = parse_step(
        "separation(implies(member(element, source), equal(first, second)), element, source, result, parameters=[first, second])",
    )
    .unwrap();
    assert_eq!(
        separation,
        ProofStep::Separation(ProofSeparation {
            predicate: Formula::implies(
                Formula::member(FreeVariable::new(0), FreeVariable::new(1)),
                Formula::equal(FreeVariable::new(2), FreeVariable::new(3)),
            )
            .into(),
            element: FreeVariable::new(0),
            source: FreeVariable::new(1),
            result: FreeVariable::new(4),
            parameters: vec![FreeVariable::new(2), FreeVariable::new(3)],
        })
    );

    let replacement = parse_step(
        "replacement(implies(equal(input, output), member(input, parameter)), input, output, witness, source, result, parameters=[parameter, unused])",
    )
    .unwrap();
    assert_eq!(
        replacement,
        ProofStep::Replacement(ProofReplacement {
            predicate: Formula::implies(
                Formula::equal(FreeVariable::new(0), FreeVariable::new(1)),
                Formula::member(FreeVariable::new(0), FreeVariable::new(2)),
            )
            .into(),
            input: FreeVariable::new(0),
            output: FreeVariable::new(1),
            uniqueness_witness: FreeVariable::new(3),
            source: FreeVariable::new(4),
            result: FreeVariable::new(5),
            parameters: vec![FreeVariable::new(2), FreeVariable::new(6)],
        })
    );

    let statement_id = |parameters| {
        let step = parse_step(&format!(
            "separation(equal(first, second), element, source, result, parameters=[{parameters}])"
        ))
        .unwrap();
        normalize_and_check(ProofCertificate::new(vec![step]).unwrap())
            .unwrap()
            .statement_id()
    };
    assert_ne!(statement_id("first, second"), statement_id("second, first"));
}

#[test]
fn reachable_schema_errors_remain_checker_owned_and_unreachable_ones_are_pruned() {
    const INVALID: &str =
        "invalid = separation(equal(result, result), element, source, result, parameters=[])";
    let reachable = complete_source("forall(x, equal(x, x))", INVALID, "invalid");
    assert_check_error(
        compile(&reachable),
        CheckError::Schema {
            step: 0,
            source: SchemaError::ForbiddenPredicateVariable(FreeVariable::new(0)),
        },
    );

    let unreachable = SOURCE.replace(
        "p0 = equality_reflexivity(x)",
        &format!("{INVALID} p0 = equality_reflexivity(x)"),
    );
    assert_eq!(compile(&unreachable).unwrap(), compile(SOURCE).unwrap());
}

#[test]
fn combined_schema_errors_follow_foundation_precedence_after_lowering() {
    for (step, expected) in [
        (
            "separation(equal(result, result), shared, shared, result, parameters=[shared, shared])",
            SchemaError::RoleVariableCollision(FreeVariable::new(1)),
        ),
        (
            "separation(equal(result, result), element, source, result, parameters=[source, source])",
            SchemaError::ParameterCollidesWithRole(FreeVariable::new(2)),
        ),
        (
            "separation(equal(result, result), element, source, result, parameters=[parameter, parameter])",
            SchemaError::DuplicateParameter(FreeVariable::new(3)),
        ),
        (
            "separation(implies(equal(result, result), equal(undeclared, undeclared)), element, source, result, parameters=[])",
            SchemaError::ForbiddenPredicateVariable(FreeVariable::new(0)),
        ),
        (
            "separation(implies(equal(undeclared, undeclared), equal(result, result)), element, source, result, parameters=[])",
            SchemaError::UndeclaredPredicateVariable(FreeVariable::new(0)),
        ),
    ] {
        assert_check_error(
            compile_schema_step(step),
            CheckError::Schema {
                step: 0,
                source: expected,
            },
        );
    }
}

#[test]
fn source_shell_is_one_clean_prerelease_replacement() {
    const LEGACY: &str = r#"
foundation "naome:zfc";
theorem equality_is_reflexive {
  statement (forall x (equal x x));
  proof {
    step p0 = (equality-reflexivity x);
    step p1 = (generalization p0 x);
    result p1;
  }
}
"#;
    assert!(matches!(compile(LEGACY), Err(CompileError::Syntax { .. })));

    for source in [
        SOURCE.replace("foundation =", "foundation"),
        SOURCE.replace("statement =", "statement:"),
        SOURCE.replace("proof:", "proof"),
        SOURCE.replace("return p1", "result p1"),
        SOURCE.replace("return p1", "return p1;"),
        SOURCE.replace("p0 =", "step p0 ="),
        SOURCE.replace("equality_reflexivity", "equality-reflexivity"),
    ] {
        assert!(matches!(compile(&source), Err(CompileError::Syntax { .. })));
    }
}

#[test]
fn indentation_comments_and_python_identifiers_are_presentation_only() {
    let compact = "foundation = \"naome:zfc\" statement = forall(x,equal(x,x)) proof: P0 = equality_reflexivity(x) P1 = generalization(P0,x) return P1";
    assert_eq!(compile(compact).unwrap(), compile(SOURCE).unwrap());

    let irregular = r#"
foundation	=	"naome:zfc"
statement = forall(
 x,
 equal(x, x), # trailing formula comment
)
proof:
          _p0 = equality_reflexivity(x,) # arbitrary indentation
	_p1 = generalization(_p0, x,)
return _p1 # EOF comment"#;
    assert_eq!(compile(irregular).unwrap(), compile(SOURCE).unwrap());

    for source in [
        SOURCE.replace("p0 =", "p-0 ="),
        SOURCE.replace("equal(x, x)", "equal(x-y, x-y)"),
        SOURCE.replace("p0 =", "0p ="),
    ] {
        assert!(matches!(compile(&source), Err(CompileError::Syntax { .. })));
    }
}

#[test]
fn duplicate_unknown_forward_and_nonfinal_steps_fail_at_their_source_offsets() {
    let duplicate = SOURCE.replace("p1 = generalization(p0, x)", "p0 = generalization(p0, x)");
    let duplicate_offset = duplicate.rfind("p0 =").unwrap();
    assert_eq!(
        compile(&duplicate),
        Err(CompileError::DuplicateStep {
            offset: duplicate_offset,
            name: "p0".to_owned(),
        })
    );

    let unknown = SOURCE.replace("generalization(p0, x)", "generalization(missing, x)");
    let unknown_offset = unknown.find("missing").unwrap();
    assert_eq!(
        compile(&unknown),
        Err(CompileError::UnknownStep {
            offset: unknown_offset,
            name: "missing".to_owned(),
        })
    );

    let forward = SOURCE.replace("p0 = equality_reflexivity(x)", "p0 = generalization(p1, x)");
    assert!(matches!(
        compile(&forward),
        Err(CompileError::UnknownStep { name, .. }) if name == "p1"
    ));

    let nonfinal = SOURCE.replace("return p1", "return p0");
    assert!(matches!(
        compile(&nonfinal),
        Err(CompileError::ReturnNotFinal { .. })
    ));
}

#[test]
fn formula_binding_block_is_nonempty_unique_and_backward_only() {
    let source = |bindings: &str, statement: &str| {
        format!(
            "foundation = \"naome:zfc\" formulas: {bindings} statement = {statement} proof: p0 = equality_reflexivity(x) p1 = generalization(p0, x) return p1"
        )
    };

    let empty = source("", "forall(x, equal(x, x))");
    assert_eq!(
        compile(&empty),
        Err(CompileError::Syntax {
            offset: empty.find("statement").unwrap(),
            expected: "at least one formula binding",
        })
    );

    let repeated_block = source(
        "fact = equal(x, x) formulas: other = equal(x, x)",
        "forall(x, fact)",
    );
    assert_eq!(
        compile(&repeated_block),
        Err(CompileError::Syntax {
            offset: repeated_block.rfind("formulas:").unwrap(),
            expected: "a non-reserved formula binding name",
        })
    );

    let duplicate = source("fact = equal(x, x) fact = unsupported(", "forall(x, fact)");
    let duplicate_offset = duplicate.rfind("fact =").unwrap();
    assert_eq!(
        compile(&duplicate),
        Err(CompileError::DuplicateFormulaBinding {
            offset: duplicate_offset,
            name: "fact".to_owned(),
        })
    );

    for bindings in ["fact = fact", "fact = later later = equal(x, x)"] {
        let invalid = source(bindings, "forall(x, equal(x, x))");
        let reference = if bindings == "fact = fact" {
            invalid.find("= fact").unwrap() + 2
        } else {
            invalid.find("= later").unwrap() + 2
        };
        let expected_name = if bindings == "fact = fact" {
            "fact"
        } else {
            "later"
        };
        assert_eq!(
            compile(&invalid),
            Err(CompileError::UnknownFormulaBinding {
                offset: reference,
                name: expected_name.to_owned(),
            })
        );
    }

    let unknown = source("fact = equal(x, x)", "forall(x, missing)");
    assert_eq!(
        compile(&unknown),
        Err(CompileError::UnknownFormulaBinding {
            offset: unknown.find("missing").unwrap(),
            name: "missing".to_owned(),
        })
    );
}

#[test]
fn fixed_names_and_call_shape_cannot_be_reinterpreted_as_bindings() {
    const RESERVED: &[&str] = &[
        "foundation",
        "formulas",
        "statement",
        "proof",
        "return",
        "parameters",
        "equal",
        "member",
        "not_",
        "implies",
        "forall",
        "and_",
        "or_",
        "iff",
        "exists",
        "not_equal",
        "simplification",
        "frege",
        "classical_contraposition",
        "universal_distribution",
        "vacuous_universal",
        "universal_instantiation",
        "modus_ponens",
        "equality_reflexivity",
        "equality_substitution",
        "zfc_axiom",
        "separation",
        "replacement",
        "cite",
        "generalization",
    ];

    for name in RESERVED {
        let source = format!(
            "foundation = \"naome:zfc\" formulas: {name} = equal(x, x) statement = forall(x, equal(x, x)) proof: p0 = equality_reflexivity(x) p1 = generalization(p0, x) return p1"
        );
        assert!(
            matches!(compile(&source), Err(CompileError::Syntax { .. })),
            "accepted reserved binding {name}"
        );
    }

    for bare in ["equal", "return", "simplification"] {
        let source = complete_source(
            &format!("forall(x, {bare})"),
            "p0 = equality_reflexivity(x) p1 = generalization(p0, x)",
            "p1",
        );
        assert!(matches!(compile(&source), Err(CompileError::Syntax { .. })));
    }

    let unknown_call = complete_source(
        "forall(x, missing())",
        "p0 = equality_reflexivity(x) p1 = generalization(p0, x)",
        "p1",
    );
    assert!(matches!(
        compile(&unknown_call),
        Err(CompileError::UnknownDefinitionAlias { name, .. }) if name == "missing"
    ));

    let unknown_bare = complete_source(
        "forall(x, missing)",
        "p0 = equality_reflexivity(x) p1 = generalization(p0, x)",
        "p1",
    );
    assert!(matches!(
        compile(&unknown_bare),
        Err(CompileError::UnknownFormulaBinding { name, .. }) if name == "missing"
    ));

    let binding_as_axiom_selector = r#"
foundation = "naome:zfc"
formulas:
    selector = equal(x, x)
statement = forall(x, equal(x, x))
proof:
    p0 = zfc_axiom(selector)
    return p0
"#;
    assert!(matches!(
        compile(binding_as_axiom_selector),
        Err(CompileError::Syntax {
            expected: "a quoted ZFC axiom selector",
            ..
        })
    ));
}

#[test]
fn formula_binding_failures_keep_source_precedence_and_bounded_full_name_spans() {
    let wrong_foundation = "foundation = \"wrong\" formulas: fact = missing statement = missing";
    assert!(matches!(
        compile(wrong_foundation),
        Err(CompileError::FoundationMismatch { .. })
    ));

    let malformed_block = SOURCE.replacen(
        "statement =",
        "formulas = fact = equal(x, x) statement =",
        1,
    );
    assert!(matches!(
        compile(&malformed_block),
        Err(CompileError::Syntax {
            expected: "`:`",
            ..
        })
    ));

    let long_name = "n".repeat(DIAGNOSTIC_NAME_MAX_SCALARS + 32);
    let source = format!(
        "foundation = \"naome:zfc\" formulas: {long_name} = equal(x, x) {long_name} = equal(x, x) statement = forall(x, equal(x, x)) proof: p0 = equality_reflexivity(x) p1 = generalization(p0, x) return p1"
    );
    let offset = source.rfind(&long_name).unwrap();
    let error = compile(&source).unwrap_err();
    assert_eq!(
        error,
        CompileError::DuplicateFormulaBinding {
            offset,
            name: long_name.clone(),
        }
    );
    let diagnostic = error.diagnostic(&source);
    let span = diagnostic.primary_span().unwrap();
    assert_eq!(&source[span.start()..span.end()], long_name);
    assert_eq!(diagnostic.code(), DiagnosticCode::DuplicateFormulaBinding);
    assert_eq!(
        diagnostic.message(),
        format!(
            "duplicate formula binding \"{}...\"",
            "n".repeat(DIAGNOSTIC_NAME_MAX_SCALARS)
        )
    );

    let unknown_source = format!(
        "foundation = \"naome:zfc\" formulas: fact = equal(x, x) statement = forall(x, {long_name}) proof: p0 = equality_reflexivity(x) p1 = generalization(p0, x) return p1"
    );
    let offset = unknown_source.find(&long_name).unwrap();
    let error = compile(&unknown_source).unwrap_err();
    assert_eq!(
        error,
        CompileError::UnknownFormulaBinding {
            offset,
            name: long_name.clone(),
        }
    );
    let diagnostic = error.diagnostic(&unknown_source);
    let span = diagnostic.primary_span().unwrap();
    assert_eq!(&unknown_source[span.start()..span.end()], long_name);
    assert_eq!(diagnostic.code(), DiagnosticCode::UnknownFormulaBinding);
    assert_eq!(
        diagnostic.message(),
        format!(
            "unknown or forward formula binding \"{}...\"",
            "n".repeat(DIAGNOSTIC_NAME_MAX_SCALARS)
        )
    );
}

#[test]
fn complete_parsing_precedes_checking_and_statement_comparison() {
    let trailing = format!("{SOURCE} trailing");
    assert!(matches!(
        compile(&trailing),
        Err(CompileError::Syntax {
            expected: "end of source",
            ..
        })
    ));

    let open = complete_source("equal(x, x)", "p0 = equality_reflexivity(x)", "p0");
    assert!(matches!(
        compile(&open),
        Err(CompileError::Check { source, .. })
            if matches!(source.as_ref(), CheckError::OpenConclusion { .. })
    ));

    let mismatch = SOURCE.replace("forall(x, equal(x, x))", "forall(x, member(x, x))");
    assert!(matches!(
        compile(&mismatch),
        Err(CompileError::StatementMismatch { .. })
    ));

    let invalid_mp = IMPLICATION_SOURCE.replace("modus_ponens(p1, p2)", "modus_ponens(p2, p1)");
    assert!(matches!(
        compile(&invalid_mp),
        Err(CompileError::Check { source, .. })
            if matches!(source.as_ref(), CheckError::Logic { .. })
    ));
}

#[test]
fn citation_lowers_to_the_exact_checked_identity_without_mutating_state() {
    let (state, direct) = checked_state(SOURCE);
    let reference =
        compile_with_proof_state(&proof_reference_source(SELF_EQUALITY_PROOF_ID_HEX), &state)
            .unwrap();

    assert_eq!(reference.statement_id(), direct.statement_id());
    assert_eq!(reference.derivation_id(), direct.derivation_id());
    assert_eq!(
        reference.proof_id(),
        ProofId::from_bytes(hex32(SELF_EQUALITY_REFERENCE_PROOF_ID_HEX))
    );
    assert_eq!(
        reference.canonical_proof_bytes(),
        hex_bytes(SELF_EQUALITY_REFERENCE_PROOF_HEX)
    );
    let decoded =
        ProofCertificate::from_canonical_bytes(reference.canonical_proof_bytes()).unwrap();
    assert_eq!(
        decoded.steps(),
        &[ProofStep::ProofReference {
            proof_id: ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX)),
        }]
    );
    assert!(state.contains_proof(ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX))));
    assert!(!state.contains_proof(reference.proof_id()));
}

#[test]
fn formula_bindings_do_not_change_citation_identity_or_reference_authority() {
    let (state, _) = checked_state(SOURCE);
    let inlined = proof_reference_source(SELF_EQUALITY_PROOF_ID_HEX);
    let bound = format!(
        "foundation = \"naome:zfc\" formulas: reflexive = equal(x, x) closed = forall(x, reflexive) statement = closed proof: known = cite(\"{SELF_EQUALITY_PROOF_ID_HEX}\") return known"
    );
    assert_eq!(
        compile_with_proof_state(&bound, &state).unwrap(),
        compile_with_proof_state(&inlined, &state).unwrap()
    );
    assert_check_error(
        compile(&bound),
        CheckError::UnknownProofReference {
            step: 0,
            proof_id: ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX)),
        },
    );

    let binding_as_id = "foundation = \"naome:zfc\" formulas: dependency = forall(x, equal(x, x)) statement = dependency proof: known = cite(dependency) return known";
    assert!(matches!(
        compile(binding_as_id),
        Err(CompileError::Syntax {
            expected: PROOF_ID_EXPECTED,
            ..
        })
    ));
}

#[test]
fn citation_requires_the_exact_proof_id_in_the_supplied_state() {
    let reference = proof_reference_source(SELF_EQUALITY_PROOF_ID_HEX);
    let expected = || CheckError::UnknownProofReference {
        step: 0,
        proof_id: ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX)),
    };
    assert_check_error(compile(&reference), expected());
    assert_check_error(
        compile_with_proof_state(&reference, &ProofState::new()),
        expected(),
    );

    let (wrong_statement_state, _) = checked_state(EXTENSIONALITY_SOURCE);
    assert_check_error(
        compile_with_proof_state(&reference, &wrong_statement_state),
        expected(),
    );
    let (same_statement_state, _) = checked_state(QUANTIFIER_SOURCE);
    assert_check_error(
        compile_with_proof_state(&reference, &same_statement_state),
        expected(),
    );
    let (exact_state, _) = checked_state(SOURCE);
    assert!(compile_with_proof_state(&reference, &exact_state).is_ok());
}

#[test]
fn citation_is_identity_neutral_only_for_presentation_changes() {
    let (state, _) = checked_state(SOURCE);
    let baseline =
        compile_with_proof_state(&proof_reference_source(SELF_EQUALITY_PROOF_ID_HEX), &state)
            .unwrap();
    let renamed = format!(
        "# presentation only\nfoundation = \"naome:zfc\" statement = forall(value, equal(value, value)) proof: imported = cite(\"{SELF_EQUALITY_PROOF_ID_HEX}\") return imported"
    );
    assert_eq!(
        compile_with_proof_state(&renamed, &state).unwrap(),
        baseline
    );

    for alias in [
        SELF_EQUALITY_STATEMENT_ID_HEX,
        SELF_EQUALITY_DERIVATION_ID_HEX,
    ] {
        let alias_id = ProofId::from_bytes(hex32(alias));
        assert_check_error(
            compile_with_proof_state(&proof_reference_source(alias), &state),
            CheckError::UnknownProofReference {
                step: 0,
                proof_id: alias_id,
            },
        );
    }

    let certificate =
        ProofCertificate::from_canonical_bytes(baseline.canonical_proof_bytes()).unwrap();
    let checked = naome_checker::normalize_and_check_with_state(certificate, &state).unwrap();
    let alias_id = checked.proof_id();
    assert_eq!(
        ProofState::new().register_proof(checked),
        Err(ProofStateError::MissingProofDependency {
            proof_id: ProofId::from_bytes(hex32(SELF_EQUALITY_PROOF_ID_HEX)),
        })
    );

    let certificate =
        ProofCertificate::from_canonical_bytes(baseline.canonical_proof_bytes()).unwrap();
    let checked = naome_checker::normalize_and_check_with_state(certificate, &state).unwrap();
    let mut populated = state;
    assert_eq!(
        populated.register_proof(checked),
        Err(ProofStateError::DuplicateDerivation {
            derivation_id: DerivationId::from_bytes(hex32(SELF_EQUALITY_DERIVATION_ID_HEX)),
        })
    );
    assert!(!populated.contains_proof(alias_id));
}

#[test]
fn unreachable_citations_are_parsed_then_pruned_before_resolution() {
    let unknown = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let unreachable = SOURCE.replace(
        "p0 = equality_reflexivity(x)",
        &format!("unused = cite(\"{unknown}\") p0 = equality_reflexivity(x)"),
    );
    assert_eq!(compile(&unreachable).unwrap(), compile(SOURCE).unwrap());

    let malformed = unreachable.replace(unknown, &unknown[..63]);
    let content_offset = malformed.find(&unknown[..63]).unwrap();
    assert_eq!(
        compile(&malformed),
        Err(CompileError::Syntax {
            offset: content_offset,
            expected: PROOF_ID_EXPECTED,
        })
    );
}

#[test]
fn citation_hex_and_quotes_are_exact_with_precise_byte_offsets() {
    let valid = proof_reference_source(SELF_EQUALITY_PROOF_ID_HEX);
    let content_offset = valid.find(SELF_EQUALITY_PROOF_ID_HEX).unwrap();
    assert!(matches!(
        parse_step(&format!(
            "cite( # before\n \"{SELF_EQUALITY_PROOF_ID_HEX}\" # after\n,)"
        )),
        Ok(ProofStep::ProofReference { .. })
    ));

    for malformed in [
        &SELF_EQUALITY_PROOF_ID_HEX[..63],
        "0x17c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73",
        "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e7g",
        "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e7-",
        "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e7_",
        "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e7é",
    ] {
        let source = proof_reference_source(malformed);
        let start = source.find(malformed).unwrap();
        let first_invalid = malformed
            .bytes()
            .position(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte));
        let expected_offset = start + first_invalid.unwrap_or(0);
        assert_eq!(
            compile(&source),
            Err(CompileError::Syntax {
                offset: expected_offset,
                expected: PROOF_ID_EXPECTED,
            }),
            "misreported {malformed:?}"
        );
    }

    for (index, _) in SELF_EQUALITY_PROOF_ID_HEX
        .bytes()
        .enumerate()
        .filter(|(_, byte)| byte.is_ascii_alphabetic())
    {
        let mut uppercase = SELF_EQUALITY_PROOF_ID_HEX.as_bytes().to_vec();
        uppercase[index].make_ascii_uppercase();
        let uppercase = String::from_utf8(uppercase).unwrap();
        let source = proof_reference_source(&uppercase);
        assert_eq!(
            compile(&source),
            Err(CompileError::Syntax {
                offset: content_offset + index,
                expected: PROOF_ID_EXPECTED,
            })
        );
    }

    let overlong = format!("{SELF_EQUALITY_PROOF_ID_HEX}0");
    let source = proof_reference_source(&overlong);
    assert_eq!(
        compile(&source),
        Err(CompileError::Syntax {
            offset: content_offset + 64,
            expected: "a closing quote after the ProofId",
        })
    );
}

#[test]
fn derived_formula_node_and_depth_limits_apply_to_expanded_primitives() {
    const IFF: &str = "iff(equal(x, x), equal(y, y))";
    let expanded_nodes = 9;
    for (context, maximum) in [
        (FormulaContext::Binding, FORMULA_BINDING_MAX_NODES),
        (FormulaContext::Statement, FORMULA_MAX_NODES),
        (FormulaContext::Certificate, CERTIFICATE_MAX_FORMULA_NODES),
    ] {
        let mut parser = Parser::new(IFF);
        match context {
            FormulaContext::Binding => {
                parser.formula_binding_nodes = maximum - expanded_nodes;
            }
            FormulaContext::Statement => parser.statement_nodes = maximum - expanded_nodes,
            FormulaContext::Certificate => {
                parser.certificate_formula_nodes = maximum - expanded_nodes;
            }
        }
        let parsed = parser.parsed_formula(1, context).unwrap();
        assert_eq!(parsed.expanded_nodes as usize, expanded_nodes);
        assert_eq!(
            match context {
                FormulaContext::Binding => parser.formula_binding_nodes,
                FormulaContext::Statement => parser.statement_nodes,
                FormulaContext::Certificate => parser.certificate_formula_nodes,
            },
            maximum
        );

        let mut parser = Parser::new(IFF);
        match context {
            FormulaContext::Binding => {
                parser.formula_binding_nodes = maximum - expanded_nodes + 1;
            }
            FormulaContext::Statement => parser.statement_nodes = maximum - expanded_nodes + 1,
            FormulaContext::Certificate => {
                parser.certificate_formula_nodes = maximum - expanded_nodes + 1;
            }
        }
        assert!(match (context, parser.parsed_formula(1, context)) {
            (
                FormulaContext::Binding,
                Err(CompileError::FormulaBindingNodeLimitExceeded { maximum, .. }),
            ) => maximum == FORMULA_BINDING_MAX_NODES,
            (
                FormulaContext::Statement,
                Err(CompileError::Statement {
                    source: FormulaCodecError::NodeLimitExceeded { maximum },
                    ..
                }),
            ) => maximum == FORMULA_MAX_NODES,
            (
                FormulaContext::Certificate,
                Err(CompileError::Certificate {
                    source: ProofCertificateError::FormulaNodeLimitExceeded { maximum },
                    ..
                }),
            ) => maximum == CERTIFICATE_MAX_FORMULA_NODES,
            _ => false,
        });
    }

    let wrap = |count: u32, body: &str| {
        format!(
            "{}{}{}",
            "not_(".repeat(count as usize),
            body,
            ")".repeat(count as usize)
        )
    };
    assert!(parse_formula(&wrap(FORMULA_MAX_DEPTH - 5, IFF), FormulaContext::Statement).is_ok());
    let too_deep = wrap(FORMULA_MAX_DEPTH - 4, IFF);
    let iff_offset = too_deep.find("iff").unwrap();
    assert!(matches!(
        parse_formula(&too_deep, FormulaContext::Statement),
        Err(CompileError::FormulaDepthLimitExceeded { offset, maximum })
            if offset == iff_offset && maximum == FORMULA_MAX_DEPTH
    ));

    let exact_default_stack_boundary = wrap(FORMULA_MAX_DEPTH - 1, "equal(x, x)");
    assert!(parse_formula(&exact_default_stack_boundary, FormulaContext::Statement).is_ok());
    let over_default_stack_boundary = wrap(FORMULA_MAX_DEPTH, "equal(x, x)");
    let terminal_offset = over_default_stack_boundary.find("equal").unwrap();
    assert!(matches!(
        parse_formula(
            &over_default_stack_boundary,
            FormulaContext::Statement
        ),
        Err(CompileError::FormulaDepthLimitExceeded { offset, maximum })
            if offset == terminal_offset && maximum == FORMULA_MAX_DEPTH
    ));
}

#[test]
fn formula_alias_uses_recharge_every_context_before_clone() {
    const SOURCE: &str = "fact = iff(equal(x, x), equal(y, y)) fact";
    const NODES: usize = 9;
    const DEPTH: u32 = 5;

    for (context, maximum) in [
        (FormulaContext::Binding, FORMULA_BINDING_MAX_NODES),
        (FormulaContext::Statement, FORMULA_MAX_NODES),
        (FormulaContext::Certificate, CERTIFICATE_MAX_FORMULA_NODES),
    ] {
        let mut at_limit = Parser::new(SOURCE);
        at_limit.formula_binding().unwrap();
        match context {
            FormulaContext::Binding => at_limit.formula_binding_nodes = maximum - NODES,
            FormulaContext::Statement => at_limit.statement_nodes = maximum - NODES,
            FormulaContext::Certificate => {
                at_limit.certificate_formula_nodes = maximum - NODES;
            }
        }
        let alias_offset = at_limit.next_offset();
        let parsed = at_limit.parsed_formula(1, context).unwrap();
        assert_eq!(parsed.expanded_nodes as usize, NODES);
        assert_eq!(parsed.expanded_depth, DEPTH);
        assert_eq!(
            match context {
                FormulaContext::Binding => at_limit.formula_binding_nodes,
                FormulaContext::Statement => at_limit.statement_nodes,
                FormulaContext::Certificate => at_limit.certificate_formula_nodes,
            },
            maximum
        );
        at_limit.end().unwrap();

        let mut over_limit = Parser::new(SOURCE);
        over_limit.formula_binding().unwrap();
        match context {
            FormulaContext::Binding => over_limit.formula_binding_nodes = maximum - NODES + 1,
            FormulaContext::Statement => over_limit.statement_nodes = maximum - NODES + 1,
            FormulaContext::Certificate => {
                over_limit.certificate_formula_nodes = maximum - NODES + 1;
            }
        }
        assert!(match (context, over_limit.parsed_formula(1, context)) {
            (
                FormulaContext::Binding,
                Err(CompileError::FormulaBindingNodeLimitExceeded { offset, maximum }),
            ) => offset == alias_offset && maximum == FORMULA_BINDING_MAX_NODES,
            (
                FormulaContext::Statement,
                Err(CompileError::Statement {
                    offset,
                    source: FormulaCodecError::NodeLimitExceeded { maximum },
                }),
            ) => offset == alias_offset && maximum == FORMULA_MAX_NODES,
            (
                FormulaContext::Certificate,
                Err(CompileError::Certificate {
                    offset,
                    source: ProofCertificateError::FormulaNodeLimitExceeded { maximum },
                }),
            ) => offset == alias_offset && maximum == CERTIFICATE_MAX_FORMULA_NODES,
            _ => false,
        });

        let mut at_depth = Parser::new(SOURCE);
        at_depth.formula_binding().unwrap();
        assert!(
            at_depth
                .parsed_formula(FORMULA_MAX_DEPTH - DEPTH + 1, context)
                .is_ok()
        );
        let mut over_depth = Parser::new(SOURCE);
        over_depth.formula_binding().unwrap();
        assert!(matches!(
            over_depth.parsed_formula(FORMULA_MAX_DEPTH - DEPTH + 2, context),
            Err(CompileError::FormulaDepthLimitExceeded { offset, maximum })
                if offset == alias_offset && maximum == FORMULA_MAX_DEPTH
        ));
    }
}

#[test]
fn unknown_alias_precedes_an_exhausted_use_budget_in_every_context() {
    for (context, maximum) in [
        (FormulaContext::Binding, FORMULA_BINDING_MAX_NODES),
        (FormulaContext::Statement, FORMULA_MAX_NODES),
        (FormulaContext::Certificate, CERTIFICATE_MAX_FORMULA_NODES),
    ] {
        let mut parser = Parser::new("missing");
        match context {
            FormulaContext::Binding => parser.formula_binding_nodes = maximum,
            FormulaContext::Statement => parser.statement_nodes = maximum,
            FormulaContext::Certificate => parser.certificate_formula_nodes = maximum,
        }
        assert!(matches!(
            parser.parsed_formula(1, context),
            Err(CompileError::UnknownFormulaBinding { offset: 0, name })
                if name == "missing"
        ));
    }
}

#[test]
fn alias_doubling_cannot_bypass_the_cumulative_retention_budget() {
    use std::fmt::Write as _;

    let mut source = String::from("a0 = equal(x, x) ");
    for index in 1..=15 {
        write!(
            &mut source,
            "a{index} = implies(a{}, a{}) ",
            index - 1,
            index - 1
        )
        .unwrap();
    }
    let mut parser = Parser::new(&source);
    for _ in 0..15 {
        parser.formula_binding().unwrap();
    }
    assert_eq!(parser.formula_binding_nodes, 65_519);
    let error_offset = source.rfind("a15 = implies(a14").unwrap() + "a15 = implies(".len();
    let error = parser.formula_binding().unwrap_err();
    assert_eq!(
        error,
        CompileError::FormulaBindingNodeLimitExceeded {
            offset: error_offset,
            maximum: FORMULA_BINDING_MAX_NODES,
        }
    );
    assert!(!parser.formula_bindings.contains_key("a15"));
    let diagnostic = error.diagnostic(&source);
    let span = diagnostic.primary_span().unwrap();
    assert_eq!(&source[span.start()..span.end()], "a14");
    assert_eq!(
        diagnostic.message(),
        format!("formula bindings exceed the {FORMULA_BINDING_MAX_NODES}-node retention limit")
    );
}

#[test]
fn certificate_formula_node_budget_accumulates_across_steps() {
    const TWO_STEPS: &str = "vacuous_universal(equal(x, x)) vacuous_universal(equal(y, y))";

    let mut at_limit = Parser::new(TWO_STEPS);
    at_limit.certificate_formula_nodes = CERTIFICATE_MAX_FORMULA_NODES - 2;
    at_limit.proof_step().unwrap();
    at_limit.proof_step().unwrap();
    at_limit.end().unwrap();
    assert_eq!(
        at_limit.certificate_formula_nodes,
        CERTIFICATE_MAX_FORMULA_NODES
    );

    let mut over_limit = Parser::new(TWO_STEPS);
    over_limit.certificate_formula_nodes = CERTIFICATE_MAX_FORMULA_NODES - 1;
    over_limit.proof_step().unwrap();
    assert!(matches!(
        over_limit.proof_step(),
        Err(CompileError::Certificate {
            source: ProofCertificateError::FormulaNodeLimitExceeded { maximum },
            ..
        }) if maximum == CERTIFICATE_MAX_FORMULA_NODES
    ));
}

#[test]
fn source_and_step_limits_fail_before_unbounded_growth_or_later_syntax() {
    let oversized = " ".repeat(AUTHORING_SOURCE_MAX_BYTES + 1);
    assert_eq!(
        compile(&oversized),
        Err(CompileError::SourceTooLong {
            actual: AUTHORING_SOURCE_MAX_BYTES + 1,
            maximum: AUTHORING_SOURCE_MAX_BYTES,
        })
    );

    let mut source = String::from(
        "foundation = \"naome:zfc\" statement = forall(x, equal(x, x)) proof: p0 = equality_reflexivity(x) ",
    );
    for index in 1..CERTIFICATE_MAX_STEPS {
        use std::fmt::Write as _;
        write!(&mut source, "p{index} = generalization(p{}, x) ", index - 1).unwrap();
    }
    source.push_str("excess = unsupported(");
    assert!(matches!(
        compile(&source),
        Err(CompileError::Certificate {
            source: ProofCertificateError::TooManySteps {
                actual,
                maximum,
            },
            ..
        }) if actual == CERTIFICATE_MAX_STEPS + 1 && maximum == CERTIFICATE_MAX_STEPS
    ));
}

#[test]
fn every_truncation_of_the_complete_source_fails_without_output() {
    let complete = SOURCE.trim_end();
    assert!(compile(complete).is_ok());
    for boundary in 0..complete.len() {
        if complete.is_char_boundary(boundary) {
            assert!(
                compile(&complete[..boundary]).is_err(),
                "accepted {boundary}"
            );
        }
    }
}

#[test]
fn diagnostic_codes_and_source_positions_are_stable() {
    let proof_id = ProofId::from_bytes([0; ProofId::BYTE_LENGTH]);
    let errors = [
        CompileError::SourceTooLong {
            actual: 2,
            maximum: 1,
        },
        CompileError::Syntax {
            offset: 0,
            expected: "syntax",
        },
        CompileError::FoundationMismatch { offset: 0 },
        CompileError::DuplicateStep {
            offset: 0,
            name: "step".to_owned(),
        },
        CompileError::UnknownStep {
            offset: 0,
            name: "step".to_owned(),
        },
        CompileError::ReturnNotFinal { offset: 0 },
        CompileError::FormulaDepthLimitExceeded {
            offset: 0,
            maximum: FORMULA_MAX_DEPTH,
        },
        CompileError::Statement {
            offset: 0,
            source: FormulaCodecError::NodeLimitExceeded {
                maximum: FORMULA_MAX_NODES,
            },
        },
        CompileError::Certificate {
            offset: 0,
            source: ProofCertificateError::EmptyCertificate,
        },
        CompileError::Check {
            span: SourceSpan::point(0),
            source: Box::new(CheckError::UnknownProofReference { step: 0, proof_id }),
        },
        CompileError::StatementMismatch {
            span: SourceSpan::point(0),
        },
        CompileError::DuplicateFormulaBinding {
            offset: 0,
            name: "formula".to_owned(),
        },
        CompileError::UnknownFormulaBinding {
            offset: 0,
            name: "formula".to_owned(),
        },
        CompileError::FormulaBindingNodeLimitExceeded {
            offset: 0,
            maximum: FORMULA_BINDING_MAX_NODES,
        },
    ];
    assert_eq!(
        errors
            .iter()
            .map(|error| error.diagnostic_code().as_str())
            .collect::<Vec<_>>(),
        vec![
            "NAO0001", "NAO0002", "NAO0003", "NAO0004", "NAO0005", "NAO0006", "NAO0007", "NAO0008",
            "NAO0009", "NAO0010", "NAO0011", "NAO0012", "NAO0013", "NAO0014",
        ]
    );
    assert_eq!(errors[0].source_offset(), None);
    assert_eq!(errors[1].source_offset(), Some(0));

    let source = "αβx\r\nq\rr\tz\n";
    assert_eq!(
        source_position(source, 4),
        Some(SourcePosition { line: 1, column: 3 })
    );
    assert_eq!(
        source_position(source, source.find('q').unwrap()),
        Some(SourcePosition { line: 2, column: 1 })
    );
    assert_eq!(
        source_position(source, source.find('r').unwrap()),
        Some(SourcePosition { line: 3, column: 1 })
    );
    assert_eq!(
        source_position(source, source.find('z').unwrap()),
        Some(SourcePosition { line: 3, column: 3 })
    );
    assert_eq!(
        source_position(source, source.len()),
        Some(SourcePosition { line: 4, column: 1 })
    );
}

#[test]
fn diagnostics_use_exact_token_statement_and_eof_spans() {
    let wrong_foundation = SOURCE.replace("naome:zfc", "wrong");
    let error = compile(&wrong_foundation).unwrap_err();
    let diagnostic = error.diagnostic(&wrong_foundation);
    let span = diagnostic.primary_span().unwrap();
    assert_eq!(&wrong_foundation[span.start()..span.end()], "\"wrong\"");
    assert_eq!(diagnostic.code(), DiagnosticCode::FoundationMismatch);

    let mismatch = SOURCE.replace("forall(x, equal(x, x))", "forall(x, member(x, x))");
    let error = compile(&mismatch).unwrap_err();
    let diagnostic = error.diagnostic(&mismatch);
    let span = diagnostic.primary_span().unwrap();
    assert_eq!(
        &mismatch[span.start()..span.end()],
        "forall(x, member(x, x))"
    );
    assert_eq!(diagnostic.code(), DiagnosticCode::StatementMismatch);

    let truncated = SOURCE.trim_end().strip_suffix("p1").unwrap();
    let error = compile(truncated).unwrap_err();
    let diagnostic = error.diagnostic(truncated);
    assert_eq!(diagnostic.code(), DiagnosticCode::Syntax);
    assert_eq!(
        diagnostic.primary_span(),
        Some(SourceSpan::point(truncated.len()))
    );
}

#[test]
fn checker_diagnostics_map_normalized_steps_back_to_source_assignments() {
    const ZERO_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ONE_ID: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    let unreachable = format!(
        "foundation = \"naome:zfc\"\nstatement = equal(x, x)\nproof:\n  dead = cite(\"{ONE_ID}\")\n  broken = cite(\"{ZERO_ID}\")\n  root = generalization(broken, x)\n  return root"
    );
    assert_check_diagnostic_origin(
        &unreachable,
        "broken",
        &format!("broken = cite(\"{ZERO_ID}\")"),
    );

    let reordered = "foundation = \"naome:zfc\"\nstatement = equal(x, x)\nproof:\n  a0 = equality_reflexivity(x)\n  a1 = simplification(equal(x, x), equal(x, x))\n  broken_result = modus_ponens(a1, a0)\n  b0 = equality_reflexivity(y)\n  root = modus_ponens(b0, broken_result)\n  return root";
    assert_check_diagnostic_origin(
        reordered,
        "broken_result",
        "broken_result = modus_ponens(a1, a0)",
    );

    let interned = format!(
        "foundation = \"naome:zfc\"\nstatement = equal(x, x)\nproof:\n  p0 = cite(\"{ZERO_ID}\")\n  p1 = cite(\"{ZERO_ID}\")\n  root = modus_ponens(p1, p0)\n  return root"
    );
    assert_check_diagnostic_origin(&interned, "p0", &format!("p0 = cite(\"{ZERO_ID}\")"));
}

fn assert_check_diagnostic_origin(source: &str, step_name: &str, assignment: &str) {
    let error = compile(source).unwrap_err();
    let CompileError::Check { span, .. } = &error else {
        panic!("expected checker error, got {error:?}");
    };
    assert_eq!(&source[span.start()..span.end()], assignment);
    assert!(source[span.start()..span.end()].starts_with(step_name));

    let diagnostic = error.diagnostic(source);
    assert_eq!(diagnostic.code(), DiagnosticCode::Check);
    assert!(
        diagnostic
            .message()
            .contains(&format!("step {step_name:?}"))
    );
    assert!(!diagnostic.message().contains("proof step"));
    assert_eq!(diagnostic.primary_span(), Some(*span));
}

#[test]
fn consuming_bytes_returns_the_exact_owned_output() {
    let proof = compile(SOURCE).unwrap();
    let expected = proof.canonical_proof_bytes().to_vec();
    assert_eq!(proof.into_canonical_proof_bytes().into_vec(), expected);
}

#[test]
fn definition_source_names_are_identity_neutral_and_source_helpers_are_rejected() {
    let first =
        compile_artifact("foundation = \"naome:zfc\" definition first = relation(x,): equal(x, x)")
            .unwrap();
    let renamed = compile_artifact(
        "foundation = \"naome:zfc\" definition presentation_only = relation(value): equal(value, value)",
    )
    .unwrap();
    assert_eq!(first, renamed);

    let formulas = "foundation = \"naome:zfc\" formulas: helper = equal(x, x) definition relation_name = relation(x): equal(x, x)";
    assert!(matches!(
        compile_artifact(formulas),
        Err(CompileError::Syntax {
            expected: "a proof statement after formula bindings",
            ..
        })
    ));
    for duplicate in [
        "foundation = \"naome:zfc\" definition bad = relation(x, x): equal(x, x)",
        "foundation = \"naome:zfc\" definition bad = function(x, x, obligation = \"0000000000000000000000000000000000000000000000000000000000000000\"): equal(x, x)",
    ] {
        assert!(matches!(
            compile_artifact(duplicate),
            Err(CompileError::Syntax {
                expected: "a unique definition parameter",
                ..
            })
        ));
    }
}

#[test]
fn all_definition_declarations_reach_the_typed_semantic_boundary() {
    let relation =
        compile_artifact("foundation = \"naome:zfc\" definition r = relation(x, y): equal(x, y)")
            .unwrap();
    assert!(matches!(relation, CompiledArtifact::Definition(_)));

    for source in [
        "foundation = \"naome:zfc\" definition c = constant(value, obligation = \"0000000000000000000000000000000000000000000000000000000000000000\"): equal(value, value)",
        "foundation = \"naome:zfc\" definition f = function(input, output, obligation = \"0000000000000000000000000000000000000000000000000000000000000000\",): equal(output, input)",
    ] {
        assert!(matches!(
            compile_artifact(source),
            Err(CompileError::DefinitionCheck { .. })
        ));
    }
}

#[test]
fn definition_names_cannot_create_self_or_forward_authority() {
    assert!(matches!(
        compile_artifact(
            "foundation = \"naome:zfc\" definition recursive = relation(x): recursive(x)"
        ),
        Err(CompileError::UnknownDefinitionAlias { name, .. }) if name == "recursive"
    ));
    assert!(matches!(
        compile_artifact(
            "foundation = \"naome:zfc\" definitions: future = \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\" definition current = relation(x): future(x)"
        ),
        Err(CompileError::DefinitionNotSelected { .. })
    ));
}

#[test]
fn term_sugar_relationalizes_unary_nested_and_multi_input_calls_exactly_once() {
    let obligation = ProofId::from_bytes([0x41; 32]);
    let identity_id = DefinitionId::from_bytes([0x51; 32]);
    let binary_id = DefinitionId::from_bytes([0x52; 32]);

    let parse = |source: &'static str| {
        let mut parser = Parser::new(source);
        parser.definition_aliases.insert(
            "identity",
            DefinitionAlias {
                definition_id: identity_id,
                kind: DefinitionKind::Function {
                    input_arity: 1,
                    total_unique_proof: obligation,
                },
            },
        );
        parser.definition_aliases.insert(
            "binary",
            DefinitionAlias {
                definition_id: binary_id,
                kind: DefinitionKind::Function {
                    input_arity: 2,
                    total_unique_proof: obligation,
                },
            },
        );
        let formula = parser
            .parsed_formula(1, FormulaContext::Statement)
            .unwrap()
            .formula;
        parser.end().unwrap();
        formula
    };

    let x = FreeVariable::new(0);
    let first = FreeVariable::new(1);
    let second = FreeVariable::new(2);
    let third = FreeVariable::new(3);

    let unary = DefinedFormula::exists(
        first,
        DefinedFormula::conjunction(
            DefinedFormula::defined_relation(identity_id, [x, first]),
            DefinedFormula::equal(first, x),
        ),
    );
    assert_eq!(parse("equal(identity(x), x)"), unary);

    let nested = DefinedFormula::exists(
        first,
        DefinedFormula::exists(
            second,
            DefinedFormula::conjunction(
                DefinedFormula::defined_relation(identity_id, [x, first]),
                DefinedFormula::conjunction(
                    DefinedFormula::defined_relation(identity_id, [first, second]),
                    DefinedFormula::equal(second, x),
                ),
            ),
        ),
    );
    assert_eq!(parse("equal(identity(identity(x)), x)"), nested);

    let multi_input = DefinedFormula::exists(
        second,
        DefinedFormula::exists(
            third,
            DefinedFormula::conjunction(
                DefinedFormula::defined_relation(identity_id, [first, second]),
                DefinedFormula::conjunction(
                    DefinedFormula::defined_relation(binary_id, [x, second, third]),
                    DefinedFormula::equal(third, first),
                ),
            ),
        ),
    );
    assert_eq!(parse("equal(binary(x, identity(y)), y)"), multi_input);
}

fn hex32(hex: &str) -> [u8; 32] {
    hex_bytes(hex).try_into().unwrap()
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
        .collect()
}
