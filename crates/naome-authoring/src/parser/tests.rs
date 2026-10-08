#[path = "../../tests/support/hex_decode.rs"]
mod hex_decode;
use hex_decode::{hex_bytes, hex32};

#[path = "../../tests/support/golden.rs"]
mod golden;
use golden::*;
use golden::{
    DERIVATION_ID as SELF_EQUALITY_DERIVATION_ID_HEX, PROOF_BYTES as SELF_EQUALITY_PROOF_HEX,
    PROOF_ID as SELF_EQUALITY_PROOF_ID_HEX, STATEMENT_ID as SELF_EQUALITY_STATEMENT_ID_HEX,
};

use naome_checker::{
    ArtifactState as ProofState, ArtifactStateError as ProofStateError, normalize_and_check,
};
use naome_foundation::{Formula, SchemaError};
use naome_proof::{DerivationId, ProofCertificate, ProofId, StatementId};

use super::*;

const SOURCE: &str = r#"
# Presentation-only comment and indentation.

goal = all(x, eq(x, x))
proof:
    p0 = refl(x)
    p1 = gen(p0, x)
    return p1
"#;

const SELF_EQUALITY_REFERENCE_PROOF_ID_HEX: &str =
    "bfd427b447e1514686cfa31b0b5aa1dd5036464cd8c5d73d0c3112cb46b0519b";
const SELF_EQUALITY_REFERENCE_PROOF_HEX: &str =
    "0000000130c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73";
const PROOF_ID_EXPECTED: &str = "a 64-digit lowercase hexadecimal ProofId";

const IMPLICATION_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/implication-identity.nao"
));
const INLINED_IMPLICATION_SOURCE: &str = r#"

goal = all(x, imp(eq(x, x), eq(x, x)))
proof:
    p0 = simp(eq(x, x), eq(x, x))
    p1 = simp(
        eq(x, x),
        imp(eq(x, x), eq(x, x)),
    )
    p2 = frege(
        eq(x, x),
        imp(eq(x, x), eq(x, x)),
        eq(x, x),
    )
    p3 = mp(p1, p2)
    p4 = mp(p0, p3)
    p5 = gen(p4, x)
    return p5
"#;
const QUANTIFIER_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/quantifier-instantiation.nao"
));
const EQUALITY_SUBSTITUTION_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/equality-substitution.nao"
));
const EXTENSIONALITY_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/extensionality.nao"
));
const SEPARATION_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/separation.nao"
));
const REPLACEMENT_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/replacement.nao"
));

fn proof_reference_source(proof_id: &str) -> String {
    format!("goal = all(x, eq(x, x)) proof: known = cite(\"{proof_id}\") return known")
}

fn complete_source(statement: &str, steps: &str, result: &str) -> String {
    format!("goal = {statement} proof: {steps} return {result}")
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
        "all(closed, eq(closed, closed))",
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
        (SOURCE, STATEMENT_ID, DERIVATION_ID, PROOF_ID, PROOF_BYTES),
        (
            IMPLICATION_SOURCE,
            IMPLICATION_STATEMENT_ID,
            IMPLICATION_DERIVATION_ID,
            IMPLICATION_PROOF_ID,
            IMPLICATION_PROOF_BYTES,
        ),
        (
            QUANTIFIER_SOURCE,
            QUANTIFIER_STATEMENT_ID,
            QUANTIFIER_DERIVATION_ID,
            QUANTIFIER_PROOF_ID,
            QUANTIFIER_PROOF_BYTES,
        ),
        (
            EQUALITY_SUBSTITUTION_SOURCE,
            SUBSTITUTION_STATEMENT_ID,
            SUBSTITUTION_DERIVATION_ID,
            SUBSTITUTION_PROOF_ID,
            SUBSTITUTION_PROOF_BYTES,
        ),
        (
            EXTENSIONALITY_SOURCE,
            EXTENSIONALITY_STATEMENT_ID,
            EXTENSIONALITY_DERIVATION_ID,
            EXTENSIONALITY_PROOF_ID,
            EXTENSIONALITY_PROOF_BYTES,
        ),
        (
            SEPARATION_SOURCE,
            SEPARATION_STATEMENT_ID,
            SEPARATION_DERIVATION_ID,
            SEPARATION_PROOF_ID,
            SEPARATION_PROOF_BYTES,
        ),
        (
            REPLACEMENT_SOURCE,
            REPLACEMENT_STATEMENT_ID,
            REPLACEMENT_DERIVATION_ID,
            REPLACEMENT_PROOF_ID,
            REPLACEMENT_PROOF_BYTES,
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

let:
    unused = eq(z, z)
    reflexive = eq(x, x)
    identity = imp(reflexive, reflexive)
goal = all(x, identity)
proof:
    p0 = simp(reflexive, reflexive)
    p1 = simp(reflexive, identity)
    p2 = frege(reflexive, identity, reflexive)
    p3 = mp(p1, p2)
    p4 = mp(p0, p3)
    p5 = gen(p4, x)
    return p5
"#;
    let baseline = compile(INLINED_IMPLICATION_SOURCE).unwrap();
    assert_eq!(compile(IMPLICATION_SOURCE).unwrap(), baseline);
    assert_eq!(compile(bound).unwrap(), baseline);

    let reordered = bound.replace(
        "    unused = eq(z, z)\n    reflexive = eq(x, x)",
        "    reflexive = eq(x, x)\n    unused = eq(z, z)",
    );
    assert_eq!(compile(&reordered).unwrap(), baseline);

    let renamed = bound
        .replace("reflexive", "r")
        .replace("identity", "i")
        .replace("unused = eq(z, z)", "other = eq(y, y)");
    assert_eq!(compile(&renamed).unwrap(), baseline);
}

#[test]
fn binding_expansion_uses_the_global_variable_namespace_and_enclosing_binders() {
    let captured = r#"

let:
    reflexive = eq(x, x)
    closed = all(x, reflexive)
goal = closed
proof:
    p0 = refl(x)
    p1 = gen(p0, x)
    return p1
"#;
    assert_eq!(compile(captured).unwrap(), compile(SOURCE).unwrap());

    let independent_namespaces = r#"

let:
    x = eq(x, x)
    p0 = x
goal = all(x, p0)
proof:
    p0 = refl(x)
    p1 = gen(p0, x)
    return p1
"#;
    assert_eq!(
        compile(independent_namespaces).unwrap(),
        compile(SOURCE).unwrap()
    );

    let step_position = r#"

let:
    premise = eq(x, x)
goal = all(x, premise)
proof:
    p0 = refl(x)
    p1 = mp(premise, p0)
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
        ("simp(Fact, Fact)", "simp(eq(x, x), eq(x, x))"),
        (
            "frege(Fact, Fact, Fact)",
            "frege(eq(x, x), eq(x, x), eq(x, x))",
        ),
        ("contra(Fact, Fact)", "contra(eq(x, x), eq(x, x))"),
        ("dist(x, Fact, Fact)", "dist(x, eq(x, x), eq(x, x))"),
        ("vacuous(Fact)", "vacuous(eq(x, x))"),
        ("inst(x, x, Fact)", "inst(x, x, eq(x, x))"),
        ("subst(x, x, Fact)", "subst(x, x, eq(x, x))"),
        (
            "sep(Fact, x, x, x, parameters=[Fact])",
            "sep(eq(x, x), x, x, x, parameters=[Fact])",
        ),
        (
            "replace(Fact, x, x, x, x, x, parameters=[])",
            "replace(eq(x, x), x, x, x, x, x, parameters=[])",
        ),
    ] {
        assert_eq!(
            parse_bound_step("Fact = eq(x, x)", bound).unwrap(),
            parse_step(inlined).unwrap(),
            "binding changed {bound}"
        );
    }
}

#[test]
fn every_derived_formula_lowers_to_the_existing_primitive_structure() {
    for (derived, primitive) in [
        (
            "and(eq(x, x), mem(y, z))",
            "not(imp(eq(x, x), not(mem(y, z))))",
        ),
        ("or(eq(x, x), mem(y, z))", "imp(not(eq(x, x)), mem(y, z))"),
        (
            "iff(eq(x, x), mem(y, z))",
            "not(imp(imp(eq(x, x), mem(y, z)), not(imp(mem(y, z), eq(x, x)))))",
        ),
        ("ex(x, mem(x, set))", "not(all(x, not(mem(x, set))))"),
        ("ne(x, y)", "not(eq(x, y))"),
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
    const A: &str = "all(x, ne(x, x))";
    const B: &str = "ex(y, and(eq(y, y), or(mem(y, y), iff(eq(y, y), mem(y, y)))))";
    const PRIMITIVE_A: &str = "all(x, not(eq(x, x)))";
    const PRIMITIVE_B: &str = "not(all(y, not(not(imp(eq(y, y), not(imp(not(mem(y, y)), not(imp(imp(eq(y, y), mem(y, y)), not(imp(mem(y, y), eq(y, y))))))))))))";
    let source = |a: &str, b: &str| {
        complete_source(
            &format!("imp({a}, imp({b}, {a}))"),
            &format!("p0 = simp({a}, {b})"),
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
        "and(eq(left, left), mem(right, set))",
        FormulaContext::Certificate,
    )
    .unwrap();
    let swapped = parse_formula(
        "and(mem(right, set), eq(left, left))",
        FormulaContext::Certificate,
    )
    .unwrap();
    assert_ne!(left.formula, swapped.formula);

    let exists = parse_formula(
        "ex(x, and(mem(x, set), all(x, mem(x, x))))",
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
        "eq(x, y,)",
        "not(eq(x, x),)",
        "imp(eq(x, x), eq(y, y),)",
        "all(x, eq(x, x),)",
        "and(eq(x, x), eq(y, y),)",
        "or(eq(x, x), eq(y, y),)",
        "iff(eq(x, x), eq(y, y),)",
        "ex(x, eq(x, x),)",
        "ne(x, y,)",
    ] {
        assert!(
            parse_formula(source, FormulaContext::Statement).is_ok(),
            "{source}"
        );
    }

    for source in [
        "eq(x y)",
        "eq(x,, y)",
        "eq(x, y, z)",
        "eq(x, y,,)",
        "eq(x)",
        "not()",
        "not(eq(x, x), eq(y, y))",
        "all(x eq(x, x))",
        "ex(x,)",
        "ne(x)",
    ] {
        assert!(
            matches!(
                parse_formula(source, FormulaContext::Statement),
                Err(CompileError::Syntax { .. })
            ),
            "accepted {source:?}"
        );
    }

    for source in ["and(broken, eq(x, x))", "and(eq(x, x), broken)"] {
        assert!(matches!(
            parse_formula(source, FormulaContext::Statement),
            Err(CompileError::UnknownFormulaBinding { name, .. }) if name == "broken"
        ));
    }

    for (source, expected) in [
        ("or(eq(x, x))", "`,`"),
        ("iff(eq(x, x), eq(y, y), extra)", "`)`"),
        ("ex(1bad, eq(x, x))", "a name"),
        ("ne(x)", "`,`"),
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
        "not_(eq(x, x))",
        "and_(eq(x, x), eq(y, y))",
        "or_(eq(x, x), eq(y, y))",
        "not-eq(x, y)",
        "ne(x-y, z)",
    ] {
        assert!(parse_formula(source, FormulaContext::Statement).is_err());
    }

    for source in [
        "(equality-reflexivity x)",
        "equality-reflexivity(x)",
        "proof_reference(\"c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73\")",
    ] {
        assert!(matches!(
            parse_step(source),
            Err(CompileError::Syntax { .. })
        ));
    }
    assert!(matches!(
        parse_step("cite(c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73)"),
        Err(CompileError::UnknownProofReference { .. })
    ));
}

#[test]
fn every_proof_call_maps_to_the_existing_protocol_step() {
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let z = FreeVariable::new(2);

    assert_eq!(
        parse_step("simp(eq(x, x), mem(y, z))").unwrap(),
        ProofStep::Simplification {
            antecedent: Formula::equal(x, x).into(),
            consequent: Formula::member(y, z).into(),
        }
    );
    assert_eq!(
        parse_step("frege(eq(x, x), mem(y, z), eq(z, y))").unwrap(),
        ProofStep::Frege {
            first: Formula::equal(x, x).into(),
            second: Formula::member(y, z).into(),
            third: Formula::equal(z, y).into(),
        }
    );
    assert_eq!(
        parse_step("contra(eq(x, x), mem(y, z))").unwrap(),
        ProofStep::ClassicalContraposition {
            antecedent: Formula::equal(x, x).into(),
            consequent: Formula::member(y, z).into(),
        }
    );
    assert_eq!(
        parse_step("dist(x, eq(x, x), mem(y, z))").unwrap(),
        ProofStep::UniversalDistribution {
            variable: x,
            antecedent: Formula::equal(x, x).into(),
            consequent: Formula::member(y, z).into(),
        }
    );
    assert_eq!(
        parse_step("vacuous(eq(x, x))").unwrap(),
        ProofStep::VacuousUniversal {
            formula: Formula::equal(x, x).into(),
        }
    );
    assert_eq!(
        parse_step("inst(x, y, mem(x, z))").unwrap(),
        ProofStep::UniversalInstantiation {
            variable: x,
            replacement: y,
            body: Formula::member(x, z).into(),
        }
    );
    assert_eq!(
        parse_step_with_names("mp(p0, p1)", &["p0", "p1"]).unwrap(),
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        }
    );
    assert_eq!(
        parse_step("refl(x)").unwrap(),
        ProofStep::EqualityReflexivity { variable: x }
    );
    assert_eq!(
        parse_step("subst(x, y, mem(x, z))").unwrap(),
        ProofStep::EqualitySubstitution {
            from: x,
            to: y,
            body: Formula::member(x, z).into(),
        }
    );
    assert_eq!(
        parse_step("sep(mem(element, filter), element, source, result, parameters=[filter])")
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
            "replace(eq(input, output), input, output, witness, source, result, parameters=[])"
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
        parse_step_with_names("gen(p0, x)", &["p0"]).unwrap(),
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        }
    );
}

#[test]
fn formula_parser_keeps_the_maximum_expanded_depth_on_the_default_stack() {
    let mut source = format!(
        "{}iff(eq(x,x),eq(y,y)){}",
        "not(".repeat((FORMULA_MAX_DEPTH - 5) as usize),
        ")".repeat((FORMULA_MAX_DEPTH - 5) as usize)
    );
    let mut parser = Parser::new(&source);

    assert!(parser.parsed_formula(1, FormulaContext::Statement).is_ok());
    source = format!("not({source})");
    let mut parser = Parser::new(&source);

    assert!(matches!(
        parser.parsed_formula(1, FormulaContext::Statement),
        Err(CompileError::FormulaDepthLimitExceeded { .. })
    ));
}

#[test]
fn equality_substitution_preserves_roles_and_avoids_capture_under_a_binder() {
    let source = r#"

goal = all(x, all(y,
    imp(eq(x, y),
        imp(all(bound, mem(x, bound)),
            all(bound, mem(y, bound))))))
proof:
    substitute = subst(x, y, all(y, mem(x, y)))
    for_y = gen(substitute, y)
    for_x = gen(for_y, x)
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
            "subst(x, y, all(y, mem(x, y)))",
            "subst(y, x, all(y, mem(x, y)))",
        ),
        source.replace(
            "subst(x, y, all(y, mem(x, y)))",
            "subst(x, y, all(y, mem(y, y)))",
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
            parse_step(&format!("axiom(\"{selector}\")")).unwrap(),
            ProofStep::ZfcAxiom(expected)
        );
        assert_eq!(
            parse_step(&format!("axiom(\"{selector}\",)")).unwrap(),
            ProofStep::ZfcAxiom(expected)
        );
    }

    for source in [
        "axiom(extensionality)",
        "axiom(\"power-set\")",
        "zfc-axiom(\"extensionality\")",
        "axiom(\"Extensionality\")",
        "axiom(\"unsupported\")",
        "axiom(\"extensionality\", \"pairing\")",
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
        "simp(eq(x, x) eq(y, y))",
        "simp(eq(x, x),)",
        "frege(eq(x, x), eq(y, y))",
        "dist(x, eq(x, x) eq(y, y))",
        "inst(x, y)",
        "subst(x, y, mem(x, y), extra)",
        "gen(p0 x)",
        "mp(p0,, p1)",
        "refl(x, y)",
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
        "simp(eq(x, x), eq(y, y),)",
        "frege(eq(x, x), eq(y, y), eq(z, z),)",
        "contra(eq(x, x), eq(y, y),)",
        "dist(x, eq(x, x), eq(y, y),)",
        "vacuous(eq(x, x),)",
        "inst(x, y, eq(x, x),)",
        "mp(p0, p1,)",
        "refl(x,)",
        "subst(x, y, eq(x, x),)",
        "gen(p0, x,)",
    ] {
        let names = ["p0", "p1"];
        assert!(parse_step_with_names(source, &names).is_ok(), "{source}");
    }
}

#[test]
fn schema_parameter_lists_are_named_comma_delimited_and_trailing_comma_tolerant() {
    for source in [
        "sep(eq(element, element), element, source, result, parameters=[]) ",
        "sep(eq(element, element), element, source, result, parameters=[first])",
        "sep(eq(element, element), element, source, result, parameters=[first, second,],)",
        "replace(eq(input, output), input, output, witness, source, result, parameters=[])",
        "replace(eq(input, output), input, output, witness, source, result, parameters=[first, second],)",
    ] {
        assert!(parse_step(source).is_ok(), "{source}");
    }

    for source in [
        "sep(eq(element, element), element, source, result)",
        "sep(eq(element, element), element, source, result, parameters())",
        "sep(eq(element, element), element, source, result, parameters=())",
        "sep(eq(element, element), element, source, result, parameter=[])",
        "sep(eq(element, element), element, source, result, parameters=[first second])",
        "sep(eq(element, element), element, source, result, parameters=[,])",
        "sep(eq(element, element), element, source, result, parameters=[first,, second])",
        "sep(eq(element, element), element, source, result, parameters=[], extra)",
        "replace(eq(input, output), input, output, witness, source, result, extra, parameters=[])",
    ] {
        assert!(
            matches!(parse_step(source), Err(CompileError::Syntax { .. })),
            "accepted {source:?}"
        );
    }

    let separation = parse_step(
        "sep(imp(mem(element, source), eq(first, second)), element, source, result, parameters=[first, second])",
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
        "replace(imp(eq(input, output), mem(input, parameter)), input, output, witness, source, result, parameters=[parameter, unused])",
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
            "sep(eq(first, second), element, source, result, parameters=[{parameters}])"
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
        "invalid = sep(eq(result, result), element, source, result, parameters=[])";
    let reachable = complete_source("all(x, eq(x, x))", INVALID, "invalid");
    assert_check_error(
        compile(&reachable),
        CheckError::Schema {
            step: 0,
            source: SchemaError::ForbiddenPredicateVariable(FreeVariable::new(0)),
        },
    );

    let unreachable = SOURCE.replace("p0 = refl(x)", &format!("{INVALID} p0 = refl(x)"));
    assert_eq!(compile(&unreachable).unwrap(), compile(SOURCE).unwrap());
}

#[test]
fn combined_schema_errors_follow_foundation_precedence_after_lowering() {
    for (step, expected) in [
        (
            "sep(eq(result, result), shared, shared, result, parameters=[shared, shared])",
            SchemaError::RoleVariableCollision(FreeVariable::new(1)),
        ),
        (
            "sep(eq(result, result), element, source, result, parameters=[source, source])",
            SchemaError::ParameterCollidesWithRole(FreeVariable::new(2)),
        ),
        (
            "sep(eq(result, result), element, source, result, parameters=[parameter, parameter])",
            SchemaError::DuplicateParameter(FreeVariable::new(3)),
        ),
        (
            "sep(imp(eq(result, result), eq(undeclared, undeclared)), element, source, result, parameters=[])",
            SchemaError::ForbiddenPredicateVariable(FreeVariable::new(0)),
        ),
        (
            "sep(imp(eq(undeclared, undeclared), eq(result, result)), element, source, result, parameters=[])",
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
        format!("foundation = \"naome:zfc\" {SOURCE}"),
        SOURCE.replace("goal =", "goal:"),
        SOURCE.replace("proof:", "proof"),
        SOURCE.replace("return p1", "result p1"),
        SOURCE.replace("return p1", "return p1;"),
        SOURCE.replace("p0 =", "step p0 ="),
        SOURCE.replace("refl", "equality-reflexivity"),
    ] {
        assert!(matches!(compile(&source), Err(CompileError::Syntax { .. })));
    }
}

#[test]
fn indentation_comments_and_python_identifiers_are_presentation_only() {
    let compact = "goal = all(x,eq(x,x)) proof: P0 = refl(x) P1 = gen(P0,x) return P1";
    assert_eq!(compile(compact).unwrap(), compile(SOURCE).unwrap());

    let irregular = r#"

goal = all(
 x,
 eq(x, x), # trailing formula comment
)
proof:
          _p0 = refl(x,) # arbitrary indentation
	_p1 = gen(_p0, x,)
return _p1 # EOF comment"#;
    assert_eq!(compile(irregular).unwrap(), compile(SOURCE).unwrap());

    for source in [
        SOURCE.replace("p0 =", "p-0 ="),
        SOURCE.replace("eq(x, x)", "eq(x-y, x-y)"),
        SOURCE.replace("p0 =", "0p ="),
    ] {
        assert!(matches!(compile(&source), Err(CompileError::Syntax { .. })));
    }
}

#[test]
fn duplicate_unknown_forward_and_nonfinal_steps_fail_at_their_source_offsets() {
    let duplicate = SOURCE.replace("p1 = gen(p0, x)", "p0 = gen(p0, x)");
    let duplicate_offset = duplicate.rfind("p0 =").unwrap();
    assert_eq!(
        compile(&duplicate),
        Err(CompileError::DuplicateStep {
            offset: duplicate_offset,
            name: "p0".to_owned(),
        })
    );

    let unknown = SOURCE.replace("gen(p0, x)", "gen(missing, x)");
    let unknown_offset = unknown.find("missing").unwrap();
    assert_eq!(
        compile(&unknown),
        Err(CompileError::UnknownStep {
            offset: unknown_offset,
            name: "missing".to_owned(),
        })
    );

    let forward = SOURCE.replace("p0 = refl(x)", "p0 = gen(p1, x)");
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
        format!("let: {bindings} goal = {statement} proof: p0 = refl(x) p1 = gen(p0, x) return p1")
    };

    let empty = source("", "all(x, eq(x, x))");
    assert_eq!(
        compile(&empty),
        Err(CompileError::Syntax {
            offset: empty.find("goal").unwrap(),
            expected: "at least one formula binding",
        })
    );

    let repeated_block = source("fact = eq(x, x) let: other = eq(x, x)", "all(x, fact)");
    assert_eq!(
        compile(&repeated_block),
        Err(CompileError::Syntax {
            offset: repeated_block.rfind("let:").unwrap(),
            expected: "a non-reserved formula binding name",
        })
    );

    let duplicate = source("fact = eq(x, x) fact = unsupported(", "all(x, fact)");
    let duplicate_offset = duplicate.rfind("fact =").unwrap();
    assert_eq!(
        compile(&duplicate),
        Err(CompileError::DuplicateFormulaBinding {
            offset: duplicate_offset,
            name: "fact".to_owned(),
        })
    );

    for bindings in ["fact = fact", "fact = later later = eq(x, x)"] {
        let invalid = source(bindings, "all(x, eq(x, x))");
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

    let unknown = source("fact = eq(x, x)", "all(x, missing)");
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
        "defs",
        "refs",
        "let",
        "goal",
        "def",
        "relation",
        "function",
        "success",
        "proof",
        "return",
        "parameters",
        "eq",
        "mem",
        "not",
        "imp",
        "all",
        "and",
        "or",
        "iff",
        "ex",
        "ne",
        "simp",
        "frege",
        "contra",
        "dist",
        "vacuous",
        "inst",
        "mp",
        "refl",
        "subst",
        "axiom",
        "sep",
        "replace",
        "cite",
        "gen",
    ];

    for name in RESERVED {
        let source = format!(
            "let: {name} = eq(x, x) goal = all(x, eq(x, x)) proof: p0 = refl(x) p1 = gen(p0, x) return p1"
        );
        assert!(
            matches!(compile(&source), Err(CompileError::Syntax { .. })),
            "accepted reserved binding {name}"
        );
    }

    for bare in ["eq", "return", "simp"] {
        let source = complete_source(
            &format!("all(x, {bare})"),
            "p0 = refl(x) p1 = gen(p0, x)",
            "p1",
        );
        assert!(matches!(compile(&source), Err(CompileError::Syntax { .. })));
    }

    let unknown_call = complete_source("all(x, missing())", "p0 = refl(x) p1 = gen(p0, x)", "p1");
    assert!(matches!(
        compile(&unknown_call),
        Err(CompileError::UnknownDefinitionAlias { name, .. }) if name == "missing"
    ));

    let unknown_bare = complete_source("all(x, missing)", "p0 = refl(x) p1 = gen(p0, x)", "p1");
    assert!(matches!(
        compile(&unknown_bare),
        Err(CompileError::UnknownFormulaBinding { name, .. }) if name == "missing"
    ));

    let binding_as_axiom_selector = r#"

let:
    selector = eq(x, x)
goal = all(x, eq(x, x))
proof:
    p0 = axiom(selector)
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
    let malformed_block = SOURCE.replacen("goal =", "let = fact = eq(x, x) goal =", 1);
    assert!(matches!(
        compile(&malformed_block),
        Err(CompileError::Syntax {
            expected: "`:`",
            ..
        })
    ));

    let long_name = "n".repeat(DIAGNOSTIC_NAME_MAX_SCALARS + 32);
    let source = format!(
        "let: {long_name} = eq(x, x) {long_name} = eq(x, x) goal = all(x, eq(x, x)) proof: p0 = refl(x) p1 = gen(p0, x) return p1"
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
        "let: fact = eq(x, x) goal = all(x, {long_name}) proof: p0 = refl(x) p1 = gen(p0, x) return p1"
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

    let open = complete_source("eq(x, x)", "p0 = refl(x)", "p0");
    assert!(matches!(
        compile(&open),
        Err(CompileError::Check { source, .. })
            if matches!(source.as_ref(), CheckError::OpenConclusion { .. })
    ));

    let mismatch = SOURCE.replace("all(x, eq(x, x))", "all(x, mem(x, x))");
    assert!(matches!(
        compile(&mismatch),
        Err(CompileError::StatementMismatch { .. })
    ));

    let invalid_mp = IMPLICATION_SOURCE.replace("mp(p1, p2)", "mp(p2, p1)");
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
        "let: reflexive = eq(x, x) closed = all(x, reflexive) goal = closed proof: known = cite(\"{SELF_EQUALITY_PROOF_ID_HEX}\") return known"
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

    let binding_as_id = "let: dependency = all(x, eq(x, x)) goal = dependency proof: known = cite(dependency) return known";
    assert!(matches!(
        compile(binding_as_id),
        Err(CompileError::UnknownProofReference { name, .. }) if name == "dependency"
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
        "# presentation only\ngoal = all(value, eq(value, value)) proof: imported = cite(\"{SELF_EQUALITY_PROOF_ID_HEX}\") return imported"
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
        "p0 = refl(x)",
        &format!("unused = cite(\"{unknown}\") p0 = refl(x)"),
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
    const IFF: &str = "iff(eq(x, x), eq(y, y))";
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
            "not(".repeat(count as usize),
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

    let exact_default_stack_boundary = wrap(FORMULA_MAX_DEPTH - 1, "eq(x, x)");
    assert!(parse_formula(&exact_default_stack_boundary, FormulaContext::Statement).is_ok());
    let over_default_stack_boundary = wrap(FORMULA_MAX_DEPTH, "eq(x, x)");
    let terminal_offset = over_default_stack_boundary.find("eq").unwrap();
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
    const SOURCE: &str = "fact = iff(eq(x, x), eq(y, y)) fact";
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

    let mut source = String::from("a0 = eq(x, x) ");
    for index in 1..=15 {
        write!(
            &mut source,
            "a{index} = imp(a{}, a{}) ",
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
    let error_offset = source.rfind("a15 = imp(a14").unwrap() + "a15 = imp(".len();
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
    const TWO_STEPS: &str = "vacuous(eq(x, x)) vacuous(eq(y, y))";

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

    let mut source = String::from("goal = all(x, eq(x, x)) proof: p0 = refl(x) ");
    for index in 1..CERTIFICATE_MAX_STEPS {
        use std::fmt::Write as _;
        write!(&mut source, "p{index} = gen(p{}, x) ", index - 1).unwrap();
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
fn diagnostics_use_exact_token_statement_and_eof_spans() {
    let mismatch = SOURCE.replace("all(x, eq(x, x))", "all(x, mem(x, x))");
    let error = compile(&mismatch).unwrap_err();
    let diagnostic = error.diagnostic(&mismatch);
    let span = diagnostic.primary_span().unwrap();
    assert_eq!(&mismatch[span.start()..span.end()], "all(x, mem(x, x))");
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
        "goal = eq(x, x)\nproof:\n  dead = cite(\"{ONE_ID}\")\n  broken = cite(\"{ZERO_ID}\")\n  root = gen(broken, x)\n  return root"
    );
    assert_check_diagnostic_origin(
        &unreachable,
        "broken",
        &format!("broken = cite(\"{ZERO_ID}\")"),
    );

    let reordered = "goal = eq(x, x)\nproof:\n  a0 = refl(x)\n  a1 = simp(eq(x, x), eq(x, x))\n  broken_result = mp(a1, a0)\n  b0 = refl(y)\n  root = mp(b0, broken_result)\n  return root";
    assert_check_diagnostic_origin(reordered, "broken_result", "broken_result = mp(a1, a0)");

    let interned = format!(
        "goal = eq(x, x)\nproof:\n  p0 = cite(\"{ZERO_ID}\")\n  p1 = cite(\"{ZERO_ID}\")\n  root = mp(p1, p0)\n  return root"
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
    let first = compile_artifact("def first = relation(x,): eq(x, x)").unwrap();
    let renamed =
        compile_artifact("def presentation_only = relation(value): eq(value, value)").unwrap();
    assert_eq!(first, renamed);

    let formulas = "let: helper = eq(x, x) def relation_name = relation(x): eq(x, x)";
    assert!(matches!(
        compile_artifact(formulas),
        Err(CompileError::Syntax {
            expected: "a proof statement after formula bindings",
            ..
        })
    ));
    for duplicate in [
        "def bad = relation(x, x): eq(x, x)",
        "def bad = function(x, x): eq(x, x)",
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
    let relation = compile_artifact("def r = relation(x, y): eq(x, y)").unwrap();
    assert!(matches!(relation, CompiledArtifact::Definition(_)));

    let function =
        compile_artifact("def f = function(input, output): eq(output, input)").unwrap_err();
    assert!(matches!(
        function,
        CompileError::DefinitionCheck { source, .. }
            if matches!(
                source.as_ref(),
                DefinitionCheckError::UnknownObligationStatement { statement_id }
                    if *statement_id == StatementId::from_bytes(hex32(
                        "31a017582bf7e6314670d35aeb7d206d060a12bc4df139163297a139161e01a1"
                    ))
            )
    ));

    for removed in [
        "def c = constant(value): eq(value, value)",
        "def f = function(input, output, obligation = \"0000000000000000000000000000000000000000000000000000000000000000\"): eq(output, input)",
    ] {
        assert!(matches!(
            compile_artifact(removed),
            Err(CompileError::Syntax { .. })
        ));
    }
}

#[test]
fn definition_parameter_lists_stop_at_the_canonical_graph_arity_bound() {
    assert!(matches!(
        compile_artifact("def empty = relation(): eq(x, x)"),
        Err(CompileError::Definition {
            source: DefinitionCertificateError::ZeroRelationArity,
            ..
        })
    ));

    let parameters = (0..=DEFINITION_MAX_GRAPH_ARITY)
        .map(|identifier| format!("p{identifier}"))
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!("def too_wide = relation({parameters}): eq(p0, p0)");
    let error = compile_artifact(&source).unwrap_err();
    assert!(matches!(
        &error,
        CompileError::Definition {
            source: DefinitionCertificateError::ArityTooLarge {
                actual,
                maximum: DEFINITION_MAX_GRAPH_ARITY,
            },
            ..
        } if *actual == u64::from(DEFINITION_MAX_GRAPH_ARITY) + 1
    ));
    let span = error.diagnostic(&source).primary_span().unwrap();
    assert_eq!(&source[span.start()..span.end()], "p256");
}

#[test]
fn definition_names_cannot_create_self_or_forward_authority() {
    assert!(matches!(
        compile_artifact(
            "def recursive = relation(x): recursive(x)"
        ),
        Err(CompileError::UnknownDefinitionAlias { name, .. }) if name == "recursive"
    ));
    assert!(matches!(
        compile_artifact(
            "defs: future = \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\" def current = relation(x): future(x)"
        ),
        Err(CompileError::DefinitionNotSelected { .. })
    ));
}

#[test]
fn term_sugar_relationalizes_unary_nested_and_multi_input_calls_exactly_once() {
    let identity_id = DefinitionId::from_bytes([0x51; 32]);
    let binary_id = DefinitionId::from_bytes([0x52; 32]);

    let parse = |source: &'static str| {
        let mut parser = Parser::new(source);
        parser.definition_aliases.insert(
            "identity",
            DefinitionAlias {
                definition_id: identity_id,
                kind: DefinitionKind::Function { input_arity: 1 },
            },
        );
        parser.definition_aliases.insert(
            "binary",
            DefinitionAlias {
                definition_id: binary_id,
                kind: DefinitionKind::Function { input_arity: 2 },
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
    assert_eq!(parse("eq(identity(x), x)"), unary);

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
    assert_eq!(parse("eq(identity(identity(x)), x)"), nested);

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
    assert_eq!(parse("eq(binary(x, identity(y)), y)"), multi_input);
}
