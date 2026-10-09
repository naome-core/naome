use super::*;

fn source(formula: &str) -> String {
    format!("goal = {formula}\n")
}
fn compile(formula: &str) -> CompiledQuestion {
    CompiledQuestion::compile(&source(formula)).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn canonical_closed_formula_and_resolution_golden() {
    let question = compile("all(x, eq(x,x))");
    assert_eq!(hex(question.canonical_core()), "040001000000000100000000");
    assert_eq!(
        hex(question.resolution_id()),
        "8cb7976f42b68e2ecd89e610bac06630c872ae961b02a8863ef3712e89583dcf"
    );
    let x = FreeVariable::new(987);
    assert_eq!(question.core(), &Formula::for_all(x, Formula::equal(x, x)));
    assert_eq!(
        question.negative_target(),
        &Formula::negate(question.core().clone())
    );
}

#[test]
fn alpha_and_leading_negations_share_family_but_keep_orientation() {
    let plain = compile("all(x,eq(x,x))");
    let alpha = compile("all(y,eq(y,y))");
    let odd = compile("not(all(x,eq(x,x)))");
    let even = compile("not(not(all(x,eq(x,x))))");
    for question in [&alpha, &odd, &even] {
        assert_eq!(question.resolution_id(), plain.resolution_id());
        assert_eq!(question.canonical_core(), plain.canonical_core());
    }
    assert!(!plain.negation_parity());
    assert!(odd.negation_parity());
    assert!(!even.negation_parity());
    assert_eq!(odd.proved_target(), plain.refuted_target());
    assert_eq!(odd.refuted_target(), plain.proved_target());
    assert_ne!(alpha.source_hash(), plain.source_hash());
}

#[test]
fn source_codec_golden_and_strict_recompilation() {
    let question = compile("all(x,eq(x,x))");
    let bytes = question.to_canonical_bytes().unwrap();
    assert_eq!(bytes[0], 1);
    assert_eq!(
        &bytes[1..5],
        &(question.source().len() as u32).to_be_bytes()
    );
    assert_eq!(&bytes[5..], question.source().as_bytes());
    assert_eq!(
        CompiledQuestion::from_canonical_bytes(&bytes).unwrap(),
        question
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        CompiledQuestion::from_canonical_bytes(&trailing),
        Err(QuestionError::TrailingBytes)
    );
    let mut unknown = bytes.clone();
    unknown[0] = 2;
    assert!(CompiledQuestion::from_canonical_bytes(&unknown).is_err());
    for end in 0..bytes.len() {
        assert!(CompiledQuestion::from_canonical_bytes(&bytes[..end]).is_err());
    }
}

#[test]
fn existing_closed_question_sources_compile() {
    let a = CompiledQuestion::compile(
        "# Proof obligation A: universally quantified self-equality.\ngoal = all(y, all(x, eq(x, x)))\n",
    )
    .unwrap();
    let b = CompiledQuestion::compile(
        "# Proof obligation B: negative orientation; solution-b.nao refutes this.\ngoal = not(imp(all(x, eq(x, x)), all(x, eq(x, x))))\n",
    )
    .unwrap();
    let c = CompiledQuestion::compile(
        "# Proof obligation C is exactly helper H, already known after A settles.\ngoal = all(x, eq(x, x))\n",
    )
    .unwrap();
    assert!(!a.negation_parity());
    assert!(b.negation_parity());
    assert_ne!(a.resolution_id(), b.resolution_id());
    assert_ne!(a.resolution_id(), c.resolution_id());
    assert_ne!(b.resolution_id(), c.resolution_id());
}

#[test]
fn derived_notation_matches_foundation_constructors() {
    let x = FreeVariable::new(0);
    let atom = Formula::equal(x, x);
    for (expression, formula) in [
        ("ne(x,x)", Formula::negate(atom.clone())),
        (
            "and(eq(x,x),mem(x,x))",
            Formula::conjunction(atom.clone(), Formula::member(x, x)),
        ),
        (
            "or(eq(x,x),mem(x,x))",
            Formula::disjunction(atom.clone(), Formula::member(x, x)),
        ),
        (
            "iff(eq(x,x),mem(x,x))",
            Formula::biconditional(atom.clone(), Formula::member(x, x)),
        ),
        (
            "ex(y,eq(x,y))",
            Formula::exists(
                FreeVariable::new(1),
                Formula::equal(x, FreeVariable::new(1)),
            ),
        ),
    ] {
        let question = compile(&format!("all(x,{expression})"));
        assert_eq!(question.formula(), &Formula::for_all(x, formula));
    }
}

#[test]
fn trivia_trailing_comma_and_explicit_resolve_policy() {
    let input = "# research\ngoal = all(x, eq(x,x,),) # target\nsuccess = \"resolve\"\n";
    let question = CompiledQuestion::compile(input).unwrap();
    assert_eq!(
        question.resolution_id(),
        compile("all(y,eq(y,y))").resolution_id()
    );
}

#[test]
fn rejects_free_variables_assumptions_imports_and_bad_syntax() {
    for input in [
        source("eq(x,x)"),
        source("all(x, eq(x,y))"),
        source("all(x, unknown(x))"),
        source("all(x, eq(f(x),x))"),
        source("all(x, eq(x,x),,)"),
        source("all(x, eq(x,x)) garbage"),
        source("all(x, eq(x,x)) success = \"prove\""),
        "foundation = \"other\" goal = all(x,eq(x,x))".to_owned(),
        "assumptions = [] goal = all(x,eq(x,x))".to_owned(),
        "defs: h = \"abc\" goal = h(x)".to_owned(),
        "references = [] goal = all(x,eq(x,x))".to_owned(),
        "goal = all(x,eq(x,x)) limits = {target_nodes: 2}".to_owned(),
        "goal = all(x,eq(x,x)) allow_substitution = false".to_owned(),
        source("all(x,eq(x,x)) proof: return p"),
    ] {
        assert!(
            CompiledQuestion::compile(&input).is_err(),
            "accepted {input}"
        );
    }
}

#[test]
fn target_depth_counts_added_negative_target_and_ignores_removed_prefix() {
    let mut body = "eq(x,x)".to_owned();
    for _ in 0..30 {
        body = format!("all(x,{body})");
    }
    assert!(CompiledQuestion::compile(&source(&body)).is_ok());
    let too_deep = format!("all(x,{body})");
    assert_eq!(
        CompiledQuestion::compile(&source(&too_deep)),
        Err(QuestionError::Limit("question target depth"))
    );
    // Leading input negations do not increase either canonical target depth.
    for _ in 0..40 {
        body = format!("not({body})");
    }
    assert!(CompiledQuestion::compile(&source(&body)).is_ok());
}

#[test]
fn bounded_expansion_rejects_exponential_iff_and_deep_source() {
    let mut formula = "eq(x,x)".to_owned();
    for _ in 0..20 {
        formula = format!("iff(eq(x,x),{formula})");
    }
    assert!(matches!(
        CompiledQuestion::compile(&source(&format!("all(x,{formula})"))),
        Err(QuestionError::Limit(_))
    ));
    let deep = format!("{}all(x,eq(x,x)){}", "not(".repeat(300), ")".repeat(300));
    assert!(matches!(
        CompiledQuestion::compile(&source(&deep)),
        Err(QuestionError::Limit(_))
    ));
    assert_eq!(
        CompiledQuestion::compile(&" ".repeat(QUESTION_SOURCE_MAX_BYTES + 1)),
        Err(QuestionError::Limit("question source bytes"))
    );
}

#[test]
fn nominal_node_boundary_applies_to_the_larger_target() {
    fn tree(leaves: usize) -> String {
        if leaves == 1 {
            return "eq(x,x)".to_owned();
        }
        let left = leaves / 2;
        format!("imp({},{})", tree(left), tree(leaves - left))
    }
    // 511 leaves + 510 implications + 2 quantifiers = 1023 core nodes;
    // the negative target has exactly 1024.
    let exact = source(&format!("all(y,all(x,{}))", tree(511)));
    assert!(CompiledQuestion::compile(&exact).is_ok());
    // 512 leaves + 511 implications + 1 quantifier = 1024 core nodes;
    // the negative target exceeds the ceiling by one.
    let excessive = source(&format!("all(x,{})", tree(512)));
    assert_eq!(
        CompiledQuestion::compile(&excessive),
        Err(QuestionError::Limit("question target nodes"))
    );
}

#[test]
fn source_decoder_rejects_bad_utf8_and_oversized_declared_length() {
    assert!(CompiledQuestion::from_canonical_bytes(&[1, 0, 0, 0, 1, 255]).is_err());
    assert!(CompiledQuestion::from_canonical_bytes(&[1, 255, 255, 255, 255]).is_err());
}

#[test]
fn well_formedness_does_not_assert_mathematical_truth() {
    let question = compile("all(x,ne(x,x))");
    let x = FreeVariable::new(0);
    assert_eq!(
        question.formula(),
        &Formula::for_all(x, Formula::negate(Formula::equal(x, x)))
    );
}

#[test]
fn checked_proof_matches_exact_targets_with_original_negation_orientation() {
    use naome_checker::{CheckedProof, normalize_and_check};
    use naome_proof::ProofCertificate;

    fn checked(source: &str) -> CheckedProof {
        let compiled = crate::compile(source).unwrap();
        let certificate =
            ProofCertificate::from_canonical_bytes(compiled.canonical_proof_bytes()).unwrap();
        let checked = normalize_and_check(certificate).unwrap();
        assert_eq!(
            checked.normal_form().canonical_bytes(),
            compiled.canonical_proof_bytes()
        );
        checked
    }

    let proof = checked(include_str!("../../tests/fixtures/self-equality.nao"));
    let question = compile("all(x,eq(x,x))");
    let alpha = compile("all(y,eq(y,y))");
    let negative = compile("not(all(x,eq(x,x)))");
    let twice_negative = compile("not(not(all(x,eq(x,x))))");
    assert_eq!(
        question.classify_checked_proof(&proof),
        Ok(QuestionOutcome::Proved)
    );
    assert_eq!(
        alpha.classify_checked_proof(&proof),
        Ok(QuestionOutcome::Proved)
    );
    assert_eq!(
        negative.classify_checked_proof(&proof),
        Ok(QuestionOutcome::Refuted)
    );
    assert_eq!(
        twice_negative.classify_checked_proof(&proof),
        Ok(QuestionOutcome::Proved)
    );

    let unrelated = checked(include_str!(
        "../../tests/fixtures/implication-identity.nao"
    ));
    assert!(question.classify_checked_proof(&unrelated).is_err());
    let unrelated_question = compile("all(x,mem(x,x))");
    assert!(unrelated_question.classify_checked_proof(&proof).is_err());
}

#[test]
fn unsupported_operator_diagnostic_marks_the_original_name_before_its_call() {
    for operator in ["satisfies", "equal", "forall"] {
        let source = format!("# original UTF8 ä\r\ngoal=all(x,{operator}(x,x))");
        let error = CompiledQuestion::compile_with_diagnostic(&source).unwrap_err();
        assert_eq!(error.diagnostic().code(), DiagnosticCode::QuestionSyntax);
        let span = error.diagnostic().primary_span().unwrap();
        assert_eq!(&source[span.start()..span.end()], operator);
        assert_eq!(span.start(), source.find(operator).unwrap());
    }
}
