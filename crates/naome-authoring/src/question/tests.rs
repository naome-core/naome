use super::*;

fn source(formula: &str) -> String {
    format!("foundation = \"naome:zfc\"\nstatement = {formula}\n")
}
fn compile(formula: &str) -> CompiledQuestion {
    CompiledQuestion::compile(&source(formula)).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn canonical_closed_formula_and_resolution_golden() {
    let question = compile("forall(x, equal(x,x))");
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
    let plain = compile("forall(x,equal(x,x))");
    let alpha = compile("forall(y,equal(y,y))");
    let odd = compile("not_(forall(x,equal(x,x)))");
    let even = compile("not_(not_(forall(x,equal(x,x))))");
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
    let question = compile("forall(x,equal(x,x))");
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
        "# Proof obligation A: universally quantified self-equality.\nfoundation = \"naome:zfc\"\nstatement = forall(y, forall(x, equal(x, x)))\n",
    )
    .unwrap();
    let b = CompiledQuestion::compile(
        "# Proof obligation B: negative orientation; solution-b.nao refutes this.\nfoundation = \"naome:zfc\"\nstatement = not_(implies(forall(x, equal(x, x)), forall(x, equal(x, x))))\n",
    )
    .unwrap();
    let c = CompiledQuestion::compile(
        "# Proof obligation C is exactly helper H, already known after A settles.\nfoundation = \"naome:zfc\"\nstatement = forall(x, equal(x, x))\n",
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
        ("not_equal(x,x)", Formula::negate(atom.clone())),
        (
            "and_(equal(x,x),member(x,x))",
            Formula::conjunction(atom.clone(), Formula::member(x, x)),
        ),
        (
            "or_(equal(x,x),member(x,x))",
            Formula::disjunction(atom.clone(), Formula::member(x, x)),
        ),
        (
            "iff(equal(x,x),member(x,x))",
            Formula::biconditional(atom.clone(), Formula::member(x, x)),
        ),
        (
            "exists(y,equal(x,y))",
            Formula::exists(
                FreeVariable::new(1),
                Formula::equal(x, FreeVariable::new(1)),
            ),
        ),
    ] {
        let question = compile(&format!("forall(x,{expression})"));
        assert_eq!(question.formula(), &Formula::for_all(x, formula));
    }
}

#[test]
fn trivia_trailing_comma_and_explicit_resolve_policy() {
    let input = "# research\nfoundation = \"naome:zfc\"\n statement = forall(x, equal(x,x,),) # target\nsuccess = \"resolve\"\n";
    let question = CompiledQuestion::compile(input).unwrap();
    assert_eq!(
        question.resolution_id(),
        compile("forall(y,equal(y,y))").resolution_id()
    );
}

#[test]
fn rejects_free_variables_assumptions_imports_and_bad_syntax() {
    for input in [
        source("equal(x,x)"),
        source("forall(x, equal(x,y))"),
        source("forall(x, unknown(x))"),
        source("forall(x, equal(f(x),x))"),
        source("forall(x, equal(x,x),,)"),
        source("forall(x, equal(x,x)) garbage"),
        source("forall(x, equal(x,x)) success = \"prove\""),
        "foundation = \"other\" statement = forall(x,equal(x,x))".to_owned(),
        "foundation = \"naome:zfc\" assumptions = [] statement = forall(x,equal(x,x))".to_owned(),
        "foundation = \"naome:zfc\" definitions: h = \"abc\" statement = h(x)".to_owned(),
        "foundation = \"naome:zfc\" references = [] statement = forall(x,equal(x,x))".to_owned(),
        "foundation = \"naome:zfc\" statement = forall(x,equal(x,x)) limits = {target_nodes: 2}"
            .to_owned(),
        "foundation = \"naome:zfc\" statement = forall(x,equal(x,x)) allow_substitution = false"
            .to_owned(),
        source("forall(x,equal(x,x)) proof: return p"),
    ] {
        assert!(
            CompiledQuestion::compile(&input).is_err(),
            "accepted {input}"
        );
    }
}

#[test]
fn target_depth_counts_added_negative_target_and_ignores_removed_prefix() {
    let mut body = "equal(x,x)".to_owned();
    for _ in 0..30 {
        body = format!("forall(x,{body})");
    }
    assert!(CompiledQuestion::compile(&source(&body)).is_ok());
    let too_deep = format!("forall(x,{body})");
    assert_eq!(
        CompiledQuestion::compile(&source(&too_deep)),
        Err(QuestionError::Limit("question target depth"))
    );
    // Leading input negations do not increase either canonical target depth.
    for _ in 0..40 {
        body = format!("not_({body})");
    }
    assert!(CompiledQuestion::compile(&source(&body)).is_ok());
}

#[test]
fn bounded_expansion_rejects_exponential_iff_and_deep_source() {
    let mut formula = "equal(x,x)".to_owned();
    for _ in 0..20 {
        formula = format!("iff(equal(x,x),{formula})");
    }
    assert!(matches!(
        CompiledQuestion::compile(&source(&format!("forall(x,{formula})"))),
        Err(QuestionError::Limit(_))
    ));
    let deep = format!(
        "{}forall(x,equal(x,x)){}",
        "not_(".repeat(300),
        ")".repeat(300)
    );
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
            return "equal(x,x)".to_owned();
        }
        let left = leaves / 2;
        format!("implies({},{})", tree(left), tree(leaves - left))
    }
    // 511 leaves + 510 implications + 2 quantifiers = 1023 core nodes;
    // the negative target has exactly 1024.
    let exact = source(&format!("forall(y,forall(x,{}))", tree(511)));
    assert!(CompiledQuestion::compile(&exact).is_ok());
    // 512 leaves + 511 implications + 1 quantifier = 1024 core nodes;
    // the negative target exceeds the ceiling by one.
    let excessive = source(&format!("forall(x,{})", tree(512)));
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
    let question = compile("forall(x,not_equal(x,x))");
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

    let proof = checked(include_str!("../../../../examples/self-equality.nao"));
    let question = compile("forall(x,equal(x,x))");
    let alpha = compile("forall(y,equal(y,y))");
    let negative = compile("not_(forall(x,equal(x,x)))");
    let twice_negative = compile("not_(not_(forall(x,equal(x,x))))");
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
        "../../../../examples/implication-identity.nao"
    ));
    assert!(question.classify_checked_proof(&unrelated).is_err());
    let unrelated_question = compile("forall(x,member(x,x))");
    assert!(unrelated_question.classify_checked_proof(&proof).is_err());
}
