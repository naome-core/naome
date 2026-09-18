use super::*;
use crate::profile::{Limits, TimingKind};

fn source(formula: &str) -> String {
    format!("foundation = \"naome:zfc\"\nstatement = {formula}\n")
}
fn compile(formula: &str) -> CompiledQuestion {
    CompiledQuestion::compile(&source(formula), &Profile::lab()).unwrap()
}
fn context() -> QuestionContext {
    QuestionContext {
        genesis: GenesisId::from_bytes([1; 32]),
        profile: Profile::lab().id(),
        checker: checker_profile_id("naome-checker-v1"),
        library_root: [2; 32],
        author: AccountId::from_bytes([3; 32]),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn canonical_closed_formula_and_resolution_golden() {
    let question = compile("forall(x, equal(x,x))");
    assert_eq!(hex(question.canonical_core()), "040001000000000100000000");
    assert_eq!(
        hex(question.resolution_id().as_bytes()),
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
    assert_ne!(
        alpha.question_id(context(), "purpose").unwrap(),
        plain.question_id(context(), "purpose").unwrap()
    );
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
        CompiledQuestion::from_canonical_bytes(&bytes, &Profile::lab()).unwrap(),
        question
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        CompiledQuestion::from_canonical_bytes(&trailing, &Profile::lab()),
        Err(ResearchError::TrailingBytes)
    );
    let mut unknown = bytes.clone();
    unknown[0] = 2;
    assert!(CompiledQuestion::from_canonical_bytes(&unknown, &Profile::lab()).is_err());
    for end in 0..bytes.len() {
        assert!(CompiledQuestion::from_canonical_bytes(&bytes[..end], &Profile::lab()).is_err());
    }
}

#[test]
fn actual_acceptance_fixture_questions_compile() {
    let a = CompiledQuestion::compile(
        include_str!("../../../../examples/research-mvp/question-a.nao"),
        &Profile::lab(),
    )
    .unwrap();
    let b = CompiledQuestion::compile(
        include_str!("../../../../examples/research-mvp/question-b.nao"),
        &Profile::lab(),
    )
    .unwrap();
    let c = CompiledQuestion::compile(
        include_str!("../../../../examples/research-mvp/question-c.nao"),
        &Profile::lab(),
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
    let question = CompiledQuestion::compile(input, &Profile::lab()).unwrap();
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
        source("forall(x,equal(x,x)) proof: return p"),
    ] {
        assert!(
            CompiledQuestion::compile(&input, &Profile::lab()).is_err(),
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
    assert!(CompiledQuestion::compile(&source(&body), &Profile::lab()).is_ok());
    let too_deep = format!("forall(x,{body})");
    assert_eq!(
        CompiledQuestion::compile(&source(&too_deep), &Profile::lab()),
        Err(ResearchError::Limit("question target depth"))
    );
    // Leading input negations do not increase either canonical target depth.
    for _ in 0..40 {
        body = format!("not_({body})");
    }
    assert!(CompiledQuestion::compile(&source(&body), &Profile::lab()).is_ok());
}

#[test]
fn bounded_expansion_rejects_exponential_iff_and_deep_source() {
    let mut formula = "equal(x,x)".to_owned();
    for _ in 0..20 {
        formula = format!("iff(equal(x,x),{formula})");
    }
    assert!(matches!(
        CompiledQuestion::compile(&source(&format!("forall(x,{formula})")), &Profile::lab()),
        Err(ResearchError::Limit(_))
    ));
    let deep = format!(
        "{}forall(x,equal(x,x)){}",
        "not_(".repeat(300),
        ")".repeat(300)
    );
    assert!(matches!(
        CompiledQuestion::compile(&source(&deep), &Profile::lab()),
        Err(ResearchError::Limit(_))
    ));
    assert_eq!(
        CompiledQuestion::compile(&" ".repeat(QUESTION_SOURCE_MAX_BYTES + 1), &Profile::lab()),
        Err(ResearchError::Limit("question source bytes"))
    );
}

#[test]
fn profile_smaller_bounds_are_enforced_for_both_targets() {
    let nodes = Profile::with_limits(
        TimingKind::Lab,
        Limits {
            target_nodes: 2,
            target_depth: 2,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(
        CompiledQuestion::compile(&source("forall(x,equal(x,x))"), &nodes),
        Err(ResearchError::Limit("question target nodes"))
    );
    let depth = Profile::with_limits(
        TimingKind::Lab,
        Limits {
            target_depth: 2,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(
        CompiledQuestion::compile(&source("forall(x,equal(x,x))"), &depth),
        Err(ResearchError::Limit("question target depth"))
    );
    let bytes = Profile::with_limits(
        TimingKind::Lab,
        Limits {
            question_source_bytes: 8,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(CompiledQuestion::compile(&source("forall(x,equal(x,x))"), &bytes).is_err());
}

#[test]
fn every_opening_context_component_affects_question_id() {
    let question = compile("forall(x,equal(x,x))");
    let original = context();
    let id = question.question_id(original, "purpose").unwrap();
    let mut changed = original;
    changed.genesis = GenesisId::from_bytes([4; 32]);
    assert_ne!(id, question.question_id(changed, "purpose").unwrap());
    changed = original;
    changed.profile = ProfileId::from_bytes([4; 32]);
    assert_eq!(
        question.question_id(changed, "purpose"),
        Err(ResearchError::Invalid(
            "question compilation profile mismatch"
        ))
    );
    changed = original;
    changed.checker = checker_profile_id("other-checker");
    assert_ne!(id, question.question_id(changed, "purpose").unwrap());
    changed = original;
    changed.library_root = [4; 32];
    assert_ne!(id, question.question_id(changed, "purpose").unwrap());
    changed = original;
    changed.author = AccountId::from_bytes([4; 32]);
    assert_ne!(id, question.question_id(changed, "purpose").unwrap());
    assert_ne!(
        id,
        question.question_id(original, "different purpose").unwrap()
    );
}

#[test]
fn solution_round_uses_finalized_approval_and_nonzero_attempt() {
    let c = context();
    let q = compile("forall(x,equal(x,x))")
        .question_id(c, "purpose")
        .unwrap();
    let approval = RecordId::from_bytes([7; 32]);
    let id = solution_round_id(c.genesis, q, 1, approval).unwrap();
    assert_ne!(id, solution_round_id(c.genesis, q, 2, approval).unwrap());
    assert_ne!(
        id,
        solution_round_id(c.genesis, q, 1, RecordId::from_bytes([8; 32])).unwrap()
    );
    assert!(solution_round_id(c.genesis, q, 0, approval).is_err());
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
    assert!(CompiledQuestion::compile(&exact, &Profile::lab()).is_ok());
    // 512 leaves + 511 implications + 1 quantifier = 1024 core nodes;
    // the negative target exceeds the ceiling by one.
    let excessive = source(&format!("forall(x,{})", tree(512)));
    assert_eq!(
        CompiledQuestion::compile(&excessive, &Profile::lab()),
        Err(ResearchError::Limit("question target nodes"))
    );
}

#[test]
fn source_decoder_rejects_bad_utf8_and_oversized_declared_length() {
    assert!(
        CompiledQuestion::from_canonical_bytes(&[1, 0, 0, 0, 1, 255], &Profile::lab()).is_err()
    );
    assert!(
        CompiledQuestion::from_canonical_bytes(&[1, 255, 255, 255, 255], &Profile::lab()).is_err()
    );
}
