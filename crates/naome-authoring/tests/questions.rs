use naome_authoring::validate_question_against_proof_context as validate;
use naome_checker::ArtifactState;

#[test]
fn closed_questions_reuse_real_authoring_without_a_dummy_proof() {
    let targets = [
        "forall(x, forall(y, implies(equal(x, y), equal(y, x))))",
        "forall(x, forall(y, forall(z, implies(and_(member(x,y), member(y,z)), member(x,z)))))",
        "forall(x, forall(y, implies(forall(z, iff(member(z,x), member(z,y))), equal(x,y))))",
        "forall(x, exists(y, forall(z, iff(member(z,y), or_(equal(z,x), equal(z,y))))))",
        "forall(x, exists(y, forall(z, iff(member(z,y), and_(member(z,x), not_(equal(z,x)))))))",
        "forall(x, forall(y, implies(equal(x,y), forall(z, iff(member(x,z), member(y,z))))))",
    ];
    for (i, target) in targets.iter().enumerate() {
        let source = format!("foundation = \"naome:zfc\"\nquestion = {target}\n");
        let question = validate(&source, &ArtifactState::new()).unwrap();
        assert!(question.formula().is_closed());
        assert_eq!(
            question.canonical_bytes(),
            question.formula().encode_canonical().unwrap()
        );
        println!(
            "sample={i} source={source:?} canonical={:?}",
            question.canonical_bytes()
        );
    }
}

#[test]
fn invalid_open_unchecked_context_and_extra_answer_are_guard_rejections() {
    let bad = [
        "foundation = \"other\"\nquestion = forall(x,equal(x,x))",
        "foundation = \"naome:zfc\"\nquestion = equal(x,x)",
        "foundation = \"naome:zfc\"\nquestion = forall(x,unknown(x))",
        "foundation = \"naome:zfc\"\nquestion = forall(x,equal(x,x))\nproof: p0 = equality_reflexivity(x) return p0",
        "foundation = \"naome:zfc\"\ndefinitions:\n r = \"0000000000000000000000000000000000000000000000000000000000000000\"\nquestion = forall(x,r(x))",
    ];
    for source in bad {
        assert!(validate(source, &ArtifactState::new()).is_err(), "{source}");
    }
}

#[test]
fn question_binding_and_binder_names_do_not_change_canonical_identity() {
    let a = validate(
        "foundation = \"naome:zfc\"\nquestion = forall(x,equal(x,x))",
        &ArtifactState::new(),
    )
    .unwrap();
    let b=validate("foundation = \"naome:zfc\"\nformulas:\n p = forall(renamed,equal(renamed,renamed))\nquestion = p",&ArtifactState::new()).unwrap();
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
}

#[test]
fn questions_expand_only_checked_definitions_and_keep_legacy_question_alias() {
    use naome_authoring::{CompiledArtifact, compile, compile_artifact};
    use naome_checker::check_definition_with_state;
    use naome_proof::DefinitionCertificate;
    let CompiledArtifact::Definition(definition) =
        compile_artifact(include_str!("../../../examples/membership-relation.nao")).unwrap()
    else {
        panic!("definition");
    };
    let mut state = ArtifactState::new();
    let certificate =
        DefinitionCertificate::from_canonical_bytes(definition.canonical_definition_bytes())
            .unwrap();
    let checked = check_definition_with_state(certificate, &state).unwrap();
    state.register_definition(checked).unwrap();
    let id = definition
        .definition_id()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let source = format!(
        "foundation = \"naome:zfc\"\ndefinitions:\n holds = \"{id}\"\nquestion = forall(x,forall(y,holds(x,y)))"
    );
    let parsed = validate(&source, &state).unwrap();
    let primitive = validate(
        "foundation = \"naome:zfc\"\nquestion = forall(x,forall(y,member(x,y)))",
        &state,
    )
    .unwrap();
    assert_eq!(parsed.canonical_bytes(), primitive.canonical_bytes());
    assert_eq!(parsed.definition_ids(), &[definition.definition_id()]);
    assert!(validate(&source, &ArtifactState::new()).is_err());
    assert!(validate(&source.replace("holds(x,y)", "holds(x)"), &state).is_err());
    assert!(validate(&source.replace(" holds =", " question ="), &state).is_err());
    // Existing proof syntax keeps this presentation alias valid.
    let legacy = format!(
        "foundation = \"naome:zfc\"\ndefinitions:\n question = \"{id}\"\nstatement = implies(forall(x,forall(y,question(x,y))), implies(forall(x,forall(y,question(x,y))), forall(x,forall(y,question(x,y)))))\nproof:\n p0 = simplification(forall(x,forall(y,question(x,y))), forall(x,forall(y,question(x,y))))\n return p0"
    );
    compile_against(&legacy, &state);
    let _ = compile(include_str!("../../../examples/self-equality.nao")).unwrap();
    fn compile_against(source: &str, state: &ArtifactState) {
        let _ = naome_authoring::compile_against_proof_context(source, state).unwrap();
    }
}

fn function_context() -> (ArtifactState, String) {
    use naome_authoring::{
        CompiledArtifact, compile_against_proof_context, compile_artifact_against_proof_context,
    };
    use naome_checker::{check_definition_with_state, normalize_and_check_with_state};
    use naome_proof::{DefinitionCertificate, ProofCertificate};
    let mut state = ArtifactState::new();
    let proof = compile_against_proof_context(
        include_str!("../../../examples/identity-function-obligation.nao"),
        &state,
    )
    .unwrap();
    let certificate =
        ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    state
        .register_proof_for_replication(
            normalize_and_check_with_state(certificate, &ArtifactState::new()).unwrap(),
        )
        .unwrap();
    let CompiledArtifact::Definition(definition) = compile_artifact_against_proof_context(
        include_str!("../../../examples/identity-function.nao"),
        &state,
    )
    .unwrap() else {
        panic!("definition");
    };
    let certificate =
        DefinitionCertificate::from_canonical_bytes(definition.canonical_definition_bytes())
            .unwrap();
    let checked = check_definition_with_state(certificate, &state).unwrap();
    state.register_definition(checked).unwrap();
    let id = definition
        .definition_id()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    (state, id)
}
#[test]
fn function_term_recursion_guard_runs_in_an_isolated_process() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "function_term_recursion_child", "--nocapture"])
        .env("NAOME_QUESTION_TERM_GUARD_CHILD", "1")
        .status()
        .unwrap();
    assert!(
        status.success(),
        "isolated parser guard process failed: {status}"
    );
}
#[test]
fn function_term_recursion_child() {
    if std::env::var_os("NAOME_QUESTION_TERM_GUARD_CHILD").is_none() {
        return;
    }
    use naome_authoring::CompileError;
    use naome_foundation::FORMULA_MAX_DEPTH;
    let (state, id) = function_context();
    let target = |count: usize| {
        let term = format!("{}x{}", "f(".repeat(count), ")".repeat(count));
        format!(
            "foundation = \"naome:zfc\"\ndefinitions:\n f = \"{id}\"\nquestion = forall(x,equal({term},x))"
        )
    };
    let _ = validate(&target(1), &state).unwrap();
    // The shared lowering adds six primitive levels per nested function.
    let boundary = (FORMULA_MAX_DEPTH as usize - 4) / 6;
    let _ = validate(&target(boundary), &state).unwrap();
    assert!(validate(&target(boundary + 1), &state).is_err());
    let excessive = target(5000);
    assert!(excessive.len() < 65536);
    assert!(matches!(
        validate(&excessive, &state),
        Err(CompileError::FormulaDepthLimitExceeded { .. })
    ));
    assert!(validate(&target(1), &ArtifactState::new()).is_err());
}
