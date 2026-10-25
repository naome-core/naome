use crate::{compile, compile_against_proof_context, inspect_source};
use naome_checker::{
    ArtifactState,
    diagnostics::{
        Digest, ExpansionKind, Failure, FormulaNode, FormulaQuery, InspectionError,
        OperandRole as R, PathSegment, Variable,
    },
};

const SWAPPED: &str = "# ä\r\ngoal=all(x,imp(eq(x,x),eq(x,x)))\nproof:\n a=refl(x)\n b=simp(eq(x,x),eq(x,x))\n c=mp(b,a)\n d=gen(c,x)\n return d";

#[test]
fn public_error_retains_exact_source_rule_arguments_and_the_original_target() {
    let error = compile(SWAPPED).unwrap_err();
    let diagnostic = error.diagnostic();
    let report = diagnostic.proof().unwrap();
    assert_eq!(
        report.failure,
        Failure::ExpectedImplication {
            operand: R::Implication
        }
    );
    assert_eq!(diagnostic.source_digest(), Digest::of(SWAPPED.as_bytes()));
    assert_eq!(report.input.source_digest, Some(diagnostic.source_digest()));
    let span = diagnostic.operand_span().unwrap();
    assert_eq!(&SWAPPED[span.start()..span.end()], "a");
    let origin = &report.location.origins[0];
    assert_eq!(origin.name, "c");
    assert_eq!(
        &SWAPPED[origin.assignment.start as usize..origin.assignment.end as usize],
        "c=mp(b,a)"
    );
    let argument = origin
        .arguments
        .iter()
        .find(|a| a.role == R::Premise)
        .unwrap();
    assert_eq!(
        &SWAPPED[argument.range.start as usize..argument.range.end as usize],
        "b"
    );
    let fixed = compile(&SWAPPED.replace("mp(b,a)", "mp(a,b)")).unwrap();
    let target = report.target.as_ref().unwrap();
    assert_eq!(
        target.root,
        Digest(naome_proof::program::formula_hash(
            fixed.into_checked_proof().conclusion()
        ))
    );
    #[cfg(feature = "developer-tools")]
    {
        let json = serde_json::to_value(&error).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["proof"]["failure"]["code"], "mp.expected_implication");
        assert_eq!(json["operand_span"]["start"], span.start());
    }
}

#[test]
fn normalized_variables_map_back_to_their_original_source_tokens() {
    let source = "goal=all(goal_var,eq(goal_var,goal_var)) proof: a=refl(actual_var) b=simp(eq(expected_var,expected_var),eq(actual_var,actual_var)) c=mp(a,b) return c";
    let error = compile(source).unwrap_err();
    let report = error.diagnostic().proof().unwrap();
    assert_eq!(report.failure, Failure::AntecedentMismatch);
    let actual = report
        .variable_origins
        .iter()
        .find(|v| v.name_preview == "actual_var")
        .unwrap();
    let expected = report
        .variable_origins
        .iter()
        .find(|v| v.name_preview == "expected_var")
        .unwrap();
    assert_eq!(
        (actual.source_identifier, actual.normalized_identifier),
        (1, 0)
    );
    assert_eq!(
        (expected.source_identifier, expected.normalized_identifier),
        (2, 1)
    );
    assert_eq!(
        &source[actual.range.start as usize..actual.range.end as usize],
        "actual_var"
    );
    assert!(report.variable_origins_complete);
    assert_eq!(
        report.difference.as_ref().unwrap().actual.node,
        FormulaNode::Equal {
            left: Variable::Free(0),
            right: Variable::Free(0)
        }
    );
}

#[test]
fn interning_reports_all_source_occurrences_and_typed_reference_declarations() {
    let id = "00".repeat(32);
    let source = format!(
        "refs: helper=\"{id}\" goal=all(x,eq(x,x)) proof: a=cite(helper) b=cite(helper) c=mp(a,b) return c"
    );
    let error = compile(&source).unwrap_err();
    let report = error.diagnostic().proof().unwrap();
    assert_eq!(
        report
            .location
            .origins
            .iter()
            .map(|o| o.name.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
    assert!(report.location.origins_complete);
    let expansion = &report.location.origins[0].arguments[0].expansions[0];
    assert_eq!(expansion.kind, ExpansionKind::ProofReference);
    assert_eq!(expansion.proof_id, Some(Digest([0; 32])));
    assert_eq!(
        &source[expansion.usage.start as usize..expansion.usage.end as usize],
        "helper"
    );
    assert!(
        source[expansion.declaration.start as usize..expansion.declaration.end as usize]
            .starts_with("helper=")
    );
}

#[test]
fn formula_binding_expansion_edges_distinguish_a_use_from_shared_declarations() {
    let source = "let: A=eq(y,y) B=imp(A,A) goal=all(x,eq(x,x)) proof: a=refl(x) b=simp(B,eq(x,x)) c=mp(a,b) return c";
    let error = compile(source).unwrap_err();
    let report = error.diagnostic().proof().unwrap();
    let origin = &report.operand(R::Implication).unwrap().origins[0];
    let argument = origin
        .arguments
        .iter()
        .find(|a| a.role == R::Antecedent)
        .unwrap();
    assert_eq!(
        &source[argument.range.start as usize..argument.range.end as usize],
        "B"
    );
    assert!(argument.expansions_complete);
    assert_eq!(argument.expansions.len(), 3);
    assert!(
        argument
            .expansions
            .iter()
            .all(|e| e.kind == ExpansionKind::FormulaBinding)
    );
    assert_eq!(
        &source[argument.expansions[0].declaration.start as usize
            ..argument.expansions[0].declaration.end as usize],
        "B=imp(A,A)"
    );
}

#[test]
fn offending_parameters_remain_exact_beyond_the_bounded_argument_prefix() {
    let mut parameters = (0..40).map(|i| format!("p{i}")).collect::<Vec<_>>();
    parameters.push("p35".into());
    let source = format!(
        "goal=all(e,eq(e,e)) proof: broken=sep(eq(e,e),e,s,r,parameters=[{}]) return broken",
        parameters.join(",")
    );
    let error = compile(&source).unwrap_err();
    let report = error.diagnostic().proof().unwrap();
    assert!(matches!(
        report.failure,
        Failure::DuplicateParameter {
            first: 35,
            second: 40,
            ..
        }
    ));
    let origin = &report.location.origins[0];
    assert!(!origin.arguments_complete);
    for index in [35, 40] {
        assert!(origin.arguments.iter().any(|a| a.index == Some(index)));
    }
    let span = error.diagnostic().operand_span().unwrap();
    assert_eq!(span.start(), source.rfind("p35").unwrap());
}

#[test]
fn source_inspection_rechecks_and_rejects_stale_context_and_source_bindings() {
    let error = compile(SWAPPED).unwrap_err();
    let report = error.diagnostic().proof().unwrap();
    let root = report
        .operand(R::Premise)
        .unwrap()
        .formula
        .as_ref()
        .unwrap()
        .root;
    let query = FormulaQuery {
        start: None,
        operand: R::Premise,
        root,
        path: vec![PathSegment::Consequent],
        maximum_nodes: 4,
    };
    let fragment = inspect_source(SWAPPED, &ArtifactState::new(), report, &query).unwrap();
    assert!(fragment.complete);
    assert_eq!(
        fragment.root_node().unwrap().node.kind(),
        naome_checker::diagnostics::NodeKind::Implies
    );
    let target_query = FormulaQuery {
        operand: R::Target,
        root: report.target_root.unwrap(),
        start: None,
        path: vec![PathSegment::Quantified],
        maximum_nodes: 4,
    };
    let target = inspect_source(SWAPPED, &ArtifactState::new(), report, &target_query).unwrap();
    assert_eq!(target.scope_depth, Some(1));
    assert_eq!(
        target.variable_namespace,
        naome_checker::diagnostics::VariableNamespace::Source
    );
    assert_eq!(
        inspect_source(
            &format!("{SWAPPED}\n"),
            &ArtifactState::new(),
            report,
            &query
        ),
        Err(InspectionError::InputChanged)
    );
    let proof = compile("goal=all(x,eq(x,x)) proof: a=refl(x) b=gen(a,x) return b")
        .unwrap()
        .into_checked_proof();
    let mut context = ArtifactState::new();
    context.register_proof(proof).unwrap();
    assert_eq!(
        inspect_source(SWAPPED, &context, report, &query),
        Err(InspectionError::ContextChanged)
    );
}

#[test]
fn selected_definition_uses_retain_the_exact_external_definition_identity() {
    let mut context = ArtifactState::new();
    let definition = naome_checker::normalize_and_check_definition_with_state(
        naome_proof::DefinitionKind::Relation { arity: 1 },
        naome_proof::DefinedFormula::equal(
            naome_foundation::FreeVariable::new(0),
            naome_foundation::FreeVariable::new(0),
        ),
        &context,
    )
    .unwrap();
    let id = definition.definition_id();
    context.register_definition(definition).unwrap();
    let source = format!(
        "defs: same=\"{}\" goal=all(x,eq(x,x)) proof: a=refl(x) b=simp(same(y),eq(x,x)) c=mp(a,b) return c",
        Digest(*id.as_bytes())
    );
    let error = compile_against_proof_context(&source, &context).unwrap_err();
    let report = error.diagnostic().proof().unwrap();
    let argument = report.operand(R::Implication).unwrap().origins[0]
        .arguments
        .iter()
        .find(|a| a.role == R::Antecedent)
        .unwrap();
    assert_eq!(argument.expansions[0].kind, ExpansionKind::Definition);
    assert_eq!(
        argument.expansions[0].definition_id,
        Some(Digest(*id.as_bytes()))
    );
}
