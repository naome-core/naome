use super::*;
#[test]
#[ignore = "explicit observed incomplete-prerequisite regression; not fresh qualification"]
fn observed_filtered_leaf_completes_its_original_parent_within_the_total_budget() {
    let path =
        std::path::PathBuf::from(std::env::var("NAOME_LEMMA_LOOP_REGRESSION_OUTPUT").unwrap());
    assert!(!path.join("summary.json").exists());
    let input: Inputs = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/recursive-lemma-loop.json"
    ))
    .unwrap();
    let question = CompiledQuestion::compile(&input.cases[22].source).unwrap();
    assert_eq!(
        crate::hex(question.resolution_id()),
        "9a623c5e1c3837f0900970df0ebb8206b2b9428f31d83fd2a8be977385b40e11"
    );
    let (state, io) = inputs::checkpoint(211, &path.join("common-model"));
    let result = run::arm(
        &question,
        "recursive_loop",
        211,
        &state,
        &io,
        &path.join("recursive_loop"),
    );
    write(&path.join("summary.json"), &result);
    assert_eq!(result["counted_solution"], true);
}
#[test]
#[ignore = "explicit question-only preflight; never executes a model"]
fn preflight_fresh_composition_questions() {
    fn families(q: &CompiledQuestion, depth: usize, out: &mut BTreeSet<String>) {
        out.insert(curriculum::owned::family(q.proved_target()));
        if depth >= 2 {
            return;
        }
        if let Some((left, negative_right)) = q
            .formula()
            .view()
            .negated()
            .and_then(|f| f.implication_parts())
            && let Some(right) = negative_right.negated()
        {
            for part in [left.to_owned(), right.to_owned()] {
                let q = CompiledQuestion::from_formula(part).unwrap();
                families(&q, depth + 1, out);
            }
        }
    }
    let path =
        std::path::PathBuf::from(std::env::var("NAOME_COMPOSITION_PREFLIGHT_INPUT").unwrap());
    let output =
        std::path::PathBuf::from(std::env::var("NAOME_COMPOSITION_PREFLIGHT_OUTPUT").unwrap());
    assert!(!output.exists());
    let raw = std::fs::read(&path).unwrap();
    let input: Inputs = serde_json::from_slice(&raw).unwrap();
    let old: Inputs = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/recursive-lemma-loop.json"
    ))
    .unwrap();
    let mut previous = BTreeSet::new();
    for case in old.cases {
        families(
            &CompiledQuestion::compile(&case.source).unwrap(),
            0,
            &mut previous,
        );
    }
    let graph = crate::Graph::default();
    let mut owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let mut ids = BTreeSet::new();
    let mut rows = Vec::new();
    for case in input.cases {
        let question = CompiledQuestion::compile(&case.source).unwrap();
        assert!(question.formula().free_variables().is_empty());
        assert!(ids.insert(*question.resolution_id()));
        let decision = owner.assess(&graph, &question);
        let mut actual = BTreeSet::new();
        families(&question, 0, &mut actual);
        let overlap = actual.intersection(&previous).cloned().collect::<Vec<_>>();
        rows.push(json!({"question":question.source(),"id":crate::hex(question.resolution_id()),"group":case.family,
            "shape":case.shape,"eligible":State::eligible(question.source()),"initial_formal_passed":decision.passed(),
            "has_answer":decision.has_answer(),"rule":decision.rule,"reason":format!("{:?}",decision.reason),
            "structural_families":actual,"development_family_overlap":overlap}));
    }
    write(
        &output,
        &json!({"input_sha256":crate::hex(&Sha256::digest(&raw)),"model_executions":0,
        "family_contract":"Canonical primitive connective, quantifier and atom-kind structure, ignoring all atomic arguments; root and closed conjunction obligations through depth two.","rows":rows}),
    );
}
#[test]
#[ignore = "explicit previously observed development case, not fresh qualification"]
fn observed_lost_recursive_goal_closes_within_the_original_total_budget() {
    let path =
        std::path::PathBuf::from(std::env::var("NAOME_LEMMA_LOOP_REGRESSION_OUTPUT").unwrap());
    assert!(!path.join("summary.json").exists());
    let input: Inputs = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/recursive-lemma-loop.json"
    ))
    .unwrap();
    let question = CompiledQuestion::compile(&input.cases[2].source).unwrap();
    assert_eq!(
        crate::hex(question.resolution_id()),
        "d8b3b1334367db8bafb03bb101a86ef990cfcfe09d8772889f6bdbfa30692a7d"
    );
    let (state, io) = inputs::checkpoint(73, &path.join("common-model"));
    let result = run::arm(
        &question,
        "recursive_loop",
        73,
        &state,
        &io,
        &path.join("recursive_loop"),
    );
    write(&path.join("summary.json"), &result);
    assert_eq!(
        result["counted_solution"], true,
        "preserve the original aggregate CPU, wall, expansion, checker and I/O limits"
    );
}
#[test]
#[ignore = "explicit native development regression, excluded from fresh comparison"]
fn observed_nested_goal_executes_its_failed_helpers_children() {
    let path = std::path::PathBuf::from(
        std::env::var("NAOME_LEMMA_LOOP_REGRESSION_OUTPUT")
            .expect("explicit development regression output"),
    );
    assert!(!path.join("summary.json").exists());
    let old: Vec<String> = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/lemma-loop-questions.json"
    ))
    .unwrap();
    let q = CompiledQuestion::compile(old.last().unwrap()).unwrap();
    let (common, io) = inputs::checkpoint(41, &path.join("common-model"));
    let mut results = BTreeMap::new();
    let mut removal = BTreeMap::new();
    for kind in ["flat_loop", "recursive_loop"] {
        let value = run::arm(&q, kind, 41, &common, &io, &path.join(kind));
        if value["counted_solution"] == true
            && !value["used_helpers"].as_array().unwrap().is_empty()
        {
            removal.insert(
                kind,
                run::removal(
                    &q,
                    &value,
                    &common,
                    &io,
                    &path.join(format!("{kind}-removal")),
                ),
            );
        }
        results.insert(kind, value);
    }
    let events: Vec<Value> =
        serde_json::from_slice(&std::fs::read(path.join("recursive_loop/events.json")).unwrap())
            .unwrap();
    let descendants = events.iter().filter(|e| e["role"] == "descendant").count();
    write(
        &path.join("summary.json"),
        &json!({"question":q.source(),"arms":results,"helper_removal":removal,"descendant_attempts":descendants,"scope":"Previously observed development goal, excluded from the fresh 24-question comparison"}),
    );
    assert!(
        descendants > 0,
        "the observed failed composite helper must release its actual children"
    );
}
