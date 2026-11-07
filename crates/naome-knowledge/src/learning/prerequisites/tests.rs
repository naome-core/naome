use super::super::{SolveContext, construction, search_question_report};
use super::*;

fn inputs() -> (naome_authoring::CompiledQuestion, crate::Graph, Vec<String>) {
    let (goal, helpers) = crate::learning::tests::helper_goal();
    let mut graph = crate::Graph::default();
    let mut required = Vec::new();
    for helper in helpers {
        let solution = crate::learning::tests::symbolic_solution(&helper);
        let (root, batch) = graph
            .prepare_generated(&solution.source, &solution.helpers, &helper)
            .unwrap();
        graph
            .commit_batch(
                root,
                batch,
                std::time::Instant::now() + std::time::Duration::from_secs(10),
            )
            .unwrap();
        required.push(solution.proof_id);
    }
    (goal, graph, required)
}
struct NoNeural;
impl super::super::model::Ranker for NoNeural {
    fn scores(&mut self, _: &super::super::model::Decision) -> Result<Vec<f32>, String> {
        panic!("checked composition must not invent a neural decision");
    }
}
#[test]
fn an_answered_internal_obligation_supplies_a_checked_certificate_without_intake() {
    let (_, graph, required) = inputs();
    let (_, helpers) = crate::learning::tests::helper_goal();
    let axiom = naome_foundation::ZfcAxiom::Extensionality.formula();
    let internal = naome_authoring::CompiledQuestion::from_formula(axiom.clone()).unwrap();
    let mut owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let decision = owner.assess(&graph, &internal);
    assert!(decision.has_answer());
    assert!(!decision.passed());
    let goal = naome_authoring::CompiledQuestion::from_formula(
        naome_foundation::Formula::conjunction(helpers[0].formula().clone(), axiom),
    )
    .unwrap();
    let required = &required[..1];
    let full = graph.prerequisites(required).unwrap().unwrap();
    let before = graph.content_root();
    let result = search_question_report(
        goal.source(),
        &mut NoNeural,
        16,
        &SolveContext {
            required,
            prerequisites: Some(&full),
            ..Default::default()
        },
    )
    .unwrap();
    let solution = result
        .solution
        .expect("internal checker evidence must complete the parent");
    let _ = solution.checked().unwrap();
    assert_eq!(result.cost.search_expansions, 4);
    assert_eq!(
        graph.content_root(),
        before,
        "worker checking cannot register graph facts or questions"
    );
    assert_eq!(owner.assess(&graph, &internal), decision);
}

#[test]
fn an_internal_refutation_never_supplies_the_positive_prerequisite() {
    let (_, graph, required) = inputs();
    let infinity = naome_foundation::ZfcAxiom::Infinity.formula();
    let opposite = infinity.view().negated().unwrap().to_owned();
    let internal = naome_authoring::CompiledQuestion::from_formula(opposite.clone()).unwrap();
    let mut owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let decision = owner.assess(&graph, &internal);
    assert_eq!(
        decision.reason,
        Some(naome_checker::question::RejectionReason::KnownRefutation)
    );
    let full = graph.prerequisites(&required[..1]).unwrap().unwrap();
    let terms = full.terms(&required[..1]).unwrap();
    let target = naome_foundation::Formula::conjunction(terms[0].formula(), opposite);
    let (proof, work) =
        construction::composition::construct(&target, &terms, 16, std::time::Instant::now())
            .unwrap();
    assert!(proof.is_none());
    assert!(work <= 16);
}
#[test]
fn full_prerequisites_compose_without_populating_the_neural_snapshot() {
    let (goal, mut graph, required) = inputs();
    let full = graph.prerequisites(&required).unwrap().unwrap();
    let base = State::fresh();
    assert!(base.require_theorems(&required).is_err());
    full.require(&base, &required).unwrap();
    let generated = search_question_report(
        goal.source(),
        &mut NoNeural,
        3,
        &SolveContext {
            required: &required,
            prerequisites: Some(&full),
            ..Default::default()
        },
    )
    .unwrap();
    let solution = generated.solution.expect("compose both original sources");
    assert_eq!(generated.cost.search_expansions, 3);
    assert!(generated.cost.checker_calls > 0);
    let _ = solution.checked().unwrap();
    assert!(
        super::super::search::compile(goal.proved_target(), &solution.tree)
            .unwrap()
            .1
            .is_empty()
    );
    let mut changed = solution.tree.clone();
    if let super::super::search::Tree::Composed { work, .. } = &mut changed {
        *work = 1;
    }
    assert!(super::super::search::compile(goal.proved_target(), &changed).is_err());
    let (root, batch) = graph
        .prepare_generated(&solution.source, &solution.helpers, &goal)
        .unwrap();
    graph
        .commit_batch(
            root,
            batch,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        )
        .unwrap();
    let dependencies = graph.direct_dependencies(root).unwrap();
    assert!(
        required
            .iter()
            .all(|id| dependencies.contains(&crate::object::proof_address(id).unwrap()))
    );
    assert!(base.knowledge.is_empty());
    let restored: Prerequisites =
        serde_json::from_slice(&serde_json::to_vec(&full).unwrap()).unwrap();
    assert_eq!(restored.terms(&required).unwrap().len(), 2);
    assert!(
        construction::composition::construct(
            goal.proved_target(),
            &full.terms(&required).unwrap(),
            2,
            std::time::Instant::now()
        )
        .unwrap()
        .0
        .is_none()
    );
}
#[test]
fn claimed_addresses_do_not_replace_checked_identity_or_complete_dependencies() {
    let (_, graph, required) = inputs();
    let full = graph.prerequisites(&required).unwrap().unwrap();
    let mut artifacts = full.0.artifacts.clone();
    artifacts[0].artifact_id = crate::hex(&[3; 32]);
    assert!(
        Prerequisites::new(artifacts)
            .unwrap()
            .terms(&required)
            .is_err()
    );
    let mut artifacts = full.0.artifacts.clone();
    artifacts[0].statement_id = Some(crate::hex(&[7; 32]));
    assert!(
        Prerequisites::new(artifacts)
            .unwrap()
            .terms(&required)
            .is_err()
    );
    let mut artifacts = full.0.artifacts.clone();
    artifacts[0].payload = "00".into();
    assert!(
        Prerequisites::new(artifacts)
            .unwrap()
            .terms(&required)
            .is_err()
    );
    assert!(
        Prerequisites::default()
            .require(&State::fresh(), &required)
            .is_err()
    );
}

#[test]
#[ignore = "explicit previously observed development input; never fresh qualification"]
fn large_checked_prerequisites_resolve_the_observed_missing_root() {
    fn admit_discovery(
        graph: &mut crate::Graph,
        question: &naome_authoring::CompiledQuestion,
        solution: &super::super::Solution,
    ) -> Result<(), crate::Error> {
        let (root, batch) =
            graph.prepare_generated(&solution.source, &solution.helpers, question)?;
        graph.commit_batch(
            root,
            batch,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        )?;
        Ok(())
    }
    let path =
        std::path::PathBuf::from(std::env::var("NAOME_COMPOSITION_DEVELOPMENT_INPUT").unwrap());
    let events: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(path.join("events.json")).unwrap()).unwrap();
    let mut graph = crate::Graph::default();
    let mut required = Vec::new();
    let mut oversized = false;
    for event in &events {
        if matches!(
            event["role"].as_str(),
            Some("helper" | "parent_retry" | "descendant")
        ) && !event["solution"].is_null()
        {
            let question =
                naome_authoring::CompiledQuestion::compile(event["question"].as_str().unwrap())
                    .unwrap();
            let solution: super::super::Solution =
                serde_json::from_value(event["solution"].clone()).unwrap();
            admit_discovery(&mut graph, &question, &solution).unwrap();
            oversized |= graph
                .learning_certificate(crate::object::proof_address(&solution.proof_id).unwrap())
                .unwrap()
                .is_none();
            required.push(solution.proof_id);
        }
    }
    assert!(
        oversized,
        "development regression must cross the neural-view boundary"
    );
    let root = events.iter().find(|e| e["role"] == "initial_goal").unwrap()["question"]
        .as_str()
        .unwrap();
    let full = graph.prerequisites(&required).unwrap().unwrap();
    let generated = search_question_report(
        root,
        &mut NoNeural,
        16,
        &SolveContext {
            required: &required,
            prerequisites: Some(&full),
            ..Default::default()
        },
    )
    .unwrap();
    let solution = generated
        .solution
        .expect("full checked conjunction prerequisites must compose");
    admit_discovery(
        &mut graph,
        &naome_authoring::CompiledQuestion::compile(root).unwrap(),
        &solution,
    )
    .unwrap();
    eprintln!(
        "{}",
        serde_json::json!({"event":"observed_large_context_resolved","cost":generated.cost,"proof_id":solution.proof_id})
    );
}
