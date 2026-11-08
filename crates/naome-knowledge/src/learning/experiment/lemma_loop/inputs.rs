use super::*;
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inputs {
    pub model_seeds: Vec<u64>,
    pub cases: Vec<Case>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Case {
    pub family: String,
    pub shape: String,
    pub source: String,
}
#[test]
fn frozen_inputs_are_closed_distinct_and_do_not_reuse_observed_goals() {
    let input: Inputs = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/recursive-lemma-loop.json"
    ))
    .unwrap();
    assert_eq!(input.model_seeds, [41, 73, 101, 137, 211]);
    assert_eq!(input.cases.len(), 24);
    let old: Vec<String> = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/lemma-loop-questions.json"
    ))
    .unwrap();
    let old = old
        .iter()
        .map(|s| *ResearchQuestion::from_hex(s).unwrap().resolution_id())
        .collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new();
    let mut families = BTreeMap::<String, usize>::new();
    for case in input.cases {
        assert!(!case.shape.is_empty());
        let q = ResearchQuestion::from_hex(&case.source).unwrap();
        assert!(q.formula().free_variables().is_empty());
        assert!(!old.contains(q.resolution_id()));
        assert!(ids.insert(*q.resolution_id()));
        *families.entry(case.family).or_default() += 1;
    }
    assert_eq!(families.len(), 6);
    assert!(families.values().all(|n| *n == 4));
}

#[cfg(feature = "developer-tools")]
pub(super) fn checkpoint(seed: u64, output: &Path) -> (State, MemoryStore) {
    let mut state = State::fresh();
    state.model.seed = seed;
    let mut io = MemoryStore::default();
    state.model = Engine::default().snapshot(&state.model, &mut io).unwrap();
    state.feedback = crate::training::ability::Feedback::fresh(digest(&state.model));
    state.validate().unwrap();
    export_model(output, &state.model, &io);
    (state, io)
}
