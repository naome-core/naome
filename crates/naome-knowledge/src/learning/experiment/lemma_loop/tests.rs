use super::*;
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
