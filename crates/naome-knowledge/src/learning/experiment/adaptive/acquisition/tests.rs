use super::*;
#[test]
fn every_round_rebinds_identical_owned_data_without_replacing_learning_state() {
    let mut source = State::fresh();
    source
        .accept(crate::learning::tests::own_example())
        .unwrap();
    let input = FrozenRound {
        state: source.clone(),
        evidence: Vec::new(),
        rows: Vec::new(),
    };
    let mut previous = source.clone();
    previous.model.seed = 1927;
    previous.feedback = crate::training::ability::Feedback::fresh(digest(&previous.model));
    previous.draws = 17;
    previous.trained = source.epoch;
    previous.replay.clear();
    previous.anchors.clear();
    let mut hashes = BTreeSet::new();
    for method in [
        Preparation::Balanced,
        Preparation::Targeted,
        Preparation::Meta,
    ] {
        previous.preparation = method;
        let actual = bind(&input, &previous);
        actual.validate().unwrap();
        assert_eq!(actual.model, previous.model);
        assert_eq!(actual.draws, 17);
        assert_eq!(actual.trained, previous.trained);
        assert_eq!(digest(&actual.feedback), digest(&previous.feedback));
        hashes.insert(digest(&(&actual.replay, &actual.anchors)));
        assert_eq!(digest(&actual.replay), digest(&input.state.replay));
        assert_eq!(digest(&actual.anchors), digest(&input.state.anchors));
    }
    assert_eq!(hashes.len(), 1);
}

#[test]
#[ignore = "Explicit complete two-round cold source layout; no optimizer or final inference"]
fn complete_matched_source_layout_preflight() {
    let output = std::env::var("NAOME_TRANSFER_SOURCE_OUTPUT").expect("fresh cold source output");
    let root = Path::new(&output);
    assert!(!root.exists());
    std::fs::create_dir_all(root).unwrap();
    let clock = Clock::start();
    for seed in [2411, 3203, 3301] {
        let path = root.join(format!("seed-{seed}"));
        let common = common(seed, &path.join("common"));
        let frozen = freeze(seed, &common, 2, &path.join("frozen"));
        assert_eq!(frozen.rounds.len(), 2);
        assert!(frozen.rounds[1].state.epoch > frozen.rounds[0].state.epoch);
        for input in &frozen.rounds {
            for preparation in [
                Preparation::Balanced,
                Preparation::Targeted,
                Preparation::Meta,
            ] {
                let mut previous = common.state.clone();
                previous.preparation = preparation;
                let actual = bind(input, &previous);
                actual.validate().unwrap();
                assert_eq!(digest(&actual.replay), digest(&input.state.replay));
                assert_eq!(digest(&actual.anchors), digest(&input.state.anchors));
            }
        }
        resource_boundary();
    }
    write(
        &root.join("completed.json"),
        &serde_json::json!({
            "contexts":3,"rounds":2,"optimizer_updates":0,"final_inferences":0,
            "peak_rss_bytes":resource_boundary(),"elapsed":clock.elapsed()
        }),
    );
}
