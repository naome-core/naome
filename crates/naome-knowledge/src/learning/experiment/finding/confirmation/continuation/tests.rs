use super::*;

#[test]
fn switches_on_a_checked_native_prefix_with_the_same_grant() {
    let directory = Directory::new();
    let question = ResearchQuestion::from_hex(
        "0404030204020101000000000100000002030403010100000000010000000201010000000001000000010204020101000000000100000001",
    ).unwrap();
    let protocol = Protocol {
        search_limit: 32,
        switch_after: 1,
        combined_limit: 200_000,
        fixed: FixedOrder::Native,
        cases: Vec::new(),
    };
    let budget = crate::resources::tests::snapshot(false).budget;
    let mut engine = Engine::default();
    let mut store = MemoryStore::default();
    let checkpoint = Checkpoint::fresh();
    let mut perform = |arm, name| {
        engine
            .with(&checkpoint, &mut store, |runtime| {
                run(
                    &question,
                    1,
                    arm,
                    &protocol,
                    runtime,
                    &budget,
                    &directory.0.join(name),
                )
            })
            .unwrap()
    };
    let learned = perform(Arm::Learned, "learned");
    let switched = perform(Arm::Switch, "switched");
    let fixed = perform(Arm::Fixed(FixedOrder::Native), "fixed");
    let prefix = matched_prefix(&learned, &switched, protocol.switch_after).unwrap();
    let native = engine
        .with(&checkpoint, &mut store, |runtime| {
            search::solve(
                question.proved_target(),
                &mut Exploring {
                    model: runtime,
                    seed: 1,
                    explore: false,
                },
                protocol.search_limit,
            )
        })
        .unwrap();
    assert_eq!(learned.expansions, native.expansions);
    assert!(learned.events == events(&question, native.execution.as_ref()).unwrap());
    assert!(prefix.memory.is_some());
    assert_ne!(
        switched.prefix[protocol.switch_after].applied,
        switched.prefix[protocol.switch_after].learned
    );
    assert!(prefix.expansions > 0);
    assert!(prefix.expansions < switched.expansions);
    assert!(switched.native_plan_calls > protocol.switch_after + 1);
    assert!(switched.proof.is_some(), "{:?}", switched.check_error);
    assert!(switched.checker_steps > 0);
    assert!(switched.expansions + switched.checker_steps <= protocol.combined_limit);
    assert_eq!(fixed.native_plan_calls, 0);
    assert!(fixed.expansions <= protocol.search_limit);
}

#[test]
fn rejects_shared_lineage_and_requires_protected_held_cases() {
    let source = "04040304030101000000000100000002010100000000010000000103040101000000000100000002040101000000000100000001";
    let case = |split, seed, expected_proof| Source {
        question: source.into(),
        lineage: "observed".into(),
        split,
        seed,
        expected_proof,
    };
    let mut protocol = Protocol {
        search_limit: 32,
        switch_after: 1,
        combined_limit: 200_000,
        fixed: FixedOrder::Native,
        cases: vec![case(Split::Held, 2, None)],
    };
    assert!(
        protocol
            .validate()
            .unwrap_err()
            .contains("requires protected")
    );
    protocol
        .cases
        .push(case(Split::Protected, 1, Some("00".repeat(32))));
    assert!(
        protocol
            .validate()
            .unwrap_err()
            .contains("share a source family")
    );
}
