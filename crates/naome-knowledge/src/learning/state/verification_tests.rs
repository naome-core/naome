use super::*;

#[test]
fn a_complete_active_replay_set_stays_verified_after_other_owned_inputs() {
    let original = crate::learning::tests::own_example();
    let mut examples = (1..=128)
        .map(|job| Example {
            job,
            ..original.clone()
        })
        .collect::<Vec<_>>();
    examples.sort_by_key(digest);
    VERIFIED.with(|known| known.borrow_mut().clear());
    for example in &examples {
        validate_example(example).unwrap();
    }
    // A State owns at most32replay and4anchors. Prime from other legitimate
    // owned observations, then revisit this complete working set twice.
    let active = &examples[..REPLAY + 4];
    for example in active {
        validate_example(example).unwrap();
    }
    let checked = proof::checking_work().calls;
    for example in active {
        validate_example(example).unwrap();
    }
    assert_eq!(
        proof::checking_work().calls,
        checked,
        "unchanged active inputs must not repeatedly rebuild their native proofs"
    );
}

#[test]
fn changed_provenance_never_inherits_a_verified_neighbour() {
    let example = crate::learning::tests::own_example();
    VERIFIED.with(|known| known.borrow_mut().clear());
    validate_example(&example).unwrap();
    let mut changed = example.clone();
    changed.proof_id = "f1".repeat(32);
    let checked = proof::checking_work().calls;
    assert!(validate_example(&changed).is_err());
    assert!(proof::checking_work().calls > checked);
    let checked = proof::checking_work().calls;
    validate_example(&example).unwrap();
    assert_eq!(proof::checking_work().calls, checked);
}

#[test]
fn a_new_worker_rechecks_witnesses_in_its_own_empty_cache() {
    let example = crate::learning::tests::own_example();
    validate_example(&example).unwrap();
    std::thread::spawn(move || {
        let checked = proof::checking_work().calls;
        validate_example(&example).unwrap();
        assert!(proof::checking_work().calls > checked);
        assert_eq!(VERIFIED.with(|known| known.borrow().len()), 1);
    })
    .join()
    .unwrap();
}
