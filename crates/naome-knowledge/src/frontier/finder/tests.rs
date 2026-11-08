use super::*;

#[test]
fn frozen_model_keeps_all_gradient_ports_closed_and_rejects_invalid_labels_atomically() {
    let question = ResearchQuestion::from_hex(&crate::learning::tests::own_question()).unwrap();
    let descriptor = analysis::Descriptor::of(&question);
    let mut model = Model::seeded(91);
    model.freeze();
    let before = model.clone();
    model.observe(&question, true, 7).unwrap();
    model.support(&question).unwrap();
    model.observe_utility(&descriptor, 0.75).unwrap();
    model
        .rehearse(&descriptor, Some(true), Some(7), Some(true), Some(0.75))
        .unwrap();
    assert_eq!(model, before);
    assert!(model.observe_utility(&descriptor, f32::NAN).is_err());
    assert!(
        model
            .rehearse(&descriptor, Some(true), None, None, Some(f32::NAN))
            .is_err()
    );
    assert_eq!(model, before);
    let mut live = Model::seeded(91);
    let initial = live.clone();
    assert!(
        live.rehearse(&descriptor, Some(true), Some(7), None, Some(f32::NAN))
            .is_err()
    );
    assert_eq!(
        live, initial,
        "invalid utility cannot partly train another output"
    );
    live.observe(&question, true, 7).unwrap();
    assert_ne!(live, initial);
    assert_ne!(Model::seeded(91), Model::seeded(97));
}
fn q(source: &str) -> ResearchQuestion {
    ResearchQuestion::from_hex(source).unwrap()
}

#[test]
fn relation_rotation_uses_the_whole_retained_context() {
    let seeds = VecDeque::from(crate::test_inputs::relation_examples());
    let first = seeds.iter().take(4).cloned().collect();
    let collect = |seeds: &VecDeque<Formula>| {
        (0..96)
            .flat_map(|cursor| {
                questions(cursor, seeds, &VecDeque::new(), 12, 64 * 1024, &mut |_| {
                    true
                })
            })
            .map(|q| key(&q))
            .collect::<BTreeSet<_>>()
    };
    assert_ne!(
        collect(&seeds),
        collect(&first),
        "later checked relations must change exploration without another graph insertion"
    );
}

#[test]
fn predictor_learns_variable_wiring_cost_without_using_variable_names() {
    let a = q("0404040301010000000201000000010301010000000101000000000101000000020100000000");
    let b = q("0404040301010000000201000000010301010000000101000000000101000000000100000002");
    let renamed = q("0404040301010000000201000000010301010000000101000000000101000000020100000000");
    assert_eq!(
        super::super::Features::of(&a),
        super::super::Features::of(&b)
    );
    let mut model = Model::fresh();
    for _ in 0..96 {
        model.observe(&a, false, 1).unwrap();
        model.observe(&b, false, 65_535).unwrap();
    }
    assert!(
        model.predictions(&a)[1] < model.predictions(&b)[1],
        "identical syntax counts cannot erase differing variable-role observations"
    );
    assert_eq!(model.predictions(&a), model.predictions(&renamed));
}

#[test]
fn formal_rejections_refill_the_page_within_the_fixed_check_budget() {
    let mut seen = BTreeSet::new();
    let candidates = (0..32)
        .flat_map(|cursor| {
            questions(
                cursor,
                &VecDeque::new(),
                &VecDeque::new(),
                12,
                64 * 1024,
                &mut |_| true,
            )
        })
        .filter(|q| seen.insert(key(q)))
        .take(5)
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 5);
    let expected = candidates[3..]
        .iter()
        .map(|q| *q.resolution_id())
        .collect::<Vec<_>>();
    let mut calls = 0;
    let page = bounded_eligible(candidates, 2, 64 * 1024, &mut |_| {
        calls += 1;
        calls > 3
    });
    assert_eq!(
        page.iter().map(|q| *q.resolution_id()).collect::<Vec<_>>(),
        expected
    );
    assert_eq!(calls, 5);
}
#[test]
fn research_screen_rejects_boolean_padding_without_rejecting_relation_properties() {
    for source in [
        "040001000000000100000000",
        "04020001000000000100000000",
        "040301010000000001000000000101000000000100000000",
        "040302030101000000000100000000020201010000000001000000000001000000000100000000",
        "0402030301010000000001000000000101000000000100000000020301010000000001000000000101000000000100000000",
        "040403020300010000000101000000000200010000000001000000010001000000010100000000",
    ] {
        assert!(!meaningful(&q(source)), "{source}");
    }
    let symmetry = q("04040300010000000101000000000001000000000100000001");
    assert!(meaningful(&symmetry));
    assert_eq!(
        key(&symmetry),
        key(&q("040402020300010000000101000000000001000000000100000001"))
    );
}
#[test]
fn ordinary_exploration_is_closed_bounded_and_not_a_tautology_catalog() {
    let mut unique = BTreeSet::new();
    for cursor in 0..32 {
        let page = questions(
            cursor,
            &VecDeque::new(),
            &VecDeque::new(),
            12,
            64 * 1024,
            &mut |_| true,
        );
        assert!(
            page.iter()
                .map(|q| q.to_hex().len() * 8 + 256)
                .sum::<usize>()
                <= 64 * 1024
        );
        let mut seen = BTreeSet::new();
        for question in page {
            assert!(question.formula().is_closed());
            assert!(meaningful(&question));
            assert!(crate::learning::State::eligible(&question.to_hex()));
            assert!(seen.insert(key(&question)));
            unique.insert(*question.resolution_id());
            assert_eq!(
                ResearchQuestion::from_hex(&question.to_hex())
                    .unwrap()
                    .core(),
                question.core()
            );
        }
    }
    assert!(
        unique.len() >= 8,
        "a fresh node needs a useful theory frontier, got {}",
        unique.len()
    );
    assert!(questions(0, &VecDeque::new(), &VecDeque::new(), 12, 1, &mut |_| true).is_empty());
}
#[test]
fn helpers_are_proper_goal_parts_with_capture_free_parameter_roles() {
    let goal = q(
        "0403040301010000000001000000010101000000010100000000040301010000000101000000000101000000000100000001",
    );
    let expected = q("04040301010000000001000000010101000000010100000000");
    let candidates = helpers(&goal, 0);
    assert!(candidates.iter().any(|q| q.core() == expected.core()));
    assert!(
        candidates
            .iter()
            .all(|q| q.formula().is_closed() && key(q) != key(&goal))
    );
    assert!(relevance(&expected, &goal) > 0);
}
#[test]
fn elementary_wrappers_cannot_claim_goal_support() {
    let lemma = q("04040300010000000101000000000001000000000100000001");
    let wrapper = q(
        "040403030404030001000000010100000000000100000000010000000101010000000101000000000101000000010100000000",
    );
    assert!(!independent_goal(&lemma, &wrapper));
    assert!(!independent_goal(&lemma, &lemma));
    let substitution =
        q("0404040300010000000201000000010301010000000201000000000101000000010100000000");
    let instance = q("04040300010000000101000000000301010000000101000000010101000000000100000001");
    assert!(independent_goal(&substitution, &instance));
}
#[test]
fn actual_support_outweighs_repeated_cheap_resolution_in_the_learned_prior() {
    let question = q(&crate::learning::tests::own_question());
    let mut easy = Model::fresh();
    let mut missed = easy.clone();
    for _ in 0..32 {
        easy.observe(&question, true, 1).unwrap();
        missed.observe(&question, false, 1).unwrap();
    }
    assert!(easy.predictions(&question)[0] > missed.predictions(&question)[0]);
    let mut useful = easy.clone();
    for _ in 0..32 {
        useful.support(&question).unwrap();
    }
    assert!(useful.weight(&question) > easy.weight(&question));
    assert!(useful.predictions(&question)[2] > easy.predictions(&question)[2]);
    assert_eq!(
        (useful.updates, useful.resolved, useful.supports),
        (64, 32, 32)
    );
    let reopened: Model = serde_json::from_slice(&serde_json::to_vec(&useful).unwrap()).unwrap();
    assert_eq!(useful, reopened);
    assert_eq!(useful.weight(&question), reopened.weight(&question));
}
