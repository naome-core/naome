use super::*;
fn q(source: &str) -> CompiledQuestion {
    CompiledQuestion::compile(source).unwrap()
}
fn checkpoint() -> String {
    "11".repeat(32)
}

#[test]
fn scarce_checked_completions_keep_half_the_rehearsal_share_without_more_updates() {
    let mut learning = Learning::fresh(checkpoint());
    let mut model = Model::fresh();
    let sources = [
        "goal=all(a,all(b,imp(eq(a,b),eq(b,a))))",
        "goal=all(a,all(b,imp(mem(a,b),mem(b,a))))",
        "goal=all(a,all(b,not(mem(a,b))))",
        "goal=all(a,all(b,all(c,imp(mem(a,b),mem(a,c)))))",
        "goal=all(a,all(b,all(c,not(mem(a,b)))))",
    ];
    for (index, source) in sources.iter().enumerate() {
        learning
            .remember(
                &mut model,
                &q(source),
                Some(&checkpoint()),
                index == 0,
                1,
                index as u64 + 1,
            )
            .unwrap();
    }
    let mut positive = 0;
    let mut total = 0;
    for cursor in 0..200 {
        learning.cursor = cursor;
        let indices = learning.rehearsal_indices();
        assert!(indices.len() <= 3);
        for index in indices {
            positive += usize::from(learning.samples[index].resolved == Some(true));
            total += 1;
        }
    }
    assert_eq!(positive * 2, total);
    assert_eq!(total, 600);
    assert_eq!(
        model.updates, 0,
        "rehearsal never creates fresh observation credit"
    );
    learning.bind(&"22".repeat(32));
    let before = model.clone();
    learning.rehearse(&mut model).unwrap();
    assert_eq!(
        model, before,
        "completion balance cannot reuse stale solver labels"
    );
}

#[test]
fn recent_misses_in_one_formula_family_do_not_evict_its_checked_success() {
    let mut learning = Learning::fresh(checkpoint());
    let mut model = Model::fresh();
    let success = q("goal=all(a,all(b,all(c,imp(and(mem(a,b),mem(a,c)),and(mem(a,b),mem(a,c))))))");
    learning
        .remember(&mut model, &success, Some(&checkpoint()), true, 1, 1)
        .unwrap();
    let atoms = [
        "mem(a,b)", "mem(b,a)", "mem(a,c)", "mem(c,a)", "mem(b,c)", "mem(c,b)", "mem(a,a)",
    ];
    for bits in 0..120u64 {
        let body = atoms
            .iter()
            .enumerate()
            .map(|(bit, atom)| {
                if bits & (1 << bit) == 0 {
                    (*atom).to_owned()
                } else {
                    format!("not({atom})")
                }
            })
            .reduce(|a, b| format!("and({a},{b})"))
            .unwrap();
        let miss = q(&format!("goal=all(a,all(b,all(c,{body})))"));
        assert_eq!(
            Descriptor::of(&success).features.family,
            Descriptor::of(&miss).features.family
        );
        learning
            .remember(&mut model, &miss, Some(&checkpoint()), false, 5, bits + 2)
            .unwrap();
    }
    assert_eq!(
        learning.samples.len(),
        (Learning::budget() / 1024).min(MEMORY)
    );
    assert!(
        learning
            .samples
            .iter()
            .any(|s| s.offer.id == *success.resolution_id())
    );
}

#[test]
fn productive_construction_recipes_outweigh_mastered_and_unreached_cells() {
    let mut learning = Learning::fresh(checkpoint());
    let mut model = Model::fresh();
    let recipes = [
        Recipe {
            operator: 0,
            level: 0,
        },
        Recipe {
            operator: 1,
            level: 0,
        },
        Recipe {
            operator: 2,
            level: 0,
        },
    ];
    let sources = [
        "goal=all(a,all(b,imp(mem(a,b),mem(b,a))))",
        "goal=all(a,all(b,imp(eq(a,b),mem(a,b))))",
        "goal=all(a,all(b,not(mem(a,b))))",
    ];
    for step in 0..32 {
        for (index, source) in sources.iter().enumerate() {
            let question = q(source);
            learning.selected(&question, Some(recipes[index]));
            learning
                .remember(
                    &mut model,
                    &question,
                    Some(&checkpoint()),
                    match index {
                        0 => true,
                        1 => step % 3 == 0,
                        _ => false,
                    },
                    5,
                    step,
                )
                .unwrap();
        }
    }
    assert!(learning.priority(1, 32) > learning.priority(0, 32));
    assert!(learning.priority(1, 32) > learning.priority(2, 32));
    let mut selected = [0; 3];
    for draw in 32..232 {
        for recipe in learning.recipes(draw, draw) {
            if recipe.level == 0 && recipe.operator < 3 {
                selected[recipe.operator as usize] += 1;
            }
        }
    }
    assert!(selected[1] > selected[0]);
    assert!(selected[1] > selected[2]);
    assert!(
        selected[2] > 0,
        "failed recipes keep bounded exploration mass"
    );
    let before = learning.cells[1].solved;
    learning.bind(&"22".repeat(32));
    assert!(before > 0);
    assert_eq!(learning.cells[1].attempts, 0);
    learning.validate().unwrap();
}

#[test]
fn recipe_scheduling_waits_for_current_checkpoint_observations() {
    let mut learning = Learning::fresh(checkpoint());
    let mut model = Model::fresh();
    let question = q("goal=all(a,all(b,imp(mem(a,b),mem(b,a))))");
    let recipe = Recipe {
        operator: 2,
        level: 0,
    };
    for draw in 0..4 {
        assert_eq!(learning.priority(recipe.index(), draw), 65536);
        learning.selected(&question, Some(recipe));
        learning
            .remember(
                &mut model,
                &question,
                Some(&checkpoint()),
                false,
                1000,
                draw,
            )
            .unwrap();
    }
    assert!(learning.priority(recipe.index(), 4) < 65536);
    learning.bind(&"22".repeat(32));
    assert_eq!(learning.priority(recipe.index(), 5), 65536);
    learning
        .remember(&mut model, &question, Some(&checkpoint()), false, 1000, 6)
        .unwrap();
    assert_eq!(learning.priority(recipe.index(), 6), 65536);
}

#[test]
fn late_old_checkpoint_results_do_not_train_current_recipe_ability() {
    let mut learning = Learning::fresh(checkpoint());
    let mut model = Model::fresh();
    let question = q("goal=all(a,all(b,imp(mem(a,b),mem(b,a))))");
    learning.selected(
        &question,
        Some(Recipe {
            operator: 0,
            level: 0,
        }),
    );
    learning
        .remember(&mut model, &question, Some(&"22".repeat(32)), false, 123, 5)
        .unwrap();
    assert_eq!(learning.cells[0].attempts, 0);
    assert_eq!(model.rehearsals, 0);
    assert_eq!(learning.samples.len(), 1);
}

#[test]
fn replay_preserves_families_and_does_not_relabel_old_solver_outcomes() {
    let mut learning = Learning::fresh(checkpoint());
    let mut model = Model::fresh();
    let equality = q("goal=all(a,all(b,imp(eq(a,b),eq(b,a))))");
    learning
        .remember(&mut model, &equality, Some(&checkpoint()), true, 1, 1)
        .unwrap();
    let atoms = [
        "mem(a,b)", "mem(b,a)", "mem(a,c)", "mem(c,a)", "mem(b,c)", "mem(c,b)", "mem(a,a)",
    ];
    let mut distinct = std::collections::BTreeSet::new();
    for i in 0..120u64 {
        let body = atoms
            .iter()
            .enumerate()
            .map(|(bit, atom)| {
                if i & (1 << bit) == 0 {
                    (*atom).to_owned()
                } else {
                    format!("not({atom})")
                }
            })
            .reduce(|a, b| format!("and({a},{b})"))
            .unwrap();
        let question = q(&format!("goal=all(a,all(b,all(c,{body})))"));
        assert!(distinct.insert(*question.resolution_id()));
        learning
            .remember(
                &mut model,
                &question,
                Some(&checkpoint()),
                false,
                1000,
                2 + i,
            )
            .unwrap();
    }
    assert_eq!(distinct.len(), 120);
    assert_eq!(
        learning.samples.len(),
        (Learning::budget() / 1024).min(MEMORY)
    );
    assert!(
        learning
            .samples
            .iter()
            .any(|s| s.offer.id == *equality.resolution_id())
    );
    assert!(model.rehearsals > 0);
    learning.bind(&"22".repeat(32));
    let before = model.clone();
    learning.rehearse(&mut model).unwrap();
    assert_eq!(
        before, model,
        "old completion labels have no new-checkpoint authority"
    );
    learning.validate().unwrap();
}

#[test]
fn pending_lemma_use_is_not_rehearsed_as_failure() {
    let question = q("goal=all(a,all(b,imp(eq(a,b),eq(b,a))))");
    let mut learning = Learning::fresh(checkpoint());
    let mut model = Model::fresh();
    model.observe(&question, true, 1).unwrap();
    for draw in 1..=128 {
        learning
            .remember(&mut model, &question, Some(&checkpoint()), true, 1, draw)
            .unwrap();
    }
    assert_eq!(model.supports, 0);
    assert!(
        model.predictions(&question)[2] > 0.35,
        "rehearsal must not turn pending downstream use into demonstrated failure"
    );
    let before = model.predictions(&question)[2];
    learning.support(&mut model, &question).unwrap();
    for _ in 0..32 {
        learning.rehearse(&mut model).unwrap();
    }
    assert!(model.predictions(&question)[2] > before);
    let mut reopened: Learning =
        serde_json::from_slice(&serde_json::to_vec(&learning).unwrap()).unwrap();
    assert_eq!(reopened.samples[0].support, Some(true));
    reopened.bind(&"22".repeat(32));
    let before = model.rehearsals;
    reopened.rehearse(&mut model).unwrap();
    assert_eq!(model.rehearsals, before + 1);
}

#[test]
fn utility_is_idempotent_checkpoint_bound_and_copies_receive_no_positive_credit() {
    let mut learning = Learning::fresh(checkpoint());
    let mut model = Model::fresh();
    let question = q("goal=all(a,all(b,imp(eq(a,b),eq(b,a))))");
    learning
        .remember(&mut model, &question, Some(&checkpoint()), true, 5, 1)
        .unwrap();
    let mut utility = crate::learning::finder::Utility {
        checkpoint: checkpoint(),
        references: vec!["33".repeat(32)],
        scores: vec![crate::learning::finder::Score {
            resolution: crate::hex(question.resolution_id()),
            proof: "44".repeat(32),
            alignment: 32767,
            novelty: 0,
        }],
        cpu_micros: 1,
        wall_micros: 1,
        gradient_passes: 2,
    };
    assert!(learning.utility(&mut model, &utility).unwrap());
    assert_eq!(model.utility(&Descriptor::of(&question)), 0.5);
    assert_eq!(model.utility_observations, 1);
    assert!(!learning.utility(&mut model, &utility).unwrap());
    assert_eq!(model.utility_observations, 1);
    learning.cells[0].utility_count = 1;
    learning.cells[0].utility_sum = 65535;
    learning.bind(&"22".repeat(32));
    assert!(!learning.utility_current());
    assert_eq!(learning.cells[0].utility_count, 0);
    assert_eq!(learning.cells[0].utility_sum, 0);
    assert!(!learning.utility(&mut model, &utility).unwrap());
    utility.checkpoint = "22".repeat(32);
    utility.scores[0].novelty = 65535;
    assert!(learning.utility(&mut model, &utility).unwrap());
    assert!(model.utility(&Descriptor::of(&question)) > 0.5);
    assert!(learning.utility_current());
    // The old solve label remains attached to its actual old checkpoint.
    assert_eq!(
        learning.samples[0].checkpoint.as_deref(),
        Some(checkpoint().as_str())
    );
}

#[test]
fn current_curriculum_rejects_corrupt_recipes_and_replay_descriptors() {
    let mut learning = Learning::fresh(checkpoint());
    let mut model = Model::fresh();
    let question = q("goal=all(a,all(b,imp(mem(a,b),mem(b,a))))");
    learning
        .remember(&mut model, &question, Some(&checkpoint()), false, 10, 1)
        .unwrap();
    learning.samples[0].offer.recipe = Some(Recipe {
        operator: 99,
        level: 0,
    });
    assert!(learning.validate().is_err());
    learning.samples[0].offer.recipe = None;
    learning.samples[0].offer.descriptor.bindings[0] = f32::NAN;
    assert!(learning.validate().is_err());
}
