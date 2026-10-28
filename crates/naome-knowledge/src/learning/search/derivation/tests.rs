use super::*;
use naome_authoring::CompiledQuestion;

fn chain(state: &State, path: &[Action]) -> Tree {
    if let Some((action, rest)) = path.split_first() {
        let children = next(state, action).unwrap();
        assert_eq!(children.len(), 1);
        Tree::Step {
            action: action.clone(),
            children: vec![chain(&children[0], rest)],
        }
    } else {
        let (a, b) = close(state).unwrap();
        Tree::Close(a, b)
    }
}
fn source_id(target: &Formula, tree: &Tree) -> String {
    let (term, _) = compile(target, tree).unwrap();
    let verified = super::super::super::proof::verify(&term, target).unwrap();
    crate::hex(verified.native_id.as_bytes())
}

#[test]
fn contextual_fragments_recheck_all_premises_scope_and_original_branch() {
    let q = CompiledQuestion::compile(
        "goal=all(a,all(b,all(c,imp(imp(mem(a,a),mem(b,b)),imp(imp(mem(b,b),mem(c,c)),imp(mem(a,a),mem(c,c)))))))",
    ).unwrap();
    let target = q.proved_target();
    let state = prepare(target).unwrap().state;
    let after = next(&state, &Action::Mp(0, 2)).unwrap().remove(0);
    let b = after.facts.len() - 1;
    let tree = chain(&state, &[Action::Mp(0, 2), Action::Mp(1, b)]);
    let id = source_id(target, &tree);
    let derived = checked(target, &tree, &id).unwrap();
    assert_eq!(derived.steps.len(), 2);
    assert_eq!(derived.steps[0].parent, None);
    assert_eq!(derived.steps[1].parent, Some((0, 0)));
    assert_eq!(
        derived.steps[1].graph.binding,
        trace::binding(&after).unwrap()
    );
    assert_eq!(
        derived.fragments.len(),
        1,
        "{:?}",
        derived.rejected_fragments
    );
    let fragment = &derived.fragments[0];
    let verified = fragment.verify().unwrap();
    assert!(verified.target.free_variables().is_empty());
    assert_ne!(
        verified.target, after.goal,
        "assumptions cannot become globally true facts"
    );
    assert_eq!(fragment.assumptions.len(), after.facts.len() - 1);
    fragment.validate_source(target, &tree, &id).unwrap();
    for mutation in 0..5 {
        let mut changed = fragment.clone();
        match mutation {
            0 => {
                changed.assumptions.pop();
            }
            1 => {
                changed.variables.pop();
            }
            2 => changed.branch = vec![1],
            3 => changed.source_tree = "ff".repeat(32),
            _ => changed.state = "ff".repeat(32),
        }
        assert!(
            changed.validate_source(target, &tree, &id).is_err(),
            "mutation {mutation}"
        );
    }
    let invalid = Tree::Step {
        action: Action::Mp(0, 2),
        children: vec![Tree::Close(0, 0)],
    };
    assert!(checked(target, &invalid, &id).is_err());
}

#[test]
fn symbolic_preferences_require_two_checked_completions_of_the_same_state() {
    let q = CompiledQuestion::compile(
        "goal=all(a,all(b,all(c,imp(imp(mem(a,a),mem(c,c)),imp(imp(mem(a,a),mem(b,b)),imp(imp(mem(b,b),mem(c,c)),imp(mem(a,a),mem(c,c))))))))",
    ).unwrap();
    let target = q.proved_target();
    let state = prepare(target).unwrap().state;
    let after = next(&state, &Action::Mp(1, 3)).unwrap().remove(0);
    let b = after.facts.len() - 1;
    let paths = [
        vec![Action::Mp(0, 3)],
        vec![Action::Mp(1, 3), Action::Mp(2, b)],
    ];
    let mut pool = super::super::super::pool::Pool::default();
    let mut roots = Vec::new();
    for path in paths {
        let tree = chain(&state, &path);
        let id = source_id(target, &tree);
        let graphs = compile(target, &tree).unwrap().1;
        roots.push(graphs[0].clone());
        pool.add(false, "dependency", "family", &id, graphs)
            .unwrap();
        pool.add_derivation(checked(target, &tree, &id).unwrap())
            .unwrap();
    }
    assert_eq!(roots[0].key(), roots[1].key());
    let witnesses = pool.witnesses(&roots[0]);
    assert_eq!(witnesses.len(), 2);
    assert_ne!(witnesses[0].source, witnesses[1].source);
    assert_eq!(
        witnesses
            .iter()
            .map(|w| w.remaining_steps)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 2])
    );
    assert!(
        roots[0].candidates.len() > witnesses.len(),
        "unvisited alternatives remain unknown"
    );
    assert_eq!(pool.derived_counts().preferences, 1);
}

#[test]
fn witness_branch_sequences_keep_the_actual_fresh_variable_scope() {
    struct Ordered;
    impl Ranker for Ordered {
        fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
            Ok(vec![0.; d.candidates.len()])
        }
    }
    let q = CompiledQuestion::compile("goal=all(x,imp(ex(y,mem(y,x)),ex(y,or(mem(y,x),eq(y,x)))))")
        .unwrap();
    let tree = solve(q.proved_target(), &mut Ordered, 128)
        .unwrap()
        .tree
        .unwrap();
    let id = source_id(q.proved_target(), &tree);
    let derived = checked(q.proved_target(), &tree, &id).unwrap();
    assert!(
        derived
            .steps
            .iter()
            .any(|step| matches!(step.action, Action::Witness(..)))
    );
    assert!(
        !derived.fragments.is_empty(),
        "{:?}",
        derived.rejected_fragments
    );
    for fragment in &derived.fragments {
        fragment
            .validate_source(q.proved_target(), &tree, &id)
            .unwrap();
        assert!(
            fragment
                .verify()
                .unwrap()
                .target
                .free_variables()
                .is_empty()
        );
    }
}

#[test]
fn hindsight_does_not_invent_observation_of_a_rebased_checked_path() {
    struct Detour;
    impl Ranker for Detour {
        fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
            Ok(d.candidates
                .iter()
                .map(|c| {
                    if c.rule == Rule::DoubleNegation {
                        1.
                    } else {
                        0.
                    }
                })
                .collect())
        }
    }
    let q = CompiledQuestion::compile(
        "goal=all(x,all(y,imp(not(not(mem(x,x))),imp(not(not(mem(y,x))),imp(and(mem(x,x),mem(y,y)),mem(y,y))))))",
    ).unwrap();
    let found = solve(q.proved_target(), &mut Detour, 128).unwrap();
    let tree = found.tree.unwrap();
    let trace = found.execution.unwrap();
    let id = source_id(q.proved_target(), &tree);
    let original = checked(q.proved_target(), &tree, &id).unwrap();
    let (core, cost, _) = core::checked(q.proved_target(), &tree).unwrap();
    assert!(cost.useful_steps < cost.original_steps);
    let pruned = checked(q.proved_target(), &core, &id).unwrap();
    let observed = trace.reconcile(&original).unwrap();
    let rebased = trace.reconcile(&pruned).unwrap();
    assert!(!observed.is_empty());
    assert!(rebased.len() < observed.len());
    assert!(
        rebased
            .iter()
            .all(|(_, witness)| pruned.steps.iter().any(|s| &s.witness == witness))
    );
}
