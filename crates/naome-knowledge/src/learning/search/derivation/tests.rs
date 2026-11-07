use super::*;
use naome_authoring::CompiledQuestion;

#[test]
fn oversized_optional_fragments_preserve_checked_parent_training() {
    #[derive(Deserialize)]
    struct Fixture {
        records: Vec<Record>,
    }
    #[derive(Deserialize)]
    struct Record {
        question: String,
        solution: crate::learning::Solution,
        observation: crate::learning::experience::Observation,
    }
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native-fragment-capacity.json"
    ))
    .unwrap();
    let mut raw_oversized = 0;
    let mut omitted_admitted = 0;
    let mut omitted_observed = 0;
    for record in fixture.records {
        let q = CompiledQuestion::compile(&record.question).unwrap();
        let target = if record.solution.refuted {
            q.refuted_target()
        } else {
            q.proved_target()
        };
        let original_id = record.solution.proof_id;
        let (core, _, verified) = core::checked(target, &record.solution.tree).unwrap();
        assert_eq!(crate::hex(verified.native_id.as_bytes()), original_id);
        let (source, tree, state) = source(target, &core, &original_id).unwrap();
        if let Tree::Step { action, children } = tree {
            for (index, (tree, state)) in children
                .iter()
                .zip(next(&state, action).unwrap())
                .enumerate()
            {
                if !matches!(tree, Tree::Step { .. }) {
                    continue;
                }
                if let Ok(fragment) = contextual(&source, tree, &state, &[index])
                    && fragment.packet.len() > crate::learning::knowledge::BYTES
                {
                    raw_oversized += 1;
                    assert!(
                        crate::checkpoint::encode(&fragment).is_err(),
                        "the native packet serializer keeps its existing bound"
                    );
                    assert!(!fragment.within_capacity().unwrap());
                    assert!(
                        fragment.verify().is_err(),
                        "oversized material cannot become an admitted fragment"
                    );
                }
            }
        }
        let derived = checked(target, &core, &original_id).unwrap();
        assert!(!derived.steps.is_empty());
        assert_eq!(derived.source_proof.as_deref(), Some(original_id.as_str()));
        omitted_admitted += derived.oversized_fragments;
        for fragment in &derived.fragments {
            assert!(fragment.within_capacity().unwrap());
            fragment
                .validate_source(target, &core, &original_id)
                .unwrap();
        }
        let mut pool = crate::learning::pool::Pool::default();
        pool.add(
            false,
            "original-source",
            "original-family",
            &original_id,
            compile(target, &core).unwrap().1,
        )
        .unwrap();
        pool.add_derivation(derived, true).unwrap();
        assert!(
            !pool.is_empty(),
            "optional fragment size cannot discard the checked parent's decisions"
        );
        for derived in observed(&record.observation).unwrap() {
            omitted_observed += derived.oversized_fragments;
            if derived.fragments.is_empty() {
                assert!(
                    derived.steps.is_empty(),
                    "an omitted conditional proof supplies no positive targets"
                );
            }
            for fragment in derived.fragments {
                assert!(fragment.within_capacity().unwrap());
                fragment.validate_observation(&record.observation).unwrap();
            }
        }
    }
    assert!(
        raw_oversized > 0,
        "fixture must exercise the original serializer failure"
    );
    assert!(omitted_admitted > 0);
    assert!(omitted_observed > 0);
}

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
            3 => {
                changed.parent = Parent::Admitted {
                    proof: id.clone(),
                    tree: "ff".repeat(32),
                }
            }
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
        pool.add_derivation(checked(target, &tree, &id).unwrap(), true)
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
    let mut masked = crate::learning::pool::Pool::default();
    masked
        .add(
            false,
            "dependency",
            "family",
            "first-checked-path",
            vec![roots[0].clone()],
        )
        .unwrap();
    masked.reconcile(&[], false).unwrap();
    masked
        .add(
            false,
            "dependency",
            "family",
            "second-checked-path",
            vec![roots[1].clone()],
        )
        .unwrap();
    let merged = masked
        .graphs()
        .iter()
        .find(|g| g.key() == roots[0].key())
        .unwrap();
    assert_eq!(
        masked.target_graph(merged, false).successes,
        roots[0].successes,
        "an overlapping auxiliary action cannot enter the original target mask"
    );
    assert!(
        masked
            .target_graph(merged, true)
            .successes
            .contains(&roots[1].expert)
    );
    assert_eq!(
        masked.target_graph(merged, false).key(),
        masked.target_graph(merged, true).key()
    );
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

fn unresolved_observation() -> super::super::super::experience::Observation {
    use crate::learning::{GenerationCost, Origin, digest, experience};
    struct BranchFirst;
    impl Ranker for BranchFirst {
        fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
            Ok(d.candidates
                .iter()
                .map(|c| {
                    if c.rule == Rule::ImplicationBranch {
                        1.
                    } else {
                        0.
                    }
                })
                .collect())
        }
    }
    let q = CompiledQuestion::compile(
        "goal=all(a,all(b,all(c,all(d,imp(imp(mem(a,a),mem(b,b)),imp(imp(mem(d,d),mem(a,a)),imp(mem(d,d),imp(not(not(mem(b,b))),mem(c,c)))))))))",
    ).unwrap();
    assert!(crate::learning::State::eligible(q.source()));
    let started = Instant::now();
    let found = solve(q.proved_target(), &mut BranchFirst, 128).unwrap();
    assert!(
        found.tree.is_none(),
        "the root question is not solved by the recorded search"
    );
    let executions = vec![found.execution.unwrap()];
    let mut summary = experience::ExperienceSummary {
        job: 7,
        question: crate::hex(q.resolution_id()),
        // Explicit symbolic test policy: no fabricated neural execution.
        checkpoint: digest(&"no neural model used"),
        policy: digest(&"branch-first symbolic fixture"),
        request_binding: digest(&q.source()),
        native_context: digest(&Vec::<String>::new()),
        origin: Origin::Local,
        terminal: found.terminal,
        trace: experience::TraceBinding {
            checked_trajectory: None,
            observed_branches: found.frontier.as_ref().map(digest),
            observed_execution: Some(digest(&executions)),
        },
        cost: Some(GenerationCost {
            search_expansions: found.expansions,
            ..GenerationCost::default()
        }),
        search_limit: 128,
        spent_ms: started.elapsed().as_millis() as u64,
        reserved_units: 1,
        receipt: String::new(),
    };
    summary.receipt = digest(&summary);
    let observation = experience::Observation {
        question: q.source().into(),
        summary,
        frontier: found.frontier,
        executions,
        knowledge: Vec::new(),
    };
    observation.validate().unwrap();
    observation
}

#[test]
fn an_unresolved_search_contributes_only_independently_checked_conditional_branches() {
    let observation = unresolved_observation();
    let partials = observed(&observation).unwrap();
    assert!(!partials.is_empty());
    assert!(partials.iter().all(|d| d.source_proof.is_none()));
    let fragments: Vec<_> = partials.iter().flat_map(|d| &d.fragments).collect();
    assert!(
        !fragments.is_empty(),
        "closed observed branch must have its own native proof"
    );
    let question = CompiledQuestion::compile(&observation.question).unwrap();
    for fragment in fragments {
        fragment.validate_observation(&observation).unwrap();
        let proof = fragment.verify().unwrap();
        assert_ne!(&proof.target, question.proved_target());
        assert!(matches!(fragment.parent, Parent::Observed { job: 7, .. }));
        let mut substituted = observation.clone();
        substituted.summary.job += 1;
        substituted.summary.receipt.clear();
        substituted.summary.receipt = crate::learning::digest(&substituted.summary);
        assert!(fragment.validate_observation(&substituted).is_err());
    }
    let mut actions = crate::learning::pool::Pool::default();
    let engine =
        crate::learning::Engine::default().with_targets(crate::learning::model::Targets::Actions);
    actions
        .reconcile(std::slice::from_ref(&observation), engine.rich_targets())
        .unwrap();
    let mut rich = crate::learning::pool::Pool::default();
    rich.reconcile(
        std::slice::from_ref(&observation),
        crate::learning::Engine::default().rich_targets(),
    )
    .unwrap();
    assert!(!actions.is_empty());
    assert!(!rich.is_empty());
    assert_eq!(
        actions.graphs().iter().map(Graph::key).collect::<Vec<_>>(),
        rich.graphs().iter().map(Graph::key).collect::<Vec<_>>(),
        "target masks do not change the observed input schedule"
    );
    assert_eq!(
        actions.derived_counts().fragments,
        rich.derived_counts().fragments,
        "both treatments check the same source; the action mask excludes its auxiliary targets"
    );
    assert!(rich.graphs().iter().all(|g| !g.successes.is_empty()));
}

#[test]
fn matched_observed_inputs_report_active_and_masked_auxiliary_labels() {
    use crate::learning::{Engine, model, pool::Pool, tests::MemoryStore};
    let observation = unresolved_observation();
    let mut pool = Pool::default();
    pool.reconcile(&[observation], true).unwrap();
    let fresh = model::Checkpoint::fresh();
    let mut io = MemoryStore::default();
    let mut measurements = Vec::new();
    for target in [model::Targets::Actions, model::Targets::Rich] {
        let mut engine = Engine::default().with_targets(target);
        let mut cursor = 71;
        engine.train(&fresh, &pool, &mut cursor, &mut io).unwrap();
        assert_eq!(cursor, 71 + 16 * model::UPDATES_PER_UNIT);
        measurements.push(engine.cost.measurements);
    }
    let [actions, rich] = measurements.as_slice() else {
        unreachable!()
    };
    assert_eq!(
        actions.input_digest, rich.input_digest,
        "the actual graph sequence must match, including predecessor edges"
    );
    assert_ne!(actions.target_digest, rich.target_digest);
    assert_eq!(actions.auxiliary_slots, rich.auxiliary_slots);
    assert!(actions.masked_auxiliary_slots > 0);
    assert_eq!(actions.active_auxiliary_slots, 0);
    assert_eq!(actions.cost_targets, 0);
    assert_eq!(actions.preference_targets, 0);
    assert_eq!(rich.masked_auxiliary_slots, 0);
    assert!(rich.active_auxiliary_slots > 0 && rich.cost_targets > 0);
}
