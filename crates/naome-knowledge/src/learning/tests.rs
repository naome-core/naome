fn fixed_state() -> State {
    let mut state = State::fresh();
    state.preparation = Preparation::Targeted;
    state
}
use super::*;

struct UniversalChoice(usize);
impl model::Ranker for UniversalChoice {
    fn scores(&mut self, d: &model::Decision) -> Result<Vec<f32>, String> {
        let offered = d
            .candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| c.rule == model::Rule::UniversalInstance)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let mut scores = vec![0.; d.candidates.len()];
        if let Some(i) = offered.get(self.0) {
            scores[*i] = 1.;
        }
        Ok(scores)
    }
}

#[test]
fn equivalent_universal_choices_share_the_checked_success_mass() {
    let q = ResearchQuestion::from_hex(
        "0404030403010100000002010000000101010000000101000000020301010000000101000000000101000000000100000001",
    )
    .unwrap();
    let mut graphs = Vec::new();
    let mut chosen = std::collections::BTreeSet::new();
    for index in 0..2 {
        let result = search::solve(q.proved_target(), &mut UniversalChoice(index), 32).unwrap();
        let tree = result.tree.unwrap();
        if let search::Tree::Step {
            action: search::Action::Instantiate(_, v),
            ..
        } = &tree
        {
            chosen.insert(*v);
        }
        let (term, states) = search::compile(q.proved_target(), &tree).unwrap();
        proof::verify(&term, q.proved_target()).unwrap();
        assert_eq!(states.len(), 1);
        graphs.push(states.into_iter().next().unwrap());
    }
    assert_eq!(
        chosen.len(),
        2,
        "both native instantiations independently verify"
    );
    for graph in graphs {
        assert_eq!(graph.candidates.len(), 2);
        assert_eq!(
            graph.nodes[graph.candidates[0]],
            graph.nodes[graph.candidates[1]]
        );
        assert_eq!(graph.successes, vec![0, 1]);
    }
}

#[test]
fn different_universal_consequences_keep_separate_labels() {
    let q = ResearchQuestion::from_hex(
        "0404030403010100000000010000000101010000000101000000000301010000000101000000000101000000000100000001",
    )
    .unwrap();
    let result = search::solve(q.proved_target(), &mut UniversalChoice(0), 32).unwrap();
    let (term, states) = search::compile(q.proved_target(), &result.tree.unwrap()).unwrap();
    proof::verify(&term, q.proved_target()).unwrap();
    let graph = &states[0];
    assert_ne!(
        graph.nodes[graph.candidates[0]].right,
        graph.nodes[graph.candidates[1]].right
    );
    assert_eq!(graph.successes, vec![graph.expert]);
}
use naome_foundation::{Formula, FreeVariable, ZfcAxiom};
pub(crate) fn own_question() -> String {
    curriculum::CORPUS
        .cases
        .iter()
        .find(|q| {
            q.id == "0b9642ac64348266b101937f7e963be206ff56282f962f95a8501737bcc3fb7e"
                && !q.development
        })
        .expect("eligible native question")
        .source
        .clone()
}
/// Two admissible helper goals beyond the elementary prefilter.
pub(crate) fn helper_goal() -> (ResearchQuestion, [ResearchQuestion; 2]) {
    let helpers = [
        "04040300010000000101000000000001000000000100000001",
        "040403040300010000000201000000000001000000010100000000040300010000000101000000000001000000020100000000",
    ]
    .map(|s| ResearchQuestion::from_hex(s).unwrap());
    let goal = ResearchQuestion::from_formula(Formula::conjunction(
        helpers[0].formula().clone(),
        helpers[1].formula().clone(),
    ))
    .unwrap();
    (goal, helpers)
}
pub(crate) fn own_example() -> Example {
    let question = own_question();
    let (solution, diagnostic) = search_question(&question, &mut Symbolic, 128).unwrap();
    let solution = solution.unwrap_or_else(|| panic!("own native solution: {diagnostic}"));
    Example {
        origin: Origin::Local,
        job: 41,
        question,
        proof_id: solution.proof_id,
        refuted: solution.refuted,
        tree: solution.tree,
    }
}
#[test]
fn question_seed_preserves_dependency_partitions_and_native_identities() {
    use sha2::{Digest, Sha256};
    let c = &*curriculum::CORPUS;
    assert_eq!(c.cases.iter().filter(|q| !q.development).count(), 1308);
    assert_eq!(c.cases.iter().filter(|q| q.development).count(), 232);
    let mut groups = BTreeMap::new();
    let mut ids = std::collections::BTreeSet::new();
    for q in &c.cases {
        let compiled = ResearchQuestion::from_hex(&q.source).unwrap();
        assert_eq!(crate::hex(compiled.resolution_id()), q.id);
        assert!(ids.insert(q.id.clone()));
        assert!(c.reserved_ids.binary_search(&q.id).is_err());
        let hash = crate::hex(&Sha256::digest(q.dependency.as_bytes()));
        let bucket = u64::from_str_radix(&hash[..8], 16).unwrap() % 5;
        assert_ne!(bucket, 1);
        assert_eq!(q.development, bucket == 0);
        if let Some(old) = groups.insert(q.dependency.clone(), q.development) {
            assert_eq!(old, q.development);
        }
    }
    assert_eq!(curriculum::development().len(), curriculum::DEVELOPMENT);
    assert_eq!(
        curriculum::development()
            .iter()
            .take(curriculum::CORPUS_DEVELOPMENT)
            .map(|q| q.dependency.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        11
    );
    assert!(c.reserved_ids.windows(2).all(|w| w[0] < w[1]));
}
#[test]
fn progress_statistics_remain_canonical_through_repeated_observation_and_reload() {
    let question = own_question();
    let mut state = fixed_state();
    for attempt in 0..200 {
        state.observe(&question, Some(attempt % 3 != 0));
        let bytes = crate::checkpoint::encode(&state).unwrap();
        let restored: State = crate::checkpoint::decode(&bytes).unwrap();
        assert_eq!(crate::checkpoint::encode(&restored).unwrap(), bytes);
        state = restored;
    }
    state.validate().unwrap();
}
#[test]
fn action_graph_preserves_transition_information_and_keeps_labels_out_of_features() {
    use model::{Binding, Candidate, Decision, Rule};
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let p = Formula::member(x, x);
    let q = Formula::member(y, y);
    let mut decision = Decision {
        context: vec![
            Binding {
                formula: Formula::implies(p.clone(), q.clone()),
            },
            Binding { formula: p.clone() },
        ],
        goal: q.clone(),
        candidates: vec![
            Candidate {
                rule: Rule::ModusPonens,
                premises: vec![0, 1],
                consequences: vec![q.clone()],
            },
            Candidate {
                rule: Rule::ImplicationBranch,
                premises: vec![0],
                consequences: vec![Formula::negate(p), q],
            },
        ],
        expert: 0,
    };
    let encoded = graph::Graph::encode(&decision).unwrap();
    assert_eq!(
        encoded.context.len(),
        2,
        "only actual facts enter context pooling"
    );
    let action = &encoded.nodes[encoded.candidates[0]];
    assert_eq!(action.kind, Rule::ModusPonens.kind());
    assert_eq!(
        encoded.nodes[action.left].kind, 14,
        "both MP premises are linked"
    );
    assert_eq!(
        action.right, encoded.goal,
        "the actual consequence is linked to the goal"
    );
    assert_ne!(
        encoded.candidates[0], encoded.context[0],
        "an action must not alias its source formula"
    );
    assert_ne!(encoded.nodes[encoded.candidates[1]].kind, action.kind);
    decision.expert = 1;
    let relabeled = graph::Graph::encode(&decision).unwrap();
    assert_eq!(encoded.nodes, relabeled.nodes);
    assert_eq!(encoded.candidates, relabeled.candidates);
    assert_eq!(encoded.context, relabeled.context);
}
#[test]
fn a_single_new_proof_does_not_trigger_repeated_full_training() {
    let mut state = fixed_state();
    state.accept(own_example()).unwrap();
    assert!(!state.needs_training());
    state.attempted(state.accepted);
    assert!(!state.needs_training());
}
#[test]
fn native_search_reconstructs_classical_quantifier_equality_and_zfc_proofs() {
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let a = Formula::member(x, x);
    let targets = [
        Formula::implies(Formula::negate(Formula::negate(a.clone())), a.clone()),
        Formula::implies(Formula::for_all(y, Formula::member(y, y)), a.clone()),
        Formula::implies(
            Formula::equal(x, y),
            Formula::implies(a, Formula::member(y, y)),
        ),
        ZfcAxiom::Pairing.formula(),
    ];
    for target in targets {
        let source = ResearchQuestion::from_formula(proof::close(target))
            .unwrap()
            .to_hex();
        let solution = search_question(&source, &mut Symbolic, 128)
            .unwrap()
            .0
            .expect("native candidate");
        assert!(!solution.refuted);
        let proof = crate::learning::proof::check_artifact(
            &solution.source,
            &naome_checker::ArtifactState::new(),
        )
        .unwrap();
        assert_eq!(crate::hex(proof.proof_id().as_bytes()), solution.proof_id);
    }
    let source = "040101000000000100000000";
    assert!(
        search_question(source, &mut Symbolic, 1)
            .unwrap()
            .0
            .is_none(),
        "failure is not a refutation label"
    );
}
#[test]
fn learning_replays_only_checked_owned_eligible_solutions_and_is_atomic_on_forgery() {
    let mut state = fixed_state();
    let e = own_example();
    assert!(state.accept(e.clone()).unwrap());
    assert!(!state.accept(e.clone()).unwrap());
    let before = digest(&state);
    let mut forged = e;
    forged.job += 1;
    forged.proof_id = "01".repeat(32);
    forged.tree = search::Tree::Close(0, 0);
    assert!(state.accept(forged).is_err());
    assert_eq!(digest(&state), before);
    let mut job = state.job();
    job.base_hash = "02".repeat(32);
    assert!(job.validate().is_err());
}
#[test]
fn checkpoint_after_work_before_acknowledgement_is_idempotent() {
    let mut job = fixed_state().job();
    let mut engine = Engine::default();
    let mut io = MemoryStore::default();
    let source = curriculum::CORPUS
        .cases
        .iter()
        .find(|q| q.development)
        .unwrap()
        .source
        .clone();
    job.execute(1, Some(&source), 61, &mut engine, &mut io)
        .unwrap();
    let bytes = serde_json::to_vec(&job).unwrap();
    let mut resumed: Job = serde_json::from_slice(&bytes).unwrap();
    resumed.validate().unwrap();
    resumed
        .execute(1, Some(&source), 61, &mut engine, &mut io)
        .unwrap();
    assert_eq!(serde_json::to_vec(&resumed).unwrap(), bytes);
    assert!(
        resumed
            .execute(3, Some(&source), 61, &mut engine, &mut io)
            .is_err()
    );
}
#[test]
fn retained_training_plan_and_measured_cost_cannot_change_between_units() {
    let mut state = State::fresh();
    state.accept(own_example()).unwrap();
    let mut job = state.job();
    job.training = true;
    let mut io = MemoryStore::default();
    let selection = meta::Engine::default().select(&state, &mut io).unwrap();
    let mut progress = finished_progress(&state);
    progress.unit = 1;
    progress.trained = state.trained;
    progress.plan = Some(selection);
    progress.cpu_micros = 10;
    progress.wall_micros = 20;
    job.retain_progress(51, progress.clone()).unwrap();
    let before = digest(&job);
    job.retain_progress(51, progress.clone()).unwrap();
    assert_eq!(before, digest(&job));
    let mut altered = progress.clone();
    altered.plan.as_mut().unwrap().plan.phases[0].focused ^= true;
    assert!(job.retain_progress(51, altered.clone()).is_err());
    altered.unit = 2;
    assert!(job.retain_progress(51, altered).is_err());
    progress.unit = 2;
    progress.cpu_micros = 9;
    assert!(job.retain_progress(51, progress.clone()).is_err());
    assert_eq!(before, digest(&job));
    progress.cpu_micros = 11;
    job.retain_progress(51, progress).unwrap();
}
#[test]
fn meta_outcome_is_bound_to_its_retained_candidate_and_commits_only_once() {
    let mut state = State::fresh();
    state.accept(own_example()).unwrap();
    let lower = state.model.clone();
    let mut job = state.job();
    job.training = true;
    let mut io = MemoryStore::default();
    let mut meta = meta::Engine::default();
    let selection = meta.select(&state, &mut io).unwrap();
    // This typed owner fixture isolates the receipt boundary. Actual lower
    // updates and the full independent gate run in the ordinary node fixture.
    let mut candidate = lower.clone();
    candidate.updates = 250;
    candidate.model = Some(Blob::of(&[1; 32]));
    candidate.optimizer = Some(Blob::of(&[2; 32]));
    let mut previous = finished_progress(&state);
    previous.unit = job.units() - 1;
    previous.plan = Some(selection.clone());
    previous.candidate = Some(candidate.clone());
    previous.transfer.observed = transfer::Summary::prefix(transfer::CASES);
    previous.cpu_micros = 10;
    previous.wall_micros = 20;
    previous.meta_cpu_micros = 1;
    previous.meta_wall_micros = 1;
    job.progress = Some(previous.clone());
    let update = meta
        .learn(
            &state,
            &selection,
            meta::Experience {
                job: 61,
                context: selection.context,
                plan: selection.plan.clone(),
                source_model: digest(&lower),
                selected_model: digest(&lower),
                candidate_model: Some(digest(&candidate)),
                source_epoch: state.epoch,
                before: 0,
                after: 0,
                protected_loss: false,
                anchor_loss: false,
                transfer: previous.transfer,
                lower_cpu_micros: 9,
                lower_wall_micros: 19,
            },
            &mut io,
        )
        .unwrap();
    let mut progress = previous;
    progress.unit = job.units();
    progress.candidate = None;
    progress.rejections += 1;
    progress.meta_update = Some(update);
    progress.cpu_micros = 13;
    progress.wall_micros = 23;
    progress.meta_cpu_micros = 2;
    progress.meta_wall_micros = 2;
    let retained = digest(&job);
    let mut forged = progress.clone();
    forged
        .meta_update
        .as_mut()
        .unwrap()
        .experience
        .candidate_model = None;
    assert!(job.retain_progress(61, forged).is_err());
    assert!(job.retain_progress(62, progress.clone()).is_err());
    assert_eq!(retained, digest(&job));
    job.retain_progress(61, progress.clone()).unwrap();
    job.retain_progress(61, progress).unwrap();
    assert!(state.qualify(&job));
    assert_eq!(state.model, lower);
    assert_eq!(state.meta.trials, 1);
    assert_eq!(state.meta.model.updates, 8);
    assert!(!state.qualify(&job));
}
#[test]
fn partial_meta_pair_write_replays_the_same_measured_trial_and_update_bytes() {
    struct Interrupted {
        store: MemoryStore,
        writes: usize,
    }
    impl ArtifactIo for Interrupted {
        fn read(&mut self, blob: &Blob, range: std::ops::Range<usize>) -> Result<Vec<u8>, String> {
            self.store.read(blob, range)
        }
        fn write(
            &mut self,
            blob: &Blob,
            range: std::ops::Range<usize>,
            bytes: Vec<u8>,
        ) -> Result<(), String> {
            self.writes += 1;
            if self.writes == 2 {
                return Err("injected partial meta pair write".into());
            }
            self.store.write(blob, range, bytes)
        }
    }
    let mut state = State::fresh();
    state.accept(own_example()).unwrap();
    let mut job = state.job();
    job.training = true;
    let plan = meta::Engine::default()
        .select(&state, &mut MemoryStore::default())
        .unwrap();
    let mut prior = finished_progress(&state);
    prior.unit = job.units() - 1;
    prior.plan = Some(plan);
    prior.cpu_micros = 123456;
    prior.wall_micros = 234567;
    prior.meta_cpu_micros = 23;
    prior.meta_wall_micros = 45;
    prior.diagnostic = "no_ambiguous_training_decisions".into();
    job.progress = Some(prior);
    let original = digest(&job);
    let mut control = job.clone();
    let mut uninterrupted = MemoryStore::default();
    control
        .execute(
            control.units(),
            None,
            71,
            &mut Engine::default(),
            &mut uninterrupted,
        )
        .unwrap();
    let mut interrupted = Interrupted {
        store: MemoryStore::default(),
        writes: 0,
    };
    assert!(
        job.execute(
            job.units(),
            None,
            71,
            &mut Engine::default(),
            &mut interrupted
        )
        .is_err()
    );
    assert_eq!(digest(&job), original);
    assert_eq!(interrupted.store.0.len(), 1);
    // A new Engine models the lost worker. The prior durable cost, plan and
    // candidate define this same trial; retry wall/CPU cannot change its label.
    job.execute(
        job.units(),
        None,
        71,
        &mut Engine::default(),
        &mut interrupted,
    )
    .unwrap();
    job.validate().unwrap();
    let retried = job.progress.as_ref().unwrap().meta_update.as_ref().unwrap();
    let expected = control
        .progress
        .as_ref()
        .unwrap()
        .meta_update
        .as_ref()
        .unwrap();
    assert_eq!(retried.model, expected.model);
    assert_eq!(digest(&retried.experience), digest(&expected.experience));
    assert_eq!(retried.draw, expected.draw);
    assert_eq!(interrupted.store.0, uninterrupted.0);
}
#[test]
fn rejected_candidate_retains_a_trained_incumbent_and_its_exact_adam_continuation() {
    let mut state = fixed_state();
    state.accept(own_example()).unwrap();
    let mut io = MemoryStore::default();
    let mut engine = Engine::default();
    let graphs = state.training_graphs().unwrap();
    let incumbent = model::test_update(&state.model, &graphs, &mut 31, &mut io).unwrap();
    state.model = incumbent.clone();
    state.feedback = crate::training::ability::Feedback::fresh(digest(&state.model));
    let development_parent = state.clone();
    let mut job = state.job();
    job.training = true;
    let (candidate, _, _) = engine
        .train(
            &incumbent,
            &pool::Pool::from_graphs(&graphs),
            &mut 47,
            &mut io,
        )
        .unwrap();
    assert_ne!(candidate.model, incumbent.model);
    assert_ne!(candidate.optimizer, incumbent.optimizer);
    let candidate_for_development_regression = candidate.clone();
    let candidate_for_transfer_regression = candidate.clone();
    let mut finished = job.base.clone();
    finished.trained = finished.accepted;
    job.progress = Some(Progress {
        frontier: None,
        cost: None,
        training_cost: model::TrainingCost::default(),
        unit: job.units() - 1,
        model: finished.model,
        trained: finished.trained,
        promotions: finished.promotions,
        rejections: finished.rejections,
        candidate: Some(candidate),
        rng: 9,
        first_loss: Some(1.),
        last_loss: Some(0.1),
        incumbent_score: 1,
        candidate_score: 2,
        anchor_regression: true,
        development_regression: false,
        original_score: [0, 0],
        transfer: transfer::Summary::default(),
        result: None,
        diagnostic: "candidate_requires_qualification".into(),
        ..finished_progress(&job.base)
    });
    job.execute(job.units(), None, 42, &mut engine, &mut io)
        .unwrap();
    assert_eq!(
        job.progress.as_ref().unwrap().diagnostic,
        "forgetting_rejected"
    );
    assert!(state.qualify(&job));
    assert_eq!(state.model, incumbent);
    let actual = model::test_update(&state.model, &graphs, &mut 59, &mut io).unwrap();
    let expected = model::test_update(&incumbent, &graphs, &mut 59, &mut io).unwrap();
    assert_eq!(
        actual, expected,
        "the next real update must retain both model and Adam state"
    );
    let mut alternate = development_parent;
    let mut job = alternate.job();
    job.training = true;
    let mut progress = finished_progress(&alternate);
    progress.unit = job.units() - 1;
    progress.candidate = Some(candidate_for_development_regression);
    progress.candidate_score = 20;
    progress.incumbent_score = 12;
    progress.original_score = [7, 6];
    progress.development_regression = true;
    job.progress = Some(progress);
    job.execute(job.units(), None, 43, &mut engine, &mut io)
        .unwrap();
    assert_eq!(
        job.progress.as_ref().unwrap().diagnostic,
        "development_regression_rejected"
    );
    assert!(alternate.qualify(&job));
    assert_eq!(alternate.model, incumbent);

    let mut transfer_parent = job.base.clone();
    let mut job = transfer_parent.job();
    job.training = true;
    let mut progress = finished_progress(&transfer_parent);
    progress.unit = job.units() - 1;
    progress.candidate = Some(candidate_for_transfer_regression.clone());
    progress.candidate_score = 2;
    progress.incumbent_score = 1;
    progress.first_loss = Some(1.);
    progress.last_loss = Some(0.9);
    for index in 0..transfer::CASES {
        progress
            .transfer
            .record(index, index == 0, index == 1 || index == 2)
            .unwrap();
    }
    let pending = progress.clone();
    job.progress = Some(progress);
    job.execute(job.units(), None, 44, &mut engine, &mut io)
        .unwrap();
    assert_eq!(
        job.progress.as_ref().unwrap().diagnostic,
        "transfer_regression_rejected"
    );
    job.validate().unwrap();

    let mut invalid_promotion = job.clone();
    let progress = invalid_promotion.progress.as_mut().unwrap();
    progress.model = candidate_for_transfer_regression;
    progress.promotions += 1;
    progress.rejections -= 1;
    progress.diagnostic = "candidate_promoted".into();
    progress.development_after = crate::training::ability::Profile::new(digest(&progress.model));
    progress.finder = None;
    let mut worker_job = job.clone();
    worker_job.progress = Some(pending);
    assert_eq!(
        worker_job
            .retain_progress(44, invalid_promotion.progress.clone().unwrap())
            .unwrap_err(),
        "learning checkpoint loses an incumbent transfer success"
    );

    let restored: Job =
        serde_json::from_slice(&serde_json::to_vec(&invalid_promotion).unwrap()).unwrap();
    restored.validate().unwrap();
    assert!(!transfer_parent.qualify(&restored));
    assert_eq!(transfer_parent.model, incumbent);

    assert!(transfer_parent.qualify(&job));
    assert_eq!(transfer_parent.model, incumbent);
    assert!(!transfer_parent.qualify(&job));
    assert_eq!(transfer_parent.model, incumbent);
}
fn finished_progress(state: &State) -> Progress {
    Progress {
        executions: Vec::new(),
        terminal: experience::TerminalEvidence::NoSearch(experience::NoSearch::TrainingOnly),
        finder: None,
        frontier: None,
        prepared: None,
        plan: None,
        meta_update: None,
        cpu_micros: 0,
        wall_micros: 0,
        meta_cpu_micros: 0,
        meta_wall_micros: 0,
        cost: None,
        training_cost: model::TrainingCost::default(),
        unit: 0,
        model: state.model.clone(),
        trained: state.epoch,
        promotions: state.promotions,
        rejections: state.rejections,
        candidate: None,
        rng: state.draws,
        first_loss: None,
        last_loss: None,
        incumbent_score: 0,
        candidate_score: 0,
        anchor_regression: false,
        development_regression: false,
        original_score: [0, 0],
        transfer: transfer::Summary::default(),
        development_before: crate::training::ability::Profile::new(digest(&state.model)),
        development_after: crate::training::ability::Profile::new(digest(&state.model)),
        regressions: [0; crate::training::ability::SKILLS],
        gains: [0; crate::training::ability::SKILLS],
        result: None,
        diagnostic: String::new(),
    }
}
pub(crate) fn measured_progress() -> Progress {
    let mut progress = finished_progress(&fixed_state());
    let question = ResearchQuestion::from_hex(&own_question()).unwrap();
    progress
        .development_before
        .observe(&question, 32, Some(true), 1234);
    progress
        .development_after
        .observe(&question, 32, Some(false), 5678);
    progress
}
#[derive(Default)]
pub(crate) struct MemoryStore(pub BTreeMap<(String, usize), Vec<u8>>);
impl ArtifactIo for MemoryStore {
    fn read(&mut self, blob: &Blob, range: std::ops::Range<usize>) -> Result<Vec<u8>, String> {
        blob.range_len(&range)?;
        let mut bytes = Vec::new();
        for index in range {
            bytes.extend_from_slice(
                self.0
                    .get(&(blob.sha256.clone(), index))
                    .ok_or("test checkpoint missing")?,
            );
        }
        Ok(bytes)
    }
    fn write(
        &mut self,
        blob: &Blob,
        range: std::ops::Range<usize>,
        bytes: Vec<u8>,
    ) -> Result<(), String> {
        assert_eq!(blob.range_len(&range)?, bytes.len());
        for (index, part) in
            range.zip(bytes.chunks(crate::resources::limits().native_model_chunk_bytes))
        {
            self.0.insert((blob.sha256.clone(), index), part.to_vec());
        }
        Ok(())
    }
}
struct Symbolic;
impl model::Ranker for Symbolic {
    fn scores(&mut self, d: &model::Decision) -> Result<Vec<f32>, String> {
        Ok(vec![0.; d.candidates.len()])
    }
}

pub(crate) fn own_solution() -> Solution {
    search_question(&own_question(), &mut Symbolic, 128)
        .unwrap()
        .0
        .unwrap()
}

#[test]
fn targeted_preparation_rehearses_owned_anchors_without_duplicate_source_weight() {
    let solution = own_solution();
    let mut state = fixed_state();
    assert!(
        state
            .accept(Example {
                origin: Origin::Local,
                job: 1,
                question: own_question(),
                proof_id: solution.proof_id,
                refuted: solution.refuted,
                tree: solution.tree
            })
            .unwrap()
    );
    let original = state
        .training_pool(&[])
        .unwrap()
        .graphs()
        .iter()
        .map(graph::Graph::key)
        .collect::<Vec<_>>();
    assert!(!original.is_empty());
    assert_eq!(state.training_sources().count(), 1);
    state.replay.clear();
    state.validate().unwrap();
    assert_eq!(
        original,
        state
            .training_pool(&[])
            .unwrap()
            .graphs()
            .iter()
            .map(graph::Graph::key)
            .collect::<Vec<_>>()
    );
    assert_eq!(state.local_examples, 1);
    state.preparation = Preparation::Balanced;
    assert!(state.training_pool(&[]).unwrap().is_empty());
}
#[test]
fn evicted_stored_anchor_uses_its_original_owned_evidence_and_existing_source_cap() {
    let solution = own_solution();
    let mut state = fixed_state();
    let trace = solution.tree.clone();
    assert!(
        state
            .accept(Example {
                origin: Origin::Local,
                job: 1,
                question: own_question(),
                proof_id: solution.proof_id.clone(),
                refuted: solution.refuted,
                tree: trace.clone()
            })
            .unwrap()
    );
    state.replay.clear();
    state.anchors[0].tree = search::Tree::Stored {
        coverage: coverage::Profile::of(&state.anchors[0]).unwrap(),
        steps: 1,
        bytes: serde_json::to_vec(&trace).unwrap().len(),
        binding: digest(&trace),
    };
    state.validate().unwrap();
    let mut job = state.job();
    job.training = true;
    assert!(
        job.validate().is_err(),
        "stored rehearsal cannot invent a source trace"
    );
    job.evidence.push(Evidence {
        job: 1,
        proof_id: solution.proof_id,
        trace,
    });
    job.validate().unwrap();
    assert!(!state.training_pool(&job.evidence).unwrap().is_empty());
    job.evidence[0].job = 2;
    assert!(job.validate().is_err());
    let mut other = state.anchors[0].clone();
    other.job = 2;
    for entry in [&mut state.anchors[0], &mut other] {
        let search::Tree::Stored { bytes, .. } = &mut entry.tree else {
            unreachable!()
        };
        *bytes = REPLAY * 8 * 1024 / 2 + 1;
    }
    state.anchors.push(other);
    assert!(
        state.validate().is_err(),
        "retained anchors share the original trace-byte allowance"
    );
}
pub(crate) fn completed(job: &mut Job, solution: Solution) {
    job.progress = Some(Progress {
        terminal: experience::TerminalEvidence::certified(&solution),
        frontier: None,
        cost: Some((*solution.cost).clone()),
        training_cost: model::TrainingCost::default(),
        unit: 1,
        model: job.base.model.clone(),
        trained: job.base.trained,
        promotions: job.base.promotions,
        rejections: job.base.rejections,
        candidate: None,
        rng: 1,
        first_loss: None,
        last_loss: None,
        incumbent_score: 0,
        candidate_score: 0,
        anchor_regression: false,
        development_regression: false,
        original_score: [0, 0],
        transfer: transfer::Summary::default(),
        result: Some(solution),
        diagnostic: "certified_candidate".into(),
        ..finished_progress(&job.base)
    });
}
pub(crate) fn candidate_refs(job: &mut Job, model: Blob, optimizer: Blob) {
    // This fixture tests model chunk custody independently of history preparation.
    job.history_request = None;
    job.history = None;
    let mut state = job.base.clone();
    state.trained = state.accepted;
    let mut candidate = state.model.clone();
    candidate.model = Some(model);
    candidate.optimizer = Some(optimizer);
    candidate.updates += model::UPDATES_PER_UNIT;
    let plan = super::meta::Engine::default()
        .select(&job.base, &mut MemoryStore::default())
        .unwrap();
    job.progress = Some(Progress {
        frontier: None,
        cost: None,
        training_cost: model::TrainingCost::default(),
        unit: 1,
        model: state.model,
        trained: state.trained,
        promotions: state.promotions,
        rejections: state.rejections,
        candidate: Some(candidate),
        rng: 1,
        first_loss: Some(1.),
        last_loss: Some(0.9),
        incumbent_score: 0,
        candidate_score: 0,
        anchor_regression: false,
        development_regression: false,
        original_score: [0, 0],
        transfer: transfer::Summary::default(),
        result: None,
        diagnostic: "candidate_requires_qualification".into(),
        plan: Some(plan),
        ..finished_progress(&job.base)
    });
}

#[test]
fn compact_worker_progress_cannot_replace_parent_replay_or_select_an_unqualified_model() {
    let mut state = fixed_state();
    state.accept(own_example()).unwrap();
    let mut job = state.job();
    job.training = true;
    completed(&mut job, own_solution());
    job.progress.as_mut().unwrap().result = None;
    job.progress.as_mut().unwrap().terminal =
        experience::TerminalEvidence::NoSearch(experience::NoSearch::TrainingOnly);
    job.progress.as_mut().unwrap().cost = None;
    job.validate().unwrap();
    let progress = serde_json::to_value(job.progress.as_ref().unwrap()).unwrap();
    assert!(progress.get("state").is_none() && progress.get("replay").is_none());
    assert!(
        serde_json::to_vec(&progress).unwrap().len() * (job.units() as usize)
            < crate::resources::limits().provider_stream_bytes / 2
    );
    job.progress.as_mut().unwrap().model.seed += 1;
    assert!(
        job.validate()
            .unwrap_err()
            .contains("before successful qualification")
    );
}

#[test]
fn later_better_proof_advances_replay_revision_without_recounting_the_question() {
    let original = own_example();
    let q = ResearchQuestion::from_hex(&original.question).unwrap();
    let target = q.proved_target();
    let (term, _) = search::compile(target, &original.tree).unwrap();
    let k = proof::Kernel::new(naome_proof::ProofStep::Simplification {
        antecedent: target.clone().into(),
        consequent: target.clone().into(),
    })
    .unwrap();
    let detour = proof::Term::apply(
        proof::Term::apply(proof::Term::Kernel(k), term.clone()).unwrap(),
        term,
    )
    .unwrap();
    let checked = proof::verify(&detour, target).unwrap();
    let mut earlier = original.clone();
    earlier.proof_id = crate::hex(checked.native_id.as_bytes());
    earlier.tree = search::Tree::Certificate(
        peer::pack(&checked.certificate.to_canonical_bytes(), &[]).unwrap(),
    );
    earlier.job = 40;
    assert_ne!(earlier.proof_id, original.proof_id);
    let mut state = fixed_state();
    assert!(state.consider(earlier, true).unwrap());
    let unique = state.sample_counts();
    assert!(state.consider(original.clone(), false).unwrap());
    assert_eq!(state.sample_counts(), unique);
    assert_eq!(state.accepted, 1);
    assert_eq!(state.epoch, 2);
    assert!(state.replay.len() <= 2);
    assert!(state.replay.iter().any(|e| e.proof_id == original.proof_id));
    assert!(!state.consider(original, false).unwrap());
    assert_eq!(state.epoch, 2);
    state.validate().unwrap();
}

#[test]
fn proof_strategy_cost_uses_the_same_native_unit_for_local_traces_and_peer_dags() {
    let own = own_example();
    let q = ResearchQuestion::from_hex(&own.question).unwrap();
    let (_, cost, checked) = search::core::checked(q.proved_target(), &own.tree).unwrap();
    let native = checked.certificate.steps().len();
    assert_ne!(
        native, cost.useful_steps,
        "the fixture must distinguish macro actions from native steps"
    );
    let peer = search::Tree::Stored {
        coverage: coverage::Profile::of(&own).unwrap(),
        steps: native,
        bytes: serde_json::to_vec(&own.tree).unwrap().len(),
        binding: digest(&own.tree),
    };
    assert_eq!(
        state::proof_steps(q.proved_target(), &own.tree).unwrap(),
        native
    );
    assert_eq!(
        state::proof_steps(q.proved_target(), &peer).unwrap(),
        native
    );
}

#[test]
fn definition_retention_uses_distinct_checked_goal_uses_instead_of_birth_or_reference_count() {
    fn meaning(source: &str) -> definitions::Entry {
        let naome_proof::ArtifactPayload::Definition(d) =
            naome_proof::ArtifactPayload::from_canonical_bytes(&crate::unhex(source).unwrap())
                .unwrap()
        else {
            panic!("definition")
        };
        definitions::Entry {
            certificate: d.canonical_bytes().to_vec(),
            obligation: None,
        }
    }
    fn using(entry: &definitions::Entry) -> Example {
        let mut e = own_example();
        e.tree = search::Tree::Definitions {
            entries: vec![entry.clone()],
            selected: 0,
            available: 1,
            proof: Box::new(e.tree),
        };
        let q = ResearchQuestion::from_hex(&e.question).unwrap();
        e.proof_id = crate::hex(
            search::core::checked(q.proved_target(), &e.tree)
                .unwrap()
                .2
                .native_id
                .as_bytes(),
        );
        e
    }
    let equality = meaning("0100000000020000000b0000000000000000000001");
    let mut state = fixed_state();
    assert!(state.remember_definition(equality.clone()).unwrap());
    let id = crate::hex(equality.address().unwrap().as_bytes());
    assert_eq!(state.definition_uses[&id], 0);
    let example = using(&equality);
    assert!(state.accept(example.clone()).unwrap());
    assert_eq!(state.definition_uses[&id], 1);
    assert!(!state.accept(example).unwrap());
    assert_eq!(state.definition_uses[&id], 1);
    for n in 0..10 {
        let x = naome_foundation::FreeVariable::new(0);
        let y = naome_foundation::FreeVariable::new(1);
        let mut body = Formula::member(x, y);
        for _ in 0..n {
            body = Formula::negate(body);
        }
        let definition = naome_proof::DefinitionCertificate::relation(
            2,
            naome_proof::DefinedFormula::from_primitive(&body).unwrap(),
        )
        .unwrap();
        state
            .remember_definition(definitions::Entry {
                certificate: definition.canonical_bytes().to_vec(),
                obligation: None,
            })
            .unwrap();
    }
    assert!(
        state.definitions.contains(&equality),
        "a useful older meaning survives unused newer meanings"
    );
    assert_eq!(state.definition_uses[&id], 1);
    let restored: State =
        crate::checkpoint::decode(&crate::checkpoint::encode(&state).unwrap()).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored.definition_uses[&id], 1);
    let unused = meaning("0100000000020000000b0100000000000000000001");
    let mut state = fixed_state();
    state.remember_definition(unused.clone()).unwrap();
    let mut unsupported = own_example();
    unsupported.tree = search::Tree::Definitions {
        entries: vec![unused.clone()],
        selected: 0,
        available: 1,
        proof: Box::new(unsupported.tree),
    };
    let q = ResearchQuestion::from_hex(&unsupported.question).unwrap();
    assert!(
        search::core::checked(q.proved_target(), &unsupported.tree).is_err(),
        "a selected but unused name is not a winning decision"
    );
    assert_eq!(
        state.definition_uses[&crate::hex(unused.address().unwrap().as_bytes())],
        0,
        "an unused selected name earns no proof utility"
    );
}

#[test]
fn a_peer_certificate_cannot_be_reclassified_as_a_local_discovery_trace() {
    let mut solution = own_solution();
    let q = ResearchQuestion::from_hex(&own_question()).unwrap();
    let verified = search::core::checked(q.proved_target(), &solution.tree)
        .unwrap()
        .2;
    let mut job = fixed_state().job();
    completed(&mut job, solution.clone());
    job.validate_generated_trace().unwrap();
    solution.tree = search::Tree::Certificate(evidence::pack(&verified).unwrap());
    completed(&mut job, solution);
    assert!(job.validate_generated_trace().is_err());
}

#[test]
fn valid_stored_theorems_beyond_question_capacity_do_not_halt_learning() {
    let mut term = calculus::axiom(naome_proof::ProofStep::EqualityReflexivity {
        variable: naome_foundation::FreeVariable::new(0),
    })
    .unwrap();
    for variable in 0..40 {
        term = proof::Term::Generalize(
            naome_foundation::FreeVariable::new(variable),
            Box::new(term),
        );
    }
    let verified = proof::verify(&term, &term.formula()).unwrap();
    assert!(matches!(
        ResearchQuestion::from_formula(verified.target.clone()),
        Err(naome_checker::question::QuestionError::Limit(_))
    ));
    let entry = knowledge::Entry {
        packet: evidence::pack(&verified).unwrap(),
    };
    let mut state = fixed_state();
    let before = digest(&state);
    assert!(!state.remember_theorem(entry).unwrap());
    assert_eq!(digest(&state), before);
}

#[test]
fn selecting_a_checkpoint_compacts_replay_without_losing_anchors_or_the_model_pair() {
    let mut state = fixed_state();
    state.accept(own_example()).unwrap();
    let anchors = digest(&state.anchors);
    let accepted = state.accepted;
    let capacity = crate::resources::limits().closure_bytes.min(128 * 1024) / 4;
    // Exercise the real byte boundary with checked replay and bounded
    // scheduling observations.
    state.replay.push(state.replay[0].clone());
    crate::learning::tests::fill_checkpoint_budget(&mut state, capacity);
    state.validate().unwrap();
    let before_bytes = crate::checkpoint::encode(&state).unwrap().len();
    let mut job = state.job();
    job.training = true;
    let mut progress = finished_progress(&state);
    progress.unit = job.units();
    progress.rng += u64::from(model::TRAINING_UNITS) * model::UPDATES_PER_UNIT * 16;
    progress.model.updates = 250;
    progress.model.model = Some(Blob::of(&[1; 32]));
    progress.model.optimizer = Some(Blob::of(&[2; 32]));
    progress.promotions += 1;
    progress.transfer = transfer::Summary {
        before: 1,
        after: 3,
        observed: transfer::Summary::prefix(transfer::CASES),
    };
    progress.development_after.checkpoint = digest(&progress.model);
    let selected = progress.model.clone();
    let expanded = crate::checkpoint::encode(&selected).unwrap().len()
        - crate::checkpoint::encode(&state.model).unwrap().len();
    assert!(before_bytes + expanded > capacity);
    job.progress = Some(progress);
    assert!(state.qualify(&job));
    state.validate().unwrap();
    assert!(crate::checkpoint::encode(&state).unwrap().len() <= capacity);
    assert_eq!(state.model, selected);
    assert_eq!(digest(&state.anchors), anchors);
    assert_eq!(state.accepted, accepted);
    assert!(state.replay.len() < job.base.replay.len());
}

#[test]
fn retained_promotion_cannot_trade_a_transfer_family_loss_for_aggregate_gain() {
    let mut state = fixed_state();
    state.accept(own_example()).unwrap();
    let mut job = state.job();
    job.training = true;
    let mut p = finished_progress(&state);
    p.unit = job.units();
    p.promotions = state.promotions + 1;
    p.incumbent_score = 45;
    p.candidate_score = 49;
    p.transfer = transfer::Summary {
        before: 1,
        after: 12,
        observed: transfer::Summary::prefix(transfer::CASES),
    };
    job.progress = Some(p.clone());
    assert!(job.validate().is_err());
    p.transfer.after = 3;
    job.progress = Some(p);
    job.validate().unwrap();
}
#[test]
fn a_later_worker_unit_cannot_rewrite_an_observed_transfer_outcome() {
    let mut state = fixed_state();
    state.accept(own_example()).unwrap();
    let mut job = state.job();
    job.training = true;
    let mut p = finished_progress(&state);
    p.unit = model::TRAINING_UNITS + 1;
    p.first_loss = Some(1.);
    p.last_loss = Some(0.5);
    p.transfer.record(0, true, true).unwrap();
    job.progress = Some(p.clone());
    let before = digest(&job);
    p.unit += 1;
    p.transfer.record(1, false, true).unwrap();
    let mut forged = p.clone();
    forged.transfer.before ^= 1;
    assert!(job.retain_progress(71, forged).is_err());
    assert_eq!(digest(&job), before);
    job.retain_progress(71, p).unwrap();
}

pub(crate) fn stalled_frontier(question: &ResearchQuestion) -> SearchFrontier {
    let failed = search::solve(question.proved_target(), &mut Symbolic, 16).unwrap();
    assert!(failed.tree.is_none());
    failed.frontier.unwrap()
}
pub(crate) fn symbolic_solution(question: &ResearchQuestion) -> Solution {
    search_question(&question.to_hex(), &mut Symbolic, 128)
        .unwrap()
        .0
        .unwrap()
}

/// Fill the real working allowance using only valid current state records.
pub(super) fn fill_checkpoint_budget(state: &mut State, capacity: usize) {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/checked-learning-library.json"
    ))
    .unwrap();
    for (index, row) in fixture["examples"].as_array().unwrap().iter().enumerate() {
        let example = Example {
            origin: Origin::Local,
            job: 100 + index as u64,
            question: row["question"].as_str().unwrap().into(),
            proof_id: row["proof_id"].as_str().unwrap().into(),
            refuted: row["refuted"].as_bool().unwrap(),
            tree: serde_json::from_value(row["tree"].clone()).unwrap(),
        };
        state.replay.push(example);
        if crate::checkpoint::encode(state).unwrap().len() > capacity {
            state.replay.pop();
        }
    }
    // The graph's learned library and definition catalog contribute real
    // checked bytes. Keep sufficient room for a fresh ability observation.
    let budget = capacity - 32;
    for example in state.replay.clone() {
        let question = ResearchQuestion::from_hex(&example.question).unwrap();
        let target = if example.refuted {
            question.refuted_target()
        } else {
            question.proved_target()
        };
        let Ok((_, _, verified)) = search::core::checked(target, &example.tree) else {
            continue;
        };
        let Ok(packet) = evidence::pack(&verified) else {
            continue;
        };
        if state.knowledge.iter().any(|entry| entry.packet == packet) {
            continue;
        }
        state.knowledge.push(knowledge::Entry { packet });
        if knowledge::validate(&state.knowledge).is_err()
            || crate::checkpoint::encode(state).unwrap().len() > budget
        {
            state.knowledge.pop();
        }
    }

    fn repeated(count: usize) -> naome_foundation::Formula {
        use naome_foundation::{Formula, FreeVariable};
        if count == 1 {
            return Formula::member(FreeVariable::new(0), FreeVariable::new(0));
        }
        let half = count / 2;
        Formula::conjunction(repeated(half), repeated(count - half))
    }
    let mut low = 1;
    let mut high = 1024;
    let mut selected = None;
    while low <= high {
        let count = (low + high) / 2;
        let relation = naome_proof::DefinedFormula::from_primitive(&repeated(count)).unwrap();
        let certificate = naome_proof::DefinitionCertificate::relation(1, relation).unwrap();
        let entry = definitions::Entry {
            certificate: certificate.to_canonical_bytes(),
            obligation: None,
        };
        state.definitions.push(entry);
        let fits = state
            .definitions
            .iter()
            .map(definitions::Entry::bytes)
            .sum::<usize>()
            <= definitions::BYTES
            && crate::checkpoint::encode(state).unwrap().len() <= budget;
        let entry = state.definitions.pop().unwrap();
        if fits {
            selected = Some(entry);
            low = count + 1;
        } else {
            high = count - 1;
        }
    }
    if let Some(entry) = selected {
        state.definitions.push(entry);
    }

    let question = ResearchQuestion::from_hex(&own_question()).unwrap();
    for allowance in 256..384 {
        let previous = state.feedback.development.clone();
        for digits in (0..20).rev() {
            state.feedback.development = previous.clone();
            state.feedback.development.observe(
                &question,
                allowance,
                Some(true),
                10_u64.pow(digits),
            );
            if crate::checkpoint::encode(state).unwrap().len() <= capacity {
                break;
            }
        }
        if crate::checkpoint::encode(state).unwrap().len() > capacity {
            state.feedback.development = previous;
            break;
        }
    }
    let remaining = capacity - crate::checkpoint::encode(state).unwrap().len();
    assert!(
        remaining <= 19,
        "checkpoint test fixture leaves {remaining} bytes unused"
    );
    state.feedback.revision = 10_u64.pow(remaining.min(19) as u32);
}
