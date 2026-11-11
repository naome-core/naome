fn fixed_state() -> State {
    let mut state = State::fresh();
    state.preparation = Preparation::Targeted;
    state
}
use super::*;

/// Native qualification fixtures share the process work reservation.
pub(super) fn qualification_fixture() -> std::sync::MutexGuard<'static, ()> {
    static RESERVATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
    RESERVATION
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

struct UniversalChoice(usize);
impl model::Ranker for UniversalChoice {
    fn scores(&mut self, d: &model::Decision) -> Result<Vec<f32>, crate::Error> {
        let offered = d
            .candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| c.rule == model::Rule::UniversalInstance && c.premises.len() == 1)
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
    let direct = ResearchQuestion::from_hex(
        "0404030403010100000002010000000101010000000101000000020301010000000101000000000101000000000100000001",
    )
    .unwrap();
    let [x, y, unused] = [0, 1, 2].map(FreeVariable::new);
    let premise = Formula::member(x, y);
    let intermediate = Formula::member(y, x);
    let conclusion = Formula::member(y, y);
    let universal = Formula::for_all(
        unused,
        Formula::implies(premise.clone(), intermediate.clone()),
    );
    let target = Formula::implies(
        universal,
        Formula::implies(
            premise,
            Formula::implies(
                Formula::implies(intermediate, conclusion.clone()),
                conclusion,
            ),
        ),
    );
    let q =
        ResearchQuestion::from_formula(Formula::for_all(x, Formula::for_all(y, target))).unwrap();
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
        graphs.push(states.into_iter().next().unwrap());
    }
    assert_eq!(
        chosen.len(),
        2,
        "both native instantiations independently verify"
    );
    for graph in graphs {
        let pure: Vec<_> = graph
            .candidates
            .iter()
            .enumerate()
            .filter_map(|(index, root)| {
                let action = &graph.nodes[*root];
                (action.kind == model::Rule::UniversalInstance.kind()
                    && graph.nodes[action.left].kind != 14)
                    .then_some(index)
            })
            .collect();
        assert_eq!(pure.len(), 2);
        assert_eq!(
            graph.nodes[graph.candidates[pure[0]]],
            graph.nodes[graph.candidates[pure[1]]]
        );
        assert_eq!(graph.successes, pure);
    }
    let fused = search::solve(direct.proved_target(), &mut Symbolic, 1).unwrap();
    assert_eq!(fused.expansions, 1);
    let tree = fused.tree.expect("the matched quantifier closes directly");
    assert!(matches!(
        &tree,
        search::Tree::Step {
            action: search::Action::InstantiateApply(..),
            ..
        }
    ));
    let (term, _) = search::compile(direct.proved_target(), &tree).unwrap();
    proof::verify(&term, direct.proved_target()).unwrap();
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
    let solution = solution.unwrap_or_else(|| panic!("own native solution: {diagnostic:?}"));
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
                replacement: None,
                consequences: vec![q.clone()],
            },
            Candidate {
                rule: Rule::ImplicationBranch,
                premises: vec![0],
                replacement: None,
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
    assert!(matches!(
        resumed.execute(3, Some(&source), 61, &mut engine, &mut io),
        Err(crate::Error::Research(
            crate::ResearchFailure::LearningUnitSequence
        ))
    ));
    assert_eq!(serde_json::to_vec(&resumed).unwrap(), bytes);
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
    assert_eq!(
        job.retain_progress(51, altered.clone()).unwrap_err(),
        crate::ResearchFailure::ProgressRepeatedMismatch.into()
    );
    altered.unit = 2;
    assert_eq!(
        job.retain_progress(51, altered).unwrap_err(),
        crate::ResearchFailure::ProgressContinuationMismatch.into()
    );
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
    previous.first_loss = Some(1.);
    previous.last_loss = Some(0.5);
    for _ in 0..curriculum::DEVELOPMENT + state.anchors.len() {
        previous.evaluation.push(false, [false; 2], [32; 2], [1; 2]);
    }
    for index in 0..transfer::CASES {
        previous.evaluation.push(true, [false; 2], [32; 2], [1; 2]);
        previous.transfer.record(index, false, false).unwrap();
    }
    let assessment = previous.evaluation.assessment(&state).unwrap();
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
                assessment: Some(assessment),
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
    progress.assessment = Some(assessment);
    progress.qualification = Qualification::InsufficientResearchValue;
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
    let _reservation = qualification_fixture();
    struct Interrupted {
        store: MemoryStore,
        writes: usize,
    }
    impl ArtifactIo for Interrupted {
        fn read(
            &mut self,
            blob: &Blob,
            range: std::ops::Range<usize>,
        ) -> Result<Vec<u8>, crate::Error> {
            self.store.read(blob, range)
        }
        fn write(
            &mut self,
            blob: &Blob,
            range: std::ops::Range<usize>,
            bytes: Vec<u8>,
        ) -> Result<(), crate::Error> {
            self.writes += 1;
            if self.writes == 2 {
                return Err(crate::WorkerFailure::GrantClosed.into());
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
    prior.qualification = Qualification::NoAmbiguousTrainingDecisions;
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
    let error = job
        .execute(
            job.units(),
            None,
            71,
            &mut Engine::default(),
            &mut interrupted,
        )
        .unwrap_err();
    assert_eq!(error.code(), u32::from(crate::WorkerFailure::GrantClosed));
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
    let _reservation = qualification_fixture();
    let mut state = fixed_state();
    state.accept(own_example()).unwrap();
    let mut io = MemoryStore::default();
    let mut engine = Engine::default();
    let graphs = state.training_graphs().unwrap();
    let incumbent = model::test_update(&state.model, &graphs, &mut 31, &mut io).unwrap();
    state.model = incumbent.clone();
    state.feedback = crate::training::ability::Feedback::fresh(digest(&state.model));
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
    let mut pending = finished_progress(&state);
    pending.unit = job.units() - 1;
    pending.candidate = Some(candidate.clone());
    pending.first_loss = Some(1.);
    pending.last_loss = Some(0.1);
    pending.development_regression = true;
    pending.incumbent_score = 1;
    pending.original_score = [1, 0];
    for index in 0..curriculum::DEVELOPMENT + state.anchors.len() {
        pending
            .evaluation
            .push(false, [index == 0, false], [32; 2], [1; 2]);
    }
    for index in 0..transfer::CASES {
        let checked = [index == 0, index == 1];
        pending.evaluation.push(true, checked, [32; 2], [1; 2]);
        pending
            .transfer
            .record(index, checked[0], checked[1])
            .unwrap();
    }
    job.progress = Some(pending.clone());
    job.execute(job.units(), None, 42, &mut engine, &mut io)
        .unwrap();
    assert_eq!(
        job.progress.as_ref().unwrap().qualification,
        Qualification::InsufficientResearchValue
    );
    job.validate().unwrap();

    let mut forged = job.progress.clone().unwrap();
    forged.model = candidate;
    forged.promotions += 1;
    forged.rejections -= 1;
    forged.qualification = Qualification::Promoted;
    let mut worker = job.clone();
    worker.progress = Some(pending);
    assert!(worker.retain_progress(42, forged.clone()).is_err());
    worker.progress = Some(forged);
    assert!(!state.qualify(&worker));

    assert!(state.qualify(&job));
    assert_eq!(state.model, incumbent);
    let actual = model::test_update(&state.model, &graphs, &mut 59, &mut io).unwrap();
    let expected = model::test_update(&incumbent, &graphs, &mut 59, &mut io).unwrap();
    assert_eq!(
        actual, expected,
        "the next real update retains both model and Adam state"
    );
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
        evaluation: transfer::Evidence::default(),
        assessment: None,
        development_before: crate::training::ability::Profile::new(digest(&state.model)),
        development_after: crate::training::ability::Profile::new(digest(&state.model)),
        regressions: [0; crate::training::ability::SKILLS],
        gains: [0; crate::training::ability::SKILLS],
        result: None,
        qualification: Qualification::NoNewAcceptedSolutions,
        generation: None,
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
    fn read(
        &mut self,
        blob: &Blob,
        range: std::ops::Range<usize>,
    ) -> Result<Vec<u8>, crate::Error> {
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
    ) -> Result<(), crate::Error> {
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
    fn scores(&mut self, d: &model::Decision) -> Result<Vec<f32>, crate::Error> {
        Ok(vec![0.; d.candidates.len()])
    }
}

pub(crate) fn own_solution() -> Solution {
    search_question(&own_question(), &mut Symbolic, 128)
        .unwrap()
        .0
        .unwrap()
}

pub(crate) fn binary_program(
    prefix: &[naome_proof::program::Command],
    secondary: ZfcAxiom,
) -> (String, peer::Packet) {
    use naome_proof::{ArtifactPayload, ProofCertificate, ProofStep, program::Command};
    let original = own_solution();
    let question = own_question();
    let q = ResearchQuestion::from_hex(&question).unwrap();
    let axiom = ProofCertificate::new(vec![ProofStep::ZfcAxiom(secondary)]).unwrap();
    let second = proof::check(axiom.clone(), &naome_checker::ArtifactState::new()).unwrap();
    let offset = prefix.len() as u64;
    let mut commands = prefix.to_vec();
    commands.extend([
        Command::ProofReference {
            proof_id: crate::object::id_bytes(&original.proof_id).unwrap(),
        },
        Command::ProofReference {
            proof_id: *second.proof_id().as_bytes(),
        },
        Command::Simplification {
            antecedent: offset,
            consequent: offset + 1,
        },
        Command::ModusPonens {
            premise: offset,
            implication: offset + 2,
        },
        Command::ModusPonens {
            premise: offset + 1,
            implication: offset + 3,
        },
        Command::Seal { proof: offset + 4 },
    ]);
    let mut artifacts = original
        .helpers
        .iter()
        .chain(std::iter::once(&original.source))
        .map(|hex| std::sync::Arc::from(crate::unhex(hex).unwrap()))
        .collect::<Vec<_>>();
    artifacts.push(ArtifactPayload::Proof(axiom).to_canonical_bytes().into());
    let packet = peer::Packet::compose(q.proved_target(), &commands, &[], artifacts).unwrap();
    (question, packet)
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
        qualification: Qualification::NoNewAcceptedSolutions,
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
        qualification: Qualification::Pending,
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
    let before = digest(&state);
    assert!(
        !state.qualify(&job),
        "incomplete updates cannot become the inference checkpoint"
    );
    assert_eq!(digest(&state), before);
    job.progress.as_mut().unwrap().model.seed += 1;
    assert_eq!(
        job.validate().unwrap_err(),
        crate::ResearchFailure::JobPromotionBinding.into()
    );
    assert!(
        !state.qualify(&job),
        "a substituted update cannot become the inference checkpoint"
    );
    assert_eq!(digest(&state), before);
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
    completed(&mut job, solution.clone());
    assert_eq!(
        job.validate_generated_trace().unwrap_err(),
        crate::ResearchFailure::GeneratedTraceMissing.into()
    );
    solution.tree = search::Tree::Composed {
        packet: Vec::new(),
        inputs: vec!["input".into()],
        work: 1,
    };
    completed(&mut job, solution);
    assert!(matches!(
        job.validate_generated_trace(),
        Err(crate::Error::LearningEvidence(
            crate::EvidenceFailure::Framing
        ))
    ));
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
    evaluate_fixture(&job.base, &mut progress, 1, 0b01010100);
    progress.qualification = Qualification::Promoted;
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

fn evaluate_fixture(base: &State, progress: &mut Progress, before: u32, after: u32) {
    progress.first_loss = Some(1.);
    progress.last_loss = Some(0.5);
    for _ in 0..curriculum::DEVELOPMENT + base.anchors.len() {
        progress.evaluation.push(false, [false; 2], [32; 2], [1; 2]);
    }
    for index in 0..transfer::CASES {
        let checked = [before & (1 << index) != 0, after & (1 << index) != 0];
        progress.evaluation.push(true, checked, [32; 2], [1; 2]);
        progress
            .transfer
            .record(index, checked[0], checked[1])
            .unwrap();
    }
    progress.assessment = Some(progress.evaluation.assessment(base).unwrap());
}

#[test]
fn native_promotion_uses_paired_value_even_with_a_lost_case() {
    let mut state = fixed_state();
    state.accept(own_example()).unwrap();
    let mut job = state.job();
    job.training = true;
    let mut p = finished_progress(&state);
    p.unit = job.units();
    p.model.updates = 250;
    p.model.model = Some(Blob::of(&[1; 32]));
    p.model.optimizer = Some(Blob::of(&[2; 32]));
    p.promotions = state.promotions + 1;
    p.qualification = Qualification::Promoted;
    p.development_after.checkpoint = digest(&p.model);
    evaluate_fixture(&job.base, &mut p, 1, 0b01010100);
    assert!(p.assessment.unwrap().accepts());
    assert_eq!(p.assessment.unwrap().losses, 1);
    job.progress = Some(p.clone());
    job.validate().unwrap();
    let mut changed = state.clone();
    let example = own_example();
    let question = ResearchQuestion::from_hex(&example.question).unwrap();
    let target = question.proved_target();
    let (term, _) = search::compile(target, &example.tree).unwrap();
    let verified = proof::verify(&term, target).unwrap();
    assert!(
        changed
            .remember_theorem(knowledge::Entry {
                packet: evidence::pack(&verified).unwrap(),
            })
            .unwrap()
    );
    let changed_checkpoint = digest(&changed);
    assert!(!changed.qualify(&job));
    assert_eq!(digest(&changed), changed_checkpoint);
    assert!(state.qualify(&job));
    assert_eq!(state.model, p.model);
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
    p.evaluation.push(false, [false; 2], [32; 2], [1; 2]);
    p.evaluation.push(true, [true; 2], [32; 2], [1; 2]);
    job.progress = Some(p.clone());
    let before = digest(&job);
    p.unit += 1;
    p.transfer.record(1, false, true).unwrap();
    p.evaluation.push(false, [false; 2], [32; 2], [1; 2]);
    p.evaluation.push(true, [false, true], [32; 2], [1; 2]);
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

    // Add small, valid observations independently of the completion under test.
    // Grow the final observation's decimal cost and the revision to hit the
    // exact encoded limit despite the coarser sizing of the checked entries.
    let question = crate::test_inputs::question(crate::test_inputs::member_self());
    state.feedback.revision = 1;
    let mut last_allowance = None;
    for allowance in 1..64 {
        let previous = state.feedback.development.clone();
        state
            .feedback
            .development
            .observe(&question, allowance, Some(true), 1);
        if crate::checkpoint::encode(state).unwrap().len() > capacity {
            state.feedback.development = previous;
            break;
        }
        last_allowance = Some(allowance);
    }

    let allowance = last_allowance.expect("checkpoint fixture needs an ability observation");
    let previous = state.feedback.development.clone();
    for digits in (0..20).rev() {
        state.feedback.development = previous.clone();
        state.feedback.development.observe(
            &question,
            allowance,
            Some(true),
            10_u64.pow(digits) - 1,
        );
        if crate::checkpoint::encode(state).unwrap().len() <= capacity {
            break;
        }
    }
    let remaining = capacity - crate::checkpoint::encode(state).unwrap().len();
    assert!(
        remaining <= 19,
        "checkpoint fixture leaves {remaining} bytes unused"
    );
    state.feedback.revision = 10_u64.pow(remaining as u32);
    assert_eq!(crate::checkpoint::encode(state).unwrap().len(), capacity);
}

pub(crate) fn typed_scope_candidate(conjoin: bool) -> (ResearchQuestion, Solution) {
    let [element, set, binder] = [0, 1, 2].map(FreeVariable::new);
    let rule = Formula::for_all(
        binder,
        Formula::implies(
            Formula::member(binder, binder),
            Formula::member(binder, set),
        ),
    );
    let instance = Formula::member(element, set);
    let premise = Formula::member(element, element);
    let consequence = if conjoin {
        Formula::conjunction(instance, premise.clone())
    } else {
        instance
    };
    let target = Formula::for_all(
        element,
        Formula::for_all(
            set,
            Formula::implies(rule, Formula::implies(premise, consequence)),
        ),
    );
    let question = ResearchQuestion::from_formula(target).unwrap();
    let source = question.to_hex();
    let mut engine = Engine::default();
    let mut store = MemoryStore::default();
    let generation = engine
        .with(&model::Checkpoint::fresh(), &mut store, |runtime| {
            solve_with_report(&source, runtime, 32, 1, SolveContext::default())
        })
        .unwrap();
    let solution = generation
        .solution
        .unwrap_or_else(|| panic!("typed scope: {:?}", generation.diagnostic));
    let search::Tree::Scoped { target, actions } = &solution.tree else {
        panic!("native scope action trace absent");
    };
    assert!(actions.iter().any(|action| matches!(
        action,
        naome_proof::program::ScopedAction::Instantiate { premises, .. } if !premises.is_empty()
    )));
    if conjoin {
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, naome_proof::program::ScopedAction::Conjoin { .. }))
        );
    }
    assert!(solution.cost.search_expansions <= 32);
    let (term, training) = search::compile(question.proved_target(), &solution.tree).unwrap();
    assert!(
        !training.is_empty(),
        "the scored typed menu must reach training input"
    );
    assert_eq!(
        proof::verify(&term, question.proved_target())
            .unwrap()
            .native_id
            .as_bytes(),
        &crate::object::id_bytes(&solution.proof_id).unwrap()
    );
    let mut invalid = actions.clone();
    invalid[0] = naome_proof::program::ScopedAction::Conjoin {
        left: 0,
        right: u32::MAX,
    };
    assert!(
        search::compile(
            question.proved_target(),
            &search::Tree::Scoped {
                target: target.clone(),
                actions: invalid
            }
        )
        .is_err()
    );
    (question, solution)
}

pub(crate) fn typed_definition_consumer(
    graph: &crate::Graph,
    first: &ResearchQuestion,
    second: &ResearchQuestion,
) -> (
    ResearchQuestion,
    Solution,
    Vec<String>,
    naome_proof::DefinitionId,
) {
    let relation = naome_proof::DefinitionCertificate::relation(
        2,
        naome_proof::DefinedFormula::member(FreeVariable::new(0), FreeVariable::new(1)),
    )
    .unwrap();
    let definition = definitions::Entry {
        certificate: relation.to_canonical_bytes(),
        obligation: None,
    };
    let target = Formula::conjunction(first.formula().clone(), second.formula().clone());
    let compact = definitions::represent(&target, &[definition]).unwrap();
    let question = ResearchQuestion::from_defined_formula(
        compact.as_defined().unwrap().clone(),
        graph.checked_context(),
    )
    .unwrap();
    assert_eq!(question.dependencies(), &[relation.definition_id().into()]);
    let directory = crate::checkpoint::tests::Directory::new();
    let frontier = crate::frontier::Frontier::open(
        &directory.0,
        graph,
        41,
        crate::jobs::Settings {
            native_proof_learning: true,
            ..Default::default()
        },
    )
    .unwrap();
    let (required, inputs) = frontier.solving_inputs(graph, &question, &[]).unwrap();
    assert_eq!(
        required.len(),
        2,
        "both checked closed subgoals must be offered"
    );
    let source = ResearchQuestion::from_formula(target).unwrap().to_hex();
    let mut engine = Engine::default();
    let mut store = MemoryStore::default();
    let result = engine
        .with(&model::Checkpoint::fresh(), &mut store, |runtime| {
            solve_with_report(
                &source,
                runtime,
                128,
                8,
                SolveContext {
                    required: &required,
                    prerequisites: Some(&inputs),
                    ..Default::default()
                },
            )
        })
        .unwrap();
    let solution = result
        .solution
        .unwrap_or_else(|| panic!("typed context: {:?}", result.diagnostic));
    assert!(
        solution.cost.definition_references > 0,
        "{:?}",
        solution.cost
    );
    assert!(matches!(solution.tree, search::Tree::Program(_)));
    solution.check_target(&question).unwrap();
    (question, solution, required, relation.definition_id())
}

/// Use a stopped receiver from the native-goal process test. The ordinary
/// Finder and Solver must cite its checked program under the original ID.
#[test]
#[ignore = "Requires the checked receiver catalog from the two-node Nat process test"]
fn native_nat_program_reuse_from_a_received_catalog() {
    use naome_checker::ContextView;
    crate::resources::tests::budget(false);
    let directory = std::path::PathBuf::from(std::env::var_os("NAOME_TEST_NAT_CATALOG").unwrap());
    let question =
        ResearchQuestion::from_hex(&std::env::var("NAOME_TEST_NAT_QUESTION").unwrap()).unwrap();
    let mut graph = crate::Graph::open(&directory).unwrap();
    let target = question.proved_target().encode_canonical().unwrap();
    let statement = naome_proof::StatementId::of_canonical_formula(&target).unwrap();
    let id = graph
        .checked_context()
        .statement_header(statement)
        .unwrap()
        .unwrap()
        .proof_id();
    let manifest = graph
        .program_manifest(id.into())
        .unwrap()
        .expect("received Nat program");
    assert_eq!(manifest.proof_id(), id);
    let pairing = naome_proof::ProofCertificate::new(vec![naome_proof::ProofStep::ZfcAxiom(
        naome_foundation::ZfcAxiom::Pairing,
    )])
    .unwrap();
    graph.produce(&proof::artifact(&pairing)).unwrap();
    let target = graph
        .ids_page(None, 16)
        .unwrap()
        .into_iter()
        .filter(|artifact| *artifact != manifest.artifact_id())
        .filter_map(|artifact| graph.learning_question(artifact).unwrap())
        .find_map(|other| {
            ResearchQuestion::from_formula(Formula::conjunction(
                question.formula().clone(),
                other.formula().clone(),
            ))
            .ok()
        })
        .expect("second already checked operand within the question limits");
    let runtime = crate::checkpoint::tests::Directory::new();
    let frontier = crate::frontier::Frontier::open(
        &runtime.0,
        &graph,
        41,
        crate::jobs::Settings {
            native_proof_learning: true,
            ..Default::default()
        },
    )
    .unwrap();
    let meter = crate::resources::feedback::Meter::start();
    let (required, inputs) = frontier.solving_inputs(&graph, &target, &[]).unwrap();
    assert!(required.contains(&crate::hex(id.as_bytes())));
    let mut engine = Engine::default();
    let mut store = MemoryStore::default();
    let result = engine
        .with(&model::Checkpoint::fresh(), &mut store, |runtime| {
            solve_with_report(
                &target.to_hex(),
                runtime,
                128,
                8,
                SolveContext {
                    required: &required,
                    prerequisites: Some(&inputs),
                    native_programs: true,
                    ..Default::default()
                },
            )
        })
        .unwrap();
    let solution = result.solution.expect("checked native composition");
    assert!(solution.source.is_empty() && solution.helpers.is_empty());
    let candidate = super::program::Candidate::from_solution(&solution, &target).unwrap();
    assert!(candidate.commands.iter().any(|command| matches!(
        command, naome_proof::program::Command::ProofReference { proof_id }
            if proof_id == id.as_bytes()
    )));
    let sample = meter.finish(0, true);
    eprintln!(
        "native_nat_prerequisite proof_id={} source_bytes={} result_bytes={} elapsed_micros={} peak_rss_bytes={:?}",
        crate::hex(id.as_bytes()),
        manifest.input_bytes,
        candidate.manifest.input_bytes,
        sample.elapsed_nanos / 1000,
        sample.peak_rss_bytes
    );
}

mod native_prerequisite;
pub(crate) use native_prerequisite::{catalog_case, publish_catalog_solution};
// Independent native checking reserves process-wide memory. Give these
// scenarios separate budgets so the parallel test harness cannot spend them.
pub(super) fn isolated(name: &str) -> bool {
    const CHILD: &str = "NAOME_LEARNING_CHECKER_TEST";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(CHILD, name)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("running 1 test"),
        "{stdout}\n{stderr}"
    );
    print!("{stdout}");
    eprint!("{stderr}");
    false
}

#[test]
fn checked_lemma_index_supplies_a_native_scope_without_mandatory_inputs() {
    if !isolated(
        "learning::tests::checked_lemma_index_supplies_a_native_scope_without_mandatory_inputs",
    ) {
        return;
    }
    let (_, [lemma, _]) = helper_goal();
    let solved = symbolic_solution(&lemma);
    let mut graph = crate::Graph::default();
    let (root, batch) = graph
        .prepare_generated(&solved.source, &solved.helpers, &lemma)
        .unwrap();
    graph
        .commit_batch(
            root,
            batch,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        )
        .unwrap();
    let variable = FreeVariable::new(0);
    let formula = lemma
        .proved_target()
        .open_outer_universal(variable)
        .unwrap();
    let other = FreeVariable::new(1);
    let target = Formula::for_all(
        variable,
        Formula::for_all(
            other,
            Formula::implies(Formula::member(variable, other), formula),
        ),
    );
    let target = ResearchQuestion::from_formula(target).unwrap();
    let directory = crate::checkpoint::tests::Directory::new();
    let mut finder = crate::frontier::Frontier::open(
        &directory.0,
        &graph,
        41,
        crate::jobs::Settings {
            native_proof_learning: true,
            ..Default::default()
        },
    )
    .unwrap();
    finder.refresh(&graph, |_| true).unwrap();
    let (required, inputs) = finder.solving_inputs(&graph, &target, &[]).unwrap();
    assert!(required.is_empty());
    assert!(inputs.has_offer());
    assert!(
        !inputs.is_empty(),
        "structural lookup must supply the checked lemma"
    );
    let mut engine = Engine::default();
    let mut io = MemoryStore::default();
    let generated = engine
        .with(&model::Checkpoint::fresh(), &mut io, |runtime| {
            solve_with_report(
                &target.to_hex(),
                runtime,
                16,
                1,
                SolveContext {
                    prerequisites: Some(&inputs),
                    native_programs: true,
                    ..Default::default()
                },
            )
        })
        .unwrap();
    let solution = generated
        .solution
        .expect("checked scope with a cited lemma");
    solution.check_target(&target).unwrap();
    let search::Tree::Program(packet) = solution.tree else {
        panic!("expected a checked program");
    };
    let expected = crate::object::id_bytes(&solved.proof_id).unwrap();
    assert!(packet.commands().unwrap().iter().any(|command| matches!(
        command, naome_proof::program::Command::ProofReference { proof_id } if *proof_id == expected
    )));
    assert!(
        !peer::program_graphs(target.proved_target(), &packet)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn discovered_relation_is_authored_from_a_previously_checked_meaning() {
    use naome_proof::{ArtifactPayload, ProofSeparation, ProofStep, program::Command};

    const CASE: &str =
        "learning::tests::discovered_relation_is_authored_from_a_previously_checked_meaning";
    const ISOLATED: &str = "NAOME_DEFINITION_AUTHORING_TEST";
    if std::env::var_os(ISOLATED).is_none() {
        let run = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env(ISOLATED, "1")
            .output()
            .unwrap();
        assert!(
            run.status.success() && String::from_utf8_lossy(&run.stdout).contains("running 1 test"),
            "{}
{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        return;
    }
    crate::resources::tests::budget(false);

    fn construct(
        predicate: &Formula,
        earlier: &[definitions::Entry],
        author: bool,
    ) -> (Formula, construction::ProgramCandidate) {
        let term = calculus::axiom(ProofStep::Separation(ProofSeparation {
            predicate: predicate.clone().into(),
            element: FreeVariable::new(0),
            source: FreeVariable::new(1),
            result: FreeVariable::new(2),
            parameters: Vec::new(),
        }))
        .unwrap();
        let target = term.formula();
        let mut recipe = proof::recipe(&term, &target).unwrap();
        recipe.definitions = definitions::construction_choices(&target, earlier).unwrap();
        let candidate = construction::program_from_authored_recipe(
            &target,
            recipe,
            if author { earlier } else { &[] },
        )
        .unwrap();
        (target, candidate)
    }
    fn used_meaning(
        candidate: &construction::ProgramCandidate,
        formula: &Formula,
    ) -> definitions::Entry {
        candidate
            .helpers
            .iter()
            .find_map(|artifact| {
                let bytes = crate::unhex(artifact).unwrap();
                let ArtifactPayload::Definition(certificate) =
                    ArtifactPayload::from_canonical_bytes(&bytes).unwrap()
                else {
                    return None;
                };
                let entry = definitions::Entry {
                    certificate: certificate.to_canonical_bytes(),
                    obligation: None,
                };
                (entry.body().unwrap() == *formula).then_some(entry)
            })
            .expect("the discovered predicate is an actual helper")
    }

    fn publish(graph: &mut crate::Graph, candidate: &construction::ProgramCandidate, name: &str) {
        use crate::{
            graph::program::PreparedProgram, proof_work::Work, resources::adaptive::Budget,
        };
        use naome_proof::program::{CHUNK_BYTES, CHUNK_RECORDS};
        use std::time::{Duration, Instant};

        let staged = graph.prepare_generated_helpers(&candidate.helpers).unwrap();
        let mut work = Work::open(&graph.ownership().directory().join(name)).unwrap();
        work.append_group(&candidate.packet.commands().unwrap())
            .unwrap();
        let budget = Budget {
            memory_bytes: 256 * 1024 * 1024,
            concurrency: 1,
            cache_bytes: 32768,
            batch_steps: 64,
            network_requests: 1,
            yield_ms: 0,
            paused: None,
        };
        while work.advance(&budget, staged.context()).unwrap() {}
        while !work.prepare_export(&budget).unwrap() {}
        let mut checked = PreparedProgram::new(work.into_checked().unwrap());
        let proof = checked.proof().unwrap();
        let manifest = &candidate.packet.manifest;
        proof.check_manifest(manifest).unwrap();
        let store = graph.ownership();
        let mut progress = store.start_program(manifest).unwrap();
        while progress.commands < manifest.commands {
            let chunk = proof
                .input_chunk(progress.commands, CHUNK_RECORDS, CHUNK_BYTES)
                .unwrap();
            progress = store.append_program(manifest, &chunk).unwrap();
        }
        if !checked.advance_after(graph, 64, Some(staged)).unwrap() {
            while !checked.advance(graph, 64).unwrap() {}
        }
        graph
            .commit_batch(
                manifest.artifact_id(),
                checked.take_batch().unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
    }

    let x = FreeVariable::new(0);
    let membership = Formula::member(x, x);
    let equality = Formula::equal(x, x);
    let simple = Formula::implies(
        Formula::negate(membership),
        Formula::implies(equality.clone(), Formula::negate(equality.clone())),
    );
    let compound = Formula::conjunction(simple.clone(), equality);
    let (first_target, first) = construct(&simple, &[], true);
    let parent = used_meaning(&first, &simple);
    let parent_id = parent.certificate().unwrap().definition_id();
    assert!(
        peer::program_definitions(&first_target, &first.packet)
            .unwrap()
            .contains(&parent_id)
    );
    let (target, candidate) = construct(&compound, std::slice::from_ref(&parent), true);
    let derived = used_meaning(&candidate, &compound)
        .certificate()
        .unwrap()
        .definition_id();
    let (_, control) = construct(&compound, std::slice::from_ref(&parent), false);
    assert_eq!(
        candidate.packet.target().unwrap(),
        control.packet.target().unwrap()
    );
    assert_eq!(
        candidate.packet.manifest.statement_id(),
        control.packet.manifest.statement_id()
    );
    assert_ne!(parent_id, derived);

    let commands = candidate.packet.commands().unwrap();
    assert!(commands.iter().any(|command| matches!(command, Command::AuthoredRelation { definition_id, .. } if definition_id == derived.as_bytes())));
    let used = peer::program_definitions(&target, &candidate.packet).unwrap();
    assert!(used.contains(&parent_id) && used.contains(&derived));
    assert!(
        !peer::program_definitions(&target, &control.packet)
            .unwrap()
            .contains(&parent_id)
    );

    let parent_artifact = parent.artifact().unwrap();
    let missing_parent = candidate
        .helpers
        .iter()
        .filter(|helper| **helper != parent_artifact)
        .map(|source| std::sync::Arc::from(crate::unhex(source).unwrap()));
    assert!(peer::Packet::compose(&target, &commands, &[], missing_parent).is_err());

    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = crate::Graph::open(&directory.0).unwrap();
    publish(&mut graph, &first, "first.sqlite3");
    let parent = graph
        .learning_definition(parent_id.into())
        .unwrap()
        .unwrap();
    assert_eq!(parent.artifact().unwrap(), parent_artifact);
    assert!(!graph.contains(derived.into()).unwrap());
    publish(&mut graph, &candidate, "composed.sqlite3");
    let manifest = candidate.packet.manifest.clone();
    drop(graph);

    let mut graph = crate::Graph::open(&directory.0).unwrap();
    let replay = graph.peer_program(manifest.clone()).unwrap().unwrap();
    assert_eq!(replay.manifest, manifest);
    assert_eq!(replay.commands().unwrap(), commands);
    assert_eq!(replay.target().unwrap(), target);
    let earlier = graph.learning_definition(derived.into()).unwrap().unwrap();
    let continuation = Formula::conjunction(compound, Formula::negate(Formula::equal(x, x)));
    let (later_target, later) = construct(&continuation, &[earlier], true);
    assert_ne!(
        later.packet.manifest.statement_id(),
        manifest.statement_id()
    );
    assert!(
        peer::program_definitions(&later_target, &later.packet)
            .unwrap()
            .contains(&derived)
    );
    publish(&mut graph, &later, "downstream.sqlite3");
    assert!(graph.contains(later.packet.manifest.artifact_id()).unwrap());
}

#[test]
fn model_blob_range_and_index_failures_keep_distinct_codes() {
    let blob = Blob::of(b"model");
    assert_eq!(
        blob.chunk_len(1).unwrap_err(),
        crate::Error::Research(crate::ResearchFailure::ModelChunkIndex)
    );
    assert_eq!(
        blob.range_len(&(0..0)).unwrap_err(),
        crate::Error::Research(crate::ResearchFailure::ModelChunkRange)
    );
    let empty = Blob::of(b"");
    assert_eq!(
        empty.validate().unwrap_err(),
        crate::Error::Research(crate::ResearchFailure::ModelBlobCapacity)
    );
}

#[test]
fn history_owner_failure_keeps_its_code_through_learning_execution() {
    struct FailedHistory;
    impl ArtifactIo for FailedHistory {
        fn history(&mut self, _: &history::Request) -> Result<history::Receipt, crate::Error> {
            Err(crate::WorkerFailure::GrantIdentity.into())
        }
        fn read(&mut self, _: &Blob, _: std::ops::Range<usize>) -> Result<Vec<u8>, crate::Error> {
            unreachable!()
        }
        fn write(
            &mut self,
            _: &Blob,
            _: std::ops::Range<usize>,
            _: Vec<u8>,
        ) -> Result<(), crate::Error> {
            unreachable!()
        }
    }
    let mut state = State::fresh();
    state.accept(own_example()).unwrap();
    let mut job = state.job();
    job.training = true;
    job.request_history(1);
    let before = digest(&job);
    let error = job
        .execute(1, None, 1, &mut Engine::default(), &mut FailedHistory)
        .unwrap_err();
    assert_eq!(error.code(), u32::from(crate::WorkerFailure::GrantIdentity));
    assert_eq!(digest(&job), before);
}

#[test]
fn model_owner_failure_keeps_its_code_through_model_loading() {
    struct FailedModel;
    impl ArtifactIo for FailedModel {
        fn read(&mut self, _: &Blob, _: std::ops::Range<usize>) -> Result<Vec<u8>, crate::Error> {
            Err(crate::WorkerFailure::GrantDecoding.into())
        }
        fn write(
            &mut self,
            _: &Blob,
            _: std::ops::Range<usize>,
            _: Vec<u8>,
        ) -> Result<(), crate::Error> {
            unreachable!()
        }
    }
    let mut checkpoint = Checkpoint::fresh();
    checkpoint.model = Some(Blob::of(b"model"));
    checkpoint.optimizer = Some(Blob::of(b"optimizer"));
    let error = Engine::default()
        .with_error(&checkpoint, &mut FailedModel, |_| Ok(()))
        .unwrap_err();
    assert_eq!(error.code(), u32::from(crate::WorkerFailure::GrantDecoding));
}

#[test]
fn model_write_failure_keeps_its_code_through_training_execution() {
    struct FailedWrite;
    impl ArtifactIo for FailedWrite {
        fn read(&mut self, _: &Blob, _: std::ops::Range<usize>) -> Result<Vec<u8>, crate::Error> {
            unreachable!()
        }
        fn write(
            &mut self,
            _: &Blob,
            _: std::ops::Range<usize>,
            _: Vec<u8>,
        ) -> Result<(), crate::Error> {
            Err(crate::WorkerFailure::GrantClosed.into())
        }
    }
    let mut state = fixed_state();
    state.accept(own_example()).unwrap();
    let mut job = state.job();
    job.training = true;
    let before = digest(&job);
    let error = job
        .execute(1, None, 1, &mut Engine::default(), &mut FailedWrite)
        .unwrap_err();
    assert_eq!(error.code(), u32::from(crate::WorkerFailure::GrantClosed));
    assert_eq!(digest(&job), before);
}

#[test]
fn native_artifact_check_preserves_proof_and_format_diagnostics() {
    let context = naome_checker::ArtifactState::new();
    let certificate =
        naome_proof::ProofCertificate::new(vec![naome_proof::ProofStep::ProofReference {
            proof_id: naome_proof::ProofId::from_bytes([7; 32]),
        }])
        .unwrap();
    let bytes = naome_proof::ArtifactPayload::Proof(certificate).to_canonical_bytes();
    let error = proof::check_artifact(&crate::hex(&bytes), &context).unwrap_err();
    assert!(error.diagnostic().is_some());
    assert!(
        serde_json::to_value(&error)
            .unwrap()
            .get("diagnostic")
            .is_some()
    );

    let definition_error = proof::check_artifact("01ff", &context).unwrap_err();
    assert!(
        matches!(definition_error, crate::Error::CertificateFormat(ref value)
        if matches!(value.reason, crate::FormatFailure::UnknownTag {
            domain: crate::FormatTagClass::DefinitionKind, tag: 255
        }))
    );

    let error = proof::check_artifact("ff", &context).unwrap_err();
    assert!(matches!(error, crate::Error::CertificateFormat(ref value)
    if matches!(value.reason, crate::FormatFailure::UnknownTag {
        domain: crate::FormatTagClass::ArtifactPayload, tag: 255
    })));
}

#[test]
fn job_validation_preserves_snapshot_and_missing_theorem_diagnostics() {
    let mut job = fixed_state().job();
    job.base_hash = "different".into();
    assert_eq!(
        job.validate().unwrap_err(),
        crate::ResearchFailure::JobParentSnapshot.into()
    );
    let mut job = fixed_state().job();
    let id = [42; 32];
    job.required = vec![crate::hex(&id)];
    assert_eq!(
        job.validate().unwrap_err(),
        crate::Error::MissingRequiredTheorem(naome_proof::ProofId::from_bytes(id))
    );
}

#[test]
fn state_mutation_preserves_causes_and_rejects_overflow_atomically() {
    let mut state = State::fresh();
    let invalid = definitions::Entry {
        certificate: vec![],
        obligation: None,
    };
    let expected = invalid.certificate().unwrap_err();
    assert_eq!(state.remember_definition(invalid).unwrap_err(), expected);
    assert!(state.definitions.is_empty());

    state.local_examples = u64::MAX;
    let before = digest(&state);
    assert_eq!(
        state.consider(own_example(), true).unwrap_err(),
        crate::ResearchFailure::LearningLocalCountOverflow.into()
    );
    assert_eq!(digest(&state), before);
}

#[test]
fn invalid_search_question_preserves_decoder_failure() {
    let source = "invalid";
    let expected = crate::Error::from(ResearchQuestion::from_hex(source).unwrap_err());
    let actual =
        search_question_report(source, &mut UniversalChoice(0), 1, &SolveContext::default())
            .err()
            .unwrap();
    assert_eq!(actual, expected);
    let mut engine = Engine::default();
    let mut io = MemoryStore::default();
    let actual = engine
        .with_error(&model::Checkpoint::fresh(), &mut io, |runtime| {
            solve_with_report_typed(source, runtime, 1, 1, SolveContext::default())
        })
        .err()
        .unwrap();
    assert_eq!(actual, expected);
}
