use super::*;
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
        let compiled = CompiledQuestion::compile(&q.source).unwrap();
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
    let mut state = State::fresh();
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
    let mut state = State::fresh();
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
        let source = format!("goal={}", proof::close(target).to_source());
        let solution = search_question(&source, &mut Symbolic, 128)
            .unwrap()
            .0
            .expect("native candidate");
        assert!(!solution.refuted);
        let proof = naome_authoring::compile(&solution.source).unwrap();
        assert_eq!(crate::hex(proof.proof_id().as_bytes()), solution.proof_id);
    }
    let source = "goal=all(x,mem(x,x))";
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
    let mut state = State::fresh();
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
    let mut job = State::fresh().job();
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
fn rejected_candidate_retains_a_trained_incumbent_and_its_exact_adam_continuation() {
    let mut state = State::fresh();
    state.accept(own_example()).unwrap();
    let mut io = MemoryStore::default();
    let mut engine = Engine::default();
    let graphs = state.training_graphs().unwrap();
    let incumbent = model::test_update(&state.model, &graphs, &mut 31, &mut io).unwrap();
    state.model = incumbent.clone();
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
    let mut finished = job.base.clone();
    finished.trained = finished.accepted;
    job.progress = Some(Progress {
        cost: None,
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
        result: None,
        diagnostic: "candidate_requires_qualification".into(),
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
}
#[derive(Default)]
pub(crate) struct MemoryStore(pub BTreeMap<(String, usize), Vec<u8>>);
impl ArtifactIo for MemoryStore {
    fn read(&mut self, blob: &Blob, index: usize) -> Result<Vec<u8>, String> {
        self.0
            .get(&(blob.sha256.clone(), index))
            .cloned()
            .ok_or("test checkpoint missing".into())
    }
    fn write(&mut self, blob: &Blob, index: usize, bytes: Vec<u8>) -> Result<(), String> {
        self.0.insert((blob.sha256.clone(), index), bytes);
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
pub(crate) fn completed(job: &mut Job, solution: Solution) {
    job.progress = Some(Progress {
        cost: None,
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
        result: Some(solution),
        diagnostic: "certified_candidate".into(),
    });
}
pub(crate) fn candidate_refs(job: &mut Job, model: Blob, optimizer: Blob) {
    let mut state = job.base.clone();
    state.trained = state.accepted;
    let mut candidate = state.model.clone();
    candidate.model = Some(model);
    candidate.optimizer = Some(optimizer);
    candidate.updates += model::UPDATES_PER_UNIT;
    job.progress = Some(Progress {
        cost: None,
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
        result: None,
        diagnostic: "candidate_requires_qualification".into(),
    });
}

#[test]
fn compact_worker_progress_cannot_replace_parent_replay_or_select_an_unqualified_model() {
    let mut state = State::fresh();
    state.accept(own_example()).unwrap();
    let mut job = state.job();
    job.training = true;
    completed(&mut job, own_solution());
    job.progress.as_mut().unwrap().result = None;
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
fn curriculum_distinguishes_easy_frontier_and_representation_failure() {
    let mut state = State::fresh();
    let easy = own_question();
    let easy_case = CompiledQuestion::compile(&easy).unwrap();
    let easy_group = &curriculum::learning(&crate::hex(easy_case.resolution_id()))
        .unwrap()
        .dependency;
    let frontier = curriculum::CORPUS
        .cases
        .iter()
        .find(|q| !q.development && &q.dependency != easy_group)
        .unwrap();
    state.observe_result(&easy, true, "certified_candidate");
    state.observe_result(&frontier.source, false, "search_budget");
    let chosen = |cursor| {
        let source = state.question(cursor);
        let q = CompiledQuestion::compile(&source).unwrap();
        assert!(State::eligible(&source));
        curriculum::learning(&crate::hex(q.resolution_id()))
            .unwrap()
            .dependency
            .clone()
    };
    assert_eq!(chosen(0), *easy_group);
    assert_eq!(chosen(2), frontier.dependency);
    state.observe_result(&frontier.source, false, "formula_graph_capacity");
    assert_eq!(state.statistics[&frontier.dependency].failures[..2], [1, 1]);
    let recovered: State =
        crate::checkpoint::decode(&crate::checkpoint::encode(&state).unwrap()).unwrap();
    assert_eq!(state.question(2), recovered.question(2));
}

#[test]
fn later_better_proof_advances_replay_revision_without_recounting_the_question() {
    let original = own_example();
    let q = CompiledQuestion::compile(&original.question).unwrap();
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
    earlier.tree =
        search::Tree::Certificate(peer::pack(&checked.certificate.to_canonical_bytes()).unwrap());
    earlier.job = 40;
    assert_ne!(earlier.proof_id, original.proof_id);
    let mut state = State::fresh();
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
    let q = CompiledQuestion::compile(&own.question).unwrap();
    let (_, cost, checked) = search::core::checked(q.proved_target(), &own.tree).unwrap();
    let native = checked.certificate.steps().len();
    assert_ne!(
        native, cost.useful_steps,
        "the fixture must distinguish macro actions from native steps"
    );
    let peer = search::Tree::Peer { steps: native };
    assert_eq!(
        state::proof_steps(q.proved_target(), &own.tree).unwrap(),
        native
    );
    assert_eq!(
        state::proof_steps(q.proved_target(), &peer).unwrap(),
        native
    );
}
