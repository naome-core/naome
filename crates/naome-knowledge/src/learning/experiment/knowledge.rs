//! Matched primitive/retrieval/retained-learning experiment on new compositions.
use super::*;
#[derive(Default)]
struct Store {
    inner: MemoryStore,
    read_bytes: u64,
    written_bytes: u64,
    reads: u64,
    writes: u64,
}
impl ArtifactIo for Store {
    fn read(&mut self, b: &Blob, r: std::ops::Range<usize>) -> Result<Vec<u8>, String> {
        let bytes = self.inner.read(b, r)?;
        self.read_bytes += bytes.len() as u64;
        self.reads += 1;
        Ok(bytes)
    }
    fn write(&mut self, b: &Blob, r: std::ops::Range<usize>, bytes: Vec<u8>) -> Result<(), String> {
        self.written_bytes += bytes.len() as u64;
        self.writes += 1;
        self.inner.write(b, r, bytes)
    }
}
struct Run {
    seed: u64,
    state: State,
    initial: Checkpoint,
    candidate: Checkpoint,
    store: Store,
    rounds: Vec<serde_json::Value>,
    evidence: Vec<Evidence>,
}
fn evidence_for(state: &State, source: &[Evidence]) -> Vec<Evidence> {
    let mut needed = state
        .replay
        .iter()
        .filter_map(Example::evidence_job)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|job| {
            source
                .iter()
                .find(|e| e.job == job)
                .expect("own admitted trace retained")
                .clone()
        })
        .collect::<Vec<_>>();
    needed.sort_by_key(|e| e.job);
    needed
}
fn admit_discovery(
    graph: &mut crate::Graph,
    q: &CompiledQuestion,
    solution: &Solution,
) -> Result<bool, crate::Error> {
    let checked = solution.checked()?.into_checked_proof();
    let outcome = q
        .classify_checked_proof(&checked)
        .map_err(crate::Error::from)?;
    if solution.refuted != (outcome == naome_authoring::QuestionOutcome::Refuted) {
        return Err("own discovery orientation differs".into());
    }
    let root = crate::object::proof_address(&solution.proof_id)?;
    if graph.contains(root)? {
        // This run's Graph already admitted this exact checked derivation.
        // A repeated own discovery is not a new mathematical publication.
        return Ok(false);
    }
    let (prepared, batch) = graph.prepare_generated(&solution.source, &solution.helpers, q)?;
    if root != prepared {
        return Err("own discovery native identity differs".into());
    }
    graph.commit_batch(root, batch, Instant::now() + Duration::from_secs(10))?;
    Ok(true)
}
fn acquire(
    state: &mut State,
    source: &str,
    job: u64,
    engine: &mut Engine,
    store: &mut Store,
    graph: &mut crate::Graph,
    history: (&mut Vec<Evidence>, bool),
) -> serde_json::Value {
    let (all, observe) = history;
    eprintln!(
        "{}",
        serde_json::json!({"event":"own_search_started","job":job,"question":source})
    );
    let started = Instant::now();
    let (solution, diagnostic, cost) = engine
        .with(&state.model, store, |runtime| {
            solve_with_definitions(
                source,
                runtime,
                128,
                job,
                &state.definitions,
                &state.knowledge,
            )
        })
        .unwrap();
    let mut retained = false;
    let mut lemma = false;
    let mut newly_admitted = false;
    if let Some(solution) = &solution {
        let q = CompiledQuestion::compile(source).unwrap();
        newly_admitted = admit_discovery(graph, &q, solution).unwrap_or_else(|error| {
            eprintln!("{}", serde_json::json!({"event":"own_admission_failed","job":job,"solution":solution,"error":error.to_string()}));
            panic!("own search failed ordinary graph admission: {error}")
        });
        let root = crate::object::proof_address(&solution.proof_id).unwrap();
        all.push(Evidence {
            job,
            proof_id: solution.proof_id.clone(),
            trace: solution.tree.clone(),
        });
        retained = state
            .accept(Example {
                origin: Origin::Local,
                job,
                question: source.to_owned(),
                proof_id: solution.proof_id.clone(),
                refuted: solution.refuted,
                tree: solution.tree.clone(),
            })
            .unwrap();
        if observe {
            if let Some(packet) = graph.learning_certificate(root).unwrap() {
                lemma = state
                    .remember_theorem(super::super::knowledge::Entry { packet })
                    .unwrap();
            }
            for entry in definitions::selected(&solution.tree).unwrap() {
                state.remember_definition(entry).unwrap();
            }
        }
    }
    let event = serde_json::json!({"job":job,"question":source,"solution":solution,"diagnostic":diagnostic,"cost":cost,"newly_admitted":newly_admitted,"accepted_replay":retained,"accepted_lemma":lemma,"elapsed_micros":started.elapsed().as_micros()});
    eprintln!(
        "{}",
        serde_json::json!({"event":"own_search_completed","acquisition":event})
    );
    event
}
fn train(seed: u64, rounds: usize, path: &Path) -> Run {
    std::fs::create_dir_all(path).unwrap();
    let mut state = State::fresh();
    state.model.seed = seed;
    let mut store = Store::default();
    let mut engine = Engine::default();
    state.model = engine.snapshot(&state.model, &mut store).unwrap();
    let initial = state.model.clone();
    export_model(&path.join("initial"), &initial, &store.inner);
    let mut graph = crate::Graph::default();
    let mut all = Vec::new();
    let mut common = Vec::new();
    // Exactly the seven preselected question-only helpers, then a balanced own
    // bootstrap. Only the helper observations populate this matched dictionary.
    for (i, q) in curriculum::composition::BANK.helpers.iter().enumerate() {
        common.push(acquire(
            &mut state,
            &q.source,
            1 + i as u64,
            &mut engine,
            &mut store,
            &mut graph,
            (&mut all, true),
        ));
    }
    let schedule = shuffled_learning(seed)
        .into_iter()
        .filter(|q| !q.family.starts_with("composition-"))
        .filter(|q| {
            !curriculum::composition::BANK
                .helpers
                .iter()
                .any(|helper| helper.id == q.id)
        })
        .take(64 + rounds * 48)
        .collect::<Vec<_>>();
    assert_eq!(schedule.len(), 64 + rounds * 48);
    assert_eq!(
        schedule
            .iter()
            .map(|q| &q.id)
            .collect::<BTreeSet<_>>()
            .len(),
        schedule.len()
    );
    for (i, q) in schedule.iter().take(64).enumerate() {
        common.push(acquire(
            &mut state,
            &q.source,
            100 + i as u64,
            &mut engine,
            &mut store,
            &mut graph,
            (&mut all, false),
        ));
    }
    write(&path.join("common-acquisitions.json"), &common);
    write(&path.join("common-state.json"), &state);
    write(&path.join("common-evidence.json"), &all);
    let dictionary = state.knowledge.clone();
    let meanings = state.definitions.clone();
    let mut compositions = curriculum::composition::BANK
        .learning
        .iter()
        .collect::<Vec<_>>();
    compositions.sort_by_key(|q| Sha256::digest(format!("{seed}:{}", q.id)));
    assert!(compositions.len() >= rounds * 80);
    let mut events = Vec::new();
    let mut candidate = initial.clone();
    for round in 0..rounds {
        let mut acquisitions = Vec::new();
        for (i, q) in compositions.iter().skip(round * 80).take(80).enumerate() {
            acquisitions.push(acquire(
                &mut state,
                &q.source,
                10_000 + round as u64 * 128 + i as u64,
                &mut engine,
                &mut store,
                &mut graph,
                (&mut all, false),
            ));
            if i % 16 == 15 {
                eprintln!(
                    "knowledge_learning seed={seed} round={round} composition_attempts={} accepted={} library={}",
                    i + 1,
                    state.accepted,
                    state.knowledge.len()
                );
            }
        }
        for (i, q) in schedule.iter().skip(64 + round * 48).take(48).enumerate() {
            acquisitions.push(acquire(
                &mut state,
                &q.source,
                10_000 + round as u64 * 128 + 80 + i as u64,
                &mut engine,
                &mut store,
                &mut graph,
                (&mut all, false),
            ));
        }
        assert_eq!(digest(&dictionary), digest(&state.knowledge));
        assert_eq!(digest(&meanings), digest(&state.definitions));
        write(
            &path.join(format!("round-{round}-acquisitions.json")),
            &acquisitions,
        );
        let evidence = evidence_for(&state, &all);
        let pool = state.training_pool(&evidence).unwrap();
        let before = decision_metrics(&state.model, pool.graphs(), &mut engine, &mut store.inner);
        let mut after = serde_json::Value::Null;
        let mut gate = serde_json::Value::Null;
        if state.needs_training() {
            let io_before = store.read_bytes + store.written_bytes;
            let mut job = state.job();
            job.training = true;
            job.evidence = evidence.clone();
            job.validate().unwrap();
            state.attempted(state.learning_epoch());
            for unit in 1..=job.units() {
                job.execute(unit, None, 700_000 + seed, &mut engine, &mut store)
                    .unwrap();
                job.validate().unwrap();
                if unit % 5 == 0 {
                    eprintln!(
                        "knowledge_training seed={seed} round={round} unit={unit}/{}",
                        job.units()
                    );
                }
                if unit == model::TRAINING_UNITS {
                    candidate = job
                        .progress
                        .as_ref()
                        .unwrap()
                        .candidate
                        .as_ref()
                        .unwrap()
                        .clone();
                    after =
                        decision_metrics(&candidate, pool.graphs(), &mut engine, &mut store.inner);
                    export_model(
                        &path.join(format!("round-{round}-candidate")),
                        &candidate,
                        &store.inner,
                    );
                }
                let keep = job
                    .blobs()
                    .into_iter()
                    .chain(initial.blobs())
                    .chain(candidate.blobs())
                    .map(|b| b.sha256.clone())
                    .collect::<BTreeSet<_>>();
                store.inner.0.retain(|(hash, _), _| keep.contains(hash));
            }
            assert!(
                store.read_bytes + store.written_bytes - io_before
                    <= model::REQUIREMENTS.io_bytes as u64,
                "retain the original per-job model IO bound"
            );
            let p = job.progress.as_ref().unwrap();
            gate = serde_json::json!({"diagnostic":p.diagnostic,"incumbent":p.incumbent_score,"candidate":p.candidate_score,"original_scores":p.original_score,"anchor_regression":p.anchor_regression,"development_regression":p.development_regression,"first_loss":p.first_loss,"last_loss":p.last_loss,"training_cost":p.training_cost});
            assert!(state.qualify(&job));
            state.validate().unwrap();
            assert_eq!(digest(&dictionary), digest(&state.knowledge));
            assert_eq!(digest(&meanings), digest(&state.definitions));
        }
        let event = serde_json::json!({"round":round,"accepted":state.accepted,"replay":state.replay.len(),"pool_graphs":pool.graphs().len(),"decision_before":before,"decision_candidate":after,"qualification":gate,"retained_updates":state.model.updates,"read_bytes":store.read_bytes,"written_bytes":store.written_bytes,"read_operations":store.reads,"write_operations":store.writes});
        eprintln!("{event}");
        events.push(event);
        export_model(
            &path.join(format!("round-{round}-selected")),
            &state.model,
            &store.inner,
        );
        write(&path.join(format!("round-{round}-state.json")), &state);
        write(
            &path.join(format!("round-{round}-evidence.json")),
            &evidence,
        );
        write(&path.join("rounds.json"), &events);
    }
    Run {
        seed,
        state,
        initial,
        candidate,
        store,
        rounds: events,
        evidence: all,
    }
}

#[test]
fn repeated_own_discovery_reuses_its_already_checked_graph_root() {
    let source = super::super::tests::own_question();
    let question = CompiledQuestion::compile(&source).unwrap();
    let solution = super::super::tests::own_solution();
    let mut graph = crate::Graph::default();
    assert!(admit_discovery(&mut graph, &question, &solution).unwrap());
    let accepted = graph.accepted_count();
    assert!(!admit_discovery(&mut graph, &question, &solution).unwrap());
    assert_eq!(graph.accepted_count(), accepted);
    let other = CompiledQuestion::compile("goal=all(x,mem(x,x))").unwrap();
    assert!(admit_discovery(&mut graph, &other, &solution).is_err());
    assert_eq!(graph.accepted_count(), accepted);
}
fn contains_question(entry: &super::super::knowledge::Entry, q: &CompiledQuestion) -> bool {
    let v = entry.verified().unwrap();
    let matches = |formula: &naome_foundation::Formula| {
        formula == q.proved_target() || formula == q.refuted_target()
    };
    if matches(&v.target) {
        return true;
    }
    let context = proof::lemma_context(&v.definitions, &v.lemmas).unwrap();
    context
        .proof_conclusions()
        .any(|(_, _, formula, _)| matches(formula))
}
fn evaluate_arm(
    run: &mut Run,
    model: &Checkpoint,
    cases: &[curriculum::Case],
    arm: &str,
    budget: usize,
    path: &Path,
) -> Vec<serde_json::Value> {
    let mut engine = Engine::default();
    let mut rows = Vec::new();
    for (i, q) in cases.iter().enumerate() {
        let mut known = if arm == "A_primitive" || arm == "C_empty" {
            Vec::new()
        } else {
            run.state.knowledge.clone()
        };
        let meanings = if arm == "A_primitive" || arm == "C_empty" {
            Vec::new()
        } else {
            run.state.definitions.clone()
        };
        let helper = q
            .family
            .strip_prefix("composition-helper-")
            .and_then(|s| s.parse::<usize>().ok());
        let required = helper.map(|h| {
            CompiledQuestion::compile(&curriculum::composition::BANK.helpers[h].source).unwrap()
        });
        let offered_before = known.len();
        let mut required_present = false;
        if let Some(required) = &required {
            required_present = known.iter().any(|entry| contains_question(entry, required));
            if arm == "C_missing" {
                known.retain(|entry| !contains_question(entry, required));
            }
        }
        let removed_entries = offered_before - known.len();
        let target = CompiledQuestion::compile(&q.source).unwrap();
        assert!(
            known.iter().all(|entry| !contains_question(entry, &target)),
            "no exact target answer anywhere in the dictionary closure"
        );
        let started = Instant::now();
        let result = engine.with(model, &mut run.store, |runtime| {
            solve_with_definitions(
                &q.source,
                runtime,
                budget,
                900_000 + i as u64,
                &meanings,
                &known,
            )
        });
        let elapsed = started.elapsed().as_micros();
        let (solution, diagnostic, cost) = match result {
            Ok(r) => r,
            Err(e) => (
                None,
                format!("provider_error: {e}"),
                GenerationCost::default(),
            ),
        };
        let mut citations = 0;
        let mut existing_references = 0;
        let mut existing_roots = 0;
        let mut definition_refs = 0;
        let mut existing_definition_refs = 0;
        let mut definition_decisions = 0;
        let mut plans = 0;
        let mut root_steps = 0;
        let mut closure_steps = 0;
        if let Some(solution) = &solution {
            let actual = solution.checked().unwrap().into_checked_proof();
            assert_eq!(crate::hex(actual.proof_id().as_bytes()), solution.proof_id);
            let target = if solution.refuted {
                target.refuted_target()
            } else {
                target.proved_target()
            };
            let (core, _, verified) = search::core::checked(target, &solution.tree).unwrap();
            let graphs = search::compile(target, &core).unwrap().1;
            let known_ids = super::super::knowledge::proof_ids(&known).unwrap();
            let cited = verified
                .lemmas
                .iter()
                .chain(std::iter::once(&verified.certificate))
                .flat_map(|c| c.steps())
                .filter_map(|s| match s {
                    naome_proof::ProofStep::ProofReference { proof_id }
                        if known_ids.contains(proof_id) =>
                    {
                        Some(*proof_id)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            let known_definitions = meanings
                .iter()
                .map(|entry| entry.certificate().unwrap().definition_id())
                .collect::<BTreeSet<_>>();
            existing_definition_refs = verified
                .lemmas
                .iter()
                .chain(std::iter::once(&verified.certificate))
                .flat_map(|c| c.steps())
                .flat_map(naome_proof::ProofStep::definition_references)
                .filter(|id| known_definitions.contains(id))
                .count();
            definition_decisions = graphs
                .iter()
                .filter(|g| {
                    g.candidates
                        .iter()
                        .any(|i| g.nodes[*i].kind == model::Rule::DefinitionReference.kind())
                })
                .count();
            existing_references = cited.len();
            existing_roots = cited.into_iter().collect::<BTreeSet<_>>().len();
            root_steps = verified.certificate.steps().len();
            closure_steps = root_steps
                + verified
                    .lemmas
                    .iter()
                    .map(|c| c.steps().len())
                    .sum::<usize>();
            citations = verified
                .certificate
                .steps()
                .iter()
                .filter(|s| matches!(s, naome_proof::ProofStep::ProofReference { .. }))
                .count();
            definition_refs = actual
                .direct_artifact_dependencies()
                .iter()
                .filter(|id| {
                    verified
                        .definitions
                        .iter()
                        .any(|d| d.address().is_ok_and(|a| a == **id))
                })
                .count();
            plans = graphs
                .iter()
                .filter(|g| {
                    g.candidates.iter().any(|i| {
                        g.nodes[*i].kind == model::Rule::ConstructionPlan.kind()
                            || g.nodes[*i].kind == model::Rule::LemmaReference.kind()
                    })
                })
                .count();
        }
        rows.push(serde_json::json!({"id":q.id,"dependency":q.dependency,"family":q.family,"arm":arm,"budget":budget,"required_helper_present_before_control":required_present,"offered_lemmas":known.len(),"removed_entries":removed_entries,"solved":solution.is_some(),"refuted":solution.as_ref().map(|s|s.refuted),"diagnostic":diagnostic,"cost":cost,"search_and_load_micros":elapsed,"root_steps":root_steps,"closure_steps":closure_steps,"root_citations":citations,"existing_lemma_references":existing_references,"existing_lemma_roots_used":existing_roots,"definition_dependencies":definition_refs,"existing_definition_references":existing_definition_refs,"definition_decisions":definition_decisions,"hierarchical_decisions":plans,"solution":solution}));
    }
    write(path, &rows);
    eprintln!(
        "knowledge_confirmation seed={} arm={arm} budget={budget} solved={}/{}",
        run.seed,
        rows.iter().filter(|q| q["solved"] == true).count(),
        rows.len()
    );
    rows
}

#[test]
#[ignore = "Explicit finite native knowledge-learning experiment; Release only"]
fn matched_knowledge_learning_experiment() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "Release required"
    );
    let output = std::env::var("NAOME_KNOWLEDGE_OUTPUT").expect("explicit local output directory");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve all earlier attempts");
    std::fs::create_dir_all(output).unwrap();
    let pilot = std::env::var_os("NAOME_KNOWLEDGE_PILOT").is_some();
    let seeds = if pilot {
        vec![1327]
    } else {
        vec![1423, 1543, 1663]
    };
    let rounds = if pilot { 1 } else { 2 };
    let bank = &*curriculum::composition::BANK;
    write(
        &output.join("bank.json"),
        &serde_json::json!({"helpers":bank.helpers,"learning":bank.learning,"development":bank.development,"confirmation":bank.confirmation}),
    );
    let protocol: serde_json::Value =
        serde_json::from_str(include_str!("../knowledge-protocol.json")).unwrap();
    write(&output.join("protocol.json"), &protocol);
    let source = std::env::var("NAOME_KNOWLEDGE_COMMIT")
        .unwrap_or_else(|_| "unfrozen-engineering-pilot".into());
    write(
        &output.join("run-source.json"),
        &serde_json::json!({"source_commit":source,"specification":Checkpoint::fresh().specification,"bank_sha256":digest(&( &bank.helpers,&bank.learning,&bank.development,&bank.confirmation)),"protocol_sha256":crate::hex(&Sha256::digest(include_bytes!("../knowledge-protocol.json"))),"pilot":pilot,"seeds":seeds,"rounds":rounds,"parameters":model::PARAMETERS,"backend":"Burn CPU Flex float32","training_before_confirmation":true}),
    );
    let started = Instant::now();
    let mut runs = Vec::new();
    for seed in &seeds {
        runs.push(train(*seed, rounds, &output.join(format!("seed-{seed}"))));
    }
    // Every learning job and selection decision across all seeds has ended
    // before the first call on a final-confirmation composition.
    let learned_at = started.elapsed().as_micros();
    let mut results = Vec::new();
    for run in &mut runs {
        let cases = if pilot {
            &bank.development
        } else {
            &bank.confirmation
        };
        let path = output.join(format!("seed-{}", run.seed));
        let initial = run.initial.clone();
        let selected = run.state.model.clone();
        let candidate = run.candidate.clone();
        let mut arms = Vec::new();
        for (arm, model) in [
            ("A_primitive", &initial),
            ("B_frozen_with_knowledge", &initial),
            ("C_retained_with_knowledge", &selected),
            ("C_empty", &selected),
            ("C_missing", &selected),
            ("D_last_unselected_candidate", &candidate),
        ] {
            arms.push(serde_json::json!({"arm":arm,"budget":32,"rows":evaluate_arm(run,model,cases,arm,32,&path.join(format!("{arm}-32.json")))}));
        }
        if !pilot {
            for (arm, model) in [
                ("A_primitive", &initial),
                ("B_frozen_with_knowledge", &initial),
                ("C_retained_with_knowledge", &selected),
            ] {
                arms.push(serde_json::json!({"arm":arm,"budget":128,"rows":evaluate_arm(run,model,cases,arm,128,&path.join(format!("{arm}-128.json")))}));
            }
        }
        let evidence = evidence_for(&run.state, &run.evidence);
        write(&path.join("final-evidence.json"), &evidence);
        results.push(serde_json::json!({"seed":run.seed,"initial":run.initial,"retained":run.state.model,"last_candidate":run.candidate,"retained_updates":run.state.model.updates,"library":run.state.knowledge,"definitions":run.state.definitions,"rounds":run.rounds,"arms":arms}));
        write(
            &output.join("results.json"),
            &serde_json::json!({"source_commit":source,"pilot":pilot,"training_finished_micros":learned_at,"elapsed_micros":started.elapsed().as_micros(),"runs":results}),
        );
    }
}
