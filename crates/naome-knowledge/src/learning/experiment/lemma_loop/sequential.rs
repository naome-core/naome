//! Finite parameter-learning validation, separate from symbolic graph gains.
use super::super::knowledge::evidence_for;
use super::*;
const STAGES: [&str; 3] = [
    "equality_transport",
    "inclusion_composition",
    "quantified_transfer",
];
const ARMS: [&str; 3] = ["balanced_replay", "current_task_only", "frozen"];
const SEEDS: [u64; 3] = [41, 73, 101];
const PER_STAGE: usize = 8;
const INFERENCE: usize = 128;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Source {
    stage: usize,
    receipt: u64,
    question: String,
    solution: Solution,
    origin: Value,
}
fn families(q: &CompiledQuestion, depth: usize, out: &mut BTreeSet<String>) {
    out.insert(curriculum::owned::family(q.proved_target()));
    if depth >= 2 {
        return;
    }
    if let Some((left, nr)) = q
        .formula()
        .view()
        .negated()
        .and_then(|f| f.implication_parts())
        && let Some(right) = nr.negated()
    {
        for part in [left.to_owned(), right.to_owned()] {
            families(
                &CompiledQuestion::from_formula(part).unwrap(),
                depth + 1,
                out,
            );
        }
    }
}
fn sources(root: &Path, output: &Path, excluded: &BTreeSet<String>) -> Vec<Vec<Source>> {
    let rows: Vec<Value> =
        serde_json::from_slice(&std::fs::read(root.join("results.json")).unwrap()).unwrap();
    let mut best = BTreeMap::<(usize, String), Source>::new();
    for (row_index, row) in rows.iter().enumerate() {
        if row["seed"] != 41 {
            continue;
        }
        let Some(stage) = STAGES.iter().position(|g| row["family"] == *g) else {
            continue;
        };
        let Some(arms) = row["arms"].as_object() else {
            continue;
        };
        for (arm_index, (arm, _)) in arms.iter().enumerate() {
            let path = root
                .join("41")
                .join(row["id"].as_str().unwrap())
                .join(arm)
                .join("events.json");
            let bytes = std::fs::read(&path).unwrap();
            let events: Vec<Value> = serde_json::from_slice(&bytes).unwrap();
            for (event_index, event) in events.iter().enumerate() {
                if event["solution"].is_null() {
                    continue;
                }
                let question =
                    CompiledQuestion::compile(event["question"].as_str().unwrap()).unwrap();
                if !State::eligible(question.source())
                    || excluded.contains(&curriculum::owned::family(question.proved_target()))
                {
                    continue;
                }
                let solution: Solution = serde_json::from_value(event["solution"].clone()).unwrap();
                let key = (stage, crate::hex(question.resolution_id()));
                // Data selection is frozen from old development evidence only.
                let source = Source {
                    stage,
                    receipt: 1
                        + row_index as u64 * 1024
                        + arm_index as u64 * 128
                        + event_index as u64,
                    question: question.source().into(),
                    solution,
                    origin: json!({"events":path,"events_sha256":crate::hex(&Sha256::digest(&bytes)),
                        "run_seed":41,"root":row["id"],"arm":arm,"job_seed":event["job_seed"],"event_index":event_index}),
                };
                if best.get(&key).is_none_or(|old| {
                    (source.solution.cost.useful_steps, &source.solution.proof_id)
                        < (old.solution.cost.useful_steps, &old.solution.proof_id)
                }) {
                    best.insert(key, source);
                }
            }
        }
    }
    let groups = (0..STAGES.len())
        .map(|stage| {
            best.iter()
                .filter(|((s, _), _)| *s == stage)
                .take(PER_STAGE)
                .map(|(_, s)| s.clone())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    // Exact input receipts precede independent rechecking and every model run.
    write(&output.join("selected-inputs.json"), &groups);
    assert!(
        groups.iter().all(|g| g.len() >= 2),
        "inadequate source pool is not learning evidence"
    );
    groups
}
fn example(source: &Source) -> Example {
    Example {
        origin: Origin::Local,
        job: source.receipt,
        question: source.question.clone(),
        proof_id: source.solution.proof_id.clone(),
        refuted: source.solution.refuted,
        tree: source.solution.tree.clone(),
    }
}
fn pool(state: &State, evidence: &[Evidence], current: Option<&BTreeSet<u64>>) -> pool::Pool {
    let mut pool = pool::Pool::default();
    for e in state
        .training_sources()
        .filter(|e| current.is_none_or(|jobs| jobs.contains(&e.job)))
    {
        let q = CompiledQuestion::compile(&e.question).unwrap();
        let target = if e.refuted {
            q.refuted_target()
        } else {
            q.proved_target()
        };
        let (tree, _, checked) =
            search::core::checked(target, e.trajectory(evidence).unwrap()).unwrap();
        assert_eq!(crate::hex(checked.native_id.as_bytes()), e.proof_id);
        let case = curriculum::owned::case(&e.question).unwrap();
        pool.add(
            false,
            &case.dependency,
            &case.family,
            &e.proof_id,
            search::compile(target, &tree).unwrap().1,
        )
        .unwrap();
    }
    pool
}
fn evaluate_questions(
    c: &Checkpoint,
    questions: &[String],
    engine: &mut Engine,
    io: &mut Store,
) -> Vec<Value> {
    questions.iter().map(|source| {
        let q = CompiledQuestion::compile(source).unwrap();
        let generated = engine.with(c,io,|runtime| solve_with_report(source,runtime,INFERENCE,100,SolveContext::default()));
        match generated {
            Ok(g) => {
                if let Some(s) = &g.solution {
                    q.classify_checked_proof(&s.checked().unwrap().into_checked_proof()).unwrap();
                }
                json!({"id":crate::hex(q.resolution_id()),"solved":g.solution.is_some(),
                    "proof_id":g.solution.map(|s|s.proof_id),"diagnostic":g.diagnostic,"cost":g.cost})
            },
            Err(error) => json!({"id":crate::hex(q.resolution_id()),"solved":false,"technical_failure":error}),
        }
    }).collect()
}
fn readout(
    c: &Checkpoint,
    groups: &[Vec<Source>],
    fresh: &Inputs,
    engine: &mut Engine,
    io: &mut Store,
) -> Value {
    let mut tasks = Vec::new();
    for (stage, group) in groups.iter().enumerate() {
        let questions = group.iter().map(|s| s.question.clone()).collect::<Vec<_>>();
        let mut checked_pool = pool::Pool::default();
        for source in group {
            let e = example(source);
            let q = CompiledQuestion::compile(&e.question).unwrap();
            let target = if e.refuted {
                q.refuted_target()
            } else {
                q.proved_target()
            };
            let graphs = search::compile(target, &e.tree).unwrap().1;
            let case = curriculum::owned::case(&e.question).unwrap();
            checked_pool
                .add(false, &case.dependency, &case.family, &e.proof_id, graphs)
                .unwrap();
        }
        let metrics = engine
            .with(c, io, |runtime| {
                let mut correct = 0;
                let mut loss = 0f64;
                for graph in checked_pool.graphs() {
                    let scores = runtime.scores_graph(graph)?;
                    let selected = (0..scores.len())
                        .max_by(|a, b| scores[*a].total_cmp(&scores[*b]).then(b.cmp(a)))
                        .unwrap();
                    correct += usize::from(graph.successes.contains(&selected));
                    let maximum = scores.iter().copied().fold(f32::NEG_INFINITY, f32::max);
                    let total = scores
                        .iter()
                        .map(|s| f64::from(*s - maximum).exp())
                        .sum::<f64>();
                    let success = graph
                        .successes
                        .iter()
                        .map(|i| f64::from(scores[*i] - maximum).exp())
                        .sum::<f64>();
                    loss += total.ln() - success.ln();
                }
                Ok(
                    json!({"states":checked_pool.graphs().len(),"top_one":correct,
                "mean_cross_entropy":loss/checked_pool.graphs().len().max(1) as f64}),
                )
            })
            .unwrap();
        tasks.push(json!({"task":STAGES[stage],"questions":evaluate_questions(c,&questions,engine,io),"decision_fit":metrics}));
    }
    let transfer = fresh
        .cases
        .iter()
        .map(|q| q.source.clone())
        .collect::<Vec<_>>();
    json!({"checkpoint":digest(c),"updates":c.updates,"tasks":tasks,
        "unseen_transfer":evaluate_questions(c,&transfer,engine,io)})
}
fn costs(cpu: u64, wall: Instant, io: &Store, prefix: &Value) -> Value {
    let cpu = meta::cpu_micros().unwrap() - cpu + prefix["cpu_micros"].as_u64().unwrap();
    let wall = wall.elapsed().as_micros() + u128::from(prefix["wall_micros"].as_u64().unwrap());
    let writes = io.writes + prefix["writes"].as_u64().unwrap();
    let written = io.written_bytes + prefix["written_bytes"].as_u64().unwrap();
    json!({"cpu_micros":cpu,"wall_micros":wall,"read_bytes":io.read_bytes,"written_bytes":written,
        "reads":io.reads,"writes":writes,"charged_shared_prefix":prefix,"within_budget":cpu<=180_000_000 && wall<=240_000_000
            && io.read_bytes+written<=crate::resources::limits().native_model_io_bytes as u64
            && io.reads+writes<=(crate::resources::limits().native_model_io_bytes / crate::resources::limits().native_model_chunk_bytes * 2) as u64})
}
#[test]
#[ignore = "explicit three-stage retained-parameter validation; no production promotion"]
fn retained_parameter_learning_retention_and_transfer() {
    let output = std::path::PathBuf::from(std::env::var("NAOME_SEQUENTIAL_OUTPUT").unwrap());
    assert!(!output.join("summary.json").exists());
    std::fs::create_dir_all(&output).unwrap();
    let old = std::path::PathBuf::from(std::env::var("NAOME_SEQUENTIAL_SOURCE").unwrap());
    let fresh_path = std::path::PathBuf::from(std::env::var("NAOME_SEQUENTIAL_TRANSFER").unwrap());
    let fresh: Inputs = serde_json::from_slice(&std::fs::read(&fresh_path).unwrap()).unwrap();
    let preparation = Instant::now();
    let preparation_cpu = meta::cpu_micros().unwrap();
    let mut excluded = BTreeSet::new();
    for case in &fresh.cases {
        families(
            &CompiledQuestion::compile(&case.source).unwrap(),
            0,
            &mut excluded,
        );
    }
    let groups = sources(&old, &output, &excluded);
    let mut graph = crate::Graph::default();
    for source in groups.iter().flatten() {
        let q = CompiledQuestion::compile(&source.question).unwrap();
        admit_discovery(&mut graph, &q, &source.solution).unwrap();
    }
    drop(graph);
    let preparation = json!({"cpu_micros":meta::cpu_micros().unwrap()-preparation_cpu,
        "wall_micros":preparation.elapsed().as_micros(),"source":"Previously paid archived checked development data; independent current rechecking measured here."});
    write(&output.join("preparation.json"), &preparation);
    let mut runs = Vec::new();
    for seed in SEEDS {
        let seed_path = output.join(seed.to_string());
        let model_preparation = Instant::now();
        let model_preparation_cpu = meta::cpu_micros().unwrap();
        let (initial, common_io) = inputs::checkpoint(seed, &seed_path.join("initial"));
        let prefix = json!({"cpu_micros":preparation["cpu_micros"].as_u64().unwrap()+meta::cpu_micros().unwrap()-model_preparation_cpu,
            "wall_micros":preparation["wall_micros"].as_u64().unwrap()+model_preparation.elapsed().as_micros() as u64,
            "written_bytes":initial.model.blobs().map(|b|b.bytes as u64).sum::<u64>(),
            "writes":initial.model.blobs().map(|b|b.chunks() as u64).sum::<u64>()});
        for arm in ARMS {
            let path = seed_path.join(arm);
            std::fs::create_dir_all(&path).unwrap();
            let started = Instant::now();
            let cpu = meta::cpu_micros().unwrap();
            let mut state = initial.clone();
            let mut c = initial.model.clone();
            let mut io = Store {
                inner: MemoryStore(common_io.0.clone()),
                ..Default::default()
            };
            let mut engine = Engine::default();
            let mut all = Vec::new();
            let mut stages = Vec::new();
            let mut rng = seed;
            let first = readout(&c, &groups, &fresh, &mut engine, &mut io);
            write(&path.join("checkpoint-0-readout.json"), &first);
            let mut readouts = vec![first];
            let mut complete = true;
            for (stage, group) in groups.iter().enumerate() {
                let mut accepted = Vec::new();
                for source in group {
                    all.push(Evidence {
                        job: source.receipt,
                        proof_id: source.solution.proof_id.clone(),
                        trace: source.solution.tree.clone(),
                    });
                    accepted.push(json!({"receipt":source.receipt,"proof_id":source.solution.proof_id,"retained":state.consider(example(source),true).unwrap()}));
                }
                state.validate().unwrap();
                let current = group.iter().map(|s| s.receipt).collect::<BTreeSet<_>>();
                let evidence = evidence_for(&state, &all);
                let selected = pool(
                    &state,
                    &evidence,
                    (arm == "current_task_only").then_some(&current),
                );
                let before = c.clone();
                let training = if arm == "frozen" {
                    Value::Null
                } else if selected.is_empty() {
                    complete = false;
                    json!({"inconclusive":"no checked neural decision states"})
                } else {
                    let result = engine.train(&c, &selected, &mut rng, &mut io).unwrap();
                    c = result.0;
                    assert_eq!(c.updates, before.updates + 10);
                    assert_ne!(c.model, before.model);
                    assert_ne!(c.optimizer, before.optimizer);
                    json!({"first_loss":result.1,"last_loss":result.2,"states":selected.graphs().len()})
                };
                export_model(
                    &path.join(format!("checkpoint-{}", stage + 1)),
                    &c,
                    &io.inner,
                );
                engine = Engine::default();
                let restored = engine.snapshot(&c, &mut io).unwrap();
                assert_eq!(restored, c);
                let after = readout(&c, &groups, &fresh, &mut engine, &mut io);
                write(
                    &path.join(format!("checkpoint-{}-readout.json", stage + 1)),
                    &after,
                );
                readouts.push(after);
                stages.push(json!({"stage":stage,"task":STAGES[stage],"accepted":accepted,"training":training,
                    "source_checkpoint":digest(&before),"candidate_checkpoint":digest(&c),"candidate_updates":c.updates,
                    "retained_source_state_sha256":digest(&state),"cost":costs(cpu,started,&io,&prefix)}));
                let keep = initial
                    .model
                    .blobs()
                    .chain(c.blobs())
                    .map(|b| b.sha256.clone())
                    .collect::<BTreeSet<_>>();
                io.inner.0.retain(|(sha, _), _| keep.contains(sha));
                if costs(cpu, started, &io, &prefix)["within_budget"] != true {
                    complete = false;
                    break;
                }
            }
            let row = json!({"seed":seed,"arm":arm,"completed":complete && stages.len()==3,
                "initial_checkpoint":digest(&initial.model),"candidate_checkpoint":digest(&c),"candidate_updates":c.updates,
                "production_selected_checkpoint":digest(&state.model),"production_promotions":0,
                "readouts":readouts,"stages":stages,"cost":costs(cpu,started,&io,&prefix),"shared_preparation":preparation});
            write(&path.join("result.json"), &row);
            runs.push(row);
            write(&output.join("results.json"), &runs);
        }
    }
    write(
        &output.join("summary.json"),
        &json!({"complete":true,"runs":runs,
        "claim":"Retained raw parameter candidates and measured task/transfer readouts only. No production promotion or positive learning effect is assumed. Symbolic planning and graph knowledge are held out of the model-only probes."}),
    );
}
