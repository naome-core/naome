//! Read-only native search observations; inference choices never become labels.
use super::*;
use naome_foundation::Formula;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    gentle_results: String,
    files_sha256: BTreeMap<String, String>,
}
fn inputs() -> (Inputs, super::warm::Inputs, serde_json::Value) {
    let path = std::env::var("NAOME_TRACE_INPUT").expect("frozen trace inputs");
    let input: Inputs = read(&path);
    for (path, hash) in &input.files_sha256 {
        assert_eq!(
            crate::hex(&Sha256::digest(std::fs::read(path).unwrap())),
            *hash
        );
    }
    let warm_path = std::env::var("NAOME_TRACE_WARM_INPUT").unwrap();
    assert!(input.files_sha256.contains_key(&warm_path));
    let warm = super::warm::inputs("NAOME_TRACE_WARM_INPUT");
    for case in &warm.cases {
        for file in ["checkpoint.json", "model.bpk", "optimizer.bpk"] {
            assert!(input.files_sha256.contains_key(&format!(
                "{}/{}/gentle/candidate/{file}",
                input.gentle_results, case.name
            )));
        }
    }
    let completed: serde_json::Value = read(&format!("{}/completed.json", input.gentle_results));
    assert_eq!(completed["cases"].as_array().unwrap().len(), 24);
    assert_eq!(
        curriculum::development()[18].id,
        "049b426f093f080266277abe7ed5e1d27e5ab8393e9c24ff2d032ec6348ef00c"
    );
    (input, warm, completed)
}
struct Observer<'a> {
    runtime: &'a mut model::Runtime,
    calls: Vec<serde_json::Value>,
}
impl model::Ranker for Observer<'_> {
    fn scores(&mut self, decision: &model::Decision) -> Result<Vec<f32>, String> {
        let scores = model::Ranker::scores(self.runtime, decision)?;
        assert_eq!(scores.len(), decision.candidates.len());
        assert!(scores.iter().all(|x| x.is_finite()));
        let mut graph = serde_json::to_value(graph::Graph::encode(decision)?).unwrap();
        // Inference supplies a placeholder expert index. It is not evidence of
        // a witnessed successful action and must never be exported as a label.
        graph.as_object_mut().unwrap().remove("expert");
        graph.as_object_mut().unwrap().remove("successes");
        let encode = |f: &Formula| f.encode_canonical().map(|b| crate::hex(&b));
        let context = decision
            .context
            .iter()
            .map(|b| encode(&b.formula))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let offered = decision.candidates.iter().map(|c| {
            let consequences=c.consequences.iter().map(encode).collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
            Ok::<_,String>(serde_json::json!({"rule":format!("{:?}",c.rule),"premises":c.premises,"consequences_canonical_hex":consequences}))
        }).collect::<Result<Vec<_>,_>>()?;
        self.calls.push(serde_json::json!({"graph_features":graph,
            "goal_canonical_hex":encode(&decision.goal).map_err(|e|e.to_string())?,
            "context_canonical_hex":context,"offered":offered,
            "scores_bits":scores.iter().map(|x|x.to_bits()).collect::<Vec<_>>(),
            "unlabelled_inference_observation":true}));
        Ok(scores)
    }
}

#[test]
#[ignore = "Read-only36 search traces; no optimizer, final queries or installation"]
fn protected_native_search_trace() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "Release only"
    );
    let output = std::env::var("NAOME_TRACE_OUTPUT").expect("fresh trace output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve previous observations");
    let (input, warm, completed) = inputs();
    let question = curriculum::development()[18];
    let meter = crate::resources::feedback::Meter::start();
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let mut rows = Vec::new();
    for branch in ["parent", "original", "gentle"] {
        for case in &warm.cases {
            let clock = (Instant::now(), meta::cpu_micros().unwrap());
            let job: Job = read(&case.original_job);
            let base = &job.base;
            let base_binding = digest(base);
            let mut store = Store::default();
            let path = match branch {
                "parent" => case.parent_checkpoint.clone(),
                "original" => case.candidate_checkpoint.clone(),
                _ => format!("{}/{}/gentle/candidate", input.gentle_results, case.name),
            };
            let model = checkpoint(&path, &mut store);
            let reference = completed["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| {
                    r["case"] == case.name
                        && r["branch"]
                            == if branch == "gentle" {
                                "gentle"
                            } else {
                                "original"
                            }
                })
                .unwrap();
            if branch == "parent" {
                assert_eq!(model, base.model);
            } else {
                assert_eq!(
                    serde_json::to_value(&model).unwrap(),
                    reference["candidate"]
                );
            }
            let key = if branch == "parent" {
                "before"
            } else {
                "after"
            };
            let expected = reference["qualification"]["native_evaluations"][18][key]
                .as_bool()
                .unwrap();
            let mut engine = Engine::default();
            eprintln!("native_trace_started {} {branch}", case.name);
            let (canonical, canonical_diagnostic, canonical_cost) = engine
                .with(&model, &mut store, |runtime| {
                    solve_with_definitions(
                        &question.source,
                        runtime,
                        32,
                        case.job,
                        &base.definitions,
                        &base.knowledge,
                    )
                })
                .unwrap();
            assert_eq!(canonical.is_some(), expected);
            limits(clock.0, clock.1);
            let ((traced, diagnostic, cost), calls) = engine
                .with(&model, &mut store, |runtime| {
                    let mut observer = Observer {
                        runtime,
                        calls: Vec::new(),
                    };
                    let result = search_question_with_knowledge(
                        &question.source,
                        &mut observer,
                        32,
                        &base.knowledge,
                        &base.definitions,
                    )?;
                    Ok((result, observer.calls))
                })
                .unwrap();
            assert_eq!(traced.is_some(), expected);
            assert_eq!(canonical_cost.search_expansions, cost.search_expansions);
            assert_eq!(canonical_cost.unique_states, cost.unique_states);
            assert_eq!(canonical_cost.core_work, cost.core_work);
            if let (Some(canonical), Some(traced)) = (&canonical, &traced) {
                let _ = canonical.checked().unwrap();
                let _ = traced.checked().unwrap();
                let canonical_tree = match &canonical.tree {
                    search::Tree::Definitions { proof, .. } => proof.as_ref(),
                    tree => tree,
                };
                assert_eq!(
                    serde_json::to_value(canonical_tree).unwrap(),
                    serde_json::to_value(&traced.tree).unwrap()
                );
                assert_eq!(canonical.refuted, traced.refuted);
            }
            assert_eq!(engine.snapshot(&model, &mut store.inner).unwrap(), model);
            assert_eq!(digest(base), base_binding);
            limits(clock.0, clock.1);
            let directory = output.join(&case.name).join(branch);
            std::fs::create_dir_all(&directory).unwrap();
            let row = serde_json::json!({"case":case.name,"job":case.job,"branch":branch,
                "model":model,"base_binding":base_binding,"question":question,
                "expected_solved":expected,"canonical_solution":canonical,
                "canonical_diagnostic":canonical_diagnostic,"canonical_cost":canonical_cost,
                "traced_search_solution":traced,"traced_search_diagnostic":diagnostic,
                "traced_search_cost":cost,"calls":calls,
                "canonical_and_trace_outcome_exact":true,
                "solved_native_search_tree_exact":canonical.as_ref().map(|_|true),
                "scope":"Native search before optional post-search definition representation",
                "optimizer_updates":0,"new_final_queries":0,"training_observations":false,
                "installed_resumed_or_promoted":false,
                "cpu_micros":meta::cpu_micros().unwrap()-clock.1,
                "wall_micros":clock.0.elapsed().as_micros(),
                "artifact_read_bytes":store.read_bytes,"artifact_written_bytes":store.written_bytes});
            write(&directory.join("result.json"), &row);
            let written = std::fs::metadata(directory.join("result.json"))
                .unwrap()
                .len();
            assert!(
                store.read_bytes + store.written_bytes + written
                    <= model::REQUIREMENTS.io_bytes as u64
            );
            rows.push(row);
            write(&output.join("partial.json"), &rows);
            eprintln!("native_trace_completed {} {branch}", case.name);
        }
    }
    let resource = meter.finish(0, true);
    assert!(resource.peak_rss_bytes.unwrap() <= model::REQUIREMENTS.work_bytes as u64);
    write(
        &output.join("completed.json"),
        &serde_json::json!({"cases":rows,
        "branches":36,"native_queries":72,"optimizer_updates":0,"new_final_queries":0,
        "cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":started.elapsed().as_micros(),
        "peak_rss_bytes":resource.peak_rss_bytes,"diagnostic_only":true,
        "inference_observations_are_not_training_labels":true}),
    );
}
