//! Source-only confirmation preparation. No solver, optimizer or model calls.
use super::*;

pub(super) fn import_model(path: &Path) -> Result<(Checkpoint, MemoryStore), String> {
    use std::io::Read;
    let read = |path: &Path, cap: usize| -> Result<Vec<u8>, String> {
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.take(cap as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > cap {
            return Err("frozen model file exceeds its declared bound".into());
        }
        Ok(bytes)
    };
    let model: Checkpoint =
        serde_json::from_slice(&read(&path.join("checkpoint.json"), history::PAGE_BYTES)?)
            .map_err(|e| e.to_string())?;
    model.validate()?;
    let mut io = MemoryStore::default();
    for (name, blob) in [("model", &model.model), ("optimizer", &model.optimizer)] {
        if let Some(blob) = blob {
            let bytes = read(&path.join(format!("{name}.bpk")), blob.bytes)?;
            if Blob::of(&bytes) != *blob {
                return Err("frozen model bytes differ from their checkpoint".into());
            }
            for (index, chunk) in bytes
                .chunks(crate::resources::limits().native_model_chunk_bytes)
                .enumerate()
            {
                io.0.insert((blob.sha256.clone(), index), chunk.to_vec());
            }
        }
    }
    Ok((model, io))
}

#[test]
fn frozen_parameters_and_optimizer_restore_every_exact_chunk() {
    let directory = Directory::new();
    let mut engine = Engine::default();
    let mut source = MemoryStore::default();
    let model = engine.snapshot(&Checkpoint::fresh(), &mut source).unwrap();
    assert!(model.model.is_some() && model.optimizer.is_some());
    export_model(&directory.0, &model, &source);
    let (restored, mut store) = import_model(&directory.0).unwrap();
    assert_eq!(restored, model);
    for blob in [model.model.as_ref(), model.optimizer.as_ref()]
        .into_iter()
        .flatten()
    {
        assert!(blob.chunks() > 1);
        assert_eq!(
            artifact::load(&mut store, blob).unwrap(),
            artifact::load(&mut source, blob).unwrap()
        );
    }
    let path = directory.0.join("model.bpk");
    let mut bytes = std::fs::read(&path).unwrap();
    let index = crate::resources::limits().native_model_chunk_bytes;
    bytes[index] ^= 1;
    std::fs::write(path, bytes).unwrap();
    assert!(import_model(&directory.0).err().unwrap().contains("differ"));
}

#[test]
#[ignore = "single frozen confirmation evaluation; never supplies learning feedback"]
fn evaluate_frozen_confirmation_models() {
    let bank_path =
        std::path::PathBuf::from(std::env::var("NAOME_FINDER_CONFIRMATION_INPUTS").unwrap());
    let models =
        std::path::PathBuf::from(std::env::var("NAOME_FINDER_CONFIRMATION_MODELS").unwrap());
    let output =
        std::path::PathBuf::from(std::env::var("NAOME_FINDER_CONFIRMATION_OUTPUT").unwrap());
    assert!(!output.exists());
    std::fs::create_dir_all(&output).unwrap();
    let bank_bytes = std::fs::read(&bank_path).unwrap();
    let bank: Value = serde_json::from_slice(&bank_bytes).unwrap();
    let reserved = bank["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["family"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    let mut observer = crate::resources::adaptive::Observer::default();
    let resource = observer.refresh(&output).unwrap().clone();
    assert!(resource.budget.paused.is_none());
    write(
        &output.join("manifest.json"),
        &json!({"bank":bank_path,"bank_sha256":crate::hex(&Sha256::digest(&bank_bytes)),"models":models,"model_source_contract":input_specification(),"case_count":bank["cases"].as_array().unwrap().len(),"seeds":bank["seeds"],"search_expansions":128,"case_cpu_limit_micros":2_500_000,"case_wall_limit_micros":5_000_000,"scope":"First confirmation inference on frozen source-only questions. No examples, gradients, training, promotion, feedback or theorem hints are produced from these outcomes. Actual CPU, IO, checking and late proofs are retained separately.","initial_resources":resource}),
    );
    let arms = ["initial", "previous", "censored_replay", "uniform", "full"];
    let mut results = Vec::new();
    for (seed_index, seed) in bank["seeds"].as_array().unwrap().iter().enumerate() {
        let seed = seed.as_u64().unwrap();
        for offset in 0..arms.len() {
            let arm = arms[(seed_index + offset) % arms.len()];
            let path = output.join(seed.to_string()).join(arm);
            std::fs::create_dir_all(&path).unwrap();
            let source = models.join(seed.to_string());
            let state_path = if arm == "initial" {
                source.join("initial-state.json")
            } else {
                source.join(arm).join("state-final.json")
            };
            let state: State = serde_json::from_slice(&std::fs::read(state_path).unwrap()).unwrap();
            state.validate().unwrap();
            for example in state.examples() {
                let q = CompiledQuestion::compile(&example.question).unwrap();
                assert!(
                    !reserved.contains(&curriculum::owned::family(q.proved_target())),
                    "confirmation lineage entered a training source"
                );
            }
            let started = Instant::now();
            let cpu = meta::cpu_micros().unwrap();
            let model_path = if arm == "initial" {
                source.join("initial-model")
            } else {
                source.join(arm).join("selected-model")
            };
            let (model, data) = import_model(&model_path).unwrap();
            assert_eq!(model, state.model);
            let mut io = Store {
                inner: data,
                ..Default::default()
            };
            let mut engine = Engine::default();
            let mut graph = crate::Graph::default();
            let mut rows = Vec::new();
            for (index, case) in bank["cases"].as_array().unwrap().iter().enumerate() {
                if observer.due(Instant::now()) {
                    assert!(
                        observer.refresh(&output).unwrap().budget.paused.is_none(),
                        "confirmation paused by resource owner"
                    );
                }
                let q = CompiledQuestion::compile(case["source"].as_str().unwrap()).unwrap();
                assert_eq!(curriculum::owned::family(q.proved_target()), case["family"]);
                let wall = Instant::now();
                let before = meta::cpu_micros().unwrap();
                let bytes = io.bytes;
                let generated = engine
                    .with(&model, &mut io, |runtime| {
                        solve_with_report(
                            q.source(),
                            runtime,
                            128,
                            800_000 + index as u64,
                            SolveContext {
                                definitions: &state.definitions,
                                theorems: &[],
                                required: &[],
                                prerequisites: None,
                            },
                        )
                    })
                    .unwrap();
                if let Some(solution) = &generated.solution {
                    drop(solution.checked().unwrap());
                    let (root, batch) = graph
                        .prepare_generated(&solution.source, &solution.helpers, &q)
                        .unwrap();
                    graph
                        .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
                        .unwrap();
                    std::fs::write(path.join(format!("proof-{index}.nao")), &solution.source)
                        .unwrap();
                }
                let cpu_used = meta::cpu_micros().unwrap() - before;
                let wall_used = wall.elapsed().as_micros();
                let in_budget = cpu_used <= 2_500_000 && wall_used <= 5_000_000;
                rows.push(json!({"case":index,"resolution":case["resolution"],"lineage":case["lineage"],"family":case["family"],"solved":generated.solution.is_some()&&in_budget,"late_checked_solution":generated.solution.is_some()&&!in_budget,"refuted":generated.solution.as_ref().map(|s|s.refuted),"diagnostic":generated.diagnostic,"cost":generated.cost,"cpu_micros":cpu_used,"wall_micros":wall_used,"model_io_bytes":io.bytes-bytes}));
                write(&path.join("cases.json"), &rows);
            }
            assert_eq!(state.model, model);
            let result = json!({"seed":seed,"arm":arm,"model":model,"cases":rows,"cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":started.elapsed().as_micros(),"model_io_bytes":io.bytes,"learning_updates_from_confirmation":0});
            write(&path.join("result.json"), &result);
            results.push(result);
            write(&output.join("results.json"), &results);
            eprintln!("confirmation seed={seed} arm={arm} complete");
        }
    }
}

#[test]
#[ignore = "explicit source-only confirmation freeze; run before inference"]
fn freeze_disjoint_confirmation_questions() {
    let output =
        std::path::PathBuf::from(std::env::var("NAOME_FINDER_CONFIRMATION_OUTPUT").unwrap());
    assert!(!output.exists());
    let bytes =
        include_bytes!("../../../../tests/fixtures/finder-repair-confirmation-candidates.json");
    let inputs: Value = serde_json::from_slice(bytes).unwrap();
    let mut known = curriculum::owned::original_exclusions().clone();
    for content in [
        include_str!("../../../../tests/fixtures/finder-feedback.json"),
        include_str!("../../../../tests/fixtures/recursive-lemma-loop.json"),
    ] {
        let prior: Value = serde_json::from_str(content).unwrap();
        for case in prior["cases"].as_array().unwrap() {
            let q = CompiledQuestion::compile(case["source"].as_str().unwrap()).unwrap();
            known.insert(curriculum::owned::family(q.proved_target()));
        }
    }
    let graph = crate::Graph::default();
    let mut owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let mut cases = Vec::new();
    let mut excluded = Vec::new();
    let mut identities = BTreeSet::new();
    for input in inputs["cases"].as_array().unwrap() {
        let q = CompiledQuestion::compile(input["source"].as_str().unwrap()).unwrap();
        let id = crate::hex(q.resolution_id());
        let family = curriculum::owned::family(q.proved_target());
        let assessment = owner.assess(&graph, &q);
        let reason = if known.contains(&family) || !State::eligible(q.source()) {
            Some("existing_or_reserved_structural_family")
        } else if !assessment.passed() {
            Some("formal_question_prefilter")
        } else if !identities.insert(id.clone()) {
            Some("duplicate_canonical_question")
        } else {
            None
        };
        let row = json!({"source":q.source(),"resolution":id,"family":family,"lineage":input["lineage"],"variant":input["variant"],"exclusion":reason});
        if reason.is_some() {
            excluded.push(row);
        } else {
            cases.push(row);
        }
    }
    let result = json!({"scope":"First source-only freeze. No model calls or truth labels. Structural families are excluded from training, utility, replay and promotion feedback in the confirmation consumer. Authored-lineage siblings remain correlated.","source_sha256":crate::hex(&Sha256::digest(bytes)),"seeds":[173,251,389],"search_expansions":128,"cases":cases,"excluded":excluded});
    write(&output, &result);
    assert!(
        cases.len() >= 8,
        "source-only bank has insufficient independent material; preserve exclusions"
    );
    assert!(
        cases
            .iter()
            .map(|c| c["lineage"].as_str().unwrap())
            .collect::<BTreeSet<_>>()
            .len()
            >= 3
    );
}
