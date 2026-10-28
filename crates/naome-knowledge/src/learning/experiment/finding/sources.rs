//! One immutable native source collection shared by all treatment arms.
use super::*;
use serde::Deserialize;
pub(super) mod history;
mod storage;

const MAX_EPOCHS: usize = 3;
const QUERIES: usize = 48;
const CPU: u64 = 180_000_000;
const WALL: u128 = 240_000_000;
const IO: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Default)]
struct Archive {
    bytes: u64,
    operations: u64,
}
impl Archive {
    fn write(&mut self, path: &Path, value: &impl Serialize) {
        let bytes = serde_json::to_vec_pretty(value).unwrap();
        std::fs::write(path, &bytes).unwrap();
        self.bytes += bytes.len() as u64;
        self.operations += 1;
    }
    fn written(&mut self, path: &Path) {
        self.bytes += std::fs::metadata(path).unwrap().len();
        self.operations += 1;
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Episode {
    pub(super) lineage: String,
    pub(super) authored_lineage: String,
    pub(super) observation: experience::Observation,
    pub(super) solution: Option<Solution>,
}
impl Episode {
    pub(super) fn validate(
        &self,
        common: &State,
        ledger: &lineage::Ledger,
        holdout: &lineage::Holdout,
    ) -> Result<(), String> {
        self.observation.validate()?;
        let q = CompiledQuestion::compile(&self.observation.question).map_err(|e| e.to_string())?;
        holdout.question(&q, Some(&self.authored_lineage))?;
        ledger.allowed(&self.lineage, holdout)?;
        let summary = &self.observation.summary;
        if !ledger.matches_original(&self.lineage, &q, &self.authored_lineage, summary) {
            return Err("frozen episode substituted another source lineage".into());
        }
        summary.terminal.validate(self.solution.as_ref())?;
        let context = SolveContext {
            definitions: &common.definitions,
            theorems: &common.knowledge,
            ..Default::default()
        };
        if !matches!(summary.origin, Origin::Local)
            || summary.search_limit != SEARCH as u32
            || digest(&self.observation.knowledge) != digest(&common.knowledge)
            || summary.checkpoint != digest(&common.model)
            || summary.policy != common.model.specification
            || summary.native_context
                != digest(&(&digest(common), context.required, context.prerequisites))
            || summary.trace.checked_trajectory != self.solution.as_ref().map(|s| digest(&s.tree))
        {
            return Err("frozen episode differs from its native source context".into());
        }
        for trace in &self.observation.executions {
            trace.validate_context(&q, &common.knowledge)?;
        }
        if let Some(solution) = &self.solution {
            if summary
                .cost
                .as_ref()
                .is_none_or(|cost| digest(cost) != digest(solution.cost.as_ref()))
            {
                return Err("frozen candidate cost differs from its actual execution".into());
            }
            let checked = solution.checked()?.into_checked_proof();
            let expected = if solution.refuted {
                q.refuted_target()
            } else {
                q.proved_target()
            };
            if checked.conclusion() != expected {
                return Err("frozen source proof differs from its question".into());
            }
        }
        Ok(())
    }
}

pub(super) struct Frozen {
    pub(super) initial: State,
    pub(super) store: MemoryStore,
    pub(super) epochs: Vec<State>,
    pub(super) episodes: Vec<Episode>,
    pub(super) ledgers: Vec<lineage::Ledger>,
    pub(super) cost: Value,
}

/// No treatment model or optimizer participates in this collection. Every
/// question is screened before the common model is even initialized.
pub(super) fn freeze(seed: u64, count: usize, holdout: &lineage::Holdout, output: &Path) -> Frozen {
    assert!((1..=MAX_EPOCHS).contains(&count));
    assert!(!output.exists());
    std::fs::create_dir_all(output).unwrap();
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let checking = proof::checking_work();
    let mut archive = Archive::default();
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    let mut excluded = Vec::new();
    for case in shuffled_learning(seed) {
        let q = CompiledQuestion::compile(&case.source).unwrap();
        if !State::eligible(q.source()) || holdout.question(&q, Some(&case.dependency)).is_err() {
            excluded.push(json!({"case":case.id,"dependency":case.dependency,"resolution":crate::hex(q.resolution_id())}));
            continue;
        }
        if seen.insert(crate::hex(q.resolution_id())) {
            selected.push(case);
        }
        if selected.len() == count * QUERIES {
            break;
        }
    }
    assert_eq!(
        selected.len(),
        count * QUERIES,
        "source-only split lacks the fixed question count"
    );
    archive.write(
        &output.join("schedule.json"),
        &json!({"seed":seed,"questions":selected,"excluded":excluded,"source_selection_uses_model_outputs":false}),
    );
    let mut observer = crate::resources::adaptive::Observer::default();
    let resources = observer.refresh(output).unwrap().clone();
    assert!(
        resources.budget.paused.is_none(),
        "source collection paused by its resource owner"
    );
    archive.write(&output.join("initial-resources.json"), &resources);
    let mut io = Store::default();
    let mut engine = Engine::default();
    let mut initial = State::fresh();
    initial.model.seed = seed;
    initial.model = engine.snapshot(&initial.model, &mut io).unwrap();
    initial.feedback = crate::training::ability::Feedback::fresh(digest(&initial.model));
    initial.validate().unwrap();
    assert!(initial.examples().next().is_none());
    // Self-contained native sources make the initial acquisition factorization
    // explicit. Each source's actual tree still carries its helper closure.
    assert!(initial.knowledge.is_empty() && initial.definitions.is_empty());
    archive.write(&output.join("initial-state.json"), &initial);
    export_model(&output.join("initial-model"), &initial.model, &io.inner);
    for file in std::fs::read_dir(output.join("initial-model")).unwrap() {
        archive.written(&file.unwrap().path());
    }
    let mut state = initial.clone();
    let mut graph = crate::Graph::default();
    let mut ledger = lineage::Ledger::new(holdout);
    let mut ledgers = Vec::new();
    let mut episodes = Vec::new();
    let mut epochs = Vec::new();
    for (index, case) in selected.into_iter().enumerate() {
        if observer.due(Instant::now()) {
            assert!(
                observer.refresh(output).unwrap().budget.paused.is_none(),
                "source collection interrupted by its resource owner"
            );
        }
        assert!(
            meta::cpu_micros().unwrap() - cpu < CPU
                && started.elapsed().as_micros() < WALL
                && io.bytes <= IO,
            "source collection exhausted its unchanged total allowance"
        );
        let q = CompiledQuestion::compile(&case.source).unwrap();
        holdout.question(&q, Some(&case.dependency)).unwrap();
        let job = 1 + index as u64;
        let wall = Instant::now();
        let generation = solve(&initial, &mut engine, &mut io, &q, job);
        let completion = completed_search(
            &initial,
            &q,
            job,
            &generation,
            SolveContext {
                definitions: &initial.definitions,
                theorems: &initial.knowledge,
                ..Default::default()
            },
            SEARCH,
            wall.elapsed().as_millis() as u64,
        );
        let observation = experience::Observation {
            question: q.source().to_owned(),
            summary: completion.experience.unwrap(),
            frontier: generation.frontier,
            executions: generation.executions,
            knowledge: initial.knowledge.clone(),
        };
        let lineage = ledger
            .original(&q, &case.dependency, &observation.summary)
            .unwrap();
        let episode = Episode {
            lineage,
            authored_lineage: case.dependency.clone(),
            observation,
            solution: generation.solution,
        };
        episode.validate(&initial, &ledger, holdout).unwrap();
        // Persist every execution, including incomplete search and unavailable
        // targets, before deciding whether its checked source enters replay.
        archive.write(&output.join(format!("episode-{job}.json")), &episode);
        archive.write(
            &output.join(format!("lineage-{}.json", epochs.len())),
            &ledger,
        );
        if let Some(solution) = &episode.solution {
            accept(&mut state, &mut graph, &q, solution, job, output);
            archive.written(&output.join(format!("proof-{job}.nao")));
        }
        episodes.push(episode);
        if (index + 1) % QUERIES == 0 {
            state.compact().unwrap();
            state
                .compact_with_meta_headroom(super::super::adaptive::outer_metadata_headroom(&state))
                .unwrap();
            state.validate().unwrap();
            assert_eq!(
                state.model, initial.model,
                "source collection modified model weights or Adam"
            );
            archive.write(&output.join(format!("epoch-{}.json", epochs.len())), &state);
            epochs.push(state.clone());
            // Separate acquisition epochs are separate bounded input pages.
            // A later native job still has the original single-page allowance.
            ledgers.push(ledger);
            ledger = lineage::Ledger::new(holdout);
        }
        archive.write(
            &output.join("progress.json"),
            &json!({"completed_episodes":episodes.len(),"cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":started.elapsed().as_micros(),"model_io_bytes":io.bytes,"model_io_operations":io.operations,"archive_written_bytes":archive.bytes,"archive_writes":archive.operations,"complete":false}),
        );
        let sample = crate::resources::feedback::Meter::start().finish(0, true);
        let peak = sample
            .peak_rss_bytes
            .expect("native source RSS observation");
        assert!(
            peak <= model::REQUIREMENTS.work_bytes as u64,
            "source collection exceeds the unchanged model work reservation"
        );
        assert!(
            meta::cpu_micros().unwrap() - cpu <= CPU
                && started.elapsed().as_micros() <= WALL
                && io.bytes <= IO,
            "late source collection cannot qualify"
        );
    }
    let final_checking = proof::checking_work();
    let cost = json!({"cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":started.elapsed().as_micros(),"model_io_bytes":io.bytes,"model_io_operations":io.operations,"archive_written_bytes":archive.bytes,"archive_writes":archive.operations,"checker_calls":final_checking.calls-checking.calls,"checker_steps":final_checking.steps-checking.steps,"optimizer_updates":0,"episodes":episodes.len(),"epochs":epochs.len(),"source_sha256":digest(&episodes),"initial_state_sha256":digest(&initial),"complete":true});
    write(&output.join("cost.json"), &cost);
    Frozen {
        initial,
        store: io.inner,
        epochs,
        episodes,
        ledgers,
        cost,
    }
}

#[test]
#[ignore = "explicit fixed-source collection; run alone before treatment updates"]
fn freeze_shared_experience_sources() {
    let bank = std::fs::read(std::env::var("NAOME_FINDER_CONFIRMATION_INPUTS").unwrap()).unwrap();
    let expected = std::env::var("NAOME_EXPERIENCE_HOLDOUT_SHA256").unwrap();
    let holdout = lineage::Holdout::read(&bank, &expected).unwrap();
    let output =
        std::path::PathBuf::from(std::env::var("NAOME_EXPERIENCE_SOURCES_OUTPUT").unwrap());
    let seed = std::env::var("NAOME_EXPERIENCE_SEED")
        .unwrap()
        .parse()
        .unwrap();
    let count = std::env::var("NAOME_EXPERIENCE_EPOCHS")
        .unwrap()
        .parse()
        .unwrap();
    let frozen = freeze(seed, count, &holdout, &output);
    assert_eq!(frozen.epochs.len(), count);
    assert_eq!(frozen.episodes.len(), count * QUERIES);
    assert_eq!(frozen.cost["initial_state_sha256"], digest(&frozen.initial));
    assert_eq!(frozen.ledgers.len(), count);
    assert!(!frozen.store.0.is_empty());
    assert_eq!(frozen.cost["optimizer_updates"], 0);
}

#[test]
fn another_allowed_receipt_cannot_replace_an_episodes_original_source() {
    let held = CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let bank = serde_json::to_vec(&json!({"cases":[{"source":held.source(),"resolution":crate::hex(held.resolution_id()),"family":curriculum::owned::family(held.proved_target()),"lineage":"held"}]})).unwrap();
    let holdout = lineage::Holdout::read(&bank, &crate::hex(&Sha256::digest(&bank))).unwrap();
    let common = State::fresh();
    let q = CompiledQuestion::compile(
        "goal=all(a,all(b,imp(not(eq(a,b)),imp(all(x,all(y,mem(x,y))),mem(b,a)))))",
    )
    .unwrap();
    assert!(State::eligible(q.source()));
    let mut ledger = lineage::Ledger::new(&holdout);
    let mut fixture = |job| {
        // Deliberately unknown unit-test evidence, never a collected outcome.
        let mut summary = crate::frontier::evidence::observed_completion(
            &q,
            job,
            experience::TerminalEvidence::Unknown,
            0,
            None,
        )
        .experience
        .unwrap();
        let context = SolveContext::default();
        summary.native_context =
            digest(&(&digest(&common), context.required, context.prerequisites));
        summary.receipt.clear();
        summary.receipt = digest(&summary);
        let lineage = ledger.original(&q, "training", &summary).unwrap();
        Episode {
            lineage,
            authored_lineage: "training".into(),
            observation: experience::Observation {
                question: q.source().into(),
                summary,
                frontier: None,
                executions: Vec::new(),
                knowledge: Vec::new(),
            },
            solution: None,
        }
    };
    let original = fixture(1);
    let another = fixture(2);
    original.validate(&common, &ledger, &holdout).unwrap();
    another.validate(&common, &ledger, &holdout).unwrap();
    let mut substituted = original.clone();
    substituted.lineage = another.lineage;
    assert!(
        substituted
            .validate(&common, &ledger, &holdout)
            .unwrap_err()
            .contains("substituted")
    );
    let restored: Episode =
        serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
    restored.validate(&common, &ledger, &holdout).unwrap();
    let mut other_model = common.clone();
    other_model.model.seed += 1;
    assert!(restored.validate(&other_model, &ledger, &holdout).is_err());
}
