//! Matched current-architecture treatments using the ordinary native job owner.
use super::*;
mod audit;
mod closed_loop;
mod meter;
mod run;
use meter::Meter;

#[derive(Clone, Copy, Debug)]
enum Arm {
    Baseline,
    Experience,
    Latent,
    Combined,
    ComputeControl,
    IndependentPreservation,
    ContextualPreservation,
    ReadoutOnly,
}
const ARMS: [Arm; 5] = [
    Arm::Baseline,
    Arm::Experience,
    Arm::Latent,
    Arm::Combined,
    Arm::ComputeControl,
];
const PRESERVATION_ARMS: [Arm; 2] = [Arm::IndependentPreservation, Arm::ContextualPreservation];
const READOUT_ARMS: [Arm; 2] = [Arm::Combined, Arm::ReadoutOnly];
impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Experience => "experience",
            Self::Latent => "latent",
            Self::Combined => "combined",
            Self::ComputeControl => "compute_control",
            Self::IndependentPreservation => "independent_preservation",
            Self::ContextualPreservation => "contextual_preservation",
            Self::ReadoutOnly => "readout_only",
        }
    }
    fn engine(self) -> Engine {
        let targets = match self {
            Self::Baseline | Self::Latent => model::Targets::Actions,
            _ => model::Targets::Rich,
        };
        let recurrence = match self {
            Self::Baseline | Self::Experience => model::Recurrence::Disabled,
            Self::Latent
            | Self::Combined
            | Self::IndependentPreservation
            | Self::ContextualPreservation
            | Self::ReadoutOnly => model::Recurrence::Carry,
            Self::ComputeControl => model::Recurrence::Reset,
        };
        Engine::default()
            .with_targets(targets)
            .with_recurrence(recurrence)
            .with_contextual_preservation(matches!(self, Self::ContextualPreservation))
            .with_readout_only(matches!(self, Self::ReadoutOnly))
    }
}

/// Replace only the immutable acquisition inputs; retain the real learning and
/// history state selected by the preceding complete native job.
fn bind(input: &State, previous: &State) -> Result<State, String> {
    let mut state = input.clone();
    state.model = previous.model.clone();
    state.meta = previous.meta.clone();
    state.preparation = Preparation::Balanced;
    state.trained = previous.trained;
    state.attempted = previous.attempted;
    state.draws = previous.draws;
    state.promotions = previous.promotions;
    state.rejections = previous.rejections;
    state.feedback = previous.feedback.clone();
    state.peer_cursor = previous.peer_cursor;
    state.history_cursor = previous.history_cursor.clone();
    state.compact()?;
    if digest(&(
        &state.replay,
        &state.anchors,
        &state.knowledge,
        &state.definitions,
    )) != digest(&(
        &input.replay,
        &input.anchors,
        &input.knowledge,
        &input.definitions,
    )) {
        return Err("treatment metadata displaced a frozen source input".into());
    }
    state.validate()?;
    Ok(state)
}

#[test]
fn acquisition_epoch_preserves_real_history_rotation_and_learning_state() {
    let input = State::fresh();
    let mut previous = input.clone();
    previous.draws = 41;
    previous.meta.draw = 19;
    previous.peer_cursor = 7;
    let request = history::Request {
        lane: history::Lane::Sources,
        after: None,
        horizon: 100,
    };
    let receipt = history::Receipt {
        request,
        blob: Blob::of(b"unit-test cursor transport"),
        next: Some("ab".repeat(32)),
        read_bytes: 1,
        read_operations: 1,
        read_cpu_micros: 0,
    };
    previous.history_cursor.advance(&receipt);
    let next = bind(&input, &previous).unwrap();
    assert_eq!(next.model, previous.model);
    assert_eq!(digest(&next.meta), digest(&previous.meta));
    assert_eq!(next.history_cursor, previous.history_cursor);
    assert_ne!(next.history_cursor, input.history_cursor);
    assert_eq!(next.draws, previous.draws);
    assert_eq!(next.peer_cursor, previous.peer_cursor);
    assert_eq!(next.preparation, Preparation::Balanced);
    let mut job = next.job();
    job.request_history(101);
    assert_eq!(job.history_request.unwrap().lane, history::Lane::Records);
}

fn execute(
    arm: Arm,
    seed: u64,
    input: &Path,
    output: &Path,
    holdout: &lineage::Holdout,
    epochs: usize,
) -> Result<Value, String> {
    assert!(!output.exists());
    std::fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let mut meter = Meter::start()?;
    let (frozen, rechecks) = match sources::Frozen::read(input, holdout) {
        Ok(frozen) => frozen,
        Err(error) => {
            meter.write(
                &output.join("restore-failure.json"),
                &json!({"error":error,"cost":meter.restore_failure()}),
            )?;
            return Err(error);
        }
    };
    meter.common(&frozen.cost, &rechecks)?;
    if frozen.epochs.len() != epochs {
        return Err("treatment epoch count differs from its complete source input".into());
    }
    if frozen.initial.model.seed != seed {
        return Err("treatment seed differs from its frozen initial parameters".into());
    }
    // Native promotion uses these same development and transfer questions.
    // Preflight the complete set before the first model call in any arm.
    for case in curriculum::development()
        .into_iter()
        .chain(&curriculum::adaptive::BANK.transfer)
    {
        let q = CompiledQuestion::compile(&case.source).map_err(|e| e.to_string())?;
        holdout.question(&q, Some(&case.dependency))?;
    }
    let mut io = sources::history::Io::new(&frozen, input);
    let mut state = frozen.initial.clone();
    state.preparation = Preparation::Balanced;
    let mut engine = arm.engine();
    let mut observer = crate::resources::adaptive::Observer::default();
    meter.write(
        &output.join("input.json"),
        &json!({"arm":arm.name(),"seed":state.model.seed,"initial_state_sha256":digest(&frozen.initial),"initial_model":state.model,"initial_draws":state.draws,"input_sources_sha256":frozen.cost["source_sha256"],"source_cost":frozen.cost,"restore_cost":rechecks,"parameters":model::PARAMETERS,"specification":input_specification(),"preparation":state.preparation,"plan":meta::Plan::balanced(),"common_cost_charged_once_to_each_arm":true}),
    )?;
    let mut rounds = Vec::new();
    let outcome = (|| -> Result<Value, String> {
        run::available(&mut meter, &io, &mut observer, output)?;
        let initial = run::evaluate(
            &state,
            &mut engine,
            &mut io,
            &mut meter,
            &mut observer,
            output,
            "initial",
            holdout,
        )?;
        meter.write(&output.join("initial-evaluation.json"), &initial)?;
        for epoch in 0..epochs {
            io.epoch(epoch)?;
            state = bind(&frozen.epochs[epoch], &state)?;
            run::available(&mut meter, &io, &mut observer, output)?;
            let path = output.join(format!("epoch-{epoch}"));
            std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            let trial = run::train(
                &mut state,
                &mut engine,
                &mut io,
                &mut meter,
                &mut observer,
                &frozen.episodes[..(epoch + 1) * 48],
                1_000_000 + epoch as u64,
                &path,
            )?;
            let evaluation = run::evaluate(
                &state,
                &mut engine,
                &mut io,
                &mut meter,
                &mut observer,
                &path,
                "selected",
                holdout,
            )?;
            let row = json!({"epoch":epoch,"source_state_sha256":digest(&frozen.epochs[epoch]),"trial":trial,"selected_model":state.model,"state_sha256":digest(&state),"evaluation":evaluation,"history_cursor":state.history_cursor,"cost":meter.report(&io)});
            meter.write(&path.join("result.json"), &row)?;
            meter.write(&path.join("selected-state.json"), &state)?;
            rounds.push(row);
            meter.write(&output.join("rounds.json"), &rounds)?;
            run::available(&mut meter, &io, &mut observer, output)?;
        }
        meter.export(
            &output.join("selected-model"),
            &state.model,
            &io.store.inner,
        )?;
        meter.write(&output.join("selected-state.json"), &state)?;
        run::available(&mut meter, &io, &mut observer, output)?;
        Ok(initial)
    })();
    let result = json!({"arm":arm.name(),"seed":state.model.seed,"complete":outcome.is_ok(),"error":outcome.as_ref().err(),"initial_evaluation":outcome.as_ref().ok(),"rounds":rounds,"selected_model":state.model,"selected_state_sha256":digest(&state),"retained_updates":state.promotions,"rejected_trials":state.rejections,"history_pages":io.pages,"cost":meter.report(&io),"quality_qualified":false});
    meter.write(&output.join("result.json"), &result)?;
    // The result serialization itself is charged before declaring completion.
    let final_check = meter.check(&io);
    write(
        &output.join("cost-seal.json"),
        &json!({"complete":outcome.is_ok()&&final_check.is_ok(),"cost":meter.report(&io),"seal_write_is_reporting_overhead":true}),
    );
    outcome?;
    final_check?;
    Ok(result)
}

#[test]
#[ignore = "finite matched experience/recurrence comparison; requires frozen native sources"]
fn matched_experience_and_recurrence() {
    matched(&ARMS);
}

#[test]
#[ignore = "finite matched preservation-context comparison; requires fresh frozen native sources"]
fn matched_contextual_preservation() {
    matched(&PRESERVATION_ARMS);
}

#[test]
#[ignore = "finite matched full/readout-only learning; requires fresh frozen native sources"]
fn matched_readout_learning() {
    matched(&READOUT_ARMS);
}

fn matched(arms: &[Arm]) {
    let bank = std::fs::read(std::env::var("NAOME_FINDER_CONFIRMATION_INPUTS").unwrap()).unwrap();
    let holdout = lineage::Holdout::read(
        &bank,
        &std::env::var("NAOME_EXPERIENCE_HOLDOUT_SHA256").unwrap(),
    )
    .unwrap();
    let input = std::path::PathBuf::from(std::env::var("NAOME_EXPERIENCE_SOURCES_INPUT").unwrap());
    let output =
        std::path::PathBuf::from(std::env::var("NAOME_EXPERIENCE_COMPARISON_OUTPUT").unwrap());
    let epochs: usize = std::env::var("NAOME_EXPERIENCE_EPOCHS")
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=3).contains(&epochs));
    let seed: u64 = std::env::var("NAOME_EXPERIENCE_SEED")
        .unwrap()
        .parse()
        .unwrap();
    let selected = std::env::var("NAOME_EXPERIENCE_ARM").ok();
    assert!(
        selected
            .as_ref()
            .is_none_or(|name| arms.iter().any(|arm| arm.name() == name))
    );
    assert!(!output.exists());
    std::fs::create_dir_all(&output).unwrap();
    let rotation = [41, 73, 101, 173, 251, 389]
        .iter()
        .position(|s| *s == seed)
        .unwrap();
    write(
        &output.join("manifest.json"),
        &json!({"seed":seed,"epochs":epochs,"input":input,"source_commit":std::env::var("NAOME_EXPERIENCE_COMMIT").unwrap(),"specification":input_specification(),"parameters":model::PARAMETERS,"arms":arms.iter().map(|a|a.name()).collect::<Vec<_>>(),"selected_arm":selected,"rotation":rotation,"total_cpu_micros":180_000_000,"total_wall_micros":240_000_000,"total_io_bytes":2u64*1024*1024*1024,"job_cpu_micros":TRAIN_CPU,"job_wall_micros":TRAIN_WALL,"initial_source_inference_uses_treatments":false,"holdout_inference":false,"scope":"Known development mechanism and outcome comparison; does not itself establish independent quality qualification."}),
    );
    for offset in 0..arms.len() {
        let arm = arms[(rotation + offset) % arms.len()];
        if selected.as_ref().is_some_and(|name| name != arm.name()) {
            continue;
        }
        let result = execute(
            arm,
            seed,
            &input,
            &output.join(arm.name()),
            &holdout,
            epochs,
        );
        if let Err(error) = &result {
            write(
                &output.join("interrupted.json"),
                &json!({"arm":arm.name(),"error":error,"complete":false,"partial_job_resumed":false}),
            );
        }
        let result = result.unwrap();
        assert_eq!(result["seed"], seed);
        eprintln!(
            "completed experience arm {} seed {seed}: retained={}, rejected={}",
            arm.name(),
            result["retained_updates"],
            result["rejected_trials"]
        );
    }
}
