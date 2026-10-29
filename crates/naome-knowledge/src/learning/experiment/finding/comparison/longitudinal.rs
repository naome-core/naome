//! Source-pinned longitudinal measurement, separate from productive selection.
//! Assessment is a terminal read-only consumer of sealed whole checkpoints.
use super::*;
mod analysis;
mod assessment;
mod bank;
mod barrier;
mod calibration;
mod checkpoint;
mod design;
mod tests;
mod trajectory;

const PROTOCOL: &str = include_str!("longitudinal/protocol.json");
const PHASES: usize = 5;
const SEEDS: [u64; 3] = [2_903_101, 2_903_109, 2_903_123];
const TRACKS: [&str; 3] = [
    "lemma_composition",
    "quantified_transport",
    "equality_congruence",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arm {
    Adaptive,
    FrozenWeights,
    FixedChoices,
}
impl Arm {
    fn read(name: &str) -> Result<Self, String> {
        match name {
            "adaptive" => Ok(Self::Adaptive),
            "frozen_weights" => Ok(Self::FrozenWeights),
            "fixed_choices" => Ok(Self::FixedChoices),
            _ => Err("unknown longitudinal control".into()),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Adaptive => "adaptive",
            Self::FrozenWeights => "frozen_weights",
            Self::FixedChoices => "fixed_choices",
        }
    }
    fn finder(self, finder: &mut Frontier) {
        if self != Self::Adaptive {
            finder.freeze_parameters();
        }
        finder.treatment(if self == Self::FixedChoices {
            Treatment::Uniform
        } else {
            Treatment::Full
        });
    }
}

#[derive(Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    source: String,
    resolution: String,
    family: String,
    construction: String,
    track: usize,
    recipe: usize,
    variant: usize,
}

#[derive(Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Bank {
    acquisition: Vec<Case>,
    calibration: Vec<Case>,
    assessment: Vec<Case>,
    pilot: Vec<Case>,
    construction_notes: Vec<String>,
}

fn admitted_design() -> Result<design::Design, String> {
    let mut cost = persistence::Cost::default();
    let read = |name: &str, cost: &mut persistence::Cost| -> Result<Vec<u8>, String> {
        let path = std::path::PathBuf::from(std::env::var(name).map_err(|e| e.to_string())?);
        persistence::read(
            &path,
            crate::resources::limits().native_model_blob_bytes,
            cost,
        )
    };
    let bank = read("NAOME_FRONTIER_BANK", &mut cost)?;
    let calibration = read("NAOME_FRONTIER_CALIBRATION", &mut cost)?;
    for (name, bytes) in [
        ("NAOME_FRONTIER_BANK_SHA256", &bank),
        ("NAOME_FRONTIER_CALIBRATION_SHA256", &calibration),
    ] {
        if crate::hex(&Sha256::digest(bytes)) != std::env::var(name).map_err(|e| e.to_string())? {
            return Err("prospective bank/calibration content hash differs".into());
        }
    }
    design::Design::read(&bank, &calibration)
}

fn decline(output: &Path, reason: &str) {
    assert!(!output.exists());
    std::fs::create_dir_all(output).unwrap();
    write(
        &output.join("declined.json"),
        &json!({"ready":false,"reason":reason,
        "candidate_initializations":0,"candidate_optimizer_updates":0,"assessment_model_calls":0,
        "overall_goal_qualified":false}),
    );
}

#[test]
#[ignore = "prospectively gated common-source preparation; never bypass calibration"]
fn freeze_longitudinal_common_sources() {
    let output = std::path::PathBuf::from(std::env::var("NAOME_FRONTIER_OUTPUT").unwrap());
    let design = match admitted_design() {
        Ok(d) => d,
        Err(e) => {
            decline(&output, &e);
            return;
        }
    };
    let seed: u64 = std::env::var("NAOME_FRONTIER_SEED")
        .unwrap()
        .parse()
        .unwrap();
    assert!(SEEDS.contains(&seed) || seed == 2_903_001);
    sources::freeze(seed, 1, &design.holdout, &output);
}

#[test]
#[ignore = "five-phase current-owner trajectory; requires admitted calibration and a separate immutable grant"]
fn run_longitudinal_trajectory() {
    let output = std::path::PathBuf::from(std::env::var("NAOME_FRONTIER_OUTPUT").unwrap());
    let design = match admitted_design() {
        Ok(d) => d,
        Err(e) => {
            decline(&output, &e);
            return;
        }
    };
    let seed: u64 = std::env::var("NAOME_FRONTIER_SEED")
        .unwrap()
        .parse()
        .unwrap();
    assert!(SEEDS.contains(&seed) || seed == 2_903_001);
    let arm = Arm::read(&std::env::var("NAOME_FRONTIER_ARM").unwrap()).unwrap();
    let common = std::path::PathBuf::from(std::env::var("NAOME_FRONTIER_COMMON").unwrap());
    trajectory::execute(seed, arm, &design, &common, &output).unwrap();
}

#[test]
#[ignore = "terminal read-only assessment; requires every learning trajectory to be sealed"]
fn assess_longitudinal_trajectories() {
    let output = std::path::PathBuf::from(std::env::var("NAOME_FRONTIER_OUTPUT").unwrap());
    let design = match admitted_design() {
        Ok(d) => d,
        Err(e) => {
            decline(&output, &e);
            return;
        }
    };
    let root = std::path::PathBuf::from(std::env::var("NAOME_FRONTIER_TRAJECTORIES").unwrap());
    let pilot = std::env::var("NAOME_FRONTIER_PILOT").as_deref() == Ok("1");
    assessment::execute(&root, &design, pilot, &output).unwrap();
}

#[test]
#[ignore = "source-only frontier split feasibility; never invokes a Solver or optimizer"]
fn seal_longitudinal_questions() {
    let output = std::path::PathBuf::from(std::env::var("NAOME_FRONTIER_OUTPUT").unwrap());
    assert!(!output.exists());
    std::fs::create_dir_all(&output).unwrap();
    let bytes = std::fs::read(std::env::var("NAOME_FRONTIER_HISTORICAL").unwrap()).unwrap();
    let historical: Vec<String> = serde_json::from_slice(&bytes).unwrap();
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let result = bank::build(&historical);
    write(
        &output.join("source-feasibility.json"),
        &json!({
        "complete":result.is_ok(),"error":result.as_ref().err(),"phases":PHASES,"seeds":SEEDS,
        "historical_sources":historical.len(),"cpu_micros":meta::cpu_micros().unwrap()-cpu,
        "wall_micros":started.elapsed().as_micros(),"solver_model_calls":0,"optimizer_updates":0,
        "question_counts":result.as_ref().ok().map(|b|[b.acquisition.len(),b.calibration.len(),b.assessment.len(),b.pilot.len()])}),
    );
    let bank = result.unwrap();
    write(&output.join("bank.json"), &bank);
}
