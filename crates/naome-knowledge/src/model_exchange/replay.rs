use super::{
    Blob, Model, Profile, Registration,
    plan::{self, Challenge, Family, Lane},
};
use crate::{
    frontier::RankingModel,
    learning::{ArtifactIo, Engine, digest, model::Checkpoint, search},
};
use naome_authoring::CompiledQuestion;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::LazyLock};

pub(super) fn contract(profile: Profile) -> String {
    static SOLVER: LazyLock<String> = LazyLock::new(|| reference(Profile::Solver));
    static FINDER: LazyLock<String> = LazyLock::new(|| reference(Profile::Finder));
    match profile {
        Profile::Solver => &*SOLVER,
        Profile::Finder => &*FINDER,
    }
    .clone()
}

fn reference(profile: Profile) -> String {
    let limits = crate::resources::limits();
    digest(&(
        "naome:model-score-reference",
        profile,
        crate::compatibility(),
        crate::learning::input_specification(),
        // The Float32 kernels are only comparable within the reference target.
        (
            std::env::consts::OS,
            std::env::consts::ARCH,
            cfg!(debug_assertions),
            cpu_features(),
        ),
        (
            limits.proof_bytes,
            limits.closure_steps,
            limits.closure_bytes,
            limits.closure_work_bytes,
        ),
        include_str!("plan.rs"),
        include_str!("replay.rs"),
        include_str!("../learning/model/verification.rs"),
        include_str!("../frontier/finder/model.rs"),
        include_str!("../frontier/finder/analysis.rs"),
        include_str!("../structure.rs"),
        include_str!("../sampling.rs"),
        include_str!("../../../../Cargo.lock"),
        include_str!("../../../../rust-toolchain.toml"),
    ))
}

// The upstream Float32 kernel may pick a different vector route depending
// on the target. Bind supported hardware classes and require exact replay.
fn cpu_features() -> Vec<bool> {
    #[cfg(target_arch = "x86_64")]
    return vec![
        std::arch::is_x86_feature_detected!("sse4.1"),
        std::arch::is_x86_feature_detected!("avx"),
        std::arch::is_x86_feature_detected!("avx2"),
        std::arch::is_x86_feature_detected!("fma"),
        std::arch::is_x86_feature_detected!("avx512f"),
    ];
    #[cfg(target_arch = "aarch64")]
    return vec![
        std::arch::is_aarch64_feature_detected!("neon"),
        std::arch::is_aarch64_feature_detected!("dotprod"),
        std::arch::is_aarch64_feature_detected!("i8mm"),
        std::arch::is_aarch64_feature_detected!("sve"),
    ];
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    Vec::new()
}

/// The full comparison can be reproduced from its registrations and challenge.
/// Only replay results enter the counts. A transcript commits to the checked
/// proof identities and exact work for each visited task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Comparison {
    pub(crate) challenge: Challenge,
    pub(crate) blocks: u64,
    pub(crate) local: u64,
    pub(crate) remote: u64,
    pub(crate) transcript: String,
    pub(crate) extension: Extension,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Extension {
    Eligible,
    NoCalibration,
}

impl Comparison {
    pub(crate) fn validate(&self) -> Result<(), String> {
        self.challenge.validate()?;
        if self.blocks == 0
            || self.local > self.blocks.saturating_mul(plan::FAMILIES as u64)
            || self.remote > self.blocks.saturating_mul(plan::FAMILIES as u64)
        {
            return Err("model comparison counts differ from its plan".into());
        }
        crate::object::id_bytes(&self.transcript)?;
        Ok(())
    }

    /// Decide an audit step using only newly executed results and the public
    /// claim. A sender may claim a longer prefix, but cannot skip any block.
    pub(crate) fn audit_against(&self, claim: &Self) -> Result<bool, String> {
        if self.challenge != claim.challenge {
            return Err("offered comparison uses different conditions".into());
        }
        if self == claim {
            return Ok(true);
        }
        if self.extension == Extension::NoCalibration
            || self.blocks > claim.blocks
            || self.blocks == claim.blocks && claim.extension == Extension::Eligible
            || self.local > claim.local
            || self.remote > claim.remote
        {
            return Err("offered score or transcript failed independent replay".into());
        }
        Ok(false)
    }

    pub(crate) fn id(&self) -> String {
        digest(&("naome:model-comparison", self))
    }
}

#[derive(Serialize)]
struct Outcome {
    task: String,
    expansions: usize,
    proof: Option<String>,
}

struct Attempt<'a> {
    solver: &'a Checkpoint,
    finder: Option<RankingModel>,
}

impl<'a> Attempt<'a> {
    fn new(
        registration: &'a Registration,
        fixed: &'a Checkpoint,
        engine: &mut Engine,
        io: &mut impl ArtifactIo,
    ) -> Result<Self, String> {
        let attempt = match &registration.model {
            Model::Solver { checkpoint } => Self {
                solver: checkpoint,
                finder: None,
            },
            Model::Finder { checkpoint } => Self {
                solver: fixed,
                finder: Some(decode_finder(&crate::learning::load_artifact(
                    io, checkpoint,
                )?)?),
            },
        };
        // Validate and restore both halves of the solver checkpoint even if
        // the plan happens to terminate before scoring a task.
        engine.verify_reference(attempt.solver, io)?;
        Ok(attempt)
    }

    fn select<'b>(&self, family: &'b Family) -> &'b CompiledQuestion {
        let index = self.finder.as_ref().map_or(0, |finder| {
            let page = family
                .candidates
                .iter()
                .map(|q| ((), finder.reference_weight(q)))
                .collect::<Vec<_>>();
            let mut random = crate::sampling::Random::new(family.draw);
            crate::sampling::choose(&mut random, &page, false)
        });
        &family.candidates[index]
    }

    fn block(
        &self,
        engine: &mut Engine,
        io: &mut impl ArtifactIo,
        block: &[Family],
    ) -> Result<Vec<Outcome>, String> {
        engine.with(self.solver, io, |ranker| {
            let mut seen = BTreeSet::new();
            block
                .iter()
                .map(|family| {
                    let question = self.select(family);
                    let task = crate::hex(question.resolution_id());
                    if !seen.insert(task.clone()) {
                        return Err("repeated comparison task".into());
                    }
                    let target = question.proved_target();
                    let result = search::solve_reference(target, ranker, plan::EXPANSIONS)?;
                    let proof = result
                        .tree
                        .map(|tree| {
                            let (_, _, checked) = search::core::checked(target, &tree)?;
                            Ok::<_, String>(crate::hex(checked.native_id.as_bytes()))
                        })
                        .transpose()?;
                    Ok(Outcome {
                        task,
                        expansions: result.expansions,
                        proof,
                    })
                })
                .collect()
        })
    }
}

pub(crate) fn decode_finder(bytes: &[u8]) -> Result<RankingModel, String> {
    if bytes.len() > crate::checkpoint::MAX_HEADER {
        return Err("finder checkpoint byte capacity".into());
    }
    let model: RankingModel = crate::checkpoint::decode(bytes)?;
    model.validate()?;
    if [model.updates, model.rehearsals, model.utility_observations].contains(&u64::MAX) {
        return Err("finder checkpoint cannot advance its update count".into());
    }
    Ok(model)
}

pub(crate) fn encode_finder(model: &RankingModel) -> Result<(Blob, Vec<u8>), String> {
    let bytes = crate::checkpoint::encode(model)?;
    Ok((Blob::of(&bytes), bytes))
}

fn score(outcomes: &[Outcome]) -> u64 {
    outcomes
        .iter()
        .filter(|outcome| outcome.proof.is_some())
        .count() as u64
}

/// An invocation admits one bounded extension probe. An accepted prefix can
/// be extended again with exactly the same frozen participants and new block
/// tasks. Saturation and technical failures never fabricate a zero score.
pub(crate) fn replay(
    challenge: Challenge,
    previous: Option<&Comparison>,
    io: &mut impl ArtifactIo,
) -> Result<Comparison, String> {
    challenge.validate()?;
    let mut engine = Engine::default();
    let fixed = Checkpoint::fresh();
    let local = Attempt::new(&challenge.local, &fixed, &mut engine, io)?;
    let remote = Attempt::new(&challenge.remote, &fixed, &mut engine, io)?;
    let run = |engine: &mut Engine, io: &mut _, block: &[Family]| {
        Ok::<_, String>((
            local.block(engine, io, block)?,
            remote.block(engine, io, block)?,
        ))
    };
    let mut result = if let Some(previous) = previous {
        previous.validate()?;
        if previous.challenge != challenge {
            return Err("previous comparison uses different conditions".into());
        }
        if previous.extension == Extension::NoCalibration {
            return Ok(previous.clone());
        }
        previous.clone()
    } else {
        let (l, r) = run(&mut engine, io, &plan::block(&challenge, 0, Lane::Score)?)?;
        Comparison {
            challenge: challenge.clone(),
            blocks: 1,
            local: score(&l),
            remote: score(&r),
            transcript: digest(&(&challenge, &l, &r)),
            extension: Extension::Eligible,
        }
    };

    let (l, r) = run(
        &mut engine,
        io,
        &plan::block(&challenge, result.blocks, Lane::Calibration)?,
    )?;
    // Admit a new block only if fresh held-out outcomes distinguish the
    // contenders. Both checkpoints then take the separate scored block.
    if score(&l) == score(&r) {
        result.extension = Extension::NoCalibration;
        result.transcript = digest(&(&result.transcript, &l, &r, Extension::NoCalibration));
        return Ok(result);
    }
    let (next_l, next_r) = run(
        &mut engine,
        io,
        &plan::block(&challenge, result.blocks, Lane::Score)?,
    )?;
    result.blocks = result
        .blocks
        .checked_add(1)
        .ok_or("comparison block count overflow")?;
    result.local = result
        .local
        .checked_add(score(&next_l))
        .ok_or("local score overflow")?;
    result.remote = result
        .remote
        .checked_add(score(&next_r))
        .ok_or("peer score overflow")?;
    result.transcript = digest(&(&result.transcript, &l, &r, &next_l, &next_r));
    Ok(result)
}
