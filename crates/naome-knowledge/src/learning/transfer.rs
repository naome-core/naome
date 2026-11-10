//! Whole-family transfer outcomes. Search misses are operational outcomes,
//! never mathematical falsity or authority to admit a proof.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const FAMILIES: usize = 12;
pub const CASES: usize = FAMILIES * 2;
pub(super) const ALLOWANCE: u8 = 32;
const ALL: u32 = (1 << CASES) - 1;
const CHECKED: u8 = 1 << 7;
const PAIR_BYTES: usize = 10;

/// The native trial's paired work and outcomes, in execution order. Each arm
/// uses a byte for paid expansions and exact proof status, followed by the
/// measured process CPU micros. Memory admission is the same for both arms.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evidence {
    development: String,
    transfer: String,
}

#[derive(Default)]
pub(super) struct Development {
    pub overall: [u32; 2],
    pub original: [u32; 2],
    pub protected_loss: bool,
    pub anchor_loss: bool,
}

impl Evidence {
    pub fn extends(&self, previous: &Self) -> bool {
        self.development.starts_with(&previous.development)
            && self.transfer.starts_with(&previous.transfer)
    }

    pub fn record(&mut self, transfer: bool, evaluated: &Evaluation) {
        self.push(
            transfer,
            [evaluated.before.solved, evaluated.after.solved],
            [evaluated.before.expansions, evaluated.after.expansions],
            [evaluated.before.cpu_micros, evaluated.after.cpu_micros],
        );
    }

    pub fn push(&mut self, transfer: bool, checked: [bool; 2], paid: [u8; 2], cpu: [u32; 2]) {
        let mut bytes = [0; PAIR_BYTES];
        for i in 0..2 {
            bytes[i] = paid[i] | if checked[i] { CHECKED } else { 0 };
            bytes[2 + 4 * i..6 + 4 * i].copy_from_slice(&cpu[i].to_le_bytes());
        }
        let pair = crate::hex(&bytes);
        let lane = if transfer {
            &mut self.transfer
        } else {
            &mut self.development
        };
        lane.push_str(&pair);
    }

    fn decoded(source: &str, count: usize) -> Result<Vec<u8>, crate::Error> {
        if source.len() != 2 * PAIR_BYTES * count {
            return Err(crate::ResearchFailure::ResearchValueInvalid.into());
        }
        let bytes = crate::unhex(source)?;
        if bytes
            .chunks_exact(PAIR_BYTES)
            .any(|pair| pair[..2].iter().any(|n| n & !CHECKED > ALLOWANCE))
        {
            return Err(crate::ResearchFailure::ResearchValueInvalid.into());
        }
        Ok(bytes)
    }

    pub fn validate(&self, count: usize, transfer: Summary) -> Result<Development, crate::Error> {
        let development = Self::decoded(&self.development, count)?;
        let pairs = Self::decoded(&self.transfer, transfer.observed.count_ones() as usize)?;
        for (index, pair) in pairs.chunks_exact(PAIR_BYTES).enumerate() {
            if (pair[0] & CHECKED != 0) != (transfer.before & (1 << index) != 0)
                || (pair[1] & CHECKED != 0) != (transfer.after & (1 << index) != 0)
            {
                return Err(crate::ResearchFailure::ResearchValueInvalid.into());
            }
        }
        let mut summary = Development::default();
        for (index, pair) in development.chunks_exact(PAIR_BYTES).enumerate() {
            let successes = [pair[0], pair[1]].map(|arm| u32::from(arm & CHECKED != 0));
            let lost = successes == [1, 0];
            if index < super::curriculum::DEVELOPMENT {
                for (total, observed) in summary.overall.iter_mut().zip(successes) {
                    *total += observed;
                }
            } else {
                summary.anchor_loss |= lost;
            }
            if index < super::curriculum::CORPUS_DEVELOPMENT {
                for (total, observed) in summary.original.iter_mut().zip(successes) {
                    *total += observed;
                }
                summary.protected_loss |= lost;
            }
        }
        Ok(summary)
    }

    pub fn assessment(
        &self,
        base: &super::State,
    ) -> Result<crate::research_value::Assessment, crate::Error> {
        let development = super::curriculum::development();
        let anchors = base
            .anchors
            .iter()
            .map(|anchor| {
                super::curriculum::owned::case(&anchor.question)
                    .ok_or(crate::ResearchFailure::ResearchValueInvalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let observed = Self::decoded(&self.development, development.len() + anchors.len())?;
        let transfer = Self::decoded(&self.transfer, CASES)?;
        let mut comparison = crate::research_value::Comparison::default();
        let mut cpu_comparison = crate::research_value::Comparison::default();
        for (family, pair) in development
            .into_iter()
            .chain(&anchors)
            .map(|case| &case.dependency)
            .zip(observed.chunks_exact(PAIR_BYTES))
            .chain(
                super::curriculum::adaptive::BANK
                    .transfer
                    .iter()
                    .map(|case| &case.dependency)
                    .zip(transfer.chunks_exact(PAIR_BYTES)),
            )
        {
            let block = Sha256::digest(family.as_bytes()).into();
            let checked = |i: usize| pair[i] & CHECKED != 0;
            let measured = |i| {
                crate::research_value::measured_proof(
                    checked(i),
                    u64::from(pair[i] & !CHECKED),
                    u64::from(ALLOWANCE),
                )
            };
            let time = |i: usize| {
                u64::from(u32::from_le_bytes(
                    pair[2 + 4 * i..6 + 4 * i]
                        .try_into()
                        .expect("paired CPU width"),
                ))
            };
            let time_scale = time(0).max(time(1));
            let timed = |i| crate::research_value::measured_proof(checked(i), time(i), time_scale);
            comparison.record(block, measured(0), measured(1));
            cpu_comparison.record(block, timed(0), timed(1));
        }
        Ok(comparison
            .assess()
            .with_resource_bound(cpu_comparison.assess()))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub before: u32,
    pub after: u32,
    pub observed: u32,
}
impl Summary {
    pub fn prefix(count: usize) -> u32 {
        (1u32 << count.min(CASES)) - 1
    }
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.observed & !ALL != 0
            || self.observed & self.observed.wrapping_add(1) != 0
            || (self.before | self.after) & !self.observed != 0
        {
            return Err(crate::ResearchFailure::TransferCoverageInvalid.into());
        }
        Ok(())
    }
    pub fn record(&mut self, index: usize, before: bool, after: bool) -> Result<(), crate::Error> {
        self.validate()?;
        if index >= CASES || self.observed != Self::prefix(index) {
            return Err(crate::ResearchFailure::TransferSequence.into());
        }
        self.before |= u32::from(before) << index;
        self.after |= u32::from(after) << index;
        self.observed |= 1 << index;
        Ok(())
    }
    pub fn complete(&self) -> bool {
        self.observed == ALL
    }
}
pub(super) struct Outcome {
    pub solved: bool,
    pub expansions: u8,
    pub cpu_micros: u32,
    pub terminal: super::experience::TerminalEvidence,
    #[cfg(all(test, feature = "developer-tools"))]
    pub diagnostic: crate::outcome::GenerationOutcome,
    pub micros: u64,
    #[cfg(all(test, feature = "developer-tools"))]
    pub proof_id: Option<String>,
}
pub(super) struct Evaluation {
    pub before: Outcome,
    pub after: Outcome,
}
pub(super) fn evaluate<I: super::ArtifactIo + ?Sized>(
    source: &str,
    base: &super::State,
    candidate: &super::Checkpoint,
    engine: &mut super::Engine,
    io: &mut I,
    job: u64,
) -> Result<Evaluation, crate::Error> {
    let mut solve = |checkpoint: &super::Checkpoint| {
        let start = std::time::Instant::now();
        let cpu = super::meta::cpu_micros()?;
        let generation = engine.with_error(checkpoint, io, |runtime| {
            super::solve_with_report_typed(
                source,
                runtime,
                usize::from(ALLOWANCE),
                job,
                super::SolveContext {
                    definitions: &base.definitions,
                    theorems: &base.knowledge,
                    native_programs: true,
                    ..Default::default()
                },
            )
        })?;
        let expansions = u8::try_from(generation.cost.search_expansions)
            .ok()
            .filter(|used| *used <= ALLOWANCE)
            .ok_or(crate::ResearchFailure::ResearchValueInvalid)?;
        if let Some(solution) = &generation.solution {
            let question = naome_checker::question::ResearchQuestion::from_hex(source)?;
            solution.check_target(&question)?;
        }
        Ok::<_, crate::Error>(Outcome {
            solved: generation.solution.is_some(),
            expansions,
            cpu_micros: u32::try_from(super::meta::cpu_micros()?.saturating_sub(cpu))
                .map_err(|_| crate::ResearchFailure::ResearchValueInvalid)?,
            terminal: generation.terminal,
            #[cfg(all(test, feature = "developer-tools"))]
            proof_id: generation.solution.map(|s| s.proof_id),
            #[cfg(all(test, feature = "developer-tools"))]
            diagnostic: generation.diagnostic,
            micros: start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        })
    };
    let result = Evaluation {
        before: solve(&base.model)?,
        after: solve(candidate)?,
    };
    #[cfg(all(test, feature = "developer-tools"))]
    observation::record(source, &result)?;
    Ok(result)
}
#[cfg(all(test, feature = "developer-tools"))]
pub(super) mod observation;
#[cfg(test)]
mod tests;
