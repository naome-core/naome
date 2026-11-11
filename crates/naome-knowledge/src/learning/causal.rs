//! Solver counterfactuals within a reserved training job. Every success comes
//! from the installed native search and independent target checker.
mod selection;
use super::{model::intervention::Span, transfer, *};
use selection::{Subset, intervention, rank};

pub(super) const SCREEN: usize = 32;
const WITNESSES: usize = transfer::FAMILIES;
const CONFIRMATION_FAMILIES: usize = transfer::FAMILIES;
pub(super) const LOCALIZATION: usize = SCREEN + WITNESSES;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Trial {
    proposal: Option<String>,
    discovery: transfer::Summary,
    discovery_trace: Option<String>,
    comparable_gains: u32,
    screens: u8,
    tested_masks: u8,
    screen_expansions: u32,
    witness_families: u8,
    best: Option<Subset>,
    pub selected: Option<String>,
    pub witnessed: u32,
    pub sufficient: u32,
    pub removal_losses: u32,
    pub alternative_proofs: u32,
    witness_trace: Option<String>,
    insertion_fork: Option<Fork>,
    removal_fork: Option<Fork>,
    confirmation: transfer::Summary,
    confirmation_trace: Option<String>,
    confirmation_gains: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fork {
    case: usize,
    event: usize,
    state: String,
    menu: String,
    before: usize,
    after: usize,
}

impl Trial {
    fn invalid() -> crate::ResearchFailure {
        crate::ResearchFailure::CausalTrialBinding
    }

    fn gained(&self) -> u32 {
        self.comparable_gains
    }

    fn required(&self) -> u32 {
        self.gained() | self.discovery.before
    }

    pub(super) fn localization(&self) -> usize {
        if self.gained() != 0 && self.discovery.complete() {
            LOCALIZATION
        } else {
            0
        }
    }

    pub(super) fn discover(
        &mut self,
        index: usize,
        candidate: &Checkpoint,
        pair: &transfer::Evaluation,
    ) -> Result<(), crate::Error> {
        let proposal = digest(candidate);
        if self.proposal.get_or_insert(proposal.clone()) != &proposal {
            return Err(Self::invalid().into());
        }
        self.discovery
            .record(index, pair.before.solved, pair.after.solved)?;
        if fixed_search_miss(&pair.before) && pair.after.solved {
            self.comparable_gains |= 1 << index;
        }
        self.discovery_trace = Some(digest(&(
            &self.discovery_trace,
            index,
            observation(&pair.before),
            observation(&pair.after),
        )));
        Ok(())
    }

    pub(super) fn screen<I: ArtifactIo + ?Sized>(
        &mut self,
        round: usize,
        base: &State,
        candidate: &Checkpoint,
        engine: &mut Engine,
        io: &mut I,
        job: u64,
    ) -> Result<(), crate::Error> {
        if self.localization() == 0 || round != usize::from(self.screens) || round >= SCREEN {
            return Err(Self::invalid().into());
        }
        let weights = engine.intervention_weights(&base.model, candidate, io)?;
        if self.best.is_none() {
            let spans = vec![Span {
                start: 0,
                end: weights.parameters,
            }];
            self.best = Some(Subset {
                changed: weights.changed(&spans) as u32,
                spans,
                checked: self.discovery.after & self.required(),
            });
        }
        let modules = weights
            .modules
            .iter()
            .map(|(_, span)| *span)
            .collect::<Vec<_>>();
        let incumbent = self.best.as_ref().ok_or_else(Self::invalid)?;
        let spans = intervention(round, &modules, incumbent, self.gained());
        let changed = weights.changed(&spans) as u32;
        if changed != 0 && spans.len() <= 16 && spans != incumbent.spans {
            let required = self.required();
            let (checked, paid) =
                engine.with_intervention(&base.model, candidate, &spans, false, io, |runtime| {
                    let mut checked = 0;
                    let mut paid = 0;
                    for (index, case) in curriculum::adaptive::BANK.transfer.iter().enumerate() {
                        let bit = 1 << index;
                        if required & bit != 0 {
                            let result = transfer::solve(&case.source, base, runtime, job)?;
                            paid += u32::from(result.expansions);
                            if result.solved {
                                checked |= bit;
                            }
                        }
                    }
                    Ok((checked, paid))
                })?;
            self.tested_masks += 1;
            self.screen_expansions += paid;
            let proposal = Subset {
                spans,
                changed,
                checked,
            };
            if rank(&proposal, self.gained(), self.discovery.before)
                > rank(incumbent, self.gained(), self.discovery.before)
            {
                self.best = Some(proposal);
            }
        }
        self.screens += 1;
        Ok(())
    }

    pub(super) fn witness<I: ArtifactIo + ?Sized>(
        &mut self,
        family: usize,
        base: &State,
        candidate: &Checkpoint,
        engine: &mut Engine,
        io: &mut I,
        job: u64,
    ) -> Result<(), crate::Error> {
        if self.screens as usize != SCREEN
            || family != self.witness_families as usize
            || family >= WITNESSES
        {
            return Err(Self::invalid().into());
        }
        let best = self.best.as_ref().ok_or_else(Self::invalid)?;
        for index in [2 * family, 2 * family + 1] {
            let bit = 1 << index;
            if self.gained() & bit == 0 {
                continue;
            }
            let source = &curriculum::adaptive::BANK.transfer[index].source;
            let originals = transfer::pair(source, base, candidate, engine, io, job)?;
            if !fixed_search_miss(&originals.before) || !originals.after.solved {
                // The fixed panel did not reproduce; this gain cannot qualify.
                continue;
            }
            let mut intervention = |removal| {
                engine.with_intervention(
                    &base.model,
                    candidate,
                    &best.spans,
                    removal,
                    io,
                    |runtime| transfer::solve(source, base, runtime, job),
                )
            };
            let inserted = intervention(false)?;
            let removed = intervention(true)?;
            self.witnessed |= bit;
            if inserted.solved {
                self.sufficient |= bit;
            }
            if fixed_search_miss(&removed) {
                self.removal_losses |= bit;
            } else if removed.solved && removed.proof_id != originals.after.proof_id {
                self.alternative_proofs |= bit;
            }
            let insertion = fork(index, &originals.before, &inserted);
            let removal = fork(index, &originals.after, &removed);
            self.witness_trace = Some(digest(&(
                &self.witness_trace,
                index,
                observation(&originals.before),
                observation(&originals.after),
                observation(&inserted),
                observation(&removed),
                &insertion,
                &removal,
            )));
            if self.insertion_fork.is_none() {
                self.insertion_fork = insertion;
            }
            if self.removal_fork.is_none() {
                self.removal_fork = removal;
            }
        }
        self.witness_families += 1;
        Ok(())
    }

    pub(super) fn freeze<I: ArtifactIo + ?Sized>(
        &mut self,
        parent: &Checkpoint,
        candidate: &Checkpoint,
        engine: &mut Engine,
        io: &mut I,
    ) -> Result<Checkpoint, crate::Error> {
        if self.witness_families as usize != WITNESSES || self.selected.is_some() {
            return Err(Self::invalid().into());
        }
        let best = self.best.as_ref().ok_or_else(Self::invalid)?;
        let evaluated = if self.sufficient != 0 && best.changed != 0 {
            engine.checkpoint_intervention(parent, candidate, &best.spans, io)?
        } else {
            candidate.clone()
        };
        self.selected = Some(digest(&evaluated));
        Ok(evaluated)
    }

    /// Outcome-blind selection of one sibling from each sealed, independent
    /// family that uses the same generator operation as a discovered gain.
    pub(super) fn confirmation_cases(&self) -> Vec<&'static curriculum::Case> {
        let Some(identity) = &self.proposal else {
            return Vec::new();
        };
        if self.localization() == 0 {
            return Vec::new();
        }
        let operations = curriculum::adaptive::BANK
            .transfer
            .iter()
            .enumerate()
            .filter(|(i, _)| self.gained() & (1 << i) != 0)
            .map(|(_, case)| &case.family)
            .collect::<std::collections::BTreeSet<_>>();
        let mut families = curriculum::adaptive::BANK
            .confirmation
            .chunks_exact(2)
            .filter(|pair| operations.contains(&pair[0].family))
            .map(|pair| {
                let order = digest(&(identity, &pair[0].dependency));
                let variant = usize::from(order.as_bytes()[0] & 1);
                (order, &pair[variant])
            })
            .collect::<Vec<_>>();
        families.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        families
            .into_iter()
            .take(CONFIRMATION_FAMILIES)
            .map(|(_, case)| case)
            .collect()
    }

    pub(super) fn confirm(
        &mut self,
        index: usize,
        pair: &transfer::Evaluation,
    ) -> Result<(), crate::Error> {
        self.confirmation
            .record(index, pair.before.solved, pair.after.solved)?;
        if fixed_search_miss(&pair.before) && pair.after.solved {
            self.confirmation_gains |= 1 << index;
        }
        self.confirmation_trace = Some(digest(&(
            &self.confirmation_trace,
            index,
            observation(&pair.before),
            observation(&pair.after),
        )));
        Ok(())
    }

    pub(super) fn accepts(&self, transfer: transfer::Summary) -> bool {
        self.selected.is_some()
            && self.gained() != 0
            && transfer.complete()
            && transfer.before == self.discovery.before
            && transfer.after & self.discovery.before == self.discovery.before
            && transfer.after & self.sufficient & self.gained() != 0
            && self.confirmation.observed
                == transfer::Summary::prefix(self.confirmation_cases().len())
            && self.confirmation.after & self.confirmation.before == self.confirmation.before
            && self.confirmation_gains != 0
    }

    pub(super) fn continues(&self, previous: &Self) -> bool {
        let extends = |next: transfer::Summary, prior: transfer::Summary| {
            next.observed & prior.observed == prior.observed
                && (next.before ^ prior.before) & prior.observed == 0
                && (next.after ^ prior.after) & prior.observed == 0
        };
        extends(self.discovery, previous.discovery)
            && extends(self.confirmation, previous.confirmation)
            && self.comparable_gains & previous.discovery.observed == previous.comparable_gains
            && self.confirmation_gains & previous.confirmation.observed
                == previous.confirmation_gains
            && previous
                .proposal
                .as_ref()
                .is_none_or(|old| Some(old) == self.proposal.as_ref())
            && previous
                .selected
                .as_ref()
                .is_none_or(|old| Some(old) == self.selected.as_ref())
            && (previous.screens != self.screens || previous.best == self.best)
            && (previous.tested_masks..=previous.tested_masks + 1).contains(&self.tested_masks)
            && (previous.screen_expansions
                ..=previous.screen_expansions
                    + transfer::CASES as u32 * u32::from(transfer::ALLOWANCE))
                .contains(&self.screen_expansions)
            && (previous.screens != self.screens
                || (previous.tested_masks == self.tested_masks
                    && previous.screen_expansions == self.screen_expansions))
            && self.witnessed & previous.witnessed == previous.witnessed
            && self.sufficient & previous.sufficient == previous.sufficient
            && self.removal_losses & previous.removal_losses == previous.removal_losses
            && self.alternative_proofs & previous.alternative_proofs == previous.alternative_proofs
            && (previous.discovery.observed != self.discovery.observed
                || previous.discovery_trace == self.discovery_trace)
            && (previous.confirmation.observed != self.confirmation.observed
                || previous.confirmation_trace == self.confirmation_trace)
            && (previous.witness_families != self.witness_families
                || (previous.witness_trace == self.witness_trace
                    && previous.witnessed == self.witnessed
                    && previous.sufficient == self.sufficient
                    && previous.removal_losses == self.removal_losses
                    && previous.alternative_proofs == self.alternative_proofs
                    && previous.insertion_fork == self.insertion_fork
                    && previous.removal_fork == self.removal_fork))
    }

    pub(super) fn valid(
        &self,
        evaluated_units: usize,
        confirmation_count: usize,
        candidate: Option<&Checkpoint>,
    ) -> Result<(), crate::Error> {
        self.discovery.validate()?;
        self.confirmation.validate()?;
        let after_discovery = evaluated_units.saturating_sub(transfer::CASES);
        let expected_screen = after_discovery.min(SCREEN);
        let expected_witness = after_discovery.saturating_sub(SCREEN).min(WITNESSES);
        let active = self.localization() != 0;
        let expected_selected = active && after_discovery > LOCALIZATION;
        if self.discovery.observed
            != transfer::Summary::prefix(evaluated_units.min(transfer::CASES))
            || self.comparable_gains & !(self.discovery.after & !self.discovery.before) != 0
            || self.confirmation_gains & !(self.confirmation.after & !self.confirmation.before) != 0
            || self.proposal.is_some() != (evaluated_units > 0)
            || self.discovery_trace.is_some() != (evaluated_units > 0)
            || self.screens as usize != if active { expected_screen } else { 0 }
            || self.witness_families as usize != if active { expected_witness } else { 0 }
            || self.selected.is_some() != expected_selected
            || self.best.is_some() != (self.screens > 0)
            || self.tested_masks > self.screens
            || self.screen_expansions
                > u32::from(self.tested_masks)
                    * transfer::CASES as u32
                    * u32::from(transfer::ALLOWANCE)
            || (self.sufficient | self.removal_losses | self.alternative_proofs) & !self.witnessed
                != 0
            || self.witness_trace.is_some() != (self.witnessed != 0)
            || self.witnessed
                & !(self.gained() & transfer::Summary::prefix(2 * self.witness_families as usize))
                != 0
            || self.removal_losses & self.alternative_proofs != 0
            || self.confirmation.observed != transfer::Summary::prefix(confirmation_count)
            || self.confirmation_trace.is_some() != (confirmation_count > 0)
        {
            return Err(Self::invalid().into());
        }
        if let Some(candidate) = candidate
            && let Some(binding) = self.selected.as_ref().or(self.proposal.as_ref())
            && *binding != digest(candidate)
        {
            return Err(Self::invalid().into());
        }
        for digest in [
            &self.proposal,
            &self.selected,
            &self.discovery_trace,
            &self.witness_trace,
            &self.confirmation_trace,
        ]
        .into_iter()
        .flatten()
        {
            crate::object::id_bytes(digest)?;
        }
        if let Some(best) = &self.best {
            let maximum = model::PARAMETERS as u32;
            if best.spans.is_empty()
                || best.spans.len() > 16
                || best.checked & !self.required() != 0
                || best
                    .spans
                    .iter()
                    .any(|span| span.start >= span.end || span.end > maximum)
                || !best.spans.windows(2).all(|w| w[0].end <= w[1].start)
                || best.changed
                    > best
                        .spans
                        .iter()
                        .map(|span| span.end - span.start)
                        .sum::<u32>()
            {
                return Err(Self::invalid().into());
            }
        }
        for fork in [&self.insertion_fork, &self.removal_fork]
            .into_iter()
            .flatten()
        {
            crate::object::id_bytes(&fork.state)?;
            crate::object::id_bytes(&fork.menu)?;
            if fork.case >= transfer::CASES
                || self.gained() & (1 << fork.case) == 0
                || fork.event >= usize::from(transfer::ALLOWANCE)
                || fork.before == fork.after
            {
                return Err(Self::invalid().into());
            }
        }
        Ok(())
    }

    /// Each existing paid evaluation checkpoint covers the same deterministic
    /// interval on replay. The confirmation set is consulted after the mask freezes.
    pub(super) fn evaluated(&self, units: usize, normal_cases: usize) -> usize {
        let start = transfer::CASES + self.localization();
        let count = normal_cases + self.confirmation_cases().len();
        count * units.saturating_sub(start) / (EVALUATIONS as usize - start)
    }
}

fn fixed_search_miss(outcome: &transfer::Outcome) -> bool {
    use experience::{Budget, TerminalEvidence};
    !outcome.solved
        && outcome.expansions > 0
        && matches!(
            outcome.terminal,
            TerminalEvidence::PolicyExhausted
                | TerminalEvidence::Budget(
                    Budget::Expansions | Budget::BranchExpansions | Budget::Depth
                )
        )
}

fn observation(
    outcome: &transfer::Outcome,
) -> (
    u8,
    &experience::TerminalEvidence,
    &Option<String>,
    Vec<String>,
) {
    (
        outcome.expansions,
        &outcome.terminal,
        &outcome.proof_id,
        outcome
            .decisions
            .iter()
            .map(SearchTrace::decision_digest)
            .collect(),
    )
}

fn fork(case: usize, original: &transfer::Outcome, changed: &transfer::Outcome) -> Option<Fork> {
    let found = original.decisions.iter().find_map(|a| {
        changed
            .decisions
            .iter()
            .find_map(|b| a.first_decision_fork(b))
    })?;
    Some(Fork {
        case,
        event: found.index,
        state: found.state.to_owned(),
        menu: found.offered.to_owned(),
        before: found.original,
        after: found.intervened,
    })
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(super) use tests::{test_fixture, test_pair};
